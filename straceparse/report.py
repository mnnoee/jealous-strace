"""Построение человекочитаемого отчёта из собранных данных StraceParser."""

from collections import Counter, defaultdict

from . import constants as ct
from . import load, mem, mtls, redirects, servertiming, signatures, sql_timing, wp
from .parse_utils import fmt_bytes, normalize_sql
from .wp import classify_wp_component


def slow_http(p, min_dur=5.0):
    http = p.http_requests
    slow = [r for r in http if r.get("start") and r.get("end") and r["end"] > r["start"]]
    slow.sort(key=lambda r: (r["end"] - r["start"]).total_seconds(), reverse=True)
    return [r for r in slow if (r["end"] - r["start"]).total_seconds() >= min_dur]


def build_report(p):
    lines = []
    w = lines.append
    w("=" * 78)
    w("ОТЧЁТ ПО STRACE-ЛОГАМ")
    w("=" * 78)

    w(f"\nСтрок обработано: {p.lines_total}")
    w(f"Форматы строк: {dict(p.format_counts)}")

    # вычислить длительность покрытия лога
    all_starts = [st["start"] for st in p.pid_stats.values() if st["start"]]
    all_ends = [st["end"] for st in p.pid_stats.values() if st["end"]]
    duration = 0.0
    if all_starts and all_ends:
        duration = (max(all_ends) - min(all_starts)).total_seconds()

    if p.exited_pids:
        w(f"Завершившиеся процессы: {len(p.exited_pids)}")
        bad = {k: v for k, v in p.exited_pids.items() if v not in (0, 1)}
        if bad:
            w(f"  Процессы с ненулевым кодом: {bad}")

    # ---- WordPress диагностика ----
    if p.wordpress:
        wp_issues = wp.diagnose(p)
        if wp_issues or p.wp_version or p.wp_active_theme or p.wp_php_version_hint:
            w("\n--- WORDPRESS: ДИАГНОСТИКА ---")
            if p.wp_version:
                w(f"  Версия WP: {p.wp_version}")
            if p.wp_php_version_hint:
                w(f"  Версия PHP: {p.wp_php_version_hint}")
            if p.wp_active_theme:
                w(f"  Активная тема: {p.wp_active_theme}")
            if p.wp_abspath:
                w(f"  ABSPATH: {p.wp_abspath}")
            if wp_issues:
                w("")
                # CRITICAL first, then ERROR, WARNING, INFO
                severity_order = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}
                sorted_issues = sorted(wp_issues, key=lambda x: severity_order.get(x[0], 99))
                for sev, msg in sorted_issues:
                    prefix = {"CRITICAL": "[!!!]", "ERROR": "[!!]", "WARNING": "[!]", "INFO": "[i]"}.get(sev, "[?]")
                    w(f"  {prefix} {msg}")
            else:
                w("  Критических проблем не обнаружено.")

    # ---- Ключевые проблемы ----
    w("\n--- КЛЮЧЕВЫЕ ПРОБЛЕМЫ (сводка) ---")
    problems = []
    http_err = [r for r in p.http_requests if r.get("status") and r["status"] >= 400]
    if http_err:
        by_code = Counter(r["status"] for r in http_err)
        problems.append(f"HTTP-ошибки (4xx/5xx): {len(http_err)} "
                        f"({', '.join(f'{c}={n}' for c, n in sorted(by_code.items()))})")
    slow_http_list = slow_http(p)
    if slow_http_list:
        problems.append(f"Очень медленные HTTP-запросы (>5s): {len(slow_http_list)}")
    conn_err = [c for c in p.connects if c["errno"] and c["errno"] != "EINPROGRESS"]
    if conn_err:
        by_err = Counter(c["errno"] for c in conn_err)
        problems.append(f"Ошибки connect(): {len(conn_err)} "
                        f"({', '.join(f'{e}={n}' for e, n in sorted(by_err.items()))})")
    dns_err = [q for q in p.dns_queries if str(q.get("status", "")).startswith("err")]
    if dns_err:
        by_rc = Counter(str(q.get("rcode")) for q in dns_err)
        problems.append(f"Ошибки DNS: {len(dns_err)} ({dict(by_rc)})")
    slow_sys = [s for s in p.slow_calls if s[4] > 1.0]
    if slow_sys:
        problems.append(f"Очень медленные syscalls (>1s): {len(slow_sys)}")
    if p.unfinished_open:
        problems.append(f"Незавершённые вызовы: {len(p.unfinished_open)}")
    if p.open_missing:
        problems.append(f"Открытия несуществующих файлов (ENOENT): {sum(p.open_missing.values())}")
    if p.oom_detected:
        problems.append(f"OOM КРАШ: {p.oom_message[:120]}")
    if p.mtls and p.mtls_ssl_errors:
        n = len(p.mtls_ssl_errors)
        problems.append(f"SSL/mTLS: сервер отклонил клиентские сертификаты ({n} {'ошибка' if n == 1 else 'ошибки'})")
    enomem = p.errno_counter.get("ENOMEM", 0)
    if enomem > 0:
        problems.append(f"ENOMEM: {enomem}")
    if problems:
        for problem in problems:
            w(f"  [i] {problem}")
    else:
        w("  (не обнаружено)")

    # ---- сигнатуры инцидентов ----
    sig = signatures.detect(p)
    if sig:
        w("\n--- СИГНАТУРЫ ИНЦИДЕНТОВ ---")
        mark = {"CRITICAL": "[!!!]", "ERROR": "[!!]", "WARNING": "[!]", "INFO": "[i]"}.get
        for sev, msg in sig:
            w(f"  {mark(sev, '[?]')} {msg}")

    # ---- RAM / OOM анализ ----
    mem.report_section(p, w)

    # --- DNS серверы ---
    dns_servers = Counter()
    for c in p.connects:
        ep = c["endpoint"]
        if ep and ep.get("port") == 53 and ep.get("ip"):
            dns_servers[(ep.get("ip"), c["ret"], c["errno"])] += 1
    if dns_servers:
        w("\n--- DNS-СЕРВЕРЫ (connect к порту 53) ---")
        for (ip, ret, err), cnt in dns_servers.most_common(10):
            status = "OK" if ret == "0" else f"ERR {err}"
            w(f"  {ip:<18} {status:<12} {cnt}")

    # --- HTTP ---
    http = p.http_requests
    if http:
        status_counter = Counter(r.get("status") for r in http if r.get("status"))
        w("\n--- HTTP/FCGI запросы ---")
        w(f"Всего запросов: {len(http)}")
        if status_counter:
            w("Статусы ответов:")
            for s, c in sorted(status_counter.items(), key=lambda x: -x[1]):
                w(f"  {s}: {c}")
        w("Запросы (метод uri host длительность):")
        for r in sorted(http, key=lambda x: (x.get("start") or 0)):
            dur = 0.0
            if r.get("start") and r.get("end") and r["end"] > r["start"]:
                dur = (r["end"] - r["start"]).total_seconds()
            loc = f"  loc={r.get('location')}" if r.get("status") in (301, 302, 303, 307, 308) else ""
            sch = f"  s={r.get('scheme')}" if r.get("scheme") else ""
            w(f"  {r.get('method', '?'):<6} {r.get('uri', '?'):<60} {r.get('host', '?'):<25} "
              f"status={r.get('status', '?')}  {dur:.3f}s{loc}{sch}")
        problems_http = [r for r in http if r.get("status") and r["status"] >= 400]
        w(f"\nЗапросы с ошибками (4xx/5xx): {len(problems_http)}")
        for r in problems_http[:40]:
            w(f"  {r['status']} {r.get('method', '?')} {r.get('uri')} host={r.get('host')} "
              f"pid={r.get('pid')} fd={r.get('fd')} loc={r.get('location')}")

        # медленные запросы
        slow_http_list = slow_http(p)
        if slow_http_list:
            w("\nСамые медленные запросы (по времени между accept и ответом):")
            for r in slow_http_list[:10]:
                dur = (r["end"] - r["start"]).total_seconds() if r["end"] > r["start"] else 0
                w(f"  {dur:.3f}s {r.get('method', '?')} {r.get('uri')} status={r.get('status')} host={r.get('host')}")

        # --- редиректы ---
        redirects.report_chains(p, w)

        # --- фазы Server-Timing ---
        servertiming.report_section(p, w)

    # --- syscalls ---
    w("\n--- СИСТЕМНЫЕ ВЫЗОВЫ ---")
    total = sum(p.syscalls.values())
    w(f"Всего вызовов: {total}")
    w("\nТоп вызовов (кол-во, ошибки, время):")
    w(f"{'Вызов':<22}{'Кол-во':>10}{'Ошибки':>10}{'Сумм.время':>12}")
    for name, cnt in p.syscalls.most_common(40):
        err = p.syscall_err_count[name]
        times = p.syscall_time[name]
        tsum = sum(times) if times else 0.0
        w(f"{name:<22}{cnt:>10}{err:>10}{tsum:>12.3f}")

    # --- скорость ---
    if duration > 0:
        w(f"\n--- СКОРОСТЬ (за {duration:.1f} сек) ---")
        w(f"{'syscall/сек':<22}{total / duration:>10.0f}")
        for name, cnt in p.syscalls.most_common(10):
            w(f"{name + '/сек':<22}{cnt / duration:>10.0f}")
        sql_per_sec = len(p.sql_queries) / duration
        w(f"{'SQL/сек':<22}{sql_per_sec:>10.0f}")

    # --- ошибки ---
    w("\n--- ОШИБКИ (=-1) ---")
    if p.errno_counter:
        w(f"Всего ошибок: {sum(p.errno_counter.values())}")
        for err, cnt in p.errno_counter.most_common(30):
            w(f"  {err}: {cnt}")
            if err in p.errno_examples:
                w(f"      пример: {p.errno_examples[err][:200]}")
    else:
        w("  (нет)")

    # --- файлы ---
    w("\n--- ФАЙЛЫ ---")
    if p.files:
        w(f"Уникальных путей: {len(p.files)}")

        if p.wordpress:
            # группировка по компонентам WP
            comp_count = Counter()
            comp_reads = defaultdict(int)
            comp_files = defaultdict(set)
            for path, ops in p.files.items():
                comp = classify_wp_component(path)
                comp_count[comp] += sum(ops.values())
                comp_reads[comp] += p.file_bytes[path].get("read", 0)
                comp_files[comp].add(path)
            if comp_count:
                w("\nТоп компонентов по числу обращений:")
                for comp, cnt in comp_count.most_common(15):
                    w(f"  {cnt:>6}  {comp}")

        w("\nТоп файлов по числу обращений:")
        w(f"{'Путь':<70}{'Открыто':>10}{'Чтений':>10}{'Записей':>10}{'Прочитано':>12}{'Записано':>12}")
        top_files = sorted(p.files.items(), key=lambda kv: sum(kv[1].values()), reverse=True)[:40]
        for path, ops in top_files:
            reads = ops.get("read", 0)
            writes = ops.get("write", 0)
            opens = ops.get("openat", 0) + ops.get("open", 0)
            rb = p.file_bytes[path].get("read", 0)
            wb = p.file_bytes[path].get("write", 0)
            w(f"{path[:70]:<70}{opens:>10}{reads:>10}{writes:>10}{fmt_bytes(rb):>12}{fmt_bytes(wb):>12}")
        if p.open_missing:
            w(f"\nФайлы, которые НЕ найдены (ENOENT): {sum(p.open_missing.values())}")
            for path, cnt in p.open_missing.most_common(30):
                w(f"  {cnt:>5}  {path}")
    else:
        w("  (нет)")

    # --- сеть ---
    w("\n--- СЕТЬ ---")
    if p.connects:
        conns_ok = Counter()
        conns_err = Counter()
        conns_pending = Counter()
        endpoints = {}
        for c in p.connects:
            ep = c["endpoint"]
            if not ep:
                continue
            # адрес: ip для TCP/UDP, путь сокета для AF_UNIX (mysqld.sock и т.п.)
            addr = ep.get("ip") or ep.get("path") or "?"
            port = ep.get("port")
            key = (addr, port)
            if c["ret"] == "0":
                conns_ok[key] += 1
                endpoints.setdefault(key, {"ep": ep, "ok": 0, "err": 0, "pending": 0, "final": 0})
                endpoints[key]["ok"] += 1
            elif c["errno"] == "EINPROGRESS":
                conns_pending[key] += 1
                endpoints.setdefault(key, {"ep": ep, "ok": 0, "err": 0, "pending": 0, "final": 0})
                endpoints[key]["pending"] += 1
            else:
                conns_err[key] += 1
                endpoints.setdefault(key, {"ep": ep, "ok": 0, "err": 0, "pending": 0, "final": 0})
                endpoints[key]["err"] += 1

        w(f"Всего connect(): {len(p.connects)}")
        w("\nПодключения по адресам:")
        w(f"{'Адрес':<40}{'Порт':>6}{'OK':>6}{'ERR':>6}{'EINPROGRESS':>12}")
        for (addr, port), cnt in conns_ok.most_common(30):
            err = conns_err.get((addr, port), 0)
            pend = conns_pending.get((addr, port), 0)
            w(f"{str(addr)[:40]:<40}{port if port is not None else '?':>6}{cnt:>6}{err:>6}{pend:>12}")

        w("\nОшибки подключения:")
        for (ip, port), cnt in conns_err.most_common(30):
            w(f"  {ip}:{port} - {cnt}")

        # таймауты: EINPROGRESS, который так и не завершился успехом
        unresolved = []
        for c in p.connects:
            ep = c["endpoint"] or {}
            if c["errno"] == "EINPROGRESS" and not c.get("resolved"):
                unresolved.append(c)
        if unresolved:
            w(f"\nТаймауты/незавершённые соединения (EINPROGRESS без успешного завершения): {len(unresolved)}")
            for c in unresolved[:30]:
                ep = c["endpoint"] or {}
                w(f"  pid={c['pid']} fd={c['fd']} {ep.get('ip')}:{ep.get('port')} ts={c['ts'].strftime('%H:%M:%S') if c['ts'] else '?'} [{c['file']}]")
    else:
        w("  (нет)")

    # --- DNS ---
    w("\n--- DNS ---")
    if p.dns_queries:
        qcount = Counter(q.get("qname") for q in p.dns_queries)
        w(f"Всего DNS-запросов: {len(p.dns_queries)}")
        w("\nТоп DNS-имён:")
        for q, c in qcount.most_common(30):
            w(f"  {c:>5}  {q}")
        err_dns = [q for q in p.dns_queries if q.get("status", "").startswith("err")]
        if err_dns:
            w(f"\nОшибки DNS: {len(err_dns)}")
            for q in err_dns[:30]:
                w(f"  {q.get('ts')} {q.get('qname')} rcode={ct.RCODE_NAMES.get(q.get('rcode'), q.get('rcode'))}")
    else:
        w("  (нет)")

    # --- SSL / mTLS анализ ---
    mtls.report_section(p, w)

    # --- SQL ---
    w("\n--- SQL-ЗАПРОСЫ ---")
    if p.sql_queries:
        w(f"Всего SQL-запросов: {len(p.sql_queries)}")

        # нормализация и топ запросов
        norm_counter = Counter()
        for q in p.sql_queries:
            norm = normalize_sql(q["sql"][:200])
            norm_counter[norm] += 1

        w("\nТоп запросов (нормализованные):")
        total_sql = len(p.sql_queries)
        for norm, cnt in norm_counter.most_common(15):
            pct = cnt / total_sql * 100
            w(f"  {cnt:>6} ({pct:>5.1f}%)  {norm[:100]}")

        if p.wordpress:
            # autoload bloat
            autoload_count = sum(1 for q in p.sql_queries if 'autoload' in q['sql'].lower())
            if autoload_count > 500:
                w("\n[!] AUTOLOAD BLOB DETECTED")
                w(f"    {autoload_count} из {total_sql} запросов ({autoload_count / total_sql * 100:.1f}%) — загрузка опций с autoload.")
                w("    Норма: <500 запросов на загрузку страницы.")
                w("    Рекомендация: очистить wp_options от неиспользуемых опций,")
                w("    проверить плагины, создающие autoload-записи.")
    else:
        w("  (нет)")

    # --- SQL: тайминг и повторы ---
    sql_timing.report_section(p, w)

    # --- по PID ---
    w("\n--- ПО ПРОЦЕССАМ (PID) ---")
    w(f"{'PID':>10}{'Вызовов':>10}{'Ошибок':>8}{'Начало':>12}{'Конец':>12}")
    for pid, st in sorted(p.pid_stats.items(), key=lambda kv: kv[1]["count"], reverse=True):
        start = st["start"].strftime("%H:%M:%S") if st["start"] else "?"
        end = st["end"].strftime("%H:%M:%S") if st["end"] else "?"
        exitcode = p.exited_pids.get(pid, "")
        w(f"{pid:>10}{st['count']:>10}{st['err']:>8}{start:>12}{end:>12}  exit={exitcode}")

    # --- незавершённые вызовы ---
    w("\n--- НЕЗАВЕРШЁННЫЕ ВЫЗОВЫ (<unfinished>, потенциальные таймауты/зависания) ---")
    if p.unfinished_open:
        names = Counter(n for _, n, _, _, _ in p.unfinished_open)
        w(f"Всего вызовов начато, но не завершено: {len(p.unfinished_open)}")
        w("Топ таких вызовов:")
        for n, c in names.most_common(20):
            w(f"  {c:>6}  {n}")
        w("\nПервые примеры (pid, имя, время):")
        for pid, name, ts, fname, _ in p.unfinished_open[:30]:
            w(f"  pid={pid} {name} ts={ts.strftime('%H:%M:%S') if ts else '?'} [{fname}]")
    else:
        w("  (нет)")

    # --- медленные вызовы ---
    w("\n--- САМЫЕ МЕДЛЕННЫЕ ВЫЗОВЫ ---")
    if p.slow_calls:
        w(f"Вызовы медленнее {p.threshold:.2f}s: {len(p.slow_calls)}")
        for pid, ts, name, args, dur, _fname in p.slow_calls[:p.slow_top]:
            w(f"  {dur:>8.4f}s pid={pid} {p._fmt_syscall(name, args)[:110]} ts={ts.strftime('%H:%M:%S') if ts else '?'}")
    else:
        w("  (нет)")

    # --- стоимость на запрос ---
    http_count = len(p.http_requests)
    if http_count > 0:
        w("\n--- СТОИМОСТЬ ОДНОГО HTTP-ЗАПРОСА ---")
        w(f"(на основе {http_count} HTTP-запросов" + (f" за {duration:.1f} сек)" if duration > 0 else ")"))
        w("")
        per_req = total / http_count
        w(f"{'syscall/запрос':<22}{per_req:>10.0f}")
        for name in ['openat', 'lstat', 'access', 'read', 'write', 'connect']:
            cnt = p.syscalls.get(name, 0)
            if cnt > 0:
                w(f"{name + '/запрос':<22}{cnt / http_count:>10.0f}")
        sql_per_req = len(p.sql_queries) / http_count
        w(f"{'SQL/запрос':<22}{sql_per_req:>10.0f}")

    # --- тяжёлые плагины ---
    wp.report_heavy_plugins(p, w)

    # --- атрибуция нагрузки ---
    load.report_section(p, w)

    w("\n" + "=" * 78)
    return "\n".join(lines)
