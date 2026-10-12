"""RAM/OOM анализ: mmap-трекинг, PHP Out-of-memory, секция отчёта."""

import re
from collections import Counter

from .parse_utils import fmt_bytes
from .wp import classify_wp_component

PHP_OOM_RE = re.compile(
    r"Fatal error:\s*Out of memory\s*\(allocated (\d+) bytes\)\s*"
    r"\(tried to allocate (\d+) bytes\)\s*in\s*(.+?)\s*on line\s*(\d+)"
)


def check_oom(p, ts, txt_clean):
    """Детект 'PHP Fatal error: Out of memory' в тексте socket write."""
    oom_m = PHP_OOM_RE.search(txt_clean)
    if not oom_m:
        return
    p.oom_detected = True
    allocated = int(oom_m.group(1))
    tried = int(oom_m.group(2))
    p.oom_message = (
        f"PHP Fatal error: Out of memory "
        f"(allocated {allocated} bytes = {fmt_bytes(allocated)}, "
        f"tried to allocate {tried} bytes = {fmt_bytes(tried)}) "
        f"in {oom_m.group(3)} on line {oom_m.group(4)}"
    )
    p.php_fatal_errors.append((ts, p.oom_message, oom_m.group(3), int(oom_m.group(4))))


def report_section(p, w):
    """Секция отчёта '--- RAM / OOM АНАЛИЗ ---'."""
    has_mem_data = p.oom_detected or p.mmap_count > 0 or p.php_fatal_errors
    if not has_mem_data:
        return
    w("\n--- RAM / OOM АНАЛИЗ ---")
    if p.oom_detected:
        w(f"\n  Fatal: {p.oom_message}")

    if p.oom_detected:
        # определить страницу
        page = "unknown"
        if p.http_requests:
            uri = p.http_requests[0].get("uri") or ""
            # если URI — это полный путь к файлу, берём только имя
            if uri and ".php" in uri:
                # /var/www/.../wp-admin/post.php -> wp-admin/post.php
                m = re.search(r"/(wp-admin/\w+\.php)", uri)
                if m:
                    page = m.group(1)
                else:
                    page = uri.split("/")[-1]
            elif uri and uri.startswith("/"):
                page = uri
        if page == "unknown" or page.endswith(".php") and "/" not in page:
            # fallback: ищем wp-admin/*.php
            for path in p.files:
                m = re.search(r"/wp-admin/(\w+\.php)$", path)
                if m:
                    page = f"wp-admin/{m.group(1)}"
                    break
            if page == "unknown":
                for path in p.files:
                    if "wp-login.php" in path:
                        page = "wp-login.php"
                        break
                    if "wp-cron.php" in path:
                        page = "wp-cron.php"
                        break
        w(f"  Страница: {page}")

        # компоненты, загруженные до краша
        if p.files:
            comp_count = Counter()
            for path in p.files:
                comp = classify_wp_component(path)
                comp_count[comp] += 1
            w(f"  Загружено файлов: {len(p.files)} уникальных")
            w("  Компоненты ( кол-во файлов ):")
            for comp, cnt in comp_count.most_common(15):
                w(f"    {cnt:>4}  {comp}")

            # SQL перед крашем
            if p.sql_queries:
                total_mysql_bytes = sum(q["recv_bytes"] for q in p.sql_queries)
                w(f"  SQL-запросов: {len(p.sql_queries)}")
                w(f"  Данные от MySQL: {fmt_bytes(total_mysql_bytes)}")
                # топ запросов по объёму данных
                queries_with_data = [q for q in p.sql_queries if q["recv_bytes"] > 0]
                if queries_with_data:
                    queries_sorted = sorted(queries_with_data, key=lambda q: q["recv_bytes"], reverse=True)
                    w("\n  Топ SQL-запросов по объёму ответа:")
                    for q in queries_sorted[:20]:
                        sql_short = q["sql"][:80]
                        w(f"    {fmt_bytes(q['recv_bytes']):>10}  {sql_short}")
                # все запросы с объёмом
                w("\n  Все SQL-запросы с объёмом данных:")
                for q in p.sql_queries:
                    sql_short = q["sql"][:80]
                    w(f"    {fmt_bytes(q['recv_bytes']):>10}  {sql_short}")

            # mmap
            if p.mmap_count > 0:
                peak_est = p.mmap_total - p.munmap_total
                w(f"  mmap итого: {fmt_bytes(p.mmap_total)}, munmap: {fmt_bytes(p.munmap_total)}, пик: ~{fmt_bytes(max(peak_est, 0))}")

            # объём данных от MySQL
            if p.sql_queries:
                total_mysql_bytes = sum(q["recv_bytes"] for q in p.sql_queries)
                if total_mysql_bytes > 0:
                    w(f"  Данные от MySQL: {fmt_bytes(total_mysql_bytes)} ({len(p.sql_queries)} запросов)")
                    # корневая причина: запрос с максимальным объёмом данных
                    top_q = max(p.sql_queries, key=lambda q: q["recv_bytes"])
                    if top_q["recv_bytes"] > 0:
                        pct = top_q["recv_bytes"] / total_mysql_bytes * 100
                        w("\n  >>> КОРНЕВАЯ ПРИЧИНА OOM:")
                        w(f"  Запрос вернул {fmt_bytes(top_q['recv_bytes'])} ({pct:.1f}% всех данных MySQL):")
                        w(f"  {top_q['sql']}")
                        if top_q["recv_bytes"] > 100 * 1024 * 1024:
                            w("  Этот ОДИН запрос загрузил > 100MB данных в память PHP.")

            enomem = p.errno_counter.get("ENOMEM", 0)
            if enomem > 0:
                w(f"  ENOMEM (mmap отказал): {enomem}")

        if p.php_fatal_errors and not p.oom_detected:
            for ts, msg, _fname, _line in p.php_fatal_errors:
                w(f"  {ts.strftime('%H:%M:%S') if ts else '?'} {msg}")
