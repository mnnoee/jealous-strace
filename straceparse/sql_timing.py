"""Тайминг SQL-запросов и детект N+1 (повторяющиеся запросы).

Длительность запроса (приблизительная) = время между отправкой запроса
(start_ts) и получением ответа (end_ts). end_ts берётся из recv на том же
MySQL-сокете либо из времени следующего запроса на этом сокете.
"""


from .parse_utils import fmt_bytes, normalize_sql


def query_duration(q):
    """Длительность запроса в секундах или None."""
    st = q.get("start_ts") or q.get("ts")
    en = q.get("end_ts")
    if st is None or en is None or en <= st:
        return None
    return (en - st).total_seconds()


def timed_queries(p):
    """Все запросы с известной длительностью: список (dur, query)."""
    out = []
    for q in p.sql_queries:
        d = query_duration(q)
        if d is not None:
            out.append((d, q))
    out.sort(key=lambda x: x[0], reverse=True)
    return out


def percentiles(durations, pcts=(50, 95, 99)):
    if not durations:
        return {}
    d = sorted(durations)
    res = {}
    for pc in pcts:
        k = max(0, min(len(d) - 1, int(len(d) * pc / 100.0)))
        res[pc] = d[k]
    return res


def uri_for_query(p, q):
    """Лучшая привязка запроса к URI: тот же pid, ближайший старт <= ts."""
    ts = q.get("start_ts") or q.get("ts")
    pid = q.get("pid")
    best = None
    best_key = None
    for r in p.http_requests:
        st = r.get("start")
        if st is None or ts is None or st > ts:
            continue
        rpid = r.get("pid")
        key = (rpid == pid, st)
        if best is None or key > best_key:
            best = r
            best_key = key
    if best is None:
        return None
    return f"{best.get('method', '?')} {best.get('uri', '?')}"


def find_n_plus_1(p, min_repeats=10):
    """Находит конвейеры повтора одной нормализованной формы SQL (N+1).

    Сортируем запросы по времени и ищем последовательные серии одной формы
    длиной >= min_repeats. Каждая серия — подозрение на цикл по строкам.
    """
    rows = sorted((q for q in p.sql_queries if q.get("start_ts") is not None),
                  key=lambda q: q["start_ts"])
    runs = []
    cur = []
    for q in rows:
        n = normalize_sql(q["sql"][:200])
        if cur and cur[-1][1] == n:
            cur.append((q, n))
            continue
        if cur:
            runs.append(cur)
        cur = [(q, n)]
    if cur:
        runs.append(cur)

    out = []
    for run in runs:
        if len(run) < min_repeats:
            continue
        q0 = run[0][0]
        q1 = run[-1][0]
        total_sec = None
        if q0.get("start_ts") and q1.get("end_ts"):
            total_sec = (q1["end_ts"] - q0["start_ts"]).total_seconds()
        recv_bytes = sum(q.get("recv_bytes", 0) for q, _ in run)
        out.append({
            "normalized": run[0][1],
            "repeats": len(run),
            "start_ts": q0.get("start_ts"),
            "end_ts": q1.get("end_ts"),
            "total_sec": total_sec,
            "pid": q0.get("pid"),
            "uri": uri_for_query(p, q0),
            "recv_bytes": recv_bytes,
        })
    out.sort(key=lambda x: x["repeats"], reverse=True)
    return out


def _fmt_ts(ts):
    return ts.strftime("%H:%M:%S") if ts else "?"


def report_section(p, w):
    """Секция отчёта: тайминг SQL + N+1."""
    durs = [d for d, _ in timed_queries(p)]
    n1 = find_n_plus_1(p)
    if not durs and not n1:
        return

    w("\n--- SQL: ТАЙМИНГ И ПОВТОРЫ (N+1) ---")

    if durs:
        pct = percentiles(durs)
        w(f"Запросов с известной длительностью: {len(durs)}")
        w(f"Перцентили: p50={pct.get(50, 0) * 1000:.1f}мс  "
          f"p95={pct.get(95, 0) * 1000:.1f}мс  "
          f"p99={pct.get(99, 0) * 1000:.1f}мс")
        w("\nТоп медленных SQL (по длительности):")
        for d, q in timed_queries(p)[:15]:
            uri = uri_for_query(p, q)
            uri_s = f"  uri={uri}" if uri else ""
            # payload из php-fpm (FastCGI) содержит переводы строк — схлопываем в одну строку
            one_line = ' '.join(q.get('sql', '').split())[:90]
            w(f"  {d * 1000:>9.1f}мс pid={q.get('pid')} {one_line}{uri_s}")

    if n1:
        w(f"\n[!] ПОВТОРЯЮЩИЕСЯ ЗАПРОСЫ (N+1) — один запрос в цикле ({len(n1)} кандидатов):")
        for item in n1[:15]:
            ts_s = f"{_fmt_ts(item['start_ts'])}->{_fmt_ts(item['end_ts'])}" if item["start_ts"] else "?"
            dur_s = f"  интервал={item['total_sec']:.1f}s" if item["total_sec"] is not None else ""
            bytes_s = f"  данные={fmt_bytes(item['recv_bytes'])}" if item["recv_bytes"] else ""
            uri_s = f"  uri={item['uri']}" if item["uri"] else ""
            w(f"  x{item['repeats']:>4}  {item['normalized'][:80]}{dur_s}{bytes_s}{uri_s}")
            w(f"         время: {ts_s}")
