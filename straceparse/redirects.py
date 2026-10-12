"""Модуль анализа HTTP/FCGI редиректов: восстановление цепочек перенаправлений.

Работает с собранными StraceParser.http_requests (каждый запрос содержит
method/uri/host/status/location/referer/start/end). Строит из отдельных
302/301/303/307/308 цепочки "куда что редиректило" и выводит их в отчёт.
"""

from urllib.parse import urlsplit

# Статусы, которые считаются редиректами с Location.
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _location_path(location):
    """Из Location (полный или относительный URL) вытащить путь (без host/query)."""
    if not location:
        return None
    # относительный редирект (например /wp-login.php или wp-admin/)
    if not location.startswith(("http://", "https://")):
        path = location.split("?", 1)[0].split("#", 1)[0]
        return path or "/"
    parts = urlsplit(location)
    path = parts.path or "/"
    # убрать trailing slash для сравнения с URI без него
    return path


def _normalize_uri(uri):
    """Нормализует request uri для сравнения с путём из Location."""
    if not uri:
        return None
    path = uri.split("?", 1)[0].split("#", 1)[0] or "/"
    return path.rstrip("/") or "/"


def build_chains(p):
    """Строит цепочки редиректов из p.http_requests.

    Возвращает список цепочек. Каждая цепочка — список запросов по порядку,
    где редирект i ведёт на запрос i+1. Звенья — это исходные dict'ы из
    p.http_requests (обогащённые ключом "t" = время начала).
    """
    reqs = sorted(p.http_requests, key=lambda r: (r.get("start") is None, r.get("start") or 0))
    # только requests с запрошенным uri и временем
    usable = [r for r in reqs if r.get("uri")]
    # для каждого запроса храним нормализованный путь
    path_by_req = [_normalize_uri(r.get("uri")) for r in usable]
    used = [False] * len(usable)
    chains = []

    for i, r in enumerate(usable):
        if used[i]:
            continue
        chain = [r]
        used[i] = True
        cur = r
        # идём вперёд по редиректам: текущий запрос должен быть редиректом с Location
        while cur.get("status") in REDIRECT_STATUSES and cur.get("location"):
            target_path = _location_path(cur.get("location"))
            if not target_path:
                break
            target_path = target_path.rstrip("/") or "/"
            t_cur = cur.get("start")
            # найти следующий запрос, чей uri совпадает с Location
            nxt_index = None
            for j, cand in enumerate(usable):
                if used[j]:
                    continue
                if path_by_req[j] == target_path:
                    t_cand = cand.get("start")
                    if t_cur is not None and t_cand is not None and t_cand < t_cur:
                        continue
                    nxt_index = j
                    break
            if nxt_index is None:
                break
            used[nxt_index] = True
            chain.append(usable[nxt_index])
            cur = usable[nxt_index]
        # оставить только "настоящие" цепочки — минимум один переход
        if len(chain) >= 2:
            chains.append(chain)

    return chains


def _fmt_method_uri(r):
    return f"{r.get('method', '?')} {r.get('uri', '?')}"


def _fmt_location(r):
    return r.get("location")


def report_chains(p, w):
    """Выводит секцию о редиректах (цепочки + плоский список)."""
    redirects = [r for r in p.http_requests
                 if r.get("status") in REDIRECT_STATUSES and r.get("location")]
    if not redirects:
        return

    w("\n--- РЕДИРЕКТЫ (HTTP 3xx) ---")
    w(f"Всего редиректов (3xx с Location): {len(redirects)}")

    chains = build_chains(p)

    # 1) цепочки
    real_chains = [c for c in chains if len(c) >= 2]
    if real_chains:
        w(f"\nЦепочки перенаправлений ({len(real_chains)}):")
        for c in real_chains:
            w("  " + " -> ".join(_fmt_method_uri(r) for r in c))
            w("    " + " -> ".join(_fmt_location(r) for r in c[:-1] if r.get("location")))
    else:
        w("\nСвязанных цепочек (переход редиректа на следующий запрос) не найдено —")
        w("отдельные редиректы перечислены ниже.")

    # 2) плоский список всех редиректов по времени
    w("\nВсе редиректы (по порядку):")
    for r in sorted(redirects, key=lambda x: (x.get("start") is None, x.get("start") or 0)):
        dur = ""
        if r.get("start") and r.get("end") and r["end"] > r["start"]:
            dur = f"  { (r['end']-r['start']).total_seconds():.1f}s"
        w(f"  {r.get('method', '?'):<6} {str(r.get('uri')):<50} "
          f"-> {r.get('status')}  {r.get('location')}{dur}")
