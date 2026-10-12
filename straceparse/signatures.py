"""Сигнатуры инцидентов: автодетект типовых проблем по собранным данным.

Каждая функция-детектор проверяет один паттерн и возвращает список
(severity, message) — строки добавляются в секцию «КЛЮЧЕВЫЕ ПРОБЛЕМЫ» отчёта.
"""

from collections import Counter

from .redirects import REDIRECT_STATUSES, build_chains


def _req_scheme(r):
    """'https' / 'http' / None для запроса (из FCGI HTTPS-параметра)."""
    s = r.get("scheme")
    if s == "https":
        return "https"
    return "http"


def _url_scheme(location):
    if not location:
        return None
    if location.startswith("https://"):
        return "https"
    if location.startswith("http://"):
        return "http"
    return None


def detect_redirect_loop(p):
    """Петля редиректов: URI повторяется внутри одной цепочки."""
    issues = []
    for chain in build_chains(p):
        keys = [f"{r.get('method', '?')} {r.get('uri', '?')}" for r in chain]
        seen = set()
        repeated = set()
        for k in keys:
            if k in seen:
                repeated.add(k)
            seen.add(k)
        if repeated:
            issues.append((
                "CRITICAL",
                f"ПЕТЛЯ ПЕРЕПРАВЛЕНИЙ: «{' -> '.join(keys)}» — URI повторяется в цепочке "
                f"(повтор: {', '.join(sorted(repeated))}). Браузер/клиент зацикливается."
            ))
    return issues


def detect_repeated_chains(p):
    """Одинаковая цепочка редиректов повторяется много раз (признак зацикливания)."""
    issues = []
    chains = build_chains(p)
    if len(chains) < 2:
        return issues
    def key_of(c):
        return " -> ".join(f"{r.get('method', '?')} {r.get('uri', '?')}" for r in c)

    counts = Counter(key_of(c) for c in chains)
    for key, cnt in counts.items():
        if cnt >= 2:
            issues.append((
                "WARNING",
                f"Цепочка редиректов «{key}» повторяется {cnt} раз подряд — "
                f"признак зацикленного доступа (например, заход на закрытую страницу)."
            ))
    return issues


def detect_scheme_switch(p):
    """Редирект из http в https (или наоборот) внутри цепочки.

    Классика: форма логина присылает Location https, а следующий запрос
    приходит по http — админка «не открывается» (недостижимый https-редирект).
    """
    issues = []
    for chain in build_chains(p):
        for prev, nxt in zip(chain, chain[1:]):
            if prev.get("status") not in REDIRECT_STATUSES:
                continue
            loc_scheme = _url_scheme(prev.get("location"))
            if not loc_scheme:
                continue
            nxt_scheme = _req_scheme(nxt)
            if prev.get("location") and (loc_scheme == "https") != (nxt_scheme == "https"):
                issues.append((
                    "CRITICAL",
                    f"СМЕШАННЫЕ HTTP/HTTPS: {prev.get('method', '?')} {prev.get('uri')} -> "
                    f"Location {prev.get('location')}, а следующий запрос пришёл по {nxt_scheme}. "
                    f"Редирект в недоступный протокол — страница не открывается."
                ))
    return issues


def detect_secure_cookie_over_http(p):
    """Secure-cookie выдаётся по HTTP (без https) — кука не дойдёт обратно."""
    issues = []
    for r in p.http_requests:
        cookies = r.get("set_cookie") or []
        for c in cookies:
            if c.get("secure") and _req_scheme(r) != "https":
                issues.append((
                    "WARNING",
                    f"Secure-cookie «{c.get('name')}» установлена по HTTP для "
                    f"{r.get('method', '?')} {r.get('uri')} host={r.get('host')}. "
                    f"Кука помечена Secure, но соединение не HTTPS — браузер её не вернёт."
                ))
    return issues


def detect_enoent_storm(p, threshold=200):
    """Шквал обращений к несуществующим файлам (ENOENT)."""
    issues = []
    total = sum(p.open_missing.values())
    if total < threshold:
        return issues
    top = p.open_missing.most_common(3)
    sample = ", ".join(f"{path[:60]} (x{n})" for path, n in top)
    issues.append((
        "WARNING",
        f"Шквал ENOENT: {total} обращений к несуществующим файлам. "
        f"Топ: {sample}. Обход несуществующих путей грузит диски и файловые кэши."
    ))
    return issues


def detect(p):
    """Все сигнатуры разом. Возвращает список (severity, message)."""
    out = []
    out += detect_redirect_loop(p)
    out += detect_repeated_chains(p)
    out += detect_scheme_switch(p)
    out += detect_secure_cookie_over_http(p)
    out += detect_enoent_storm(p)
    return out
