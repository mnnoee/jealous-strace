"""Сигнатуры инцидентов"""

from collections import Counter

try:
    from . import phpmail
except Exception:  # pragma: no cover
    phpmail = None

from . import smtp
from .i18n import t
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
                t("sig.loop", keys=" -> ".join(keys),
                  repeated=", ".join(sorted(repeated)))
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
                t("sig.repeated", key=key, n=cnt)
            ))
    return issues


def detect_scheme_switch(p):
    """Редирект из http в https (или наоборот) внутри цепочки"""
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
                    t("sig.scheme", method=prev.get("method", "?"), uri=prev.get("uri"),
                      location=prev.get("location"), scheme=nxt_scheme)
                ))
    return issues


def detect_secure_cookie_over_http(p):
    """Secure-cookie"""
    issues = []
    for r in p.http_requests:
        cookies = r.get("set_cookie") or []
        for c in cookies:
            if c.get("secure") and _req_scheme(r) != "https":
                issues.append((
                    "WARNING",
                    t("sig.cookie", name=c.get("name"), method=r.get("method", "?"),
                      uri=r.get("uri"), host=r.get("host"))
                ))
    return issues


def detect_enoent_storm(p, threshold=200):
    """ENOENT"""
    issues = []
    total = sum(p.open_missing.values())
    if total < threshold:
        return issues
    top = p.open_missing.most_common(3)
    sample = ", ".join(f"{path[:60]} (x{n})" for path, n in top)
    issues.append((
        "WARNING",
        t("sig.enoent", n=total, sample=sample)
    ))
    return issues


def detect(p):
    """Все сигнатуры разом. Возвращает список"""
    out = []
    out += detect_redirect_loop(p)
    out += detect_repeated_chains(p)
    out += detect_scheme_switch(p)
    out += detect_secure_cookie_over_http(p)
    out += detect_enoent_storm(p)
    out += smtp.detect(p)
    if phpmail is not None and getattr(p, "mail_body", False):
        out += phpmail.detect(p)
    return out
