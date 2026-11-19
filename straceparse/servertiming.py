"""Разбивка времени WordPress по фазам из заголовка Server-Timing"""

import statistics

from .i18n import plural_word, t

# длительности < порога считаем «быстрыми» и в секцию не выводим (шум)
SLOW_REQ_DUR = 1.0


def phases_by_request(p):
    """Для каждого HTTP-запроса с server_timing: dict имя_фазы -> (dur_ms, request)."""
    out = []
    for r in p.http_requests:
        st = r.get("server_timing")
        if not st:
            continue
        out.append((r, dict(st)))
    return out


def _req_dur(r):
    if r.get("start") and r.get("end") and r["end"] > r["start"]:
        return (r["end"] - r["start"]).total_seconds()
    return None


def report_section(p, w):
    items = phases_by_request(p)
    if not items:
        return

    w(t("st.title"))

    slow = [r for r, _ in items if (_req_dur(r) or 0) >= SLOW_REQ_DUR]
    if slow:
        w(t("st.slow", secs=SLOW_REQ_DUR))
        for r in slow[:10]:
            phases = dict(r.get("server_timing") or [])
            dur = _req_dur(r) or 0.0
            parts = "  ".join(f"{n}={v:.1f}{t('st.ms')}" for n, v in phases.items())
            w(f"  {dur:>6.2f}s {r.get('method', '?')} {r.get('uri')}  [{parts}]")

    # агрегат по фазам
    phase_vals = {}
    for _r, phases in items:
        for name, v in phases.items():
            if name == "wp-total":
                continue
            phase_vals.setdefault(name, []).append(v)
    if phase_vals:
        w(t("st.aggregate"))
        for name, vals in sorted(phase_vals.items(), key=lambda kv: -statistics.median(kv[1])):
            med = statistics.median(vals)
            total = sum(vals)
            w(t("st.line", name=name, med=med, total=total, n=len(vals),
                word=plural_word(len(vals), "request")))
        top = max(phase_vals.items(), key=lambda kv: statistics.median(kv[1]))[0]
        w(t("st.most", top=top))

    totals = [v for r, phases in items for name, v in phases.items() if name == "wp-total"]
    if totals:
        w(t("st.total", med=statistics.median(totals),
            p95=sorted(totals)[min(len(totals) - 1, int(len(totals) * 0.95))]))
