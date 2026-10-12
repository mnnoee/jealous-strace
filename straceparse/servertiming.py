"""Разбивка времени WordPress по фазам из заголовка Server-Timing.

WordPress (плагин Server-Timing) добавляет в ответ заголовок вида:
    Server-Timing: wp-before-template;dur=1169.49, wp-template;dur=230.07,
                   wp-total;dur=1399.55
Показываем фазы по каждому медленному запросу и агрегат по фазам.
"""

import statistics

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

    w("\n--- ФАЗЫ ЗАПРОСОВ (Server-Timing) ---")

    slow = [r for r, _ in items if (_req_dur(r) or 0) >= SLOW_REQ_DUR]
    if slow:
        w(f"\nМедленные запросы (> {SLOW_REQ_DUR:.0f}s) с разбивкой фаз:")
        for r in slow[:10]:
            phases = dict(r.get("server_timing") or [])
            dur = _req_dur(r) or 0.0
            parts = "  ".join(f"{n}={v:.1f}мс" for n, v in phases.items())
            w(f"  {dur:>6.2f}s {r.get('method', '?')} {r.get('uri')}  [{parts}]")

    # агрегат по фазам
    phase_vals = {}
    for _r, phases in items:
        for name, v in phases.items():
            if name == "wp-total":
                continue
            phase_vals.setdefault(name, []).append(v)
    if phase_vals:
        w("\nАгрегат фаз по запросам (медиана, мс):")
        for name, vals in sorted(phase_vals.items(), key=lambda kv: -statistics.median(kv[1])):
            med = statistics.median(vals)
            total = sum(vals)
            w(f"  {name:<24} медиана={med:>9.1f}мс   сумма={total:>10.1f}мс "
              f"({len(vals)} {'запросов' if len(vals) > 1 else 'запрос'})")
        top = max(phase_vals.items(), key=lambda kv: statistics.median(kv[1]))[0]
        w(f"\n  БОЛЬШЕ ВСЕГО ВРЕМЕНИ — фаза «{top}» (медианная длительность по запросам).")

    totals = [v for r, phases in items for name, v in phases.items() if name == "wp-total"]
    if totals:
        w(f"\n  wp-total: медиана={statistics.median(totals):.1f}мс "
          f"p95={sorted(totals)[min(len(totals) - 1, int(len(totals) * 0.95))]:.1f}мс (render всего ответа)")
