"""Экспорт результатов анализа в JSON (машиночитаемый отчёт)."""

import json
import os
from collections import Counter

from . import load, wp
from .parse_utils import normalize_sql
from .redirects import build_chains
from .signatures import detect as detect_signatures
from .sql_timing import find_n_plus_1, timed_queries


def _ts(v):
    return v.isoformat() if hasattr(v, "isoformat") else v


def _req_json(r):
    dur = None
    if r.get("start") and r.get("end") and r["end"] > r["start"]:
        dur = round((r["end"] - r["start"]).total_seconds(), 6)
    return {
        "pid": r.get("pid"),
        "fd": r.get("fd"),
        "method": r.get("method"),
        "uri": r.get("uri"),
        "host": r.get("host"),
        "query": r.get("query"),
        "referer": r.get("referer"),
        "ua": r.get("ua"),
        "scheme": r.get("scheme"),
        "status": r.get("status"),
        "location": r.get("location"),
        "server_timing": r.get("server_timing"),
        "set_cookie": r.get("set_cookie"),
        "start": _ts(r.get("start")),
        "end": _ts(r.get("end")),
        "duration_sec": dur,
        "file": r.get("file"),
    }


def build_json(p):
    """Собирает dict со всеми результатами анализа."""
    data = {
        "meta": {
            "lines_total": p.lines_total,
            "formats": dict(p.format_counts),
        },
        "syscalls": {"total": sum(p.syscalls.values())},
        "sql": {"count": len(p.sql_queries)},
        "http": {"requests": [], "statuses": {}},
        "errors": [],
        "files": {"unique": len(p.files), "enoent": {}},
        "network": {"connects": len(p.connects)},
        "dns": {"queries": [], "errors": []},
        "signatures": [],
        "mem": {},
        "wordpress": {},
        "redirect_chains": [],
        "server_timing": {},
    }

    # Метаданные: длительность покрытия
    starts = [st["start"] for st in p.pid_stats.values() if st["start"]]
    ends = [st["end"] for st in p.pid_stats.values() if st["end"]]
    if starts and ends:
        data["meta"]["duration_sec"] = round((max(ends) - min(starts)).total_seconds(), 3)

    # syscalls: топ + ошибки + время
    top = []
    for name, cnt in p.syscalls.most_common(40):
        times = p.syscall_time.get(name) or []
        top.append({
            "name": name,
            "count": cnt,
            "errors": p.syscall_err_count.get(name, 0),
            "time_sec": round(sum(times), 3) if times else 0.0,
        })
    data["syscalls"]["top"] = top

    # ошибки
    for err, cnt in p.errno_counter.most_common(30):
        item = {"errno": err, "count": cnt}
        if err in p.errno_examples:
            item["example"] = p.errno_examples[err][:300]
        data["errors"].append(item)

    # файлы
    top_files = []
    for path, ops in sorted(p.files.items(), key=lambda kv: sum(kv[1].values()), reverse=True)[:40]:
        top_files.append({
            "path": path,
            "opens": ops.get("openat", 0) + ops.get("open", 0),
            "reads": ops.get("read", 0),
            "writes": ops.get("write", 0),
            "read_bytes": p.file_bytes[path].get("read", 0),
            "write_bytes": p.file_bytes[path].get("write", 0),
        })
    data["files"]["top"] = top_files
    data["files"]["enoent"] = dict(p.open_missing.most_common(30))

    # сеть
    conns_ok = Counter()
    conns_err = Counter()
    for c in p.connects:
        ep = c.get("endpoint") or {}
        addr = ep.get("ip") or ep.get("path") or "?"
        port = ep.get("port")
        key = f"{addr}:{port if port is not None else '?'}"
        if c["ret"] == "0":
            conns_ok[key] += 1
        elif c["errno"] != "EINPROGRESS":
            conns_err[key] += 1
    data["network"]["ok"] = dict(conns_ok.most_common(30))
    data["network"]["err"] = dict(conns_err.most_common(30))
    data["network"]["unresolved"] = len(
        [c for c in p.connects if c["errno"] == "EINPROGRESS" and not c.get("resolved")])

    # DNS
    qcount = Counter(q.get("qname") for q in p.dns_queries)
    data["dns"]["queries"] = [{"qname": q, "count": c} for q, c in qcount.most_common(30)]
    err_dns = [q for q in p.dns_queries if str(q.get("status", "")).startswith("err")]
    data["dns"]["errors"] = [{"qname": q.get("qname"), "rcode": q.get("rcode"),
                              "status": q.get("status")} for q in err_dns[:30]]

    # SQL: топ + объёмы + тайминг + N+1
    total_sql = len(p.sql_queries)
    norm_counter = Counter(normalize_sql(q["sql"][:200]) for q in p.sql_queries)
    data["sql"]["top"] = [
        {"sql": n, "count": c, "pct": round(c / total_sql * 100, 2) if total_sql else 0.0}
        for n, c in norm_counter.most_common(15)
    ]
    data["sql"]["top_by_recv"] = [
        {"sql": q["sql"][:200], "recv_bytes": q["recv_bytes"]}
        for q in sorted(p.sql_queries, key=lambda q: q.get("recv_bytes", 0), reverse=True)[:15]
        if q.get("recv_bytes", 0) > 0
    ]
    timed = timed_queries(p)
    data["sql"]["timed"] = [{
        "dur_sec": round(d, 3),
        "sql": q["sql"][:150],
        "pid": q.get("pid"),
        "ts": _ts(q.get("start_ts")),
    } for d, q in timed[:15]]
    data["sql"]["n_plus_1"] = [{
        "repeats": item["repeats"],
        "sql": item["normalized"],
        "total_sec": round(item["total_sec"], 3) if item["total_sec"] is not None else None,
        "pid": item["pid"],
        "uri": item["uri"],
        "recv_bytes": item["recv_bytes"],
    } for item in find_n_plus_1(p)[:15]]

    # HTTP
    statuses = Counter(r.get("status") for r in p.http_requests if r.get("status"))
    data["http"]["statuses"] = {str(k): v for k, v in sorted(statuses.items(), key=lambda kv: -kv[1])}
    for r in sorted(p.http_requests, key=lambda x: (x.get("start") is None, x.get("start") or 0)):
        j = _req_json(r)
        if j["duration_sec"] is not None and j["duration_sec"] >= 5.0:
            data["http"].setdefault("slow", []).append(j)
        if j["status"] is not None and j["status"] >= 400:
            data["http"].setdefault("errors", []).append(j)
        data["http"]["requests"].append(j)

    # редиректы (цепочки)
    data["redirect_chains"] = [
        [_req_json(r) for r in chain] for chain in build_chains(p)
    ]

    # Server-Timing агрегат
    phase_vals = {}
    for r in p.http_requests:
        for name, v in (r.get("server_timing") or []):
            phase_vals.setdefault(name, []).append(v)
    data["server_timing"] = {
        name: {"requests": len(vals), "sum_sec": round(sum(vals) / 1000.0, 3)}
        for name, vals in sorted(phase_vals.items())
    }

    # сигнатуры и проблемы
    for sev, msg in detect_signatures(p):
        data["signatures"].append({"severity": sev, "message": msg})

    # память
    data["mem"] = {
        "mmap_bytes": p.mmap_total,
        "mmap_count": p.mmap_count,
        "munmap_bytes": p.munmap_total,
        "munmap_count": p.munmap_count,
        "oom_detected": p.oom_detected,
        "oom_message": p.oom_message,
    }

    # атрибуция нагрузки (кто потребляет ресурсы)
    data["load"] = load.load_report_data(p)

    # WordPress
    if p.wordpress:
        wp_issues = wp.diagnose(p)
        data["wordpress"] = {
            "version": p.wp_version,
            "php": p.wp_php_version_hint,
            "theme": p.wp_active_theme,
            "abspath": p.wp_abspath,
            "issues": [{"severity": sev, "message": msg} for sev, msg in wp_issues],
        }

    return data


def write_json_report(p, outdir):
    """Пишет report.json в outdir, возвращает путь к файлу."""
    return write_json_to(p, os.path.join(outdir, "report.json"))


def write_json_to(p, path):
    """Пишет JSON-отчёт в указанный путь, возвращает его."""
    data = build_json(p)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    return path
