"""Запись CSV-файлов из собранных данных StraceParser."""

import csv
import os

from . import constants as ct

try:
    from . import phpmail
except Exception:  # pragma: no cover
    phpmail = None


def write_csvs(p, outdir):
    os.makedirs(outdir, exist_ok=True)

    # syscalls.csv
    with open(os.path.join(outdir, "syscalls.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["syscall", "count", "errors", "total_time_s", "avg_time_s", "max_time_s"])
        for name, cnt in p.syscalls.most_common():
            times = p.syscall_time[name]
            tsum = sum(times) if times else 0
            tavg = tsum / len(times) if times else 0
            tmax = max(times) if times else 0
            writer.writerow([name, cnt, p.syscall_err_count[name], round(tsum, 6), round(tavg, 6), round(tmax, 6)])

    # errors.csv
    with open(os.path.join(outdir, "errors.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["pid", "ts", "syscall", "args", "ret", "errno", "file"])
        for pid, ts, name, args, ret, errno, fname in p.errors_list:
            writer.writerow([pid, ts.strftime("%H:%M:%S") if ts else "", name, args, ret, errno, fname])

    # files.csv
    with open(os.path.join(outdir, "files.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "openat", "open", "read", "write", "fstat", "read_bytes", "write_bytes", "enonent"])
        for path, ops in p.files.items():
            writer.writerow([path, ops.get("openat", 0), ops.get("open", 0), ops.get("read", 0),
                             ops.get("write", 0), ops.get("fstat", 0),
                             p.file_bytes[path].get("read", 0), p.file_bytes[path].get("write", 0),
                             p.open_missing.get(path, 0)])

    # network.csv
    with open(os.path.join(outdir, "network.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["pid", "ts", "fd", "family", "ip", "port", "path", "ret", "errno", "dur"])
        for c in p.connects:
            ep = c["endpoint"] or {}
            writer.writerow([c["pid"], c["ts"].strftime("%H:%M:%S") if c["ts"] else "", c["fd"],
                             ep.get("family"), ep.get("ip"), ep.get("port"), ep.get("path"),
                             c["ret"], c["errno"], c["dur"]])

    # dns.csv
    with open(os.path.join(outdir, "dns.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ts", "pid", "qname", "type", "rcode", "status"])
        for q in p.dns_queries:
            writer.writerow([q["ts"].strftime("%H:%M:%S") if q["ts"] else "", q["pid"],
                             q["qname"], q["type"], ct.RCODE_NAMES.get(q["rcode"], q["rcode"]) if q["rcode"] is not None else "",
                             q["status"]])

    # sql.csv
    with open(os.path.join(outdir, "sql.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ts", "pid", "server", "sql"])
        for q in p.sql_queries:
            writer.writerow([q["ts"].strftime("%H:%M:%S") if q["ts"] else "", q["pid"], q["server"], q["sql"]])

    # http.csv
    with open(os.path.join(outdir, "http.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["start", "end", "pid", "fd", "host", "method", "uri", "query", "referer", "ua", "status", "location", "duration_s"])
        for r in p.http_requests:
            dur = (r["end"] - r["start"]).total_seconds() if r.get("start") and r.get("end") and r["end"] > r["start"] else ""
            writer.writerow([r["start"].strftime("%H:%M:%S.%f") if r.get("start") else "",
                             r["end"].strftime("%H:%M:%S.%f") if r.get("end") else "",
                             r["pid"], r["fd"], r.get("host"), r.get("method"), r.get("uri"),
                             r.get("query"), r.get("referer"), r.get("ua"), r.get("status"),
                             r.get("location"), f"{dur:.6f}" if dur != "" else ""])

    # pids.csv
    with open(os.path.join(outdir, "pids.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["pid", "syscalls", "errors", "start", "end", "exit_code"])
        for pid, st in sorted(p.pid_stats.items(), key=lambda kv: kv[1]["count"], reverse=True):
            writer.writerow([pid, st["count"], st["err"],
                             st["start"].strftime("%H:%M:%S") if st["start"] else "",
                             st["end"].strftime("%H:%M:%S") if st["end"] else "",
                             p.exited_pids.get(pid, "")])

    # slow.csv
    with open(os.path.join(outdir, "slow.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["pid", "ts", "syscall", "args", "dur", "file"])
        for pid, ts, name, args, dur, fname in p.slow_calls:
            writer.writerow([pid, ts.strftime("%H:%M:%S") if ts else "", name, args, f"{dur:.6f}", fname])

    # unfinished.csv
    with open(os.path.join(outdir, "unfinished.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["pid", "ts", "syscall", "file"])
        for pid, name, ts, fname, _ in p.unfinished_open:
            writer.writerow([pid, ts.strftime("%H:%M:%S") if ts else "", name, fname])

    # mail.csv (PHP mail)
    if phpmail is not None:
        phpmail.write_csv(p, outdir)

    # access.csv
    if p.access_entries:
        with open(os.path.join(outdir, "access.csv"), "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "time", "vhost", "method", "uri", "proto", "status", "bytes", "referer", "ua"])
            for a in p.access_entries:
                writer.writerow([a["ip"], a["time"], a["vhost"], a["method"], a["uri"],
                                 a["proto"], a["status"], a["bytes"], a["referer"], a["ua"]])
