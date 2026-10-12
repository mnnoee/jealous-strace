"""Атрибуция нагрузки: кто потребляет ресурсы.

strace не измеряет CPU напрямую (не видно времени ВНУТРИ пользовательского кода),
поэтому даём честные верхнеуровневые оценки:

  - kernel  — суммарное время внутри syscall (включая блокировки)
  - blocking— время в блокирующих ожиданиях (accept/poll/select/... = НЕ CPU, это простой)
  - cpu_est — время процесса ВНЕ блокирующих ожиданий = пользовательский код (PHP)
              + короткие вызовы. Это и есть главный индикатор "кто жрёт CPU".

Плюс: число syscall/сек (активность), атрибуция по HTTP-запросам (какая страница),
по компонентам WP (какой плагин) и пиковые секунды.
"""

import datetime as _dt

from .wp import classify_wp_component

BLOCKING = {
    "accept", "accept4", "poll", "ppoll", "select", "pselect6",
    "epoll_wait", "epoll_pwait", "futex", "nanosleep", "clock_nanosleep",
    "wait4", "waitid", "mq_timedreceive",
    "read", "pread64", "preadv", "recv", "recvfrom", "recvmsg", "recvmmsg",
}

PATH_SYSCALLS = {
    "openat", "open", "creat", "stat", "lstat", "newfstatat", "statx",
    "access", "faccessat",
}


def _t(ts):
    if isinstance(ts, _dt.datetime):
        return ts.timestamp()
    return ts or 0.0


def per_pid(p):
    """Помесячная сводка по PID из аудит-трейла syscall_events."""
    agg = {}
    for ev in p.syscall_events:
        pid = ev["pid"]
        a = agg.get(pid)
        if a is None:
            a = {"count": 0, "first": _t(ev["ts"]), "last": _t(ev["ts"]),
                 "kernel": 0.0, "blocking": 0.0, "names": {}}
            agg[pid] = a
        t = _t(ev["ts"])
        a["count"] += 1
        a["first"] = min(a["first"], t)
        a["last"] = max(a["last"], t)
        d = ev["dur"]
        if d:
            a["kernel"] += d
            if ev["name"] in BLOCKING:
                a["blocking"] += d
        a["names"][ev["name"]] = a["names"].get(ev["name"], 0) + 1
    res = []
    for pid, a in agg.items():
        wall = max(0.0, a["last"] - a["first"])
        res.append({
            "pid": pid,
            "count": a["count"],
            "wall": round(wall, 3),
            "kernel": round(a["kernel"], 3),
            "blocking": round(a["blocking"], 3),
            "cpu": round(max(0.0, wall - a["blocking"]), 3),
            "rate": round(a["count"] / wall, 1) if wall > 0 else 0.0,
            "top": max(a["names"].items(), key=lambda x: x[1])[0] if a["names"] else None,
        })
    res.sort(key=lambda r: r["cpu"], reverse=True)
    return res


def per_request(p):
    """Сколько syscall и estimated-CPU приходится на каждый HTTP-запрос."""
    rows = []
    for r in p.http_requests:
        if not r.get("start") or not r.get("end") or r.get("pid") is None:
            continue
        pid = r["pid"]
        t0, t1 = _t(r["start"]), _t(r["end"])
        cnt = kern = block = 0
        names = {}
        comps = {}
        for ev in p.syscall_events:
            if ev["pid"] != pid:
                continue
            t = _t(ev["ts"])
            if not (t0 <= t <= t1):
                continue
            if ev["name"] in ("accept", "accept4"):
                continue  # ожидание соединения ДО начала запроса
            cnt += 1
            d = ev["dur"]
            if d:
                kern += d
                if ev["name"] in BLOCKING:
                    block += d
            names[ev["name"]] = names.get(ev["name"], 0) + 1
            if ev["path"]:
                comp = classify_wp_component(ev["path"])
                comps[comp] = comps.get(comp, 0) + 1
        dur = max(0.0, t1 - t0)
        rows.append({
            "pid": pid,
            "method": r.get("method"),
            "uri": r.get("uri"),
            "host": r.get("host"),
            "status": r.get("status"),
            "dur": round(dur, 3),
            "count": cnt,
            "rate": round(cnt / dur, 1) if dur > 0 else 0.0,
            "kernel": round(kern, 3),
            "blocking": round(block, 3),
            "cpu": round(max(0.0, dur - block), 3) if cnt else 0.0,
            "top": max(names.items(), key=lambda x: x[1])[0] if names else None,
            "components": comps,
        })
    rows.sort(key=lambda r: (r["cpu"], r["count"]), reverse=True)
    return rows


def peak_seconds(p, top=10):
    """Секунды максимальной глобальной активности (syscall/сек) + топ PID в них."""
    bins = {}
    for ev in p.syscall_events:
        b = int(_t(ev["ts"]))
        if b <= 0:
            continue
        d = bins.get(b)
        if d is None:
            d = {"count": 0, "pids": {}}
            bins[b] = d
        d["count"] += 1
        d["pids"][ev["pid"]] = d["pids"].get(ev["pid"], 0) + 1
    out = []
    for b, d in sorted(bins.items(), key=lambda kv: kv[1]["count"], reverse=True)[:top]:
        top_pid, top_cnt = max(d["pids"].items(), key=lambda x: x[1])
        out.append({"second": b, "count": d["count"],
                    "pid": top_pid, "pid_count": top_cnt,
                    "pids_count": len(d["pids"])})
    return out


def _fmt_pid_rows(w, rows, limit):
    if not rows:
        return
    w("  PID   вызовы  wall,с  kernel,с  block,с   CPU~,с  вызов/сек  топ-syscall")
    for r in rows[:limit]:
        w("  {pid:>6}  {count:>7}  {wall:>6.1f}  {kernel:>7.1f}  {block:>7.1f}  "
          "{cpu:>7.1f}  {rate:>9.1f}  {top}".format(
              pid=r["pid"], count=r["count"], wall=r["wall"],
              kernel=r["kernel"], block=r["blocking"], cpu=r["cpu"],
              rate=r["rate"], top=r["top"] or "-"))


def report_section(p, w, top_pid=10, top_requests=8):
    evs = getattr(p, "syscall_events", None)
    if not evs:
        return
    w("--- НАГРУЗКА: КТО ПОТРЕБЛЯЕТ РЕСУРСЫ (оценка) ---")
    w("kernel=время внутри syscall, block=ожидание (accept/poll/read/recv/...), "
      "CPU~=время вне ожиданий (пользовательский код). strace НЕ видит CPU внутри PHP.")
    per = per_pid(p)
    if per:
        w("По PID:")
        _fmt_pid_rows(w, per, top_pid)
    reqs = per_request(p)
    if reqs:
        w("По HTTP-запросам (топ по CPU~):")
        w("  URI (метод status): dur,с | вызовы | вызов/сек | CPU~,с | kernel,с | top-syscall")
        for r in reqs[:top_requests]:
            line = f"  {r['method']} {r['uri']} {r['status']}: " \
                   f"{r['dur']}с | {r['count']} | {r['rate']} | {r['cpu']}с | " \
                   f"{r['kernel']}с | {r['top'] or '-'}"
            w(line)
        # компоненты самого нагрузочного запроса
        top = reqs[0]
        if top["components"]:
            w("Компоненты WP в самом `CPU-тяжёлом` запросе "
              f"{top['method']} {top['uri']} (по числу syscall):")
            for comp, n in sorted(top["components"].items(), key=lambda x: x[1], reverse=True)[:8]:
                w(f"    {comp}: {n}")
    peaks = peak_seconds(p, top=5)
    if peaks:
        w("Пиковые секунды (максимум syscall/сек):")
        for pk in peaks:
            ts = _dt.datetime.fromtimestamp(pk["second"]).strftime("%H:%M:%S") \
                if pk["second"] else str(pk["second"])
            w(f"  {ts}: {pk['count']} syscall, топ pid={pk['pid']} "
              f"({pk['pid_count']}, процессов в секунду: {pk['pids_count']})")
    w("")


def load_report_data(p):
    """Данные для JSON: плоские (datetime пишется default=str, но здесь отдаём числа)."""
    return {
        "per_pid": per_pid(p),
        "per_request": per_request(p),
        "peak_seconds": peak_seconds(p),
    }
