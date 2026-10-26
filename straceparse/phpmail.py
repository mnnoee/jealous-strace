import ast
import re

MAILLOG_RE = re.compile(
    r"mail\(\)\s+on\s+\[(.*?):(\d+)\]:\s*To:\s*(.*?)\s*--\s*Headers:\s*(.*?)\s*--\s*Subject:\s*(.*?)(?:\\n|$)",
    re.S | re.I,
)

HEADER_NAMES = ("From", "Reply-To", "Content-Type", "X-Mailer")


def _ensure_state(p):
    if not hasattr(p, "mail_sends"):
        p.mail_sends = []
    if not hasattr(p, "_pipe_creators"):
        p._pipe_creators = {}
    if not hasattr(p, "_pipe_child"):
        p._pipe_child = {}
    if not hasattr(p, "_child_pipe"):
        p._child_pipe = {}


def _to_bytes(data):
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8", "replace")
    return b""


def _to_text(data):
    return _to_bytes(data).decode("utf-8", "replace")


def _parse_headers(headers_str):
    res = {}
    s = headers_str or ""
    for name in HEADER_NAMES:
        pat = re.compile(
            rf"{re.escape(name)}:\s*(.*?)(?=\s{{2,}}(?:{'|'.join(re.escape(h) for h in HEADER_NAMES)}):|$)",
            re.I | re.S,
        )
        m = pat.search(s)
        if m:
            res[name.lower().replace("-", "_")] = m.group(1).strip()
    out = {}
    if "from" in res:
        out["from"] = res["from"]
    if "reply_to" in res:
        out["reply-to"] = res["reply_to"]
    if "content_type" in res:
        out["content-type"] = res["content_type"]
    if "x_mailer" in res:
        out["x-mailer"] = res["x_mailer"]
    return out


def _parse_rfc822(raw_bytes):
    text = raw_bytes.decode("utf-8", "replace")
    sep = "\r\n\r\n"
    if sep not in text:
        sep = "\n\n"
    if sep in text:
        head, body = text.split(sep, 1)
    else:
        head, body = text, ""
    headers = {}
    for line in head.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers, body


def _find_record(p, parent_pid=None, pipe_inode=None, child_pid=None,
                 recipient=None, subject=None, ts=None):
    _ensure_state(p)
    for rec in reversed(p.mail_sends):
        if child_pid is not None and rec.get("child_pid") == child_pid:
            return rec
        if pipe_inode is not None and rec.get("pipe_inode") == pipe_inode:
            return rec
        if parent_pid is not None and rec.get("parent_pid") == parent_pid:
            if ts is not None and rec.get("ts") is not None:
                try:
                    delta = abs((ts - rec["ts"]).total_seconds())
                except Exception:
                    delta = 0
                if delta > 15:
                    continue
            if recipient and rec.get("recipient") and recipient != rec["recipient"]:
                continue
            if subject and rec.get("subject") and subject != rec["subject"]:
                continue
            return rec
    if (parent_pid is None and pipe_inode is None and child_pid is None
            and ts is not None):
        for rec in reversed(p.mail_sends):
            if rec.get("child_pid") is not None:
                continue
            if rec.get("ts") is None:
                continue
            try:
                delta = abs((ts - rec["ts"]).total_seconds())
            except Exception:
                delta = 0
            if delta <= 15:
                return rec
    return None


def _new_record(p, ts, parent_pid=None, source=None):
    _ensure_state(p)
    rec = {
        "ts": ts,
        "parent_pid": parent_pid,
        "child_pid": None,
        "pipe_inode": None,
        "recipient": None,
        "sender": None,
        "envelope_sender": None,
        "subject": None,
        "reply_to": None,
        "content_type": None,
        "x_mailer": None,
        "script": None,
        "script_line": None,
        "command": None,
        "exec_ts": None,
        "exec_bin": None,
        "delivery_exit_code": None,
        "wait_ts": None,
        "duration_sec": None,
        "body": None,
        "body_size": None,
        "maillog_path": None,
        "source": list(source or []),
        "file": None,
    }
    p.mail_sends.append(rec)
    return rec


def maybe_record_maillog(p, pid, ts, data, path, filename):
    if not getattr(p, "mail", False):
        return
    _ensure_state(p)
    text = _to_text(data)
    m = MAILLOG_RE.search(text)
    if not m:
        return
    script = m.group(1).strip()
    try:
        line_no = int(m.group(2))
    except (ValueError, TypeError):
        line_no = None
    recipient = m.group(3).strip()
    headers_str = m.group(4).strip()
    subject = m.group(5).strip()
    hdrs = _parse_headers(headers_str)

    rec = _find_record(p, parent_pid=pid, recipient=recipient, subject=subject, ts=ts)
    if rec is None:
        rec = _new_record(p, ts, parent_pid=pid, source=["mail.log"])
    if "mail.log" not in rec["source"]:
        rec["source"].append("mail.log")
    rec["ts"] = rec["ts"] or ts
    rec["parent_pid"] = rec["parent_pid"] or pid
    rec["recipient"] = recipient or rec["recipient"]
    rec["subject"] = subject or rec["subject"]
    rec["script"] = script or rec["script"]
    rec["script_line"] = line_no if line_no is not None else rec["script_line"]
    rec["maillog_path"] = path or rec["maillog_path"]
    rec["file"] = rec["file"] or filename
    if "from" in hdrs:
        rec["sender"] = hdrs["from"]
    if "reply-to" in hdrs:
        rec["reply_to"] = hdrs["reply-to"]
    if "content-type" in hdrs:
        rec["content_type"] = hdrs["content-type"]
    if "x-mailer" in hdrs:
        rec["x_mailer"] = hdrs["x-mailer"]


def maybe_record_pipe(p, pid, ts, args, filename):
    if not getattr(p, "mail", False):
        return
    _ensure_state(p)
    pairs = re.findall(r"(\d+)<pipe:\[(\d+)\]>", args or "")
    if not pairs:
        return
    inode = int(pairs[0][1])
    read_fd = int(pairs[0][0])
    write_fd = int(pairs[1][0]) if len(pairs) > 1 else None
    inodes = {int(x[1]) for x in pairs}
    if len(inodes) == 1:
        p._pipe_creators[inode] = {
            "parent_pid": pid,
            "ts": ts,
            "read_fd": read_fd,
            "write_fd": write_fd,
            "file": filename,
        }


def maybe_record_dup2(p, pid, ts, args, filename):
    if not getattr(p, "mail", False):
        return
    _ensure_state(p)
    m = re.search(r"dup2\((\d+)<pipe:\[(\d+)\]>", args or "")
    if not m:
        return
    inode = int(m.group(2))
    p._pipe_child[inode] = pid
    p._child_pipe[pid] = inode


def maybe_record_execve(p, pid, ts, args, filename):
    if not getattr(p, "mail", False):
        return
    _ensure_state(p)
    a = (args or "").strip()
    m = re.match(r'^execve\("([^"]*)",\s*\[(.*)\],\s*\[(.*)\]\)$', a)
    if not m:
        return
    binpath = m.group(1)
    argv_str = m.group(2)
    env_str = m.group(3)
    try:
        argv = ast.literal_eval("[" + argv_str + "]")
    except Exception:
        argv = [x.strip().strip('"') for x in argv_str.split(",")]
    haystack = " ".join([binpath] + [str(x) for x in argv] + [env_str])
    is_mail = any(tok in haystack.lower() for tok in ("sendmail", "postfix", "exim"))
    cmd = None
    if binpath.endswith("sh") and "-c" in argv:
        try:
            ci = argv.index("-c")
            if ci + 1 < len(argv):
                cmd = argv[ci + 1]
        except ValueError:
            pass
        if cmd and any(tok in str(cmd).lower() for tok in ("sendmail", "postfix", "exim")):
            is_mail = True
    if not is_mail:
        return
    if cmd is None:
        cmd = " ".join(str(x) for x in argv)

    envelope = None
    for i, x in enumerate(argv):
        if x == "-f" and i + 1 < len(argv):
            envelope = argv[i + 1]

    pipe_inode = p._child_pipe.get(pid)
    parent_pid = None
    if pipe_inode is not None:
        creator = p._pipe_creators.get(pipe_inode)
        if creator:
            parent_pid = creator["parent_pid"]

    rec = _find_record(p, child_pid=pid, pipe_inode=pipe_inode,
                       parent_pid=parent_pid, ts=ts)
    if rec is None:
        rec = _new_record(p, ts, parent_pid=parent_pid, source=["execve"])
    if "execve" not in rec["source"]:
        rec["source"].append("execve")
    rec["child_pid"] = pid
    if pipe_inode is not None:
        rec["pipe_inode"] = pipe_inode
    if parent_pid is not None:
        rec["parent_pid"] = rec["parent_pid"] or parent_pid
    rec["exec_ts"] = ts
    rec["exec_bin"] = binpath
    rec["command"] = cmd
    if envelope is not None:
        rec["envelope_sender"] = envelope
    rec["file"] = rec["file"] or filename
    if rec["ts"] is None:
        rec["ts"] = ts


def maybe_record_pipe_email(p, pid, ts, fdnum, data, filename):
    if not getattr(p, "mail", False):
        return
    _ensure_state(p)
    raw = _to_bytes(data)
    if b"To:" not in raw or b"Subject:" not in raw or b"From:" not in raw:
        return
    headers, body = _parse_rfc822(raw)
    recipient = headers.get("to")
    subject = headers.get("subject")
    sender = headers.get("from")

    pipe_inode = None
    for inode, creator in p._pipe_creators.items():
        if creator.get("parent_pid") == pid:
            cts = creator.get("ts")
            if cts is None or ts is None or abs((ts - cts).total_seconds()) <= 15:
                pipe_inode = inode
                break

    rec = _find_record(p, parent_pid=pid, pipe_inode=pipe_inode,
                       recipient=recipient, subject=subject, ts=ts)
    if rec is None:
        rec = _new_record(p, ts, parent_pid=pid, source=["pipe"])
    if "pipe" not in rec["source"]:
        rec["source"].append("pipe")
    rec["parent_pid"] = rec["parent_pid"] or pid
    rec["ts"] = rec["ts"] or ts
    rec["pipe_inode"] = rec["pipe_inode"] or pipe_inode
    if recipient:
        rec["recipient"] = recipient
    if subject:
        rec["subject"] = subject
    if sender:
        rec["sender"] = sender
    if headers.get("reply-to"):
        rec["reply_to"] = headers.get("reply-to")
    if headers.get("content-type"):
        rec["content_type"] = headers.get("content-type")
    if headers.get("x-mailer"):
        rec["x_mailer"] = headers.get("x-mailer")
    rec["body_size"] = len(raw)
    if getattr(p, "mail_body", False):
        rec["body"] = body.strip() if body and body.strip() else None
    rec["file"] = rec["file"] or filename


def maybe_record_wait4(p, pid, ts, args, ret, filename):
    if not getattr(p, "mail", False):
        return
    _ensure_state(p)
    child_pid = None
    if isinstance(ret, str) and ret.isdigit():
        child_pid = int(ret)
    if child_pid is None:
        m = re.match(r"wait4\((\d+)", args or "")
        if m:
            try:
                val = int(m.group(1))
                if val > 0:
                    child_pid = val
            except ValueError:
                pass
    if child_pid is None:
        return
    exit_code = None
    m = re.search(r"WEXITSTATUS\(s\)\s*==\s*(\d+)", args or "")
    if m:
        exit_code = int(m.group(1))

    rec = _find_record(p, child_pid=child_pid, ts=ts)
    if rec is None:
        rec = _find_record(p, parent_pid=pid, ts=ts)
    if rec is None:
        return
    rec["child_pid"] = rec["child_pid"] or child_pid
    rec["wait_ts"] = ts
    if exit_code is not None:
        rec["delivery_exit_code"] = exit_code
    if rec.get("parent_pid") is None:
        rec["parent_pid"] = pid
    if rec.get("exec_ts") is not None and ts is not None:
        try:
            rec["duration_sec"] = round((ts - rec["exec_ts"]).total_seconds(), 6)
        except Exception:
            pass
    rec["file"] = rec["file"] or filename


def detect(p):
    _ensure_state(p)
    out = []
    sends = getattr(p, "mail_sends", []) or []
    if not sends:
        return out
    for rec in sends:
        recipient = rec.get("recipient") or "?"
        subject = rec.get("subject") or "?"
        script = ""
        if rec.get("script"):
            script = f"{rec['script']}:{rec.get('script_line')}"
        out.append(("INFO", f"Отправка PHP mail(): To={recipient} Subject={subject[:80]} script={script or '?'}"))
        code = rec.get("delivery_exit_code")
        if code is not None and code != 0:
            out.append(("ERROR", f"Неудачная доставка PHP mail() (sendmail exit code {code}): To={recipient} Subject={subject[:80]}"))
        env = rec.get("envelope_sender")
        sender = rec.get("sender")
        if env and sender:
            from_addr = sender
            m = re.search(r"<([^>]+)>", sender)
            if m:
                from_addr = m.group(1)
            if env != from_addr:
                out.append(("WARNING", f"Несовпадение отправителя PHP mail(): envelope={env} vs From={sender}"))
    if len(sends) >= 5:
        out.append(("WARNING", f"Массовая отправка PHP mail(): {len(sends)} писем за анализируемый период."))
    return out


def report_section(p, w):
    _ensure_state(p)
    w("\n--- PHP mail() / ОТПРАВКА ПОЧТЫ ---")
    sends = getattr(p, "mail_sends", []) or []
    if not sends:
        w("  Отправки почты не обнаружены.")
        if getattr(p, "mail_body", False):
            w("  Не обнаружено сигнатур.")
        w("")
        return
    w(f"  Обнаружено отправок: {len(sends)}")
    w(f"  {'Время':<20}{'PID':>8}  {'Получатель':<28}  {'От кого':<26}  {'Тема':<30}")
    for rec in sorted(sends, key=lambda r: (r.get("ts") is None, r.get("ts") or __import__("datetime").datetime.min)):
        ts = rec["ts"].strftime("%Y-%m-%d %H:%M:%S") if rec.get("ts") else "?"
        sender = str(rec.get("sender") or "?")
        env = rec.get("envelope_sender")
        if env and env != sender:
            sender = sender + " *"
        w(f"  {ts:<20}{str(rec.get('parent_pid') or '?'):>8}  "
          f"{str(rec.get('recipient') or '?')[:28]:<28}  {sender[:26]:<26}  {str(rec.get('subject') or '?')[:30]}")
    if any((r.get("envelope_sender") and r.get("sender") and r.get("envelope_sender") != r.get("sender")) for r in sends):
        w("  * — отправитель From отличается от envelope (-f) sendmail")
    if not getattr(p, "mail_body", False):
        w("")
        return
    for i, rec in enumerate(sorted(sends, key=lambda r: (r.get("ts") is None, r.get("ts") or __import__("datetime").datetime.min)), 1):
        w(f"\n  Отправка #{i}:")
        ts = rec["ts"].strftime("%Y-%m-%d %H:%M:%S") if rec.get("ts") else "?"
        w(f"    Время: {ts}")
        w(f"    PID процесса: {rec.get('parent_pid')}, дочерний (sendmail): {rec.get('child_pid')}")
        w(f"    Получатель: {rec.get('recipient')}")
        w(f"    Отправитель (From): {rec.get('sender')}")
        w(f"    Envelope (-f): {rec.get('envelope_sender')}")
        w(f"    Тема: {rec.get('subject')}")
        w(f"    Reply-To: {rec.get('reply_to')}")
        w(f"    Content-Type: {rec.get('content_type')}")
        w(f"    X-Mailer: {rec.get('x_mailer')}")
        script = rec.get("script")
        if script:
            w(f"    Скрипт: {script}:{rec.get('script_line')}")
        if rec.get("command"):
            w(f"    Команда: {rec.get('command')}")
        w(f"    Статус доставки (exit code sendmail): {rec.get('delivery_exit_code')}")
        if rec.get("duration_sec") is not None:
            w(f"    Длительность: {rec['duration_sec']} с")
        w(f"    Размер письма: {rec.get('body_size')} байт")
        w(f"    Источники: {', '.join(rec.get('source') or [])}")
        if getattr(p, "mail_body", False) and rec.get("body"):
            w("    Тело:")
            for line in str(rec["body"]).splitlines():
                w("      " + line)
    sigs = detect(p)
    if sigs:
        w("\n  Сигнатуры:")
        for sev, msg in sigs:
            w(f"    [{sev}] {msg}")
    else:
        w("\n  Не обнаружено сигнатур.")
    w("")


def build_json(p):
    _ensure_state(p)
    sends = getattr(p, "mail_sends", []) or []
    out = []
    for rec in sends:
        item = {
            "ts": rec["ts"].isoformat() if rec.get("ts") else None,
            "parent_pid": rec.get("parent_pid"),
            "child_pid": rec.get("child_pid"),
            "pipe_inode": rec.get("pipe_inode"),
            "recipient": rec.get("recipient"),
            "sender": rec.get("sender"),
            "envelope_sender": rec.get("envelope_sender"),
            "subject": rec.get("subject"),
            "reply_to": rec.get("reply_to"),
            "content_type": rec.get("content_type"),
            "x_mailer": rec.get("x_mailer"),
            "script": rec.get("script"),
            "script_line": rec.get("script_line"),
            "command": rec.get("command"),
            "exec_bin": rec.get("exec_bin"),
            "exec_ts": rec["exec_ts"].isoformat() if rec.get("exec_ts") else None,
            "delivery_exit_code": rec.get("delivery_exit_code"),
            "wait_ts": rec["wait_ts"].isoformat() if rec.get("wait_ts") else None,
            "duration_sec": rec.get("duration_sec"),
            "body_size": rec.get("body_size"),
            "maillog_path": rec.get("maillog_path"),
            "sources": rec.get("source") or [],
            "file": rec.get("file"),
        }
        if getattr(p, "mail_body", False):
            item["body"] = rec.get("body")
        else:
            item["body"] = None
        out.append(item)
    return {"count": len(sends), "sends": out}


def write_csv(p, outdir):
    import csv
    import os
    _ensure_state(p)
    sends = getattr(p, "mail_sends", []) or []
    if not sends:
        return
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "mail.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ts", "parent_pid", "child_pid", "pipe_inode", "recipient", "sender",
            "envelope_sender", "subject", "reply_to", "content_type", "x_mailer",
            "script", "script_line", "command", "delivery_exit_code", "duration_sec",
            "body_size", "maillog_path", "sources", "file", "body",
        ])
        for rec in sends:
            writer.writerow([
                rec["ts"].strftime("%Y-%m-%d %H:%M:%S") if rec.get("ts") else "",
                rec.get("parent_pid"),
                rec.get("child_pid"),
                rec.get("pipe_inode"),
                rec.get("recipient"),
                rec.get("sender"),
                rec.get("envelope_sender"),
                rec.get("subject"),
                rec.get("reply_to"),
                rec.get("content_type"),
                rec.get("x_mailer"),
                rec.get("script"),
                rec.get("script_line"),
                rec.get("command"),
                rec.get("delivery_exit_code"),
                rec.get("duration_sec"),
                rec.get("body_size"),
                rec.get("maillog_path"),
                ",".join(rec.get("source") or []),
                rec.get("file"),
                rec.get("body") if getattr(p, "mail_body", False) else "",
            ])
