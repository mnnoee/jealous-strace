"""Анализ отправки почты по SMTP"""

import re

from .i18n import t
from .mtls import SNI_TLD_RE

SMTP_PORTS = {25, 465, 587}
SMTP_LIB_RE = re.compile(
    r"(phpmailer|swiftmailer|symfony[/\\]mailer|zend[/\\]mail|class\.smtp\.php|"
    r"mailer[/\\]smtp|smtp\.php)",
    re.I,
)
COMMAND_RE = re.compile(r"^(EHLO|HELO|MAIL FROM|RCPT TO|DATA|AUTH|STARTTLS|QUIT|RSET)\b", re.I)
CODE_RE = re.compile(r"^(\d{3})[ -]")


def _sni_from_hello(data):
    """SNI из TLS ClientHello (extension server_name), с regex-фолбэком."""
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            raise ValueError
        pos = 5 + 4 + 2 + 32
        sid_len = data[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cs_len
        cm_len = data[pos]
        pos += 1 + cm_len
        ext_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(len(data), pos + ext_len)
        while pos + 4 <= end:
            etype = int.from_bytes(data[pos:pos + 2], "big")
            elen = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0:
                q = pos + 2
                nlen = int.from_bytes(data[q + 1:q + 3], "big")
                return data[q + 3:q + 3 + nlen].decode("ascii", "replace")
            pos += elen
    except (IndexError, ValueError):
        pass
    m = SNI_TLD_RE.search(data)
    return m.group(0).decode("utf-8", "replace") if m else None


def is_smtp_lib(path):
    return bool(SMTP_LIB_RE.search(path or ""))


def record_lib(p, pid, path):
    if is_smtp_lib(path):
        p.smtp_lib[pid] = True


def record_connect(p, pid, ts, endpoint, ret, errno, fd):
    if not endpoint or fd is None:
        return
    port = endpoint.get("port")
    if port not in SMTP_PORTS:
        return
    session = {
        "pid": pid, "fd": fd, "ts": ts, "ip": endpoint.get("ip"),
        "port": port, "sni": None, "tls": port == 465,
        "starttls": False, "bytes_out": 0, "bytes_in": 0,
        "status": "ok" if ret == "0" else "pending",
        "error": errno, "codes": [], "mail_from": None,
        "rcpt": [], "auth": False, "saw_data": False,
        "library": bool(p.smtp_lib.get(pid)),
    }
    p.smtp_sessions.append(session)
    p.smtp_current[(pid, fd)] = session


def record_so_error(p, pid, fd, value):
    session = p.smtp_current.get((pid, fd))
    if not session:
        return
    if value == "0":
        session["status"] = "ok"
        session["error"] = None
    elif value:
        session["status"] = "failed"
        session["error"] = value


def record_close(p, pid, fd, ts):
    session = p.smtp_current.pop((pid, fd), None)
    if session and session["status"] == "pending":
        session["status"] = "closed"


def record_write(p, pid, fd, data, nbytes, ts):
    session = p.smtp_current.get((pid, fd))
    if not session or not data:
        return
    size = nbytes if nbytes is not None else len(data)
    session["bytes_out"] += size
    if data.startswith(b"\x16\x03"):
        session["tls"] = True
        if not session["sni"]:
            session["sni"] = _sni_from_hello(data)
        return
    if session["tls"]:
        return
    if session["port"] == 465:
        return
    text = data.decode("utf-8", "replace")
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        m = COMMAND_RE.match(line)
        if not m:
            continue
        cmd = m.group(1).upper()
        if cmd == "STARTTLS":
            session["starttls"] = True
        elif cmd == "AUTH":
            session["auth"] = True
        elif cmd == "DATA":
            session["saw_data"] = True
        elif cmd.startswith("MAIL FROM"):
            session["mail_from"] = line.split(":", 1)[1].strip(" <>") or None
        elif cmd.startswith("RCPT TO"):
            addr = line.split(":", 1)[1].strip(" <>")
            if addr:
                session["rcpt"].append(addr)
        if session["starttls"]:
            session["tls"] = True


def record_read(p, pid, fd, data, nbytes, ts):
    session = p.smtp_current.get((pid, fd))
    if not session or not data:
        return
    session["bytes_in"] += nbytes if nbytes is not None else len(data)
    if session["tls"]:
        return
    text = data.decode("utf-8", "replace")
    for line in text.replace("\r\n", "\n").split("\n"):
        m = CODE_RE.match(line.strip())
        if m:
            session["codes"].append(int(m.group(1)))


def result(session):
    codes = session.get("codes") or []
    if session.get("status") == "failed":
        return "failed"
    if any(c in (530, 534, 535) for c in codes):
        return "auth_failed"
    if any(500 <= c < 600 for c in codes) and not session.get("saw_data"):
        return "failed"
    if session.get("rcpt") and session.get("saw_data"):
        return "sent"
    if session.get("tls") and session.get("bytes_out", 0) > 0:
        return "sent_tls"
    if session.get("rcpt"):
        return "accepted"
    return "unknown"


def target(session):
    return f"{session.get('ip') or '?'}:{session.get('port') or '?'}"


def report_section(p, w):
    if not getattr(p, "mail_body", False):
        return
    sessions = getattr(p, "smtp_sessions", None) or []
    if not sessions:
        return
    w(t("smtp.title"))
    for s in sessions:
        stamp = s["ts"].strftime("%H:%M:%S") if s.get("ts") else "?"
        tls_state = t("smtp.tls") if s.get("tls") else t("smtp.plain")
        sni = t("smtp.sni", v=s["sni"]) if s.get("sni") else ""
        lib = t("smtp.lib", v="PHPMailer") if s.get("library") else ""
        w(t("smtp.line", ts=stamp, pid=s.get("pid"), target=target(s),
            tls=tls_state, result=t("smtp." + result(s)), sni=sni, lib=lib))
        if s.get("mail_from"):
            w(t("smtp.from", v=s["mail_from"]))
        for addr in s.get("rcpt") or []:
            w(t("smtp.to", v=addr))
        if s.get("auth"):
            w(t("smtp.auth"))
        for code in s.get("codes") or []:
            if code >= 400:
                w(t("smtp.error", code=code))


def write_csv(p, outdir):
    import csv
    import os
    sessions = getattr(p, "smtp_sessions", None) or []
    if not sessions:
        return
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "smtp.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ts", "pid", "ip", "port", "sni", "tls", "starttls", "status", "result",
            "bytes_out", "bytes_in", "library", "mail_from", "rcpt", "auth", "codes", "error",
        ])
        for s in sessions:
            writer.writerow([
                s["ts"].strftime("%Y-%m-%d %H:%M:%S") if s.get("ts") else "",
                s.get("pid"),
                s.get("ip"),
                s.get("port"),
                s.get("sni") or "",
                int(bool(s.get("tls"))),
                int(bool(s.get("starttls"))),
                s.get("status") or "",
                result(s),
                s.get("bytes_out", 0),
                s.get("bytes_in", 0),
                int(bool(s.get("library"))),
                s.get("mail_from") or "",
                "; ".join(s.get("rcpt") or []),
                int(bool(s.get("auth"))),
                ",".join(str(c) for c in s.get("codes") or []),
                s.get("error") or "",
            ])


def build_json(p):
    sessions = getattr(p, "smtp_sessions", None) or []
    out = []
    for s in sessions:
        item = dict(s)
        item["ts"] = s["ts"].isoformat() if s.get("ts") else None
        item["result"] = result(s)
        out.append(item)
    return {"count": len(out), "sessions": out}


def detect(p):
    """Сигнатуры проблем SMTP."""
    issues = []
    for s in getattr(p, "smtp_sessions", None) or []:
        codes = s.get("codes") or []
        if any(c in (530, 534, 535) for c in codes):
            code = next(c for c in codes if c in (530, 534, 535))
            issues.append(("ERROR", t("sig.smtp_auth", target=target(s), code=code)))
        elif any(500 <= c < 600 for c in codes):
            code = next(c for c in codes if 500 <= c < 600)
            issues.append(("WARNING", t("sig.smtp_reject", target=target(s), code=code)))
        if s.get("status") == "failed":
            issues.append(("WARNING", t("sig.smtp_connect", target=target(s),
                                        err=s.get("error") or "?")))
    return issues
