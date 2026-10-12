"""Чистые вспомогательные функции парсинга и форматирования (без состояния)."""

import re

from . import constants as ct


def unescape_strace(s):
    """Преобразует strace-строку с экранированием в байты."""
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch != "\\":
            out.extend(ch.encode("utf-8", "replace"))
            i += 1
            continue
        # backslash
        if i + 1 >= n:
            out.append(0x5C)
            i += 1
            continue
        nxt = s[i + 1]
        if nxt in "01234567":
            m = ct.OCTAL_RE.match(s[i:])
            if m:
                out.append(int(m.group(0)[1:], 8) & 0xFF)
                i += len(m.group(0))
                continue
        if nxt == "x":
            m = ct.HEX_RE.match(s[i:])
            if m:
                out.append(int(m.group(0)[2:], 16) & 0xFF)
                i += len(m.group(0))
                continue
        if nxt in ct.SIMPLE_ESC:
            out.extend(ct.SIMPLE_ESC[nxt].encode("utf-8", "replace"))
            i += 2
            continue
        # неизвестная escape-последовательность - оставить как есть
        out.append(0x5C)
        i += 1
    return bytes(out)


def extract_first_string(args):
    """Вытаскивает первую строку в кавычках из аргументов вызова."""
    m = re.search(r'"((?:[^"\\]|\\.)*)"', args)
    if m:
        return unescape_strace(m.group(1))
    return None


def extract_all_strings(args):
    """Вытаскивает все строки в кавычках."""
    res = []
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', args):
        res.append(unescape_strace(m.group(1)))
    return res


def strip_fd_token(args):
    """Отбрасывает syscall-имя и fd-аннотацию `N<...>`, чтобы остались аргументы.

    С `strace -yy` fd декодируется как `4<UNIX:[...],"/path">, "...", N)`,
    и первая строка в кавычках оказывается путём fd, а не полезной нагрузкой.
    Возвращает хвост аргументов после fd-токена (сама строка-вызов без имени).
    """
    if not args:
        return args
    m = re.match(r"^\w+\((\d+)\s*(<[^)]*?>)?\s*,\s*", args)
    if not m:
        return args
    return args[m.end():]


def payload_first_string(args):
    """Первая строка в кавычках среди аргументов, игнорируя fd-аннотацию."""
    return extract_first_string(strip_fd_token(args))


def payload_all_strings(args):
    """Все строки в кавычках среди аргументов, игнорируя fd-аннотацию."""
    return extract_all_strings(strip_fd_token(args))


def parse_sockaddr(addr_str):
    """Парсит {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}."""
    if not addr_str:
        return None
    fam = re.search(r"sa_family=(\w+)", addr_str)
    family = fam.group(1) if fam else None
    port = re.search(r"htons\((\d+)\)", addr_str)
    ip = re.search(r'inet_addr\("([0-9a-fA-F:.]+)"\)', addr_str)
    ip6 = re.search(r'sin6_addr=\{\{__in6_u=\{\{__u6_addr32=\{((?:0x[0-9a-fA-F]+, )*0x[0-9a-fA-F]+)\}\}\}\}', addr_str)
    sun = re.search(r'sun_path="([^"]*)"', addr_str)
    res = {"family": family}
    if port:
        res["port"] = int(port.group(1))
    if ip:
        res["ip"] = ip.group(1)
    if ip6:
        try:
            parts = [int(x, 16) for x in ip6.group(1).replace("0x", "").replace(",", " ").split()]
            # части могут быть в формате "0x7f000101"
            if len(parts) >= 4:
                b = b"".join(p.to_bytes(4, "big") for p in parts)
                res["ip"] = __import__("ipaddress").ip_address(b).compressed
        except Exception:
            pass
    if sun:
        res["path"] = sun.group(1)
    return res


def parse_fcgi_params(data):
    """Парсит FCGI name-value пары (params), возвращает dict."""
    params = {}
    i = 0
    n = len(data)
    while i + 1 < n:
        b1 = data[i]
        b2 = data[i + 1]
        i += 2
        if b1 & 0x80:
            if i + 3 >= n:
                break
            name_len = ((b1 & 0x7F) << 24) | (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
            i += 3
        else:
            name_len = b1
        if b2 & 0x80:
            if i + 3 >= n:
                break
            val_len = ((b2 & 0x7F) << 24) | (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
            i += 3
        else:
            val_len = b2
        if i + name_len + val_len > n:
            break
        name = data[i:i + name_len].decode("utf-8", "replace")
        value = data[i + name_len:i + name_len + val_len].decode("utf-8", "replace")
        params[name] = value
        i += name_len + val_len
    return params


def extract_status(payload):
    """Ищет HTTP-статус в FCGI/HTTP ответе: 'Status: 302' или 'HTTP/1.1 302'."""
    txt = payload.decode("utf-8", "replace")
    m = re.search(r"Status:\s*(\d{3})", txt)
    if m:
        return int(m.group(1))
    m = re.search(r"HTTP/\d+\.\d+\s+(\d{3})", txt)
    if m:
        return int(m.group(1))
    return None


def extract_location(payload):
    txt = payload.decode("utf-8", "replace")
    m = re.search(r"Location:\s*(\S+)", txt)
    return m.group(1) if m else None


def looks_like_http_response(payload):
    txt = payload.decode("utf-8", "replace")
    return bool(re.search(r"Status:\s*\d{3}", txt) or re.search(r"HTTP/\d+\.\d+\s+\d{3}", txt))


def extract_server_timing(payload):
    """Парсит заголовок Server-Timing (фазы WordPress) из HTTP/FCGI ответа.

    Пример: 'Server-Timing: wp-before-template;dur=1169.49, wp-template;dur=230.07'.
    Возвращает список кортежей (имя_фазы, длительность_мс) или None.
    """
    if not payload:
        return None
    txt = payload.decode("utf-8", "replace")
    m = re.search(r"Server-Timing:\s*([^\r\n]+)", txt, re.I)
    if not m:
        return None
    phases = []
    for part in m.group(1).split(","):
        part = part.strip()
        em = re.match(r"([^;\s]+);\s*dur\s*=\s*([0-9.]+)", part, re.I)
        if em:
            try:
                phases.append((em.group(1), float(em.group(2))))
            except ValueError:
                continue
    return phases or None


def extract_set_cookie(payload):
    """Извлекает Set-Cookie заголовки из HTTP/FCGI ответа.

    Возвращает список dict: {"name", "value", "flags" (list str), "secure" (bool)}.
    """
    if not payload:
        return []
    txt = payload.decode("utf-8", "replace")
    cookies = []
    for m in re.finditer(r"Set-Cookie:\s*([^\r\n]+)", txt, re.I):
        raw = m.group(1).strip()
        parts = raw.split(";")
        name = None
        value = ""
        flags = []
        for i, part in enumerate(parts):
            part = part.strip()
            if not part:
                continue
            if i == 0:
                nv = part.split("=", 1)
                name = nv[0].strip()
                value = nv[1].strip() if len(nv) > 1 else ""
            else:
                flags.append(part.lower())
        if name:
            cookies.append({
                "name": name,
                "value": value,
                "flags": flags,
                "secure": "secure" in flags,
            })
    return cookies


def looks_like_dns_payload(payload):
    # DNS-запрос: первые 12 байт заголовок, потом QNAME
    if len(payload) < 12:
        return False
    return True


def parse_dns_qname(payload):
    """Парсит QNAME из DNS-запроса (первые 12 байт заголовок)."""
    if len(payload) < 12:
        return None
    # формат: ID(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
    qdcount = (payload[4] << 8) | payload[5]
    if qdcount == 0:
        return None
    labels = []
    pos = 12
    while pos < len(payload):
        ln = payload[pos]
        if ln == 0:
            break
        if ln & 0xC0:
            break
        pos += 1
        if pos + ln > len(payload):
            return None
        labels.append(payload[pos:pos + ln].decode("utf-8", "replace"))
        pos += ln
    return ".".join(labels) if labels else None


def parse_dns_rcode(payload):
    """RCODE из DNS-ответа."""
    if len(payload) < 6:
        return None
    flags = (payload[2] << 8) | payload[3]
    if not (flags & 0x8000):  # не ответ
        return None
    return flags & 0x000F


def parse_ip_port_from_payload_hex(payload):
    """Пытается извлечь IP:port из payload (для DNS запросов обычно не нужно)."""
    return None


def fmt_bytes(n):
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.1f}G"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.1f}M"
    if n >= 1024:
        return f"{n / 1024:.1f}K"
    return str(n)


def normalize_sql(sql):
    """Нормализует SQL-запрос для группировки."""
    s = sql.strip()
    s = re.sub(r'\s+LIMIT\s+\d+', '', s, flags=re.I)
    s = re.sub(r"=\s*'[^']*'", "= '...'", s)
    s = re.sub(r'=\s*\d+', '= N', s)
    s = re.sub(r'IN\s*\([^)]+\)', 'IN (...)', s, flags=re.I)
    s = re.sub(r'\s+', ' ', s).strip()
    return s
