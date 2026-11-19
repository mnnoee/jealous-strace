"""SSL/mTLS анализ"""

import re
from collections import defaultdict

from .i18n import t

SNI_TLD_RE = re.compile(rb"[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:ru|com|net|org|pro|io|xyz|info|site|online|store|shop|biz|su)")
SSL_ERR_RE = re.compile(r"(SSL certificate error|400 The SSL certificate|client certificate|bad certificate|sslv3 alert)", re.I)
CERT_EXT_RE = re.compile(r"\.(pem|crt|cer|key|p12|pfx)$", re.I)
CA_STORE_RE = re.compile(r"(ca-bundle|cacert|ca-cert|ca_trust|certs/|pki/|certificates/)", re.I)


def record_cert_open(p, pid, ts, path):
    """Записывает обращение к клиентскому сертификату/ключу"""
    if not CA_STORE_RE.search(path):
        p.mtls_cert_files[path].append((pid, ts))
    # первый открытый .php после accept = entry script -> URI
    if path.endswith(".php"):
        key = p._last_accept.get(pid)
        if key:
            req = p.current_http_by_pid_fd.get(key)
            if req and req.get("uri") is None:
                req["uri"] = path
                p._last_accept[pid] = None


def maybe_record_sni(p, data, ip):
    """Записывает SNI домен из TLS ClientHello, если его ещё нет для этого IP."""
    if ip is None or (ip, 443) in p.mtls_conn_domains:
        return
    sni = SNI_TLD_RE.search(data)
    if sni:
        p.mtls_conn_domains[(ip, 443)] = sni.group(0).decode("utf-8", "replace")


def is_ssl_error(txt):
    return bool(SSL_ERR_RE.search(txt))


def record_ssl_error(p, pid, ts, txt, filename):
    """Детект 'The SSL certificate error'"""
    txt_clean = re.sub(r"<[^>]+>", "", txt)
    m_frag = re.search(r"(?:HTTP/1\.\d\s+400[^\r\n]*|The SSL certificate|SSL certificate error)[^\n]{0,120}", txt, re.I)
    if m_frag:
        snippet = re.sub(r"[\x00-\x1f]", " ", m_frag.group(0))
        snippet = re.sub(r"\s+", " ", snippet).strip()
    else:
        snippet = re.sub(r"[\x00-\x1f]", " ", txt_clean)[:160]
    snippet = re.sub(r"<[^>]*>", " ", snippet)          # HTML-теги
    snippet = snippet.replace("\\r", " ").replace("\\n", " ").replace("\\/", "/")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    cut = snippet.lower().rfind("nginx")
    if cut > 0:
        snippet = snippet[:cut + len("nginx")]
    snippet = snippet.strip()[:240]
    p.mtls_ssl_errors.append((pid, ts, snippet, filename))


def report_section(p, w):
    """Секция отчёта '--- SSL / mTLS АНАЛИЗ ---'."""
    if not p.mtls:
        return
    w(t("mtls.title"))
    cert_files = {path: evs for path, evs in p.mtls_cert_files.items()}
    ssl_conns = [c for c in p.connects
                 if (c["endpoint"] or {}).get("port") == 443]

    if cert_files:
        # pid -> набор клиентских сертификатов/ключей
        cert_by_pid = defaultdict(list)   # pid -> [(path, count)]
        for path, evs in cert_files.items():
            for pidi, _ in evs:
                cert_by_pid[pidi].append(path)
        for pidi in cert_by_pid:
            cert_by_pid[pidi] = sorted(set(cert_by_pid[pidi]))

        # pid -> хосты, к которым подключался
        host_by_pid = defaultdict(set)
        mtls_conn_pids = set()
        for c in ssl_conns:
            ep = c["endpoint"] or {}
            ip = ep.get("ip")
            h = p.mtls_conn_domains.get((ip, 443))
            if h:
                host_by_pid[c["pid"]].add(h)
            if c.get("final_ok") is not False:
                mtls_conn_pids.add(c["pid"])

        w(t("mtls.cert_files"))
        for path, evs in sorted(cert_files.items(), key=lambda kv: -len(kv[1])):
            pids = sorted(set(pidi for pidi, _ in evs))
            ts = evs[0][1]
            w(t("mtls.cert_line", name=path.split("/")[-1],
                path=path.split("/data/")[-1] if "/data/" in path else path))
            w(t("mtls.cert_stats", pids=",".join(map(str, pids)), n=len(evs),
                ts=ts.strftime("%H:%M:%S") if ts else "?"))

        # mTLS-процессы которые имеют и сертификат, и HTTPS на 443
        cert_pids = set(cert_by_pid.keys())
        mtls_pids = sorted(cert_pids & mtls_conn_pids)
        if mtls_pids:
            w(t("mtls.mutual"))
            for pidi in mtls_pids:
                hosts = ", ".join(sorted(host_by_pid.get(pidi, []))) or "?"
                certs = ", ".join(c.split('/')[-1] for c in cert_by_pid[pidi])
                w(t("mtls.client_cert", pid=pidi, hosts=hosts, certs=certs))

        if ssl_conns:
            # какие 443-соединения привели к SSL-ошибке это ближайший connect по времени до ошибки
            err_conn_idx = set()
            for pidi, ts, _txt, _fname in p.mtls_ssl_errors:
                best = None
                for i, c in enumerate(ssl_conns):
                    if c["pid"] != pidi:
                        continue
                    if ts is None:
                        continue
                    cts = c["ts"]
                    if cts is not None and (best is None or cts >= best[0]) and cts <= ts:
                        best = (cts, i)
                if best:
                    err_conn_idx.add(best[1])
            w(t("mtls.https"))
            w(f"{t('mtls.col_ip'):<22}{t('mtls.col_host'):<28}{t('mtls.col_pid'):>10}"
              f"{t('mtls.col_time'):>12}{t('mtls.col_result'):>10}")
            for i, c in enumerate(ssl_conns):
                ep = c["endpoint"] or {}
                ip = ep.get("ip") or "?"
                host = p.mtls_conn_domains.get((ip, 443), "")
                ts = c["ts"].strftime("%H:%M:%S") if c["ts"] else "?"
                res = "SSL-ERR" if i in err_conn_idx else ("OK" if c.get("final_ok") is not False else "ERR")
                w(f"{ip:<22}{(host or ''):<28}{c['pid']:>10}{ts:>12}{res:>10}")

    # Ошибки SSL-сертификата
    if p.mtls_ssl_errors:
        w(t("mtls.ssl_errors", n=len(p.mtls_ssl_errors)))
        err_to_conn = {}
        for pidi, ts, _txt, _fname in p.mtls_ssl_errors:
            best = None
            for i, c in enumerate(ssl_conns):
                if c["pid"] != pidi:
                    continue
                if ts is None:
                    continue
                cts = c["ts"]
                if cts is not None and (best is None or cts >= best[0]) and cts <= ts:
                    best = (cts, i)
            err_to_conn[(pidi, ts)] = best[1] if best else None
        for pidi, ts, txt, _fname in p.mtls_ssl_errors[:10]:
            conn_i = err_to_conn.get((pidi, ts))
            if conn_i is not None:
                c = ssl_conns[conn_i]
                ip = (c["endpoint"] or {}).get("ip")
                fail_host = p.mtls_conn_domains.get((ip, 443)) or (ip or "?")
            else:
                fail_host = ", ".join(sorted(host_by_pid.get(pidi, []))) or "?"
            certs = ", ".join(cf.split('/')[-1] for cf in cert_by_pid.get(pidi, [])) or "?"
            w(f"  - pid={pidi} ts={ts.strftime('%H:%M:%S') if ts else '?'} host={fail_host}")
            w(t("mtls.cert", certs=certs))
            w(t("mtls.response", txt=txt))
    if not cert_files and not p.mtls_ssl_errors:
        w(t("mtls.none"))
