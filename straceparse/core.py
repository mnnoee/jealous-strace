"""Ядро: класс Syscall и StraceParser — разбор строк и трекинг состояния.

Feature-модули (wp, mem, mtls) подключаются через функции-хуки,
НЕ наследуются: они работают с переданным экземпляром StraceParser.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime

from . import constants as ct
from . import mem, mtls, wp
from .parse_utils import (
    extract_location,
    extract_server_timing,
    extract_set_cookie,
    extract_status,
    looks_like_http_response,
    parse_dns_qname,
    parse_dns_rcode,
    parse_fcgi_params,
    parse_sockaddr,
    payload_all_strings,
    payload_first_string,
)


class Syscall:
    __slots__ = ("pid", "ts", "name", "args", "ret", "errno", "dur", "unfinished", "resumed", "file", "line")

    def __init__(self, pid, ts, name, args, ret, errno, dur, unfinished, resumed, file, line):
        self.pid = pid
        self.ts = ts
        self.name = name
        self.args = args
        self.ret = ret
        self.errno = errno
        self.dur = dur
        self.unfinished = unfinished
        self.resumed = resumed
        self.file = file
        self.line = line


class StraceParser:
    def __init__(self, threshold=0.1, slow_top=50, wordpress=False, mtls=False):
        self.threshold = threshold
        self.slow_top = slow_top
        self.wordpress = wordpress
        self.mtls = mtls
        self.syscalls = Counter()
        self.syscall_err_count = Counter()
        self.syscall_time = defaultdict(list)
        self.errno_counter = Counter()
        self.errno_examples = {}
        self.errors_list = []
        self.files = defaultdict(Counter)  # path -> Counter(access type)
        self.file_bytes = defaultdict(Counter)  # path -> Counter(access type)
        self.open_missing = Counter()  # path -> count
        self.connects = []  # список dict
        self.dns_queries = []  # список dict
        self.sql_queries = []
        self.http_requests = []  # список dict
        self.http_current = {}  # (pid, fd) -> dict
        self.pid_stats = defaultdict(lambda: {"count": 0, "err": 0, "start": None, "end": None,
                                              "syscalls": Counter(), "slow": [], "dur": 0.0})
        self.unfinished_open = []  # (pid, name, ts)
        self.slow_calls = []
        self.syscall_events = []  # аудит-трейл: {pid, ts, name, dur, path} для атрибуции нагрузки
        self.pid_last_ts = defaultdict(float)
        self.lines_total = 0
        self.fd_table = defaultdict(dict)  # pid -> {fd: {"type": "file|sock", ...}}
        self.conn_state = {}  # (pid, fd) -> {"endpoint": ..., "status": ...}
        self.current_http_by_pid_fd = {}  # (pid, fd) -> dict
        self._last_accept = {}
        self._pending_fd = {}
        self._current_sql_by_pid_fd = {}  # (pid, fd) -> index in sql_queries
        self.last_http_key = None
        self.access_entries = []  # для access-логов (не strace)
        self.exited_pids = {}
        self.x32_pids = set()
        self.format_counts = Counter()
        # RAM/OOM
        self.mmap_total = 0          # суммарно байт mmap(..., SIZE, ...)
        self.mmap_count = 0
        self.munmap_total = 0        # суммарно байт munmap(..., SIZE)
        self.munmap_count = 0
        self.oom_detected = False
        self.oom_message = ""        # текст ошибки OOM
        self.php_fatal_errors = []   # (ts, message, file, line)
        # WordPress диагностика
        self.wp_version = None
        self.wp_active_theme = None
        self.wp_entry_script = None  # index.php path
        self.wp_abspath = None       # ABSPATH из лога
        self.wp_core_files = {}      # path -> {"found": bool, "size": int}
        self.wp_theme_files = {}     # path -> {"found": bool, "size": int}
        self.wp_content_files = {}   # path -> {"found": bool, "size": int}
        self.wp_php_version_hint = None  # из пути (php54, php70 и т.д.)
        self.wp_file_reads = {}      # path -> bytes_read (для определения что реально читалось)
        self.wp_detected_issues = [] # список (severity, message)
        # --- SSL / mTLS анализ ---
        self.mtls_cert_files = defaultdict(list)  # path -> [(pid, ts)]
        self.mtls_ssl_errors = []    # (pid, ts, text, filename) — nginx/ssl cert error в данных
        self.mtls_conn_domains = {}  # (ip, port) -> имя хоста из SNI/connect

    # -- определение формата строки --
    def finalize(self):
        """Финализировать открытые HTTP-запросы и незакрытые соединения в конце."""
        for _key, req in list(self.current_http_by_pid_fd.items()):
            req["end"] = req.get("start")
            self.http_requests.append(req)
        self.current_http_by_pid_fd.clear()
        # закрыть незавершённые замеры SQL-запросов (end_ts = начало)
        for q in self.sql_queries:
            if q.get("end_ts") is None:
                q["end_ts"] = q.get("start_ts") or q.get("ts")
        # определить тему и PHP-версию по собранным данным
        if self.wordpress:
            wp.detect_theme(self)
            wp.detect_php_version(self)

    def parse_line(self, line, filename):
        line = line.rstrip("\n")
        self.lines_total += 1
        if not line:
            return

        # access log (nginx/apache combined)
        if re.match(r"^\S+ - - \[\d{2}/[A-Za-z]{3}/\d{4}:", line):
            self.parse_access_line(line, filename)
            self.format_counts["access_log"] += 1
            return

        # PID + epoch <seconds>.[us] + [instruction pointer] + syscall (strace -ff -ttt -i)
        m = ct.PID_EPOCH_IP_RE.match(line)
        if m:
            pid = int(m.group(1))
            ts = self._parse_epoch_ts(m.group(2))
            rest = m.group(4)
            self.format_counts["epoch_ip"] += 1
            self.handle_rest(pid, ts, rest, filename, line)
            return

        # epoch <seconds>.[us] + [instruction pointer] + syscall (strace -ttt -i)
        # без PID: цельный лог одного процесса (strace -ff на один PID)
        m = ct.EPOCH_IP_RE.match(line)
        if m:
            ts = self._parse_epoch_ts(m.group(1))
            rest = m.group(3)
            self.format_counts["epoch_ip"] += 1
            self.handle_rest(None, ts, rest, filename, line)
            return

        # PID + время + syscall
        m = re.match(r"^(\d+)\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(.*)$", line)
        if m:
            pid = int(m.group(1))
            ts = self._parse_ts(m.group(2))
            rest = m.group(3)
            self.format_counts["pid_time"] += 1
            self.handle_rest(pid, ts, rest, filename, line)
            return

        # PID + syscall (без времени)
        m = re.match(r"^(\d+)\s+(\w+\(.*)$", line)
        if m:
            pid = int(m.group(1))
            ts = None
            rest = m.group(2)
            self.format_counts["pid_only"] += 1
            self.handle_rest(pid, ts, rest, filename, line)
            return

        # syscall без PID (например trace_log или strace_sample)
        m = re.match(r"^(\w+\(.*)$", line)
        if m:
            self.format_counts["plain"] += 1
            self.handle_rest(None, None, m.group(1), filename, line)
            return

        # прочее
        self.format_counts["other"] += 1
        # [ Process PID=... ], +++ exited, --- SIG..., restart_syscall
        if "exited with" in line:
            m = re.search(r"(\d+).*exited with (\d+)", line)
            if m:
                self.exited_pids[int(m.group(1))] = int(m.group(2))
        elif "Process PID=" in line:
            m = re.search(r"Process PID=(\d+)", line)
            if m:
                self.x32_pids.add(int(m.group(1)))

    def _parse_ts(self, ts_str):
        try:
            if "." in ts_str:
                dt = datetime.strptime(ts_str, "%H:%M:%S.%f")
            else:
                dt = datetime.strptime(ts_str, "%H:%M:%S")
            return dt
        except ValueError:
            return None

    def _parse_epoch_ts(self, epoch_str):
        # strace -ttt: абсолютный таймстамп <epoch>.<microseconds>
        try:
            return datetime.fromtimestamp(float(epoch_str))
        except (ValueError, OverflowError, OSError):
            return None

    def handle_rest(self, pid, ts, rest, filename, line):
        if not rest:
            return

        # resumption line
        m = ct.RESUMED_RE.match(rest)
        if m:
            name = m.group(1)
            rest_args = m.group(2)
            # найти последний ")" который закрывает аргументы, далее " = "
            matches = list(re.finditer(r"\)\s*=\s*", rest_args))
            if matches:
                mm = matches[-1]
                args = rest_args[:mm.start()] + ")"
                ret_str = rest_args[mm.end():]
                ret, errno, dur = self._parse_ret(ret_str)
                self.record_syscall(pid, ts, name, args, ret, errno, dur, False, True, filename, line)
            return

        # unfinished line
        if ct.UNFINISHED_RE.search(rest):
            m2 = ct.SYS_NAME_RE.match(rest)
            if m2:
                name = m2.group(1)
                args = rest
                self.record_syscall(pid, ts, name, args, None, None, None, True, False, filename, line)
            return

        # restart_syscall
        if rest.startswith("restart_syscall("):
            self.record_syscall(pid, ts, "restart_syscall", rest, None, None, None, False, False, filename, line)
            return

        # normal: name(args) = ret
        m2 = ct.SYS_NAME_RE.match(rest)
        if m2:
            name = m2.group(1)
            # найти последний ")" который закрывает аргументы, далее " = "
            matches = list(re.finditer(r"\)\s*=\s*", rest))
            if not matches:
                return
            mm = matches[-1]
            args = rest[:mm.start()] + ")"
            ret_str = rest[mm.end():]
            ret, errno, dur = self._parse_ret(ret_str)
            self.record_syscall(pid, ts, name, args, ret, errno, dur, False, False, filename, line)

    def _parse_ret(self, ret_str):
        ret = None
        errno = None
        dur = None
        ret_str = ret_str.strip()
        # длительность в <...>
        m = re.search(r"<([\d.]+)>\s*$", ret_str)
        if m:
            dur = float(m.group(1))
            ret_str = ret_str[:m.start()].strip()
        # -1 ENOENT (No such file or directory)
        m = re.match(r"^(-?\d+)\s+([A-Z_][A-Z0-9_]*)\s*(?:\((.*?)\))?\s*$", ret_str)
        if m:
            ret = m.group(1)
            errno = m.group(2)
        else:
            m = re.match(r"^(-?\d+|0x[0-9a-fA-F]+|\?)\s*(.*)$", ret_str)
            if m:
                ret = m.group(1)
        return ret, errno, dur

    @staticmethod
    def _fmt_syscall(name, args):
        a = args or ""
        if a.lstrip().startswith(name + "("):
            a = a.lstrip()[len(name) + 1:]
        while a.endswith(")"):
            a = a[:-1]
        return f"{name}({a})"

    # -- основной обработчик syscall --
    def record_syscall(self, pid, ts, name, args, ret, errno, dur, unfinished, resumed, filename, line):
        if pid is None:
            pid = 0
        self.syscalls[name] += 1
        st = self.pid_stats[pid]
        st["count"] += 1
        if ts is not None:
            if st["start"] is None or ts < st["start"]:
                st["start"] = ts
            if st["end"] is None or ts > st["end"]:
                st["end"] = ts
        st["syscalls"][name] += 1
        if dur is not None:
            st["dur"] += dur
            self.syscall_time[name].append(dur)

        if ts is not None and not unfinished:
            ev_path = None
            if name in ("openat", "open", "creat", "stat", "lstat",
                        "newfstatat", "statx", "access", "faccessat"):
                em = re.search(r'"([^"]*)"', args)
                if em:
                    ev_path = em.group(1)
            self.syscall_events.append(
                {"pid": pid, "ts": ts, "name": name, "dur": dur, "path": ev_path})

        if errno or (ret == "-1"):
            self.syscall_err_count[name] += 1
            st["err"] += 1
            self.errno_counter[errno or "UNKNOWN"] += 1
            if (errno or "UNKNOWN") not in self.errno_examples:
                self.errno_examples[errno or "UNKNOWN"] = line[:300]
            self.errors_list.append((pid, ts, name, args[:200], ret, errno, filename))

        if not unfinished and dur is not None and dur >= self.threshold:
            self.slow_calls.append((pid, ts, name, args[:200], dur, filename))

        self._track_fd_and_special(pid, ts, name, args, ret, errno, dur, unfinished, resumed, filename)

        if unfinished:
            fd = self._get_fd_arg(args) if self._has_fd(name) else None
            if fd is not None:
                self._pending_fd[(pid, name)] = fd
            self.unfinished_open.append((pid, name, ts, filename, fd))
        elif resumed:
            # парное завершение: убрать один незавершённый вызов этого имени для этого pid
            for i in range(len(self.unfinished_open) - 1, -1, -1):
                p, n, t, f, fdv = self.unfinished_open[i]
                if p == pid and n == name:
                    self.unfinished_open.pop(i)
                    break
            self._pending_fd.pop((pid, name), None)

    def _track_fd_and_special(self, pid, ts, name, args, ret, errno, dur, unfinished, resumed, filename):
        fd_tab = self.fd_table[pid]
        # --- открытие файлов ---
        if name in ("openat", "open", "creat"):
            path_m = re.search(r'"([^"]*)"', args)
            flags_m = re.search(r"O_[A-Z_|]+", args)
            flags = flags_m.group(0) if flags_m else ""
            if path_m:
                path = path_m.group(1)
                if ret and ret != "-1":
                    try:
                        fdn = int(ret)
                        fd_tab[fdn] = {"type": "file", "path": path, "flags": flags}
                    except (ValueError, TypeError):
                        pass
                if name == "openat":
                    self.files[path]["openat"] += 1
                else:
                    self.files[path]["open"] += 1
                if errno == "ENOENT":
                    self.open_missing[path] += 1
            # SSL/mTLS: клиентские сертификаты и ключи
            if self.mtls and re.search(r"\.(pem|crt|cer|key|p12|pfx)$", path, re.I):
                mtls.record_cert_open(self, pid, ts, path)

        elif name in ("stat", "lstat", "newfstatat", "statx", "access", "faccessat"):
            path_m = re.search(r'"([^"]*)"', args)
            if path_m:
                self.files[path_m.group(1)][name] += 1
                if errno == "ENOENT":
                    self.open_missing[path_m.group(1)] += 1

        # --- сокеты ---
        elif name == "socket":
            if ret and ret != "-1":
                try:
                    fd_tab[int(ret)] = {"type": "sock", "endpoint": None, "kind": "raw"}
                except (ValueError, TypeError):
                    pass

        elif name == "getcwd":
            # Извлечь путь для определения PHP-версии
            wp.maybe_php_version_from_cwd(self, args)

        elif name in ("accept", "accept4"):
            # принять соединение
            if ret and ret != "-1":
                try:
                    fdn = int(ret)
                except (ValueError, TypeError):
                    return
                fd_tab[fdn] = {"type": "sock", "endpoint": None, "kind": "fcgi"}
                self.current_http_by_pid_fd[(pid, fdn)] = {
                    "pid": pid, "fd": fdn, "start": ts,
                    "host": None, "method": None, "uri": None,
                    "referer": None, "ua": None, "query": None,
                    "scheme": None, "status": None, "location": None,
                    "server_timing": None, "set_cookie": None, "end": None,
                    "file": filename,
                }
                self._last_accept[pid] = (pid, fdn)

        elif name == "connect":
            addr_str = re.search(r"\{[^}]*sa_family=[^}]*\}", args)
            endpoint = parse_sockaddr(addr_str.group(0)) if addr_str else None
            conn = {
                "pid": pid, "ts": ts, "endpoint": endpoint,
                "ret": ret, "errno": errno, "fd": self._get_fd_arg(args, pid, name),
                "dur": dur, "resolved": False, "final_ok": None,
                "file": filename,
            }
            self.connects.append(conn)
            fdnum = self._get_fd_arg(args, pid, name)
            if endpoint:
                sock_path = endpoint.get("path") or ""
                if endpoint.get("port") == 53:
                    fd_tab[fdnum] = {"type": "sock", "endpoint": endpoint, "kind": "dns"}
                elif endpoint.get("port") == 3306 or sock_path.endswith(".sock"):
                    # TCP 3306 или локальный Unix-сокет MySQL (mysqld.sock)
                    fd_tab[fdnum] = {"type": "sock", "endpoint": endpoint, "kind": "mysql"}
                else:
                    fd_tab[fdnum] = {"type": "sock", "endpoint": endpoint, "kind": "net"}
                self.conn_state[(pid, fdnum)] = {"endpoint": endpoint, "status": "ok" if ret == "0" else "pending"}

        elif name == "getsockopt":
            # SO_ERROR: [0] или [EHOSTUNREACH]
            m = re.search(r"SO_ERROR,\s*\[([^\]]*)\]", args)
            fdnum = self._get_fd_arg(args, pid, name)
            if m:
                val = m.group(1)
                if val == "0":
                    self.conn_state[(pid, fdnum)]["status"] = "ok"
                    for c in reversed(self.connects):
                        if c["pid"] == pid and c["fd"] == fdnum and c["errno"] == "EINPROGRESS" and not c["resolved"]:
                            c["final_ok"] = True
                            c["resolved"] = True
                            break
                elif val:
                    self.conn_state[(pid, fdnum)]["status"] = f"error:{val}"
                    for c in reversed(self.connects):
                        if c["pid"] == pid and c["fd"] == fdnum and not c["resolved"]:
                            c["final_ok"] = False
                            c["resolved"] = True
                            break

        elif name == "close":
            fdnum = self._get_fd_arg(args, pid, name)
            if fdnum in fd_tab:
                fd_tab.pop(fdnum, None)
                # финализируем HTTP запрос
                key = (pid, fdnum)
                if key in self.current_http_by_pid_fd:
                    req = self.current_http_by_pid_fd.pop(key)
                    req["end"] = ts
                    self.http_requests.append(req)
                self.conn_state.pop((pid, fdnum), None)

        elif name == "dup":
            pass

        # --- чтение/запись ---
        elif name in ("read", "readv", "pread64"):
            self._handle_read(pid, ts, name, args, ret, errno, dur, filename)

        elif name in ("write", "writev", "pwrite64"):
            self._handle_write(pid, ts, name, args, ret, errno, dur, filename)

        elif name in ("sendto", "sendmsg", "sendmmsg", "send"):
            self._handle_send(pid, ts, name, args, ret, errno, dur, filename)

        elif name in ("recvfrom", "recvmsg", "recvmmsg", "recv"):
            self._handle_recv(pid, ts, name, args, ret, errno, dur, filename)

        elif name in ("getaddrinfo", "gethostbyname", "gethostbyname2", "getnameinfo"):
            host = re.search(r'"([^"]*)"', args)
            self.dns_queries.append({
                "ts": ts, "pid": pid, "qname": host.group(1) if host else None,
                "type": "resolve", "rcode": None, "status": "ok" if ret == "0" else "error",
                "file": filename,
            })

        # fstat на файле - отслеживаем fd
        elif name == "fstat":
            fdnum = self._get_fd_arg(args, pid, name)
            if fdnum in fd_tab and fd_tab[fdnum]["type"] == "file":
                self.files[fd_tab[fdnum]["path"]]["fstat"] += 1

        # --- mmap/munmap: отслеживание объёма памяти ---
        elif name == "mmap":
            if ret and ret != "-1" and ret != "MAP_FAILED":
                size_m = re.search(r"mmap\([^,]*,\s*(\d+)", args)
                if size_m:
                    sz = int(size_m.group(1))
                    self.mmap_total += sz
                    self.mmap_count += 1
        elif name == "munmap":
            if ret == "0":
                size_m = re.search(r"munmap\([^,]*,\s*(\d+)", args)
                if size_m:
                    sz = int(size_m.group(1))
                    self.munmap_total += sz
                    self.munmap_count += 1

    def _get_fd_arg(self, args, pid=None, name=None):
        m = re.match(r"^\s*\w+\((\d+)", args)
        if m:
            return int(m.group(1))
        m = re.match(r"^\s*(\d+)", args)
        if m:
            return int(m.group(1))
        # fd может быть невидим в resumed строке
        if pid is not None and name is not None:
            return self._pending_fd.get((pid, name))
        return None

    @staticmethod
    def _has_fd(name):
        return name in ("read", "write", "recvfrom", "recvmsg", "recvmmsg", "recv",
                        "sendto", "sendmsg", "sendmmsg", "send", "connect",
                        "getsockopt", "setsockopt", "close", "fstat", "fcntl",
                        "ioctl", "poll", "ppoll", "select", "pselect6", "epoll_ctl",
                        "accept", "accept4", "socket", "shutdown")

    def _mark_conn_ok(self, pid, fdnum):
        self.conn_state[(pid, fdnum)]["status"] = "ok"
        for c in reversed(self.connects):
            if c["pid"] == pid and c["fd"] == fdnum and c["errno"] == "EINPROGRESS" and not c["resolved"]:
                c["final_ok"] = True
                c["resolved"] = True
                break

    @staticmethod
    def _clean_sql(txt):
        """Извлекает чистый SQL-текст из MySQL-пакета (с длиной/командой в начале)."""
        cand = txt
        # убрать управляющие/цифровые префиксы (длина пакета, команда) до первого слова
        m = re.search(r"(?is)((?:SELECT|INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|SHOW|SET|BEGIN|COMMIT|ROLLBACK|START|PREPARE|EXECUTE|CALL|GRANT|REVOKE|USE|LOCK|UNLOCK|TRUNCATE|DESCRIBE|EXPLAIN|CHECK|OPTIMIZE|ANALYZE|WITH)\b)", cand)
        if not m:
            return None
        start = m.start()
        # разрешить не более ~8 служебных байтов перед SQL
        if start > 8:
            return None
        return cand[start:]

    @staticmethod
    def _looks_like_sql(txt):
        cand = txt
        # MySQL протокол: 4-байтный префикс длины (little-endian) перед payload
        if len(txt) >= 4 and all(c in "0123456789" for c in txt[:4]):
            cand = txt[4:]
        # отбросить управляющие/бинарные символы в начале
        start = 0
        while start < len(cand) and (ord(cand[start]) < 0x20 or ord(cand[start]) > 0x7e):
            start += 1
        cand = cand[start:]
        if re.search(r"(?i)^(SELECT|INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|SHOW|SET|BEGIN|COMMIT|ROLLBACK|START|PREPARE|EXECUTE|CALL|GRANT|REVOKE|USE|LOCK|UNLOCK|TRUNCATE|DESCRIBE|EXPLAIN|CHECK|OPTIMIZE|ANALYZE|WITH)\b", cand):
            return True
        return False

    def _handle_read(self, pid, ts, name, args, ret, errno, dur, filename):
        fdnum = self._get_fd_arg(args, pid, name)
        fd_tab = self.fd_table[pid]
        res = fd_tab.get(fdnum)
        data = payload_first_string(args)
        nbytes = None
        if ret and ret.isdigit():
            nbytes = int(ret)
        if res and res["type"] == "file":
            path = res["path"]
            self.files[path]["read"] += 1
            if nbytes:
                self.file_bytes[path]["read"] += nbytes
            # WordPress: extract version from wp-includes/version.php
            if path.endswith("/wp-includes/version.php") and data:
                wp.maybe_wp_version(self, data)
            # WordPress: extract ABSPATH from index.php or wp-load.php
            if (path.endswith("/index.php") or path.endswith("/wp-load.php")) and data:
                wp.maybe_wp_abspath(self, path, data)
        elif res and res["type"] == "sock":
            kind = res.get("kind")
            key = (pid, fdnum)
            if kind == "fcgi" and data and len(data) >= 8:
                # возможно FCGI params
                params = parse_fcgi_params(data)
                if params:
                    req = self.current_http_by_pid_fd.setdefault(key, {
                        "pid": pid, "fd": fdnum, "start": ts,
                        "host": None, "method": None, "uri": None,
                        "referer": None, "ua": None, "query": None,
                        "scheme": None, "status": None, "location": None,
                        "server_timing": None, "set_cookie": None, "end": None,
                        "file": filename,
                    })
                    self._apply_fcgi_params(req, params)
                elif data.startswith(b"\x01") and len(data) > 4:
                    # FCGI заголовок
                    pass

    def _apply_fcgi_params(self, req, params):
        host = params.get("HTTP_HOST") or params.get("SERVER_NAME") or params.get("REDIRECT_HTTP_HOST")
        method = (params.get("REQUEST_METHOD") or params.get("REDIRECT_REQUEST_METHOD")
                  or params.get("HTTP_X_HTTP_METHOD_OVERRIDE"))
        uri = params.get("REQUEST_URI") or params.get("REDIRECT_URL") or params.get("SCRIPT_NAME")
        referer = params.get("HTTP_REFERER")
        ua = params.get("HTTP_USER_AGENT")
        query = params.get("QUERY_STRING")
        scheme = params.get("HTTPS") or params.get("REDIRECT_HTTPS")
        if host:
            req["host"] = host
        if method:
            req["method"] = method
        if uri:
            req["uri"] = uri
        if referer:
            req["referer"] = referer
        if ua:
            req["ua"] = ua
        if query:
            req["query"] = query
        if scheme and scheme.lower() in ("on", "1", "true", "yes"):
            req["scheme"] = "https"

    def _handle_write(self, pid, ts, name, args, ret, errno, dur, filename):
        fdnum = self._get_fd_arg(args, pid, name)
        fd_tab = self.fd_table[pid]
        res = fd_tab.get(fdnum)
        data = payload_first_string(args)
        nbytes = None
        if ret and ret.isdigit():
            nbytes = int(ret)
        if res and res["type"] == "file":
            path = res["path"]
            self.files[path]["write"] += 1
            if nbytes:
                self.file_bytes[path]["write"] += nbytes
        elif res and res["type"] == "sock" and data:
            key = (pid, fdnum)
            # SSL/mTLS: SNI hostname в TLS ClientHello через write()
            if self.mtls and res.get("kind") == "net" and res.get("endpoint") \
                    and res["endpoint"].get("port") == 443 \
                    and data.startswith(b"\x16\x03"):
                mtls.maybe_record_sni(self, data, res["endpoint"].get("ip"))
            # Server-Timing (фазы WP) — заголовок может быть в FCGI-записи без Status
            req0 = self.current_http_by_pid_fd.get(key)
            st = extract_server_timing(data)
            if st and req0:
                req0["server_timing"] = st
                req0["end"] = ts
            if looks_like_http_response(data):
                status = extract_status(data)
                loc = extract_location(data)
                req = req0
                if req:
                    if status:
                        req["status"] = status
                    if loc:
                        req["location"] = loc
                    cookies = extract_set_cookie(data)
                    if cookies:
                        req["set_cookie"] = cookies
                    req["end"] = ts
            # детект PHP Fatal error: Out of memory (в любом socket write)
            if data:
                txt = data.decode("utf-8", "replace")
                # убрать HTML-теги для простого поиска
                txt_clean = re.sub(r"<[^>]+>", "", txt)
                # SSL/mTLS: сервер (nginx) отклонил клиентский сертификат
                if self.mtls and mtls.is_ssl_error(txt):
                    mtls.record_ssl_error(self, pid, ts, txt, filename)
                mem.check_oom(self, ts, txt_clean)

    def _handle_send(self, pid, ts, name, args, ret, errno, dur, filename):
        fdnum = self._get_fd_arg(args, pid, name)
        fd_tab = self.fd_table[pid]
        res = fd_tab.get(fdnum)
        if (pid, fdnum) in self.conn_state and self.conn_state[(pid, fdnum)]["status"] == "pending" \
                and ret == "0":
            self._mark_conn_ok(pid, fdnum)
        # извлечь все строки (для sendmmsg - msg_iov)
        strings = payload_all_strings(args)
        for data in strings:
            if not data:
                continue
            # SSL/mTLS: SNI hostname в TLS ClientHello -> привязать к connect
            if self.mtls and res and res.get("kind") == "net" and res.get("endpoint") \
                    and res["endpoint"].get("port") == 443 and data \
                    and data.startswith(b"\x16\x03"):
                mtls.maybe_record_sni(self, data, res["endpoint"].get("ip"))
            # DNS
            if res and res.get("kind") == "dns":
                qname = parse_dns_qname(data)
                if qname:
                    self.dns_queries.append({
                        "ts": ts, "pid": pid, "qname": qname,
                        "type": "query", "rcode": None, "status": "sent",
                        "file": filename,
                    })
            # SQL (независимо от того, пометили ли мы сокет как mysql)
            if res is None or res.get("kind") not in ("dns",):
                txt = data.decode("utf-8", "replace")
                cleaned = self._clean_sql(txt)
                if cleaned:
                    ep = None
                    if res and res.get("endpoint"):
                        ep = res.get("endpoint").get("ip")
                    elif not res:
                        ep = self.conn_state.get((pid, fdnum), {}).get("endpoint", {}).get("ip")
                    idx = len(self.sql_queries)
                    # закрыть предыдущий запрос на этом сокете (end_ts = время следующего send)
                    if fdnum is not None:
                        prev = self._current_sql_by_pid_fd.get((pid, fdnum))
                        if prev is not None and prev < len(self.sql_queries):
                            if self.sql_queries[prev].get("end_ts") is None:
                                self.sql_queries[prev]["end_ts"] = ts
                    self.sql_queries.append({
                        "ts": ts, "pid": pid, "sql": cleaned[:500],
                        "server": ep,
                        "file": filename,
                        "recv_bytes": 0,
                        "fd": fdnum,
                        "start_ts": ts,
                        "end_ts": None,
                    })
                    # отслеживать текущий SQL-запрос для данного (pid, fd)
                    if fdnum is not None:
                        self._current_sql_by_pid_fd[(pid, fdnum)] = idx
            # отправка куда-то по сети
            elif res and res.get("kind") == "net":
                pass

    def _handle_recv(self, pid, ts, name, args, ret, errno, dur, filename):
        fdnum = self._get_fd_arg(args, pid, name)
        fd_tab = self.fd_table[pid]
        res = fd_tab.get(fdnum)
        if (pid, fdnum) in self.conn_state and self.conn_state[(pid, fdnum)]["status"] == "pending" \
                and ret == "0":
            self._mark_conn_ok(pid, fdnum)
        # отслеживание объёма данных MySQL-ответа
        if res and res.get("kind") == "mysql" and ret and ret.isdigit():
            nbytes = int(ret)
            cur_idx = self._current_sql_by_pid_fd.get((pid, fdnum))
            if cur_idx is not None and cur_idx < len(self.sql_queries):
                self.sql_queries[cur_idx]["recv_bytes"] += nbytes
                # ответ получен к этому моменту
                self.sql_queries[cur_idx]["end_ts"] = ts
        strings = payload_all_strings(args)
        for data in strings:
            if not data:
                continue
            if res and res.get("kind") == "dns":
                rcode = parse_dns_rcode(data)
                if rcode is not None:
                    # сопоставить с последним незавершённым запросом
                    for q in reversed(self.dns_queries):
                        if q.get("type") == "query" and q.get("status") == "sent" and q.get("rcode") is None:
                            q["rcode"] = rcode
                            q["status"] = "ok" if rcode == 0 else f"err_{ct.RCODE_NAMES.get(rcode, rcode)}"
                            break

    # -- access log --
    def parse_access_line(self, line, filename):
        m = re.match(
            r"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+\"([^\"]*)\"\s+\"([^\"]*)\"(.*)$",
            line)
        if not m:
            return
        self.access_entries.append({
            "ip": m.group(1), "time": m.group(2), "vhost": m.group(3),
            "method": m.group(4), "uri": m.group(5), "proto": m.group(6),
            "status": m.group(7), "bytes": m.group(8), "referer": m.group(9),
            "ua": m.group(10), "file": filename,
        })
