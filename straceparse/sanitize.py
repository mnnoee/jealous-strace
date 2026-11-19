#!/usr/bin/env python3
"""Маскировка конфиденциальных данных в strace-логах.

Использование:
    python3 sanitize_log.py input.log                  # вывод в stdout
    python3 sanitize_log.py input.log -o clean.log     # вывод в файл
    python3 sanitize_log.py input.log --report         # + отчёт о заменах

Маскирует:
  - IPv4/IPv6 адреса
  - домены и хосты, включая внутренние зоны (.local, .lan, ...)
  - email, в том числе URL-encoded (%40)
  - учётные данные и токены (env, PHP, define, заголовки, query)
  - приватные ключи PEM
  - пути с именами компаний и клиентов
  - значения и имена таблиц SQL (кроме стандартных wp_*)
  - DNS-имена в wire-формате
"""

import argparse
import gzip
import ipaddress
import os
import re
import sys
from collections import OrderedDict

from .i18n import prescan_argv, set_lang, t

# -- Паттерны ----------------------------------------------

RE_IPV4 = re.compile(
    r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])'
)

# Кандидат в IPv6. Валидность проверяется через ipaddress, чтобы не зацепить
# время (13:40:00) и другие двоеточийные токены.
RE_IPV6_CANDIDATE = re.compile(
    r'(?<![\w:])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,})(?![\w:])'
)
RE_IPV4_MAPPED = re.compile(r'(?<![\w:])::ffff:(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', re.I)

RE_EMAIL = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)
RE_EMAIL_ENCODED = re.compile(
    r'[a-zA-Z0-9._%+\-]+%40[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)

# Домены: известные публичные TLD плюс типовые внутренние зоны.
_DOMAIN_TLDS = (
    'com|org|net|edu|gov|mil|int|io|ru|su|de|fr|uk|nl|se|no|fi|dk|pl|cz|sk|'
    'ua|by|kz|uz|bg|ro|hr|rs|si|ba|me|mk|al|eu|info|biz|pro|shop|online|'
    'site|store|tech|dev|app|cloud|xyz|top|space|website|host|club|live|'
    'local|lan|internal|corp|home|test|example|invalid|svc|cluster|consul'
)
RE_DOMAIN = re.compile(
    r'(?<![\w.\-\\])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,10}'
    r'(?:' + _DOMAIN_TLDS + r')\b',
    re.I,
)

# Пути и URI в упакованных FCGI-параметрах. Значение обрывается на
# escaped-байтах следующего параметра.
RE_FCGI_PATH = re.compile(
    r'((?:DOCUMENT_ROOT|CONTEXT_DOCUMENT_ROOT|SCRIPT_FILENAME|PATH_TRANSLATED|'
    r'SCRIPT_NAME|REQUEST_URI|CONTEXT_PREFIX))'
    r'((?:/[^\\\s"]*)+)'
)

# Путь в обычных URL (Referer, Location, ссылки в тексте)
RE_URL_PATH = re.compile(
    r'(?i)((?:https?|ftp)://[^\s/"\\]+)((?:/[^\s"\\]*)+)'
)

# Домены, приклеенные к имени FCGI-параметра (упакованный формат без разделителя
# после ключа) - \b перед доменом не срабатывает, маскируем по ключу
RE_FCGI_HOST = re.compile(
    r'((?:HTTP_HOST|HTTP_X_FORWARDED_HOST|SERVER_NAME|Host))'
    r'((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})'
)

# IP, приклеенный к имени FCGI-параметра (значение без разделителя после ключа)
RE_FCGI_IP = re.compile(
    r'((?:REMOTE_ADDR|SERVER_ADDR|HTTP_X_REAL_IP|HTTP_X_FORWARDED_FOR))'
    r'((?:\d{1,3}\.){3}\d{1,3})'
)

# Учётные данные и токены
RE_URL_CREDS = re.compile(
    r'(?i)\b((?:https?|ftp)://)(?!<)[^/\s:@]+:[^/\s@]+@'
)
RE_HEADER_CREDS = re.compile(
    r'(?i)(Set-Cookie|Cookie|Authorization|Proxy-Authorization|X-Api-Key|'
    r'X-Auth-Token|X-Access-Token)(:\s*)(?!<)([^"\r\n]*?)(?=\\r\\n|\\n|"|$)'
)
RE_QUERY_CREDS = re.compile(
    r'(?i)([?&](?:password|passwd|pwd|secret|token|access_token|refresh_token|'
    r'api_key|apikey|auth|session|sessionid|sessid|csrf|email)=)(?!<)([^&\s"\']+)'
)
RE_ENV_CREDS = re.compile(
    r'(?i)((?:DB_PASSWORD|DB_PASS|DB_PWD|MYSQL_PASSWORD|MYSQL_ROOT_PASSWORD|'
    r'MYSQL_PWD|PASSWORD|PASSWD|SECRET|SECRET_KEY|API_KEY|APIKEY|ACCESS_KEY|'
    r'ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|PRIVATE_KEY)\s*=\s*)(?!<)([^\s&;,\'"]+)'
)
RE_PHP_VAR_CREDS = re.compile(
    r'(?i)(\$[A-Za-z_][\w]*(?:pass|pwd|secret|token|key|salt|login)[\w]*\s*=\s*)'
    r'([\'"])(?!<)(.*?)\2'
)
RE_DEFINE_CREDS = re.compile(
    r'(?i)(define\s*\(\s*[\'"][^\'"]*(?:PASSWORD|PASS|SECRET|TOKEN|API_KEY|'
    r'AUTH_KEY|SALT)[^\'"]*[\'"]\s*,\s*)([\'"])(?!<)(.*?)\2'
)
RE_JWT = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b')
RE_JSON_CREDS = re.compile(
    r'(?i)("(?:password|passwd|secret|token|api_key|apikey|access_token|'
    r'refresh_token)"\s*:\s*")(?!<)([^"]*)(")'
)
RE_SMTP_AUTH = re.compile(
    r'(?i)\b(AUTH\s+(?:PLAIN|LOGIN)\s+)(?!<)([A-Za-z0-9+/=]{4,})'
)

# Логин в MySQL handshake: имя пользователя идёт перед \0<auth-plugin>
# или перед \0 + 20-байтной солью (старый протокол).
RE_MYSQL_USER = re.compile(
    r'((?:\\[0-7]{1,3})?)'
    r'([a-zA-Z0-9_$.\-]{6,64})'
    r'\\0(?=caching_sha2_password|mysql_native_password'
    r'|mysql_clear_password|sha256_password)'
    r'|((?:\\0){8,})((?:\\[0-7]{1,3})?)([a-zA-Z0-9_$.\-]{6,64})\\0(?=[ -~\\])'
)

# Домены в TLS ClientHello (SNI) идут после escaped NUL, обычная граница
# слова там не срабатывает - отдельный проход по строкам с TLS-hello.
RE_DOMAIN_RELAXED = re.compile(
    r'(?<!\\)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,10}'
    r'(?:' + _DOMAIN_TLDS + r')\b',
    re.I,
)

# Поля форм и query-строки с персональными данными
RE_FORM_FIELDS = re.compile(
    r'(?i)(^|[&"\'\s])(name|email|subject|message|comment|text|phone|address|'
    r'login|user|username|password|passwd|token)=(?!<)([^&\s"\']+)'
)

RE_SENSITIVE_READ = re.compile(
    r'</(?:etc/(?:passwd|shadow|group|hosts|resolv\.conf)|proc/\d+/environ)>'
)

RE_PEM_BEGIN = re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----')
RE_PEM_END = re.compile(r'-----END [A-Z0-9 ]*PRIVATE KEY-----')

# ПРИМЕЧАНИЕ: домены в DNS wire-формате маскируем ТОЛЬКО в строках DNS-трафика
# (сокеты на порт 53): бинарные escape-последовательности strace в других payload
# неотличимы от DNS-меток, общий шаблон даёт ложные срабатывания.
DNS_WIRE_RE = re.compile(r'(?:\\[0-9]{1,3}[a-zA-Z0-9\-]+){2,}(?:\\300\\[0-9]{1,3})?')
# Обезличенное имя в wire-формате: метки mail, domain, tld
DNS_WIRE_FAKE = r'\\4mail\\6domain\\3tld'

# Пути к файлам: домашние каталоги, площадки хостинга, сетевые монтирования
RE_SENSITIVE_PATH = re.compile(
    r"("
    r"/(?:home|root)/[^/\s\"'\\<>]+"
    r"|/var/www(?:-data)?/[^/\s\"'\\<>]+"
    r"|/www/wwwroot/[^/\s\"'\\<>]+"
    r"|/data/www/[^/\s\"'\\<>]+"
    r"|/(?:domains|sites|public_html|webapps)/[^/\s\"'\\<>]+"
    r"|/srv/[^/\s\"'\\<>]+"
    r"|/opt/[^/\s\"'\\<>]+"
    r"|/mnt/[^/\s\"'\\<>]+"
    r"|/storage/[^/\s\"'\\<>]+"
    r")"
    r"(?:/[^/\s\"'\\<>]*)*"
)

# SQL
RE_SQL_KEYWORDS = re.compile(
    r'(?i)\b(SELECT|INSERT|REPLACE|UPDATE|DELETE|WHERE|VALUES|SET|JOIN|'
    r'ALTER|CREATE|DROP|TRUNCATE|CALL|SHOW|DESCRIBE|EXPLAIN|UNION)\b'
)
RE_SQL_STRING = re.compile(r"'(?:[^'\\]|\\.)*'")
RE_SQL_VALUES = re.compile(r'VALUES\s*\([^)]*\)', re.I)
RE_STRACE_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
RE_SQL_IN = re.compile(r'IN\s*\([^)]+\)', re.I)
RE_SQL_NUMBER = re.compile(r'(?<=[=<>]\s)-?\d+(?:\.\d+)?\b')
RE_SQL_LIMIT = re.compile(r'LIMIT\s+\d+', re.I)
RE_SQL_OFFSET = re.compile(r'OFFSET\s+\d+', re.I)
RE_SQL_TABLE = re.compile(
    r'(?i)\b(FROM|JOIN|INTO|UPDATE|TABLE)\s+([A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?)'
)

# Стандартные WordPress-таблицы и служебные схемы - НЕ маскируем
WP_TABLES = {
    'wp_options', 'wp_posts', 'wp_postmeta', 'wp_users', 'wp_usermeta',
    'wp_terms', 'wp_termmeta', 'wp_term_taxonomy', 'wp_term_relationships',
    'wp_comments', 'wp_commentmeta', 'wp_links', 'wp_actionscheduler_logs',
    'wp_actionscheduler_claims', 'wp_actionscheduler_actions',
}
SAFE_TABLES = {'information_schema', 'mysql', 'performance_schema', 'sys'}


class Sanitizer:
    def __init__(self):
        self.counters = {
            'ipv4': 0, 'ipv6': 0, 'email': 0, 'domain': 0,
            'path': 0, 'sql_val': 0, 'sql_in': 0, 'sql_number': 0,
            'sql_limit': 0, 'sql_values': 0, 'sql_table': 0, 'dns_wire': 0, 'cred': 0,
            'hosts': 0,
        }
        self.mappings = OrderedDict()
        self.reverse = {}
        self.in_pem = False

    def _next(self, kind, original):
        original = str(original)
        if original in self.mappings:
            return self.mappings[original]
        self.counters[kind] += 1
        tag = f"<{kind.upper()}_{self.counters[kind]}>"
        self.mappings[original] = tag
        self.reverse[tag] = original
        return tag

    def sanitize_line(self, line):
        # Сначала изолируем PID+время (первые токены), чтобы не ломать их
        header_m = re.match(r'^(\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)', line)
        if header_m:
            header = header_m.group(1)
            rest = line[len(header):]
        else:
            header = ''
            rest = line

        # 0. Приватные ключи PEM: блок маскируется целиком, построчно
        if self.in_pem:
            if RE_PEM_END.search(rest):
                self.in_pem = False
            return header + self._mask_quoted(rest)
        pem_m = RE_PEM_BEGIN.search(rest)
        if pem_m:
            self.in_pem = not bool(RE_PEM_END.search(rest[pem_m.end():]))
            tag = self._next('cred', 'pem-private-key')
            return header + rest[:pem_m.start()] + tag + rest[pem_m.end():]

        # 0а. Содержимое системных файлов с инфраструктурой и учётками
        sys_m = RE_SENSITIVE_READ.search(rest)
        if sys_m and re.search(r'\b(?:read|pread64)\(', rest):
            kind = 'hosts' if 'hosts' in sys_m.group(0) or 'resolv' in sys_m.group(0) else 'cred'
            tag = self._next(kind, sys_m.group(0))
            rest = RE_STRACE_STRING.sub(lambda m: '"' + tag + '"', rest)

        # 0в. Пути в обычных URL
        def mask_url_path(m):
            if m.group(2).startswith('/<'):
                return m.group(0)
            return m.group(1) + self._next('path', m.group(2))
        rest = RE_URL_PATH.sub(mask_url_path, rest)

        # 0б. Пути и URI в упакованных FCGI-параметрах
        rest = RE_FCGI_PATH.sub(
            lambda m: m.group(1) + self._next('path', m.group(2)), rest)

        # 1. Учётные данные и токены - до остальных правил, чтобы маскировать
        # значение целиком, а не отдельные домены/IP внутри него.
        rest = RE_URL_CREDS.sub(
            lambda m: m.group(1) + self._next('cred', m.group(0)) + '@', rest)
        rest = RE_FORM_FIELDS.sub(
            lambda m: m.group(1) + m.group(2) + "=" + self._next('cred', m.group(3)), rest)
        rest = RE_HEADER_CREDS.sub(
            lambda m: m.group(1) + m.group(2) + self._next('cred', m.group(3)), rest)
        rest = RE_QUERY_CREDS.sub(
            lambda m: m.group(1) + self._next('cred', m.group(2)), rest)
        rest = RE_ENV_CREDS.sub(
            lambda m: m.group(1) + self._next('cred', m.group(2)), rest)
        rest = RE_PHP_VAR_CREDS.sub(
            lambda m: m.group(1) + m.group(2) + self._next('cred', m.group(3)) + m.group(2), rest)
        rest = RE_DEFINE_CREDS.sub(
            lambda m: m.group(1) + m.group(2) + self._next('cred', m.group(3)) + m.group(2), rest)
        rest = RE_JWT.sub(lambda m: self._next('cred', m.group()), rest)
        rest = RE_JSON_CREDS.sub(
            lambda m: m.group(1) + self._next('cred', m.group(2)) + m.group(3), rest)
        rest = RE_SMTP_AUTH.sub(
            lambda m: m.group(1) + self._next('cred', m.group(2)), rest)

        # 7. Чувствительные пути
        def mask_path(m):
            p = m.group()
            if any(p.startswith(prefix) for prefix in (
                '/usr/', '/etc/', '/proc/', '/sys/', '/dev/',
                '/tmp/', '/run/', '/boot/', '/lib/', '/sbin/',
            )):
                return p
            return self._next('path', p)
        rest = RE_SENSITIVE_PATH.sub(mask_path, rest)

        # 2. DNS-пакеты (порт 53): маскируем имена в wire-формате до прочих правил.
        # Замена анонимная (без записи оригинала в mappings/report - NDA).
        is_dns_line = ':53]' in rest or 'htons(53)' in rest or re.match(
            r'.{0,60}\b(?:sendmmsg|sendmsg|sendto|recvfrom|recvmsg|resumed)\b', rest)
        if is_dns_line:
            n_dns = len(DNS_WIRE_RE.findall(rest))
            if n_dns:
                self.counters['dns_wire'] += n_dns
                rest = DNS_WIRE_RE.sub(DNS_WIRE_FAKE, rest)

        # 3. IP, приклеенный к FCGI-ключам (REMOTE_ADDR<ip>) - до общего прохода IPv4
        rest = RE_FCGI_IP.sub(
            lambda m: m.group(1) + self._next('ipv4', m.group(2)), rest)

        # 4. IPv6 (кандидаты валидируются через ipaddress), затем IPv4
        rest = RE_IPV4_MAPPED.sub(
            lambda m: self._next('ipv6', m.group()), rest)

        def mask_ipv6(m):
            candidate = m.group(1)
            try:
                ipaddress.ip_address(candidate.split('%', 1)[0])
            except ValueError:
                return m.group(0)
            return self._next('ipv6', m.group(0))

        rest = RE_IPV6_CANDIDATE.sub(mask_ipv6, rest)
        rest = RE_IPV4.sub(lambda m: self._next('ipv4', m.group()), rest)

        # 5. Email (обычный и URL-encoded)
        rest = RE_EMAIL_ENCODED.sub(lambda m: self._next('email', m.group()), rest)
        rest = RE_EMAIL.sub(lambda m: self._next('email', m.group()), rest)

        # 6a. Домены, приклеенные к FCGI-параметрам (до общего прохода доменов)
        rest = RE_FCGI_HOST.sub(
            lambda m: m.group(1) + self._next('domain', m.group(2)), rest)

        # 6б. Домены
        def mask_domain(m):
            d = m.group()
            if d in ('example.com', 'example.org', 'example.net', 'example.edu',
                     'example.local', 'example.test', 'localhost',
                     'test.local', 'wp.org', 'wordpress.org'):
                return d
            return self._next('domain', d)
        # SNI в TLS ClientHello идёт после escaped NUL - без границы слова
        if '\\26\\3' in rest or '\\x16\\x03' in rest:
            rest = RE_DOMAIN_RELAXED.sub(mask_domain, rest)
        rest = RE_DOMAIN.sub(mask_domain, rest)

        # 8. SQL-значения, числа, таблицы. Обрабатываем только содержимое
        # строковых аргументов, чтобы не задеть PID, время ивозвращаемое значение syscall.
        rest = RE_STRACE_STRING.sub(
            lambda m: '"' + self._mask_sql_text(m.group(0)[1:-1]) + '"', rest)

        # 9. Логин в MySQL handshake
        rest = RE_MYSQL_USER.sub(self._mask_mysql_user, rest)

        return header + rest

    def _mask_quoted(self, rest):
        tag = self._next('cred', 'pem-private-key')
        return RE_STRACE_STRING.sub(lambda m: '"' + tag + '"', rest)

    def _mask_sql_text(self, text):
        if not RE_SQL_KEYWORDS.search(text):
            return text
        text = RE_SQL_STRING.sub(self._sql_string, text)
        text = RE_SQL_VALUES.sub(
            lambda m: self._next('sql_values', m.group()), text)
        text = RE_SQL_IN.sub(self._sql_in_mask, text)
        text = RE_SQL_NUMBER.sub(
            lambda m: self._next('sql_number', m.group()), text)
        text = RE_SQL_LIMIT.sub(
            lambda m: self._next('sql_limit', m.group()), text)
        text = RE_SQL_OFFSET.sub(
            lambda m: self._next('sql_limit', m.group()), text)
        text = RE_SQL_TABLE.sub(self._sql_table, text)
        return text

    def _sql_string(self, m):
        val = m.group()
        inner = val[1:-1]
        if re.fullmatch(r'wp_[a-z0-9_]+', inner):
            return val
        return self._next('sql_val', val)

    def _sql_in_mask(self, m):
        return self._next('sql_in', m.group())

    def _sql_table(self, m):
        kw, name = m.group(1), m.group(2)
        base = name.split('.', 1)[0].lower()
        if base.startswith('wp_') or base in SAFE_TABLES:
            return m.group()
        return f"{kw} {self._next('sql_table', name)}"

    def _mask_mysql_user(self, m):
        if m.group(2) is not None:
            prefix, name = m.group(1), m.group(2)
        else:
            prefix, name = m.group(3) + (m.group(4) or ''), m.group(5)
        return prefix + self._next('cred', name) + m.group()[len(prefix) + len(name):]

    def sanitize_lines(self, lines):
        for line in lines:
            yield self.sanitize_line(line.rstrip('\n'))

    @staticmethod
    def _open_input(path):
        if path == '-':
            return sys.stdin, False
        opener = gzip.open if path.endswith('.gz') else open
        return opener(path, 'rt', encoding='utf-8', errors='replace'), True

    @staticmethod
    def _open_output(path):
        if not path or path == '-':
            return sys.stdout, False
        return open(path, 'w', encoding='utf-8'), True

    def sanitize_file(self, input_path):
        fh, close = self._open_input(input_path)
        try:
            return list(self.sanitize_lines(fh))
        finally:
            if close:
                fh.close()

    def report(self):
        lines = []
        lines.append("=" * 60)
        lines.append(t("san.title"))
        lines.append("=" * 60)

        total = sum(self.counters.values())
        if total == 0:
            lines.append(t("san.none"))
            return '\n'.join(lines)

        lines.append(t("san.total", n=total))
        for kind, count in self.counters.items():
            if count > 0:
                lines.append(f"  {kind}: {count}")

        lines.append(t("san.mappings"))
        for tag, orig in self.reverse.items():
            display = orig if len(orig) <= 80 else orig[:77] + '...'
            lines.append(f"  {tag} -> {display}")

        return '\n'.join(lines)


def main():
    set_lang(prescan_argv(sys.argv[1:]))
    ap = argparse.ArgumentParser(
        description=t("san.desc")
    )
    ap.add_argument("input", help=t("san.input"))
    ap.add_argument("-o", "--output",
                    help=t("san.output"))
    ap.add_argument("--report", action="store_true",
                    help=t("san.report"))
    ap.add_argument("--lang", choices=("auto", "ru", "en"), default="auto",
                    help=t("cli.lang"))
    args = ap.parse_args()
    set_lang(args.lang)

    if args.output and args.input != '-' and os.path.abspath(args.input) == os.path.abspath(args.output):
        print(t("san.same_file"), file=sys.stderr)
        return 1

    s = Sanitizer()
    try:
        in_fh, close_in = s._open_input(args.input)
        try:
            out_fh, close_out = s._open_output(args.output)
            try:
                for line in in_fh:
                    out_fh.write(s.sanitize_line(line.rstrip('\n')) + '\n')
            finally:
                if close_out:
                    out_fh.close()
        finally:
            if close_in:
                in_fh.close()
    except OSError as e:
        print(t("san.error", error=e), file=sys.stderr)
        return 1

    if args.output and args.output != '-':
        print(t("san.written", path=args.output), file=sys.stderr)

    if args.report:
        print(s.report(), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
