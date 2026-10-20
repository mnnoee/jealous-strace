#!/usr/bin/env python3
"""
sanitize_log.py — Маскировка конфиденциальных данных в strace-логах.

Использование:
    python3 sanitize_log.py input.log                  # вывод в stdout
    python3 sanitize_log.py input.log -o clean.log     # вывод в файл
    python3 sanitize_log.py input.log --report         # + отчёт о заменах

Маскирует:
  - IPv4/IPv6 адреса -> <IP_1>, <IP_2>, ...
  - Домены/хосты -> <HOST_1>, <HOST_2>, ...
  - Email-адреса -> <EMAIL_1>
  - Пути с потенциальными именами компаний/projects -> <PATH_1>
  - Содержимое SQL-запросов (значения в WHERE/SET/VALUES) -> сохраняя структуру
  - FCGI-параметры с хостами/URI -> generic
"""
import argparse
import re
import sys
from collections import OrderedDict

# -- Паттерны ----------------------------------------------

RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'  # полный 8-сегментный
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'                     # с :: (variant 1)
    r'|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b' # :: в начале
)

RE_EMAIL = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,4}'
    r'(?:com|org|net|edu|gov|mil|io|ru|de|fr|uk|nl|se|no|fi|dk|pl|cz|sk|'
    r'ua|by|kz|uz|bg|ro|hr|rs|si|ba|me|mk|al|eu|info|biz|pro|shop|online|'
    r'site|store|tech|dev|app|cloud|me)\b'
)

# Домены, приклеенные к имени FCGI-параметра (упакованный формат без разделителя
# после ключа) — \b перед доменом не срабатывает, маскируем по ключу
RE_FCGI_HOST = re.compile(
    r'((?:HTTP_HOST|HTTP_X_FORWARDED_HOST|SERVER_NAME|Host))'
    r'((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})'
)

# IP, приклеенный к имени FCGI-параметра (значение без разделителя после ключа)
RE_FCGI_IP = re.compile(
    r'((?:REMOTE_ADDR|SERVER_ADDR|HTTP_X_REAL_IP|HTTP_X_FORWARDED_FOR))'
    r'((?:\d{1,3}\.){3}\d{1,3})'
)

# Учётные данные в исходниках (PHP/SQL в payload): $db_pass = '...'; и т.п.
# (секреты и идентификаторы: user/pass/login + имя БД; хост — не кред)
RE_CREDS_ASSIGN = re.compile(
    r'(\$?_?(?:db|DB)_(?:pass|pwd|password|user|login|name)\s*=\s*)'
    r'\'[^\']*\''
)

# Логин в MySQL handshake: имя пользователя идёт непосредственно перед
# \0<auth-plugin> (клиентский response всегда заканчивается именем плагина)
# или перед \0 + 20-байтной солью (старый протокол, соль = printable-байты).
# Имя — любое, якоримся на плагин/соль, не на NUL-префикс.
RE_MYSQL_USER = re.compile(
    # A: [хвост соли-escape] + имя + \0 + auth-plugin (имя ≥6 симв., чтобы не
    # цеплять обрывки соли; escape-префикс поглощается и сохраняется)
    r'((?:\\[0-7]{1,3})?)'
    r'([a-zA-Z0-9_$.\-]{6,64})'
    r'\\0(?=caching_sha2_password|mysql_native_password'
    r'|mysql_clear_password|sha256_password)'
    r'|((?:\\0){8,})((?:\\[0-7]{1,3})?)([a-zA-Z0-9_$.\-]{6,64})\\0(?=[ -~\\])'
)

# ПРИМЕЧАНИЕ: домены в DNS wire-формате маскируем ТОЛЬКО в строках DNS-трафика
# (сокеты на порт 53): бинарные escape-последовательности strace в других payload
# неотличимы от DNS-меток, общий шаблон даёт ложные срабатывания. См. sanitize_line.
DNS_WIRE_RE = re.compile(r'(?:\\[0-9]{1,3}[a-zA-Z0-9\-]+){2,}(?:\\300\\[0-9]{1,3})?')
# NDA: wire-домены заменяем на обезличенный mail.domain.tld (длины меток 3+6+3)
DNS_WIRE_FAKE = r'\3mail\6domain\3tld'

# Пути к файлам: /home/user/..., /var/www/..., /srv/..., /opt/...
# Не трогаем /usr, /etc, /proc, /tmp, /sys
RE_SENSITIVE_PATH = re.compile(
    r'('
    r'/home/[^/\s"\']+'                      # /home/user...
    r'|/var/www(?:-data)?/[^/\s"\']+'        # /var/www/site..., /var/www-data/...
    r'|/srv/[^/\s"\']+'                      # /srv/...
    r'|/opt/[^/\s"\']+'                      # /opt/...
    r')'
    r'(?:/[^/\s"\']*)*'                      # далее любые подкаталоги
)

# SQL-значения
RE_SQL_STRING = re.compile(r"=\s*'[^']*'")
RE_SQL_IN     = re.compile(r'IN\s*\([^)]+\)', re.I)
RE_SQL_NUMBER = re.compile(r'(?<==\s)\d{3,}')
RE_SQL_LIMIT  = re.compile(r'LIMIT\s+\d+', re.I)

# Стандартные WordPress-таблицы — НЕ маскируем
WP_TABLES = {
    'wp_options', 'wp_posts', 'wp_postmeta', 'wp_users', 'wp_usermeta',
    'wp_terms', 'wp_termmeta', 'wp_term_taxonomy', 'wp_term_relationships',
    'wp_comments', 'wp_commentmeta', 'wp_links', 'wp_actionscheduler_logs',
    'wp_actionscheduler_claims', 'wp_actionscheduler_actions',
}


class Sanitizer:
    def __init__(self):
        self.counters = {
            'ipv4': 0, 'ipv6': 0, 'email': 0, 'domain': 0,
            'path': 0, 'sql_value': 0, 'sql_in': 0, 'sql_number': 0,
            'sql_limit': 0, 'dns_wire': 0, 'cred': 0,
        }
        self.mappings = OrderedDict()
        self.reverse = {}

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

        # 1. DNS-пакеты (порт 53): маскируем имена в wire-формате до прочих правил.
        # Замена анонимная (без записи оригинала в mappings/report — NDA).
        # Линия DNS: порт 53 в адресе, либо sendmmsg/recvfrom/resumed (UDP-сокет,
        # в resumed-строках порт не печатается)
        is_dns_line = ':53]' in rest or re.match(
            r'.{0,60}\b(?:sendmmsg|recvfrom|recvmsg|resumed)\b', rest)
        if is_dns_line:
            n_dns = len(DNS_WIRE_RE.findall(rest))
            if n_dns:
                self.counters['dns_wire'] += n_dns
                rest = DNS_WIRE_RE.sub(lambda m: DNS_WIRE_FAKE, rest)
        # 1а. IP, приклеенный к FCGI-ключам (REMOTE_ADDR<ip>) — до общего прохода IPv4
        rest = RE_FCGI_IP.sub(
            lambda m: m.group(1) + self._next('ipv4', m.group(2)), rest)

        # 1б. IPv4
        rest = RE_IPV4.sub(lambda m: self._next('ipv4', m.group()), rest)

        # 2. IPv6 — полные 8-сегментные или с ::
        rest = RE_IPV6.sub(lambda m: self._next('ipv6', m.group()), rest)

        # 3. Email
        rest = RE_EMAIL.sub(lambda m: self._next('email', m.group()), rest)

        # 4a. Домены, приклеенные к FCGI-параметрам (до общего прохода доменов)
        rest = RE_FCGI_HOST.sub(
            lambda m: m.group(1) + self._next('domain', m.group(2)), rest)

        # 4b. Домены (DNS wire-формат маскируется отдельно выше, только для :53])

        # 4в. Домены
        def mask_domain(m):
            d = m.group()
            if d in ('example.com', 'example.org', 'localhost',
                     'test.local', 'wp.org', 'wordpress.org'):
                return d
            return self._next('domain', d)
        rest = RE_DOMAIN.sub(mask_domain, rest)

        # 5. Чувствительные пути
        def mask_path(m):
            p = m.group()
            if any(p.startswith(prefix) for prefix in (
                '/usr/', '/etc/', '/proc/', '/sys/', '/dev/',
                '/tmp/', '/run/', '/boot/', '/lib/', '/sbin/',
            )):
                return p
            return self._next('path', p)
        rest = RE_SENSITIVE_PATH.sub(mask_path, rest)

        # 6. SQL-значения (только если строка похожа на SQL)
        if re.search(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|WHERE|SET)\b', rest):
            rest = RE_SQL_STRING.sub(
                lambda m: self._sql_mask(m), rest
            )
            rest = RE_SQL_IN.sub(
                lambda m: self._sql_in_mask(m), rest
            )
            rest = RE_SQL_NUMBER.sub(
                lambda m: self._next('sql_number', m.group()), rest
            )
            rest = RE_SQL_LIMIT.sub(
                lambda m: self._next('sql_limit', m.group()), rest
            )

        # 6а. Учётные данные в исходниках ($db_pass = '...'; и т.п.) — независимо от SQL
        rest = RE_CREDS_ASSIGN.sub(
            lambda m: m.group(1) + self._next('cred', "'<CRED>'"), rest)
        # 6б. Логин в MySQL handshake
        # A: группы (1=хвост соли, 2=имя); B: группы (3=NUL-флаги, 4=хвост соли, 5=имя)
        def _mask_mysql_user(m):
            if m.group(2) is not None:
                prefix, name = m.group(1), m.group(2)
            else:
                prefix, name = m.group(3) + (m.group(4) or ''), m.group(5)
            return prefix + self._next('cred', name) + m.group()[len(prefix) + len(name):]
        rest = RE_MYSQL_USER.sub(_mask_mysql_user, rest)

        return header + rest

    def _sql_mask(self, m):
        val = m.group()
        for t in WP_TABLES:
            if t in val.lower():
                return val
        self.counters['sql_value'] += 1
        tag = f"<SQL_VAL_{self.counters['sql_value']}>"
        self.mappings[val] = tag
        self.reverse[tag] = val
        return tag

    def _sql_in_mask(self, m):
        val = m.group()
        for t in WP_TABLES:
            if t in val.lower():
                return val
        self.counters['sql_in'] += 1
        tag = f"<SQL_IN_{self.counters['sql_in']}>"
        self.mappings[val] = tag
        self.reverse[tag] = val
        return tag

    def sanitize_file(self, input_path):
        with open(input_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        result = []
        for line in lines:
            result.append(self.sanitize_line(line.rstrip('\n')))
        return result

    def report(self):
        lines = []
        lines.append("=" * 60)
        lines.append("ОТЧЁТ САНИТИЗАЦИИ")
        lines.append("=" * 60)

        total = sum(self.counters.values())
        if total == 0:
            lines.append("Замаскированных данных не обнаружено.")
            return '\n'.join(lines)

        lines.append(f"\nВсего замаскировано: {total}")
        for kind, count in self.counters.items():
            if count > 0:
                lines.append(f"  {kind}: {count}")

        lines.append("\n--- Соответствия (placeholder -> оригинал) ---")
        for tag, orig in self.reverse.items():
            display = orig if len(orig) <= 80 else orig[:77] + '...'
            lines.append(f"  {tag} -> {display}")

        return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Маскировка конфиденциальных данных в strace-логах"
    )
    ap.add_argument("input", help="входной strace-лог")
    ap.add_argument("-o", "--output",
                    help="файл для очищенного лога (по умолчанию: stdout)")
    ap.add_argument("--report", action="store_true",
                    help="вывести отчёт о заменах в stderr")
    args = ap.parse_args()

    s = Sanitizer()
    cleaned = s.sanitize_file(args.input)

    output_text = '\n'.join(cleaned) + '\n'

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output_text)
        print(f"Очищенный лог: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output_text)

    if args.report:
        print(s.report(), file=sys.stderr)


if __name__ == "__main__":
    main()
