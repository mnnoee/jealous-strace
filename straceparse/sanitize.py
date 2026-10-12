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

# Пути к файлам: /home/user/..., /var/www/..., /srv/..., /opt/...
# Не трогаем /usr, /etc, /proc, /tmp, /sys
RE_SENSITIVE_PATH = re.compile(
    r'('
    r'/home/[^/\s"\']+'                      # /home/user...
    r'|/var/www/[^/\s"\']+'                  # /var/www/site...
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
            'sql_limit': 0,
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

        # 1. IPv4
        rest = RE_IPV4.sub(lambda m: self._next('ipv4', m.group()), rest)

        # 2. IPv6 — полные 8-сегментные или с ::
        rest = RE_IPV6.sub(lambda m: self._next('ipv6', m.group()), rest)

        # 3. Email
        rest = RE_EMAIL.sub(lambda m: self._next('email', m.group()), rest)

        # 4. Домены
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
