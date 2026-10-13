# jealous-strace

[README in English](README.md)

[![CI](https://github.com/mnnoee/jealous-strace/actions/workflows/ci.yml/badge.svg)](https://github.com/mnnoee/jealous-strace/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.3.0-green.svg)](CHANGELOG.md)

> Часть набора инструментов [Jealous Moon](https://github.com/mnnoee) —
> офлайн-диагностики серверов и доменов.

Универсальный парсер strace-логов с человекочитаемым отчётом и CSV-экспортом.

## Установка

Пока не на PyPI (публикация планируется). Ставится напрямую с GitHub:

```bash
pip install git+https://github.com/mnnoee/jealous-strace.git
```

После установки доступны команды `jealous-strace` и `jealous-sanitize`.
Можно запускать и без установки — прямо из клона репозитория:

```bash
python3 strace_parser.py /path/to/strace.log
```

## Возможности

- Автоопределение формата строк (PID+время, PID без времени, без PID)
- Статистика по системным вызовам (количество, ошибки, время)
- Файловый доступ (открытия, чтения, записи, байты)
- Сеть: connect, DNS, SQL-запросы, HTTP/FCGI
- Медленные вызовы, незавершённые вызовы, ошибки соединений
- Анализ по PID, гистограммы
- Редиректы и сигнатуры инцидентов (петли, смешанные HTTP/HTTPS, Secure-cookie, ENOENT)
- Тайминг SQL и детект N+1
- Фазы WordPress из Server-Timing
- Атрибуция нагрузки: кто потребляет ресурсы (PID / URI / плагины)
- JSON-экспорт (`--json`)

## Зависимости

Python 3.9+ (только стандартная библиотека).

## Пример лога

Рекомендуемый способ собрать лог (attach к живым PHP-процессам):

```bash
strace -p $(pgrep -u $USER -d',' -f 'php') -f -s 65535 -v -yy -ttt -T -i -X verbose -o ~/strace.log
```

Модуль ест вывод `strace` (автоопределение формата: PID+время, PID+epoch,
без PID, access log; поддержаны флаги `-T` (длительности), `-yy` (аннотации
fd), `-i` (instruction pointer), `-s` (длина строк)):

```
2992844 13:40:00.101234 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = 0 <0.000123>
2992844 1757932800.104567 [7f2a1b0c] openat(AT_FDCWD, "/var/www/wp-includes/version.php", O_RDONLY|O_CLOEXEC) = 7
2992844 13:40:00.110001 sendto(7, "SELECT option_value FROM wp_options", 35, 0, NULL, NULL) = 35 <0.000045>
2992845 13:40:00.115678 recvfrom(4, "HTTP/1.1 302 Found\r\nLocation: https://acme.local/wp-admin/", 8192, 0, NULL, NULL) = 58
```

## Использование

```bash
# Базовый анализ
jealous-strace /path/to/strace.log

# Несколько файлов
jealous-strace log1.log log2.log

# Каталог с логами
jealous-strace /var/log/strace/

# С флагами
jealous-strace log.txt --wordpress    # анализ для WordPress
jealous-strace log.txt --all          # все модули
jealous-strace --version              # версия
```

Без установки — так же, но через `python3 strace_parser.py`.

### Флаги

| Флаг | Описание |
|------|----------|
| `-o, --outdir` | Каталог для отчёта и CSV (по умолчанию: `report`) |
| `-t, --threshold` | Порог медленных вызовов, сек (по умолчанию: 0.1) |
| `--top` | Сколько медленных вызовов показать (по умолчанию: 50) |
| `--no-csv` | Не писать CSV-файлы |
| `--json [PATH]` | Писать JSON-отчёт: без значения — `report.json` в `outdir` (как раньше), со значением — указанный файл |
| `--wordpress` | Включить анализ для WordPress |
| `--mtls` | Включить анализ SSL/mTLS (клиентские сертификаты, ошибки SSL-сертификата) |
| `--all` | Включить все модули |

### Модуль WordPress (`--wordpress`)

- Группировка файлов по компонентам (плагины, темы, ядро)
- Autoload bloat detection (перегруженная таблица wp_options)
- Тяжёлые плагины по суммарному чтению

### Модуль SSL/mTLS (`--mtls`)

Диагностика ошибок взаимной TLS-аутентификации (например, `400 The SSL certificate error`
от nginx при обработке запроса с клиентским SSL-сертификатом). Модуль:

- Определяет клиентские сертификаты/ключи (`.pem`, `.crt`, `.key`, ...), прочитанные процессами
- Показывает HTTPS-подключения на порт 443 с распознанным SNI-хостом
- Детектит ответ сервера с текстом `SSL certificate error` (сервер отклонил клиентский сертификат)
- Даёт рекомендации (проверить срок действия сертификата, получить новый, заменить на сервере)

### Редиректы и сигнатуры

- **Редиректы**: секция «РЕДИРЕКТЫ (HTTP 3xx)» — полный список 3xx с `Location` и
  восстановление цепочек перенаправлений (`POST /login -> https://…/wp-admin/ -> GET / -> http://…`).
- **Сигнатуры инцидентов**: автодетект в секции «СИГНАТУРЫ ИНЦИДЕНТОВ»:
  петля редиректов, смешанные HTTP/HTTPS (локация ведёт в `https`, а запрос пришёл по `http` —
  классика «админка не открывается»), Secure-cookie по HTTP, шквал ENOENT.

> **Важно:** Сигнатуры — эвристика, а не истина. Совпадение с сигнатурой не
> доказывает инцидент: «шквал ENOENT» может быть штатной работой плагина,
> а смешанный HTTP/HTTPS — осознанной конфигурацией. Прежде чем действовать,
> проверьте вручную по контексту лога.

### Тайминг SQL и N+1

- Приблизительная длительность каждого SQL-запроса (send -> ответ), перцентили p50/p95/p99,
  топ самых медленных запросов с привязкой к URI.
- Детект **N+1**: одна нормализованная форма выполняется десятки раз подряд в цикле
  (частый источник CPU — чтение постов/мета по одной записи).

> Длительности SQL приблизительные (send -> recv/следующий запрос): при
> медленном стриминге ответа время завышается. Для ранжирования узких мест
> годится, для точных цифр — нет.

### Фазы WordPress (Server-Timing)

Заголовок `Server-Timing: wp-before-template;dur=…, wp-template;dur=…, wp-total;dur=…`
из HTTP/FCGI-ответов разбирается в секцию «ФАЗЫ ЗАПРОСОВ» — показывает, где теряется время
(bootstrap / тема / шаблон) и какая фаза доминирует.

### JSON-отчёт (`--json [PATH]`)

Без значения — `report.json` рядом с `report.txt` (в `outdir`), как и раньше.
Со значением — JSON пишется в указанный файл (единый контракт с
jealous-nginx и jealous-domain):

```
python3 strace_parser.py trace.log --json                # outdir/report.json
python3 strace_parser.py trace.log --json out.json       # указанный файл
```

Структурированный дамп результатов для дашбордов/алертов: syscalls, files,
network, dns, sql (+тайминг, N+1), http (+цепочки редиректов),
server_timing, signatures, mem, wordpress, load.

### Кто потребляет ресурсы (нагрузка)

strace не измеряет CPU напрямую, поэтому модуль `load.py` даёт честные оценки:

- **По PID**: число syscall, время в ядре, время в блокирующих ожиданиях
  (accept/poll/read/recv — это простой, не работа) и `CPU~` = время вне ожиданий
  (пользовательский код = PHP). Ранжирование по `CPU~`.
- **По HTTP-запросам**: какая страница сколько syscall и CPU-времени съела
  (обрабатывается в рамках окна запроса), топ самых «тяжёлых» URI.
- **По компонентам WP**: какие плагины делают больше всего syscall в самом
  нагрузочном запросе (например `wordpress-seo`, `ninja-forms`, `popup-maker`).
- **Пиковые секунды**: секунды максимальной глобальной активности + топ PID в них.

Пример вывода секции «НАГРУЗКА: КТО ПОТРЕБЛЯЕТ РЕСУРСЫ» —
`GET /topograf.php`: 14.9с CPU~ vs 0.18с kernel -> процесс молотил в PHP-коде,
а не ждал БД/сети.

## Структура кода (модульная)

Логика вынесена из одного файла в пакет `straceparse/`. `strace_parser.py` — тонкая
CLI-обёртка (`from straceparse.cli import main`), все прежние команды работают как раньше.

```
strace_parser.py            # обёртка CLI
sanitize_log.py             # обёртка санитайзера (маскировка данных)
straceparse/
  __init__.py               # экспорты: VERSION, StraceParser, build_report, main
  constants.py              # регулярные выражения, RCODE_NAMES, escape-таблицы
  parse_utils.py            # чистые хелперы: unescape, sockaddr, FCGI, DNS, fmt_bytes,
                            #   normalize_sql, server_timing, set_cookie
  core.py                   # Syscall + StraceParser: разбор строк, трекинг fd/сокетов/файлов,
                            #   вызовы feature-хуков wp/mem/mtls, схема/тайминг SQL
  wp.py                     # диагностика WordPress (компоненты, ядро, тема, версии, тяжёлые плагины)
  mem.py                    # RAM/OOM анализ (mmap/munmap, Out of memory, секция отчёта)
  mtls.py                   # SSL/mTLS анализ (сертификаты, SNI, SSL-ошибки, секция отчёта)
  redirects.py              # редиректы (цепочки 3xx, секция отчёта)
  signatures.py             # сигнатуры инцидентов (петли, http/https, secure-cookie, ENOENT)
  sql_timing.py             # тайминг SQL, перцентили, N+1, привязка к URI
  servertiming.py           # фазы WordPress из Server-Timing
  json_export.py            # build_json()/write_json_report() (--json)
  load.py                   # атрибуция нагрузки: PID/URI/плагины/пиковые секунды
  report.py                 # build_report() по секциям
  csv_export.py             # write_csvs()
  sanitize.py               # маскировка конфиденциальных данных
  cli.py                    # process_file(), main()
tests/                      # юнит-тесты на синтетических данных
pyproject.toml              # упаковка, версия, pytest, ruff
.github/workflows/ci.yml    # CI: матрица 3.9–3.13, lint + тесты + smoke
LICENSE / NOTICE            # GPL-3.0-or-later
CHANGELOG.md                # история изменений
RELEASING.md                # процесс выпуска версий
CONTRIBUTING.md             # как участвовать в разработке
```

Направление зависимостей одностороннее: `core -> (wp, mem, mtls) -> parse_utils/constants`.
Добавление новой фичи = новый модуль + хук в нужной точке `core` или секция в `report`.

## Выходные данные

### Отчёт (report.txt)

Человекочитаемый текстовый отчёт с секциями:

- Ключевые проблемы (сводка)
- Системные вызовы + скорость
- Ошибки
- Файлы (+ компоненты WP)
- Сеть, DNS
- SQL-запросы (нормализованный топ)
- По процессам
- Незавершённые вызовы
- Медленные вызовы
- Стоимость HTTP-запроса
- Тяжёлые плагины (WP)

### CSV-файлы

- `syscalls.csv` — статистика по syscall'ам
- `errors.csv` — ошибки
- `files.csv` — файловый доступ
- `network.csv` — подключения
- `dns.csv` — DNS-запросы
- `sql.csv` — SQL-запросы
- `http.csv` — HTTP/FCGI запросы
- `pids.csv` — по процессам
- `slow.csv` — медленные вызовы
- `unfinished.csv` — незавершённые вызовы
- `access.csv` — access-логи (если есть)

## Пример отчёта

```
=== СКОРОСТЬ (за 30.0 сек) ===
syscall/сек:       12000
openat/сек:          500
lstat/сек:           900
SQL/сек:             400

=== SQL-ЗАПРОСЫ ===
Всего SQL-запросов: 10000

Топ запросов (нормализованные):
   7500 (75.0%)  SELECT option_name, option_value FROM wp_options WHERE autoload IN (...)
    700 ( 7.0%)  SELECT option_value FROM wp_options WHERE option_name = ...

[!] AUTOLOAD BLOB DETECTED
    7500 из 10000 запросов (75.0%) — загрузка опций с autoload.
```

## Участие в разработке

См. [CONTRIBUTING.md](CONTRIBUTING.md).

## Идеи и предложения

Есть идея, чего не хватает в проекте? Открывайте issue — предложения по новым
секциям отчёта, детектам сигнатур, форматам выгрузки и интеграциям
приветствуются.

## Лицензия

GPL-3.0-or-later. Подробности — в [LICENSE](LICENSE) и [NOTICE](NOTICE).
