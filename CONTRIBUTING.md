# Участие в разработке

## Как предлагать идеи/фичи

Создайте Issue в репозитории с кратким описанием проблемы и желаемого поведения.

## Как предлагать код

Отправьте Pull Request с описанием изменений. До мержа убедитесь, что:

```bash
# тесты
python -m pytest

# линтер
ruff check .
```

- Код проходит тесты и линтер
- Описание PR содержит контекст: что было, что стало, зачем
- Новая фича = новый модуль в `straceparse/` + хук в нужной точке `core`
  или секция в `report`, а не разрастание существующих файлов

## Структура проекта

```
strace_parser.py          тонкая CLI-обёртка
sanitize_log.py           тонкая обёртка санитайзера
straceparse/
  __init__.py             экспорты: VERSION, StraceParser, build_report, main
  constants.py            регулярные выражения, RCODE_NAMES, VERSION
  parse_utils.py          чистые хелперы: unescape, sockaddr, FCGI, DNS,
                          normalize_sql, server_timing, set_cookie
  core.py                 Syscall + StraceParser: разбор строк, трекинг
                          fd/сокетов/файлов, feature-хуки wp/mem/mtls
  wp.py                   WordPress: компоненты, ядро, темы, тяжёлые плагины
  mem.py                  RAM/OOM анализ
  mtls.py                 SSL/mTLS анализ
  redirects.py            редиректы (цепочки 3xx)
  signatures.py           сигнатуры инцидентов
  sql_timing.py           тайминг SQL, перцентили, N+1
  servertiming.py         фазы WP из Server-Timing
  load.py                 атрибуция нагрузки
  json_export.py          машиночитаемый report.json (--json)
  report.py               build_report() по секциям
  csv_export.py           write_csvs()
  sanitize.py             маскировка конфиденциальных данных
  cli.py                  process_file(), main()
tests/                    юнит-тесты на синтетических данных
```

Направление зависимостей одностороннее:
`core -> (wp, mem, mtls) -> parse_utils/constants` (без циклов).

## Важно: конфиденциальность strace-логов

strace-логи содержат всё: хосты, пути, SQL с реальными данными, бизнес-процессы.
Если PR или Issue включает примеры логов или вывод отчёта, **обязательно**
перед публикацией:

- замените все реальные хосты/IP/домены на `example.com`, `example.org`, `test.local`
- замените пути с именами компаний/клиентов на generic-пути (`/path/to/logs/`)
- уберите содержимое SQL-запросов с реальными названиями таблиц/данных
  (кроме стандартных `wp_*` таблиц для демонстрации)
- в идеале — прогоните лог через санитайзер перед вложением в Issue/PR

### Автоматическая санитизация

```bash
# Очистка лога + отчёт о заменах
jealous-sanitize your_strace.log -o clean.log --report

# или без установки
python3 sanitize_log.py your_strace.log -o clean.log --report
```

### Какие данные маскирует санитайзер

| Тип данных | Пример до | Пример после |
|------------|-----------|--------------|
| IPv4 | `192.168.1.100` | `<IPV4_1>` |
| Домены | `shop.client.ru` | `<DOMAIN_1>` |
| Email | `dev@acmecorp.ru` | `<EMAIL_1>` |
| Пути | `/home/clientproject/www/` | `<PATH_1>` |
| SQL-значения | `WHERE name = 'John'` | `WHERE name <SQL_VAL_1>` |
| SQL IN (...) | `IN (100, 200)` | `<SQL_IN_1>` |

Стандартные WordPress-таблицы (`wp_options`, `wp_posts` и т.д.) **не маскируются**.

## Версионирование и релизы

- SemVer: `MAJOR.MINOR.PATCH`. Источник истины — `VERSION` в
  `straceparse/constants.py`; `pyproject.toml` читает её автоматически,
  руками версию нигде дублировать не нужно.
- Каждое изменение — запись в `CHANGELOG.md` (Keep a Changelog).
- Релиз: обновить `VERSION` -> запись в CHANGELOG -> тег `vX.Y.Z`.
