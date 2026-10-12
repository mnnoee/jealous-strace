# Changelog

Все заметные изменения проекта документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

## [1.3.0] — 2026-10-12

### Added
- Упаковка проекта: `pyproject.toml` (PEP 621), установка через
  `pip install jealous-strace` и консольные команды `jealous-strace`
  и `jealous-sanitize`.
- Флаг `--version` в CLI.
- **`--json [PATH]`**: без значения — `report.json` в `outdir` (прежнее
  поведение, вызовы дашборда не ломаются); со значением — JSON пишется
  в указанный файл (единый контракт с jealous-nginx и jealous-domain).
- Лицензия GPL-3.0-or-later (`LICENSE`, `NOTICE`).
- `CHANGELOG.md`.
- Тесты CLI-контракта `--json` (оба режима) и `write_json_to`.

### Changed
- `sanitize_log.py` перенесён в пакет как `straceparse/sanitize.py`;
  на прежнем месте осталась тонкая обёртка — старые вызовы работают.
- Версия теперь задаётся в одном месте — `straceparse/constants.py`
  (`VERSION`, формат SemVer `1.3.0`); `__init__.py` реэкспортирует её как
  `__version__`, `pyproject.toml` читает через `[tool.setuptools.dynamic]`.
- Конфигурация pytest перенесена в `pyproject.toml`.

### Fixed
- Китайский иероглиф в докстринге `sanitize.py` (артефакт правки).

## [1.2] — 2026-09-03

### Added
- Атрибуция нагрузки (`load.py`): per-PID / per-запрос / per-компонент WP,
  пиковые секунды; CPU~ = wall - блокирующие ожидания.
- Сигнатуры инцидентов (`signatures.py`): петля редиректов, смешанные
  HTTP/HTTPS, Secure-cookie по HTTP, шквал ENOENT.
- Тайминг SQL (`sql_timing.py`): длительности (send -> recv), перцентили
  p50/p95/p99, детект N+1, привязка медленных запросов к URI.
- Фазы WordPress из `Server-Timing` (`servertiming.py`).
- Редиректы (`redirects.py`): цепочки 3xx с восстановлением перенаправлений.
- JSON-экспорт (`json_export.py`): машиночитаемый `report.json` (`--json`).
- `sanitize_log.py`: маскировка конфиденциальных данных в strace-логах.
- RAM/OOM-анализ, SSL/mTLS-анализ (`--mtls`), WordPress-диагностика
  (`--wordpress`).

## [1.1] и ранее

См. историю git.

[Unreleased]: https://github.com/mnnoee/jealous-strace/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/mnnoee/jealous-strace/compare/v1.2...v1.3.0
[1.2]: https://github.com/mnnoee/jealous-strace/releases/tag/v1.2
