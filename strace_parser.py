#!/usr/bin/env python3
"""
Универсальный парсер strace-логов (модульная версия).

Логика вынесена в пакет straceparse/:
  - core.py       — Syscall, StraceParser (разбор строк, трекинг состояния)
  - wp.py         — диагностика WordPress
  - mem.py        — RAM/OOM анализ
  - mtls.py       — SSL/mTLS анализ (клиентские сертификаты, SNI, SSL-ошибки)
  - report.py     — построение отчёта
  - csv_export.py — CSV-файлы
  - cli.py        — CLI (процесс аргументов)

Этот файл остаётся тонкой обёрткой, чтобы сохранить прежние вызовы.
"""

from straceparse.cli import main

if __name__ == "__main__":
    main()
