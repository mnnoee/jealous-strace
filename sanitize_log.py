#!/usr/bin/env python3
"""Маскировка конфиденциальных данных в strace-логах (тонкая обёртка).

Реализация — в straceparse/sanitize.py.

Использование:
    python3 sanitize_log.py input.log                  # вывод в stdout
    python3 sanitize_log.py input.log -o clean.log     # вывод в файл
    python3 sanitize_log.py input.log --report         # + отчёт о заменах
"""

from straceparse.sanitize import main

if __name__ == "__main__":
    main()
