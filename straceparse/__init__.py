"""
straceparse — модульный парсер strace-логов.

Разбит на модули по сквозным доменам:
  constants, parse_utils — чистые константы и хелперы;
  core                  — Syscall, StraceParser (разбор + трекинг);
  wp / mem / mtls       — feature-модули (функции, работающие с экземпляром);
  report / csv_export   — вывод отчёта и CSV;
  cli                   — точка входа командной строки.
"""

from .cli import main, process_file
from .constants import VERSION
from .core import StraceParser, Syscall
from .report import build_report

# Версия берётся из constants.VERSION — единственный источник истины.
# pyproject.toml читает её через [tool.setuptools.dynamic].
__version__ = VERSION

__all__ = ["VERSION", "__version__", "StraceParser", "Syscall", "build_report", "process_file", "main"]
