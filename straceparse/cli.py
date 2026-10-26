"""Точка входа CLI для пакета straceparse."""

import argparse
import gzip
import os
import sys

from . import csv_export, json_export
from .constants import VERSION
from .core import StraceParser
from .report import build_report


def process_file(path, parser, max_lines=0, sample_every=1, progress=False):
    opener = gzip.open if path.endswith(".gz") else open
    processed = 0
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if max_lines and i > max_lines:
                break
            if sample_every > 1 and (i % sample_every != 0):
                parser.lines_total += 1
                continue
            parser.parse_line(line, path)
            processed += 1
            if progress and processed % 100000 == 0:
                print(f"  ... {processed} строк обработано ({path})", file=sys.stderr)
    if progress:
        print(f"  ... готово: {processed} строк обработано ({path})", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Парсер strace-логов")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {VERSION}")
    ap.add_argument("paths", nargs="+", help="файлы или каталоги с логами")
    ap.add_argument("-o", "--outdir", default="report", help="каталог для отчёта и CSV (по умолчанию: report)")
    ap.add_argument("-t", "--threshold", type=float, default=0.1, help="порог медленных вызовов, сек (по умолчанию 0.1)")
    ap.add_argument("--top", type=int, default=50, help="сколько медленных вызовов показать (по умолчанию 50)")
    ap.add_argument("--no-csv", action="store_true", help="не писать CSV")
    ap.add_argument("--json", nargs="?", const=True, default=False, metavar="PATH",
                    help="писать JSON-отчёт (без значения — report.json в outdir, как раньше;"
                         " со значением — указанный путь)")
    ap.add_argument("--wordpress", action="store_true", help="включить анализ для WordPress (компоненты, autoload bloat, тяжёлые плагины)")
    ap.add_argument("--mtls", action="store_true", help="включить анализ SSL/mTLS (клиентские сертификаты, ошибки SSL-сертификата)")
    ap.add_argument("--all", action="store_true", help="включить все модули (CMS и прочее)")
    ap.add_argument("--progress", action="store_true", help="показывать прогресс обработки (для больших логов)")
    ap.add_argument("--max-lines", type=int, default=0, metavar="N",
                    help="обработать не более N строк файла (0 = все)")
    ap.add_argument("--sample-every", type=int, default=1, metavar="N",
                    help="обрабатывать каждую N-ю строку (экономия RAM/времени на гигантских логах)")
    ap.add_argument("--mail-body", action="store_true", help="включать тело письма и подробности в отчёт/экспорт (приватные данные)")
    args = ap.parse_args()

    files = []
    for path_arg in args.paths:
        if os.path.isdir(path_arg):
            for root, _, fns in os.walk(path_arg):
                for fn in fns:
                    fp = os.path.join(root, fn)
                    if os.path.isfile(fp):
                        files.append(fp)
        elif os.path.isfile(path_arg):
            files.append(path_arg)
        else:
            print(f"Предупреждение: не найден путь {path_arg}", file=sys.stderr)

    parser = StraceParser(threshold=args.threshold, slow_top=args.top,
                          wordpress=args.wordpress or args.all, mtls=args.mtls or args.all,
                          mail=True, mail_body=args.mail_body)

    for fp in sorted(files):
        print(f"Обработка: {fp} ...", file=sys.stderr)
        process_file(fp, parser, max_lines=args.max_lines,
                     sample_every=args.sample_every, progress=args.progress)

    parser.finalize()
    report = build_report(parser)
    print(report)

    if not args.no_csv:
        csv_export.write_csvs(parser, args.outdir)
        print(f"\nCSV-файлы записаны в: {args.outdir}", file=sys.stderr)
        with open(os.path.join(args.outdir, "report.txt"), "w") as f:
            f.write(report)

    if args.json:
        if args.json is True:
            # --json без значения — прежнее поведение: report.json в outdir
            # (outdir обычно создаёт write_csvs; с --no-csv создаём сами)
            os.makedirs(args.outdir, exist_ok=True)
            path = json_export.write_json_report(parser, args.outdir)
        else:
            # --json PATH — единый контракт с nginx/domain: указанный файл
            path = json_export.write_json_to(parser, args.json)
        print(f"JSON-отчёт записан в: {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
