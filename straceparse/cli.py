"""Точка входа"""

import argparse
import gzip
import os
import sys

from . import csv_export, json_export
from .constants import VERSION
from .core import StraceParser
from .i18n import prescan_argv, set_lang, t
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
                print(t("cli.progress_line", n=processed, path=path), file=sys.stderr)
    if progress:
        print(t("cli.progress_done", n=processed, path=path), file=sys.stderr)


def main():
    set_lang(prescan_argv(sys.argv[1:]))
    ap = argparse.ArgumentParser(description=t("cli.desc"))
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {VERSION}")
    ap.add_argument("paths", nargs="+", help=t("cli.paths"))
    ap.add_argument("-o", "--outdir", default="report", help=t("cli.outdir"))
    ap.add_argument("-t", "--threshold", type=float, default=0.1, help=t("cli.threshold"))
    ap.add_argument("--top", type=int, default=50, help=t("cli.top"))
    ap.add_argument("--no-csv", action="store_true", help=t("cli.no_csv"))
    ap.add_argument("--json", nargs="?", const=True, default=False, metavar="PATH",
                    help=t("cli.json"))
    ap.add_argument("--wordpress", action="store_true", help=t("cli.wordpress"))
    ap.add_argument("--mtls", action="store_true", help=t("cli.mtls"))
    ap.add_argument("--all", action="store_true", help=t("cli.all"))
    ap.add_argument("--progress", action="store_true", help=t("cli.progress"))
    ap.add_argument("--max-lines", type=int, default=0, metavar="N",
                    help=t("cli.max_lines"))
    ap.add_argument("--sample-every", type=int, default=1, metavar="N",
                    help=t("cli.sample_every"))
    ap.add_argument("--mail-body", action="store_true", help=t("cli.mail_body"))
    ap.add_argument("--lang", choices=("auto", "ru", "en"), default="auto",
                    help=t("cli.lang"))
    args = ap.parse_args()
    set_lang(args.lang)

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
            print(t("cli.warn_missing", path=path_arg), file=sys.stderr)

    parser = StraceParser(threshold=args.threshold, slow_top=args.top,
                          wordpress=args.wordpress or args.all, mtls=args.mtls or args.all,
                          mail=True, mail_body=args.mail_body)

    for fp in sorted(files):
        print(t("cli.processing", path=fp), file=sys.stderr)
        process_file(fp, parser, max_lines=args.max_lines,
                     sample_every=args.sample_every, progress=args.progress)

    parser.finalize()
    report = build_report(parser)
    print(report)

    if not args.no_csv:
        csv_export.write_csvs(parser, args.outdir)
        print(t("cli.csv_written", path=args.outdir), file=sys.stderr)
        with open(os.path.join(args.outdir, "report.txt"), "w") as f:
            f.write(report)

    if args.json:
        if args.json is True:
            os.makedirs(args.outdir, exist_ok=True)
            path = json_export.write_json_report(parser, args.outdir)
        else:
            path = json_export.write_json_to(parser, args.json)
        print(t("cli.json_written", path=path), file=sys.stderr)


if __name__ == "__main__":
    main()
