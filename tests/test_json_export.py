"""Unit-тесты: JSON-экспорт."""

import datetime
import json
import os
import sys
import tempfile
import unittest
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from straceparse import json_export
from straceparse.core import StraceParser
from straceparse.json_export import build_json

T0 = datetime.datetime.fromtimestamp(1788938386)


def make_parser():
    p = StraceParser(wordpress=True)
    p.http_requests = [
        {"pid": 1, "fd": 4, "start": T0, "end": T0 + datetime.timedelta(seconds=2),
         "method": "POST", "uri": "/topograf.php", "host": "x.xyz",
         "status": 302, "location": "https://x.xyz/wp-admin/",
         "scheme": "https", "server_timing": [("wp-total", 1399.55)],
         "set_cookie": [{"name": "wordpress_sec_x", "secure": True, "flags": ["secure"]}]},
        {"pid": 1, "fd": 5, "start": T0 + datetime.timedelta(seconds=5),
         "end": T0 + datetime.timedelta(seconds=9),
         "method": "GET", "uri": "/wp-admin/", "host": "x.xyz",
         "status": 302, "location": "http://x.xyz", "scheme": None},
        {"pid": 1, "fd": 6, "start": T0 + datetime.timedelta(seconds=10),
         "end": T0 + datetime.timedelta(seconds=11),
         "method": "GET", "uri": "/", "host": "x.xyz", "status": 200},
    ]
    st = T0 + datetime.timedelta(seconds=1)
    p.sql_queries = [{
        "ts": st, "start_ts": st, "end_ts": st + datetime.timedelta(seconds=1),
        "pid": 1, "fd": 7, "file": "f", "server": None,
        "sql": "SELECT option_value FROM wpes_options WHERE option_name = 'x'",
        "recv_bytes": 512,
    }]
    p.open_missing = Counter({"no/such": 300})
    return p


class BuildJsonTest(unittest.TestCase):
    def test_structure(self):
        p = make_parser()
        data = build_json(p)
        for key in ("meta", "syscalls", "sql", "http", "errors", "files",
                    "network", "dns", "signatures", "mem", "wordpress",
                    "redirect_chains", "server_timing"):
            self.assertIn(key, data)

    def test_serializable(self):
        p = make_parser()
        data = build_json(p)
        s = json.dumps(data, ensure_ascii=False, default=str)
        self.assertIn('"uri": "/topograf.php"', s)
        self.assertEqual(json.loads(s)["meta"]["lines_total"], 0)

    def test_catches_scheme_switch_signature(self):
        data = build_json(make_parser())
        joined = " ".join(sig["message"] for sig in data["signatures"])
        self.assertIn("СМЕШАННЫЕ HTTP/HTTPS", joined)

    def test_redirect_chains(self):
        data = build_json(make_parser())
        # POST /topograf.php -> /wp-admin/ -> /
        self.assertEqual(len(data["redirect_chains"]), 1)
        chain = data["redirect_chains"][0]
        self.assertEqual([r["uri"] for r in chain], ["/topograf.php", "/wp-admin/", "/"])

    def test_sql_includes_timing(self):
        data = build_json(make_parser())
        self.assertEqual(data["sql"]["count"], 1)
        self.assertTrue(data["sql"]["timed"])


class CliJsonTest(unittest.TestCase):
    """Контракт --json: без значения — report.json в outdir (как раньше),
    со значением — указанный путь (единый контракт с nginx/domain)."""

    def _log(self, tmp):
        path = os.path.join(tmp, "trace.log")
        with open(path, "w") as f:
            f.write("")  # пустой лог — отчёт всё равно пишется
        return path

    def test_json_flag_writes_to_outdir(self):
        from unittest import mock

        from straceparse import cli as cli_mod
        with tempfile.TemporaryDirectory() as tmp:
            log = self._log(tmp)
            outdir = os.path.join(tmp, "report")
            with mock.patch("sys.argv",
                            ["strace_parser.py", log, "--outdir", outdir,
                             "--json", "--no-csv"]), \
                 mock.patch("builtins.print"):
                cli_mod.main()
            self.assertTrue(os.path.exists(os.path.join(outdir, "report.json")))

    def test_json_path_writes_to_path(self):
        from unittest import mock

        from straceparse import cli as cli_mod
        with tempfile.TemporaryDirectory() as tmp:
            log = self._log(tmp)
            out = os.path.join(tmp, "custom.json")
            with mock.patch("sys.argv",
                            ["strace_parser.py", log, "--json", out, "--no-csv"]), \
                 mock.patch("builtins.print"):
                cli_mod.main()
            self.assertTrue(os.path.exists(out))

    def test_write_json_to(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.json")
            got = json_export.write_json_to(make_parser(), path)
            self.assertEqual(got, path)
            with open(path) as f:
                doc = json.load(f)
            self.assertIn("meta", doc)


if __name__ == "__main__":
    unittest.main()
