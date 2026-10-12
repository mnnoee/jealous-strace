"""Unit-тесты: парсинг Server-Timing и секция фаз WP."""

import io
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from straceparse.parse_utils import extract_server_timing
from straceparse.servertiming import phases_by_request, report_section


class ExtractServerTimingTest(unittest.TestCase):
    def test_single(self):
        data = (b"Status: 200\r\n"
                b"Server-Timing: wp-before-template;dur=1169.49\r\n\r\n")
        self.assertEqual(extract_server_timing(data),
                         [("wp-before-template", 1169.49)])

    def test_multiple(self):
        data = (b"Server-Timing: wp-before-template;dur=1169.49, "
                b"wp-template;dur=230.07, wp-total;dur=1399.55")
        self.assertEqual(extract_server_timing(data),
                         [("wp-before-template", 1169.49),
                          ("wp-template", 230.07),
                          ("wp-total", 1399.55)])

    def test_noise_entries_ignored(self):
        data = b"Server-Timing: wp-total;dur=1.0, junk;none=2"
        self.assertEqual(extract_server_timing(data), [("wp-total", 1.0)])

    def test_absent(self):
        self.assertIsNone(extract_server_timing(b"Status: 200\r\n\r\n"))
        self.assertIsNone(extract_server_timing(None))


class ReportSectionTest(unittest.TestCase):
    def _parser(self):
        class P:
            pass
        p = P()
        p.http_requests = [
            {"method": "GET", "uri": "/", "start": None, "end": None,
             "server_timing": [("wp-before-template", 1169.49),
                               ("wp-template", 230.07),
                               ("wp-total", 1399.55)]},
        ]
        return p

    def test_phases_by_request(self):
        p = self._parser()
        items = phases_by_request(p)
        self.assertEqual(len(items), 1)
        r, phases = items[0]
        self.assertEqual(phases["wp-before-template"], 1169.49)

    def test_report_section_runs(self):
        p = self._parser()
        buf = io.StringIO()
        report_section(p, buf.write)
        out = buf.getvalue()
        self.assertIn("ФАЗЫ ЗАПРОСОВ", out)
        self.assertIn("wp-before-template", out)

    def test_report_section_empty(self):
        p = self._parser()
        p.http_requests = []
        buf = io.StringIO()
        report_section(p, buf.write)
        self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
