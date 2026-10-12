"""Unit-тесты для модуля анализа редиректов (straceparse/redirects.py)."""

import datetime
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from straceparse.redirects import _location_path, _normalize_uri, build_chains  # noqa: E402


def _req(method, uri, status, location=None, start_sec=0):
    return {
        "method": method,
        "uri": uri,
        "host": "example.com",
        "status": status,
        "location": location,
        "referer": None,
        "start": datetime.datetime.fromtimestamp(1788938386 + start_sec),
        "end": datetime.datetime.fromtimestamp(1788938386 + start_sec + 1),
        "pid": 1,
        "fd": 4,
    }


class LocationPathTest(unittest.TestCase):
    def test_absolute(self):
        self.assertEqual(
            _location_path("https://xn--80anccitz3fwb.xyz/wp-admin/"),
            "/wp-admin/")

    def test_http(self):
        self.assertEqual(_location_path("http://xn--80anccitz3fwb.xyz"), "/")

    def test_relative(self):
        self.assertEqual(_location_path("/wp-login.php?redirect_to=/wp-admin/"),
                         "/wp-login.php")

    def test_empty(self):
        self.assertIsNone(_location_path(None))
        self.assertIsNone(_location_path(""))


class NormalizeUriTest(unittest.TestCase):
    def test_query_stripped(self):
        self.assertEqual(_normalize_uri("/topograf.php?foo=1"), "/topograf.php")

    def test_trailing_slash(self):
        self.assertEqual(_normalize_uri("/wp-admin/"), "/wp-admin")

    def test_root(self):
        self.assertEqual(_normalize_uri("/"), "/")


class BuildChainsTest(unittest.TestCase):
    def test_login_loop(self):
        reqs = [
            _req("POST", "/topograf.php", 302,
                 "https://xn--80anccitz3fwb.xyz/wp-admin/", 0),
            _req("GET", "/wp-admin/", 302, "http://xn--80anccitz3fwb.xyz", 10),
            _req("GET", "/", 200, None, 20),
        ]
        chains = build_chains(type("P", (), {"http_requests": reqs})())
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual([c["uri"] for c in chain],
                         ["/topograf.php", "/wp-admin/", "/"])

    def test_isolated_redirect_no_target(self):
        # 302, но следующий запрос не совпадает с Location — цепочки нет
        reqs = [
            _req("GET", "/wp-admin/", 302, "http://xn--80anccitz3fwb.xyz", 0),
            _req("GET", "/somewhere-else", 200, None, 10),
        ]
        chains = build_chains(type("P", (), {"http_requests": reqs})())
        self.assertEqual(chains, [])

    def test_no_redirects(self):
        reqs = [_req("GET", "/", 200, None, 0)]
        chains = build_chains(type("P", (), {"http_requests": reqs})())
        self.assertEqual(chains, [])


if __name__ == "__main__":
    unittest.main()
