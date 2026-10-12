"""Unit-тесты: сигнатуры инцидентов."""

import datetime
import os
import sys
import unittest
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from straceparse.signatures import (
    detect,
    detect_enoent_storm,
    detect_redirect_loop,
    detect_repeated_chains,
    detect_scheme_switch,
    detect_secure_cookie_over_http,
)

T0 = datetime.datetime.fromtimestamp(1788938386)


class _P:
    def __init__(self, requests=None):
        self.http_requests = requests or []
        self.open_missing = Counter()


def _r(method, uri, status, location=None, scheme=None, start_sec=0, cookies=None):
    return {
        "method": method, "uri": uri, "host": "example.com",
        "status": status, "location": location, "scheme": scheme,
        "start": T0 + datetime.timedelta(seconds=start_sec),
        "end": T0 + datetime.timedelta(seconds=start_sec + 1),
        "set_cookie": cookies,
    }


def _chain(method_uri_status_loc_scheme):
    """Удобное построение цепочки из кортежей (method, uri, status, location, scheme)."""
    out = []
    for i, (m, u, s, loc, sch) in enumerate(method_uri_status_loc_scheme):
        out.append(_r(m, u, s, loc, sch, start_sec=i * 5))
    return out


class RedirectLoopTest(unittest.TestCase):
    def test_uri_repeats_in_chain(self):
        reqs = _chain([
            ("GET", "/a", 302, "/b", None),
            ("GET", "/b", 302, "/a", None),
            ("GET", "/a", 200, None, None),
        ])
        issues = detect_redirect_loop(_P(reqs))
        self.assertTrue(issues)
        self.assertEqual(issues[0][0], "CRITICAL")
        self.assertIn("ПЕТЛЯ", issues[0][1])

    def test_no_loop(self):
        reqs = _chain([
            ("GET", "/a", 302, "/b", None),
            ("GET", "/b", 200, None, None),
        ])
        self.assertEqual(detect_redirect_loop(_P(reqs)), [])


class SchemeSwitchTest(unittest.TestCase):
    def test_https_location_http_next(self):
        reqs = _chain([
            ("POST", "/topograf.php", 302, "https://xn--80anccitz3fwb.xyz/wp-admin/", "https"),
            ("GET", "/wp-admin/", 302, "http://xn--80anccitz3fwb.xyz", None),
            ("GET", "/", 200, None, None),
        ])
        issues = detect_scheme_switch(_P(reqs))
        self.assertTrue(issues)
        self.assertIn("СМЕШАННЫЕ HTTP/HTTPS", issues[0][1])

    def test_consistent_https(self):
        reqs = _chain([
            ("POST", "/wp-login.php", 302, "/wp-admin/", "https"),
            ("GET", "/wp-admin/", 200, None, "https"),
        ])
        self.assertEqual(detect_scheme_switch(_P(reqs)), [])


class RepeatedChainsTest(unittest.TestCase):
    def test_duplicate_chain(self):
        pair = [
            ("GET", "/wp-admin/", 302, "http://x", None),
            ("GET", "/", 200, None, None),
        ]
        reqs = _chain(pair + pair)
        issues = detect_repeated_chains(_P(reqs))
        self.assertTrue(issues)
        self.assertIn("повторяется 2 раз", issues[0][1])


class SecureCookieTest(unittest.TestCase):
    def test_secure_cookie_over_http(self):
        p = _P(requests=[_r("POST", "/topograf.php", 302, "https://x/wp-admin/", None, 0,
                            cookies=[{"name": "wordpress_sec_x", "secure": True, "flags": ["secure"]}])])
        issues = detect_secure_cookie_over_http(p)
        self.assertTrue(issues)
        self.assertIn("Secure-cookie", issues[0][1])

    def test_secure_cookie_over_https_ok(self):
        p = _P(requests=[_r("POST", "/wp-login.php", 200, None, "https", 0,
                            cookies=[{"name": "sec", "secure": True}])])
        self.assertEqual(detect_secure_cookie_over_http(p), [])


class EnoentStormTest(unittest.TestCase):
    def test_storm(self):
        p = _P()
        p.open_missing = Counter({"/x/1": 130, "/x/2": 90, "/x/3": 60})
        issues = detect_enoent_storm(p, threshold=200)
        self.assertTrue(issues)
        self.assertEqual(issues[0][0], "WARNING")
        self.assertIn("280", issues[0][1])

    def test_quiet(self):
        p = _P()
        p.open_missing = Counter({"/x": 5})
        self.assertEqual(detect_enoent_storm(p, threshold=200), [])


class DetectAggregateTest(unittest.TestCase):
    def test_returns_list(self):
        p = _P()
        issues = detect(p)
        self.assertIsInstance(issues, list)
        for sev, _msg in issues:
            self.assertIn(sev, ("CRITICAL", "ERROR", "WARNING", "INFO"))


if __name__ == "__main__":
    unittest.main()
