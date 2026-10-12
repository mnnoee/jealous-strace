"""Unit-тесты: атрибуция нагрузки (стop: кто жрёт ресурсы)."""

import datetime
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from straceparse.core import StraceParser
from straceparse.load import peak_seconds, per_pid, per_request

T0 = datetime.datetime.fromtimestamp(1788938386)


def _ev(pid, ts, name, dur=None, path=None):
    return {"pid": pid, "ts": ts, "name": name, "dur": dur, "path": path}


def _dt(sec):
    return T0 + datetime.timedelta(seconds=sec)


def _P(events, requests=()):
    p = StraceParser(wordpress=True)
    p.all_http_requests_seen_external = True
    p.syscall_events = events
    p.http_requests = list(requests)
    p.files = {}
    p.file_bytes = {}
    return p


class PerPidTest(unittest.TestCase):
    def test_cpu_bound_beat_blocked(self):
        # pid 1: много коротких вызовов подряд (CPU-работа)
        evs = [_ev(1, _dt(i), "read", 0.001) for i in range(10)]
        # pid 2: висит в accept() (простой, не CPU)
        evs += [_ev(2, _dt(0), "accept", 60.0), _ev(2, _dt(61), "accept", 1.0)]
        res = per_pid(_P(evs))
        by = {r["pid"]: r for r in res}
        self.assertGreater(by[1]["cpu"], by[2]["cpu"])
        self.assertLess(by[2]["cpu"], 1.0)  # accept-ожидание вычтено

    def test_blocking_subtracted_from_cpu(self):
        evs = [_ev(1, _dt(0), "accept", 30.0), _ev(1, _dt(31), "read", 0.001)]
        r = per_pid(_P(evs))[0]
        self.assertEqual(r["count"], 2)
        self.assertEqual(round(r["kernel"], 3), 30.001)
        self.assertEqual(round(r["blocking"], 3), 30.001)
        self.assertAlmostEqual(r["cpu"], 0.999, places=2)

    def test_sorted_by_cpu_desc(self):
        evs = [
            _ev(2, _dt(0), "read", 0.01),
            _ev(1, _dt(0), "accept", 5.0),
        ]
        res = per_pid(_P(evs))
        self.assertEqual([r["pid"] for r in res], [2, 1])


class PerRequestTest(unittest.TestCase):
    REQ = {"pid": 1, "fd": 4, "start": _dt(1), "end": _dt(3),
           "method": "GET", "uri": "/", "status": 200, "host": "x.xyz"}

    def test_attributes_window_events(self):
        evs = [
            _ev(1, _dt(0), "accept", 1.0),        # до окна/приём — исключается
            _ev(1, _dt(1.5), "read", 0.1),
            _ev(1, _dt(2.0), "sendto", 0.05),     # SQL-запрос
            _ev(1, _dt(2.5), "writev", 0.2),
            _ev(2, _dt(2.5), "read", 9.0),        # другой pid
            _ev(1, _dt(4.0), "read", 0.1),        # после окна
        ]
        rows = per_request(_P(evs, [self.REQ]))
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["count"], 3)          # accept и чужие/после-окна не считаются
        self.assertAlmostEqual(r["kernel"], 0.35, places=2)
        self.assertAlmostEqual(r["cpu"], 1.9, places=1)  # dur(2c) - blocking(0.1)


class ComponentInRequestTest(unittest.TestCase):
    def test_components_counted(self):
        evs = [
            _ev(1, _dt(1.2), "read", 0.01, "/var/www/wp-content/plugins/akismet/akismet.class.php"),
            _ev(1, _dt(1.4), "read", 0.01, "/var/www/wp-content/plugins/yoast-seo/main.php"),
            _ev(1, _dt(1.6), "read", 0.01, "/var/www/wp-content/themes/acme-theme/style.css"),
        ]
        req = dict(PerRequestTest.REQ)
        rows = per_request(_P(evs, [req]))
        comps = rows[0]["components"]
        self.assertEqual(comps.get("akismet"), 1)
        self.assertEqual(comps.get("yoast-seo"), 1)
        self.assertTrue(any(k.startswith("theme:") for k in comps))


class PeakSecondsTest(unittest.TestCase):
    def test_top_second(self):
        evs = []
        for i in range(100):
            evs.append(_ev(1, _dt(0) + datetime.timedelta(microseconds=i * 1000), "read", 0.001))
        for i in range(10):
            evs.append(_ev(2, _dt(1) + datetime.timedelta(microseconds=i * 1000), "read", 0.001))
        peaks = peak_seconds(_P(evs), top=3)
        self.assertEqual(len(peaks), 2)
        self.assertEqual(peaks[0]["count"], 100)
        self.assertEqual(peaks[0]["pid"], 1)
        self.assertEqual(peaks[1]["count"], 10)


if __name__ == "__main__":
    unittest.main()
