"""Unit-тесты: тайминг SQL и детект N+1."""

import datetime
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from straceparse.sql_timing import (
    find_n_plus_1,
    percentiles,
    query_duration,
    uri_for_query,
)

T0 = datetime.datetime.fromtimestamp(1788938386)

SQL_OPT = "SELECT option_value FROM wpes_options WHERE option_name = 'foo'"


class _P:
    def __init__(self, queries=None, requests=None):
        self.sql_queries = queries or []
        self.http_requests = requests or []


def _q(ts_sec, sql=SQL_OPT, pid=100, dur_sec=1):
    st = T0 + datetime.timedelta(seconds=ts_sec)
    return {
        "ts": st, "start_ts": st, "end_ts": st + datetime.timedelta(seconds=dur_sec),
        "pid": pid, "sql": sql, "fd": 5, "server": None, "recv_bytes": 0,
    }


def _r(method, uri, start_sec=0, pid=100):
    return {
        "method": method, "uri": uri, "pid": pid,
        "start": T0 + datetime.timedelta(seconds=start_sec),
    }


class QueryDurationTest(unittest.TestCase):
    def test_normal(self):
        q = _q(10, dur_sec=2.0)
        self.assertAlmostEqual(query_duration(q), 2.0, places=6)

    def test_missing_end(self):
        q = _q(0)
        q["end_ts"] = None
        self.assertIsNone(query_duration(q))

    def test_bad_order(self):
        q = _q(10)
        q["end_ts"] = q["start_ts"] - datetime.timedelta(seconds=5)
        self.assertIsNone(query_duration(q))


class PercentilesTest(unittest.TestCase):
    def test_basic(self):
        durs = [float(i) for i in range(100)]
        pct = percentiles(durs)
        self.assertEqual(pct[50], 50.0)
        self.assertEqual(pct[99], 99.0)

    def test_empty(self):
        self.assertEqual(percentiles([]), {})


class UriForQueryTest(unittest.TestCase):
    def test_matches_pid(self):
        p = _P(requests=[_r("GET", "/", 0, pid=100), _r("POST", "/topo", 5, pid=100)])
        q = _q(3, pid=100)
        self.assertEqual(uri_for_query(p, q), "GET /")

    def test_no_match(self):
        p = _P(requests=[])
        self.assertIsNone(uri_for_query(p, _q(0)))


class FindNPlus1Test(unittest.TestCase):
    def test_run_detected(self):
        # 12 одинаковых запросов подряд (N+1), затем 2 других
        queries = [_q(i, pid=100) for i in range(12)]
        queries += [
            _q(20, sql="SELECT * FROM wpes_posts WHERE ID = 1"),
            _q(21, sql="SELECT * FROM wpes_posts WHERE ID = 2"),
        ]
        p = _P(queries=queries, requests=[_r("GET", "/", 0)])
        res = find_n_plus_1(p, min_repeats=10)
        self.assertTrue(res)
        self.assertEqual(res[0]["repeats"], 12)
        self.assertIn("option_name = '...'", res[0]["normalized"])
        self.assertEqual(res[0]["uri"], "GET /")

    def test_short_run_ignored(self):
        p = _P(queries=[_q(i) for i in range(3)])
        self.assertEqual(find_n_plus_1(p, min_repeats=10), [])

    def test_single_form_high_total_is_not_n1(self):
        # те же формы, но НЕ подряд (вперемешку) — это не N+1
        queries = [
            _q(0, sql=SQL_OPT), _q(1, sql="SELECT * FROM wp_posts WHERE ID = 1"),
            _q(2, sql=SQL_OPT), _q(3, sql="SELECT * FROM wp_posts WHERE ID = 2"),
        ]
        p = _P(queries=queries)
        self.assertEqual(find_n_plus_1(p, min_repeats=2), [])


if __name__ == "__main__":
    unittest.main()
