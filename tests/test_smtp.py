"""Unit-тесты SMTP-анализа (straceparse/smtp.py)."""

import csv
import os
import tempfile
import unittest

from straceparse.core import StraceParser
from straceparse.csv_export import write_csvs
from straceparse.smtp import build_json, detect, report_section


def _parse(text, mail_body=True):
    p = StraceParser(mail_body=mail_body)
    for line in text.strip().splitlines():
        p.parse_line(line, "trace.log")
    return p


PLAIN = """
1 13:00:00.000000 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
1 13:00:00.001000 connect(3, {sa_family=AF_INET, sin_port=htons(25), sin_addr=inet_addr("203.0.113.25")}, 16) = 0
1 13:00:00.002000 write(3, "EHLO acme.local\\r\\n", 17) = 17
1 13:00:00.003000 read(3, "250-acme.local\\r\\n", 16) = 16
1 13:00:00.004000 write(3, "MAIL FROM:<sender@example.com>\\r\\n", 32) = 32
1 13:00:00.005000 write(3, "RCPT TO:<rcpt@example.com>\\r\\n", 29) = 29
1 13:00:00.006000 write(3, "DATA\\r\\n", 6) = 6
1 13:00:00.007000 read(3, "354 go ahead\\r\\n", 15) = 15
1 13:00:00.008000 write(3, "Subject: x\\r\\n\\r\\nhi\\r\\n.\\r\\n", 24) = 24
1 13:00:00.009000 read(3, "250 ok\\r\\n", 8) = 8
1 13:00:00.010000 close(3) = 0
"""

TLS465 = """
1 13:00:00.000000 openat(AT_FDCWD, "/var/www/gonotitsgo/PHPMailer/SMTP.php", O_RDONLY) = 3
1 13:00:00.001000 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
1 13:00:00.002000 connect(4, {sa_family=AF_INET, sin_port=htons(465), sin_addr=inet_addr("203.0.113.25")}, 16) = -1 EINPROGRESS (Operation now in progress)
1 13:00:00.003000 getsockopt(4, 0x1 /* SOL_SOCKET */, 0x4 /* SO_ERROR */, [0], [4]) = 0
1 13:00:00.004000 write(4, "\\26\\3\\1\\0server172.hosting.reg.ru\\0", 40) = 40
1 13:00:00.005000 close(4) = 0
"""

AUTH_FAIL = """
1 13:00:00.000000 connect(3, {sa_family=AF_INET, sin_port=htons(587), sin_addr=inet_addr("203.0.113.25")}, 16) = 0
1 13:00:00.001000 write(3, "AUTH LOGIN\\r\\n", 12) = 12
1 13:00:00.002000 read(3, "535 5.7.8 authentication failed\\r\\n", 33) = 33
1 13:00:00.003000 close(3) = 0
"""


class PlainSmtpTest(unittest.TestCase):
    def test_session_parsed(self):
        p = _parse(PLAIN)
        self.assertEqual(len(p.smtp_sessions), 1)
        s = p.smtp_sessions[0]
        self.assertEqual(s["port"], 25)
        self.assertEqual(s["mail_from"], "sender@example.com")
        self.assertEqual(s["rcpt"], ["rcpt@example.com"])
        self.assertTrue(s["saw_data"])
        self.assertTrue(s["auth"] is False)
        self.assertEqual(build_json(p)["sessions"][0]["result"], "sent")

    def test_report_contains_target(self):
        p = _parse(PLAIN)
        lines = []
        report_section(p, lines.append)
        text = "\n".join(lines)
        self.assertIn("203.0.113.25:25", text)
        self.assertIn("MAIL FROM: sender@example.com", text)


class SmtpsTest(unittest.TestCase):
    def test_tls_sni_and_result(self):
        p = _parse(TLS465)
        s = p.smtp_sessions[0]
        self.assertEqual(s["port"], 465)
        self.assertTrue(s["tls"])
        self.assertTrue(s["library"])
        self.assertEqual(s["sni"], "server172.hosting.reg.ru")
        self.assertEqual(s["status"], "ok")
        self.assertEqual(build_json(p)["sessions"][0]["result"], "sent_tls")

    def test_einprogress_resolved(self):
        p = _parse(TLS465)
        conn = [c for c in p.connects if (c.get("endpoint") or {}).get("port") == 465][0]
        self.assertTrue(conn["resolved"])
        self.assertTrue(conn["final_ok"])


class GatingTest(unittest.TestCase):
    def test_disabled_without_mail_body(self):
        p = _parse(TLS465, mail_body=False)
        self.assertEqual(p.smtp_sessions, [])
        lines = []
        report_section(p, lines.append)
        self.assertEqual(lines, [])

    def test_report_only_with_mail_body(self):
        p = _parse(TLS465)
        self.assertTrue(p.mail_body)
        lines = []
        report_section(p, lines.append)
        self.assertTrue(lines)


class CsvTest(unittest.TestCase):
    def test_smtp_csv_written(self):
        p = _parse(TLS465)
        with tempfile.TemporaryDirectory() as tmp:
            write_csvs(p, tmp)
            with open(os.path.join(tmp, "smtp.csv"), encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["port"], "465")
        self.assertEqual(rows[0]["sni"], "server172.hosting.reg.ru")
        self.assertEqual(rows[0]["result"], "sent_tls")
        self.assertEqual(rows[0]["error"], "")

    def test_no_csv_without_sessions(self):
        p = _parse(PLAIN, mail_body=False)
        with tempfile.TemporaryDirectory() as tmp:
            write_csvs(p, tmp)
            self.assertFalse(os.path.exists(os.path.join(tmp, "smtp.csv")))


class SignatureTest(unittest.TestCase):
    def test_auth_failure(self):
        p = _parse(AUTH_FAIL)
        issues = detect(p)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0][0], "ERROR")
        self.assertIn("535", issues[0][1])


if __name__ == "__main__":
    unittest.main()
