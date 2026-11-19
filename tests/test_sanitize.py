"""Unit-тесты санитайзера strace-логов (straceparse/sanitize.py)."""

import gzip
import os
import tempfile
import unittest

from straceparse.sanitize import Sanitizer


def clean(line, sanitizer=None):
    return (sanitizer or Sanitizer()).sanitize_line(line)


class IpTest(unittest.TestCase):
    def test_ipv4(self):
        out = clean('connect(4, {sin_addr=inet_addr("203.0.113.10")}, 16) = 0')
        self.assertIn("<IPV4_1>", out)
        self.assertNotIn("203.0.113.10", out)

    def test_ipv6_full(self):
        out = clean('connect(6, {sin6_addr="2001:db8:0:0:0:0:0:1"}, 28) = 0')
        self.assertIn("<IPV6_1>", out)
        self.assertNotIn("2001:db8", out)
        self.assertNotIn("<IPV6_1>:", out)

    def test_ipv6_compressed_not_partially_masked(self):
        out = clean('connect(6, {sin6_addr="2001:db8::1"}, 28) = 0')
        self.assertIn("<IPV6_1>", out)
        self.assertNotIn("::1", out)

    def test_ipv4_mapped(self):
        out = clean('connect(6, {sin6_addr="::ffff:203.0.113.10"}, 28) = 0')
        self.assertIn("<IPV6_1>", out)
        self.assertNotIn("203.0.113.10", out)
        self.assertNotIn(".0.113.10", out)

    def test_time_is_not_ipv6(self):
        out = clean("1 13:40:00.100000 read(5, 1) = 1")
        self.assertIn("13:40:00", out)
        self.assertNotIn("IPV6", out)


class DomainTest(unittest.TestCase):
    def test_deep_domain(self):
        out = clean("write(4, \"host=shop.client.example.com\", 28) = 28")
        self.assertNotIn("shop.client.example.com", out)
        self.assertIn("<DOMAIN_1>", out)

    def test_internal_domain(self):
        out = clean("write(4, \"host=db.corp.local\", 20) = 20")
        self.assertNotIn("db.corp.local", out)

    def test_allowlisted_domain_kept(self):
        out = clean("write(4, \"host=example.com\", 20) = 20")
        self.assertIn("example.com", out)

    def test_url_path_idempotent(self):
        line = 'write(4, "Referer: https://acme.local/clients/acme/page", 100) = 100'
        first = clean(line)
        second = clean(first)
        self.assertEqual(first, second)

    def test_referer_url_path(self):
        out = clean('write(4, "Referer: https://acme.local/clients/acme/page", 100) = 100')
        self.assertNotIn("/clients/acme/page", out)
        self.assertIn("<PATH_1>", out)

    def test_fcgi_path(self):
        out = clean('read(4, "SCRIPT_NAME/gonotitsgo/send.php", 100) = 100')
        self.assertNotIn("gonotitsgo", out)
        self.assertIn("<PATH_1>", out)

    def test_hosts_content(self):
        out = clean('read(5</etc/hosts>, "\\n31.31.196.214 server172.hosting.reg.ru\\n", 64) = 64')
        self.assertNotIn("31.31.196.214", out)
        self.assertNotIn("server172", out)
        self.assertIn("<HOSTS_1>", out)

    def test_system_account_files_masked(self):
        out = clean('read(5</etc/passwd>, "root:x:0:0:root:/root:/bin/bash\\n", 40) = 40')
        self.assertNotIn("root:x:0:0", out)
        self.assertIn("<CRED_1>", out)

    def test_root_path_masked(self):
        out = clean('openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 5')
        self.assertNotIn("/root/.ssh", out)
        self.assertIn("<PATH_1>", out)

    def test_proc_environ_masked(self):
        out = clean('read(5</proc/123/environ>, "DB_PASSWORD=secret\\0", 25) = 25')
        self.assertNotIn("secret", out)

    def test_php_file_is_not_domain(self):
        out = clean('openat(AT_FDCWD, "/usr/share/php/version.php", O_RDONLY) = 5')
        self.assertIn("version.php", out)

    def test_tls_sni(self):
        out = clean('write(5, "\\26\\3\\1\\0server172.hosting.reg.ru\\0", 40) = 40')
        self.assertNotIn("server172.hosting.reg.ru", out)
        self.assertIn("<DOMAIN_1>", out)
        self.assertIn("\\0<DOMAIN_1>", out)


class IdentityTest(unittest.TestCase):
    def test_encoded_email_and_form_fields(self):
        out = clean('read(4, "name=mnnoee&email=me%40mnnoee.ru&message=privet", 100) = 100')
        self.assertNotIn("me%40mnnoee.ru", out)
        self.assertNotIn("mnnoee", out)
        self.assertNotIn("privet", out)

    def test_plain_email(self):
        out = clean('write(4, "To: user@example.com\\r\\n", 30) = 30')
        self.assertNotIn("user@example.com", out)

    def test_credentials(self):
        cases = [
            "DB_PASSWORD=supersecret",
            "$db_pass = 'hunter2';",
            "define('DB_PASSWORD', 'hunter3');",
            "Authorization: Bearer abc.def.ghi",
            "Cookie: sid=secretcookie",
            "?token=deadbeef&x=1",
            "https://user:pass@site.example.com/",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.signaturepart",
            '{"password": "jsonsecret", "token": "jsontoken"}',
            "AUTH PLAIN dXNlcjpwYXNz",
        ]
        for case in cases:
            out = clean('write(4, "' + case + '", 100) = 100')
            for secret in ("supersecret", "hunter2", "hunter3", "abc.def.ghi",
                           "secretcookie", "deadbeef", "user:pass", "eyJhbGci",
                           "jsonsecret", "jsontoken", "dXNlcjpwYXNz"):
                self.assertNotIn(secret, out, msg=case)


class SqlTest(unittest.TestCase):
    def test_insert_table_and_values(self):
        out = clean('sendto(7, "INSERT INTO acme_orders (id, name) VALUES (42, \'John\')", 60, 0, NULL, NULL) = 60')
        self.assertNotIn("acme_orders", out)
        self.assertNotIn("John", out)
        self.assertIn("<SQL_TABLE_1>", out)
        self.assertIn("<SQL_VALUES_1>", out)
        self.assertIn("= 60", out)

    def test_select_value_number_limit(self):
        out = clean('sendto(7, "SELECT * FROM wp_options WHERE option_name = \'siteurl\' AND id = 5 LIMIT 10", 80, 0, NULL, NULL) = 80')
        self.assertIn("wp_options", out)
        self.assertNotIn("siteurl", out)
        self.assertNotIn("id = 5", out)
        self.assertNotIn("LIMIT 10", out)

    def test_other_table_is_masked(self):
        out = clean('sendto(7, "SELECT * FROM acme_orders", 40, 0, NULL, NULL) = 40')
        self.assertNotIn("acme_orders", out)
        self.assertIn("<SQL_TABLE_1>", out)


class PathTest(unittest.TestCase):
    def test_sensitive_paths(self):
        for path in ("/var/www/u1/site/index.php", "/home/client/project/app.py",
                     "/mnt/backup/client.tar.gz", "/srv/app/config.php"):
            out = clean(f'openat(AT_FDCWD, "{path}", O_RDONLY) = 5')
            self.assertNotIn(path, out, msg=path)
            self.assertIn("<PATH_1>", out)

    def test_system_path_kept(self):
        out = clean('openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 5')
        self.assertIn("/etc/passwd", out)


class PemTest(unittest.TestCase):
    def test_private_key_block(self):
        s = Sanitizer()
        lines = [
            '1 13:41:00.000000 read(5, "-----BEGIN RSA PRIVATE KEY-----", 32) = 32',
            '1 13:41:00.100000 read(5, "MIIEowIBAAKCAQEAsecretbase64", 28) = 28',
            '1 13:41:00.200000 read(5, "-----END RSA PRIVATE KEY-----", 30) = 30',
        ]
        out = [s.sanitize_line(line) for line in lines]
        joined = "\n".join(out)
        self.assertNotIn("secretbase64", joined)
        self.assertNotIn("BEGIN RSA", joined)
        self.assertIn("= 28", joined)


class DnsWireTest(unittest.TestCase):
    def test_dns_wire_name(self):
        out = clean('sendto(4<UDP:[10.0.0.1:53]>, "\\4test\\6domain\\3com\\0", 16, 0, NULL, NULL) = 16')
        self.assertNotIn("test", out)
        self.assertIn(r"\4mail\6domain\3tld", out)


class StreamingTest(unittest.TestCase):
    def test_lines_generator_and_idempotence(self):
        s = Sanitizer()
        line = 'read(4, "name=mnnoee&email=me%40mnnoee.ru IP=203.0.113.10", 100) = 100'
        first = list(s.sanitize_lines([line]))[0]
        self.assertNotIn("mnnoee", first)
        self.assertNotIn("203.0.113.10", first)
        second = list(Sanitizer().sanitize_lines([first]))[0]
        self.assertEqual(first, second)

    def test_gzip_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "trace.log.gz")
            with gzip.open(path, "wt", encoding="utf-8") as f:
                f.write('read(4, "ip=203.0.113.10", 20) = 20\n')
            out = Sanitizer().sanitize_file(path)
        self.assertEqual(len(out), 1)
        self.assertIn("<IPV4_1>", out[0])


class ReportTest(unittest.TestCase):
    def test_report_contains_counts(self):
        s = Sanitizer()
        s.sanitize_line('read(4, "ip=203.0.113.10 email=a@example.com", 40) = 40')
        report = s.report()
        self.assertIn("<IPV4_1>", report)
        self.assertIn("203.0.113.10", report)


if __name__ == "__main__":
    unittest.main()
