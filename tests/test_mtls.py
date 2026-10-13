"""Unit-тесты: краш mtls-ветки на openat без пути + запись сертфикатов."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from straceparse.core import StraceParser

LINE = '1562738 1791875470.444136 [00007fb727240814] {rest}\n'


class MtlsTest(unittest.TestCase):
    def test_openat_without_quoted_path_does_not_crash(self):
        # openat, где путь не строка в кавычках (NULL / декод):
        # раньше падало UnboundLocalError: path в mtls-ветке
        p = StraceParser(mtls=True)
        p.parse_line(LINE.format(rest="openat(AT_FDCWD, NULL, O_RDONLY) = -1 EFAULT"), "x.log")
        p.parse_line(LINE.format(rest="openat(4</var/www/x>, O_RDONLY) = 5"), "x.log")
        p.finalize()
        self.assertEqual(len(p.syscall_events), 2)
        self.assertEqual(dict(p.mtls_cert_files), {})

    def test_cert_open_recorded(self):
        # страховка: перенос mtls-проверки внутрь if path_m не сломал запись
        p = StraceParser(mtls=True)
        p.parse_line(LINE.format(
            rest='openat(AT_FDCWD, "/etc/ssl/client.pem", O_RDONLY) = 5'), "x.log")
        p.finalize()
        self.assertIn("/etc/ssl/client.pem", p.mtls_cert_files)

    def test_cert_in_json_report(self):
        # сертификаты попадают в --json (раньше mtls был только в текстовом отчёте)
        from straceparse.json_export import build_json
        p = StraceParser(mtls=True)
        p.parse_line(LINE.format(
            rest='openat(AT_FDCWD, "/etc/ssl/client.pem", O_RDONLY) = 5'), "x.log")
        p.finalize()
        data = build_json(p)
        self.assertEqual(data["mtls"]["cert_files"][0]["path"], "/etc/ssl/client.pem")
        self.assertEqual(data["mtls"]["cert_files"][0]["pids"], [1562738])
        # без --mtls секция пустая, но ключ есть
        self.assertEqual(build_json(StraceParser())["mtls"], {})


if __name__ == "__main__":
    unittest.main()
