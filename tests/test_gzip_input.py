"""Unit-тесты: чтение gz-входа (стрейсы с хостингов приходят .log.gz)."""

import gzip
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from straceparse.cli import process_file
from straceparse.core import StraceParser

SAMPLE = (
    '1562738 1791875467.129118 [00007fb72724d828] accept(0<UNIX:[3713423792,"/var/run/mod_fcgid/x"]>,'
    ' {sa_family=0x1 /* AF_UNIX */}, [112 => 2]) = 4 <3.313848>\n'
    '1562738 1791875470.444136 [00007fb727240814] fcntl(4, 0x1 /* F_GETFD */) = 0 <0.000011>\n'
    '1562738 1791875470.444230 [00007fb727240814] read(4, "\\1\\1\\0\\1", 8) = 8 <0.000009>\n'
)


class GzipInputTest(unittest.TestCase):
    def test_gz_input_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            gz_path = os.path.join(tmp, "strace.log.gz")
            with gzip.open(gz_path, "wt", encoding="utf-8") as f:
                f.write(SAMPLE)

            p = StraceParser()
            process_file(gz_path, p)
            p.finalize()

            self.assertEqual(len(p.syscall_events), 3)
            self.assertGreater(p.format_counts.get("epoch_ip", 0), 0)

    def test_plain_input_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain_path = os.path.join(tmp, "strace.log")
            with open(plain_path, "w", encoding="utf-8") as f:
                f.write(SAMPLE)

            p = StraceParser()
            process_file(plain_path, p)
            p.finalize()

            self.assertEqual(len(p.syscall_events), 3)


if __name__ == "__main__":
    unittest.main()
