"""Константы и скомпилированные регулярные выражения пакета straceparse."""

import re

VERSION = "1.4.1"

OCTAL_RE = re.compile(r"\\[0-7]{1,3}")
HEX_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
SIMPLE_ESC = {
    "\\": "\\", '"': '"', "t": "\t", "n": "\n", "r": "\r",
    "v": "\v", "a": "\a", "b": "\b", "f": "\f", "e": "\x1b", "0": "\0",
}

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}

LINE_RE = re.compile(r"^(?:(\d+)\s+)?(\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)?(.+)$")
EPOCH_IP_RE = re.compile(r"^(\d{10,11}\.\d+)\s+\[([0-9a-fA-F]+)\]\s+(.*)$")
PID_EPOCH_IP_RE = re.compile(r"^(\d+)\s+(\d{10,11}\.\d+)\s+\[([0-9a-fA-F]+)\]\s+(.*)$")
SYS_NAME_RE = re.compile(r"^(\w+)\(")
RESUMED_RE = re.compile(r"^<\.\.\.\s+(\w+)\s+resumed>(.*)$")
UNFINISHED_RE = re.compile(r"<unfinished \.\.\.>\s*$")
SPECIAL_RE = re.compile(r"^\[?Process PID=\d+|^\+{3}|^-{3}|^strace:|^restart_syscall")
