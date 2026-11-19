# jealous-strace

[![CI](https://github.com/mnnoee/jealous-strace/actions/workflows/ci.yml/badge.svg)](https://github.com/mnnoee/jealous-strace/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.5.0-green.svg)](CHANGELOG.md)

> Part of the [Jealous Moon](https://github.com/mnnoee) toolkit - offline
> server and domain diagnostics.

Universal strace log parser with a human-readable report and CSV export.

> [README на русском](README.ru.md) - полная документация.

## Features

- Auto-detection of line formats (PID+time, PID+epoch, no PID, access log)
- Syscall statistics (count, errors, time), file access, network, DNS, SQL
- Slow calls, unfinished calls (potential hangs), connection errors
- Redirect chains and incident signatures (loops, mixed HTTP/HTTPS,
  Secure-cookie over HTTP, ENOENT storm)
- SQL timing (p50/p95/p99) and N+1 detection
- WordPress phases from Server-Timing, autoload bloat, heavy plugins
- Load attribution: who consumes resources (PID / URI / plugins)
- PHP `mail()` and SMTP analysis (recipient, subject, status, TLS/SNI, body with `--mail-body`)
- JSON export (`--json [PATH]`)
- Russian and English interface (`--lang`)
- Fully offline: works on log files only

## Install

Not on PyPI yet (planned). Install straight from GitHub:

```bash
pip install git+https://github.com/mnnoee/jealous-strace.git
```

Both `jealous-strace` and `jealous-sanitize` are available after install.
You can also run it straight from a clone:

```bash
python3 strace_parser.py /path/to/strace.log
```

## Usage

Capture a log (attach to running PHP processes):

```bash
strace -p $(pgrep -u $USER -d',' -f 'php') -f -s 65535 -v -yy -ttt -T -i -X verbose -o ~/strace.log
```

Analyze it:

```bash
jealous-strace ~/strace.log                   # report + CSV
jealous-strace ~/strace.log --wordpress       # WordPress analysis
jealous-strace ~/strace.log --json out.json   # machine-readable report
jealous-strace ~/strace.log --mail-body       # include message bodies
jealous-strace --help                         # all options
```

## PHP mail() analysis

The parser detects mail sent through PHP `mail()` and reports the recipient,
`From`, envelope, subject, sendmail exit status, duration and size. Pass
`--mail-body` to include the message body and full details (private data),
and to enable SMTP analysis (ports 25/465/587, PHPMailer and others).
SMTP sessions show the server, SNI, TLS and result. For plaintext SMTP the
`MAIL FROM` / `RCPT TO` / `DATA` commands and response codes are parsed; on
465 and after STARTTLS they are encrypted and not visible.

## Interface language

The output language follows the locale or can be forced with `--lang {auto,ru,en}`.

## Example log

```log
2992844 13:40:00.101234 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = 0 <0.000123>
2992844 1757932800.104567 [7f2a1b0c] openat(AT_FDCWD, "/var/www/wp-includes/version.php", O_RDONLY|O_CLOEXEC) = 7
2992844 13:40:00.110001 sendto(7, "SELECT option_value FROM wp_options", 35, 0, NULL, NULL) = 35 <0.000045>
2992845 13:40:00.115678 recvfrom(4, "HTTP/1.1 302 Found\r\nLocation: https://acme.local/wp-admin/", 8192, 0, NULL, NULL) = 58
```

## Ideas & suggestions

Have an idea for the project? Open an issue - suggestions for new report
sections, signature detections, export formats and integrations are welcome.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
