# jealous-strace

[![CI](https://github.com/mnnoee/jealous-strace/actions/workflows/ci.yml/badge.svg)](https://github.com/mnnoee/jealous-strace/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.3.0-green.svg)](CHANGELOG.md)

> Part of the [Jealous Moon](https://github.com/mnnoee) toolkit — offline
> server and domain diagnostics.

Universal strace log parser with a human-readable report and CSV export.

> [README на русском](README.ru.md) — полная документация.

## Features

- Auto-detection of line formats (PID+time, PID+epoch, no PID, access log)
- Syscall statistics (count, errors, time), file access, network, DNS, SQL
- Slow calls, unfinished calls (potential hangs), connection errors
- Redirect chains and incident signatures (loops, mixed HTTP/HTTPS,
  Secure-cookie over HTTP, ENOENT storm)
- SQL timing (p50/p95/p99) and N+1 detection
- WordPress phases from Server-Timing, autoload bloat, heavy plugins
- Load attribution: who consumes resources (PID / URI / plugins)
- JSON export (`--json [PATH]`)
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
jealous-strace --help                         # all options
```

## Example log

```log
2992844 13:40:00.101234 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = 0 <0.000123>
2992844 1757932800.104567 [7f2a1b0c] openat(AT_FDCWD, "/var/www/wp-includes/version.php", O_RDONLY|O_CLOEXEC) = 7
2992844 13:40:00.110001 sendto(7, "SELECT option_value FROM wp_options", 35, 0, NULL, NULL) = 35 <0.000045>
2992845 13:40:00.115678 recvfrom(4, "HTTP/1.1 302 Found\r\nLocation: https://acme.local/wp-admin/", 8192, 0, NULL, NULL) = 58
```

## Ideas & suggestions

Have an idea for the project? Open an issue — suggestions for new report
sections, signature detections, export formats and integrations are welcome.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
