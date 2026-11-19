# Contributing

## Proposing ideas and features

Open an Issue in the repository with a short description of the problem and
the behaviour you would like to see.

## Proposing code

Send a Pull Request with a description of the changes. Before merging, make
sure that:

```bash
# tests
python -m pytest

# linter
ruff check .
```

- The code passes the tests and the linter
- User-facing strings (output, prompts, help) are added to both catalogs in
  `straceparse/locales/` (`ru` and `en`) and used in code only via `t()`
- The PR description provides context such as what it was, what it became and
  why
- A new feature means a new module in `straceparse/` plus a hook at the right
  point in `core` or a section in `report`, not growth of existing files

## Project structure

```
strace_parser.py          thin CLI wrapper
sanitize_log.py           thin sanitizer wrapper
straceparse/
  __init__.py             exports: VERSION, StraceParser, build_report, main
  constants.py            regular expressions, RCODE_NAMES, VERSION
  i18n.py                 localization engine: locale detection, t(), plurals
  locales/
    ru.py                 Russian string catalog
    en.py                 English string catalog
  parse_utils.py          pure helpers: unescape, sockaddr, FCGI, DNS,
                          normalize_sql, server_timing, set_cookie
  core.py                 Syscall + StraceParser: line parsing, fd/socket/file
                          tracking, feature hooks wp/mem/mtls/smtp/phpmail
  wp.py                   WordPress: components, core, themes, heavy plugins
  mem.py                  RAM/OOM analysis
  mtls.py                 SSL/mTLS analysis
  phpmail.py              PHP mail() analysis
  smtp.py                 SMTP sessions and delivery result
  redirects.py            redirects (3xx chains)
  signatures.py           incident signatures
  sql_timing.py           SQL timing, percentiles, N+1
  servertiming.py         WordPress phases from Server-Timing
  load.py                 load attribution
  json_export.py          machine-readable report.json (--json)
  report.py               build_report() by sections
  csv_export.py           write_csvs()
  sanitize.py             masking of confidential data
  cli.py                  process_file(), main()
tests/                    unit tests on synthetic data
```

The dependency direction is one-way,
`core -> (wp, mem, mtls, smtp, phpmail) -> parse_utils/constants`, with no
cycles.

## Important: strace log privacy

strace logs contain everything, including hosts, paths, SQL with real data and
business processes. If a PR or Issue includes log samples or report output, you
**must** do the following before publishing:

- replace all real hosts, IPs and domains with `example.com`, `example.org` or
  `test.local`
- replace paths containing company or client names with generic paths
  (`/path/to/logs/`)
- remove SQL query contents with real table or data names, except the standard
  `wp_*` tables used for demonstration
- ideally, run the log through the sanitizer before attaching it to an Issue or
  PR

### Automatic sanitization

```bash
# clean the log and print a substitution report
jealous-sanitize your_strace.log -o clean.log --report

# or without installation
python3 sanitize_log.py your_strace.log -o clean.log --report
```

### What the sanitizer masks

| Data type | Before | After |
|-----------|--------|-------|
| IPv4 | `192.168.1.100` | `<IPV4_1>` |
| IPv6 | `2001:db8::1` | `<IPV6_1>` |
| Domains | `shop.client.ru` | `<DOMAIN_1>` |
| Internal hosts | `db.corp.local` | `<DOMAIN_1>` |
| Email | `dev@acmecorp.ru` | `<EMAIL_1>` |
| URL-encoded email | `dev%40acmecorp.ru` | `<EMAIL_1>` |
| Credentials and tokens | `DB_PASSWORD=secret`, `Authorization: Bearer ...` | `<CRED_1>` |
| Private keys | `-----BEGIN PRIVATE KEY-----` block | `<CRED_1>` |
| Paths | `/home/clientproject/www/` | `<PATH_1>` |
| SQL values | `WHERE name = 'John'` | `WHERE name <SQL_VAL_1>` |
| SQL table names | `FROM acme_orders` | `FROM <SQL_TABLE_1>` |
| SQL IN (...) | `IN (100, 200)` | `<SQL_IN_1>` |
| System files | `/etc/passwd`, `/proc/*/environ` content | `<CRED_1>` / `<HOSTS_1>` |

Standard WordPress tables (`wp_options`, `wp_posts` and others) are **not**
masked.

## Versioning and releases

- SemVer, `MAJOR.MINOR.PATCH`. The source of truth is `VERSION` in
  `straceparse/constants.py`; `pyproject.toml` reads it automatically, so the
  version never needs to be duplicated by hand.
- Every change gets an entry in `CHANGELOG.md` (Keep a Changelog).
- Release: update `VERSION` -> add a CHANGELOG entry -> tag `vX.Y.Z`.
