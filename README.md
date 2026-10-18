# Logsift

**Offline summaries for web server access logs, from one stdlib-only Python file.**

Point it at an Apache or nginx access log and get the answers you actually
look for: what got hit, who hit it, what failed, when traffic spiked, and
whether this deploy's error rate is still under the line. Nothing leaves your
machine, nothing is installed, and the log files are never modified.

## Features

- Parses Common Log Format and Combined Log Format, auto-detecting whether
  referer and user-agent fields are present.
- Reads plain files, `.gz` files, or stdin (`-`), so `zcat access.log.gz | logsift summary -` works.
- Converts every timestamp to UTC, including mixed `+0200` and `-0700` offsets.
- Keeps going past bad lines by default and warns with `file:line`. `--strict` turns any bad line into a hard failure (exit 2).
- Filters by time window (`--since` / `--until`), HTTP method, status (`404`, `400-499`, `5xx`, or a list), and path prefix.
- `summary`: request count, unique IPs, time span, bytes (total, p50, p95, max), error rate, and status-class breakdown.
- `top`: most requested paths, IPs, statuses, methods, user agents or referers, ranked by request count or by bytes.
- `errors`: 4xx/5xx responses grouped by status and path, or listed one per line with `file:line` so you can jump to them.
- `timeline`: requests, errors, error rate and top path for each minute, hour or day.
- `bursts`: every minute, hour or day that reached a request threshold, with the path that dominated it.
- `check`: CI and cron gate with `--max-error-rate`, `--max-5xx`, `--max-malformed` and `--min-requests`. Exits 1 when a rule fails.
- `--format json` on every report command, for scripts and dashboards.
- Standard library only. No network calls, no accounts, no config files.

## Quick start

The repo includes a small sample log in `examples/access.log`.

```bash
python3 logsift.py summary examples/access.log
```

Output:

```text
Requests:        25
Unique IPs:      6
Time range:      2026-10-18T08:00:00Z .. 2026-10-18T11:03:44Z
Span:            3h 03m 44s
Bytes:           75279 total (p50 210, p95 9731, max 15244)
Error rate:      40.00% (10 4xx/5xx, 3 5xx)
Malformed lines: 0

class  requests
-----  --------
2xx    13
3xx    2
4xx    7
5xx    3
```

More examples:

```bash
# The five most requested paths, ranked by bytes served
python3 logsift.py top paths examples/access.log --by bytes -n 5

# Every 4xx/5xx line, with file and line number
python3 logsift.py errors examples/access.log --list

# Minutes that saw at least 4 requests
python3 logsift.py bursts examples/access.log --threshold 4

# Fail the build if more than 5% of requests are errors
python3 logsift.py check examples/access.log --max-error-rate 0.05 || echo "error budget exceeded"

# Machine-readable output from a rotated, compressed log
python3 logsift.py summary /var/log/nginx/access.log.1.gz --since 2026-10-17T00:00 --format json
```

## How to run

Needs Python 3.8 or newer. There is nothing to install.

```bash
python3 logsift.py COMMAND FILE [FILE ...] [options]
python3 logsift.py --help
python3 logsift.py COMMAND --help
```

| Command    | What it reports                                           |
|------------|-----------------------------------------------------------|
| `summary`  | Totals, time range, bytes, error rate, status classes     |
| `top`      | `paths`, `ips`, `statuses`, `methods`, `agents`, `referers` |
| `errors`   | Grouped 4xx/5xx counts, or `--list` for each line         |
| `timeline` | Per-bucket requests, errors, error rate, top path         |
| `bursts`   | Buckets at or above `--threshold` requests                |
| `check`    | Threshold rules; exit code 0 on pass, 1 on fail           |

Exit codes: `0` success, `1` a `check` rule failed, `2` usage error, unreadable
input, or malformed lines under `--strict`.

Times given to `--since` and `--until` are ISO 8601. A value without an offset
is read as UTC. `--until` is exclusive.

## How to test

```bash
python3 -m pytest tests/
```

No pytest? The suite is `unittest` and runs without it:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover parsing (both formats, escaped quotes, `-` status and size,
timezones, impossible dates), reading (comments, CRLF, gzip, malformed-line
numbering), filters, summary math, ranking, buckets, bursts, threshold checks,
and the CLI exit codes.

## Limitations

- Log formats other than CLF and Combined (for example nginx with custom
  `log_format` fields) are reported as malformed rather than guessed at.
- Query strings are removed before grouping, so `/search?q=a` and `/search?q=b`
  count as one path.
- Timeline and burst buckets list only the minutes, hours or days that had
  traffic. Quiet periods are not filled in with zeros.
- Percentiles use the nearest-rank method over response sizes. Response times
  are not in CLF, so latency is not reported.

## Layout

```text
logsift.py            the tool: parser, filters, reports and CLI
examples/access.log   sample combined-format log
tests/test_logsift.py unit and CLI tests
```
