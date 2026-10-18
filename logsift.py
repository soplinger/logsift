"""logsift: offline summaries for web server access logs.

Reads Common Log Format and Combined Log Format files (plain, .gz or stdin)
and reports totals, top paths and clients, error breakdowns, per-bucket
timelines, traffic bursts and CI-style threshold checks. Standard library only.
"""

import argparse
import gzip
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

# Quoted fields may contain backslash escapes such as \" inside a user agent.
LINE_RE = re.compile(
    r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<size>\d+|-)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<agent>(?:[^"\\]|\\.)*)")?'
)
TIME_RE = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")
MONTHS = {
    name: number
    for number, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
    )
}
BUCKET_FORMATS = {"minute": "%Y-%m-%dT%H:%MZ", "hour": "%Y-%m-%dT%HZ", "day": "%Y-%m-%dZ"}
KEY_FUNCS = {
    "paths": lambda r: r.path,
    "ips": lambda r: r.ip,
    "statuses": lambda r: str(r.status) if r.status is not None else "-",
    "methods": lambda r: r.method,
    "agents": lambda r: r.agent,
    "referers": lambda r: r.referer,
}


@dataclass(frozen=True)
class Record:
    source: str
    line_no: int
    ip: str
    time: datetime  # always UTC
    method: str
    path: str  # query string removed
    status: Optional[int]  # None when the log has "-"
    size: int
    referer: str
    agent: str

    @property
    def status_class(self):
        return f"{self.status // 100}xx" if self.status is not None else "other"


@dataclass(frozen=True)
class Issue:
    source: str
    line_no: int
    message: str


@dataclass(frozen=True)
class Filters:
    since: Optional[datetime] = None
    until: Optional[datetime] = None  # exclusive
    methods: frozenset = frozenset()
    status: Optional[Callable[[int], bool]] = None
    path_prefix: str = ""

    def keep(self, rec):
        if self.since and rec.time < self.since:
            return False
        if self.until and rec.time >= self.until:
            return False
        if self.methods and rec.method.upper() not in self.methods:
            return False
        if self.status and (rec.status is None or not self.status(rec.status)):
            return False
        return rec.path.startswith(self.path_prefix)


def parse_clf_time(text):
    """Turn '10/Oct/2026:13:55:36 -0700' into an aware UTC datetime."""
    match = TIME_RE.fullmatch(text)
    if not match or match.group(2) not in MONTHS:
        raise ValueError(f"bad timestamp {text!r}")
    day, mon, year, hh, mm, ss, sign, off_h, off_m = match.groups()
    offset = timedelta(hours=int(off_h), minutes=int(off_m))
    if sign == "-":
        offset = -offset
    local = datetime(
        int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=timezone(offset)
    )
    return local.astimezone(timezone.utc)


def parse_line(text, source="<input>", line_no=0):
    """Parse one log line into a Record. Raises ValueError with a short reason."""
    match = LINE_RE.fullmatch(text.strip())
    if not match:
        raise ValueError("not in Common or Combined Log Format")
    when = parse_clf_time(match["time"])
    method, path = (match["request"].split() + ["-", "-"])[:2]
    status = None if match["status"] == "-" else int(match["status"])
    size = 0 if match["size"] == "-" else int(match["size"])
    return Record(
        source=source,
        line_no=line_no,
        ip=match["ip"],
        time=when,
        method=method,
        path=path.split("?", 1)[0],
        status=status,
        size=size,
        referer=match["referer"] or "-",
        agent=match["agent"] or "-",
    )


def iter_lines(name):
    if name == "-":
        yield from sys.stdin
        return
    opener = gzip.open if name.endswith(".gz") else open
    with opener(name, "rt", encoding="utf-8", errors="replace") as fh:
        yield from fh


def read_sources(names):
    """Return (records, issues) for every line of every named file ('-' is stdin)."""
    records, issues = [], []
    for name in names:
        label = "<stdin>" if name == "-" else name
        for line_no, raw in enumerate(iter_lines(name), start=1):
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            try:
                records.append(parse_line(text, label, line_no))
            except ValueError as exc:
                issues.append(Issue(label, line_no, str(exc)))
    return records, issues


def parse_status_spec(spec):
    """Accept '404', '400-499', '5xx' or a comma list of those; return a predicate."""
    ranges = []
    for part in spec.split(","):
        part = part.strip().lower()
        if re.fullmatch(r"[1-5]xx", part):
            low = int(part[0]) * 100
            ranges.append((low, low + 99))
            continue
        match = re.fullmatch(r"(\d{3})(?:-(\d{3}))?", part)
        if not match:
            raise ValueError(f"bad status spec {part!r} (use 404, 400-499 or 5xx)")
        low = int(match.group(1))
        high = int(match.group(2) or low)
        if high < low:
            raise ValueError(f"bad status range {part!r}")
        ranges.append((low, high))
    return lambda code: any(low <= code <= high for low, high in ranges)


def parse_when(text):
    """ISO 8601 time to UTC. Naive values are taken as UTC."""
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"bad time {text!r} (use ISO 8601, e.g. 2026-10-18T09:00)") from None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


def make_filters(args):
    methods = frozenset(m.strip().upper() for m in args.method.split(",") if m.strip()) if args.method else frozenset()
    since = parse_when(args.since) if args.since else None
    until = parse_when(args.until) if args.until else None
    if since and until and until <= since:
        raise ValueError("--until must be later than --since")
    status = parse_status_spec(args.status) if args.status else None
    return Filters(since, until, methods, status, args.path_prefix)


def percentile(sorted_values, pct):
    """Nearest-rank percentile of an already sorted list; 0 when empty."""
    if not sorted_values:
        return 0
    rank = max(1, math.ceil(pct / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def iso(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else None


def summarize(records):
    sizes = sorted(r.size for r in records)
    classes = Counter(r.status_class for r in records)
    errors = classes["4xx"] + classes["5xx"]
    total = len(records)
    first = min((r.time for r in records), default=None)
    last = max((r.time for r in records), default=None)
    return {
        "requests": total,
        "unique_ips": len({r.ip for r in records}),
        "first": iso(first),
        "last": iso(last),
        "span_seconds": int((last - first).total_seconds()) if total else 0,
        "bytes_total": sum(sizes),
        "bytes_p50": percentile(sizes, 50),
        "bytes_p95": percentile(sizes, 95),
        "bytes_max": sizes[-1] if sizes else 0,
        "status_classes": {name: classes[name] for name in sorted(classes)},
        "errors": errors,
        "errors_5xx": classes["5xx"],
        "error_rate": round(errors / total, 4) if total else 0.0,
    }


def top(records, by, sort="requests", n=10):
    counts, sizes = Counter(), Counter()
    key = KEY_FUNCS[by]
    for rec in records:
        counts[key(rec)] += 1
        sizes[key(rec)] += rec.size
    rows = [{"key": k, "requests": counts[k], "bytes": sizes[k]} for k in counts]
    rows.sort(key=lambda row: (-row[sort], row["key"]))
    return rows[:n]


def bucket_start(when, bucket):
    if bucket == "minute":
        return when.replace(second=0, microsecond=0)
    if bucket == "hour":
        return when.replace(minute=0, second=0, microsecond=0)
    return when.replace(hour=0, minute=0, second=0, microsecond=0)


def timeline(records, bucket="hour"):
    rows = {}
    for rec in records:
        key = bucket_start(rec.time, bucket).strftime(BUCKET_FORMATS[bucket])
        row = rows.setdefault(key, {"requests": 0, "errors": 0, "paths": Counter()})
        row["requests"] += 1
        if rec.status is not None and rec.status >= 400:
            row["errors"] += 1
        row["paths"][rec.path] += 1
    out = []
    for key in sorted(rows):
        row = rows[key]
        top_path = min(row["paths"].items(), key=lambda kv: (-kv[1], kv[0]))[0]
        out.append({
            "bucket": key,
            "requests": row["requests"],
            "errors": row["errors"],
            "error_rate": round(row["errors"] / row["requests"], 4),
            "top_path": top_path,
        })
    return out


def bursts(records, bucket="minute", threshold=1):
    return [row for row in timeline(records, bucket) if row["requests"] >= threshold]


def error_paths(errors, n=10):
    counts = Counter((rec.status, rec.path) for rec in errors)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1]))[:n]
    return [{"status": status, "path": path, "count": count} for (status, path), count in ranked]


def run_checks(summary, malformed, rules):
    checks = []

    def add(rule, limit, actual, passed):
        checks.append({"rule": rule, "limit": limit, "actual": actual, "passed": passed})

    if rules["max_error_rate"] is not None:
        limit, actual = rules["max_error_rate"], summary["error_rate"]
        add("max_error_rate", limit, actual, actual <= limit)
    if rules["max_5xx"] is not None:
        limit, actual = rules["max_5xx"], summary["errors_5xx"]
        add("max_5xx", limit, actual, actual <= limit)
    if rules["max_malformed"] is not None:
        limit = rules["max_malformed"]
        add("max_malformed", limit, malformed, malformed <= limit)
    if rules["min_requests"] is not None:
        limit, actual = rules["min_requests"], summary["requests"]
        add("min_requests", limit, actual, actual >= limit)
    return checks


def table(headers, rows):
    cells = [[str(value) for value in row] for row in rows]
    widths = [max([len(h)] + [len(row[i]) for row in cells]) for i, h in enumerate(headers)]

    def fmt(values):
        return "  ".join(v.ljust(w) for v, w in zip(values, widths)).rstrip()

    lines = [fmt(headers), fmt(["-" * w for w in widths])] + [fmt(row) for row in cells]
    return "\n".join(lines)


def human_span(seconds):
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s"


def emit(args, data, text):
    print(json.dumps(data, indent=2) if args.format == "json" else text)


def report_issues(issues, strict):
    label = "error" if strict else "warning"
    shown = issues if strict else issues[:10]
    for issue in shown:
        print(f"logsift: {label}: {issue.source}:{issue.line_no}: {issue.message}", file=sys.stderr)
    if not strict and len(issues) > len(shown):
        print(f"logsift: ... and {len(issues) - len(shown)} more malformed line(s)", file=sys.stderr)
    if not strict:
        print(f"logsift: skipped {len(issues)} malformed line(s)", file=sys.stderr)


def cmd_summary(args, recs, issues):
    data = summarize(recs)
    data["malformed_lines"] = len(issues)
    classes = [[name, count] for name, count in data["status_classes"].items()]
    text = "\n".join([
        f"Requests:        {data['requests']}",
        f"Unique IPs:      {data['unique_ips']}",
        f"Time range:      {data['first'] or 'n/a'} .. {data['last'] or 'n/a'}",
        f"Span:            {human_span(data['span_seconds'])}",
        f"Bytes:           {data['bytes_total']} total "
        f"(p50 {data['bytes_p50']}, p95 {data['bytes_p95']}, max {data['bytes_max']})",
        f"Error rate:      {data['error_rate'] * 100:.2f}% "
        f"({data['errors']} 4xx/5xx, {data['errors_5xx']} 5xx)",
        f"Malformed lines: {data['malformed_lines']}",
        "",
        table(["class", "requests"], classes) if classes else "No requests matched.",
    ])
    emit(args, data, text)
    return 0


def cmd_top(args, recs, issues):
    rows = top(recs, args.what, args.by, args.n)
    data = {"by": args.what, "sort": args.by, "rows": rows}
    body = [[r["key"], r["requests"], r["bytes"]] for r in rows]
    text = table([args.what, "requests", "bytes"], body) if body else "No requests matched."
    emit(args, data, text)
    return 0


def cmd_errors(args, recs, issues):
    errors = [r for r in recs if r.status is not None and r.status >= 400]
    if args.list:
        shown = errors[: args.n]
        data = {
            "total": len(errors),
            "entries": [
                {"where": f"{r.source}:{r.line_no}", "status": r.status, "method": r.method, "path": r.path}
                for r in shown
            ],
        }
        body = [[e["where"], e["status"], e["method"], e["path"]] for e in data["entries"]]
        text = table(["where", "status", "method", "path"], body) if body else "No 4xx/5xx responses."
    else:
        rows = error_paths(errors, args.n)
        data = {"total": len(errors), "paths": rows}
        body = [[r["status"], r["count"], r["path"]] for r in rows]
        text = table(["status", "count", "path"], body) if body else "No 4xx/5xx responses."
    emit(args, data, text)
    return 0


def timeline_table(rows):
    return table(
        ["bucket", "requests", "errors", "error_rate", "top_path"],
        [[r["bucket"], r["requests"], r["errors"], f"{r['error_rate'] * 100:.2f}%", r["top_path"]] for r in rows],
    )


def cmd_timeline(args, recs, issues):
    rows = timeline(recs, args.bucket)
    data = {"bucket": args.bucket, "rows": rows}
    text = timeline_table(rows) if rows else "No requests matched."
    emit(args, data, text)
    return 0


def cmd_bursts(args, recs, issues):
    rows = bursts(recs, args.bucket, args.threshold)
    data = {"bucket": args.bucket, "threshold": args.threshold, "rows": rows}
    text = timeline_table(rows) if rows else f"No {args.bucket} reached {args.threshold} requests."
    emit(args, data, text)
    return 0


def cmd_check(args, recs, issues):
    rules = {
        "max_error_rate": args.max_error_rate,
        "max_5xx": args.max_5xx,
        "max_malformed": args.max_malformed,
        "min_requests": args.min_requests,
    }
    checks = run_checks(summarize(recs), len(issues), rules)
    passed = all(c["passed"] for c in checks)
    data = {"passed": passed, "checks": checks}
    lines = [
        f"{'PASS' if c['passed'] else 'FAIL'}  {c['rule']}: actual {c['actual']} (limit {c['limit']})"
        for c in checks
    ]
    if not lines:
        lines = ["No rules given; nothing to check."]
    else:
        lines.append(f"Result: {'PASS' if passed else 'FAIL'}")
    emit(args, data, "\n".join(lines))
    return 0 if passed else 1


COMMANDS = {
    "summary": cmd_summary,
    "top": cmd_top,
    "errors": cmd_errors,
    "timeline": cmd_timeline,
    "bursts": cmd_bursts,
    "check": cmd_check,
}


def int_min(minimum):
    def parse(text):
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"expected an integer, got {text!r}") from None
        if value < minimum:
            raise argparse.ArgumentTypeError(f"must be at least {minimum}")
        return value

    return parse


def build_parser():
    parser = argparse.ArgumentParser(prog="logsift", description="Offline summaries for web server access logs.")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def common(p):
        p.add_argument("files", nargs="+", metavar="FILE", help="access log(s); .gz is decompressed, '-' reads stdin")
        filt = p.add_argument_group("filters")
        filt.add_argument("--since", help="keep requests at or after this time (ISO 8601; naive means UTC)")
        filt.add_argument("--until", help="keep requests before this time (exclusive)")
        filt.add_argument("--method", help="comma-separated methods, e.g. GET,POST")
        filt.add_argument("--status", help="status codes, ranges or classes, e.g. 404,500-503,5xx")
        filt.add_argument("--path-prefix", default="", help="keep paths that start with this prefix")
        p.add_argument("--strict", action="store_true", help="exit 2 if any line is malformed")
        p.add_argument("--format", choices=["text", "json"], default="text", help="output format")

    p = sub.add_parser("summary", help="totals, time range, status classes and byte sizes")
    common(p)

    p = sub.add_parser("top", help="most frequent paths, IPs, statuses, methods, agents or referers")
    p.add_argument("what", choices=sorted(KEY_FUNCS))
    p.add_argument("-n", type=int_min(1), default=10, help="rows to show (default 10)")
    p.add_argument("--by", choices=["requests", "bytes"], default="requests", help="rank by request count or bytes")
    common(p)

    p = sub.add_parser("errors", help="4xx/5xx responses grouped by path, or listed with file:line")
    p.add_argument("-n", type=int_min(1), default=10, help="rows to show (default 10)")
    p.add_argument("--list", action="store_true", help="list individual error lines instead of grouping")
    common(p)

    p = sub.add_parser("timeline", help="requests and error rate per minute, hour or day")
    p.add_argument("--bucket", choices=sorted(BUCKET_FORMATS), default="hour")
    common(p)

    p = sub.add_parser("bursts", help="buckets whose request count reaches a threshold")
    p.add_argument("--bucket", choices=sorted(BUCKET_FORMATS), default="minute")
    p.add_argument("--threshold", type=int_min(1), required=True, help="minimum requests in a bucket")
    common(p)

    p = sub.add_parser("check", help="CI gate: exit 1 when a threshold is breached")
    p.add_argument("--max-error-rate", type=float, help="maximum 4xx/5xx share as a fraction, e.g. 0.05")
    p.add_argument("--max-5xx", type=int_min(0), help="maximum number of 5xx responses")
    p.add_argument("--max-malformed", type=int_min(0), help="maximum number of malformed lines")
    p.add_argument("--min-requests", type=int_min(0), help="minimum number of requests")
    common(p)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        filters = make_filters(args)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        records, issues = read_sources(args.files)
    except OSError as exc:
        print(f"logsift: cannot read input: {exc}", file=sys.stderr)
        return 2
    if issues:
        report_issues(issues, args.strict)
        if args.strict:
            return 2
    kept = [rec for rec in records if filters.keep(rec)]
    return COMMANDS[args.command](args, kept, issues)


if __name__ == "__main__":
    sys.exit(main())
