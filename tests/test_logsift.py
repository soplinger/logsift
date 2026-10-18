import contextlib
import gzip
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import logsift  # noqa: E402

COMBINED = (
    '203.0.113.7 - alice [18/Oct/2026:09:00:01 +0000] "GET /index.html HTTP/1.1" 200 5120 '
    '"https://example.org/" "Mozilla/5.0 (X11)"'
)
COMMON = '198.51.100.9 - - [18/Oct/2026:10:00:00 +0200] "POST /api/items HTTP/1.1" 500 128'
UTC = timezone.utc


def write_file(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return path


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = logsift.main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class ParseTests(unittest.TestCase):
    def test_combined_line_fields(self):
        rec = logsift.parse_line(COMBINED, "a.log", 3)
        self.assertEqual(rec.ip, "203.0.113.7")
        self.assertEqual(rec.method, "GET")
        self.assertEqual(rec.path, "/index.html")
        self.assertEqual(rec.status, 200)
        self.assertEqual(rec.size, 5120)
        self.assertEqual(rec.referer, "https://example.org/")
        self.assertEqual(rec.agent, "Mozilla/5.0 (X11)")
        self.assertEqual(rec.source, "a.log")
        self.assertEqual(rec.line_no, 3)

    def test_common_line_without_referer_and_agent(self):
        rec = logsift.parse_line(COMMON)
        self.assertEqual(rec.referer, "-")
        self.assertEqual(rec.agent, "-")
        self.assertEqual(rec.status_class, "5xx")

    def test_timestamp_converted_to_utc(self):
        rec = logsift.parse_line(COMMON)
        self.assertEqual(rec.time, datetime(2026, 10, 18, 8, 0, 0, tzinfo=UTC))

    def test_query_string_removed_from_path(self):
        rec = logsift.parse_line(COMBINED.replace("/index.html", "/search?q=a%20b"))
        self.assertEqual(rec.path, "/search")

    def test_dash_status_and_size(self):
        rec = logsift.parse_line(COMMON.replace(" 500 128", " - -"))
        self.assertIsNone(rec.status)
        self.assertEqual(rec.size, 0)
        self.assertEqual(rec.status_class, "other")

    def test_escaped_quote_in_agent_is_accepted(self):
        rec = logsift.parse_line(COMBINED.replace("Mozilla/5.0 (X11)", 'say \\"hi\\"'))
        self.assertEqual(rec.agent, 'say \\"hi\\"')

    def test_malformed_line_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            logsift.parse_line("this is not a log line")
        self.assertIn("Common or Combined", str(ctx.exception))

    def test_impossible_date_raises_value_error(self):
        with self.assertRaises(ValueError):
            logsift.parse_line(COMMON.replace("18/Oct", "31/Feb"))


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_comments_blank_lines_and_crlf_are_skipped_and_errors_numbered(self):
        text = "# header\r\n\r\n" + COMMON + "\r\nbroken line\r\n" + COMBINED + "\r\n"
        path = write_file(self.tmp.name, "crlf.log", text)
        records, issues = logsift.read_sources([path])
        self.assertEqual(len(records), 2)
        self.assertEqual([(i.line_no, i.source) for i in issues], [(4, path)])

    def test_gzip_input_is_read(self):
        path = os.path.join(self.tmp.name, "access.log.gz")
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(COMMON + "\n" + COMBINED + "\n")
        records, issues = logsift.read_sources([path])
        self.assertEqual(len(records), 2)
        self.assertEqual(issues, [])

    def test_empty_file_gives_no_records(self):
        path = write_file(self.tmp.name, "empty.log", "")
        self.assertEqual(logsift.read_sources([path]), ([], []))


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.recs = [
            logsift.parse_line(COMMON),  # 08:00 UTC, POST, 500
            logsift.parse_line(COMBINED),  # 09:00 UTC, GET, 200 /index.html
            logsift.parse_line(COMBINED.replace("200 5120", "404 10").replace("/index.html", "/api/x")),
        ]

    def kept(self, **kwargs):
        args = dict(since=None, until=None, methods=frozenset(), status=None, path_prefix="")
        args.update(kwargs)
        return [r for r in self.recs if logsift.Filters(**args).keep(r)]

    def test_since_and_until_window(self):
        since = datetime(2026, 10, 18, 8, 30, tzinfo=UTC)
        until = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)
        self.assertEqual(len(self.kept(since=since, until=until)), 0)
        self.assertEqual(len(self.kept(since=since)), 2)

    def test_method_and_path_prefix(self):
        self.assertEqual(len(self.kept(methods=frozenset({"POST"}))), 1)
        self.assertEqual(len(self.kept(path_prefix="/api")), 2)

    def test_status_predicate(self):
        self.assertEqual(len(self.kept(status=logsift.parse_status_spec("5xx"))), 1)

    def test_status_spec_forms(self):
        check = logsift.parse_status_spec("404,500-503")
        self.assertTrue(check(404))
        self.assertTrue(check(502))
        self.assertFalse(check(200))
        self.assertTrue(logsift.parse_status_spec("4xx")(418))

    def test_bad_status_spec_raises(self):
        with self.assertRaises(ValueError):
            logsift.parse_status_spec("6xx")
        with self.assertRaises(ValueError):
            logsift.parse_status_spec("503-500")

    def test_parse_when_naive_is_utc_and_aware_is_converted(self):
        self.assertEqual(logsift.parse_when("2026-10-18T09:00"), datetime(2026, 10, 18, 9, tzinfo=UTC))
        self.assertEqual(
            logsift.parse_when("2026-10-18T10:00:00+01:00"), datetime(2026, 10, 18, 9, tzinfo=UTC)
        )
        with self.assertRaises(ValueError):
            logsift.parse_when("yesterday")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.recs = [
            logsift.parse_line('10.0.0.1 - - [18/Oct/2026:09:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "x"'),
            logsift.parse_line('10.0.0.1 - - [18/Oct/2026:09:00:30 +0000] "GET /a HTTP/1.1" 200 300 "-" "x"'),
            logsift.parse_line('10.0.0.2 - - [18/Oct/2026:09:00:40 +0000] "GET /b HTTP/1.1" 404 50 "-" "x"'),
            logsift.parse_line('10.0.0.3 - - [18/Oct/2026:11:10:00 +0000] "GET /b HTTP/1.1" 500 0 "-" "x"'),
        ]

    def test_summarize_totals_and_error_rate(self):
        data = logsift.summarize(self.recs)
        self.assertEqual(data["requests"], 4)
        self.assertEqual(data["unique_ips"], 3)
        self.assertEqual(data["bytes_total"], 450)
        self.assertEqual(data["bytes_max"], 300)
        self.assertEqual(data["errors"], 2)
        self.assertEqual(data["errors_5xx"], 1)
        self.assertEqual(data["error_rate"], 0.5)
        self.assertEqual(data["status_classes"], {"2xx": 2, "4xx": 1, "5xx": 1})
        self.assertEqual(data["span_seconds"], 2 * 3600 + 10 * 60)

    def test_summarize_empty(self):
        data = logsift.summarize([])
        self.assertEqual(data["requests"], 0)
        self.assertIsNone(data["first"])
        self.assertEqual(data["error_rate"], 0.0)

    def test_percentile_nearest_rank(self):
        values = [10, 20, 30, 40]
        self.assertEqual(logsift.percentile(values, 50), 20)
        self.assertEqual(logsift.percentile(values, 95), 40)
        self.assertEqual(logsift.percentile([], 50), 0)

    def test_top_by_requests_and_bytes(self):
        by_requests = logsift.top(self.recs, "paths", "requests", 10)
        self.assertEqual([r["key"] for r in by_requests], ["/a", "/b"])
        by_bytes = logsift.top(self.recs, "ips", "bytes", 1)
        self.assertEqual(by_bytes[0]["key"], "10.0.0.1")
        self.assertEqual(by_bytes[0]["bytes"], 400)

    def test_timeline_hour_buckets_and_top_path(self):
        rows = logsift.timeline(self.recs, "hour")
        self.assertEqual([r["bucket"] for r in rows], ["2026-10-18T09Z", "2026-10-18T11Z"])
        self.assertEqual(rows[0]["requests"], 3)
        self.assertEqual(rows[0]["errors"], 1)
        self.assertEqual(rows[0]["top_path"], "/a")

    def test_bursts_threshold(self):
        rows = logsift.bursts(self.recs, "minute", 2)
        self.assertEqual([r["bucket"] for r in rows], ["2026-10-18T09:00Z"])
        self.assertEqual(logsift.bursts(self.recs, "minute", 5), [])

    def test_error_paths_grouping(self):
        errors = [r for r in self.recs if r.status >= 400]
        rows = logsift.error_paths(errors, 10)
        self.assertEqual(rows[0], {"status": 404, "path": "/b", "count": 1})
        self.assertEqual(len(rows), 2)

    def test_run_checks_pass_and_fail(self):
        summary = logsift.summarize(self.recs)
        rules = {"max_error_rate": 0.25, "max_5xx": 1, "max_malformed": None, "min_requests": 4}
        results = logsift.run_checks(summary, 0, rules)
        self.assertEqual([c["passed"] for c in results], [False, True, True])
        only_malformed = {"max_error_rate": None, "max_5xx": None, "max_malformed": 2, "min_requests": None}
        self.assertFalse(logsift.run_checks(summary, 3, only_malformed)[0]["passed"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.good = write_file(self.tmp.name, "good.log", COMMON + "\n" + COMBINED + "\n")
        self.bad = write_file(self.tmp.name, "bad.log", COMMON + "\nnope\n")

    def test_summary_json(self):
        code, out, _ = run_cli(["summary", self.good, "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["requests"], 2)
        self.assertEqual(data["malformed_lines"], 0)

    def test_malformed_lines_are_warned_but_not_fatal(self):
        code, out, err = run_cli(["summary", self.bad, "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIn(f"{self.bad}:2", err)
        self.assertEqual(json.loads(out)["malformed_lines"], 1)

    def test_strict_mode_fails_on_malformed_line(self):
        code, _, err = run_cli(["summary", self.bad, "--strict"])
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_check_exit_code_reflects_threshold(self):
        code, out, _ = run_cli(["check", self.good, "--max-5xx", "0"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL  max_5xx", out)
        code, out, _ = run_cli(["check", self.good, "--max-error-rate", "0.5", "--min-requests", "2"])
        self.assertEqual(code, 0)
        self.assertIn("Result: PASS", out)

    def test_errors_list_has_file_and_line(self):
        code, out, _ = run_cli(["errors", self.good, "--list"])
        self.assertEqual(code, 0)
        self.assertIn(f"{self.good}:1", out)

    def test_bad_filter_value_is_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                logsift.main(["summary", self.good, "--status", "9xx"])
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_file_is_reported(self):
        code, _, err = run_cli(["summary", os.path.join(self.tmp.name, "nope.log")])
        self.assertEqual(code, 2)
        self.assertIn("cannot read input", err)

    def test_sample_log_runs_all_commands(self):
        sample = os.path.join(ROOT, "examples", "access.log")
        for argv in (
            ["summary", sample],
            ["top", "paths", sample, "-n", "3"],
            ["errors", sample],
            ["timeline", sample, "--bucket", "day"],
            ["bursts", sample, "--threshold", "4"],
        ):
            code, out, _ = run_cli(argv)
            self.assertEqual(code, 0, argv)
            self.assertTrue(out.strip(), argv)


if __name__ == "__main__":
    unittest.main()
