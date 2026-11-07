"""Regression tests for input validation and malformed server responses.

Every case here used to raise an uncaught exception or return the wrong exit
code. They are pinned so the CLI stays safe to point at hostile servers.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from wraith.mcpclient import MCPClient, MCPError


def cli(args, cwd=None, stdin=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["NO_COLOR"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "wraith"] + args,
        input=stdin, capture_output=True, text=True, timeout=60,
        cwd=cwd or tempfile.mkdtemp(), env=env,
    )


class TransportRobustnessTests(unittest.TestCase):
    def test_invalid_url_raises_mcperror(self):
        client = MCPClient("not-a-url", timeout=1)
        with self.assertRaises(MCPError):
            client.initialize()

    def test_missing_host_raises_mcperror(self):
        client = MCPClient("http://", timeout=1)
        with self.assertRaises(MCPError):
            client.initialize()

    def test_batch_reply_is_unwrapped(self):
        body = json.dumps([
            {"jsonrpc": "2.0", "id": 1, "result": {"a": 1}},
            {"jsonrpc": "2.0", "id": 2, "result": {"a": 2}},
        ]).encode()
        picked = MCPClient._parse_body(body, "application/json", 2)
        self.assertEqual(picked["result"], {"a": 2})

    def test_batch_reply_without_matching_id(self):
        body = json.dumps([{"jsonrpc": "2.0", "id": 9, "result": {"a": 9}}]).encode()
        picked = MCPClient._parse_body(body, "application/json", 1)
        self.assertEqual(picked["result"], {"a": 9})

    def test_non_object_reply_is_rejected(self):
        for payload in (b'"hello"', b"42", b"[1, 2, 3]", b"null"):
            with self.assertRaises(MCPError):
                MCPClient._parse_body(payload, "application/json", 1)

    def test_sse_batch_reply_is_unwrapped(self):
        event = 'event: message\ndata: [{"jsonrpc":"2.0","id":3,"result":{"ok":true}}]\n\n'
        picked = MCPClient._parse_body(event.encode(), "text/event-stream", 3)
        self.assertEqual(picked["result"], {"ok": True})

    def test_non_json_body_is_rejected(self):
        with self.assertRaises(MCPError):
            MCPClient._parse_body(b"<html>nope</html>", "text/html", 1)


class CliValidationTests(unittest.TestCase):
    def test_probe_rejects_non_url(self):
        proc = cli(["probe", "not-a-url", "--i-own-this-target"])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr + proc.stdout)
        self.assertIn("http(s) URL", proc.stdout)

    def test_probe_rejects_url_without_scheme(self):
        proc = cli(["probe", "example.com/mcp", "--i-own-this-target"])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr + proc.stdout)

    def test_pin_rejects_non_url(self):
        proc = cli(["pin", "not-a-url", "--i-own-this-target"])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr + proc.stdout)

    def test_bad_header_is_a_usage_error(self):
        proc = cli(["probe", "http://127.0.0.1:1/mcp", "--i-own-this-target", "--header", "nocolon"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("bad --header value", proc.stderr)

    def test_analyze_reports_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"tools": [')
            proc = cli(["analyze", path])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr + proc.stdout)
        self.assertIn("invalid JSON", proc.stdout)

    def test_rules_accepts_common_flags(self):
        proc = cli(["rules", "--color", "never"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        quiet = cli(["rules", "--quiet"])
        self.assertEqual(quiet.returncode, 0, quiet.stderr)
        self.assertIn("hidden-instruction", quiet.stdout)
        self.assertNotIn(" ", quiet.stdout.split("\n")[0])


class ScopeValidationTests(unittest.TestCase):
    def test_empty_pattern_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = cli(["scope", "add", "  ", "--program", "acme",
                        "--file", os.path.join(tmp, "scope.json")], cwd=tmp)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("cannot be empty", proc.stdout)

    def test_pattern_is_trimmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope_file = os.path.join(tmp, "scope.json")
            proc = cli(["scope", "add", "  *.acme.test  ", "--program", "acme",
                        "--file", scope_file], cwd=tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout)
            with open(scope_file, encoding="utf-8") as handle:
                self.assertIn("*.acme.test", handle.read())
                self.assertNotIn("  *.acme.test", handle.read())

    def test_removing_unknown_program_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = cli(["scope", "remove", "ghost", "--file", os.path.join(tmp, "scope.json")], cwd=tmp)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no such program", proc.stdout)


class DemoExitCodeTests(unittest.TestCase):
    def test_demo_fail_on_high_exits_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = cli(["demo", "--fail-on", "high", "--evidence-dir", tmp])
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_demo_defaults_to_clean_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = cli(["demo", "--evidence-dir", tmp])
        self.assertEqual(proc.returncode, 0, proc.stderr)


class OutputRobustnessTests(unittest.TestCase):
    def test_unencodable_output_does_not_crash(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env["PYTHONIOENCODING"] = "ascii"
        proc = subprocess.run(
            [sys.executable, "-m", "wraith", "analyze", "examples/poisoned-tools.json"],
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), env=env,
        )
        self.assertNotIn("Traceback", proc.stderr + proc.stdout)
        self.assertIn(proc.returncode, (0, 1))

    def test_unwritable_evidence_dir_reports_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "blocker")
            with open(blocker, "w", encoding="utf-8") as handle:
                handle.write("x")
            proc = cli(["demo", "--evidence-dir", blocker])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr + proc.stdout)
        self.assertIn("cannot write output", proc.stdout)

    def test_report_rejects_corrupt_findings(self):
        for payload in ('{"oops": 1}', '["a", "b"]', '[{"rule": "x"}]'):
            with tempfile.TemporaryDirectory() as tmp:
                with open(os.path.join(tmp, "findings.json"), "w", encoding="utf-8") as handle:
                    handle.write(payload)
                proc = cli(["report", tmp])
            self.assertEqual(proc.returncode, 2, payload)
            self.assertNotIn("Traceback", proc.stderr + proc.stdout)
            self.assertIn("malformed findings.json", proc.stdout)

    def test_analyze_tolerates_non_dict_tool_entries(self):
        payload = {"tools": [None, "string", 42, [], {"name": "ok"}]}
        proc = cli(["analyze", "-"], stdin=json.dumps(payload))
        self.assertNotIn("Traceback", proc.stderr + proc.stdout)
        self.assertIn(proc.returncode, (0, 1))

    def test_analyze_rejects_tools_object(self):
        proc = cli(["analyze", "-"], stdin=json.dumps({"tools": {"name": "x"}}))
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main()
