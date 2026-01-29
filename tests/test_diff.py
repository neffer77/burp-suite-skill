"""Tests for the diff analysis tool."""

import json
import os
import tempfile

import pytest


class TestDiffAnalyze:
    def _run_diff(self, resp_a: dict, resp_b: dict) -> dict:
        """Run the diff command with two response dicts."""
        from burp_suite_skill.tools.diff import diff_analyze

        # Write responses to temp files
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f_a:
            json.dump(resp_a, f_a)
            path_a = f_a.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f_b:
            json.dump(resp_b, f_b)
            path_b = f_b.name

        class Args:
            response_a = path_a
            response_b = path_b

        import io
        from contextlib import redirect_stdout

        try:
            f = io.StringIO()
            with redirect_stdout(f):
                code = diff_analyze(Args())
            output = f.getvalue()
            return json.loads(output)
        finally:
            os.unlink(path_a)
            os.unlink(path_b)

    def test_identical_responses(self):
        resp = {"status_code": 200, "body": "Hello World", "headers": {"Content-Type": "text/html"}}
        result = self._run_diff(resp, resp)
        assert result["verdict"] == "RESPONSES IDENTICAL"
        assert result["differences_found"] == 0

    def test_different_status_codes(self):
        resp_a = {"status_code": 200, "body": "OK"}
        resp_b = {"status_code": 403, "body": "Forbidden"}
        result = self._run_diff(resp_a, resp_b)
        assert result["verdict"] == "RESPONSES DIFFER"
        assert result["summary"]["status_codes"]["match"] is False

    def test_different_body_length(self):
        resp_a = {"status_code": 200, "body": "short"}
        resp_b = {"status_code": 200, "body": "a much longer response body with more content"}
        result = self._run_diff(resp_a, resp_b)
        assert result["summary"]["body_lengths"]["diff"] > 0

    def test_timing_difference_detected(self):
        resp_a = {"status_code": 200, "body": "OK", "elapsed_ms": 100}
        resp_b = {"status_code": 200, "body": "OK", "elapsed_ms": 6000}
        result = self._run_diff(resp_a, resp_b)
        assert any("timing" in d.lower() for d in result["differences"])

    def test_error_message_insight(self):
        resp_a = {"status_code": 200, "body": "Welcome, user!"}
        resp_b = {"status_code": 500, "body": "Internal Server Error: database connection failed"}
        result = self._run_diff(resp_a, resp_b)
        assert any("error" in insight.lower() for insight in result["insights"])

    def test_header_differences(self):
        resp_a = {
            "status_code": 200,
            "body": "OK",
            "headers": {"Content-Type": "text/html", "X-Custom": "value1"},
        }
        resp_b = {
            "status_code": 200,
            "body": "OK",
            "headers": {"Content-Type": "text/html", "X-Custom": "value2"},
        }
        result = self._run_diff(resp_a, resp_b)
        assert "header_diffs" in result["summary"]

    def test_idor_detection_insight(self):
        resp_a = {"status_code": 200, "body": "x" * 100}
        resp_b = {"status_code": 200, "body": "x" * 500}
        result = self._run_diff(resp_a, resp_b)
        # Response B is 5x larger — should trigger data leakage insight
        assert any("larger" in i.lower() or "leak" in i.lower() for i in result["insights"])
