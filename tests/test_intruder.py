"""Tests for the intruder tool: payload loading, parameter substitution, and result analysis."""

import json
import os
import tempfile

import pytest

from burp_suite_skill.tools.intruder import (
    BUILTIN_PAYLOADS,
    _analyze_results,
    _apply_payload_to_request,
    _load_payloads,
)


class MockArgs:
    """Minimal args object for testing."""
    payload_set = None
    payload_file = None
    payloads = None


class TestLoadPayloads:
    def test_builtin_payload_set(self):
        args = MockArgs()
        args.payload_set = "sqli-basic"
        payloads = _load_payloads(args)
        assert len(payloads) > 0
        assert "'" in payloads

    def test_unknown_payload_set_raises(self):
        args = MockArgs()
        args.payload_set = "nonexistent-set"
        with pytest.raises(ValueError, match="Unknown payload set"):
            _load_payloads(args)

    def test_payload_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("payload1\npayload2\n# comment\n\npayload3\n")
            path = f.name
        try:
            args = MockArgs()
            args.payload_file = path
            payloads = _load_payloads(args)
            assert payloads == ["payload1", "payload2", "payload3"]
        finally:
            os.unlink(path)

    def test_missing_payload_file_raises(self):
        args = MockArgs()
        args.payload_file = "/nonexistent/file.txt"
        with pytest.raises(FileNotFoundError):
            _load_payloads(args)

    def test_inline_payloads(self):
        args = MockArgs()
        args.payloads = "foo,bar,baz"
        payloads = _load_payloads(args)
        assert payloads == ["foo", "bar", "baz"]

    def test_no_payloads_raises(self):
        args = MockArgs()
        with pytest.raises(ValueError, match="No payloads specified"):
            _load_payloads(args)

    def test_all_builtin_sets_exist(self):
        expected = {"sqli-basic", "xss-basic", "path-traversal", "ssti-basic", "auth-bypass", "idor-numeric"}
        assert expected == set(BUILTIN_PAYLOADS.keys())

    def test_all_builtin_sets_nonempty(self):
        for name, payloads in BUILTIN_PAYLOADS.items():
            assert len(payloads) > 0, f"Payload set '{name}' is empty"


class TestApplyPayload:
    def test_url_query_param(self):
        base = {"url": "https://target.com/search?q=test&page=1", "body": ""}
        result = _apply_payload_to_request(base, "q", "<script>alert(1)</script>")
        assert "q=<script>alert(1)</script>" in result["url"]
        assert "page=1" in result["url"]

    def test_json_body_param(self):
        base = {
            "url": "https://target.com/api",
            "headers": {"Content-Type": "application/json"},
            "body": '{"username":"admin","password":"pass"}',
        }
        result = _apply_payload_to_request(base, "password", "' OR '1'='1")
        body = json.loads(result["body"])
        assert body["password"] == "' OR '1'='1"
        assert body["username"] == "admin"

    def test_form_body_param(self):
        base = {
            "url": "https://target.com/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "username=admin&password=pass",
        }
        result = _apply_payload_to_request(base, "password", "injected")
        assert "password=injected" in result["body"]
        assert "username=admin" in result["body"]

    def test_appends_if_not_found(self):
        base = {"url": "https://target.com/api", "body": "", "headers": {}}
        result = _apply_payload_to_request(base, "newparam", "value")
        assert "newparam=value" in result["url"]

    def test_appends_with_ampersand_if_query_exists(self):
        base = {"url": "https://target.com/api?existing=1", "body": "", "headers": {}}
        result = _apply_payload_to_request(base, "newparam", "value")
        assert "&newparam=value" in result["url"]


class TestAnalyzeResults:
    def test_empty_results(self):
        analysis = _analyze_results([])
        assert "No results" in analysis["conclusion"]

    def test_all_errors(self):
        results = [
            {"index": 0, "payload": "x", "error": "fail", "elapsed_ms": 100},
        ]
        analysis = _analyze_results(results)
        assert "All requests failed" in analysis["conclusion"]

    def test_consistent_results_no_anomalies(self):
        results = [
            {"index": i, "payload": f"p{i}", "status_code": 200, "body_length": 500, "elapsed_ms": 100}
            for i in range(5)
        ]
        analysis = _analyze_results(results)
        assert analysis["anomalies_found"] == 0
        assert "No significant anomalies" in analysis["conclusion"]

    def test_status_code_anomaly_detected(self):
        results = [
            {"index": 0, "payload": "normal", "status_code": 200, "body_length": 500, "elapsed_ms": 100},
            {"index": 1, "payload": "normal2", "status_code": 200, "body_length": 500, "elapsed_ms": 100},
            {"index": 2, "payload": "evil", "status_code": 500, "body_length": 100, "elapsed_ms": 100},
        ]
        analysis = _analyze_results(results)
        status_anomalies = [a for a in analysis["anomalies"] if a["type"] == "status_code_deviation"]
        assert len(status_anomalies) >= 1
        assert status_anomalies[0]["payload"] == "evil"

    def test_timing_anomaly_detected(self):
        # Needs enough normal samples so average stays low, and the anomaly
        # exceeds max(avg*3, 3000ms)
        results = [
            {"index": 0, "payload": "normal", "status_code": 200, "body_length": 500, "elapsed_ms": 100},
            {"index": 1, "payload": "normal2", "status_code": 200, "body_length": 500, "elapsed_ms": 110},
            {"index": 2, "payload": "normal3", "status_code": 200, "body_length": 500, "elapsed_ms": 90},
            {"index": 3, "payload": "normal4", "status_code": 200, "body_length": 500, "elapsed_ms": 100},
            {"index": 4, "payload": "sleep", "status_code": 200, "body_length": 500, "elapsed_ms": 5500},
        ]
        analysis = _analyze_results(results)
        timing_anomalies = [a for a in analysis["anomalies"] if a["type"] == "timing_anomaly"]
        assert len(timing_anomalies) >= 1
        assert any(a["payload"] == "sleep" for a in timing_anomalies)

    def test_body_length_anomaly_detected(self):
        # Use enough uniform entries so the average stays close to 500,
        # making the 5000-length entry a clear outlier
        results = [
            {"index": 0, "payload": "p0", "status_code": 200, "body_length": 500, "elapsed_ms": 100},
            {"index": 1, "payload": "p1", "status_code": 200, "body_length": 510, "elapsed_ms": 100},
            {"index": 2, "payload": "p2", "status_code": 200, "body_length": 490, "elapsed_ms": 100},
            {"index": 3, "payload": "p3", "status_code": 200, "body_length": 505, "elapsed_ms": 100},
            {"index": 4, "payload": "idor", "status_code": 200, "body_length": 5000, "elapsed_ms": 100},
        ]
        analysis = _analyze_results(results)
        length_anomalies = [a for a in analysis["anomalies"] if a["type"] == "body_length_deviation"]
        assert len(length_anomalies) >= 1
        assert any(a["payload"] == "idor" for a in length_anomalies)

    def test_stats_calculated(self):
        results = [
            {"index": 0, "payload": "a", "status_code": 200, "body_length": 100, "elapsed_ms": 50},
            {"index": 1, "payload": "b", "status_code": 200, "body_length": 200, "elapsed_ms": 150},
        ]
        analysis = _analyze_results(results)
        assert analysis["body_length_stats"]["min"] == 100
        assert analysis["body_length_stats"]["max"] == 200
        assert analysis["body_length_stats"]["avg"] == 150
        assert analysis["timing_stats"]["avg_ms"] == 100
        assert analysis["timing_stats"]["max_ms"] == 150
