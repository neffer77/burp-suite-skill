"""Tests for the Belch REST client."""

import json

import pytest
import responses

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError


BELCH_BASE = "http://localhost:7850"


class TestBelchClient:
    def setup_method(self):
        self.client = BelchClient(base_url=BELCH_BASE)

    @responses.activate
    def test_health_check(self):
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/health",
            json={"status": "ok"},
            status=200,
        )
        result = self.client.health_check()
        assert result["status"] == "ok"

    @responses.activate
    def test_get_scope(self):
        scope_data = {
            "include": ["https://target.com"],
            "exclude": ["https://target.com/admin"],
        }
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/scope/config",
            json=scope_data,
            status=200,
        )
        result = self.client.get_scope()
        assert result["include"] == ["https://target.com"]
        assert result["exclude"] == ["https://target.com/admin"]

    @responses.activate
    def test_set_scope(self):
        responses.add(
            responses.POST,
            f"{BELCH_BASE}/scope/config",
            json={"include": ["https://target.com"], "exclude": []},
            status=200,
        )
        result = self.client.set_scope(include=["https://target.com"])
        assert "include" in result

    @responses.activate
    def test_is_in_scope_true(self):
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/scope/config",
            json={"include": ["https://target.com"], "exclude": []},
            status=200,
        )
        assert self.client.is_in_scope("https://target.com/api/users") is True

    @responses.activate
    def test_is_in_scope_false(self):
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/scope/config",
            json={"include": ["https://target.com"], "exclude": []},
            status=200,
        )
        assert self.client.is_in_scope("https://other.com/api") is False

    @responses.activate
    def test_is_in_scope_excluded(self):
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/scope/config",
            json={
                "include": ["https://target.com"],
                "exclude": ["https://target.com/admin"],
            },
            status=200,
        )
        assert self.client.is_in_scope("https://target.com/admin/users") is False

    @responses.activate
    def test_search_history(self):
        history_data = [
            {
                "id": 1,
                "url": "https://target.com/api/users",
                "method": "GET",
                "status": 200,
                "response": "<html>...</html>",
            }
        ]
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/proxy/search",
            json=history_data,
            status=200,
        )
        results = self.client.search_history(host="target.com")
        assert len(results) == 1
        assert results[0]["url"] == "https://target.com/api/users"

    @responses.activate
    def test_search_history_with_filters(self):
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/proxy/search",
            json=[],
            status=200,
        )
        results = self.client.search_history(
            host="target.com",
            method="POST",
            query="password",
            limit=10,
        )
        assert results == []
        # Verify query params were sent
        assert "host=target.com" in responses.calls[0].request.url
        assert "method=POST" in responses.calls[0].request.url

    @responses.activate
    def test_trigger_scan(self):
        responses.add(
            responses.POST,
            f"{BELCH_BASE}/scanner/scan-url-list",
            json={"scan_id": "abc123"},
            status=200,
        )
        result = self.client.trigger_scan(urls=["https://target.com/login"])
        assert result["scan_id"] == "abc123"

    @responses.activate
    def test_get_scan_issues(self):
        issues = [
            {
                "name": "SQL Injection",
                "severity": "High",
                "url": "https://target.com/search",
            }
        ]
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/scanner/issues",
            json=issues,
            status=200,
        )
        result = self.client.get_scan_issues(severity="High")
        assert len(result) == 1
        assert result[0]["name"] == "SQL Injection"

    @responses.activate
    def test_generate_collaborator_payload(self):
        responses.add(
            responses.POST,
            f"{BELCH_BASE}/collaborator/generate",
            json={"payload": "abc123.burpcollaborator.net"},
            status=200,
        )
        result = self.client.generate_collaborator_payload()
        assert "burpcollaborator" in result["payload"]

    @responses.activate
    def test_poll_collaborator(self):
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/collaborator/poll",
            json=[{"type": "DNS", "timestamp": "2026-01-29T00:00:00Z"}],
            status=200,
        )
        result = self.client.poll_collaborator()
        assert len(result) == 1
        assert result[0]["type"] == "DNS"

    @responses.activate
    def test_get_sitemap(self):
        sitemap = [
            {"url": "https://target.com/", "method": "GET"},
            {"url": "https://target.com/api/users", "method": "GET"},
        ]
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/target/sitemap",
            json=sitemap,
            status=200,
        )
        result = self.client.get_sitemap(host="target.com")
        assert len(result) == 2

    @responses.activate
    def test_connection_error(self):
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/health",
            body=ConnectionError("Connection refused"),
        )
        with pytest.raises(BelchClientError, match="Cannot connect"):
            self.client.health_check()

    @responses.activate
    def test_http_error(self):
        responses.add(
            responses.GET,
            f"{BELCH_BASE}/scope/config",
            json={"error": "Internal Server Error"},
            status=500,
        )
        with pytest.raises(BelchClientError, match="500"):
            self.client.get_scope()
