"""
Belch REST API client for Burp Suite.

Wraps all HTTP calls to the Belch extension's REST API, providing
high-level methods for scope management, proxy history search,
scanner control, collaborator integration, and sitemap retrieval.
"""

import logging
from typing import Any
from urllib.parse import urljoin

import requests

from burp_suite_skill.config import BELCH_API_KEY, BELCH_TIMEOUT, BELCH_URL

logger = logging.getLogger(__name__)


class BelchClientError(Exception):
    """Raised when a Belch API call fails."""


class BelchClient:
    """REST client for the Belch Burp Suite extension."""

    def __init__(
        self,
        base_url: str = BELCH_URL,
        api_key: str = BELCH_API_KEY,
        timeout: int = BELCH_TIMEOUT,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"
        self.session.headers["Accept"] = "application/json"

    def _url(self, path: str) -> str:
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def _request(self, method: str, path: str, **kwargs) -> Any:
        """Execute an HTTP request and return the parsed JSON response."""
        url = self._url(path)
        kwargs.setdefault("timeout", self.timeout)
        try:
            resp = self.session.request(method, url, **kwargs)
            resp.raise_for_status()
            if resp.content:
                return resp.json()
            return None
        except (requests.ConnectionError, ConnectionError) as exc:
            raise BelchClientError(
                f"Cannot connect to Belch at {self.base_url}. "
                "Ensure the Belch extension is running in Burp Suite."
            ) from exc
        except requests.HTTPError as exc:
            raise BelchClientError(
                f"Belch API error {resp.status_code}: {resp.text}"
            ) from exc
        except requests.Timeout as exc:
            raise BelchClientError(
                f"Belch API request timed out after {self.timeout}s"
            ) from exc

    # ── Scope Management ──────────────────────────────────────────────

    def get_scope(self) -> dict:
        """Retrieve the current target scope configuration."""
        logger.info("Fetching scope configuration")
        return self._request("GET", "/scope/config")

    def set_scope(self, include: list[str] | None = None, exclude: list[str] | None = None) -> dict:
        """
        Update target scope configuration.

        Args:
            include: List of URL prefixes to add to the include list.
            exclude: List of URL prefixes to add to the exclude list.
        """
        payload: dict[str, Any] = {}
        if include is not None:
            payload["include"] = include
        if exclude is not None:
            payload["exclude"] = exclude
        logger.info("Setting scope: include=%s, exclude=%s", include, exclude)
        return self._request("POST", "/scope/config", json=payload)

    def is_in_scope(self, url: str) -> bool:
        """Check if a given URL falls within the current target scope."""
        scope = self.get_scope()
        if not scope:
            return False
        include_list = scope.get("include", [])
        exclude_list = scope.get("exclude", [])
        # Check exclusions first
        for pattern in exclude_list:
            if url.startswith(pattern):
                return False
        # Then check inclusions
        for pattern in include_list:
            if url.startswith(pattern):
                return True
        return False

    # ── Proxy History ─────────────────────────────────────────────────

    def search_history(
        self,
        host: str | None = None,
        method: str | None = None,
        query: str | None = None,
        status_code: int | None = None,
        mime_type: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        Search proxy history with filters.

        Args:
            host: Filter by hostname.
            method: Filter by HTTP method (GET, POST, etc.).
            query: Full-text search keyword in request/response.
            status_code: Filter by response status code.
            mime_type: Filter by MIME type.
            limit: Maximum number of results to return.
        """
        params: dict[str, Any] = {}
        if host:
            params["host"] = host
        if method:
            params["method"] = method
        if query:
            params["query"] = query
        if status_code is not None:
            params["status_code"] = status_code
        if mime_type:
            params["mime_type"] = mime_type
        if limit is not None:
            params["limit"] = limit
        logger.info("Searching proxy history: %s", params)
        return self._request("GET", "/proxy/search", params=params) or []

    def get_history_item(self, item_id: int) -> dict:
        """Retrieve a specific proxy history item by ID."""
        logger.info("Fetching history item %d", item_id)
        return self._request("GET", f"/proxy/history/{item_id}")

    # ── Scanner ───────────────────────────────────────────────────────

    def trigger_scan(self, urls: list[str]) -> dict:
        """
        Trigger an active scan on one or more URLs.

        Args:
            urls: List of URLs to scan.
        """
        logger.info("Triggering scan on URLs: %s", urls)
        return self._request("POST", "/scanner/scan-url-list", json={"urls": urls})

    def get_scan_issues(
        self,
        severity: str | None = None,
        confidence: str | None = None,
        host: str | None = None,
    ) -> list[dict]:
        """
        Retrieve scanner issues (findings).

        Args:
            severity: Filter by severity (High, Medium, Low, Information).
            confidence: Filter by confidence (Certain, Firm, Tentative).
            host: Filter by hostname.
        """
        params: dict[str, Any] = {}
        if severity:
            params["severity"] = severity
        if confidence:
            params["confidence"] = confidence
        if host:
            params["host"] = host
        logger.info("Fetching scan issues: %s", params)
        return self._request("GET", "/scanner/issues", params=params) or []

    # ── Collaborator ──────────────────────────────────────────────────

    def generate_collaborator_payload(self) -> dict:
        """Generate a new Burp Collaborator payload for OAST testing."""
        logger.info("Generating Collaborator payload")
        return self._request("POST", "/collaborator/generate")

    def poll_collaborator(self, payload_id: str | None = None) -> list[dict]:
        """
        Poll for Collaborator interactions.

        Args:
            payload_id: Optional specific payload ID to check.
        """
        params: dict[str, Any] = {}
        if payload_id:
            params["payload_id"] = payload_id
        logger.info("Polling Collaborator interactions: %s", params)
        return self._request("GET", "/collaborator/poll", params=params) or []

    # ── Sitemap ───────────────────────────────────────────────────────

    def get_sitemap(
        self,
        host: str | None = None,
        prefix: str | None = None,
    ) -> list[dict]:
        """
        Retrieve the target site map.

        Args:
            host: Filter by hostname.
            prefix: Filter by URL prefix.
        """
        params: dict[str, Any] = {}
        if host:
            params["host"] = host
        if prefix:
            params["prefix"] = prefix
        logger.info("Fetching sitemap: %s", params)
        return self._request("GET", "/target/sitemap", params=params) or []

    # ── Health ────────────────────────────────────────────────────────

    def health_check(self) -> dict:
        """Check if Belch is running and responsive."""
        return self._request("GET", "/health")
