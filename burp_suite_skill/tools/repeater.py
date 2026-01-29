"""
Repeater send tool: burp-repeater-send.

The primary action mechanism for the agent. Sends HTTP requests
through Burp Suite with optional modifications, enforcing scope
and rate limiting.
"""

import json
import logging
import sys
import time
from urllib.parse import urlparse

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError
from burp_suite_skill.clients.pyburp_client import PyBurpClient, PyBurpClientError
from burp_suite_skill.config import RESPONSE_TRUNCATE_LENGTH
from burp_suite_skill.utils.safety import (
    CircuitBreakerOpen,
    RateLimitExceeded,
    ScopeViolation,
    circuit_breaker,
    enforce_scope,
    rate_limiter,
    sanitize_output,
)

logger = logging.getLogger(__name__)


def _apply_modifications(request_data: dict, args) -> dict:
    """
    Apply user-specified modifications to a request.

    Supports header overrides, parameter changes, and body replacement.
    """
    modified = dict(request_data)

    # Apply header modifications
    if args.header:
        headers = modified.get("headers", {})
        if isinstance(headers, str):
            # Parse raw headers string into dict
            parsed = {}
            for line in headers.split("\r\n"):
                if ": " in line:
                    key, val = line.split(": ", 1)
                    parsed[key] = val
            headers = parsed

        for h in args.header:
            if ":" in h:
                key, val = h.split(":", 1)
                headers[key.strip()] = val.strip()
        modified["headers"] = headers

    # Apply parameter modifications (URL query or body form params)
    if args.param:
        url = modified.get("url", "")
        body = modified.get("body", "")
        content_type = ""
        headers = modified.get("headers", {})
        if isinstance(headers, dict):
            content_type = headers.get("Content-Type", headers.get("content-type", ""))

        for p in args.param:
            if "=" not in p:
                continue
            key, val = p.split("=", 1)

            # Try modifying in URL query string
            if f"{key}=" in url:
                import re
                url = re.sub(
                    rf"({re.escape(key)}=)[^&]*",
                    rf"\g<1>{val}",
                    url,
                )
                modified["url"] = url
            # Try modifying in body (JSON)
            elif body and "json" in content_type.lower():
                try:
                    body_json = json.loads(body)
                    if key in body_json:
                        body_json[key] = val
                        modified["body"] = json.dumps(body_json)
                except (json.JSONDecodeError, TypeError):
                    pass
            # Try modifying in body (form-encoded)
            elif body and f"{key}=" in body:
                import re
                modified["body"] = re.sub(
                    rf"({re.escape(key)}=)[^&]*",
                    rf"\g<1>{val}",
                    body,
                )

    # Replace entire body if specified
    if args.body:
        modified["body"] = args.body

    # Override method if specified
    if args.method:
        modified["method"] = args.method

    return modified


def repeater_send(args) -> int:
    """Send an HTTP request through Burp with optional modifications."""
    belch = BelchClient()
    pyburp = PyBurpClient()

    try:
        # Step 1: Get the base request
        if args.base_req_id:
            # Replay a request from proxy history with modifications
            logger.info("Loading base request from history ID %d", args.base_req_id)
            try:
                base_request = belch.get_history_item(args.base_req_id)
                if not base_request:
                    print(json.dumps({
                        "error": f"History item {args.base_req_id} not found"
                    }), file=sys.stderr)
                    return 1
            except BelchClientError as exc:
                print(json.dumps({"error": str(exc)}), file=sys.stderr)
                return 1
        elif args.url:
            # Build a fresh request from provided parameters
            base_request = {
                "method": args.method or "GET",
                "url": args.url,
                "headers": {},
                "body": "",
            }
        else:
            print(json.dumps({
                "error": "Must specify either --base-req-id or --url"
            }), file=sys.stderr)
            return 1

        # Step 2: Apply modifications
        modified_request = _apply_modifications(base_request, args)

        # Step 3: Scope check
        target_url = modified_request.get("url", "")
        try:
            scope_config = belch.get_scope()
            enforce_scope(target_url, scope_config)
        except ScopeViolation as exc:
            print(json.dumps({
                "error": f"SCOPE VIOLATION: {exc}",
                "blocked": True,
                "url": target_url,
            }), file=sys.stderr)
            return 1
        except BelchClientError:
            # If we can't check scope, refuse to proceed
            print(json.dumps({
                "error": "Cannot verify scope (Belch unreachable). Refusing to send request.",
                "blocked": True,
            }), file=sys.stderr)
            return 1

        # Step 4: Rate limit and circuit breaker checks
        try:
            circuit_breaker.check()
            rate_limiter.acquire()
        except (CircuitBreakerOpen, RateLimitExceeded) as exc:
            print(json.dumps({
                "error": f"SAFETY LIMIT: {exc}",
                "blocked": True,
            }), file=sys.stderr)
            return 1

        # Step 5: Send the request
        start_time = time.time()
        try:
            response = pyburp.send_request(
                method=modified_request.get("method", "GET"),
                url=target_url,
                headers=modified_request.get("headers"),
                body=modified_request.get("body"),
            )
            elapsed_ms = int((time.time() - start_time) * 1000)
            circuit_breaker.record_success()
        except PyBurpClientError as exc:
            elapsed_ms = int((time.time() - start_time) * 1000)
            circuit_breaker.record_error()
            print(json.dumps({
                "error": f"Request failed: {exc}",
                "elapsed_ms": elapsed_ms,
            }), file=sys.stderr)
            return 1

        # Step 6: Format and sanitize output
        status_code = response.get("status_code", 0)
        response_headers = response.get("headers", {})
        response_body = response.get("body", "")
        content_type = ""
        if isinstance(response_headers, dict):
            content_type = response_headers.get(
                "Content-Type", response_headers.get("content-type", "")
            )

        # Record error responses for circuit breaker
        if status_code >= 500:
            circuit_breaker.record_error()

        truncate_len = RESPONSE_TRUNCATE_LENGTH
        if args.full:
            truncate_len = len(response_body) if response_body else 0

        output = {
            "status_code": status_code,
            "elapsed_ms": elapsed_ms,
            "response_headers": response_headers,
            "response_body": sanitize_output(
                response_body, content_type, max_length=truncate_len
            ) if response_body else "",
            "response_length": len(response_body) if response_body else 0,
            "request": {
                "method": modified_request.get("method"),
                "url": target_url,
            },
        }
        print(json.dumps(output, indent=2))
        return 0

    except Exception as exc:
        print(json.dumps({"error": f"Unexpected error: {exc}"}), file=sys.stderr)
        return 1
    finally:
        pyburp.close()


def register_repeater_commands(subparsers) -> None:
    """Register repeater-related subcommands."""
    parser = subparsers.add_parser(
        "repeater-send",
        help="Send an HTTP request through Burp (Repeater-style)",
    )
    # Request source (one of these is required)
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--base-req-id",
        type=int,
        dest="base_req_id",
        help="History item ID to replay with modifications",
    )
    source_group.add_argument(
        "--url",
        help="Target URL for a fresh request",
    )

    # Modifications
    parser.add_argument(
        "--method",
        help="Override HTTP method (GET, POST, PUT, DELETE, etc.)",
    )
    parser.add_argument(
        "--header",
        action="append",
        metavar="NAME:VALUE",
        help="Set/override a header (repeatable). Format: 'Name: Value'",
    )
    parser.add_argument(
        "--param",
        action="append",
        metavar="KEY=VALUE",
        help="Set/override a parameter in URL or body (repeatable)",
    )
    parser.add_argument(
        "--body",
        help="Replace the entire request body",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Include full response body (no truncation)",
    )
    parser.set_defaults(func=repeater_send)
