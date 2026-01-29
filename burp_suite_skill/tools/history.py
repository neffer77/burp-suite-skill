"""
Proxy history query tool: burp-history-query.

The primary observation mechanism for the agent. Searches Burp's
proxy history via Belch's SQLite-backed full-text search, returning
filtered and sanitized results.
"""

import json
import logging
import sys

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError
from burp_suite_skill.config import MAX_HISTORY_RESULTS, RESPONSE_TRUNCATE_LENGTH
from burp_suite_skill.utils.safety import is_binary_content, sanitize_output

logger = logging.getLogger(__name__)


def history_query(args) -> int:
    """Search proxy history with filters and return sanitized results."""
    client = BelchClient()
    limit = args.limit or MAX_HISTORY_RESULTS
    truncate_len = args.truncate or RESPONSE_TRUNCATE_LENGTH

    try:
        results = client.search_history(
            host=args.host,
            method=args.method,
            query=args.grep,
            status_code=args.status_code,
            mime_type=args.mime_type,
            limit=limit,
        )

        sanitized = []
        for item in results:
            entry = {
                "id": item.get("id"),
                "url": item.get("url"),
                "method": item.get("method"),
                "status": item.get("status"),
                "content_type": item.get("content_type", ""),
                "response_length": item.get("response_length"),
            }

            # Include request headers summary
            req_headers = item.get("request_headers")
            if req_headers:
                entry["request_headers"] = req_headers

            # Sanitize and truncate response preview
            response_body = item.get("response", "") or item.get("response_body", "")
            content_type = item.get("content_type", "")

            if response_body:
                if args.full:
                    entry["response_body"] = sanitize_output(
                        response_body, content_type, max_length=len(response_body)
                    )
                else:
                    entry["response_preview"] = sanitize_output(
                        response_body, content_type, max_length=truncate_len
                    )
            elif content_type and is_binary_content(content_type):
                entry["response_preview"] = f"[Binary content: {content_type}]"

            sanitized.append(entry)

        output = {
            "total_results": len(sanitized),
            "query_params": {
                "host": args.host,
                "method": args.method,
                "grep": args.grep,
                "status_code": args.status_code,
                "mime_type": args.mime_type,
                "limit": limit,
            },
            "results": sanitized,
        }
        print(json.dumps(output, indent=2))
        return 0

    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def history_item(args) -> int:
    """Retrieve a specific proxy history item by ID."""
    client = BelchClient()
    try:
        item = client.get_history_item(args.id)
        if item:
            # Sanitize the response body
            response_body = item.get("response", "") or item.get("response_body", "")
            content_type = item.get("content_type", "")
            if response_body:
                item["response_body"] = sanitize_output(
                    response_body, content_type,
                    max_length=RESPONSE_TRUNCATE_LENGTH if not args.full else len(response_body),
                )
        print(json.dumps(item, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def register_history_commands(subparsers) -> None:
    """Register history-related subcommands."""
    # burp-history-query
    query_parser = subparsers.add_parser(
        "history",
        help="Search proxy history with filters",
    )
    query_parser.add_argument("--host", help="Filter by hostname")
    query_parser.add_argument("--method", help="Filter by HTTP method (GET, POST, etc.)")
    query_parser.add_argument("--grep", help="Full-text search keyword in request/response")
    query_parser.add_argument("--status-code", type=int, dest="status_code", help="Filter by status code")
    query_parser.add_argument("--mime-type", dest="mime_type", help="Filter by MIME type")
    query_parser.add_argument("--limit", type=int, help=f"Max results (default {MAX_HISTORY_RESULTS})")
    query_parser.add_argument("--truncate", type=int, help=f"Response truncation length (default {RESPONSE_TRUNCATE_LENGTH})")
    query_parser.add_argument("--full", action="store_true", help="Include full response bodies (no truncation)")
    query_parser.set_defaults(func=history_query)

    # burp-history-item
    item_parser = subparsers.add_parser(
        "history-item",
        help="Retrieve a specific proxy history item by ID",
    )
    item_parser.add_argument("id", type=int, help="History item ID")
    item_parser.add_argument("--full", action="store_true", help="Include full response body")
    item_parser.set_defaults(func=history_item)
