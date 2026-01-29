"""
Scope management tools: burp-scope-get and burp-scope-set.

These tools provide the foundational safety mechanism for all
agent operations by controlling the target scope in Burp Suite.
"""

import json
import logging
import sys

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError

logger = logging.getLogger(__name__)


def scope_get(args) -> int:
    """Retrieve and display the current target scope configuration."""
    client = BelchClient()
    try:
        scope = client.get_scope()
        print(json.dumps(scope, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def scope_set(args) -> int:
    """Add or remove items from the target scope."""
    client = BelchClient()
    include = args.add or []
    exclude = args.exclude or []

    if not include and not exclude:
        print(
            json.dumps({"error": "Must specify at least one --add or --exclude entry"}),
            file=sys.stderr,
        )
        return 1

    try:
        result = client.set_scope(
            include=include if include else None,
            exclude=exclude if exclude else None,
        )
        print(json.dumps({
            "status": "scope_updated",
            "include_added": include,
            "exclude_added": exclude,
            "current_scope": result,
        }, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def scope_check(args) -> int:
    """Check if a specific URL is within the current scope."""
    client = BelchClient()
    url = args.url

    try:
        in_scope = client.is_in_scope(url)
        print(json.dumps({
            "url": url,
            "in_scope": in_scope,
        }, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def register_scope_commands(subparsers) -> None:
    """Register scope-related subcommands with the argument parser."""
    # burp-scope-get
    get_parser = subparsers.add_parser(
        "scope-get",
        help="Retrieve current target scope configuration",
    )
    get_parser.set_defaults(func=scope_get)

    # burp-scope-set
    set_parser = subparsers.add_parser(
        "scope-set",
        help="Add or remove items from target scope",
    )
    set_parser.add_argument(
        "--add",
        action="append",
        metavar="URL_PREFIX",
        help="URL prefix to add to the include list (repeatable)",
    )
    set_parser.add_argument(
        "--exclude",
        action="append",
        metavar="URL_PREFIX",
        help="URL prefix to add to the exclude list (repeatable)",
    )
    set_parser.set_defaults(func=scope_set)

    # burp-scope-check
    check_parser = subparsers.add_parser(
        "scope-check",
        help="Check if a URL is within the current scope",
    )
    check_parser.add_argument(
        "url",
        help="URL to check against the scope",
    )
    check_parser.set_defaults(func=scope_check)
