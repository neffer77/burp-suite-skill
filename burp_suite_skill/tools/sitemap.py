"""
Sitemap fetch tool: burp-sitemap-fetch.

Retrieves the target site map (list of discovered URLs/endpoints)
from Burp Suite, providing the agent with a comprehensive view
of the application's attack surface.
"""

import json
import logging
import sys

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError

logger = logging.getLogger(__name__)


def sitemap_fetch(args) -> int:
    """Retrieve and display the target site map."""
    client = BelchClient()
    try:
        sitemap = client.get_sitemap(
            host=args.host,
            prefix=args.prefix,
        )

        # Organize results by host and path for readability
        organized: dict[str, list] = {}
        for entry in sitemap:
            url = entry.get("url", "")
            host = entry.get("host", "unknown")
            if host not in organized:
                organized[host] = []
            organized[host].append({
                "url": url,
                "method": entry.get("method", ""),
                "status": entry.get("status"),
                "content_type": entry.get("content_type", ""),
                "has_params": entry.get("has_params", False),
            })

        output = {
            "total_entries": len(sitemap),
            "hosts": list(organized.keys()),
            "sitemap": organized,
        }
        print(json.dumps(output, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def register_sitemap_commands(subparsers) -> None:
    """Register sitemap-related subcommands."""
    parser = subparsers.add_parser(
        "sitemap",
        help="Retrieve the target site map",
    )
    parser.add_argument("--host", help="Filter by hostname")
    parser.add_argument("--prefix", help="Filter by URL prefix")
    parser.set_defaults(func=sitemap_fetch)
