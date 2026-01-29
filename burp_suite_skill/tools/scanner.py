"""
Scanner tools: burp-scan-trigger and burp-scan-findings.

Controls Burp Suite's active scanner. Use sparingly -
active scanning is noisy and can be disruptive.
"""

import json
import logging
import sys
from urllib.parse import urlparse

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError
from burp_suite_skill.utils.safety import ScopeViolation, enforce_scope

logger = logging.getLogger(__name__)

# URL patterns that suggest destructive operations
_DESTRUCTIVE_PATTERNS = [
    "/delete", "/remove", "/destroy", "/drop",
    "/admin/", "/reset", "/purge", "/wipe",
]


def scan_trigger(args) -> int:
    """Trigger Burp's active scanner on a given URL."""
    client = BelchClient()
    url = args.url

    # Safety: scope check
    try:
        scope_config = client.get_scope()
        enforce_scope(url, scope_config)
    except ScopeViolation as exc:
        print(json.dumps({
            "error": f"SCOPE VIOLATION: {exc}",
            "blocked": True,
        }), file=sys.stderr)
        return 1
    except BelchClientError:
        print(json.dumps({
            "error": "Cannot verify scope. Refusing to scan.",
            "blocked": True,
        }), file=sys.stderr)
        return 1

    # Safety: check for potentially destructive URLs
    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    if any(pattern in path_lower for pattern in _DESTRUCTIVE_PATTERNS):
        if not args.force:
            print(json.dumps({
                "warning": f"URL path '{parsed.path}' may involve destructive operations. "
                           "Use --force to override this safety check.",
                "blocked": True,
                "url": url,
            }), file=sys.stderr)
            return 1
        logger.warning("Force-scanning potentially destructive URL: %s", url)

    try:
        result = client.trigger_scan(urls=[url])
        print(json.dumps({
            "status": "scan_initiated",
            "url": url,
            "scan_info": result,
            "note": "Scan is running asynchronously. Use 'scan-findings' to check results.",
        }, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def scan_findings(args) -> int:
    """Retrieve scanner issues (vulnerability findings)."""
    client = BelchClient()
    try:
        issues = client.get_scan_issues(
            severity=args.severity,
            confidence=args.confidence,
            host=args.host,
        )

        # Format output
        formatted = []
        for issue in issues:
            entry = {
                "name": issue.get("name"),
                "severity": issue.get("severity"),
                "confidence": issue.get("confidence"),
                "url": issue.get("url"),
                "description": issue.get("description", "")[:500],
                "remediation": issue.get("remediation", "")[:300],
            }
            formatted.append(entry)

        output = {
            "total_issues": len(formatted),
            "filters": {
                "severity": args.severity,
                "confidence": args.confidence,
                "host": args.host,
            },
            "issues": formatted,
        }
        print(json.dumps(output, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def register_scanner_commands(subparsers) -> None:
    """Register scanner-related subcommands."""
    # burp-scan-trigger
    trigger_parser = subparsers.add_parser(
        "scan-trigger",
        help="Trigger active scan on a URL (use sparingly)",
    )
    trigger_parser.add_argument("--url", required=True, help="URL to scan")
    trigger_parser.add_argument(
        "--force",
        action="store_true",
        help="Force scan even on potentially destructive URLs",
    )
    trigger_parser.set_defaults(func=scan_trigger)

    # burp-scan-findings
    findings_parser = subparsers.add_parser(
        "scan-findings",
        help="Retrieve scanner findings (vulnerabilities)",
    )
    findings_parser.add_argument(
        "--severity",
        choices=["High", "Medium", "Low", "Information"],
        help="Filter by severity level",
    )
    findings_parser.add_argument(
        "--confidence",
        choices=["Certain", "Firm", "Tentative"],
        help="Filter by confidence level",
    )
    findings_parser.add_argument("--host", help="Filter by hostname")
    findings_parser.set_defaults(func=scan_findings)
