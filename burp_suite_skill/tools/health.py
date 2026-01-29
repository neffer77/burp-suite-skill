"""
Health check tool for verifying connectivity to Burp Suite extensions.

Checks both Belch (REST) and PyBurp (gRPC) endpoints and reports
their status. Useful as a first step before any operations.
"""

import json
import sys

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError
from burp_suite_skill.clients.pyburp_client import PyBurpClient


def health_check(args) -> int:
    """Check connectivity to Belch and PyBurp."""
    results = {}

    # Check Belch
    belch = BelchClient()
    try:
        belch_status = belch.health_check()
        results["belch"] = {
            "status": "connected",
            "url": belch.base_url,
            "details": belch_status,
        }
    except BelchClientError as exc:
        results["belch"] = {
            "status": "error",
            "url": belch.base_url,
            "error": str(exc),
        }

    # Check PyBurp
    pyburp = PyBurpClient()
    try:
        pyburp_ok = pyburp.health_check()
        results["pyburp"] = {
            "status": "connected" if pyburp_ok else "error",
            "endpoint": f"{pyburp.host}:{pyburp.port}",
        }
    except Exception as exc:
        results["pyburp"] = {
            "status": "error",
            "endpoint": f"{pyburp.host}:{pyburp.port}",
            "error": str(exc),
        }
    finally:
        pyburp.close()

    all_ok = all(r["status"] == "connected" for r in results.values())
    results["overall"] = "all_connected" if all_ok else "degraded"

    print(json.dumps(results, indent=2))
    return 0 if all_ok else 1


def register_health_commands(subparsers) -> None:
    """Register health check subcommand."""
    parser = subparsers.add_parser(
        "health",
        help="Check connectivity to Burp Suite extensions",
    )
    parser.set_defaults(func=health_check)
