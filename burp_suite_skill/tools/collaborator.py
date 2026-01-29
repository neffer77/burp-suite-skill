"""
Collaborator tools: burp-collab-new and burp-collab-poll.

Manages Burp Collaborator payloads for Out-of-Band Application
Security Testing (OAST). Used to detect blind vulnerabilities
like Blind XSS, SSRF, and blind command injection.
"""

import json
import logging
import sys

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError

logger = logging.getLogger(__name__)


def collab_new(args) -> int:
    """Generate a new Burp Collaborator payload for OAST testing."""
    client = BelchClient()
    try:
        result = client.generate_collaborator_payload()
        print(json.dumps({
            "status": "payload_generated",
            "payload": result,
            "usage_hint": (
                "Inject this payload into parameters to test for blind "
                "vulnerabilities (SSRF, blind XSS, etc.). "
                "Use 'collab-poll' to check for interactions."
            ),
        }, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def collab_poll(args) -> int:
    """Poll for Collaborator interactions (DNS/HTTP callbacks)."""
    client = BelchClient()
    try:
        interactions = client.poll_collaborator(
            payload_id=args.payload_id,
        )

        output = {
            "payload_id": args.payload_id,
            "total_interactions": len(interactions),
            "interactions": interactions,
        }

        if interactions:
            output["verdict"] = (
                "INTERACTIONS DETECTED - This indicates the payload was triggered. "
                "The target is likely vulnerable to the tested blind vulnerability."
            )
        else:
            output["verdict"] = (
                "No interactions detected. The payload may not have been triggered, "
                "or more time may be needed. Consider re-polling later."
            )

        print(json.dumps(output, indent=2))
        return 0
    except BelchClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def register_collaborator_commands(subparsers) -> None:
    """Register collaborator-related subcommands."""
    # burp-collab-new
    new_parser = subparsers.add_parser(
        "collab-new",
        help="Generate a new Burp Collaborator payload for OAST testing",
    )
    new_parser.set_defaults(func=collab_new)

    # burp-collab-poll
    poll_parser = subparsers.add_parser(
        "collab-poll",
        help="Poll for Collaborator interactions",
    )
    poll_parser.add_argument(
        "--payload-id",
        dest="payload_id",
        help="Specific payload ID to check (optional)",
    )
    poll_parser.set_defaults(func=collab_poll)
