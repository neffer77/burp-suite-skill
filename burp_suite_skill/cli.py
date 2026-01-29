"""
Burp Suite Automation CLI - Main entry point.

Provides a unified command-line interface for all Burp Suite
orchestration tools. Each subcommand maps to a specific tool
in the agent's toolset.

Usage:
    burp-cli <command> [options]

Commands:
    health          Check connectivity to Burp Suite extensions
    scope-get       Retrieve current target scope
    scope-set       Add/remove items from target scope
    scope-check     Check if a URL is in scope
    history         Search proxy history with filters
    history-item    Get a specific history item by ID
    repeater-send   Send/replay HTTP requests through Burp
    scan-trigger    Trigger active scanner on a URL
    scan-findings   Retrieve scanner findings
    collab-new      Generate Collaborator payload
    collab-poll     Poll for Collaborator interactions
    sitemap         Retrieve target site map
    diff            Compare two HTTP responses
    entropy         Calculate Shannon entropy of a string
    jwt-decode      Decode and analyze a JWT token
"""

import argparse
import sys

from burp_suite_skill.tools.collaborator import register_collaborator_commands
from burp_suite_skill.tools.diff import register_diff_commands
from burp_suite_skill.tools.health import register_health_commands
from burp_suite_skill.tools.history import register_history_commands
from burp_suite_skill.tools.repeater import register_repeater_commands
from burp_suite_skill.tools.scanner import register_scanner_commands
from burp_suite_skill.tools.scope import register_scope_commands
from burp_suite_skill.tools.sitemap import register_sitemap_commands
from burp_suite_skill.tools.utilities import register_utility_commands
from burp_suite_skill.utils.logging_setup import setup_logging


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="burp-cli",
        description="Burp Suite Professional Automation CLI for Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  burp-cli health                              Check connectivity\n"
            "  burp-cli scope-get                           View current scope\n"
            "  burp-cli scope-set --add https://target.com  Set scope\n"
            "  burp-cli history --host target.com            Search history\n"
            "  burp-cli repeater-send --url https://t.com/   Send request\n"
            "  burp-cli scan-trigger --url https://t.com/    Trigger scan\n"
            "  burp-cli jwt-decode eyJhbGci...               Decode JWT\n"
        ),
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-essential output (warnings/errors only)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available tool commands",
    )

    # Register all tool subcommands
    register_health_commands(subparsers)
    register_scope_commands(subparsers)
    register_history_commands(subparsers)
    register_repeater_commands(subparsers)
    register_scanner_commands(subparsers)
    register_collaborator_commands(subparsers)
    register_sitemap_commands(subparsers)
    register_diff_commands(subparsers)
    register_utility_commands(subparsers)

    return parser


def main() -> int:
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Set up logging
    setup_logging(
        level=args.log_level,
        quiet=args.quiet,
    )

    # Execute the chosen command
    if hasattr(args, "func"):
        return args.func(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
