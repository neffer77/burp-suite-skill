"""Tests for the CLI entry point and argument parsing."""

import pytest

from burp_suite_skill.cli import build_parser


class TestCLIParser:
    def setup_method(self):
        self.parser = build_parser()

    def test_no_command_shows_help(self):
        args = self.parser.parse_args([])
        assert args.command is None

    def test_health_command(self):
        args = self.parser.parse_args(["health"])
        assert args.command == "health"

    def test_scope_get_command(self):
        args = self.parser.parse_args(["scope-get"])
        assert args.command == "scope-get"

    def test_scope_set_command(self):
        args = self.parser.parse_args(["scope-set", "--add", "https://target.com"])
        assert args.command == "scope-set"
        assert args.add == ["https://target.com"]

    def test_scope_set_multiple(self):
        args = self.parser.parse_args([
            "scope-set",
            "--add", "https://target.com",
            "--add", "https://api.target.com",
            "--exclude", "https://target.com/admin",
        ])
        assert len(args.add) == 2
        assert len(args.exclude) == 1

    def test_scope_check_command(self):
        args = self.parser.parse_args(["scope-check", "https://target.com/api"])
        assert args.command == "scope-check"
        assert args.url == "https://target.com/api"

    def test_history_command(self):
        args = self.parser.parse_args(["history", "--host", "target.com", "--method", "POST"])
        assert args.command == "history"
        assert args.host == "target.com"
        assert args.method == "POST"

    def test_history_with_grep(self):
        args = self.parser.parse_args(["history", "--grep", "password"])
        assert args.grep == "password"

    def test_history_item_command(self):
        args = self.parser.parse_args(["history-item", "42"])
        assert args.command == "history-item"
        assert args.id == 42

    def test_repeater_send_with_url(self):
        args = self.parser.parse_args([
            "repeater-send",
            "--url", "https://target.com/api",
            "--method", "POST",
            "--header", "Content-Type: application/json",
            "--param", "id=123",
        ])
        assert args.command == "repeater-send"
        assert args.url == "https://target.com/api"
        assert args.method == "POST"
        assert args.header == ["Content-Type: application/json"]
        assert args.param == ["id=123"]

    def test_repeater_send_with_base_id(self):
        args = self.parser.parse_args([
            "repeater-send",
            "--base-req-id", "42",
            "--param", "user_id=101",
        ])
        assert args.base_req_id == 42
        assert args.param == ["user_id=101"]

    def test_scan_trigger_command(self):
        args = self.parser.parse_args(["scan-trigger", "--url", "https://target.com/login"])
        assert args.command == "scan-trigger"
        assert args.url == "https://target.com/login"

    def test_scan_trigger_with_force(self):
        args = self.parser.parse_args(["scan-trigger", "--url", "https://target.com/delete", "--force"])
        assert args.force is True

    def test_scan_findings_command(self):
        args = self.parser.parse_args(["scan-findings", "--severity", "High"])
        assert args.command == "scan-findings"
        assert args.severity == "High"

    def test_collab_new_command(self):
        args = self.parser.parse_args(["collab-new"])
        assert args.command == "collab-new"

    def test_collab_poll_command(self):
        args = self.parser.parse_args(["collab-poll", "--payload-id", "abc123"])
        assert args.command == "collab-poll"
        assert args.payload_id == "abc123"

    def test_sitemap_command(self):
        args = self.parser.parse_args(["sitemap", "--host", "target.com"])
        assert args.command == "sitemap"
        assert args.host == "target.com"

    def test_diff_command(self):
        args = self.parser.parse_args(["diff", "resp_a.json", "resp_b.json"])
        assert args.command == "diff"
        assert args.response_a == "resp_a.json"
        assert args.response_b == "resp_b.json"

    def test_entropy_command(self):
        args = self.parser.parse_args(["entropy", "abc123def456"])
        assert args.command == "entropy"
        assert args.text == "abc123def456"

    def test_jwt_decode_command(self):
        args = self.parser.parse_args(["jwt-decode", "eyJhbGciOi..."])
        assert args.command == "jwt-decode"
        assert args.token == "eyJhbGciOi..."

    def test_quiet_flag(self):
        args = self.parser.parse_args(["--quiet", "health"])
        assert args.quiet is True

    def test_log_level_flag(self):
        args = self.parser.parse_args(["--log-level", "DEBUG", "health"])
        assert args.log_level == "DEBUG"
