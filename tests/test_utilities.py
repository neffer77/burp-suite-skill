"""Tests for utility tools: entropy calculation and JWT decoding."""

import json
import subprocess
import sys
from unittest.mock import patch

import pytest


class TestEntropy:
    def _run_entropy(self, text: str) -> dict:
        """Run the entropy command and parse output."""
        from burp_suite_skill.tools.utilities import entropy_calc

        class Args:
            pass

        args = Args()
        args.text = text

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            code = entropy_calc(args)

        output = f.getvalue()
        return json.loads(output) if code == 0 else {"error": output}

    def test_low_entropy_string(self):
        result = self._run_entropy("aaaaaaa")
        assert result["assessment"].startswith("LOW")
        assert result["shannon_entropy"] < 2.0

    def test_high_entropy_string(self):
        result = self._run_entropy("aB3$xZ9!mK7&pQ2@")
        assert result["shannon_entropy"] > 3.0

    def test_single_char(self):
        result = self._run_entropy("a")
        assert result["shannon_entropy"] == 0.0

    def test_uniform_distribution(self):
        # All unique chars should have high efficiency
        result = self._run_entropy("abcdefghijklmnop")
        assert result["efficiency"] > 0.9


class TestJWTDecode:
    def _run_jwt(self, token: str) -> dict:
        """Run the JWT decode command and parse output."""
        from burp_suite_skill.tools.utilities import jwt_decode

        class Args:
            pass

        args = Args()
        args.token = token

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            code = jwt_decode(args)

        output = f.getvalue()
        return json.loads(output) if code == 0 else {"error": output, "code": code}

    def test_valid_jwt(self):
        # Header: {"alg":"HS256","typ":"JWT"}
        # Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        result = self._run_jwt(token)
        assert result["algorithm"] == "HS256"
        assert result["header"]["alg"] == "HS256"
        assert result["payload"]["sub"] == "1234567890"
        assert result["signature_present"] is True

    def test_none_algorithm_warning(self):
        # Header: {"alg":"none","typ":"JWT"}
        # Payload: {"sub":"admin"}
        import base64
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"admin"}').rstrip(b"=").decode()
        token = f"{header}.{payload}."
        result = self._run_jwt(token)
        assert result["algorithm"] == "none"
        assert "CRITICAL" in result.get("warning", "")

    def test_invalid_jwt_format(self):
        result = self._run_jwt("not-a-jwt")
        assert "error" in result or result.get("code") == 1

    def test_jwt_with_admin_claim(self):
        import base64
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            b'{"sub":"user123","admin":true,"role":"user"}'
        ).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b'fake_signature_here').rstrip(b"=").decode()
        token = f"{header}.{payload}.{sig}"
        result = self._run_jwt(token)
        assert result["payload"]["admin"] is True
        # Should have testing hints about admin and role claims
        hints = result.get("analysis", {}).get("testing_hints", [])
        assert any("admin" in h for h in hints)
        assert any("role" in h for h in hints)
