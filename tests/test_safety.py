"""Tests for safety mechanisms: circuit breaker, rate limiter, scope enforcement, redaction."""

import time

import pytest

from burp_suite_skill.utils.safety import (
    CircuitBreaker,
    CircuitBreakerOpen,
    RateLimiter,
    RateLimitExceeded,
    ScopeViolation,
    enforce_scope,
    is_binary_content,
    redact_sensitive_data,
    sanitize_output,
    truncate_response,
)


class TestCircuitBreaker:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker(threshold=3, window_seconds=60)
        # Should not raise
        cb.check()

    def test_trips_after_threshold_errors(self):
        cb = CircuitBreaker(threshold=3, window_seconds=60)
        cb.record_error()
        cb.record_error()
        with pytest.raises(CircuitBreakerOpen):
            cb.record_error()

    def test_success_resets_errors(self):
        cb = CircuitBreaker(threshold=3, window_seconds=60)
        cb.record_error()
        cb.record_error()
        cb.record_success()
        # Should not raise now
        cb.record_error()
        cb.record_error()

    def test_manual_reset(self):
        cb = CircuitBreaker(threshold=2, window_seconds=60)
        cb.record_error()
        with pytest.raises(CircuitBreakerOpen):
            cb.record_error()
        cb.reset()
        # Should be fine now
        cb.check()

    def test_check_raises_when_open(self):
        cb = CircuitBreaker(threshold=2, window_seconds=60)
        cb.record_error()
        with pytest.raises(CircuitBreakerOpen):
            cb.record_error()
        with pytest.raises(CircuitBreakerOpen):
            cb.check()

    def test_auto_reset_after_window(self):
        cb = CircuitBreaker(threshold=2, window_seconds=1)
        cb.record_error()
        with pytest.raises(CircuitBreakerOpen):
            cb.record_error()
        # Wait for the window to pass
        time.sleep(1.1)
        # Should auto-reset
        cb.check()


class TestRateLimiter:
    def test_allows_within_limit(self):
        rl = RateLimiter(max_per_minute=10)
        # Should not raise for a few requests
        for _ in range(5):
            rl.acquire()

    def test_raises_when_wait_too_long(self):
        rl = RateLimiter(max_per_minute=1)
        rl.acquire()
        with pytest.raises(RateLimitExceeded):
            rl.acquire()


class TestScopeEnforcement:
    def test_in_scope_url(self):
        scope = {"include": ["https://target.com"], "exclude": []}
        # Should not raise
        enforce_scope("https://target.com/api/users", scope)

    def test_out_of_scope_url(self):
        scope = {"include": ["https://target.com"], "exclude": []}
        with pytest.raises(ScopeViolation):
            enforce_scope("https://other.com/api", scope)

    def test_excluded_url(self):
        scope = {
            "include": ["https://target.com"],
            "exclude": ["https://target.com/admin"],
        }
        with pytest.raises(ScopeViolation):
            enforce_scope("https://target.com/admin/delete", scope)

    def test_empty_scope_raises(self):
        scope = {"include": [], "exclude": []}
        with pytest.raises(ScopeViolation):
            enforce_scope("https://target.com/api", scope)

    def test_missing_include_raises(self):
        scope = {}
        with pytest.raises(ScopeViolation):
            enforce_scope("https://target.com/api", scope)


class TestTruncation:
    def test_short_text_unchanged(self):
        assert truncate_response("hello", 100) == "hello"

    def test_long_text_truncated(self):
        text = "a" * 1000
        result = truncate_response(text, 100)
        assert len(result) < 1000
        assert "TRUNCATED" in result
        assert "1000 total chars" in result

    def test_exact_length_unchanged(self):
        text = "a" * 100
        assert truncate_response(text, 100) == text


class TestBinaryDetection:
    def test_image_is_binary(self):
        assert is_binary_content("image/png") is True
        assert is_binary_content("image/jpeg") is True

    def test_pdf_is_binary(self):
        assert is_binary_content("application/pdf") is True

    def test_json_is_not_binary(self):
        assert is_binary_content("application/json") is False

    def test_html_is_not_binary(self):
        assert is_binary_content("text/html") is False

    def test_empty_is_not_binary(self):
        assert is_binary_content("") is False


class TestRedaction:
    def test_redacts_password_in_json(self):
        text = '{"username": "admin", "password": "secret123"}'
        result = redact_sensitive_data(text)
        assert "secret123" not in result
        assert "[REDACTED]" in result

    def test_redacts_password_in_form(self):
        text = "username=admin&password=secret123"
        result = redact_sensitive_data(text)
        assert "secret123" not in result
        assert "[REDACTED]" in result

    def test_redacts_credit_card(self):
        text = "Card: 4111 1111 1111 1111"
        result = redact_sensitive_data(text)
        assert "4111 1111 1111 1111" not in result
        assert "REDACTED-CC" in result

    def test_redacts_ssn(self):
        text = "SSN: 123-45-6789"
        result = redact_sensitive_data(text)
        assert "123-45-6789" not in result
        assert "REDACTED-SSN" in result

    def test_preserves_non_sensitive_text(self):
        text = "This is a normal response with no sensitive data."
        result = redact_sensitive_data(text)
        assert result == text


class TestSanitizeOutput:
    def test_binary_content_returns_placeholder(self):
        result = sanitize_output("binary data", content_type="image/png")
        assert "[Binary content: image/png]" == result

    def test_truncates_and_redacts(self):
        text = '{"password": "mysecret"}' + "x" * 5000
        result = sanitize_output(text, max_length=100)
        assert "mysecret" not in result
        assert len(result) < 5000
