"""
Safety mechanisms including circuit breaker, rate limiting,
scope enforcement, and output redaction.
"""

import logging
import re
import time
from collections import deque
from typing import Any

from burp_suite_skill.config import (
    CIRCUIT_BREAKER_THRESHOLD,
    CIRCUIT_BREAKER_WINDOW,
    MAX_REQUESTS_PER_MINUTE,
    RESPONSE_TRUNCATE_LENGTH,
)

logger = logging.getLogger(__name__)


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open (too many errors)."""


class ScopeViolation(Exception):
    """Raised when an action targets an out-of-scope URL."""


class RateLimitExceeded(Exception):
    """Raised when the rate limit has been exceeded."""


class CircuitBreaker:
    """
    Circuit breaker pattern implementation for protecting against
    runaway error loops. Trips open after consecutive errors exceed
    the threshold within the time window.
    """

    def __init__(
        self,
        threshold: int = CIRCUIT_BREAKER_THRESHOLD,
        window_seconds: int = CIRCUIT_BREAKER_WINDOW,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._errors: deque[float] = deque()
        self._is_open = False

    def record_success(self) -> None:
        """Record a successful operation, resetting the error window."""
        self._errors.clear()
        self._is_open = False

    def record_error(self) -> None:
        """Record an error and potentially trip the circuit breaker."""
        now = time.time()
        self._errors.append(now)
        self._prune_old_errors(now)
        if len(self._errors) >= self.threshold:
            self._is_open = True
            logger.warning(
                "Circuit breaker OPEN: %d errors in %ds window",
                len(self._errors),
                self.window_seconds,
            )
            raise CircuitBreakerOpen(
                f"Circuit breaker tripped: {len(self._errors)} consecutive errors "
                f"within {self.window_seconds}s. Halting to prevent harm. "
                "Reset or investigate before continuing."
            )

    def check(self) -> None:
        """Check if the circuit breaker is open. Raises if so."""
        if self._is_open:
            now = time.time()
            self._prune_old_errors(now)
            if len(self._errors) >= self.threshold:
                raise CircuitBreakerOpen(
                    "Circuit breaker is OPEN. Too many recent errors. "
                    "Wait or reset before retrying."
                )
            # Window has passed; auto-reset
            self._is_open = False
            logger.info("Circuit breaker auto-reset after window elapsed")

    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        self._errors.clear()
        self._is_open = False
        logger.info("Circuit breaker manually reset")

    def _prune_old_errors(self, now: float) -> None:
        """Remove errors older than the time window."""
        cutoff = now - self.window_seconds
        while self._errors and self._errors[0] < cutoff:
            self._errors.popleft()


class RateLimiter:
    """
    Token-bucket-style rate limiter to prevent flooding targets.
    """

    def __init__(self, max_per_minute: int = MAX_REQUESTS_PER_MINUTE):
        self.max_per_minute = max_per_minute
        self._timestamps: deque[float] = deque()

    def acquire(self) -> None:
        """
        Acquire permission to send a request.
        Blocks (sleeps) if the rate limit would be exceeded.
        Raises RateLimitExceeded if wait would be too long.
        """
        now = time.time()
        self._prune(now)

        if len(self._timestamps) >= self.max_per_minute:
            oldest = self._timestamps[0]
            wait_time = 60.0 - (now - oldest)
            if wait_time > 30:
                raise RateLimitExceeded(
                    f"Rate limit exceeded ({self.max_per_minute}/min). "
                    f"Would need to wait {wait_time:.1f}s."
                )
            if wait_time > 0:
                logger.info("Rate limiting: sleeping %.1fs", wait_time)
                time.sleep(wait_time)
                now = time.time()
                self._prune(now)

        self._timestamps.append(now)

    def _prune(self, now: float) -> None:
        cutoff = now - 60.0
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


def enforce_scope(url: str, scope_config: dict) -> None:
    """
    Verify that a URL is within the allowed scope.
    Raises ScopeViolation if not.

    Args:
        url: The URL to check.
        scope_config: Dict with 'include' and 'exclude' lists.
    """
    include_list = scope_config.get("include", [])
    exclude_list = scope_config.get("exclude", [])

    if not include_list:
        raise ScopeViolation(
            "No scope is configured. Set the target scope before sending requests."
        )

    # Check exclusions first
    for pattern in exclude_list:
        if url.startswith(pattern):
            raise ScopeViolation(
                f"URL {url} matches exclusion pattern '{pattern}'. Request blocked."
            )

    # Check inclusions
    for pattern in include_list:
        if url.startswith(pattern):
            return  # In scope

    raise ScopeViolation(
        f"URL {url} is NOT in scope. Allowed patterns: {include_list}"
    )


def truncate_response(text: str, max_length: int = RESPONSE_TRUNCATE_LENGTH) -> str:
    """Truncate a response body to a maximum length for context efficiency."""
    if len(text) <= max_length:
        return text
    return text[:max_length] + f"... [TRUNCATED, {len(text)} total chars]"


def is_binary_content(content_type: str) -> bool:
    """Check if a content type indicates binary data."""
    binary_types = [
        "image/", "audio/", "video/", "application/octet-stream",
        "application/pdf", "application/zip", "application/gzip",
        "application/x-tar", "font/",
    ]
    ct = content_type.lower()
    return any(ct.startswith(bt) for bt in binary_types)


def _redact_token_match(match: re.Match) -> str:
    """Redact a token, keeping the prefix and last 4 chars."""
    prefix = match.group(1)
    token = match.group(2)
    if len(token) > 4:
        return f"{prefix}{'*' * (len(token) - 4)}{token[-4:]}"
    return f"{prefix}[REDACTED]"


# Patterns for sensitive data redaction
_SENSITIVE_PATTERNS: list[tuple[re.Pattern, str | Any]] = [
    # Credit card numbers (basic pattern)
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "[REDACTED-CC]"),
    # SSN
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    # Common password field patterns in JSON/form data
    (re.compile(r'("password"\s*:\s*")([^"]+)(")', re.IGNORECASE), r"\1[REDACTED]\3"),
    (re.compile(r"(password=)([^&\s]+)", re.IGNORECASE), r"\1[REDACTED]"),
    # Bearer tokens (redact all but last 4 chars)
    (re.compile(r"(Bearer\s+)(\S{8,})", re.IGNORECASE), _redact_token_match),
    # API keys in common header formats
    (re.compile(r"(api[_-]?key\s*[:=]\s*)(\S{8,})", re.IGNORECASE), _redact_token_match),
]


def redact_sensitive_data(text: str) -> str:
    """
    Redact potentially sensitive data from output text.
    Handles credit cards, SSNs, passwords, bearer tokens, and API keys.
    """
    result = text
    for pattern, replacement in _SENSITIVE_PATTERNS:
        if callable(replacement):
            result = pattern.sub(replacement, result)
        else:
            result = pattern.sub(replacement, result)
    return result


def sanitize_output(
    text: str,
    content_type: str = "",
    max_length: int = RESPONSE_TRUNCATE_LENGTH,
    redact: bool = True,
) -> str:
    """
    Full sanitization pipeline for output text:
    1. Check for binary content
    2. Truncate to max length
    3. Redact sensitive data
    """
    if content_type and is_binary_content(content_type):
        return f"[Binary content: {content_type}]"

    result = truncate_response(text, max_length)
    if redact:
        result = redact_sensitive_data(result)
    return result


# Global instances for shared use
circuit_breaker = CircuitBreaker()
rate_limiter = RateLimiter()
