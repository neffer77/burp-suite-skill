"""
Diff analysis tool: burp-diff-analyze.

Compares two HTTP responses and highlights differences in
status code, headers, body length, and content. This is a
pure local tool (no API calls) used for differential analysis
during vulnerability testing.
"""

import json
import sys
from difflib import unified_diff


def diff_analyze(args) -> int:
    """Compare two HTTP responses and highlight differences."""
    # Parse the two responses (provided as JSON strings or file paths)
    try:
        resp_a = _load_response(args.response_a)
        resp_b = _load_response(args.response_b)
    except (json.JSONDecodeError, FileNotFoundError, ValueError) as exc:
        print(json.dumps({"error": f"Failed to load responses: {exc}"}), file=sys.stderr)
        return 1

    differences = []
    summary = {}

    # Compare status codes
    status_a = resp_a.get("status_code", 0)
    status_b = resp_b.get("status_code", 0)
    summary["status_codes"] = {"a": status_a, "b": status_b, "match": status_a == status_b}
    if status_a != status_b:
        differences.append(f"Status code changed: {status_a} -> {status_b}")

    # Compare response lengths
    body_a = resp_a.get("body", "") or resp_a.get("response_body", "")
    body_b = resp_b.get("body", "") or resp_b.get("response_body", "")
    len_a = len(body_a)
    len_b = len(body_b)
    len_diff = abs(len_a - len_b)
    summary["body_lengths"] = {"a": len_a, "b": len_b, "diff": len_diff}
    if len_diff > 0:
        differences.append(f"Body length changed: {len_a} -> {len_b} (diff: {len_diff})")

    # Compare timing if available
    time_a = resp_a.get("elapsed_ms", 0)
    time_b = resp_b.get("elapsed_ms", 0)
    if time_a and time_b:
        time_diff = time_b - time_a
        summary["timing_ms"] = {"a": time_a, "b": time_b, "diff": time_diff}
        if abs(time_diff) > 1000:
            differences.append(
                f"Significant timing difference: {time_a}ms -> {time_b}ms "
                f"(delta: {time_diff}ms). This may indicate time-based injection."
            )

    # Compare headers
    headers_a = resp_a.get("headers", resp_a.get("response_headers", {}))
    headers_b = resp_b.get("headers", resp_b.get("response_headers", {}))
    if isinstance(headers_a, dict) and isinstance(headers_b, dict):
        header_diffs = []
        all_keys = set(list(headers_a.keys()) + list(headers_b.keys()))
        for key in sorted(all_keys):
            val_a = headers_a.get(key)
            val_b = headers_b.get(key)
            if val_a != val_b:
                header_diffs.append({
                    "header": key,
                    "a": val_a,
                    "b": val_b,
                })
        if header_diffs:
            differences.append(f"{len(header_diffs)} header(s) differ")
            summary["header_diffs"] = header_diffs

    # Content diff (first N lines)
    if body_a != body_b:
        lines_a = body_a.splitlines(keepends=True)
        lines_b = body_b.splitlines(keepends=True)
        diff_lines = list(unified_diff(
            lines_a[:100], lines_b[:100],
            fromfile="response_a", tofile="response_b",
            lineterm="",
        ))
        if diff_lines:
            # Limit diff output to prevent excessive context usage
            truncated = diff_lines[:50]
            summary["content_diff"] = "\n".join(truncated)
            if len(diff_lines) > 50:
                summary["content_diff"] += f"\n... ({len(diff_lines) - 50} more diff lines)"
            differences.append("Response body content differs")

    # Check for specific interesting patterns in the diff
    insights = []
    if body_a != body_b:
        # Check if response B contains data that A doesn't (possible IDOR)
        if len_b > len_a * 1.5:
            insights.append("Response B is significantly larger - may indicate data leakage or IDOR")
        if "error" in body_b.lower() and "error" not in body_a.lower():
            insights.append("Error message appeared in response B - may reveal internal information")
        if "unauthorized" in body_b.lower() or "forbidden" in body_b.lower():
            insights.append("Access control message detected in response B")
        if "stack" in body_b.lower() and "trace" in body_b.lower():
            insights.append("Stack trace detected in response B - information disclosure")

    output = {
        "differences_found": len(differences),
        "summary": summary,
        "differences": differences,
        "insights": insights if insights else ["No notable patterns detected"],
        "verdict": "RESPONSES DIFFER" if differences else "RESPONSES IDENTICAL",
    }
    print(json.dumps(output, indent=2))
    return 0


def _load_response(source: str) -> dict:
    """Load a response from a JSON string or file path."""
    # Try as file path first
    try:
        with open(source) as f:
            return json.load(f)
    except (FileNotFoundError, OSError):
        pass
    # Try as inline JSON
    return json.loads(source)


def register_diff_commands(subparsers) -> None:
    """Register diff-related subcommands."""
    parser = subparsers.add_parser(
        "diff",
        help="Compare two HTTP responses and highlight differences",
    )
    parser.add_argument(
        "response_a",
        help="First response (JSON string or file path)",
    )
    parser.add_argument(
        "response_b",
        help="Second response (JSON string or file path)",
    )
    parser.set_defaults(func=diff_analyze)
