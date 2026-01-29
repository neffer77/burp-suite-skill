"""
Utility tools: util-entropy-calc and util-jwt-decode.

Pure local helpers that don't interact with Burp Suite APIs.
Used for analyzing security-relevant data like session tokens
and JWTs during penetration testing.
"""

import base64
import json
import math
import sys
from collections import Counter


def entropy_calc(args) -> int:
    """Compute Shannon entropy of a given string."""
    text = args.text
    if not text:
        print(json.dumps({"error": "Empty input"}), file=sys.stderr)
        return 1

    # Calculate Shannon entropy
    length = len(text)
    freq = Counter(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )

    # Assess randomness quality
    max_entropy = math.log2(len(freq)) if len(freq) > 1 else 0
    if max_entropy > 0:
        efficiency = entropy / max_entropy
    else:
        efficiency = 0

    # Provide interpretation
    if entropy < 2.0:
        assessment = "LOW entropy - likely predictable or structured"
    elif entropy < 3.5:
        assessment = "MODERATE entropy - some randomness but may have patterns"
    elif entropy < 4.5:
        assessment = "GOOD entropy - reasonably random"
    else:
        assessment = "HIGH entropy - appears cryptographically random"

    output = {
        "input_length": length,
        "unique_chars": len(freq),
        "shannon_entropy": round(entropy, 4),
        "max_possible_entropy": round(max_entropy, 4),
        "efficiency": round(efficiency, 4),
        "bits_per_char": round(entropy, 4),
        "total_bits": round(entropy * length, 2),
        "assessment": assessment,
    }
    print(json.dumps(output, indent=2))
    return 0


def jwt_decode(args) -> int:
    """Decode a JWT token and display its components."""
    token = args.token.strip()
    parts = token.split(".")

    if len(parts) not in (2, 3):
        print(json.dumps({
            "error": f"Invalid JWT format: expected 2-3 parts separated by '.', got {len(parts)}"
        }), file=sys.stderr)
        return 1

    def decode_part(part: str) -> dict | str:
        """Base64url-decode a JWT part."""
        # Add padding if needed
        padded = part + "=" * (4 - len(part) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return decoded.hex()
        except Exception:
            return "[unable to decode]"

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    signature_present = len(parts) == 3

    output: dict = {
        "header": header,
        "payload": payload,
        "signature_present": signature_present,
    }

    # Analyze header
    if isinstance(header, dict):
        alg = header.get("alg", "unknown")
        output["algorithm"] = alg
        if alg == "none":
            output["warning"] = "CRITICAL: Algorithm is 'none' - signature not verified!"
        elif alg in ("HS256", "HS384", "HS512"):
            output["algorithm_type"] = "symmetric (HMAC)"
            output["note"] = "Uses a shared secret key. Test for weak keys."
        elif alg.startswith("RS") or alg.startswith("PS") or alg.startswith("ES"):
            output["algorithm_type"] = "asymmetric"

    # Analyze payload
    if isinstance(payload, dict):
        import time

        analysis = {}

        # Check expiration
        exp = payload.get("exp")
        if exp:
            now = int(time.time())
            if exp < now:
                analysis["expiration"] = f"EXPIRED (expired {now - exp}s ago)"
            else:
                analysis["expiration"] = f"Valid (expires in {exp - now}s)"

        # Check issued-at
        iat = payload.get("iat")
        if iat:
            analysis["issued_at"] = iat

        # Check for common claims
        for claim in ("sub", "iss", "aud", "roles", "role", "admin", "is_admin", "scope"):
            if claim in payload:
                analysis[claim] = payload[claim]

        # Check for interesting fields that might be mutable
        mutable_hints = []
        for key in payload:
            if key in ("admin", "is_admin", "role", "roles", "group", "permissions", "privilege"):
                mutable_hints.append(
                    f"'{key}' claim may be testable for privilege escalation"
                )
            if key in ("user_id", "uid", "sub", "email", "username"):
                mutable_hints.append(
                    f"'{key}' claim may be testable for IDOR"
                )

        if mutable_hints:
            analysis["testing_hints"] = mutable_hints

        output["analysis"] = analysis

    print(json.dumps(output, indent=2))
    return 0


def register_utility_commands(subparsers) -> None:
    """Register utility subcommands."""
    # util-entropy-calc
    entropy_parser = subparsers.add_parser(
        "entropy",
        help="Compute Shannon entropy of a string (for token analysis)",
    )
    entropy_parser.add_argument("text", help="String to analyze")
    entropy_parser.set_defaults(func=entropy_calc)

    # util-jwt-decode
    jwt_parser = subparsers.add_parser(
        "jwt-decode",
        help="Decode and analyze a JWT token",
    )
    jwt_parser.add_argument("token", help="JWT token string to decode")
    jwt_parser.set_defaults(func=jwt_decode)
