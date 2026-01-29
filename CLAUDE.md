# Burp Suite Professional Orchestration Skill

## Overview

This project implements a Claude Code skill that provides programmatic control of Burp Suite Professional through a hybrid REST/gRPC architecture. The skill enables an AI agent to perform penetration testing tasks by combining two Burp Suite extensions:

- **Belch** (REST API on `localhost:7850`): High-level orchestration — scope management, proxy history search, scanner control, Collaborator integration, sitemap retrieval.
- **PyBurp** (gRPC on `localhost:50051`): Low-level manipulation — sending custom HTTP requests through Burp's HTTP engine with full TLS/HTTP2 support.

## Architecture

```
Claude Code Agent
    │
    ├── SKILL.md (decision framework, SOPs, safety rules)
    │
    └── burp_suite_skill/  (Python CLI toolset)
        ├── cli.py           (entry point: burp-cli)
        ├── config.py        (environment-based configuration)
        ├── clients/
        │   ├── belch_client.py   (REST client for Belch)
        │   └── pyburp_client.py  (gRPC client for PyBurp)
        ├── tools/
        │   ├── scope.py          (scope-get, scope-set, scope-check)
        │   ├── history.py        (history search, history item)
        │   ├── repeater.py       (repeater-send with modifications)
        │   ├── scanner.py        (scan-trigger, scan-findings)
        │   ├── collaborator.py   (collab-new, collab-poll)
        │   ├── sitemap.py        (sitemap fetch)
        │   ├── diff.py           (response diff analysis)
        │   ├── utilities.py      (entropy calc, JWT decode)
        │   └── health.py         (connectivity check)
        └── utils/
            ├── safety.py         (circuit breaker, rate limiter, redaction)
            └── logging_setup.py  (audit logging)
```

## Quick Start

```bash
# Install dependencies
pip install -e .

# Check connectivity
python -m burp_suite_skill.cli health

# Set target scope
python -m burp_suite_skill.cli scope-set --add "https://target.com"

# Search proxy history
python -m burp_suite_skill.cli history --host target.com

# Run tests
pytest tests/
```

## Configuration

All settings are environment-variable driven (see `burp_suite_skill/config.py`):

| Variable | Default | Description |
|---|---|---|
| `BELCH_URL` | `http://localhost:7850` | Belch REST API URL |
| `BELCH_API_KEY` | (empty) | Optional API key |
| `PYBURP_HOST` | `localhost` | PyBurp gRPC host |
| `PYBURP_PORT` | `50051` | PyBurp gRPC port |
| `BURP_MAX_RPM` | `60` | Max requests per minute |
| `BURP_CB_THRESHOLD` | `5` | Circuit breaker error threshold |
| `BURP_TRUNCATE_LEN` | `2000` | Response body truncation length |

## Safety Model

Multiple layers of safety are enforced:

1. **SKILL.md rules**: Immutable laws governing agent behavior (scope, rate limits, destructive actions, privacy).
2. **Tool-level checks**: Every action tool verifies scope before executing. The repeater checks rate limits and circuit breaker state.
3. **Circuit breaker**: Automatically halts operations after repeated errors to prevent runaway loops.
4. **Output redaction**: Sensitive data (passwords, tokens, credit cards, SSNs) is automatically redacted from output.
5. **Destructive URL detection**: Scanner refuses to scan URLs containing destructive path patterns without explicit override.

## Skill Location

The SKILL.md file is at `.claude/skills/burp_orchestration/SKILL.md`.
