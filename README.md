# Burp Suite Professional Orchestration Skill

A Claude Code skill that provides programmatic control of Burp Suite Professional through a hybrid REST/gRPC architecture. This enables an AI agent to perform autonomous penetration testing tasks while maintaining strict safety guardrails.

## Architecture

The skill bridges Claude Code to Burp Suite via two extensions:

- **Belch** (REST API): High-level orchestration — scope management, proxy history search (SQLite full-text), scanner control, Collaborator integration, sitemap retrieval.
- **PyBurp** (gRPC): Low-level manipulation — sending custom HTTP requests through Burp's engine with full TLS/HTTP2 support via the Montoya API bridge.

```
Claude Code Agent
    │
    └── burp_suite_skill/  (Python CLI toolset)
        ├── cli.py               ← unified entry point
        ├── clients/
        │   ├── belch_client.py  ← REST client (Belch)
        │   └── pyburp_client.py ← gRPC client (PyBurp)
        ├── tools/
        │   ├── scope.py         ← scope-get, scope-set, scope-check
        │   ├── history.py       ← proxy history search
        │   ├── repeater.py      ← send/replay HTTP requests
        │   ├── intruder.py     ← parameter fuzzing with payload lists
        │   ├── scanner.py       ← active scanner control
        │   ├── collaborator.py  ← OAST payload management
        │   ├── sitemap.py       ← site map retrieval
        │   ├── diff.py          ← response comparison
        │   ├── utilities.py     ← entropy calc, JWT decode
        │   └── health.py        ← connectivity check
        └── utils/
            ├── safety.py        ← circuit breaker, rate limiter, redaction
            └── logging_setup.py ← audit logging
```

## Prerequisites

- **Burp Suite Professional** with the following extensions installed:
  - [Belch](https://github.com/nickvdyck/belch) — provides REST API on `localhost:7850`
  - [PyBurp](https://portswigger.net/bappstore) — provides gRPC bridge on `localhost:50051`
- **Python 3.10+**

## Installation

```bash
pip install -e .

# For development (includes pytest, responses, etc.)
pip install -e ".[dev]"
```

## Usage

### CLI Commands

```bash
# Check connectivity to Burp extensions
burp-cli health

# Scope management
burp-cli scope-get
burp-cli scope-set --add "https://target.com"
burp-cli scope-check "https://target.com/api"

# Search proxy history
burp-cli history --host target.com --method POST --grep "password"
burp-cli history-item 42

# Send/replay requests (scope-enforced, rate-limited)
burp-cli repeater-send --url "https://target.com/api/users"
burp-cli repeater-send --base-req-id 42 --param "user_id=101"

# Intruder-style fuzzing
burp-cli intruder-payloads                      # list built-in payload sets
burp-cli intruder --base-req-id 42 --param-name "q" --payload-set sqli-basic
burp-cli intruder --url "https://target.com/search?q=test" --param-name "q" --payloads "',\",<script>"

# Scanner
burp-cli scan-trigger --url "https://target.com/login"
burp-cli scan-findings --severity High

# Collaborator (OAST)
burp-cli collab-new
burp-cli collab-poll --payload-id abc123

# Site map
burp-cli sitemap --host target.com

# Local analysis utilities
burp-cli diff response_a.json response_b.json
burp-cli entropy "session_token_value"
burp-cli jwt-decode "eyJhbGciOiJIUzI1NiIs..."
```

### As a Claude Code Skill

The SKILL.md at `.claude/skills/burp_orchestration/SKILL.md` provides Claude with:
- Tool definitions and usage patterns
- Immutable safety laws (scope adherence, rate limiting, no destructive actions, privacy)
- Think → Check → Act decision framework
- Standard Operating Procedures (SOPs) for common vulnerability classes (IDOR, SQLi, XSS, SSRF)
- Reporting format for findings

## Configuration

All settings via environment variables (see `burp_suite_skill/config.py`):

| Variable | Default | Description |
|---|---|---|
| `BELCH_URL` | `http://localhost:7850` | Belch REST API URL |
| `BELCH_API_KEY` | _(empty)_ | Optional API key for Belch |
| `PYBURP_HOST` | `localhost` | PyBurp gRPC host |
| `PYBURP_PORT` | `50051` | PyBurp gRPC port |
| `BURP_MAX_RPM` | `60` | Max requests per minute |
| `BURP_CB_THRESHOLD` | `5` | Circuit breaker error threshold |
| `BURP_TRUNCATE_LEN` | `2000` | Response body truncation length |

## Safety Model

Multiple layers enforce safe operation:

1. **SKILL.md rules** — immutable laws: scope adherence, rate limiting, no destructive actions, privacy
2. **Tool-level enforcement** — every action tool verifies scope before executing
3. **Circuit breaker** — halts operations after repeated errors
4. **Rate limiter** — 60 req/min default, blocks excessive traffic
5. **Output redaction** — passwords, tokens, credit cards, SSNs automatically masked
6. **Destructive URL detection** — scanner refuses paths like `/delete`, `/admin/` without `--force`

## Testing

```bash
pytest tests/ -v
```

## License

MIT
