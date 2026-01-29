"""
Configuration management for the Burp Suite Skill.

Reads settings from environment variables with sensible defaults
for local Burp Suite + Belch + PyBurp setups.
"""

import os


# Belch REST API configuration
BELCH_URL = os.environ.get("BELCH_URL", "http://localhost:7850")
BELCH_API_KEY = os.environ.get("BELCH_API_KEY", "")
BELCH_TIMEOUT = int(os.environ.get("BELCH_TIMEOUT", "30"))

# PyBurp gRPC configuration
PYBURP_HOST = os.environ.get("PYBURP_HOST", "localhost")
PYBURP_PORT = int(os.environ.get("PYBURP_PORT", "50051"))
PYBURP_TIMEOUT = int(os.environ.get("PYBURP_TIMEOUT", "30"))

# Safety configuration
MAX_REQUESTS_PER_MINUTE = int(os.environ.get("BURP_MAX_RPM", "60"))
CIRCUIT_BREAKER_THRESHOLD = int(os.environ.get("BURP_CB_THRESHOLD", "5"))
CIRCUIT_BREAKER_WINDOW = int(os.environ.get("BURP_CB_WINDOW", "60"))
RESPONSE_TRUNCATE_LENGTH = int(os.environ.get("BURP_TRUNCATE_LEN", "2000"))
MAX_HISTORY_RESULTS = int(os.environ.get("BURP_MAX_HISTORY", "50"))

# Logging
LOG_FILE = os.environ.get("BURP_LOG_FILE", "burp_agent_actions.log")
LOG_LEVEL = os.environ.get("BURP_LOG_LEVEL", "INFO")
