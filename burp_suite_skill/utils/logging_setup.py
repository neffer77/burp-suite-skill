"""
Logging configuration for the Burp Suite Skill.

Sets up both console and file logging for audit trail purposes.
All agent actions are logged to a file for accountability.
"""

import logging
import sys

from burp_suite_skill.config import LOG_FILE, LOG_LEVEL


def setup_logging(
    log_file: str = LOG_FILE,
    level: str = LOG_LEVEL,
    quiet: bool = False,
) -> None:
    """
    Configure logging for the application.

    Args:
        log_file: Path to the log file for audit trail.
        level: Logging level (DEBUG, INFO, WARNING, ERROR).
        quiet: If True, suppress console output (still logs to file).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    root_logger = logging.getLogger("burp_suite_skill")
    root_logger.setLevel(log_level)

    # Clear existing handlers
    root_logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler for audit trail
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except OSError:
        # If we can't write the log file, continue without it
        pass

    # Console handler (stderr so stdout stays clean for JSON output)
    if not quiet:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
