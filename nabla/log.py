"""Structured logging for the Nabla system.

Provides a configured logger with console and optional file output.
File logging goes to /data/logs/nabla.log with rotation (10MB, 3 backups).
Includes a log filter that redacts potential credential patterns.
"""

import logging
import os
import re
from logging.handlers import RotatingFileHandler

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_initialized = False

# Patterns that look like credentials — redact them from log output.
# Matches common credential patterns: Bearer tokens, API keys, passwords
# in URL query strings, and long hex/base64 strings that could be secrets.
_REDACT_PATTERNS = [
    # Bearer/Splunk tokens: "Bearer eyJ...", "Splunk eyJ..."
    (re.compile(r"(Bearer|Splunk)\s+\S+"), r"\1 [REDACTED]"),
    # Password in URL: "user:password@host"
    (re.compile(r"://([^:]+):([^@]+)@"), r"://\1:[REDACTED]@"),
    # Long hex strings (48+ chars) that look like API keys/tokens.
    # 48 chars catches most API keys while sparing shorter hashes
    # and UUIDs without hyphens (32 hex chars).
    (re.compile(r"\b[0-9a-fA-F]{48,}\b"), "[REDACTED_HEX]"),
    # Long base64 strings (64+ chars) that look like encoded secrets.
    # 64 chars catches JWT segments and API keys while sparing
    # shorter base64-encoded data in log messages.
    (re.compile(r"\b[A-Za-z0-9+/]{64,}={0,2}\b"), "[REDACTED_B64]"),
    # password= or token= in key-value pairs
    (re.compile(r"(password|token|secret|api_key|api_secret)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
]


class _CredentialRedactingFilter(logging.Filter):
    """Filter that redacts credential-like patterns from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pattern, replacement in _REDACT_PATTERNS:
            msg = pattern.sub(replacement, msg)
        if msg != record.getMessage():
            record.msg = msg
            record.args = ()
        return True


def _ensure_initialized() -> None:
    """Set up the nabla logger on first use."""
    global _initialized
    if _initialized:
        return
    _initialized = True

    root = logging.getLogger("nabla")
    root.setLevel(logging.DEBUG)

    # Add credential redaction filter to all messages
    root.addFilter(_CredentialRedactingFilter())

    # Console handler — INFO and above
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    root.addHandler(console)

    # File handler — DEBUG and above, if data dir exists
    try:
        from nabla.config import get_settings
        settings = get_settings()
        log_dir = os.path.join(settings.data_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "nabla.log")

        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3,
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        root.addHandler(file_handler)
    except Exception as e:
        # If data dir isn't writable (e.g., during tests), skip file logging
        import sys
        print(f"[nabla] Could not set up file logging: {e}", file=sys.stderr)


def get_logger(name: str) -> logging.Logger:
    """Get a logger under the nabla namespace.

    Usage: logger = get_logger("pipeline")
    Produces: nabla.pipeline
    """
    _ensure_initialized()
    return logging.getLogger(f"nabla.{name}")
