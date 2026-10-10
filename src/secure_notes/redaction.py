"""Redaction helpers for structured logs.

A filter can remove known secret *fields* and bearer-token spellings. It
cannot recognize an arbitrary secret that was dropped into a free-text
message. The durable control is to never pass those values to the logger.
"""

import logging
import re
from collections.abc import Mapping

REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwordhash",
        "token",
        "accesstoken",
        "refreshtoken",
        "authorization",
        "secret",
        "secretkey",
        "apikey",
        "cookie",
        "setcookie",
        "body",
        "notebody",
        "note",
    }
)

_BEARER = re.compile(r"Bearer\s+\S+", flags=re.IGNORECASE)
LOGGER_NAME = "secure_notes"


def _normalize_key(key: str) -> str:
    return key.lower().replace("-", "").replace("_", "")


def is_sensitive_key(key: str) -> bool:
    """Return whether a mapping key is treated as secret material."""

    return _normalize_key(key) in _SENSITIVE_KEYS


def redact_text(text: str) -> str:
    """Hide bearer tokens that appear in a log string."""

    return _BEARER.sub("Bearer " + REDACTED, text)


def redact_mapping(data: Mapping[str, object]) -> dict[str, object]:
    """Return a copy of ``data`` with sensitive keys replaced."""

    redacted: dict[str, object] = {}
    for key, value in data.items():
        if is_sensitive_key(key):
            redacted[key] = REDACTED
        elif isinstance(value, Mapping):
            redacted[key] = redact_mapping(value)
        elif isinstance(value, str):
            redacted[key] = redact_text(value)
        else:
            redacted[key] = value
    return redacted


_LogArgs = tuple[object, ...] | Mapping[str, object] | None


class RedactionFilter(logging.Filter):
    """Apply field and bearer redaction before a record is formatted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        record.args = _redact_args(record.args)
        return True


def _redact_args(args: _LogArgs) -> _LogArgs:
    if isinstance(args, tuple):
        return tuple(_redact_value(item) for item in args)
    if isinstance(args, Mapping):
        return redact_mapping(args)
    return args


def _redact_value(value: object) -> object:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return redact_mapping(value)
    return value


def get_logger() -> logging.Logger:
    """Return the lab logger."""

    return logging.getLogger(LOGGER_NAME)


def configure_logging() -> None:
    """Attach the redaction filter once and keep propagation enabled."""

    logger = get_logger()
    if not any(isinstance(item, RedactionFilter) for item in logger.filters):
        logger.addFilter(RedactionFilter())
    logger.setLevel(logging.INFO)


def log_event(event: Mapping[str, object]) -> None:
    """Log an already-narrow event mapping after redaction."""

    get_logger().info("audit %s", redact_mapping(dict(event)))
