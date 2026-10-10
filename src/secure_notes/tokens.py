"""Opaque session tokens.

The raw token is shown to the client once. The database stores only an
HMAC-SHA256 of the token, keyed by the server secret. HMAC here is the
maintained standard-library implementation, not a hand-rolled MAC.
"""

import hashlib
import hmac

from secure_notes.crypto_lab import generate_secret_token


def issue_bearer_token() -> str:
    """Create a fresh high-entropy bearer token."""

    return generate_secret_token()


def hash_bearer_token(secret_key: str, token: str) -> str:
    """Return the stored identifier for a bearer token."""

    digest = hmac.new(
        secret_key.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    )
    return digest.hexdigest()
