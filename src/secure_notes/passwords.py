"""Password hashing through Argon2id.

Argon2id, the salt, and the memory-hard parameters are provided by
``argon2-cffi``. This module does not reimplement the algorithm.
"""

import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

# Published minimum memory-hard profile for Argon2id (about 19 MiB, two
# iterations, one lane). Benchmark a real deployment and raise memory cost
# when the hardware allows it. These values are not a toy hash.
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19_456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

_dummy_hash: str | None = None


def hash_password(password: str) -> str:
    """Return an Argon2id hash string that embeds a fresh random salt."""

    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return whether ``password`` matches ``password_hash``.

    Failures collapse to ``False``. Callers must not branch on why
    verification failed.
    """

    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def dummy_password_hash() -> str:
    """Hash used when the username does not exist.

    Verifying against this hash keeps the missing-user path on the same
    expensive primitive as the real path. The preimage is discarded.
    """

    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(32))
    return _dummy_hash
