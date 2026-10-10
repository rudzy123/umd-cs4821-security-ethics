"""Cryptography demonstrations that call maintained libraries.

The words below are not interchangeable:

* Encoding (base64) is a reversible spelling of bytes. There is no key and
  no integrity check. Anyone can reverse it.
* A cryptographic hash is one-way and deterministic. It hides the input
  only in the sense that the input is hard to recover. It does not use a
  key, so anyone can recompute it. It is not encryption.
* A salt is a non-secret random value mixed into a hash so identical inputs
  do not share a digest. Salts stop precomputed tables. They do not make a
  fast hash a password hash.
* A MAC, including HMAC, is a keyed integrity tag. The same secret verifies
  it. A MAC does not hide the message.
* Authenticated encryption (AES-256-GCM here) hides the message and rejects
  modified ciphertext. The nonce may travel with the ciphertext. The key
  must not.
* A digital signature is produced with a private key and checked with the
  matching public key. It does not hide the message. Verification fails when
  the message or the signature changes.

Password storage does not belong in this module. The notes API hashes
passwords with Argon2id. Nothing here implements AES, SHA-256, HMAC,
Argon2, or Ed25519. Those constructions come from the Python standard
library or the ``cryptography`` package.
"""

import base64
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.hmac import HMAC

_AES_KEY_BYTES = 32
_GCM_NONCE_BYTES = 12
_GCM_TAG_BYTES = 16
_MIN_HMAC_KEY_BYTES = 32
_MIN_TOKEN_BYTES = 32


class IntegrityCheckFailed(Exception):
    """Authenticated ciphertext could not be verified.

    The message is fixed so a failure cannot echo plaintext or key bytes.
    """

    def __init__(self) -> None:
        super().__init__("integrity check failed")


def cryptographic_hash(message: bytes) -> bytes:
    """Return a SHA-256 digest. Same input, same output, no key."""

    digest = Hash(SHA256())
    digest.update(message)
    return digest.finalize()


def demonstrate_salt(message: bytes, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(salt, SHA-256(salt || message))``.

    This shows why a salt changes a digest. It is not a password hash and
    must not be used to store passwords. Use Argon2id for that.
    """

    if salt is None:
        salt = secrets.token_bytes(16)
    if salt == b"" or len(salt) > 255:
        raise ValueError("salt length must be between 1 and 255 bytes")
    digest = Hash(SHA256())
    digest.update(bytes((len(salt),)))
    digest.update(salt)
    digest.update(message)
    return salt, digest.finalize()


def generate_hmac_key() -> bytes:
    """Return a random HMAC key. Do not derive this from a short password."""

    return secrets.token_bytes(_MIN_HMAC_KEY_BYTES)


def compute_hmac(key: bytes, message: bytes) -> bytes:
    """Return an HMAC-SHA256 tag. The message itself is not hidden."""

    _require_hmac_key(key)
    mac = HMAC(key, SHA256())
    mac.update(message)
    return mac.finalize()


def verify_hmac(key: bytes, message: bytes, tag: bytes) -> bool:
    """Return whether ``tag`` matches ``message`` under ``key``.

    A mismatch, a truncated tag, and a wrong key all return ``False``.
    """

    _require_hmac_key(key)
    mac = HMAC(key, SHA256())
    mac.update(message)
    try:
        mac.verify(tag)
    except InvalidSignature:
        return False
    return True


def generate_aes_key() -> bytes:
    """Return a random 256-bit AES key."""

    return secrets.token_bytes(_AES_KEY_BYTES)


def encrypt_aes_gcm(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Encrypt with AES-256-GCM and prepend a random 96-bit nonce.

    Associated data is authenticated and is not encrypted. Changing it,
    the nonce, the ciphertext, or the tag causes decryption to fail.
    """

    _require_aes_key(key)
    nonce = secrets.token_bytes(_GCM_NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + sealed


def decrypt_aes_gcm(
    key: bytes,
    token: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt an AES-256-GCM token or raise ``IntegrityCheckFailed``."""

    _require_aes_key(key)
    if len(token) < _GCM_NONCE_BYTES + _GCM_TAG_BYTES:
        raise IntegrityCheckFailed
    nonce = token[:_GCM_NONCE_BYTES]
    sealed = token[_GCM_NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, sealed, associated_data)
    except InvalidTag:
        raise IntegrityCheckFailed from None


def generate_signing_key() -> Ed25519PrivateKey:
    """Generate an Ed25519 private key. The library draws the seed."""

    return Ed25519PrivateKey.generate()


def sign_message(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign ``message``. The signature does not encrypt ``message``."""

    return private_key.sign(message)


def verify_signature(
    public_key: Ed25519PublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """Return whether ``signature`` is valid for ``message``.

    Check signatures with the public key. A changed message or a changed
    signature returns ``False``.
    """

    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def generate_secret_token(nbytes: int = 32) -> str:
    """Return a URL-safe token from the operating system's CSPRNG.

    ``nbytes`` is the number of random bytes, not the length of the string.
    Thirty-two bytes is the minimum accepted here.
    """

    if nbytes < _MIN_TOKEN_BYTES:
        raise ValueError("token entropy must be at least 32 bytes")
    return secrets.token_urlsafe(nbytes)


def encode_base64(data: bytes) -> str:
    """Encode bytes as base64. This is not encryption and not a MAC."""

    return base64.b64encode(data).decode("ascii")


def decode_base64(text: str) -> bytes:
    """Reverse :func:`encode_base64`. No key is required."""

    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid base64") from exc


def _require_aes_key(key: bytes) -> None:
    if len(key) != _AES_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key")


def _require_hmac_key(key: bytes) -> None:
    if len(key) < _MIN_HMAC_KEY_BYTES:
        raise ValueError("HMAC key must be at least 32 bytes from a CSPRNG")
