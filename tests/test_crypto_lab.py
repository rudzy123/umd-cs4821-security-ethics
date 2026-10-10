"""Cryptography lab: distinct operations and tamper rejection."""

import pytest

from secure_notes.crypto_lab import (
    IntegrityCheckFailed,
    compute_hmac,
    cryptographic_hash,
    decode_base64,
    decrypt_aes_gcm,
    demonstrate_salt,
    encode_base64,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_hmac_key,
    generate_secret_token,
    generate_signing_key,
    sign_message,
    verify_hmac,
    verify_signature,
)


def _flip_last_byte(data: bytes) -> bytes:
    return data[:-1] + bytes((data[-1] ^ 0x01,))


def test_hash_encoding_and_salt_are_different_ideas() -> None:
    message = b"this message is longer than a sha-256 digest"
    digest = cryptographic_hash(message)
    again = cryptographic_hash(message)

    assert digest == again
    assert len(digest) == 32
    assert message not in digest

    encoded = encode_base64(message)
    assert decode_base64(encoded) == message
    assert encode_base64(digest) != encoded

    salt_a, digest_a = demonstrate_salt(message)
    salt_b, digest_b = demonstrate_salt(message)
    assert salt_a != salt_b
    assert digest_a != digest_b
    _, repeated = demonstrate_salt(message, salt_a)
    assert repeated == digest_a


def test_hmac_rejects_tampered_message_and_tag() -> None:
    key = generate_hmac_key()
    message = b"lab note"
    tag = compute_hmac(key, message)

    assert compute_hmac(key, message) == tag
    assert verify_hmac(key, message, tag)
    assert not verify_hmac(key, b"lab note!", tag)
    assert not verify_hmac(key, message, _flip_last_byte(tag))
    assert not verify_hmac(generate_hmac_key(), message, tag)


def test_aes_gcm_rejects_tampered_ciphertext_and_associated_data() -> None:
    key = generate_aes_key()
    plaintext = b"lab note"
    associated = b"note-id"
    first = encrypt_aes_gcm(key, plaintext, associated)
    second = encrypt_aes_gcm(key, plaintext, associated)

    assert first != second
    assert decrypt_aes_gcm(key, first, associated) == plaintext
    assert decode_base64(encode_base64(first)) != plaintext

    with pytest.raises(IntegrityCheckFailed):
        decrypt_aes_gcm(key, _flip_last_byte(first), associated)
    with pytest.raises(IntegrityCheckFailed):
        decrypt_aes_gcm(key, first, b"other-id")
    with pytest.raises(IntegrityCheckFailed):
        decrypt_aes_gcm(generate_aes_key(), first, associated)


def test_signature_rejects_tampered_message_and_signature() -> None:
    private_key = generate_signing_key()
    public_key = private_key.public_key()
    message = b"lab note"
    signature = sign_message(private_key, message)

    assert verify_signature(public_key, message, signature)
    assert not verify_signature(public_key, b"lab note!", signature)
    assert not verify_signature(public_key, message, _flip_last_byte(signature))
    assert signature != message


def test_secret_tokens_are_unique_and_not_a_password_echo() -> None:
    first = generate_secret_token()
    second = generate_secret_token()

    assert first != second
    assert len(first) >= 32
    assert " " not in first
    with pytest.raises(ValueError):
        generate_secret_token(16)
