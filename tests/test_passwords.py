"""Password hashing properties."""

from secure_notes.passwords import hash_password, verify_password


def test_same_password_produces_different_hashes() -> None:
    password = "correct-horse-battery-marker"
    first = hash_password(password)
    second = hash_password(password)

    assert first != second
    assert password not in first
    assert password not in second
    assert first.startswith("$argon2id$")
    assert second.startswith("$argon2id$")
    assert verify_password(password, first)
    assert verify_password(password, second)


def test_wrong_password_is_rejected() -> None:
    stored = hash_password("correct-horse-battery-marker")
    assert not verify_password("incorrect-horse-battery", stored)
    assert not verify_password("correct-horse-battery-marker", "not-a-hash")
