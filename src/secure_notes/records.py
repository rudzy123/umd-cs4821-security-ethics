"""In-process records. These types are not HTTP response models."""

from dataclasses import dataclass


@dataclass(frozen=True)
class UserRecord:
    """Stored account. The password hash stays inside the service boundary."""

    id: str
    username: str
    password_hash: str


@dataclass(frozen=True)
class AuthenticatedUser:
    """Identity established from a bearer token. No secret material."""

    id: str
    username: str


@dataclass(frozen=True)
class NoteRecord:
    """A note that belongs to exactly one owner."""

    id: str
    owner_id: str
    title: str
    body: str
    created_at: str


@dataclass(frozen=True)
class SessionRecord:
    """Server-side session metadata. The raw bearer token is never stored."""

    user_id: str
    expires_at: str


@dataclass(frozen=True)
class AuditEvent:
    """A security-relevant event with no room for a note body or a secret."""

    occurred_at: str
    event_type: str
    outcome: str
    actor_id: str | None
    resource_type: str | None
    resource_id: str | None
