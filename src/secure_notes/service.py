"""Account, session, and note rules.

HTTP status codes stay in the route layer. This module raises small
exceptions that carry no password, token, or note text.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from secure_notes.config import Settings
from secure_notes.database import Database
from secure_notes.passwords import dummy_password_hash, hash_password, verify_password
from secure_notes.records import AuditEvent, AuthenticatedUser, NoteRecord
from secure_notes.redaction import log_event
from secure_notes.tokens import hash_bearer_token, issue_bearer_token


class RegistrationRejected(Exception):
    """The account was not created. The reason is not disclosed."""

    def __init__(self) -> None:
        super().__init__("registration rejected")


class AuthenticationFailed(Exception):
    """The username and password were not accepted as a pair."""

    def __init__(self) -> None:
        super().__init__("authentication failed")


class NoteUnavailable(Exception):
    """The note is missing or belongs to someone else.

    Callers must present both cases the same way.
    """

    def __init__(self) -> None:
        super().__init__("note unavailable")


class NotesService:
    """Use cases for the lab API."""

    def __init__(self, database: Database, settings: Settings) -> None:
        self._database = database
        self._settings = settings

    def register(self, username: str, password: str) -> AuthenticatedUser:
        password_hash = hash_password(password)
        user_id = str(uuid4())
        created = self._database.create_user(
            user_id=user_id,
            username=username,
            password_hash=password_hash,
            created_at=_now_text(),
        )
        if not created:
            self._audit(
                "registration_rejected",
                "denied",
                actor_id=None,
                resource_type="user",
                resource_id=None,
            )
            raise RegistrationRejected
        self._audit(
            "registration_succeeded",
            "success",
            actor_id=user_id,
            resource_type="user",
            resource_id=user_id,
        )
        return AuthenticatedUser(id=user_id, username=username)

    def login(self, username: str, password: str) -> tuple[str, int]:
        """Return a new bearer token and its lifetime in seconds.

        The password is verified even when the username is unknown so the
        two failures share the same expensive step. Neither failure records
        the password.
        """

        user = self._database.get_user_by_username(username)
        stored_hash = user.password_hash if user is not None else dummy_password_hash()
        verified = verify_password(password, stored_hash)
        if user is None or not verified:
            self._audit(
                "login_failed",
                "denied",
                actor_id=user.id if user is not None else None,
                resource_type="session",
                resource_id=None,
            )
            raise AuthenticationFailed
        token = issue_bearer_token()
        expires_at = datetime.now(UTC) + timedelta(seconds=self._settings.token_ttl_seconds)
        self._database.store_session(
            token_hash=hash_bearer_token(self._settings.secret_key, token),
            user_id=user.id,
            expires_at=expires_at.isoformat(),
        )
        self._audit(
            "login_succeeded",
            "success",
            actor_id=user.id,
            resource_type="session",
            resource_id=None,
        )
        return token, self._settings.token_ttl_seconds

    def authenticate_token(self, token: str) -> AuthenticatedUser | None:
        token_hash = hash_bearer_token(self._settings.secret_key, token)
        session = self._database.get_session(token_hash)
        if session is None:
            self._audit(
                "session_rejected",
                "denied",
                actor_id=None,
                resource_type="session",
                resource_id=None,
            )
            return None
        expiry = datetime.fromisoformat(session.expires_at)
        if datetime.now(UTC) >= expiry:
            self._database.delete_session(token_hash)
            self._audit(
                "session_rejected",
                "denied",
                actor_id=session.user_id,
                resource_type="session",
                resource_id=None,
            )
            return None
        user = self._database.get_user_by_id(session.user_id)
        if user is None:
            self._audit(
                "session_rejected",
                "denied",
                actor_id=None,
                resource_type="session",
                resource_id=None,
            )
            return None
        return AuthenticatedUser(id=user.id, username=user.username)

    def create_note(self, user: AuthenticatedUser, title: str, body: str) -> NoteRecord:
        note = NoteRecord(
            id=str(uuid4()),
            owner_id=user.id,
            title=title,
            body=body,
            created_at=_now_text(),
        )
        self._database.create_note(
            note_id=note.id,
            owner_id=note.owner_id,
            title=note.title,
            body=note.body,
            created_at=note.created_at,
        )
        self._audit(
            "note_created",
            "success",
            actor_id=user.id,
            resource_type="note",
            resource_id=note.id,
        )
        return note

    def list_notes(self, user: AuthenticatedUser) -> list[NoteRecord]:
        notes = self._database.list_notes(user.id)
        self._audit(
            "note_listed",
            "success",
            actor_id=user.id,
            resource_type="note",
            resource_id=None,
        )
        return notes

    def get_note(self, user: AuthenticatedUser, note_id: str) -> NoteRecord:
        canonical = _canonical_id(note_id)
        note = self._database.get_note(canonical) if canonical is not None else None
        if note is None or note.owner_id != user.id:
            self._audit(
                "note_access",
                "denied",
                actor_id=user.id,
                resource_type="note",
                resource_id=None,
            )
            raise NoteUnavailable
        self._audit(
            "note_access",
            "success",
            actor_id=user.id,
            resource_type="note",
            resource_id=note.id,
        )
        return note

    def delete_note(self, user: AuthenticatedUser, note_id: str) -> None:
        canonical = _canonical_id(note_id)
        deleted = self._database.delete_note(canonical, user.id) if canonical is not None else False
        if canonical is None or not deleted:
            self._audit(
                "note_deleted",
                "denied",
                actor_id=user.id,
                resource_type="note",
                resource_id=None,
            )
            raise NoteUnavailable
        self._audit(
            "note_deleted",
            "success",
            actor_id=user.id,
            resource_type="note",
            resource_id=canonical,
        )

    def record_rate_limit(self) -> None:
        self._audit(
            "rate_limited",
            "denied",
            actor_id=None,
            resource_type=None,
            resource_id=None,
        )

    def audit_events(self) -> list[AuditEvent]:
        return self._database.list_audit_events()

    def _audit(
        self,
        event_type: str,
        outcome: str,
        *,
        actor_id: str | None,
        resource_type: str | None,
        resource_id: str | None,
    ) -> None:
        occurred_at = _now_text()
        self._database.record_audit(
            occurred_at=occurred_at,
            event_type=event_type,
            outcome=outcome,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        log_event(
            {
                "occurred_at": occurred_at,
                "event_type": event_type,
                "outcome": outcome,
                "actor_id": actor_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
            }
        )


def _now_text() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_id(value: str) -> str | None:
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return str(parsed)
