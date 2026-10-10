"""SQLite access with parameters supplied separately from SQL text.

User input is bound as data. It is never concatenated into a statement.
The schema has no audit column that could hold a password, a token, or a
note body.
"""

import sqlite3
import threading
from types import TracebackType

from secure_notes.records import AuditEvent, NoteRecord, SessionRecord, UserRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users (id)
);

CREATE INDEX IF NOT EXISTS notes_owner_id_idx ON notes (owner_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    actor_id TEXT,
    resource_type TEXT,
    resource_id TEXT
);
"""

_AUDIT_EVENTS = frozenset(
    {
        "registration_succeeded",
        "registration_rejected",
        "login_succeeded",
        "login_failed",
        "session_rejected",
        "note_created",
        "note_listed",
        "note_access",
        "note_deleted",
        "rate_limited",
    }
)
_AUDIT_OUTCOMES = frozenset({"success", "denied", "error"})


def _text(row: sqlite3.Row, column: str) -> str:
    value: object = row[column]
    if not isinstance(value, str):
        raise RuntimeError("unexpected column type")
    return value


def _optional_text(row: sqlite3.Row, column: str) -> str | None:
    value: object = row[column]
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError("unexpected column type")
    return value


class Database:
    """One SQLite connection guarded by a lock.

    FastAPI runs synchronous routes in a worker thread, so the connection
    is shared across threads and every statement holds ``_lock``.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._lock = threading.Lock()

    @classmethod
    def connect(cls, path: str) -> "Database":
        connection = sqlite3.connect(path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 3000")
        database = cls(connection)
        database._initialize()
        return database

    def _initialize(self) -> None:
        with self._lock:
            self._connection.executescript(_SCHEMA)
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def create_user(
        self,
        *,
        user_id: str,
        username: str,
        password_hash: str,
        created_at: str,
    ) -> bool:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    INSERT INTO users (id, username, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, username, password_hash, created_at),
                )
                self._connection.commit()
            except sqlite3.IntegrityError:
                self._connection.rollback()
                return False
        return True

    def get_user_by_username(self, username: str) -> UserRecord | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT id, username, password_hash
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        if row is None:
            return None
        return UserRecord(
            id=_text(row, "id"),
            username=_text(row, "username"),
            password_hash=_text(row, "password_hash"),
        )

    def get_user_by_id(self, user_id: str) -> UserRecord | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT id, username, password_hash
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return UserRecord(
            id=_text(row, "id"),
            username=_text(row, "username"),
            password_hash=_text(row, "password_hash"),
        )

    def store_session(self, *, token_hash: str, user_id: str, expires_at: str) -> None:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO sessions (token_hash, user_id, expires_at)
                VALUES (?, ?, ?)
                """,
                (token_hash, user_id, expires_at),
            )
            self._connection.commit()

    def get_session(self, token_hash: str) -> SessionRecord | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT user_id, expires_at
                FROM sessions
                WHERE token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
        if row is None:
            return None
        return SessionRecord(
            user_id=_text(row, "user_id"),
            expires_at=_text(row, "expires_at"),
        )

    def delete_session(self, token_hash: str) -> None:
        with self._lock:
            self._connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (token_hash,),
            )
            self._connection.commit()

    def create_note(
        self,
        *,
        note_id: str,
        owner_id: str,
        title: str,
        body: str,
        created_at: str,
    ) -> None:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO notes (id, owner_id, title, body, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (note_id, owner_id, title, body, created_at),
            )
            self._connection.commit()

    def get_note(self, note_id: str) -> NoteRecord | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT id, owner_id, title, body, created_at
                FROM notes
                WHERE id = ?
                """,
                (note_id,),
            ).fetchone()
        if row is None:
            return None
        return _note_from_row(row)

    def list_notes(self, owner_id: str) -> list[NoteRecord]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT id, owner_id, title, body, created_at
                FROM notes
                WHERE owner_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (owner_id,),
            ).fetchall()
        return [_note_from_row(row) for row in rows]

    def delete_note(self, note_id: str, owner_id: str) -> bool:
        """Delete a note only when both the id and the owner match."""

        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM notes WHERE id = ? AND owner_id = ?",
                (note_id, owner_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def record_audit(
        self,
        *,
        occurred_at: str,
        event_type: str,
        outcome: str,
        actor_id: str | None,
        resource_type: str | None,
        resource_id: str | None,
    ) -> None:
        if event_type not in _AUDIT_EVENTS:
            raise ValueError("unsupported audit event")
        if outcome not in _AUDIT_OUTCOMES:
            raise ValueError("unsupported audit outcome")
        _reject_audit_identifier(actor_id)
        _reject_audit_identifier(resource_id)
        if resource_type is not None and resource_type not in {"user", "note", "session"}:
            raise ValueError("unsupported audit resource")
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO audit_events (
                    occurred_at, event_type, outcome, actor_id, resource_type, resource_id
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (occurred_at, event_type, outcome, actor_id, resource_type, resource_id),
            )
            self._connection.commit()

    def list_audit_events(self) -> list[AuditEvent]:
        """Return audit rows for local review. There is no HTTP route for this."""

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT occurred_at, event_type, outcome, actor_id, resource_type, resource_id
                FROM audit_events
                ORDER BY id ASC
                """
            ).fetchall()
        return [
            AuditEvent(
                occurred_at=_text(row, "occurred_at"),
                event_type=_text(row, "event_type"),
                outcome=_text(row, "outcome"),
                actor_id=_optional_text(row, "actor_id"),
                resource_type=_optional_text(row, "resource_type"),
                resource_id=_optional_text(row, "resource_id"),
            )
            for row in rows
        ]


def _note_from_row(row: sqlite3.Row) -> NoteRecord:
    return NoteRecord(
        id=_text(row, "id"),
        owner_id=_text(row, "owner_id"),
        title=_text(row, "title"),
        body=_text(row, "body"),
        created_at=_text(row, "created_at"),
    )


def _reject_audit_identifier(value: str | None) -> None:
    """Keep identifiers inside the shape this lab actually issues.

    A raw request path must not be copied into the audit log. Note and user
    ids are UUID strings. Anything else is rejected before it is stored.
    """

    if value is None:
        return
    if len(value) > 36 or "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("audit identifier is not a lab id")
