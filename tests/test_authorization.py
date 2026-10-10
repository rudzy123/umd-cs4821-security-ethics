"""Access-control boundaries between two authenticated users."""

from fastapi.testclient import TestClient

from secure_notes.messages import AUTHENTICATION_REQUIRED, NOTE_NOT_FOUND
from tests.helpers import OTHER_PASSWORD, PASSWORD, auth_header, login, register

NOTE_BODY = "ada-private-note-body-marker"
NOTE_TITLE = "Ada only"


def _owned_note(client: TestClient, token: str) -> str:
    created = client.post(
        "/notes",
        json={"title": NOTE_TITLE, "body": NOTE_BODY},
        headers=auth_header(token),
    )
    assert created.status_code == 201
    note_id = created.json()["id"]
    assert isinstance(note_id, str)
    return note_id


def test_users_cannot_read_or_delete_each_others_notes(client: TestClient) -> None:
    register(client, "ada", PASSWORD)
    register(client, "grace", OTHER_PASSWORD)
    ada = login(client, "ada", PASSWORD)
    grace = login(client, "grace", OTHER_PASSWORD)
    note_id = _owned_note(client, ada)

    grace_list = client.get("/notes", headers=auth_header(grace))
    assert grace_list.status_code == 200
    assert grace_list.json() == []

    missing = client.get("/notes/00000000-0000-4000-8000-000000000000", headers=auth_header(grace))
    foreign = client.get(f"/notes/{note_id}", headers=auth_header(grace))
    assert missing.status_code == 404
    assert foreign.status_code == 404
    assert missing.json() == {"detail": NOTE_NOT_FOUND}
    assert foreign.json() == missing.json()
    assert NOTE_BODY not in foreign.text
    assert NOTE_TITLE not in foreign.text

    rejected = client.delete(f"/notes/{note_id}", headers=auth_header(grace))
    assert rejected.status_code == 404
    assert rejected.json() == {"detail": NOTE_NOT_FOUND}

    still_there = client.get(f"/notes/{note_id}", headers=auth_header(ada))
    assert still_there.status_code == 200
    assert still_there.json()["body"] == NOTE_BODY

    removed = client.delete(f"/notes/{note_id}", headers=auth_header(ada))
    assert removed.status_code == 204
    assert removed.content == b""
    gone = client.get(f"/notes/{note_id}", headers=auth_header(ada))
    assert gone.status_code == 404


def test_missing_and_foreign_tokens_do_not_reveal_notes(client: TestClient) -> None:
    register(client, "ada")
    ada = login(client, "ada")
    note_id = _owned_note(client, ada)

    anonymous = client.get(f"/notes/{note_id}")
    assert anonymous.status_code == 401
    assert anonymous.json() == {"detail": AUTHENTICATION_REQUIRED}
    assert NOTE_BODY not in anonymous.text

    basic = client.get(f"/notes/{note_id}", headers={"Authorization": "Basic YWRhOnB3"})
    assert basic.status_code == 401
    assert NOTE_BODY not in basic.text

    empty = client.get(f"/notes/{note_id}", headers={"Authorization": "Bearer "})
    assert empty.status_code == 401

    wrong = client.get(
        f"/notes/{note_id}",
        headers={"Authorization": "Bearer not-a-real-session-token"},
    )
    assert wrong.status_code == 401
    assert wrong.json() == anonymous.json()
    assert NOTE_BODY not in wrong.text


def test_client_cannot_assign_an_owner(client: TestClient) -> None:
    register(client, "ada")
    token = login(client, "ada")
    response = client.post(
        "/notes",
        json={
            "title": "Boundary",
            "body": "The server chooses the owner.",
            "owner_id": "00000000-0000-4000-8000-000000000000",
        },
        headers=auth_header(token),
    )
    assert response.status_code == 422
    assert "00000000-0000-4000-8000-000000000000" not in response.text
