"""Authentication behavior visible at the HTTP boundary."""

from fastapi.testclient import TestClient

from secure_notes.app import LabState
from secure_notes.messages import INVALID_CREDENTIALS, REGISTER_FAILED
from tests.helpers import PASSWORD, auth_header, login, register


def test_register_and_login_round_trip(client: TestClient) -> None:
    register(client, "ada")
    response = client.post(
        "/auth/login",
        json={"username": "ada", "password": PASSWORD},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"token", "token_type", "expires_in"}
    assert body["token_type"] == "bearer"
    assert isinstance(body["token"], str)
    assert body["token"] != PASSWORD
    created = client.post(
        "/notes",
        json={"title": "Lab", "body": "Owned by ada."},
        headers=auth_header(body["token"]),
    )
    assert created.status_code == 201


def test_login_failures_use_the_same_response(client: TestClient) -> None:
    register(client, "ada")
    unknown = client.post(
        "/auth/login",
        json={"username": "nobody", "password": PASSWORD},
    )
    wrong = client.post(
        "/auth/login",
        json={"username": "ada", "password": "incorrect-horse-battery"},
    )

    assert unknown.status_code == 401
    assert wrong.status_code == 401
    assert unknown.json() == {"detail": INVALID_CREDENTIALS}
    assert wrong.json() == unknown.json()
    assert unknown.headers["www-authenticate"] == "Bearer"
    assert PASSWORD not in unknown.text
    assert "incorrect-horse-battery" not in wrong.text
    assert "nobody" not in unknown.text
    assert "ada" not in wrong.text


def test_duplicate_registration_is_generic(client: TestClient) -> None:
    register(client, "ada")
    duplicate = client.post(
        "/auth/register",
        json={"username": "ada", "password": "another-horse-battery"},
    )

    assert duplicate.status_code == 400
    assert duplicate.json() == {"detail": REGISTER_FAILED}
    assert "exist" not in duplicate.text.lower()
    assert "taken" not in duplicate.text.lower()
    assert "another-horse-battery" not in duplicate.text


def test_stored_hashes_differ_for_the_same_password(client: TestClient) -> None:
    register(client, "ada", PASSWORD)
    register(client, "grace", PASSWORD)
    lab: LabState = client.app.state.lab
    ada = lab.database.get_user_by_username("ada")
    grace = lab.database.get_user_by_username("grace")

    assert ada is not None
    assert grace is not None
    assert ada.password_hash != grace.password_hash
    assert PASSWORD not in ada.password_hash
    assert PASSWORD not in grace.password_hash
    assert login(client, "ada")
    assert login(client, "grace")
