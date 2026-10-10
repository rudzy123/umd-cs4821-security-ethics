"""Request validation and safe failure responses."""

import pytest
from fastapi.testclient import TestClient

from secure_notes.app import create_app
from secure_notes.config import Settings, load_settings
from secure_notes.messages import INTERNAL_ERROR
from tests.helpers import PASSWORD, auth_header, login, register


def test_malformed_input_is_rejected_without_echoing_secrets(client: TestClient) -> None:
    short_password = "tiny-marker"
    short = client.post(
        "/auth/register",
        json={"username": "ada", "password": short_password},
    )
    assert short.status_code == 422
    assert short_password not in short.text
    assert "Traceback" not in short.text

    extra = client.post(
        "/auth/register",
        json={"username": "ada", "password": PASSWORD, "role": "admin"},
    )
    assert extra.status_code == 422
    assert "admin" not in extra.text

    broken = client.post(
        "/auth/login",
        content=b"{",
        headers={"content-type": "application/json"},
    )
    assert broken.status_code == 422
    assert "Traceback" not in broken.text

    quoted_name = client.post(
        "/auth/register",
        json={"username": "ada'; drop", "password": PASSWORD},
    )
    assert quoted_name.status_code == 422

    register(client, "ada")
    token = login(client, "ada")
    blank = client.post(
        "/notes",
        json={"title": "   ", "body": "text"},
        headers=auth_header(token),
    )
    assert blank.status_code == 422
    huge = client.post(
        "/notes",
        json={"title": "t" * 121, "body": "text"},
        headers=auth_header(token),
    )
    assert huge.status_code == 422


def test_unhandled_errors_hide_internal_details(settings: Settings) -> None:
    application = create_app(settings)

    @application.get("/explode")
    def explode() -> dict[str, str]:
        raise RuntimeError("password=hunter2-marker path=/var/lab/secret")

    with TestClient(application, raise_server_exceptions=False) as client:
        response = client.get("/explode")

    assert response.status_code == 500
    assert response.json() == {"detail": INTERNAL_ERROR}
    assert "hunter2-marker" not in response.text
    assert "Traceback" not in response.text
    assert "/var/lab/secret" not in response.text


def test_missing_server_secret_refuses_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTES_SECRET_KEY", raising=False)

    with pytest.raises(RuntimeError, match="NOTES_SECRET_KEY"):
        load_settings()
