"""Helpers shared by API tests. Fixtures stay in ``conftest.py``."""

from fastapi.testclient import TestClient

LAB_SECRET = "lab-only-secret-key-not-for-production"
PASSWORD = "correct-horse-battery-marker"
OTHER_PASSWORD = "different-horse-battery-marker"


def register(client: TestClient, username: str, password: str = PASSWORD) -> None:
    response = client.post(
        "/auth/register",
        json={"username": username, "password": password},
    )
    assert response.status_code == 201, response.text


def login(client: TestClient, username: str, password: str = PASSWORD) -> str:
    response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    assert isinstance(token, str)
    return token


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
