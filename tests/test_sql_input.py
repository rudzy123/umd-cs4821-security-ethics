"""Strings that look like SQL stay data."""

from urllib.parse import quote

from fastapi.testclient import TestClient

from tests.helpers import auth_header, login, register

PAYLOAD = "'; DROP TABLE notes; --"


def test_sql_like_input_is_stored_and_queried_as_data(client: TestClient) -> None:
    register(client, "ada")
    token = login(client, "ada")
    headers = auth_header(token)

    created = client.post(
        "/notes",
        json={"title": PAYLOAD, "body": PAYLOAD},
        headers=headers,
    )
    assert created.status_code == 201
    assert created.json()["title"] == PAYLOAD
    assert created.json()["body"] == PAYLOAD

    listed = client.get("/notes", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["title"] == PAYLOAD

    probed = client.get("/notes/" + quote(PAYLOAD, safe=""), headers=headers)
    assert probed.status_code == 404
    assert PAYLOAD not in probed.text

    second = client.post(
        "/notes",
        json={"title": "still here", "body": "the notes table accepted another row"},
        headers=headers,
    )
    assert second.status_code == 201
    again = client.get("/notes", headers=headers)
    assert again.status_code == 200
    titles = [item["title"] for item in again.json()]
    assert sorted(titles) == sorted([PAYLOAD, "still here"])
