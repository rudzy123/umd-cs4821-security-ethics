"""Secrets stay out of logs and out of the audit table."""

import logging

import pytest
from fastapi.testclient import TestClient

from secure_notes.app import LabState
from secure_notes.redaction import REDACTED, configure_logging, get_logger, redact_mapping
from tests.helpers import PASSWORD, auth_header, login, register

NOTE_BODY = "note-body-marker-do-not-log-this-value"


def test_redact_mapping_removes_secret_fields() -> None:
    cleaned = redact_mapping(
        {
            "username": "ada",
            "password": PASSWORD,
            "nested": {"access_token": "session-token", "ok": True},
            "Authorization": "Bearer raw-token-value",
        }
    )

    assert cleaned["username"] == "ada"
    assert cleaned["password"] == REDACTED
    assert cleaned["nested"] == {"access_token": REDACTED, "ok": True}
    assert cleaned["Authorization"] == REDACTED
    assert PASSWORD not in str(cleaned)
    assert "raw-token-value" not in str(cleaned)


def test_log_filter_redacts_bearer_tokens_and_secret_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    configure_logging()
    caplog.set_level(logging.INFO, logger="secure_notes")
    get_logger().info(
        "payload %s",
        {"password": PASSWORD, "username": "ada", "note": NOTE_BODY},
    )
    get_logger().info("header Bearer super-secret-token")

    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert PASSWORD not in messages
    assert NOTE_BODY not in messages
    assert "super-secret-token" not in messages
    assert "ada" in messages
    assert REDACTED in messages


def test_api_activity_does_not_record_secrets(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="secure_notes")
    register(client, "ada", PASSWORD)
    token = login(client, "ada", PASSWORD)
    created = client.post(
        "/notes",
        json={"title": "Private", "body": NOTE_BODY},
        headers=auth_header(token),
    )
    assert created.status_code == 201
    client.post(
        "/auth/login",
        json={"username": "ada", "password": "incorrect-horse-battery"},
    )

    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert PASSWORD not in messages
    assert "incorrect-horse-battery" not in messages
    assert token not in messages
    assert NOTE_BODY not in messages

    lab: LabState = client.app.state.lab
    for event in lab.service.audit_events():
        rendered = " ".join(
            part
            for part in (
                event.event_type,
                event.outcome,
                event.actor_id,
                event.resource_type,
                event.resource_id,
            )
            if part is not None
        )
        assert PASSWORD not in rendered
        assert token not in rendered
        assert NOTE_BODY not in rendered
        assert "incorrect-horse-battery" not in rendered
