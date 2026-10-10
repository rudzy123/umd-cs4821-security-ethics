"""Shared fixtures for the notes API lab."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secure_notes.app import create_app
from secure_notes.config import Settings
from tests.helpers import LAB_SECRET


@pytest.fixture
def settings() -> Settings:
    return Settings(
        secret_key=LAB_SECRET,
        database_path=":memory:",
        token_ttl_seconds=3600,
        rate_limit_requests=30,
        rate_limit_window_seconds=60,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    application = create_app(settings)
    with TestClient(application) as test_client:
        yield test_client
