"""Rate-limit abstraction and the login route that uses it."""

from fastapi.testclient import TestClient

from secure_notes.app import create_app
from secure_notes.config import Settings
from secure_notes.messages import TOO_MANY_REQUESTS
from secure_notes.rate_limit import InMemoryFixedWindowRateLimiter
from tests.helpers import LAB_SECRET, PASSWORD, register


def test_fixed_window_resets_with_the_injected_clock() -> None:
    clock = {"now": 0.0}
    limiter = InMemoryFixedWindowRateLimiter(
        limit=1,
        window_seconds=10,
        clock=lambda: clock["now"],
    )

    assert limiter.allow("ada")
    assert not limiter.allow("ada")
    assert limiter.allow("grace")
    clock["now"] = 10.0
    assert limiter.allow("ada")


def test_login_rate_limit_does_not_echo_the_password() -> None:
    settings = Settings(
        secret_key=LAB_SECRET,
        database_path=":memory:",
        rate_limit_requests=3,
        rate_limit_window_seconds=60,
    )
    application = create_app(settings)
    with TestClient(application) as client:
        register(client, "ada", PASSWORD)
        statuses: list[int] = []
        for _ in range(4):
            response = client.post(
                "/auth/login",
                json={"username": "ada", "password": "wrong-horse-battery"},
            )
            statuses.append(response.status_code)
            assert "wrong-horse-battery" not in response.text
            assert PASSWORD not in response.text
        assert statuses == [401, 401, 401, 429]
        blocked = client.post(
            "/auth/login",
            json={"username": "ada", "password": "wrong-horse-battery"},
        )
        assert blocked.status_code == 429
        assert blocked.json() == {"detail": TOO_MANY_REQUESTS}
        assert blocked.headers["retry-after"] == "60"
