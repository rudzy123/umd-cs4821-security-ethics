"""Response headers and the decision not to enable cross-origin reads."""

from fastapi.testclient import TestClient

EXPECTED = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cache-control": "no-store",
    "cross-origin-resource-policy": "same-origin",
}


def test_security_headers_are_present_on_success_and_failure(client: TestClient) -> None:
    success = client.get("/health")
    failure = client.get("/notes")

    assert success.status_code == 200
    assert failure.status_code == 401
    for response in (success, failure):
        lowered = {key.lower(): value for key, value in response.headers.items()}
        for name, value in EXPECTED.items():
            assert lowered[name] == value
        assert "access-control-allow-origin" not in lowered
        assert "strict-transport-security" not in lowered
