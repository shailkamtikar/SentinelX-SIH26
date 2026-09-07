"""Focused tests for the CORS behavior actually wired up in app/main.py.

app/main.py builds its FastAPI app (and CORSMiddleware) once at import
time, from whatever CORS_ALLOWED_ORIGINS is (or isn't) set to at that
moment — so these exercise the real, already-configured `app` via actual
requests carrying an Origin header, rather than reaching into Starlette's
middleware internals. Origin-list parsing itself (comma-separated,
trimming, the localhost-only default) is covered separately and more
exhaustively in tests/test_config.py.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_localhost_dev_origin_is_allowed():
    response = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_unrecognized_origin_is_not_echoed_back():
    response = client.get(
        "/health", headers={"Origin": "https://not-a-configured-origin.example"}
    )
    assert response.status_code == 200
    # The request itself still succeeds (CORS is enforced by the browser,
    # not the server) but the server must not tell that browser it's safe
    # to expose the response to a script on the unrecognized origin.
    assert "access-control-allow-origin" not in response.headers


def test_cors_never_pairs_credentials_with_the_allowed_origin():
    """Guards the exact combination CORS makes dangerous.

    allow_credentials=False is safe with a non-wildcard origin list; the
    dangerous combination is credentials=True together with a wildcard (or
    an overly broad) origin list. This asserts the actual response never
    signals allow-credentials, so a future edit can't silently introduce
    that combination without this test failing.
    """
    response = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-credentials") is None
