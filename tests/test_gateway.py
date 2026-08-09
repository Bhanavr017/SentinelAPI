from fastapi.testclient import TestClient
from app.main import app


def test_protected_endpoint_allows_clean_request():
    with TestClient(app) as client:
        response = client.get("/protected/echo?demo=clean")
    assert response.status_code == 200
    assert response.headers["X-Sentinel-Decision"] == "ALLOW"
    assert response.json()["status"] == "accepted"


def test_protected_endpoint_blocks_sql_injection():
    with TestClient(app) as client:
        response = client.get(
            "/protected/echo?id=1%27%20OR%20%271%27%3D%271"
        )
    assert response.status_code == 403
    data = response.json()
    assert data["action"] == "BLOCKED"
    assert data["risk_score"] >= 60
    assert "SQL_Injection" in data["detected_attacks"]
    assert response.headers["X-Sentinel-Decision"] == "BLOCK"
    assert response.headers["X-Sentinel-Request-ID"]


def test_jwks_endpoint_is_available():
    with TestClient(app) as client:
        response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert "keys" in response.json()


def test_gateway_blocks_malicious_request_before_upstream(monkeypatch):
    import httpx
    from fastapi.testclient import TestClient

    calls = []

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def request(self, **kwargs):
            calls.append(kwargs)
            return httpx.Response(
                status_code=200,
                json={"upstream": "REACHED"},
            )

    monkeypatch.setattr(
        "app.routes.gateway.httpx.AsyncClient",
        FakeAsyncClient,
    )

    with TestClient(app) as client:
        response = client.get(
            "/gateway/test?id=1%27%20OR%20%271%27%3D%271"
        )

    assert response.status_code == 403
    assert response.json()["action"] == "BLOCKED"
    assert response.headers["X-Sentinel-Decision"] == "BLOCK"
    assert calls == []


def test_gateway_allows_clean_request_to_upstream(monkeypatch):
    import httpx
    from fastapi.testclient import TestClient

    calls = []

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def request(self, **kwargs):
            calls.append(kwargs)
            return httpx.Response(
                status_code=200,
                json={"upstream": "REACHED"},
            )

    monkeypatch.setattr(
        "app.routes.gateway.httpx.AsyncClient",
        FakeAsyncClient,
    )

    with TestClient(app) as client:
        response = client.get("/gateway/test?demo=clean")

    assert response.status_code == 200
    assert response.json()["upstream"] == "REACHED"
    assert len(calls) == 1
    assert calls[0]["method"] == "GET"
