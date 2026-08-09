from fastapi.testclient import TestClient

from app.main import app


def test_root():
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

    html = response.text

    assert "SentinelAPI" in html


def test_health():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["redis"] == "connected"
    assert data["database"] == "connected"


def test_openapi_available():
    with TestClient(app) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200

    data = response.json()

    assert "/auth/register" in data["paths"]
    assert "/auth/login" in data["paths"]
    assert "/auth/me" in data["paths"]
    assert "/detect" in data["paths"]
    assert "/admin/attacks" in data["paths"]
    assert "/admin/stats" in data["paths"]


def test_admin_requires_authentication():
    with TestClient(app) as client:
        response = client.get("/admin/stats")

    assert response.status_code == 401


def test_admin_event_requires_authentication():
    with TestClient(app) as client:
        response = client.get("/admin/attacks/5")

    assert response.status_code == 401
