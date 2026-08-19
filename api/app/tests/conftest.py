import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_proyecto_cyber.db")
os.environ.setdefault("JWT_SECRET", "test-secret-key-not-for-prod")
os.environ.setdefault("SCANNER_API_KEY", "test-scanner-key")
os.environ.setdefault("ADMIN_USERNAME", "testadmin")
os.environ.setdefault("ADMIN_PASSWORD", "TestPass123!")
os.environ.setdefault("ALERT_WEBHOOK_URL", "")

_DB_PATH = "./test_proyecto_cyber.db"
if os.path.exists(_DB_PATH):
    os.remove(_DB_PATH)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app as fastapi_app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(fastapi_app) as c:
        yield c


@pytest.fixture()
def scanner_headers():
    return {"X-API-Key": os.environ["SCANNER_API_KEY"]}


@pytest.fixture()
def admin_client(client):
    resp = client.post(
        "/auth/login",
        json={
            "username": os.environ["ADMIN_USERNAME"],
            "password": os.environ["ADMIN_PASSWORD"],
        },
    )
    assert resp.status_code == 200
    return client
