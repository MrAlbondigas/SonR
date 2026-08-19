import os


def test_login_success(client):
    resp = client.post(
        "/auth/login",
        json={"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"
    assert "session_token" in resp.cookies


def test_login_wrong_password(client):
    resp = client.post(
        "/auth/login",
        json={"username": os.environ["ADMIN_USERNAME"], "password": "esto-no-es-la-contrasena"},
    )
    assert resp.status_code == 401


def test_dashboard_accessible_without_login(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Invitado" in resp.text


def test_admin_only_endpoint_rejects_anonymous(client):
    resp = client.post("/demo/seed")
    assert resp.status_code == 401


def test_scan_policy_update_requires_admin(client):
    resp = client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
    assert resp.status_code == 401


def test_logout_clears_session(admin_client):
    resp = admin_client.post("/auth/logout")
    assert resp.status_code == 200
    resp2 = admin_client.post("/demo/seed")
    assert resp2.status_code == 401
