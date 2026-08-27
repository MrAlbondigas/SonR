import os

from fastapi.testclient import TestClient

from app import models
from app.main import app as fastapi_app


def _login_as(username: str, password: str) -> TestClient:
    new_client = TestClient(fastapi_app)
    resp = new_client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return new_client


def test_create_user_requires_admin(client):
    resp = client.post("/users", json={"username": "u1", "password": "password123", "role": "viewer"})
    assert resp.status_code == 401


def test_admin_can_create_analyst_user(admin_client, db_session):
    resp = admin_client.post(
        "/users", json={"username": "ana-analyst", "password": "password123", "role": "analyst"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "ana-analyst"
    assert data["role"] == "analyst"
    assert "password" not in data
    assert "password_hash" not in data

    db_session.expire_all()
    user = db_session.query(models.User).filter(models.User.username == "ana-analyst").first()
    assert user is not None
    assert user.role == "analyst"


def test_create_user_rejects_invalid_role(admin_client):
    resp = admin_client.post("/users", json={"username": "bad-role-user", "password": "password123", "role": "superadmin"})
    assert resp.status_code == 400


def test_create_user_rejects_short_password(admin_client):
    resp = admin_client.post("/users", json={"username": "short-pw-user", "password": "abc", "role": "viewer"})
    assert resp.status_code == 400


def test_create_user_rejects_empty_username(admin_client):
    resp = admin_client.post("/users", json={"username": "   ", "password": "password123", "role": "viewer"})
    assert resp.status_code == 400


def test_create_user_rejects_duplicate_username(admin_client):
    admin_client.post("/users", json={"username": "dupe-user", "password": "password123", "role": "viewer"})
    resp = admin_client.post("/users", json={"username": "dupe-user", "password": "password123", "role": "viewer"})
    assert resp.status_code == 400


def test_list_users_requires_admin(client):
    resp = client.get("/users")
    assert resp.status_code == 401


def test_list_users_does_not_expose_password_hash(admin_client):
    admin_client.post("/users", json={"username": "leak-check-user", "password": "password123", "role": "viewer"})
    resp = admin_client.get("/users")
    assert resp.status_code == 200
    assert "password_hash" not in resp.text
    assert "password123" not in resp.text


def test_delete_user_requires_admin(client, db_session):
    row = models.User(username="to-delete-1", password_hash="x", role="viewer")
    db_session.add(row)
    db_session.commit()

    resp = client.delete(f"/users/{row.id}")
    assert resp.status_code == 401


def test_admin_can_delete_other_user(admin_client, db_session):
    created = admin_client.post("/users", json={"username": "to-delete-2", "password": "password123", "role": "viewer"}).json()
    resp = admin_client.delete(f"/users/{created['id']}")
    assert resp.status_code == 200

    db_session.expire_all()
    assert db_session.query(models.User).filter(models.User.id == created["id"]).first() is None


def test_admin_cannot_delete_own_account(admin_client, db_session):
    me = db_session.query(models.User).filter(models.User.username == os.environ["ADMIN_USERNAME"]).first()
    resp = admin_client.delete(f"/users/{me.id}")
    assert resp.status_code == 400


def test_delete_nonexistent_user_returns_404(admin_client):
    resp = admin_client.delete("/users/999999")
    assert resp.status_code == 404


def test_analyst_can_change_vulnerability_status_but_not_scan_policy(client, admin_client, scanner_headers, db_session):
    admin_client.post("/users", json={"username": "analyst-perm-test", "password": "password123", "role": "analyst"})
    analyst_client = _login_as("analyst-perm-test", "password123")

    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": "10.99.0.95", "software": [{"name": "RoleTestSoft", "version": "1.0", "port": 8080}]}]},
    )
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.95").first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    vuln = models.Vulnerability(software_id=software.id, cve_id="CVE-ROLE-0001", severity="medium", cvss=5.0)
    db_session.add(vuln)
    db_session.commit()

    # el analista SI puede reconocer una vulnerabilidad (accion operativa)
    ok_resp = analyst_client.post(f"/vulnerabilities/{vuln.id}/status", json={"status": "reconocida"})
    assert ok_resp.status_code == 200

    # pero NO puede tocar la politica de escaneo (accion de configuracion, solo admin)
    forbidden_resp = analyst_client.post(
        "/scan/policy",
        json={"enabled": True, "interval_seconds": 300, "excluded_ips": [], "quiet_hours_start": None, "quiet_hours_end": None},
    )
    assert forbidden_resp.status_code == 403

    # ni crear claves API
    forbidden_resp2 = analyst_client.post("/api-keys", json={"name": "should-fail"})
    assert forbidden_resp2.status_code == 403


def test_viewer_cannot_change_vulnerability_status(admin_client, scanner_headers, db_session):
    admin_client.post("/users", json={"username": "viewer-perm-test", "password": "password123", "role": "viewer"})
    viewer_client = _login_as("viewer-perm-test", "password123")

    admin_client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": "10.99.0.96", "software": [{"name": "RoleTestSoft2", "version": "1.0", "port": 8081}]}]},
    )
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.96").first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    vuln = models.Vulnerability(software_id=software.id, cve_id="CVE-ROLE-0002", severity="medium", cvss=5.0)
    db_session.add(vuln)
    db_session.commit()

    resp = viewer_client.post(f"/vulnerabilities/{vuln.id}/status", json={"status": "reconocida"})
    assert resp.status_code == 403
