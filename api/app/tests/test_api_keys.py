from app import models


def _ingest_host_with_vuln(client, scanner_headers, ip):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "ApiKeyTestSoft", "version": "1.0", "port": 8080}]}]},
    )


def test_create_api_key_requires_admin(client):
    resp = client.post("/api-keys", json={"name": "test integration"})
    assert resp.status_code == 401


def test_create_api_key_requires_nonempty_name(admin_client):
    resp = admin_client.post("/api-keys", json={"name": "   "})
    assert resp.status_code == 400


def test_admin_can_create_api_key(admin_client):
    resp = admin_client.post("/api-keys", json={"name": "Splunk SOC"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Splunk SOC"
    assert data["key"].startswith("pc_")
    assert data["key_prefix"] == data["key"][:12]


def test_list_api_keys_requires_admin(client):
    resp = client.get("/api-keys")
    assert resp.status_code == 401


def test_list_api_keys_does_not_expose_hash_or_full_key(admin_client):
    created = admin_client.post("/api-keys", json={"name": "leak-check"}).json()

    resp = admin_client.get("/api-keys")
    assert resp.status_code == 200
    body = resp.text
    assert "key_hash" not in body
    assert created["key"] not in body


def test_created_key_authenticates_export_endpoint(admin_client):
    created = admin_client.post("/api-keys", json={"name": "export-test"}).json()

    resp = admin_client.get("/api/v1/export", headers={"X-API-Key": created["key"]})
    assert resp.status_code == 200
    data = resp.json()
    assert "host_count" in data
    assert "open_vulnerabilities" in data


def test_export_requires_valid_key(admin_client):
    resp_no_key = admin_client.get("/api/v1/export")
    assert resp_no_key.status_code == 401

    resp_bad_key = admin_client.get("/api/v1/export", headers={"X-API-Key": "not-a-real-key"})
    assert resp_bad_key.status_code == 401


def test_revoke_api_key_requires_admin(client, db_session):
    row = models.ApiKey(name="revoke-auth-test", key_prefix="pc_abc123", key_hash="deadbeef")
    db_session.add(row)
    db_session.commit()

    resp = client.post(f"/api-keys/{row.id}/revoke")
    assert resp.status_code == 401


def test_revoke_nonexistent_key_returns_404(admin_client):
    resp = admin_client.post("/api-keys/999999/revoke")
    assert resp.status_code == 404


def test_revoked_key_no_longer_authenticates(admin_client):
    created = admin_client.post("/api-keys", json={"name": "revoke-test"}).json()

    ok_resp = admin_client.get("/api/v1/export", headers={"X-API-Key": created["key"]})
    assert ok_resp.status_code == 200

    revoke_resp = admin_client.post(f"/api-keys/{created['id']}/revoke")
    assert revoke_resp.status_code == 200

    after_resp = admin_client.get("/api/v1/export", headers={"X-API-Key": created["key"]})
    assert after_resp.status_code == 401

    listed = {k["id"]: k for k in admin_client.get("/api-keys").json()}
    assert listed[created["id"]]["revoked"] is True


def test_export_reflects_real_data(admin_client, scanner_headers, db_session):
    ip = "10.99.0.80"
    _ingest_host_with_vuln(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    vuln = models.Vulnerability(software_id=software.id, cve_id="CVE-APIKEY-0001", severity="high", cvss=7.5)
    db_session.add(vuln)
    db_session.commit()

    created = admin_client.post("/api-keys", json={"name": "data-check"}).json()
    resp = admin_client.get("/api/v1/export", headers={"X-API-Key": created["key"]})
    data = resp.json()

    host_ips = [h["ip"] for h in data["hosts"]]
    assert ip in host_ips
    cve_ids = [v["cve_id"] for v in data["open_vulnerabilities"]]
    assert "CVE-APIKEY-0001" in cve_ids


def test_export_does_not_expose_credential_usernames(admin_client, scanner_headers, db_session):
    ip = "10.99.0.81"
    _ingest_host_with_vuln(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    finding = models.CredentialFinding(host_id=host.id, port=22, service="ssh", username="admin", password="admin")
    db_session.add(finding)
    db_session.commit()

    created = admin_client.post("/api-keys", json={"name": "cred-leak-check"}).json()
    resp = admin_client.get("/api/v1/export", headers={"X-API-Key": created["key"]})
    assert resp.status_code == 200
    assert "credential_findings_count" in resp.json()
    assert "admin" not in resp.text
