from unittest.mock import MagicMock, patch

from app import models
from app.main import verify_http_banner


def _mock_http_response(status_code=200, headers=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    return resp


@patch("app.main.requests.get")
def test_verify_http_banner_confirms_matching_server_header(mock_get):
    mock_get.return_value = _mock_http_response(headers={"Server": "lighttpd/1.4.28"})
    success, detail = verify_http_banner("10.0.0.1", 80, "lighttpd", "1.4.28")
    assert success is True
    assert "1.4.28" in detail or "lighttpd" in detail.lower()


@patch("app.main.requests.get")
def test_verify_http_banner_reports_mismatch_when_banner_changed(mock_get):
    mock_get.return_value = _mock_http_response(headers={"Server": "nginx/1.25.0"})
    success, detail = verify_http_banner("10.0.0.1", 80, "lighttpd", "1.4.28")
    assert success is False


@patch("app.main.requests.get")
def test_verify_http_banner_handles_connection_failure(mock_get):
    mock_get.side_effect = Exception("connection refused")
    success, detail = verify_http_banner("10.0.0.1", 80, "lighttpd", "1.4.28")
    assert success is False
    assert "no se pudo conectar" in detail.lower()


def _ingest_host_with_web_service(client, scanner_headers, ip, port=8080):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "TestWeb", "version": "1.0", "port": port}]}]},
    )


def test_practice_target_toggle_requires_admin(client, scanner_headers, db_session):
    _ingest_host_with_web_service(client, scanner_headers, "10.99.0.30")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.30").first()

    resp = client.post(f"/hosts/{host.id}/practice-target", json={"is_practice_target": True})
    assert resp.status_code == 401


def test_practice_target_toggle_persists(admin_client, scanner_headers, db_session):
    _ingest_host_with_web_service(admin_client, scanner_headers, "10.99.0.31")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.31").first()
    assert host.is_practice_target is False

    resp = admin_client.post(f"/hosts/{host.id}/practice-target", json={"is_practice_target": True})
    assert resp.status_code == 200
    assert resp.json()["is_practice_target"] is True

    db_session.expire_all()
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.31").first()
    assert host.is_practice_target is True

    # y se puede desmarcar
    admin_client.post(f"/hosts/{host.id}/practice-target", json={"is_practice_target": False})
    db_session.expire_all()
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.31").first()
    assert host.is_practice_target is False


def test_verify_credential_requires_admin(client, scanner_headers, db_session):
    _ingest_host_with_web_service(client, scanner_headers, "10.99.0.32")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.32").first()
    finding = models.CredentialFinding(host_id=host.id, port=22, service="ssh", username="admin", password="admin")
    db_session.add(finding)
    db_session.commit()

    resp = client.post(f"/credentials/{finding.id}/verify")
    assert resp.status_code == 401


def test_verify_credential_rejects_host_not_marked_as_practice_target(admin_client, scanner_headers, db_session):
    _ingest_host_with_web_service(admin_client, scanner_headers, "10.99.0.33")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.33").first()
    assert host.is_practice_target is False

    finding = models.CredentialFinding(host_id=host.id, port=22, service="ssh", username="admin", password="admin")
    db_session.add(finding)
    db_session.commit()

    # ni siquiera deberia intentar conectarse — el rechazo debe ocurrir antes de tocar la red
    with patch("app.main.verify_ssh_credential") as mock_verify:
        resp = admin_client.post(f"/credentials/{finding.id}/verify")
        mock_verify.assert_not_called()

    assert resp.status_code == 403


def test_verify_credential_succeeds_for_practice_target_and_logs_attempt(admin_client, scanner_headers, db_session):
    _ingest_host_with_web_service(admin_client, scanner_headers, "10.99.0.34")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.34").first()
    admin_client.post(f"/hosts/{host.id}/practice-target", json={"is_practice_target": True})

    finding = models.CredentialFinding(host_id=host.id, port=22, service="ssh", username="admin", password="admin")
    db_session.add(finding)
    db_session.commit()

    with patch("app.main.verify_ssh_credential", return_value=(True, "Conexion SSH aceptada.")):
        resp = admin_client.post(f"/credentials/{finding.id}/verify")

    assert resp.status_code == 200
    assert resp.json()["success"] is True

    db_session.expire_all()
    attempt = db_session.query(models.PocAttempt).filter(models.PocAttempt.credential_finding_id == finding.id).first()
    assert attempt is not None
    assert attempt.success is True
    assert attempt.poc_type == "credential"


def test_verify_credential_matches_service_by_substring_not_exact_equality(admin_client, scanner_headers, db_session):
    # los hallazgos de demo etiquetan el servicio como "telnet (DEMO)", no "telnet" a secas —
    # el enrutado debe seguir reconociendolo correctamente
    _ingest_host_with_web_service(admin_client, scanner_headers, "10.99.0.38")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.38").first()
    admin_client.post(f"/hosts/{host.id}/practice-target", json={"is_practice_target": True})

    finding = models.CredentialFinding(
        host_id=host.id, port=23, service="telnet (DEMO)", username="admin", password="admin"
    )
    db_session.add(finding)
    db_session.commit()

    resp = admin_client.post(f"/credentials/{finding.id}/verify")
    assert resp.status_code == 200
    assert resp.json()["success"] is False
    assert "telnet" in resp.json()["detail"].lower()


def test_verify_poc_rejects_host_not_marked_as_practice_target(admin_client, scanner_headers, db_session):
    _ingest_host_with_web_service(admin_client, scanner_headers, "10.99.0.35")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.35").first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    vuln = models.Vulnerability(software_id=software.id, cve_id="CVE-TEST-POC-1", severity="high")
    db_session.add(vuln)
    db_session.commit()

    with patch("app.main.verify_http_banner") as mock_verify:
        resp = admin_client.post(f"/vulnerabilities/{vuln.id}/verify-poc")
        mock_verify.assert_not_called()

    assert resp.status_code == 403


def test_verify_poc_requires_software_with_a_port(admin_client, scanner_headers, db_session):
    ip = "10.99.0.36"
    admin_client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "NoPortSoft", "version": "1.0", "port": None}]}]},
    )
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    admin_client.post(f"/hosts/{host.id}/practice-target", json={"is_practice_target": True})
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    vuln = models.Vulnerability(software_id=software.id, cve_id="CVE-TEST-POC-2", severity="high")
    db_session.add(vuln)
    db_session.commit()

    resp = admin_client.post(f"/vulnerabilities/{vuln.id}/verify-poc")
    assert resp.status_code == 400


def test_verify_poc_succeeds_for_practice_target_and_logs_attempt(admin_client, scanner_headers, db_session):
    ip = "10.99.0.37"
    _ingest_host_with_web_service(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    admin_client.post(f"/hosts/{host.id}/practice-target", json={"is_practice_target": True})
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    vuln = models.Vulnerability(software_id=software.id, cve_id="CVE-TEST-POC-3", severity="high")
    db_session.add(vuln)
    db_session.commit()

    with patch("app.main.verify_http_banner", return_value=(True, "Version confirmada en vivo.")):
        resp = admin_client.post(f"/vulnerabilities/{vuln.id}/verify-poc")

    assert resp.status_code == 200
    assert resp.json()["success"] is True

    db_session.expire_all()
    attempt = db_session.query(models.PocAttempt).filter(models.PocAttempt.vulnerability_id == vuln.id).first()
    assert attempt is not None
    assert attempt.success is True
    assert attempt.poc_type == "http_banner"
