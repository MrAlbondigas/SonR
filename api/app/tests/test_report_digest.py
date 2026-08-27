from datetime import datetime, timedelta, timezone

from app import models
from app.main import build_digest_summary, format_digest_message


def _ingest_host(client, scanner_headers, ip):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "DigestTestSoft", "version": "1.0", "port": 8080}]}]},
    )


def test_digest_requires_scanner_key(client):
    resp = client.post("/reports/digest")
    assert resp.status_code == 401


def test_format_digest_message_includes_key_numbers():
    summary = {
        "host_count": 12,
        "new_vulnerabilities_7d": 3,
        "new_critical_7d": 1,
        "resolved_7d": 2,
        "overdue_sla_count": 4,
        "credential_findings_count": 5,
    }
    message = format_digest_message(summary)
    assert "12" in message
    assert "3" in message
    assert "1" in message
    assert "4" in message
    assert "5" in message


def test_digest_computes_correct_counts(client, scanner_headers, db_session):
    ip = "10.99.0.90"
    _ingest_host(client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()

    now = datetime.now(timezone.utc)
    recent_critical = models.Vulnerability(
        software_id=software.id, cve_id="CVE-DIGEST-0001", severity="critical", cvss=9.5, detected_at=now
    )
    recent_medium = models.Vulnerability(
        software_id=software.id, cve_id="CVE-DIGEST-0002", severity="medium", cvss=5.0, detected_at=now
    )
    resolved_recent = models.Vulnerability(
        software_id=software.id,
        cve_id="CVE-DIGEST-0003",
        severity="low",
        cvss=2.0,
        detected_at=now - timedelta(days=20),
        resolved_at=now,
    )
    overdue = models.Vulnerability(
        software_id=software.id,
        cve_id="CVE-DIGEST-0004",
        severity="high",
        cvss=7.0,
        detected_at=now - timedelta(days=40),
        sla_due_at=now - timedelta(days=5),
    )
    db_session.add_all([recent_critical, recent_medium, resolved_recent, overdue])
    db_session.commit()

    summary = build_digest_summary(db_session)
    assert summary["new_vulnerabilities_7d"] >= 2
    assert summary["new_critical_7d"] >= 1
    assert summary["resolved_7d"] >= 1
    assert summary["overdue_sla_count"] >= 1


def test_digest_endpoint_sends_notification_and_logs_alert(client, scanner_headers, db_session):
    alerts_before = db_session.query(models.Alert).count()

    resp = client.post("/reports/digest", headers=scanner_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "summary" in data
    assert "delivered" in data

    alerts_after = db_session.query(models.Alert).count()
    # se registra un intento por canal (webhook + email), aunque ninguno este configurado en tests
    assert alerts_after >= alerts_before + 2


def test_digest_test_endpoint_requires_admin(client):
    resp = client.post("/reports/digest/test")
    assert resp.status_code == 401


def test_digest_test_endpoint_works_for_admin(admin_client):
    resp = admin_client.post("/reports/digest/test")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
