from datetime import datetime, timedelta, timezone

from app import models


def _ingest_host(client, scanner_headers, ip):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "CisTestSoft", "version": "1.0", "port": 8080}]}]},
    )


def test_compliance_requires_auth(client):
    resp = client.get("/compliance/cis")
    assert resp.status_code == 401


def test_compliance_lists_all_controls(admin_client):
    resp = admin_client.get("/compliance/cis")
    assert resp.status_code == 200
    data = resp.json()
    ids = {c["id"] for c in data}
    assert ids == {"CIS 1", "CIS 5", "CIS 7", "CIS 12"}


def test_cis1_ok_when_hosts_exist(admin_client, scanner_headers):
    _ingest_host(admin_client, scanner_headers, "10.99.1.10")
    data = admin_client.get("/compliance/cis").json()
    cis1 = next(c for c in data if c["id"] == "CIS 1")
    assert cis1["ok"] is True


def test_cis5_flags_credential_findings(admin_client, scanner_headers, db_session):
    ip = "10.99.1.11"
    _ingest_host(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    db_session.add(models.CredentialFinding(host_id=host.id, port=22, service="ssh", username="admin", password="admin"))
    db_session.commit()

    data = admin_client.get("/compliance/cis").json()
    cis5 = next(c for c in data if c["id"] == "CIS 5")
    assert cis5["ok"] is False
    assert "credencial" in cis5["detail"].lower()


def test_cis7_flags_critical_open_vulnerability(admin_client, scanner_headers, db_session):
    ip = "10.99.1.12"
    _ingest_host(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    db_session.add(models.Vulnerability(software_id=software.id, cve_id="CVE-CIS-0001", severity="critical", cvss=9.8))
    db_session.commit()

    data = admin_client.get("/compliance/cis").json()
    cis7 = next(c for c in data if c["id"] == "CIS 7")
    assert cis7["ok"] is False
    assert "crítica" in cis7["detail"].lower() or "critica" in cis7["detail"].lower()


def test_cis7_flags_known_exploited_vulnerability(admin_client, scanner_headers, db_session):
    ip = "10.99.1.13"
    _ingest_host(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    db_session.add(
        models.Vulnerability(
            software_id=software.id, cve_id="CVE-CIS-0002", severity="medium", cvss=5.0, known_exploited=True
        )
    )
    db_session.commit()

    data = admin_client.get("/compliance/cis").json()
    cis7 = next(c for c in data if c["id"] == "CIS 7")
    assert cis7["ok"] is False
    assert "kev" in cis7["detail"].lower() or "exploit" in cis7["detail"].lower()


def test_cis7_flags_overdue_sla(admin_client, scanner_headers, db_session):
    ip = "10.99.1.14"
    _ingest_host(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    db_session.add(
        models.Vulnerability(
            software_id=software.id,
            cve_id="CVE-CIS-0003",
            severity="low",
            cvss=2.0,
            sla_due_at=datetime.now(timezone.utc) - timedelta(days=3),
        )
    )
    db_session.commit()

    data = admin_client.get("/compliance/cis").json()
    cis7 = next(c for c in data if c["id"] == "CIS 7")
    assert cis7["ok"] is False
    assert "plazo" in cis7["detail"].lower()


def test_cis12_flags_attack_paths(admin_client, scanner_headers, db_session):
    ip = "10.99.1.15"
    _ingest_host(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    db_session.add(models.CredentialFinding(host_id=host.id, port=23, service="telnet", username="admin", password="admin"))
    db_session.commit()

    data = admin_client.get("/compliance/cis").json()
    cis12 = next(c for c in data if c["id"] == "CIS 12")
    assert cis12["ok"] is False
    assert "ruta" in cis12["detail"].lower()
