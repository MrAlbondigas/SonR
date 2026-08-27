from datetime import datetime, timedelta, timezone

from app import models


def _ingest_host(client, scanner_headers, ip):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "ReportTestSoft", "version": "1.0", "port": 8080}]}]},
    )


def test_report_data_requires_scanner_key(client):
    resp = client.get("/reports/data")
    assert resp.status_code == 401


def test_report_data_includes_new_sections_shape(client, scanner_headers):
    resp = client.get("/reports/data", headers=scanner_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "sla_overdue" in data
    assert "cis_compliance" in data
    assert "group_rows" in data
    assert isinstance(data["sla_overdue"], list)
    assert isinstance(data["cis_compliance"], list)
    assert isinstance(data["group_rows"], list)
    assert {c["id"] for c in data["cis_compliance"]} == {"CIS 1", "CIS 5", "CIS 7", "CIS 12"}


def test_report_data_sla_overdue_reflects_real_vulnerability(client, scanner_headers, admin_client, db_session):
    ip = "10.99.2.10"
    _ingest_host(client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    db_session.add(
        models.Vulnerability(
            software_id=software.id,
            cve_id="CVE-REPORT-0001",
            severity="high",
            cvss=8.0,
            sla_due_at=datetime.now(timezone.utc) - timedelta(days=2),
        )
    )
    db_session.commit()

    data = client.get("/reports/data", headers=scanner_headers).json()
    cve_ids = [v["cve_id"] for v in data["sla_overdue"]]
    assert "CVE-REPORT-0001" in cve_ids


def test_report_data_group_rows_reflects_tagged_host(client, scanner_headers, admin_client, db_session):
    ip = "10.99.2.11"
    _ingest_host(client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    admin_client.post(f"/hosts/{host.id}/tags", json={"tags": ["reporte-test-tag"]})

    data = client.get("/reports/data", headers=scanner_headers).json()
    tags = [g["tag"] for g in data["group_rows"]]
    assert "reporte-test-tag" in tags
