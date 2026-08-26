from app import models

DEFAULT_POLICY = {
    "critical_days": 7,
    "high_days": 30,
    "medium_days": 90,
    "low_days": 180,
}


def _ingest_host_with_one_service(client, scanner_headers, ip, name, port):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": name, "version": "1.0", "port": port}]}]},
    )


def _get_software_id(db_session, ip):
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    software = db_session.query(models.Software).filter(models.Software.host_id == host.id).first()
    return software.id


def test_get_sla_policy_defaults(client):
    resp = client.get("/sla/policy")
    assert resp.status_code == 200
    data = resp.json()
    assert data["critical_days"] == 7
    assert data["high_days"] == 30
    assert data["medium_days"] == 90
    assert data["low_days"] == 180


def test_set_sla_policy_requires_admin(client):
    resp = client.post("/sla/policy", json=DEFAULT_POLICY)
    assert resp.status_code == 401


def test_admin_can_update_sla_policy(admin_client):
    resp = admin_client.post(
        "/sla/policy",
        json={"critical_days": 3, "high_days": 14, "medium_days": 45, "low_days": 90},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["critical_days"] == 3
    assert data["high_days"] == 14

    resp2 = admin_client.get("/sla/policy")
    assert resp2.json()["critical_days"] == 3

    # devolvemos la politica a su estado por defecto para no afectar a otros tests
    admin_client.post("/sla/policy", json=DEFAULT_POLICY)


def test_sla_policy_rejects_out_of_bounds_days(admin_client):
    resp = admin_client.post(
        "/sla/policy",
        json={"critical_days": 0, "high_days": 30, "medium_days": 90, "low_days": 180},
    )
    assert resp.status_code == 400

    resp2 = admin_client.post(
        "/sla/policy",
        json={"critical_days": 7, "high_days": 30, "medium_days": 90, "low_days": 999999},
    )
    assert resp2.status_code == 400


def test_new_critical_vulnerability_gets_sla_due_date_from_policy(client, scanner_headers, admin_client, db_session):
    admin_client.post("/sla/policy", json=DEFAULT_POLICY)

    ip = "10.99.0.60"
    _ingest_host_with_one_service(client, scanner_headers, ip, "SlaTestSoft", 8080)
    software_id = _get_software_id(db_session, ip)

    client.post(
        "/vulnerabilities/ingest",
        headers=scanner_headers,
        json={
            "software_id": software_id,
            "match_type": "cpe",
            "vulnerabilities": [{"cve_id": "CVE-SLA-0001", "cvss": 9.8, "severity": "critical", "match_type": "cpe"}],
        },
    )

    db_session.expire_all()
    vuln = db_session.query(models.Vulnerability).filter(models.Vulnerability.cve_id == "CVE-SLA-0001").first()
    assert vuln.sla_due_at is not None
    expected_days = (vuln.sla_due_at - vuln.detected_at).total_seconds() / 86400
    assert 6.9 < expected_days < 7.1


def test_vulnerability_without_severity_has_no_sla_due_date(client, scanner_headers, db_session):
    ip = "10.99.0.61"
    _ingest_host_with_one_service(client, scanner_headers, ip, "SlaTestSoft2", 8081)
    software_id = _get_software_id(db_session, ip)

    client.post(
        "/vulnerabilities/ingest",
        headers=scanner_headers,
        json={
            "software_id": software_id,
            "match_type": "keyword",
            "vulnerabilities": [{"cve_id": "CVE-SLA-0002", "match_type": "keyword"}],
        },
    )

    db_session.expire_all()
    vuln = db_session.query(models.Vulnerability).filter(models.Vulnerability.cve_id == "CVE-SLA-0002").first()
    assert vuln.sla_due_at is None


def test_reopening_a_vulnerability_recomputes_sla_due_date(client, scanner_headers, db_session):
    ip = "10.99.0.62"
    _ingest_host_with_one_service(client, scanner_headers, ip, "SlaTestSoft3", 8082)
    software_id = _get_software_id(db_session, ip)
    payload = {
        "software_id": software_id,
        "match_type": "cpe",
        "vulnerabilities": [{"cve_id": "CVE-SLA-0003", "cvss": 5.0, "severity": "medium", "match_type": "cpe"}],
    }
    client.post("/vulnerabilities/ingest", headers=scanner_headers, json=payload)

    db_session.expire_all()
    vuln = db_session.query(models.Vulnerability).filter(models.Vulnerability.cve_id == "CVE-SLA-0003").first()
    vuln.resolved_at = vuln.detected_at
    vuln.status = "resuelta"
    original_due = vuln.sla_due_at
    db_session.commit()

    # se detecta de nuevo mas tarde: el plazo debe recalcularse desde ahora, no seguir
    # anclado a la primera deteccion
    client.post("/vulnerabilities/ingest", headers=scanner_headers, json=payload)

    db_session.expire_all()
    vuln = db_session.query(models.Vulnerability).filter(models.Vulnerability.cve_id == "CVE-SLA-0003").first()
    assert vuln.resolved_at is None
    assert vuln.sla_due_at is not None
    assert vuln.sla_due_at >= original_due


def test_overdue_endpoint_requires_admin(client):
    resp = client.get("/sla/overdue")
    assert resp.status_code == 401


def test_overdue_endpoint_lists_only_past_due_open_vulnerabilities(client, scanner_headers, admin_client, db_session):
    admin_client.post("/sla/policy", json={"critical_days": 7, "high_days": 30, "medium_days": 90, "low_days": 180})

    ip = "10.99.0.63"
    _ingest_host_with_one_service(client, scanner_headers, ip, "SlaTestSoft4", 8083)
    software_id = _get_software_id(db_session, ip)
    client.post(
        "/vulnerabilities/ingest",
        headers=scanner_headers,
        json={
            "software_id": software_id,
            "match_type": "cpe",
            "vulnerabilities": [{"cve_id": "CVE-SLA-0004", "cvss": 9.0, "severity": "critical", "match_type": "cpe"}],
        },
    )

    db_session.expire_all()
    vuln = db_session.query(models.Vulnerability).filter(models.Vulnerability.cve_id == "CVE-SLA-0004").first()
    from datetime import datetime, timedelta, timezone

    vuln.sla_due_at = datetime.now(timezone.utc) - timedelta(days=2)
    db_session.commit()

    resp = admin_client.get("/sla/overdue")
    assert resp.status_code == 200
    cve_ids = [row["cve_id"] for row in resp.json()]
    assert "CVE-SLA-0004" in cve_ids
    matching = next(row for row in resp.json() if row["cve_id"] == "CVE-SLA-0004")
    assert matching["days_overdue"] >= 1
