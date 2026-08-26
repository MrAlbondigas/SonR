from app import models


def _ingest_host(client, scanner_headers, ip):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "TagTestSoft", "version": "1.0", "port": 8080}]}]},
    )


def _get_host(db_session, ip):
    return db_session.query(models.Host).filter(models.Host.ip == ip).first()


def test_set_tags_requires_admin(client, scanner_headers, db_session):
    _ingest_host(client, scanner_headers, "10.99.0.70")
    host = _get_host(db_session, "10.99.0.70")

    resp = client.post(f"/hosts/{host.id}/tags", json={"tags": ["produccion"]})
    assert resp.status_code == 401


def test_admin_can_set_and_replace_tags(admin_client, scanner_headers, db_session):
    _ingest_host(admin_client, scanner_headers, "10.99.0.71")
    host = _get_host(db_session, "10.99.0.71")

    resp = admin_client.post(f"/hosts/{host.id}/tags", json={"tags": ["produccion", "finanzas"]})
    assert resp.status_code == 200
    assert sorted(resp.json()["tags"]) == ["finanzas", "produccion"]

    db_session.expire_all()
    host = _get_host(db_session, "10.99.0.71")
    assert sorted(t.tag for t in host.tags) == ["finanzas", "produccion"]

    # reemplaza el conjunto completo, no lo acumula
    resp2 = admin_client.post(f"/hosts/{host.id}/tags", json={"tags": ["sede-madrid"]})
    assert resp2.json()["tags"] == ["sede-madrid"]
    db_session.expire_all()
    host = _get_host(db_session, "10.99.0.71")
    assert [t.tag for t in host.tags] == ["sede-madrid"]


def test_tags_are_deduped_and_trimmed(admin_client, scanner_headers, db_session):
    _ingest_host(admin_client, scanner_headers, "10.99.0.72")
    host = _get_host(db_session, "10.99.0.72")

    resp = admin_client.post(
        f"/hosts/{host.id}/tags",
        json={"tags": [" produccion ", "produccion", "", "   ", "finanzas"]},
    )
    assert sorted(resp.json()["tags"]) == ["finanzas", "produccion"]


def test_tags_capped_at_max_count(admin_client, scanner_headers, db_session):
    _ingest_host(admin_client, scanner_headers, "10.99.0.73")
    host = _get_host(db_session, "10.99.0.73")

    many_tags = [f"tag{i}" for i in range(15)]
    resp = admin_client.post(f"/hosts/{host.id}/tags", json={"tags": many_tags})
    assert len(resp.json()["tags"]) == 10


def test_tag_length_is_truncated(admin_client, scanner_headers, db_session):
    _ingest_host(admin_client, scanner_headers, "10.99.0.74")
    host = _get_host(db_session, "10.99.0.74")

    long_tag = "x" * 100
    resp = admin_client.post(f"/hosts/{host.id}/tags", json={"tags": [long_tag]})
    assert len(resp.json()["tags"][0]) == 40


def test_set_tags_for_nonexistent_host_returns_404(admin_client):
    resp = admin_client.post("/hosts/999999/tags", json={"tags": ["x"]})
    assert resp.status_code == 404


def test_list_tag_groups_requires_admin(client):
    resp = client.get("/tags")
    assert resp.status_code == 401


def test_hosts_without_tags_are_excluded_from_groups(admin_client, scanner_headers, db_session):
    _ingest_host(admin_client, scanner_headers, "10.99.0.75")

    resp = admin_client.get("/tags")
    assert resp.status_code == 200
    assert all(g["tag"] != "" for g in resp.json())


def test_list_tag_groups_aggregates_risk_across_hosts_with_shared_tag(admin_client, scanner_headers, db_session):
    ip_a, ip_b = "10.99.0.76", "10.99.0.77"
    _ingest_host(admin_client, scanner_headers, ip_a)
    _ingest_host(admin_client, scanner_headers, ip_b)
    host_a = _get_host(db_session, ip_a)
    host_b = _get_host(db_session, ip_b)

    # nombres de etiqueta unicos para este test: la agregacion cuenta TODOS los equipos
    # con esa etiqueta en la base de datos compartida entre tests, asi que un nombre
    # generico como "produccion" se contaminaria con lo que dejen otros tests
    admin_client.post(f"/hosts/{host_a.id}/tags", json={"tags": ["produccion-t76"]})
    admin_client.post(f"/hosts/{host_b.id}/tags", json={"tags": ["produccion-t76", "finanzas-t76"]})

    software_a = db_session.query(models.Software).filter(models.Software.host_id == host_a.id).first()
    vuln = models.Vulnerability(software_id=software_a.id, cve_id="CVE-TAG-0001", severity="critical", cvss=9.8)
    db_session.add(vuln)
    db_session.commit()

    resp = admin_client.get("/tags")
    assert resp.status_code == 200
    by_tag = {g["tag"]: g for g in resp.json()}

    assert by_tag["produccion-t76"]["host_count"] == 2
    assert by_tag["produccion-t76"]["open_vulns"] == 1
    assert by_tag["produccion-t76"]["total_score"] == 10  # SEVERITY_WEIGHTS["critical"]

    assert by_tag["finanzas-t76"]["host_count"] == 1
    assert by_tag["finanzas"]["total_score"] == 0
