from unittest.mock import patch

from app import models
from app.main import notify_alert


def _ingest_host(client, scanner_headers, ip):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "RouteTestSoft", "version": "1.0", "port": 8080}]}]},
    )


def test_set_route_requires_admin(client):
    resp = client.post("/tags/produccion/alert-route", json={"webhook_url": "https://x.example.com"})
    assert resp.status_code == 401


def test_get_alert_routes_requires_admin(client):
    resp = client.get("/alert-routes")
    assert resp.status_code == 401


def test_admin_can_set_and_read_route(admin_client):
    resp = admin_client.post(
        "/tags/produccion-route-t1/alert-route",
        json={"webhook_url": "https://hooks.example.com/prod", "email_to": "prod-team@example.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["webhook_url"] == "https://hooks.example.com/prod"
    assert data["email_to"] == "prod-team@example.com"

    listed = {r["tag"]: r for r in admin_client.get("/alert-routes").json()}
    assert listed["produccion-route-t1"]["webhook_url"] == "https://hooks.example.com/prod"


def test_setting_route_with_both_fields_empty_deletes_it(admin_client):
    admin_client.post(
        "/tags/temp-route-t2/alert-route", json={"webhook_url": "https://x.example.com", "email_to": None}
    )
    resp = admin_client.post("/tags/temp-route-t2/alert-route", json={"webhook_url": "", "email_to": ""})
    assert resp.status_code == 200
    assert resp.json()["webhook_url"] is None

    listed = {r["tag"]: r for r in admin_client.get("/alert-routes").json()}
    assert "temp-route-t2" not in listed


def test_delete_route_removes_it(admin_client):
    admin_client.post("/tags/delete-route-t3/alert-route", json={"webhook_url": "https://x.example.com"})
    resp = admin_client.delete("/tags/delete-route-t3/alert-route")
    assert resp.status_code == 200

    listed = {r["tag"]: r for r in admin_client.get("/alert-routes").json()}
    assert "delete-route-t3" not in listed


def test_notify_alert_fans_out_to_tag_route_without_replacing_global(admin_client, scanner_headers, db_session):
    ip = "10.99.0.97"
    _ingest_host(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    admin_client.post(f"/hosts/{host.id}/tags", json={"tags": ["produccion-route-t4"]})
    admin_client.post(
        "/tags/produccion-route-t4/alert-route",
        json={"webhook_url": "https://hooks.example.com/prod-t4", "email_to": None},
    )

    with patch("app.main.send_webhook_alert", return_value=True) as mock_webhook, \
         patch("app.main.send_email_alert", return_value=True) as mock_email:
        notify_alert(db_session, "mensaje de prueba", host_id=host.id)

    webhook_calls = mock_webhook.call_args_list
    # una llamada "global" (sin webhook_url propio) y otra dirigida al webhook de la etiqueta
    assert any(c.kwargs.get("webhook_url") is None for c in webhook_calls)
    assert any(
        c.kwargs.get("webhook_url") == "https://hooks.example.com/prod-t4"
        and c.kwargs.get("channel") == "webhook:produccion-route-t4"
        for c in webhook_calls
    )
    # el email no tenia destino propio en esta etiqueta: solo la llamada global
    assert mock_email.call_count == 1


def test_notify_alert_without_matching_route_only_sends_global(admin_client, scanner_headers, db_session):
    ip = "10.99.0.98"
    _ingest_host(admin_client, scanner_headers, ip)
    host = db_session.query(models.Host).filter(models.Host.ip == ip).first()
    admin_client.post(f"/hosts/{host.id}/tags", json={"tags": ["sin-ruta-configurada"]})

    with patch("app.main.send_webhook_alert", return_value=True) as mock_webhook, \
         patch("app.main.send_email_alert", return_value=True) as mock_email:
        notify_alert(db_session, "mensaje de prueba", host_id=host.id)

    assert mock_webhook.call_count == 1
    assert mock_email.call_count == 1
