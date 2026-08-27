def test_get_scan_policy_defaults(client):
    resp = client.get("/scan/policy")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is True
    assert data["interval_seconds"] == 300
    assert data["excluded_ips"] == []


def test_admin_can_update_policy(admin_client):
    resp = admin_client.post(
        "/scan/policy",
        json={
            "enabled": False,
            "interval_seconds": 900,
            "excluded_ips": ["10.0.0.5", "10.0.0.5", " 10.0.0.6 "],
            "quiet_hours_start": 22,
            "quiet_hours_end": 6,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is False
    assert data["interval_seconds"] == 900
    assert sorted(data["excluded_ips"]) == ["10.0.0.5", "10.0.0.6"]  # dedupe + trim

    resp2 = admin_client.get("/scan/policy")
    assert resp2.json()["interval_seconds"] == 900

    # devolvemos la politica a un estado neutro para no afectar a otros tests
    admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )


def test_interval_out_of_bounds_rejected(admin_client):
    resp = admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 10,  # por debajo del minimo de 60
            "excluded_ips": [],
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
    assert resp.status_code == 400


def test_invalid_quiet_hour_rejected(admin_client):
    resp = admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "quiet_hours_start": 25,
            "quiet_hours_end": 5,
        },
    )
    assert resp.status_code == 400


def test_admin_can_set_extra_networks(admin_client):
    resp = admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "extra_networks": ["10.20.0.0/24", "10.20.0.0/24", " 192.168.99.0/24 "],
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
    assert resp.status_code == 200
    assert sorted(resp.json()["extra_networks"]) == ["10.20.0.0/24", "192.168.99.0/24"]  # dedupe + trim

    # limpieza para no afectar a otros tests
    admin_client.post(
        "/scan/policy",
        json={"enabled": True, "interval_seconds": 300, "excluded_ips": [], "extra_networks": [], "quiet_hours_start": None, "quiet_hours_end": None},
    )


def test_extra_network_rejects_public_range(admin_client):
    resp = admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "extra_networks": ["8.8.8.0/24"],
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
    assert resp.status_code == 400
    assert "privado" in resp.json()["detail"].lower()


def test_extra_network_rejects_malformed_cidr(admin_client):
    resp = admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "extra_networks": ["not-a-network"],
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
    assert resp.status_code == 400


def test_extra_network_rejects_range_too_large(admin_client):
    resp = admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "extra_networks": ["10.0.0.0/8"],  # mas grande que el maximo permitido (/16)
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
    assert resp.status_code == 400


def test_extra_network_rejects_too_many_entries(admin_client):
    many_networks = [f"10.{i}.0.0/24" for i in range(15)]
    resp = admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "extra_networks": many_networks,
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
    assert resp.status_code == 400


def test_scan_request_rejected_when_policy_disabled(admin_client):
    admin_client.post(
        "/scan/policy",
        json={
            "enabled": False,
            "interval_seconds": 300,
            "excluded_ips": [],
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
    resp = admin_client.post("/scan/request")
    assert resp.status_code == 409

    # reactivamos para no dejar el escaneo apagado para el resto de tests
    admin_client.post(
        "/scan/policy",
        json={
            "enabled": True,
            "interval_seconds": 300,
            "excluded_ips": [],
            "quiet_hours_start": None,
            "quiet_hours_end": None,
        },
    )
