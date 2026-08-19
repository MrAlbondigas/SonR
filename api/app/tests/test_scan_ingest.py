def test_ingest_requires_scanner_key(client):
    resp = client.post("/scan/ingest", json={"hosts": []})
    assert resp.status_code == 401


def test_ingest_creates_new_host(client, scanner_headers):
    payload = {
        "hosts": [
            {
                "ip": "10.99.0.1",
                "mac": "AA:BB:CC:DD:EE:01",
                "hostname": "test-host",
                "os_guess": "Linux 5.x",
                "software": [{"name": "OpenSSH", "version": "8.9", "port": 22}],
            }
        ]
    }
    resp = client.post("/scan/ingest", headers=scanner_headers, json=payload)
    assert resp.status_code == 200
    assert resp.json()["hosts_ingested"] == 1

    hosts = client.get("/hosts").json()
    matching = [h for h in hosts if h["ip"] == "10.99.0.1"]
    assert len(matching) == 1
    assert matching[0]["software_count"] == 1


def test_ingest_same_host_twice_does_not_duplicate(client, scanner_headers):
    payload = {
        "hosts": [
            {"ip": "10.99.0.2", "software": [{"name": "nginx", "version": "1.25", "port": 80}]}
        ]
    }
    client.post("/scan/ingest", headers=scanner_headers, json=payload)
    client.post("/scan/ingest", headers=scanner_headers, json=payload)

    hosts = client.get("/hosts").json()
    matching = [h for h in hosts if h["ip"] == "10.99.0.2"]
    assert len(matching) == 1
    assert matching[0]["software_count"] == 1


def test_service_removed_only_after_three_consecutive_misses(client, scanner_headers):
    ip = "10.99.0.3"
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "ftp", "version": "1.0", "port": 21}]}]},
    )

    # dos ciclos seguidos sin ver el servicio: todavia no deberia darse por retirado
    # (evita falsos positivos por un escaneo puntual que falla)
    for _ in range(2):
        client.post("/scan/ingest", headers=scanner_headers, json={"hosts": [{"ip": ip, "software": []}]})
    still_there = [h for h in client.get("/hosts").json() if h["ip"] == ip][0]
    assert still_there["software_count"] == 1

    # tercer ciclo consecutivo sin verlo: ahora si se marca como retirado
    client.post("/scan/ingest", headers=scanner_headers, json={"hosts": [{"ip": ip, "software": []}]})
    removed = [h for h in client.get("/hosts").json() if h["ip"] == ip][0]
    assert removed["software_count"] == 0


def test_service_reappearing_resets_the_miss_counter(client, scanner_headers):
    ip = "10.99.0.4"
    with_service = {"hosts": [{"ip": ip, "software": [{"name": "telnet", "version": None, "port": 23}]}]}
    without_service = {"hosts": [{"ip": ip, "software": []}]}

    client.post("/scan/ingest", headers=scanner_headers, json=with_service)
    client.post("/scan/ingest", headers=scanner_headers, json=without_service)
    client.post("/scan/ingest", headers=scanner_headers, json=with_service)  # reaparece: el contador se reinicia
    client.post("/scan/ingest", headers=scanner_headers, json=without_service)
    client.post("/scan/ingest", headers=scanner_headers, json=without_service)

    # solo 2 fallos consecutivos desde que reapareciera: todavia deberia seguir activo
    still_there = [h for h in client.get("/hosts").json() if h["ip"] == ip][0]
    assert still_there["software_count"] == 1
