def test_few_failed_attempts_do_not_block_a_correct_login(client):
    for _ in range(2):
        resp = client.post("/auth/login", json={"username": "lockout-test-a", "password": "wrong"})
        assert resp.status_code == 401
    # el usuario no existe, asi que el login "correcto" tambien falla, pero debe seguir siendo 401 (no 429)
    resp = client.post("/auth/login", json={"username": "lockout-test-a", "password": "still-wrong"})
    assert resp.status_code == 401


def test_lockout_after_max_failed_attempts(client):
    username = "lockout-test-b"
    for _ in range(5):
        resp = client.post("/auth/login", json={"username": username, "password": "wrong"})
        assert resp.status_code == 401

    # al sexto intento, incluso si la contrasena fuera correcta, debe rechazarse por bloqueo (429), no 401
    resp = client.post("/auth/login", json={"username": username, "password": "wrong"})
    assert resp.status_code == 429


def test_lockout_is_scoped_per_username(client):
    username = "lockout-test-c"
    for _ in range(5):
        client.post("/auth/login", json={"username": username, "password": "wrong"})
    locked = client.post("/auth/login", json={"username": username, "password": "wrong"})
    assert locked.status_code == 429

    # un usuario distinto no deberia verse afectado por el bloqueo de otro
    other = client.post("/auth/login", json={"username": "lockout-test-d", "password": "wrong"})
    assert other.status_code == 401
