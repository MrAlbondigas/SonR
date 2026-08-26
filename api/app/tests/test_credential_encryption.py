from sqlalchemy import text

from app import models
from app.crypto import EncryptedString


def _ingest_host(client, scanner_headers, ip):
    client.post(
        "/scan/ingest",
        headers=scanner_headers,
        json={"hosts": [{"ip": ip, "software": [{"name": "TestSoft", "version": "1.0", "port": 22}]}]},
    )


def test_encrypted_string_round_trips(monkeypatch):
    coltype = EncryptedString()
    plaintext = "SuperSecreta123!"
    stored = coltype.process_bind_param(plaintext, dialect=None)
    assert stored != plaintext
    assert coltype.process_result_value(stored, dialect=None) == plaintext


def test_encrypted_string_returns_legacy_plaintext_unchanged():
    # datos guardados antes de activar el cifrado no son un token Fernet valido:
    # deben devolverse tal cual, no reventar
    coltype = EncryptedString()
    assert coltype.process_result_value("plaintext-legado", dialect=None) == "plaintext-legado"


def test_ssh_credential_password_encrypted_at_rest(admin_client, scanner_headers, db_session):
    _ingest_host(admin_client, scanner_headers, "10.99.0.60")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.60").first()

    resp = admin_client.post(
        f"/hosts/{host.id}/ssh-credentials", json={"username": "root", "password": "PlainPass123!"}
    )
    assert resp.status_code == 200

    db_session.expire_all()
    cred = db_session.query(models.SSHCredential).filter(models.SSHCredential.host_id == host.id).first()
    assert cred.password == "PlainPass123!"  # la ORM descifra de forma transparente

    raw = db_session.execute(
        text("select password from ssh_credentials where host_id = :hid"), {"hid": host.id}
    ).scalar()
    assert raw != "PlainPass123!"
    assert "PlainPass123!" not in raw


def test_credential_finding_password_encrypted_at_rest(admin_client, scanner_headers, db_session):
    _ingest_host(admin_client, scanner_headers, "10.99.0.61")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.61").first()

    resp = admin_client.post(
        "/credentials/ingest",
        headers=scanner_headers,
        json={"host_id": host.id, "port": 21, "service": "ftp", "username": "admin", "password": "ftp-pass"},
    )
    assert resp.status_code == 200

    db_session.expire_all()
    finding = (
        db_session.query(models.CredentialFinding).filter(models.CredentialFinding.host_id == host.id).first()
    )
    assert finding.password == "ftp-pass"

    raw = db_session.execute(
        text("select password from credential_findings where id = :fid"), {"fid": finding.id}
    ).scalar()
    assert raw != "ftp-pass"
    assert "ftp-pass" not in raw


def test_ssh_credential_update_re_encrypts_new_password(admin_client, scanner_headers, db_session):
    _ingest_host(admin_client, scanner_headers, "10.99.0.62")
    host = db_session.query(models.Host).filter(models.Host.ip == "10.99.0.62").first()

    admin_client.post(f"/hosts/{host.id}/ssh-credentials", json={"username": "root", "password": "first-pass"})
    admin_client.post(f"/hosts/{host.id}/ssh-credentials", json={"username": "root", "password": "second-pass"})

    db_session.expire_all()
    cred = db_session.query(models.SSHCredential).filter(models.SSHCredential.host_id == host.id).first()
    assert cred.password == "second-pass"

    raw = db_session.execute(
        text("select password from ssh_credentials where host_id = :hid"), {"hid": host.id}
    ).scalar()
    assert "second-pass" not in raw
    assert "first-pass" not in raw
