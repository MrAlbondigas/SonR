from unittest.mock import MagicMock, patch

from app import models
from app.main import send_email_alert, notify_alert


def test_send_email_alert_not_configured_logs_failed_attempt(db_session):
    # en los tests SMTP_HOST/ALERT_EMAIL_TO estan vacios por defecto (ver conftest) —
    # el intento debe registrarse igualmente, marcado como no entregado
    success = send_email_alert(db_session, "mensaje de prueba")
    assert success is False

    last = db_session.query(models.Alert).filter(models.Alert.channel == "email").order_by(models.Alert.id.desc()).first()
    assert last is not None
    assert last.success is False
    assert last.description == "mensaje de prueba"


def test_send_email_alert_delivers_when_configured(db_session, monkeypatch):
    monkeypatch.setattr("app.main.SMTP_HOST", "smtp.test.local")
    monkeypatch.setattr("app.main.ALERT_EMAIL_TO", "soc@example.com")

    mock_server = MagicMock()
    mock_smtp_cm = MagicMock()
    mock_smtp_cm.__enter__ = MagicMock(return_value=mock_server)
    mock_smtp_cm.__exit__ = MagicMock(return_value=False)

    with patch("app.main.smtplib.SMTP", return_value=mock_smtp_cm) as mock_smtp:
        success = send_email_alert(db_session, "vulnerabilidad critica detectada")

    assert success is True
    mock_smtp.assert_called_once()
    mock_server.starttls.assert_called_once()
    mock_server.send_message.assert_called_once()

    last = db_session.query(models.Alert).filter(models.Alert.channel == "email").order_by(models.Alert.id.desc()).first()
    assert last.success is True


def test_send_email_alert_logs_failure_when_smtp_raises(db_session, monkeypatch):
    monkeypatch.setattr("app.main.SMTP_HOST", "smtp.test.local")
    monkeypatch.setattr("app.main.ALERT_EMAIL_TO", "soc@example.com")

    with patch("app.main.smtplib.SMTP", side_effect=OSError("connection refused")):
        success = send_email_alert(db_session, "vulnerabilidad critica detectada")

    assert success is False
    last = db_session.query(models.Alert).filter(models.Alert.channel == "email").order_by(models.Alert.id.desc()).first()
    assert last.success is False


def test_notify_alert_tries_both_channels(db_session):
    with patch("app.main.send_webhook_alert", return_value=True) as mock_webhook, \
         patch("app.main.send_email_alert", return_value=False) as mock_email:
        result = notify_alert(db_session, "evento de prueba", vulnerability_id=None, host_id=None)

    assert result is True
    mock_webhook.assert_called_once()
    mock_email.assert_called_once()


def test_email_status_endpoint_reports_not_configured_by_default(client):
    resp = client.get("/email/status")
    assert resp.status_code == 200
    assert resp.json()["configured"] is False


def test_email_test_requires_admin(client):
    resp = client.post("/email/test")
    assert resp.status_code == 401


def test_email_test_as_admin_reports_not_delivered_when_unconfigured(admin_client):
    resp = admin_client.post("/email/test")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["configured"] is False
    assert data["delivered"] is False
