import os
from unittest.mock import patch, MagicMock

os.environ.setdefault("PROYECTO_CYBER_API_KEY", "test-key")
os.environ.setdefault("PROYECTO_CYBER_URL", "http://api:8000")

import server  # noqa: E402


def _mock_export_response(data):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


SAMPLE_EXPORT = {
    "generated_at": "2026-09-29T10:00:00+00:00",
    "host_count": 12,
    "network_risk_score": 47,
    "credential_findings_count": 2,
    "sla_overdue_count": 3,
    "hosts": [
        {"ip": "192.168.0.10", "hostname": "server-1", "tags": ["produccion"], "risk_score": 20, "risk_level": "Alto"},
    ],
    "open_vulnerabilities": [
        {"cve_id": "CVE-2024-0001", "cvss": 9.8, "severity": "critical", "known_exploited": True,
         "host_ip": "192.168.0.10", "software": "openssh", "detected_at": "2026-09-01T00:00:00+00:00",
         "sla_due_at": "2026-09-08T00:00:00+00:00"},
    ],
    "group_risk": [
        {"tag": "produccion", "host_count": 1, "total_score": 20, "avg_score": 20, "open_vulns": 1, "credential_findings": 0},
    ],
    "cis_compliance": [
        {"id": "CIS 1", "name": "Inventario y control de activos empresariales", "ok": True, "detail": "12 equipo(s) inventariado(s)."},
        {"id": "CIS 7", "name": "Gestion continua de vulnerabilidades", "ok": False, "detail": "1 vulnerabilidad(es) critica(s) abierta(s)."},
    ],
}


def test_resumen_seguridad_extracts_top_level_fields():
    with patch("server.requests.get", return_value=_mock_export_response(SAMPLE_EXPORT)) as mock_get:
        result = server.resumen_seguridad()

    mock_get.assert_called_once()
    called_url = mock_get.call_args.args[0]
    assert called_url == "http://api:8000/api/v1/export"
    called_headers = mock_get.call_args.kwargs["headers"]
    assert called_headers["X-API-Key"] == "test-key"

    assert result == {
        "generado_en": "2026-09-29T10:00:00+00:00",
        "equipos_monitorizados": 12,
        "puntuacion_riesgo_total": 47,
        "credenciales_por_defecto_encontradas": 2,
        "vulnerabilidades_fuera_de_plazo": 3,
    }


def test_listar_equipos_returns_hosts_list():
    with patch("server.requests.get", return_value=_mock_export_response(SAMPLE_EXPORT)):
        result = server.listar_equipos()
    assert result == SAMPLE_EXPORT["hosts"]


def test_listar_vulnerabilidades_abiertas_returns_open_vulns():
    with patch("server.requests.get", return_value=_mock_export_response(SAMPLE_EXPORT)):
        result = server.listar_vulnerabilidades_abiertas()
    assert result == SAMPLE_EXPORT["open_vulnerabilities"]
    assert result[0]["cve_id"] == "CVE-2024-0001"


def test_riesgo_por_grupo_returns_group_risk():
    with patch("server.requests.get", return_value=_mock_export_response(SAMPLE_EXPORT)):
        result = server.riesgo_por_grupo()
    assert result == SAMPLE_EXPORT["group_risk"]


def test_estado_cumplimiento_returns_cis_compliance():
    with patch("server.requests.get", return_value=_mock_export_response(SAMPLE_EXPORT)):
        result = server.estado_cumplimiento()
    assert result == SAMPLE_EXPORT["cis_compliance"]
    assert any(c["ok"] is False for c in result)


def test_fetch_export_raises_on_http_error():
    resp = MagicMock()
    resp.raise_for_status.side_effect = server.requests.exceptions.HTTPError("401")
    with patch("server.requests.get", return_value=resp):
        try:
            server._fetch_export()
            assert False, "esperaba que lanzara HTTPError"
        except server.requests.exceptions.HTTPError:
            pass
