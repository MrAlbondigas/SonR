from unittest.mock import MagicMock, patch

import enricher
from enricher import cpe22_to_23


def _mock_response(status_code, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    return resp


def test_converts_a_normal_nmap_cpe():
    result = cpe22_to_23("cpe:/a:openbsd:openssh:8.9p1")
    assert result == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"


def test_none_when_no_cpe():
    assert cpe22_to_23(None) is None


def test_none_when_empty_string():
    assert cpe22_to_23("") is None


def test_none_when_not_a_cpe_uri():
    assert cpe22_to_23("openssh 8.9p1") is None


def test_none_when_version_missing():
    # nmap a veces solo identifica vendor:product, sin version concreta —
    # sin version no se puede usar cpeName (la API de NVD lo exige)
    assert cpe22_to_23("cpe:/a:openbsd:openssh") is None


def test_none_when_version_is_placeholder():
    assert cpe22_to_23("cpe:/a:openbsd:openssh:-") is None


def test_extra_components_are_discarded_and_repadded_with_wildcards():
    # nmap a veces incluye un quinto componente (update/edition); nos quedamos solo con
    # part:vendor:product:version y repadeamos el resto a comodines en formato 2.3
    result = cpe22_to_23("cpe:/a:apache:http_server:2.4.41:.")
    assert result == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"


# --- query_nvd_by_cpe: distingue "CPE desconocido" de "CPE conocido y confirmado limpio" ---
# (comprobado contra la API real de NVD: ambos casos devuelven 404 con isVulnerable=true,
# asi que hace falta una primera consulta sin filtrar para poder diferenciarlos)


@patch("enricher.time.sleep", return_value=None)
@patch("enricher.requests.get")
def test_cpe_query_returns_none_when_nvd_does_not_recognize_the_cpe(mock_get, mock_sleep):
    mock_get.return_value = _mock_response(404)
    result = enricher.query_nvd_by_cpe("cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*")
    assert result is None
    assert mock_get.call_count == 1  # no debe gastar una segunda peticion si el CPE base ya no existe


@patch("enricher.time.sleep", return_value=None)
@patch("enricher.requests.get")
def test_cpe_query_returns_empty_list_when_cpe_known_but_confirmed_not_vulnerable(mock_get, mock_sleep):
    mock_get.side_effect = [_mock_response(200, {"vulnerabilities": []}), _mock_response(404)]
    result = enricher.query_nvd_by_cpe("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
    assert result == []
    assert mock_get.call_count == 2


@patch("enricher.time.sleep", return_value=None)
@patch("enricher.requests.get")
def test_cpe_query_returns_vulnerabilities_when_confirmed_vulnerable(mock_get, mock_sleep):
    vuln_payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-0001", "descriptions": [{"lang": "en", "value": "desc"}], "metrics": {}}}
        ]
    }
    mock_get.side_effect = [_mock_response(200, {"vulnerabilities": []}), _mock_response(200, vuln_payload)]
    result = enricher.query_nvd_by_cpe("cpe:2.3:a:openbsd:openssh:7.2p2:*:*:*:*:*:*:*")
    assert len(result) == 1
    assert result[0]["cve_id"] == "CVE-2024-0001"


@patch("enricher.time.sleep", return_value=None)
@patch("enricher.requests.get")
def test_cpe_query_returns_none_on_unexpected_error_status(mock_get, mock_sleep):
    mock_get.return_value = _mock_response(500)
    result = enricher.query_nvd_by_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
    assert result is None
