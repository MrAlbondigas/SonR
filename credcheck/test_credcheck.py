from unittest.mock import MagicMock, patch

import credcheck


def test_credentials_for_unknown_vendor_returns_generic_list_unchanged():
    result = credcheck.credentials_for("Some Random Manufacturer Inc.")
    assert result == credcheck.GENERIC_CREDS


def test_credentials_for_none_vendor_returns_generic_list():
    assert credcheck.credentials_for(None) == credcheck.GENERIC_CREDS


def test_credentials_for_known_vendor_prioritizes_vendor_creds():
    result = credcheck.credentials_for("TP-Link Corporation")
    assert result[: len(credcheck.VENDOR_CREDS["tp-link"])] == credcheck.VENDOR_CREDS["tp-link"]


def test_credentials_for_vendor_match_is_case_insensitive_substring():
    result = credcheck.credentials_for("Ubiquiti Networks Inc.")
    assert result[0] == ("ubnt", "ubnt")


def test_credentials_for_does_not_duplicate_creds_present_in_both_lists():
    result = credcheck.credentials_for("Dahua Technology")
    # ("admin","admin") esta tanto en la lista de dahua como en la generica: no debe repetirse
    assert result.count(("admin", "admin")) == 1


def test_credentials_for_unknown_vendor_still_includes_full_generic_list():
    result = credcheck.credentials_for("Completely Unknown Vendor XYZ")
    assert len(result) == len(credcheck.GENERIC_CREDS)


def _mock_socket(responses):
    sock = MagicMock()
    sock.recv.side_effect = responses
    return sock


@patch("credcheck.socket.create_connection")
def test_try_telnet_detects_success_prompt(mock_conn):
    mock_conn.return_value = _mock_socket([b"login: ", b"Password: ", b"root@device:~# "])
    result = credcheck.try_telnet("10.0.0.1", 23, [("admin", "admin")])
    assert result == ("admin", "admin")


@patch("credcheck.socket.create_connection")
def test_try_telnet_skips_credential_on_failure_hint_and_tries_next(mock_conn):
    mock_conn.side_effect = [
        _mock_socket([b"login: ", b"Password: ", b"Login incorrect\r\n"]),
        _mock_socket([b"login: ", b"Password: ", b"root@device:~# "]),
    ]
    result = credcheck.try_telnet("10.0.0.1", 23, [("admin", "wrong"), ("admin", "admin")])
    assert result == ("admin", "admin")
    assert mock_conn.call_count == 2


@patch("credcheck.socket.create_connection")
def test_try_telnet_returns_none_when_connection_fails(mock_conn):
    mock_conn.side_effect = OSError("connection refused")
    result = credcheck.try_telnet("10.0.0.1", 23, [("admin", "admin")])
    assert result is None


@patch("credcheck.socket.create_connection")
def test_try_telnet_returns_none_when_no_credentials_match(mock_conn):
    mock_conn.return_value = _mock_socket([b"login: ", b"Password: ", b"Login incorrect\r\n"])
    result = credcheck.try_telnet("10.0.0.1", 23, [("admin", "admin")])
    assert result is None
