from unittest.mock import patch

import scanner


def test_strip_dpkg_epoch_removes_numeric_prefix():
    # visto en produccion: dpkg-query devolvio "1:9.6p1-3ubuntu13.18" para openssh-server,
    # y el "1:" (epoch) contaminaba el CPE reconstruido si no se quitaba antes
    assert scanner.strip_dpkg_epoch("1:9.6p1-3ubuntu13.18") == "9.6p1-3ubuntu13.18"


def test_strip_dpkg_epoch_leaves_version_without_epoch_untouched():
    assert scanner.strip_dpkg_epoch("2.4.41-4+deb11u1") == "2.4.41-4+deb11u1"


def test_strip_dpkg_epoch_does_not_touch_non_numeric_prefix():
    # un ':' que no sea un epoch numerico no debe recortarse
    assert scanner.strip_dpkg_epoch("something:weird") == "something:weird"


def test_guess_package_name_matches_known_service():
    assert scanner.guess_package_name("OpenSSH") == "openssh-server"


def test_guess_package_name_is_case_insensitive_and_substring():
    assert scanner.guess_package_name("Apache httpd 2.4.41 ((Ubuntu))") == "apache2"


def test_guess_package_name_none_for_unknown_service():
    assert scanner.guess_package_name("some-custom-thing") is None


def test_substitute_cpe_version_normal_case():
    result = scanner.substitute_cpe_version("cpe:/a:openbsd:openssh:9.6", "9.6p1-3ubuntu13.18")
    assert result == "cpe:/a:openbsd:openssh:9.6p1"


def test_substitute_cpe_version_strips_distro_suffixes():
    result = scanner.substitute_cpe_version("cpe:/a:apache:http_server:2.4", "2.4.41-4+deb11u1")
    assert result == "cpe:/a:apache:http_server:2.4.41"


def test_substitute_cpe_version_none_without_existing_cpe():
    assert scanner.substitute_cpe_version(None, "1.2.3") is None


def test_substitute_cpe_version_none_for_malformed_cpe():
    assert scanner.substitute_cpe_version("not-a-cpe", "1.2.3") is None


def test_refine_updates_matching_software_with_verified_version():
    # version con epoch de dpkg, tal como se vio en produccion (ver strip_dpkg_epoch)
    host_data = {
        "ip": "10.0.0.5",
        "software": [
            {"name": "OpenSSH", "version": "9.6", "port": 22, "cpe": "cpe:/a:openbsd:openssh:9.6", "version_source": "network"}
        ],
    }
    with patch("scanner.verify_installed_version", return_value="1:9.6p1-3ubuntu13.18"):
        scanner.refine_with_authenticated_check(host_data, {"username": "admin", "password": "x"})

    sw = host_data["software"][0]
    assert sw["version"] == "9.6p1-3ubuntu13.18"
    assert sw["version_source"] == "authenticated"
    assert sw["cpe"] == "cpe:/a:openbsd:openssh:9.6p1"


def test_refine_skips_services_without_a_known_package():
    host_data = {
        "ip": "10.0.0.5",
        "software": [{"name": "totally-unknown-service", "version": "1.0", "port": 9999, "cpe": None, "version_source": "network"}],
    }
    with patch("scanner.verify_installed_version") as mock_verify:
        scanner.refine_with_authenticated_check(host_data, {"username": "admin", "password": "x"})
        mock_verify.assert_not_called()

    assert host_data["software"][0]["version_source"] == "network"


def test_refine_leaves_software_unchanged_when_ssh_verification_fails():
    host_data = {
        "ip": "10.0.0.5",
        "software": [{"name": "OpenSSH", "version": "9.6", "port": 22, "cpe": "cpe:/a:openbsd:openssh:9.6", "version_source": "network"}],
    }
    with patch("scanner.verify_installed_version", return_value=None):
        scanner.refine_with_authenticated_check(host_data, {"username": "admin", "password": "x"})

    sw = host_data["software"][0]
    assert sw["version"] == "9.6"
    assert sw["version_source"] == "network"


def test_run_scan_cycle_discovers_hosts_across_local_subnet_and_extra_networks():
    def fake_discover(net, excluded_ips=None):
        return {
            "192.168.1.0/24": ["192.168.1.10", "192.168.1.11"],
            "10.20.0.0/24": ["10.20.0.5"],
        }.get(net, [])

    with patch("scanner.local_subnet", return_value="192.168.1.0/24"), \
         patch("scanner.discover_hosts", side_effect=fake_discover), \
         patch("scanner.scan_host", return_value={"ip": "x", "software": []}) as mock_scan_host, \
         patch("scanner.fetch_ssh_credentials", return_value={}), \
         patch("scanner.requests.post") as mock_post:
        mock_post.return_value.raise_for_status = lambda: None
        mock_post.return_value.json = lambda: {"ok": True}
        scanner.run_scan_cycle(extra_networks=["10.20.0.0/24"])

    scanned_ips = {call.args[0] for call in mock_scan_host.call_args_list}
    assert scanned_ips == {"192.168.1.10", "192.168.1.11", "10.20.0.5"}


def test_run_scan_cycle_dedupes_host_seen_in_multiple_networks():
    def fake_discover(net, excluded_ips=None):
        # el mismo host aparece "visible" desde dos redes distintas (solapamiento real
        # de rangos configurados por error, o un host con rutas hacia ambas redes)
        return ["192.168.1.10"]

    with patch("scanner.local_subnet", return_value="192.168.1.0/24"), \
         patch("scanner.discover_hosts", side_effect=fake_discover), \
         patch("scanner.scan_host", return_value={"ip": "x", "software": []}) as mock_scan_host, \
         patch("scanner.fetch_ssh_credentials", return_value={}), \
         patch("scanner.requests.post") as mock_post:
        mock_post.return_value.raise_for_status = lambda: None
        mock_post.return_value.json = lambda: {"ok": True}
        scanner.run_scan_cycle(extra_networks=["10.20.0.0/24"])

    assert mock_scan_host.call_count == 1


def test_run_scan_cycle_skips_extra_network_equal_to_local_subnet():
    with patch("scanner.local_subnet", return_value="192.168.1.0/24"), \
         patch("scanner.discover_hosts", return_value=[]) as mock_discover, \
         patch("scanner.fetch_ssh_credentials", return_value={}), \
         patch("scanner.requests.post") as mock_post:
        mock_post.return_value.raise_for_status = lambda: None
        mock_post.return_value.json = lambda: {"ok": True}
        scanner.run_scan_cycle(extra_networks=["192.168.1.0/24"])

    # no debe escanear la misma red dos veces solo porque tambien aparezca como "extra"
    assert mock_discover.call_count == 1
