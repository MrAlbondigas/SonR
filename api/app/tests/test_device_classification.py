from app import models
from app.main import classify_device


def make_host(ip="192.168.1.50", vendor=None, os_guess=None, hostname=None, ports=None):
    host = models.Host(ip=ip, vendor=vendor, os_guess=os_guess, hostname=hostname)
    host.software = [
        models.Software(host_id=1, name="svc", port=p, removed_at=None) for p in (ports or [])
    ]
    return host


def test_router_by_ip_ending_in_one():
    host = make_host(ip="192.168.1.1")
    assert classify_device(host)["key"] == "router"


def test_router_by_vendor():
    host = make_host(ip="192.168.1.50", vendor="TP-Link Corporation")
    assert classify_device(host)["key"] == "router"


def test_printer_by_port():
    host = make_host(ip="192.168.1.50", ports=[9100])
    assert classify_device(host)["key"] == "printer"


def test_printer_vendor_overrides_router_ip_heuristic():
    # una impresora en .1 no deberia clasificarse como router
    host = make_host(ip="192.168.1.1", vendor="Hewlett Packard", ports=[9100])
    assert classify_device(host)["key"] == "printer"


def test_windows_by_smb_port():
    host = make_host(ip="192.168.1.50", ports=[445])
    assert classify_device(host)["key"] == "windows"


def test_windows_by_os_guess():
    host = make_host(ip="192.168.1.50", os_guess="Microsoft Windows 10")
    assert classify_device(host)["key"] == "windows"


def test_iot_by_vendor():
    host = make_host(ip="192.168.1.50", vendor="Google Inc.")
    assert classify_device(host)["key"] == "iot"


def test_linux_server_by_multiple_server_ports():
    host = make_host(ip="192.168.1.50", os_guess="Linux 5.x", ports=[22, 80, 3306])
    assert classify_device(host)["key"] == "server"


def test_linux_plain_workstation():
    host = make_host(ip="192.168.1.50", os_guess="Linux 5.x", ports=[22])
    assert classify_device(host)["key"] == "linux"


def test_unknown_with_no_signals():
    host = make_host(ip="192.168.1.50")
    assert classify_device(host)["key"] == "unknown"
