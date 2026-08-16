import os
import subprocess
import time
import xml.etree.ElementTree as ET

import requests

API_URL = os.environ.get("API_URL", "http://localhost:8000")
API_KEY = os.environ["SCANNER_API_KEY"]
SCAN_INTERVAL_SECONDS = int(os.environ.get("SCAN_INTERVAL_SECONDS", "300"))


def local_subnet() -> str | None:
    out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        iface, cidr = parts[1], parts[3]
        if iface == "lo":
            continue
        return cidr
    return None


def discover_hosts(subnet: str) -> list[str]:
    xml_out = subprocess.run(
        ["nmap", "-sn", subnet, "-oX", "-"], capture_output=True, text=True
    ).stdout
    root = ET.fromstring(xml_out)
    ips = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = host.find("address")
        if addr is not None:
            ips.append(addr.get("addr"))
    return ips


def scan_host(ip: str) -> dict:
    xml_out = subprocess.run(
        ["nmap", "-sV", "-O", "-T4", "--top-ports", "100", ip, "-oX", "-"],
        capture_output=True,
        text=True,
    ).stdout
    root = ET.fromstring(xml_out)
    host_el = root.find("host")
    if host_el is None:
        return {"ip": ip, "software": []}

    mac = None
    hostname = None
    for addr in host_el.findall("address"):
        if addr.get("addrtype") == "mac":
            mac = addr.get("addr")
    hn = host_el.find("hostnames/hostname")
    if hn is not None:
        hostname = hn.get("name")

    os_guess = None
    os_el = host_el.find("os/osmatch")
    if os_el is not None:
        os_guess = os_el.get("name")

    software = []
    for port in host_el.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        if service is None:
            continue
        name = service.get("product") or service.get("name") or "unknown"
        version = service.get("version")
        software.append({"name": name, "version": version, "port": int(port.get("portid"))})

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "os_guess": os_guess,
        "software": software,
    }


def run_scan_cycle():
    subnet = local_subnet()
    if not subnet:
        print("No se pudo determinar la subred local, saltando ciclo")
        return

    print(f"Escaneando subred {subnet}...")
    live_ips = discover_hosts(subnet)
    print(f"{len(live_ips)} hosts activos encontrados")

    hosts_payload = [scan_host(ip) for ip in live_ips]

    resp = requests.post(
        f"{API_URL}/scan/ingest",
        json={"hosts": hosts_payload},
        headers={"X-API-Key": API_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    print(f"Ingesta OK: {resp.json()}")


def check_manual_trigger() -> bool:
    try:
        resp = requests.get(f"{API_URL}/scan/pending", headers={"X-API-Key": API_KEY}, timeout=10)
        resp.raise_for_status()
        return resp.json().get("pending", False)
    except Exception:
        return False


def wait_for_next_cycle():
    """Duerme hasta el siguiente ciclo, pero revisa cada 5s si hay un escaneo manual pedido."""
    elapsed = 0
    check_every = 5
    while elapsed < SCAN_INTERVAL_SECONDS:
        time.sleep(check_every)
        elapsed += check_every
        if check_manual_trigger():
            print("Escaneo manual solicitado desde el dashboard, iniciando ahora...")
            return


if __name__ == "__main__":
    while True:
        try:
            run_scan_cycle()
        except Exception as exc:
            print(f"Error en ciclo de escaneo: {exc}")
        wait_for_next_cycle()
