import os
import subprocess
import time
import xml.etree.ElementTree as ET

import paramiko
import requests

API_URL = os.environ.get("API_URL", "http://localhost:8000")
API_KEY = os.environ["SCANNER_API_KEY"]
SCAN_INTERVAL_SECONDS = int(os.environ.get("SCAN_INTERVAL_SECONDS", "300"))

# nombre de servicio (tal como lo identifica nmap) -> paquete apt/dpkg equivalente,
# para poder verificar la version EXACTA instalada por SSH en vez de fiarse solo del
# banner de red. Coincidencia por substring, en minusculas.
PACKAGE_NAME_MAP = {
    "openssh": "openssh-server",
    "apache httpd": "apache2",
    "nginx": "nginx",
    "mysql": "mysql-server",
    "mariadb": "mariadb-server",
    "postgresql": "postgresql",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd-basic",
    "lighttpd": "lighttpd",
    "postfix": "postfix",
    "dovecot": "dovecot-core",
    "samba": "samba",
    "bind": "bind9",
}


def local_subnet() -> str | None:
    out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        iface, cidr = parts[1], parts[3]
        if iface == "lo":
            continue
        return cidr
    return None


def discover_hosts(subnet: str, excluded_ips: set[str] | None = None) -> list[str]:
    cmd = ["nmap", "-sn", subnet, "-oX", "-"]
    if excluded_ips:
        cmd += ["--exclude", ",".join(sorted(excluded_ips))]
    xml_out = subprocess.run(cmd, capture_output=True, text=True).stdout
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


def strip_dpkg_epoch(version: str) -> str:
    """dpkg antepone opcionalmente un 'epoch:' (p.ej. '1:9.6p1-3ubuntu13.18') que es solo
    numeracion interna del paquete, no parte de la version real del software — hay que
    quitarlo antes de usar la version para construir un CPE o mostrarla."""
    prefix, sep, rest = version.partition(":")
    if sep and prefix.isdigit():
        return rest
    return version


def guess_package_name(service_name: str) -> str | None:
    name_l = service_name.lower()
    for key, pkg in PACKAGE_NAME_MAP.items():
        if key in name_l:
            return pkg
    return None


def substitute_cpe_version(cpe22: str | None, new_version: str) -> str | None:
    """Sustituye solo el componente de version de un CPE 2.2 de nmap
    (cpe:/a:vendor:product:version) por una version verificada por SSH, conservando
    vendor/product que nmap ya suele identificar correctamente."""
    if not cpe22 or not cpe22.startswith("cpe:/"):
        return None
    parts = cpe22[len("cpe:/"):].split(":")
    if len(parts) < 3:
        return None
    part, vendor, product = parts[0], parts[1], parts[2]
    safe_version = new_version.split(" ")[0].split("-")[0].split("+")[0]
    if not safe_version:
        return None
    return f"cpe:/{part}:{vendor}:{product}:{safe_version}"


def verify_installed_version(ip: str, username: str, password: str, package: str) -> str | None:
    """Se conecta por SSH y consulta la version EXACTA instalada de un paquete via dpkg
    (operacion de solo lectura, sin privilegios). Devuelve None si falla la conexion o
    si el paquete no esta instalado con ese nombre exacto."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password, timeout=8, banner_timeout=8)
        cmd = f"dpkg-query -W -f='${{Version}}' {package} 2>/dev/null"
        _, stdout, _ = client.exec_command(cmd, timeout=10)
        version = stdout.read().decode(errors="replace").strip()
        return version or None
    except Exception:
        return None
    finally:
        client.close()


def fetch_ssh_credentials() -> dict:
    """Devuelve {ip: {username, password}} solo para equipos con credenciales SSH
    guardadas explicitamente por un administrador — nunca se intenta con equipos sin
    credenciales conocidas."""
    try:
        resp = requests.get(f"{API_URL}/ssh/credentials-for-scan", headers={"X-API-Key": API_KEY}, timeout=10)
        resp.raise_for_status()
        return {c["ip"]: c for c in resp.json() if c.get("ip")}
    except Exception as exc:
        print(f"No se pudieron obtener credenciales SSH para el escaneo autenticado: {exc}")
        return {}


def refine_with_authenticated_check(host_data: dict, cred: dict) -> None:
    verified_count = 0
    for sw in host_data["software"]:
        package = guess_package_name(sw["name"])
        if not package:
            continue
        verified_version = verify_installed_version(host_data["ip"], cred["username"], cred["password"], package)
        if not verified_version:
            continue
        verified_version = strip_dpkg_epoch(verified_version)
        sw["version"] = verified_version
        sw["version_source"] = "authenticated"
        new_cpe = substitute_cpe_version(sw.get("cpe"), verified_version)
        if new_cpe:
            sw["cpe"] = new_cpe
        verified_count += 1
    if verified_count:
        print(f"{host_data['ip']}: {verified_count} version(es) verificada(s) por SSH")


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
        cpe = service.findtext("cpe")
        software.append(
            {
                "name": name,
                "version": version,
                "port": int(port.get("portid")),
                "cpe": cpe,
                "version_source": "network",
            }
        )

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "os_guess": os_guess,
        "software": software,
    }


def run_scan_cycle(excluded_ips: set[str] | None = None):
    subnet = local_subnet()
    if not subnet:
        print("No se pudo determinar la subred local, saltando ciclo")
        return

    excluded_ips = excluded_ips or set()
    print(f"Escaneando subred {subnet}..." + (f" (excluyendo {len(excluded_ips)} IP(s))" if excluded_ips else ""))
    live_ips = [ip for ip in discover_hosts(subnet, excluded_ips) if ip not in excluded_ips]
    print(f"{len(live_ips)} hosts activos encontrados")

    hosts_payload = [scan_host(ip) for ip in live_ips]

    ssh_creds_by_ip = fetch_ssh_credentials()
    if ssh_creds_by_ip:
        for host_data in hosts_payload:
            cred = ssh_creds_by_ip.get(host_data["ip"])
            if cred:
                refine_with_authenticated_check(host_data, cred)

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


def fetch_policy() -> dict:
    default = {
        "enabled": True,
        "interval_seconds": SCAN_INTERVAL_SECONDS,
        "excluded_ips": [],
        "quiet_hours_start": None,
        "quiet_hours_end": None,
    }
    try:
        resp = requests.get(f"{API_URL}/scan/config", headers={"X-API-Key": API_KEY}, timeout=10)
        resp.raise_for_status()
        return {**default, **resp.json()}
    except Exception:
        return default


def in_quiet_hours(policy: dict) -> bool:
    start, end = policy.get("quiet_hours_start"), policy.get("quiet_hours_end")
    if start is None or end is None or start == end:
        return False
    hour = time.gmtime().tm_hour
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def wait_for_next_cycle(interval_seconds: int):
    """Duerme hasta el siguiente ciclo, pero revisa cada 5s si hay un escaneo manual pedido."""
    elapsed = 0
    check_every = 5
    while elapsed < interval_seconds:
        time.sleep(check_every)
        elapsed += check_every
        if check_manual_trigger():
            print("Escaneo manual solicitado desde el dashboard, iniciando ahora...")
            return


if __name__ == "__main__":
    while True:
        policy = fetch_policy()
        if not policy.get("enabled", True):
            print("Escaneo automatico desactivado por politica, esperando...")
        elif in_quiet_hours(policy):
            print(
                f"Dentro de horario silencioso ({policy['quiet_hours_start']}h-{policy['quiet_hours_end']}h UTC), "
                "saltando ciclo automatico"
            )
        else:
            try:
                run_scan_cycle(set(policy.get("excluded_ips", [])))
            except Exception as exc:
                print(f"Error en ciclo de escaneo: {exc}")
        wait_for_next_cycle(policy.get("interval_seconds", SCAN_INTERVAL_SECONDS))
