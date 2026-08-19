import concurrent.futures
import os
import socket
import time
from ftplib import FTP, error_perm

import paramiko
import requests

API_URL = os.environ.get("API_URL", "http://api:8000")
API_KEY = os.environ["SCANNER_API_KEY"]
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "1800"))
CONNECT_TIMEOUT = 5
HOST_BUDGET_SECONDS = 45

# Lista generica de credenciales por defecto muy conocidas y ampliamente publicadas -
# no es un diccionario de fuerza bruta, son las combinaciones mas documentadas del sector.
GENERIC_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "12345"),
    ("admin", "1234"),
    ("admin", "12345678"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "admin"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("guest", ""),
    ("support", "support"),
    ("service", "service"),
    ("supervisor", "supervisor"),
    ("operator", "operator"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("test", "test"),
    ("demo", "demo"),
    ("", ""),
]

# credenciales documentadas publicamente por fabricante — cuando el fingerprinting por
# MAC ya identifico el fabricante del equipo, se prueban ANTES que la lista generica,
# igual que haria un atacante real que reconoce el dispositivo antes de improvisar.
VENDOR_CREDS: dict[str, list[tuple[str, str]]] = {
    "ubiquiti": [("ubnt", "ubnt")],
    "hikvision": [("admin", "12345"), ("admin", "admin12345")],
    "dahua": [("admin", "admin")],
    "d-link": [("admin", ""), ("admin", "admin")],
    "netgear": [("admin", "password"), ("admin", "1234")],
    "tp-link": [("admin", "admin")],
    "zyxel": [("admin", "1234"), ("admin", "zyxel")],
    "axis communications": [("root", "pass")],
    "synology": [("admin", "admin")],
    "qnap": [("admin", "admin")],
    "cisco": [("cisco", "cisco"), ("admin", "admin")],
    "mikrotik": [("admin", "")],
    "grandstream": [("admin", "admin")],
    "polycom": [("polycom", "456")],
    "sony": [("admin", "admin")],
}


def credentials_for(vendor: str | None) -> list[tuple[str, str]]:
    """Construye la lista de credenciales a probar para un equipo: primero las
    especificas de su fabricante (si el fingerprinting por MAC lo reconocio), luego
    la lista generica, sin duplicados y preservando el orden de prioridad."""
    ordered: list[tuple[str, str]] = []
    vendor_l = (vendor or "").lower()
    for key, creds in VENDOR_CREDS.items():
        if key in vendor_l:
            ordered.extend(c for c in creds if c not in ordered)
    for cred in GENERIC_CREDS:
        if cred not in ordered:
            ordered.append(cred)
    return ordered


def run_with_timeout(func, args, timeout):
    """Ejecuta func(*args) en un hilo aparte y abandona tras `timeout` segundos
    sin esperar a que el hilo termine, por si la libreria subyacente se cuelga
    ignorando sus propios timeouts (frecuente con dispositivos embebidos raros)."""
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(func, *args)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        print(f"  timeout duro revisando {args}, abandonando este servicio")
        return None
    except Exception as exc:
        print(f"  error revisando {args}: {exc}")
        return None
    finally:
        executor.shutdown(wait=False)


def report_finding(host_id: int, port: int, service: str, username: str, password: str):
    payload = {
        "host_id": host_id,
        "port": port,
        "service": service,
        "username": username,
        "password": password,
    }
    try:
        requests.post(
            f"{API_URL}/credentials/ingest", json=payload, headers={"X-API-Key": API_KEY}, timeout=10
        )
        print(f"HALLAZGO: host_id={host_id} puerto={port} {username}/{password}")
    except Exception as exc:
        print(f"Error reportando hallazgo: {exc}")


def try_ssh(ip: str, port: int, creds: list[tuple[str, str]]) -> tuple | None:
    for username, password in creds:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                ip,
                port=port,
                username=username,
                password=password,
                timeout=CONNECT_TIMEOUT,
                banner_timeout=CONNECT_TIMEOUT,
                auth_timeout=CONNECT_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            client.close()
            return username, password
        except paramiko.AuthenticationException:
            pass
        except Exception:
            return None  # el servicio no responde bien a SSH, no seguir insistiendo
        finally:
            client.close()
        time.sleep(1)
    return None


def try_ftp(ip: str, port: int, creds: list[tuple[str, str]]) -> tuple | None:
    for username, password in creds:
        try:
            ftp = FTP()
            ftp.connect(ip, port, timeout=CONNECT_TIMEOUT)
            ftp.login(username, password)
            ftp.quit()
            return username, password
        except error_perm:
            pass
        except Exception:
            return None
        time.sleep(1)
    return None


def try_http_basic(ip: str, port: int, creds: list[tuple[str, str]]) -> tuple | None:
    url = f"http://{ip}:{port}/"
    try:
        baseline = requests.get(url, timeout=CONNECT_TIMEOUT)
    except Exception:
        return None
    if baseline.status_code != 401:
        return None  # no protegido con HTTP Basic Auth, no aplica

    for username, password in creds:
        try:
            resp = requests.get(url, auth=(username, password), timeout=CONNECT_TIMEOUT)
            if resp.status_code == 200:
                return username, password
        except Exception:
            return None
        time.sleep(1)
    return None


TELNET_FAILURE_HINTS = (b"incorrect", b"invalid", b"failed", b"denied", b"login incorrect", b"access denied")
TELNET_SUCCESS_HINTS = (b"$", b"#", b">", b"welcome", b"last login")


def _telnet_read(sock: socket.socket, size: int = 4096) -> bytes:
    try:
        return sock.recv(size)
    except socket.timeout:
        return b""
    except OSError:
        return b""


def try_telnet(ip: str, port: int, creds: list[tuple[str, str]]) -> tuple | None:
    """Comprobacion heuristica: a diferencia de SSH/FTP, telnet no tiene una senal
    formal de exito/fallo en el protocolo — se basa en reconocer patrones tipicos de
    un prompt de sistema tras el login. Es menos fiable por naturaleza del propio
    protocolo (puede dar falsos negativos en sistemas con prompts poco habituales),
    no por una limitacion de esta implementacion."""
    for username, password in creds:
        try:
            sock = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
            sock.settimeout(CONNECT_TIMEOUT)
            _telnet_read(sock)
            sock.sendall(username.encode(errors="ignore") + b"\r\n")
            _telnet_read(sock)
            sock.sendall(password.encode(errors="ignore") + b"\r\n")
            response = _telnet_read(sock)
            sock.close()
        except Exception:
            return None  # el servicio no responde bien a telnet, no seguir insistiendo

        response_l = response.lower()
        if any(h in response_l for h in TELNET_FAILURE_HINTS):
            pass
        elif any(h in response_l for h in TELNET_SUCCESS_HINTS):
            return username, password
        time.sleep(1)
    return None


def run_cycle():
    resp = requests.get(f"{API_URL}/targets", headers={"X-API-Key": API_KEY}, timeout=15)
    resp.raise_for_status()
    targets = resp.json()
    print(f"{len(targets)} equipos con servicios pendientes de revisar")

    for target in targets:
        host_id = target["host_id"]
        ip = target["ip"]
        creds = credentials_for(target.get("vendor"))
        for service in target["services"]:
            port = service["port"]
            found = None
            if port == 22:
                found = run_with_timeout(try_ssh, (ip, port, creds), HOST_BUDGET_SECONDS)
            elif port == 21:
                found = run_with_timeout(try_ftp, (ip, port, creds), HOST_BUDGET_SECONDS)
            elif port == 23:
                found = run_with_timeout(try_telnet, (ip, port, creds), HOST_BUDGET_SECONDS)
            elif port in (80, 8080):
                found = run_with_timeout(try_http_basic, (ip, port, creds), HOST_BUDGET_SECONDS)

            if found:
                username, password = found
                service_name = {22: "ssh", 21: "ftp", 23: "telnet"}.get(port, "http-basic")
                report_finding(host_id, port, service_name, username, password)

    print("Ciclo completado, esperando al siguiente")


if __name__ == "__main__":
    while True:
        try:
            run_cycle()
        except Exception as exc:
            print(f"Error en ciclo de credenciales: {exc}")
        time.sleep(CHECK_INTERVAL_SECONDS)
