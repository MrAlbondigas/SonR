import concurrent.futures
import os
import time
from ftplib import FTP, error_perm

import paramiko
import requests

API_URL = os.environ.get("API_URL", "http://api:8000")
API_KEY = os.environ["SCANNER_API_KEY"]
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "1800"))
CONNECT_TIMEOUT = 5
HOST_BUDGET_SECONDS = 45

# Lista corta de credenciales por defecto muy conocidas - no es un diccionario de fuerza bruta.
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", ""),
    ("user", "user"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
]


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


def try_ssh(ip: str, port: int) -> tuple | None:
    for username, password in DEFAULT_CREDS:
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


def try_ftp(ip: str, port: int) -> tuple | None:
    for username, password in DEFAULT_CREDS:
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


def try_http_basic(ip: str, port: int) -> tuple | None:
    url = f"http://{ip}:{port}/"
    try:
        baseline = requests.get(url, timeout=CONNECT_TIMEOUT)
    except Exception:
        return None
    if baseline.status_code != 401:
        return None  # no protegido con HTTP Basic Auth, no aplica

    for username, password in DEFAULT_CREDS:
        try:
            resp = requests.get(url, auth=(username, password), timeout=CONNECT_TIMEOUT)
            if resp.status_code == 200:
                return username, password
        except Exception:
            return None
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
        for service in target["services"]:
            port = service["port"]
            found = None
            if port == 22:
                found = run_with_timeout(try_ssh, (ip, port), HOST_BUDGET_SECONDS)
            elif port == 21:
                found = run_with_timeout(try_ftp, (ip, port), HOST_BUDGET_SECONDS)
            elif port in (80, 8080):
                found = run_with_timeout(try_http_basic, (ip, port), HOST_BUDGET_SECONDS)

            if found:
                username, password = found
                service_name = {22: "ssh", 21: "ftp"}.get(port, "http-basic")
                report_finding(host_id, port, service_name, username, password)

    print("Ciclo completado, esperando al siguiente")


if __name__ == "__main__":
    while True:
        try:
            run_cycle()
        except Exception as exc:
            print(f"Error en ciclo de credenciales: {exc}")
        time.sleep(CHECK_INTERVAL_SECONDS)
