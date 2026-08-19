import os
import time

import requests

API_URL = os.environ.get("API_URL", "http://api:8000")
API_KEY = os.environ["SCANNER_API_KEY"]
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "600"))
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

GENERIC_NAMES = {"unknown", "http", "https", "ssh", "domain", "tcpwrapped", ""}


def fetch_kev() -> set:
    try:
        resp = requests.get(KEV_URL, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as exc:
        print(f"No se pudo descargar el catalogo CISA KEV: {exc}")
        return set()


def severity_from_cvss(score):
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def cpe22_to_23(cpe22: str | None) -> str | None:
    """Convierte el CPE 2.2 URI-binding que emite nmap (cpe:/a:vendor:product:version)
    al formato 2.3 formatted-string-binding de 13 componentes que exige la API de NVD.
    Devuelve None si no hay CPE, si no empieza por 'cpe:/' o si el componente version
    esta vacio/ausente o es un comodin ('-') — la API de NVD exige version concreta
    para poder usar cpeName en vez de recurrir a busqueda por palabra clave.
    """
    if not cpe22 or not cpe22.startswith("cpe:/"):
        return None
    parts = cpe22[len("cpe:/"):].split(":")
    parts += [""] * (7 - len(parts))
    part, vendor, product, version = parts[0], parts[1], parts[2], parts[3]
    if not version or version in ("-", "*"):
        return None
    fields = [part or "*", vendor or "*", product or "*", version] + ["*"] * 7
    return "cpe:2.3:" + ":".join(fields)


def query_nvd_by_cpe(cpe23: str) -> list[dict] | None:
    """Busca CVEs confirmados como vulnerables para este CPE exacto (matching preciso,
    no aproximado). Ojo con un detalle real de la API de NVD, comprobado en produccion:
    'cpeName' + 'isVulnerable=true' devuelve 404 TANTO si el CPE no existe en su
    diccionario COMO si el CPE existe pero no esta marcado vulnerable a nada — son dos
    situaciones muy distintas (una es 'no tenemos datos', la otra es 'comprobado, limpio')
    que no se pueden distinguir con una sola peticion. Por eso primero comprobamos si NVD
    reconoce el CPE en absoluto (sin filtrar por vulnerabilidad) antes de aplicar el filtro.

    Devuelve: lista de CVEs si hay coincidencias vulnerables; lista vacia si el CPE es
    conocido pero confirmado sin vulnerabilidades activas (resultado real, no un fallo);
    None solo si NVD no reconoce el CPE en absoluto (el llamador debe recurrir entonces
    a busqueda por palabra clave).
    """
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    base_resp = requests.get(
        NVD_URL, params={"cpeName": cpe23, "resultsPerPage": 1}, headers=headers, timeout=20
    )
    if base_resp.status_code == 404:
        return None  # NVD no tiene ningun dato de aplicabilidad para este CPE exacto
    if base_resp.status_code != 200:
        print(f"NVD (cpeName) respondio {base_resp.status_code} para '{cpe23}'")
        return None

    time.sleep(6)  # respeta el limite publico de NVD (5 peticiones / 30s)

    vuln_resp = requests.get(
        NVD_URL,
        params={"cpeName": cpe23, "isVulnerable": "true", "resultsPerPage": 20},
        headers=headers,
        timeout=20,
    )
    if vuln_resp.status_code == 404:
        return []  # CPE conocido y confirmado limpio: resultado real, no un fallo de la consulta
    if vuln_resp.status_code != 200:
        print(f"NVD (cpeName+isVulnerable) respondio {vuln_resp.status_code} para '{cpe23}'")
        return None
    return _parse_nvd_response(vuln_resp.json())


def query_nvd_by_keyword(name: str, version: str | None) -> list[dict]:
    keyword = f"{name} {version}" if version else name
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    resp = requests.get(NVD_URL, params=params, headers=headers, timeout=20)
    if resp.status_code != 200:
        print(f"NVD respondio {resp.status_code} para '{keyword}'")
        return []
    return _parse_nvd_response(resp.json())


def _parse_nvd_response(data: dict) -> list[dict]:
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d["lang"] == "en"), None)
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0]["cvssData"]["baseScore"]
                break
        results.append({"cve_id": cve_id, "cvss": cvss, "description": description})
    return results


def run_cycle():
    kev = fetch_kev()
    resp = requests.get(f"{API_URL}/software/pending", headers={"X-API-Key": API_KEY}, timeout=15)
    resp.raise_for_status()
    pending = resp.json()
    print(f"{len(pending)} paquetes de software pendientes de revisar")

    for sw in pending:
        name = sw["name"]
        if name.lower() in GENERIC_NAMES:
            vulns, match_type = [], "keyword"
        else:
            cpe23 = cpe22_to_23(sw.get("cpe"))
            cves = None
            match_type = "cpe"
            if cpe23:
                try:
                    cves = query_nvd_by_cpe(cpe23)
                except Exception as exc:
                    print(f"Error consultando NVD por CPE para {name}: {exc}")
                time.sleep(6)  # respeta el limite publico de NVD (5 peticiones / 30s)

            if cves is None:
                match_type = "keyword"
                try:
                    cves = query_nvd_by_keyword(name, sw.get("version"))
                except Exception as exc:
                    print(f"Error consultando NVD por palabra clave para {name}: {exc}")
                    cves = []

            vulns = [
                {
                    "cve_id": c["cve_id"],
                    "cvss": c["cvss"],
                    "severity": severity_from_cvss(c["cvss"]),
                    "description": (c["description"] or "")[:500],
                    "remediation": f"Actualizar {name} a la ultima version estable disponible.",
                    "known_exploited": c["cve_id"] in kev,
                    "match_type": match_type,
                }
                for c in cves
                if c["cve_id"]
            ]

        payload = {"software_id": sw["id"], "vulnerabilities": vulns, "match_type": match_type}
        try:
            r = requests.post(
                f"{API_URL}/vulnerabilities/ingest",
                json=payload,
                headers={"X-API-Key": API_KEY},
                timeout=15,
            )
            r.raise_for_status()
            print(f"{name} {sw.get('version')}: {len(vulns)} CVEs encontrados")
        except Exception as exc:
            print(f"Error enviando resultados de {name}: {exc}")

        time.sleep(6)  # respeta el limite publico de NVD (5 peticiones / 30s)


if __name__ == "__main__":
    while True:
        try:
            run_cycle()
        except Exception as exc:
            print(f"Error en ciclo de enriquecimiento: {exc}")
        time.sleep(CHECK_INTERVAL_SECONDS)
