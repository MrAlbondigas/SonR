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


def query_nvd(name: str, version: str | None) -> list[dict]:
    keyword = f"{name} {version}" if version else name
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    resp = requests.get(NVD_URL, params=params, headers=headers, timeout=20)
    if resp.status_code != 200:
        print(f"NVD respondio {resp.status_code} para '{keyword}'")
        return []
    data = resp.json()
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
            vulns = []
        else:
            try:
                cves = query_nvd(name, sw.get("version"))
            except Exception as exc:
                print(f"Error consultando NVD para {name}: {exc}")
                cves = []

            vulns = [
                {
                    "cve_id": c["cve_id"],
                    "cvss": c["cvss"],
                    "severity": severity_from_cvss(c["cvss"]),
                    "description": (c["description"] or "")[:500],
                    "remediation": f"Actualizar {name} a la ultima version estable disponible.",
                    "known_exploited": c["cve_id"] in kev,
                }
                for c in cves
                if c["cve_id"]
            ]

        payload = {"software_id": sw["id"], "vulnerabilities": vulns}
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
