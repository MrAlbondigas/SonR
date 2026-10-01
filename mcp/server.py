import os

import requests
from mcp.server.mcpserver import MCPServer

API_URL = os.environ.get("SONR_URL", "http://api:8000").rstrip("/")
API_KEY = os.environ["SONR_API_KEY"]

mcp = MCPServer(
    name="SonR",
    instructions=(
        "Herramientas de solo lectura sobre SonR, una plataforma de gestion de "
        "vulnerabilidades de red. Permiten consultar el inventario de equipos, las "
        "vulnerabilidades abiertas, el riesgo agregado por grupo y el estado de cumplimiento "
        "de una red monitorizada. Ninguna de estas herramientas modifica datos ni ejecuta "
        "acciones sobre la red: usan una clave de solo lectura, independiente de la clave "
        "interna que usa el propio escaner para escribir resultados."
    ),
)


def _fetch_export() -> dict:
    resp = requests.get(f"{API_URL}/api/v1/export", headers={"X-API-Key": API_KEY}, timeout=15)
    resp.raise_for_status()
    return resp.json()


@mcp.tool()
def resumen_seguridad() -> dict:
    """Resumen general del estado de seguridad de la red: numero de equipos monitorizados,
    puntuacion de riesgo total, credenciales por defecto encontradas y cuantas vulnerabilidades
    estan fuera de su plazo de remediacion (SLA) ahora mismo."""
    data = _fetch_export()
    return {
        "generado_en": data["generated_at"],
        "equipos_monitorizados": data["host_count"],
        "puntuacion_riesgo_total": data["network_risk_score"],
        "credenciales_por_defecto_encontradas": data["credential_findings_count"],
        "vulnerabilidades_fuera_de_plazo": data["sla_overdue_count"],
    }


@mcp.tool()
def listar_equipos() -> list[dict]:
    """Lista todos los equipos descubiertos en la red, con su IP, hostname, etiquetas asignadas
    y su nivel de riesgo (puntuacion y categoria)."""
    return _fetch_export()["hosts"]


@mcp.tool()
def listar_vulnerabilidades_abiertas() -> list[dict]:
    """Lista las vulnerabilidades abiertas detectadas en la red: identificador CVE, CVSS,
    severidad, si tiene explotacion activa conocida (CISA KEV), equipo y software afectados,
    y su plazo de remediacion (SLA)."""
    return _fetch_export()["open_vulnerabilities"]


@mcp.tool()
def riesgo_por_grupo() -> list[dict]:
    """Riesgo agregado por etiqueta/grupo de equipos (por ejemplo, por unidad de negocio,
    entorno o ubicacion fisica): numero de equipos del grupo, puntuacion de riesgo total y
    media, vulnerabilidades abiertas y credenciales por defecto encontradas."""
    return _fetch_export()["group_risk"]


@mcp.tool()
def estado_cumplimiento() -> list[dict]:
    """Estado de cumplimiento simplificado frente a un subconjunto de CIS Controls v8: para
    cada control, si esta cubierto o tiene hallazgos pendientes segun lo que la herramienta mide
    de verdad. No es una certificacion oficial de CIS."""
    return _fetch_export()["cis_compliance"]


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8000,
        streamable_http_path="/mcp",
        stateless_http=True,
    )
