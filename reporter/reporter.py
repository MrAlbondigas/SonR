import os
import shutil
import time
import traceback

import requests
from fpdf import FPDF

API_URL = os.environ.get("API_URL", "http://api:8000")
API_KEY = os.environ["SCANNER_API_KEY"]
REPORT_INTERVAL_SECONDS = int(os.environ.get("REPORT_INTERVAL_SECONDS", "604800"))  # 7 dias
REPORTS_DIR = "/app/reports"


def safe(text, max_len: int = 300) -> str:
    if text is None:
        return "-"
    text = str(text).encode("latin-1", "replace").decode("latin-1")
    if len(text) > max_len:
        text = text[:max_len] + "..."
    # fpdf2 cannot wrap a run of 60+ chars with no space, so force break points
    words = text.split(" ")
    words = [w if len(w) <= 60 else " ".join(w[i : i + 60] for i in range(0, len(w), 60)) for w in words]
    return " ".join(words)


def fetch_data() -> dict:
    resp = requests.get(f"{API_URL}/reports/data", headers={"X-API-Key": API_KEY}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def build_pdf(data: dict, output_path: str):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Proyecto Cyber - Reporte de seguridad", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, safe(f"Generado: {data['generated_at']}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, safe(f"Resumen: {data['host_count']} equipos en la red"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Top prioridades
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Top prioridades", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    if data["priorities"]:
        for v in data["priorities"]:
            tag = " [EXPLOIT CONOCIDO]" if v["known_exploited"] else ""
            line = f"- {v['cve_id']}{tag} | {v['software']} en {v['host_ip']} | CVSS {v['cvss'] or '-'} ({v['severity'] or '-'})"
            pdf.multi_cell(0, 6, safe(line), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, "Sin vulnerabilidades cruzadas con CVEs todavia.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Rutas de ataque
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Rutas de ataque", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    if data["attack_paths"]:
        for p in data["attack_paths"]:
            pdf.multi_cell(0, 6, safe(f"- {p['host_ip']}: {p['description']}"), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, "No se detectaron rutas de ataque explotables.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Credenciales por defecto
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Credenciales por defecto encontradas", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    if data["credential_findings"]:
        for c in data["credential_findings"]:
            pdf.multi_cell(0, 6, safe(f"- {c['host_ip']}:{c['port']} ({c['service']}) usuario={c['username']}"), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, "Ninguna. Buena senal.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Timeline
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Cambios en los ultimos 7 dias", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    if data["events_last_7_days"]:
        for e in data["events_last_7_days"][:30]:
            pdf.multi_cell(0, 6, safe(f"- [{e['occurred_at']}] {e['description']}"), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, "Sin cambios registrados.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Inventario
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Inventario de equipos", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for h in data["hosts"]:
        line = f"- {h['ip']} | {h['hostname'] or '-'} | {h['vendor'] or '-'} | {h['os_guess'] or '-'}"
        pdf.multi_cell(0, 6, safe(line), new_x="LMARGIN", new_y="NEXT")

    pdf.output(output_path)


def run_cycle():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    data = fetch_data()
    timestamp = data["generated_at"].replace(":", "-")
    output_path = os.path.join(REPORTS_DIR, f"report-{timestamp}.pdf")
    build_pdf(data, output_path)
    shutil.copyfile(output_path, os.path.join(REPORTS_DIR, "latest.pdf"))
    print(f"Reporte generado: {output_path}")


if __name__ == "__main__":
    while True:
        try:
            run_cycle()
        except Exception as exc:
            print(f"Error generando reporte: {exc}")
            traceback.print_exc()
        time.sleep(REPORT_INTERVAL_SECONDS)
