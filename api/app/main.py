import os
from datetime import datetime, timedelta, timezone

import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from . import auth, models, schemas
from .database import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Proyecto Cyber - Network Vulnerability Scanner")
templates = Jinja2Templates(directory="app/templates")

SCANNER_API_KEY = os.environ["SCANNER_API_KEY"]
REPORTS_DIR = "/app/reports"


def lookup_vendor(mac: str) -> str | None:
    try:
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=4)
        if resp.status_code == 200:
            return resp.text.strip()
    except requests.RequestException:
        pass
    return None


@app.on_event("startup")
def create_admin_user():
    from .database import SessionLocal

    db = SessionLocal()
    try:
        username = os.environ["ADMIN_USERNAME"]
        if not db.query(models.User).filter(models.User.username == username).first():
            db.add(
                models.User(
                    username=username,
                    password_hash=auth.hash_password(os.environ["ADMIN_PASSWORD"]),
                    role="admin",
                )
            )
            db.commit()
    finally:
        db.close()


def verify_scanner_key(x_api_key: str = Header(default="")):
    if x_api_key != SCANNER_API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid scanner API key")


# --- Auth ---


@app.post("/auth/login")
def login(payload: schemas.LoginIn, response: Response, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not auth.verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = auth.create_access_token(user.username, user.role)
    response.set_cookie("session_token", token, httponly=True, samesite="lax", max_age=8 * 3600)
    return {"username": user.username, "role": user.role}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie("session_token")
    return {"ok": True}


# --- API: hosts ---


@app.get("/hosts")
def list_hosts(db: Session = Depends(get_db)):
    hosts = db.query(models.Host).order_by(models.Host.ip).all()
    return [
        {
            "id": h.id,
            "ip": h.ip,
            "mac": h.mac,
            "vendor": h.vendor,
            "hostname": h.hostname,
            "os_guess": h.os_guess,
            "last_seen": h.last_seen,
            "software_count": len(h.software),
        }
        for h in hosts
    ]


@app.get("/hosts/{host_id}")
def get_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return {
        "id": host.id,
        "ip": host.ip,
        "mac": host.mac,
        "vendor": host.vendor,
        "hostname": host.hostname,
        "os_guess": host.os_guess,
        "credential_findings": [
            {"port": c.port, "service": c.service, "username": c.username, "password": c.password}
            for c in host.credential_findings
        ],
        "software": [
            {
                "id": s.id,
                "name": s.name,
                "version": s.version,
                "port": s.port,
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "cvss": v.cvss,
                        "severity": v.severity,
                        "known_exploited": v.known_exploited,
                        "remediation": v.remediation,
                    }
                    for v in s.vulnerabilities
                ],
            }
            for s in host.software
        ],
    }


# --- Escaneo bajo demanda ---


@app.post("/scan/request")
def request_scan(
    db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)
):
    pending_exists = (
        db.query(models.ScanRequest).filter(models.ScanRequest.consumed_at.is_(None)).first()
    )
    if pending_exists:
        return {"ok": True, "already_pending": True}
    db.add(models.ScanRequest(requested_by=user.username))
    db.commit()
    return {"ok": True, "already_pending": False}


@app.get("/scan/pending", dependencies=[Depends(verify_scanner_key)])
def consume_pending_scan(db: Session = Depends(get_db)):
    pending = (
        db.query(models.ScanRequest)
        .filter(models.ScanRequest.consumed_at.is_(None))
        .order_by(models.ScanRequest.requested_at)
        .first()
    )
    if not pending:
        return {"pending": False}
    pending.consumed_at = func.now()
    db.commit()
    return {"pending": True, "requested_by": pending.requested_by}


@app.get("/scan/status")
def scan_status(db: Session = Depends(get_db)):
    latest = db.query(models.Scan).order_by(models.Scan.started_at.desc()).first()
    recent = db.query(models.Scan).order_by(models.Scan.started_at.desc()).limit(5).all()
    pending = (
        db.query(models.ScanRequest).filter(models.ScanRequest.consumed_at.is_(None)).first()
    )
    return {
        "latest": (
            {
                "id": latest.id,
                "started_at": latest.started_at,
                "finished_at": latest.finished_at,
                "status": latest.status,
                "in_progress": latest.status == "running",
            }
            if latest
            else None
        ),
        "pending_request": pending is not None,
        "recent": [
            {
                "id": s.id,
                "started_at": s.started_at,
                "finished_at": s.finished_at,
                "status": s.status,
            }
            for s in recent
        ],
    }


# --- Scanner ingest ---


@app.post("/scan/ingest", dependencies=[Depends(verify_scanner_key)])
def ingest_scan(payload: schemas.ScanIngest, db: Session = Depends(get_db)):
    scan = models.Scan(status="running")
    db.add(scan)
    db.flush()

    for host_in in payload.hosts:
        host = db.query(models.Host).filter(models.Host.ip == host_in.ip).first()
        is_new_host = host is None
        if is_new_host:
            host = models.Host(ip=host_in.ip)
            db.add(host)
            db.flush()
            db.add(
                models.Event(
                    host_id=host.id,
                    event_type="new_host",
                    description=f"Nuevo equipo detectado en la red: {host_in.ip}",
                )
            )
        if host_in.mac and (host_in.mac != host.mac or host.vendor is None):
            host.mac = host_in.mac
            host.vendor = lookup_vendor(host_in.mac)
        host.hostname = host_in.hostname or host.hostname
        host.os_guess = host_in.os_guess or host.os_guess
        host.last_seen = func.now()

        for sw_in in host_in.software:
            existing = (
                db.query(models.Software)
                .filter(
                    models.Software.host_id == host.id,
                    models.Software.name == sw_in.name,
                    models.Software.port == sw_in.port,
                )
                .first()
            )
            if existing is None:
                db.add(
                    models.Software(
                        host_id=host.id,
                        scan_id=scan.id,
                        name=sw_in.name,
                        version=sw_in.version,
                        port=sw_in.port,
                    )
                )
                if not is_new_host:
                    db.add(
                        models.Event(
                            host_id=host.id,
                            event_type="new_service",
                            description=f"Nuevo servicio en {host_in.ip}: {sw_in.name} (puerto {sw_in.port})",
                        )
                    )
            else:
                if sw_in.version and existing.version != sw_in.version:
                    db.add(
                        models.Event(
                            host_id=host.id,
                            event_type="version_change",
                            description=(
                                f"{sw_in.name} en {host_in.ip} cambio de version: "
                                f"{existing.version or 'desconocida'} -> {sw_in.version}"
                            ),
                        )
                    )
                    existing.version = sw_in.version
                    existing.cve_checked_at = None
                existing.scan_id = scan.id
                existing.detected_at = func.now()

    scan.status = "completed"
    scan.finished_at = func.now()
    db.commit()
    return {"scan_id": scan.id, "hosts_ingested": len(payload.hosts)}


# --- Vulnerability enrichment (usado por el servicio enricher) ---


@app.get("/software/pending", dependencies=[Depends(verify_scanner_key)])
def software_pending(db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    rows = (
        db.query(models.Software)
        .filter(
            (models.Software.cve_checked_at.is_(None)) | (models.Software.cve_checked_at < cutoff)
        )
        .limit(20)
        .all()
    )
    return [{"id": s.id, "name": s.name, "version": s.version} for s in rows]


@app.post("/vulnerabilities/ingest", dependencies=[Depends(verify_scanner_key)])
def ingest_vulnerabilities(payload: schemas.VulnerabilityIngest, db: Session = Depends(get_db)):
    software = db.query(models.Software).filter(models.Software.id == payload.software_id).first()
    if not software:
        raise HTTPException(status_code=404, detail="Software not found")

    existing_cves = {v.cve_id for v in software.vulnerabilities}
    new_count = 0
    for vuln_in in payload.vulnerabilities:
        if vuln_in.cve_id in existing_cves:
            continue
        db.add(models.Vulnerability(software_id=software.id, **vuln_in.model_dump()))
        new_count += 1
        if vuln_in.known_exploited:
            db.add(
                models.Event(
                    host_id=software.host_id,
                    event_type="critical_vuln",
                    description=(
                        f"Vulnerabilidad con exploit publico conocido en {software.name}: {vuln_in.cve_id}"
                    ),
                )
            )
    software.cve_checked_at = datetime.now(timezone.utc)
    db.commit()
    return {"software_id": software.id, "new_vulnerabilities": new_count}


# --- Credenciales por defecto (usado por el servicio credcheck) ---


@app.get("/targets", dependencies=[Depends(verify_scanner_key)])
def list_targets(db: Session = Depends(get_db)):
    hosts = db.query(models.Host).all()
    result = []
    for h in hosts:
        already_cracked_ports = {c.port for c in h.credential_findings}
        services = [
            {"port": s.port, "name": s.name}
            for s in h.software
            if s.port in (21, 22, 80, 8080) and s.port not in already_cracked_ports
        ]
        if services:
            result.append({"host_id": h.id, "ip": h.ip, "services": services})
    return result


@app.post("/credentials/ingest", dependencies=[Depends(verify_scanner_key)])
def ingest_credential(payload: schemas.CredentialFindingIn, db: Session = Depends(get_db)):
    existing = (
        db.query(models.CredentialFinding)
        .filter(
            models.CredentialFinding.host_id == payload.host_id,
            models.CredentialFinding.port == payload.port,
            models.CredentialFinding.username == payload.username,
        )
        .first()
    )
    if existing is None:
        db.add(models.CredentialFinding(**payload.model_dump()))
        host = db.query(models.Host).filter(models.Host.id == payload.host_id).first()
        db.add(
            models.Event(
                host_id=payload.host_id,
                event_type="default_credentials",
                description=(
                    f"Credenciales por defecto validas en {host.ip if host else payload.host_id} "
                    f"puerto {payload.port} ({payload.service}): {payload.username}/{payload.password}"
                ),
            )
        )
        db.commit()
    return {"ok": True}


# --- Timeline y priorizacion ---


@app.get("/events")
def list_events(db: Session = Depends(get_db)):
    events = db.query(models.Event).order_by(models.Event.occurred_at.desc()).limit(50).all()
    return [
        {
            "id": e.id,
            "host_id": e.host_id,
            "event_type": e.event_type,
            "description": e.description,
            "occurred_at": e.occurred_at,
        }
        for e in events
    ]


@app.get("/priorities")
def list_priorities(db: Session = Depends(get_db)):
    vulns = (
        db.query(models.Vulnerability)
        .join(models.Software)
        .order_by(models.Vulnerability.known_exploited.desc(), models.Vulnerability.cvss.desc().nullslast())
        .limit(5)
        .all()
    )
    return [
        {
            "cve_id": v.cve_id,
            "cvss": v.cvss,
            "severity": v.severity,
            "known_exploited": v.known_exploited,
            "host_ip": v.software.host.ip,
            "software": v.software.name,
            "remediation": v.remediation,
        }
        for v in vulns
    ]


def compute_attack_paths(db: Session) -> list[dict]:
    hosts = db.query(models.Host).all()
    total_hosts = len(hosts)
    paths = []

    for host in hosts:
        critical_vulns = [
            v
            for s in host.software
            for v in s.vulnerabilities
            if v.known_exploited or (v.cvss or 0) >= 9.0
        ]
        weak_creds = host.credential_findings

        if not critical_vulns and not weak_creds:
            continue

        entry_points = []
        if weak_creds:
            entry_points.append(
                f"credenciales por defecto en puerto {weak_creds[0].port} ({weak_creds[0].service})"
            )
        if critical_vulns:
            entry_points.append(f"{critical_vulns[0].cve_id} en {critical_vulns[0].software.name}")

        others = total_hosts - 1
        description = (
            f"Un atacante que comprometa {host.ip} vía {' o '.join(entry_points)} "
            f"queda dentro de la misma red local sin segmentación detectada, "
            f"con visibilidad directa sobre los otros {others} equipos de la red "
            f"(sin necesidad de saltar por ningún firewall interno)."
        )
        paths.append(
            {
                "host_ip": host.ip,
                "host_id": host.id,
                "entry_points": entry_points,
                "description": description,
                "severity": "critical" if weak_creds or any(v.known_exploited for v in critical_vulns) else "high",
            }
        )

    return paths


@app.get("/attack-paths")
def list_attack_paths(db: Session = Depends(get_db)):
    return compute_attack_paths(db)


# --- Reportes ---


@app.get("/reports/data", dependencies=[Depends(verify_scanner_key)])
def report_data(db: Session = Depends(get_db)):
    hosts = db.query(models.Host).order_by(models.Host.ip).all()
    priorities = (
        db.query(models.Vulnerability)
        .join(models.Software)
        .order_by(models.Vulnerability.known_exploited.desc(), models.Vulnerability.cvss.desc().nullslast())
        .limit(10)
        .all()
    )
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    events = (
        db.query(models.Event)
        .filter(models.Event.occurred_at >= week_ago)
        .order_by(models.Event.occurred_at.desc())
        .all()
    )
    attack_paths = compute_attack_paths(db)
    credential_findings = db.query(models.CredentialFinding).all()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host_count": len(hosts),
        "hosts": [
            {"ip": h.ip, "hostname": h.hostname, "vendor": h.vendor, "os_guess": h.os_guess}
            for h in hosts
        ],
        "priorities": [
            {
                "cve_id": v.cve_id,
                "cvss": v.cvss,
                "severity": v.severity,
                "known_exploited": v.known_exploited,
                "host_ip": v.software.host.ip,
                "software": v.software.name,
            }
            for v in priorities
        ],
        "events_last_7_days": [
            {"event_type": e.event_type, "description": e.description, "occurred_at": e.occurred_at.isoformat()}
            for e in events
        ],
        "attack_paths": attack_paths,
        "credential_findings": [
            {"host_ip": c.host.ip, "port": c.port, "service": c.service, "username": c.username}
            for c in credential_findings
        ],
    }


@app.get("/reports/latest")
def download_latest_report():
    path = os.path.join(REPORTS_DIR, "latest.pdf")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Todavia no se ha generado ningun reporte")
    return FileResponse(path, media_type="application/pdf", filename="proyecto-cyber-reporte.pdf")


# --- Datos de demostracion (reversibles) ---


@app.get("/demo/status")
def demo_status(db: Session = Depends(get_db)):
    count = db.query(models.DemoRecord).count()
    return {"active": count > 0}


@app.post("/demo/seed")
def seed_demo_data(db: Session = Depends(get_db), admin: models.User = Depends(auth.require_admin)):
    hosts = db.query(models.Host).order_by(models.Host.ip).all()
    if not hosts:
        raise HTTPException(status_code=400, detail="Necesitas al menos un equipo escaneado antes de generar datos de ejemplo")

    # ya hay datos demo activos, no duplicar
    if db.query(models.DemoRecord).first():
        return {"ok": True, "already_seeded": True}

    host_a = hosts[0]
    host_b = hosts[1] if len(hosts) > 1 else hosts[0]

    demo_software = models.Software(
        host_id=host_a.id,
        name="PAN-OS GlobalProtect (DEMO)",
        version="11.1.2",
        port=4443,
    )
    db.add(demo_software)
    db.flush()
    db.add(models.DemoRecord(table_name="software", record_id=demo_software.id))

    demo_vuln = models.Vulnerability(
        software_id=demo_software.id,
        cve_id="CVE-2024-3400",
        cvss=10.0,
        severity="critical",
        description="[DEMO] Inyeccion de comandos no autenticada en la interfaz de gestion. Permite ejecucion remota de codigo.",
        remediation="[DEMO] Actualizar a la ultima version y revisar logs de acceso en busca de indicadores de compromiso.",
        known_exploited=True,
    )
    db.add(demo_vuln)
    db.flush()
    db.add(models.DemoRecord(table_name="vulnerabilities", record_id=demo_vuln.id))

    demo_cred = models.CredentialFinding(
        host_id=host_b.id,
        port=23,
        service="telnet (DEMO)",
        username="admin",
        password="admin",
    )
    db.add(demo_cred)
    db.flush()
    db.add(models.DemoRecord(table_name="credential_findings", record_id=demo_cred.id))

    demo_event_1 = models.Event(
        host_id=host_a.id,
        event_type="critical_vuln",
        description=f"[DEMO] Vulnerabilidad con exploit publico conocido en {demo_software.name}: {demo_vuln.cve_id}",
    )
    demo_event_2 = models.Event(
        host_id=host_b.id,
        event_type="default_credentials",
        description=f"[DEMO] Credenciales por defecto validas en {host_b.ip} puerto 23 (telnet): admin/admin",
    )
    db.add(demo_event_1)
    db.add(demo_event_2)
    db.flush()
    db.add(models.DemoRecord(table_name="events", record_id=demo_event_1.id))
    db.add(models.DemoRecord(table_name="events", record_id=demo_event_2.id))

    db.commit()
    return {"ok": True, "already_seeded": False}


@app.post("/demo/clear")
def clear_demo_data(db: Session = Depends(get_db), admin: models.User = Depends(auth.require_admin)):
    records = db.query(models.DemoRecord).all()
    table_map = {
        "software": models.Software,
        "vulnerabilities": models.Vulnerability,
        "credential_findings": models.CredentialFinding,
        "events": models.Event,
    }
    for record in records:
        model_cls = table_map.get(record.table_name)
        if model_cls is None:
            continue
        row = db.query(model_cls).filter(model_cls.id == record.record_id).first()
        if row is not None:
            db.delete(row)
    db.query(models.DemoRecord).delete()
    db.commit()
    return {"ok": True, "removed": len(records)}


# --- Dashboard ---


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User | None = Depends(auth.get_current_user_optional),
):
    hosts = db.query(models.Host).order_by(models.Host.ip).all()
    events = db.query(models.Event).order_by(models.Event.occurred_at.desc()).limit(15).all()
    priorities = (
        db.query(models.Vulnerability)
        .join(models.Software)
        .order_by(models.Vulnerability.known_exploited.desc(), models.Vulnerability.cvss.desc().nullslast())
        .limit(5)
        .all()
    )
    attack_paths = compute_attack_paths(db)

    all_vulns = db.query(models.Vulnerability).all()
    severity_order = ["critical", "high", "medium", "low"]
    severity_counts = {s: 0 for s in severity_order}
    for v in all_vulns:
        if v.severity in severity_counts:
            severity_counts[v.severity] += 1
    max_severity_count = max(severity_counts.values()) if any(severity_counts.values()) else 1

    credential_count = db.query(models.CredentialFinding).count()
    critical_vuln_count = (
        db.query(models.Vulnerability)
        .filter((models.Vulnerability.known_exploited.is_(True)) | (models.Vulnerability.cvss >= 9.0))
        .count()
    )

    stats = {
        "host_count": len(hosts),
        "total_vulns": len(all_vulns),
        "critical_vulns": critical_vuln_count,
        "credential_findings": credential_count,
        "attack_paths": len(attack_paths),
    }

    latest_scan = db.query(models.Scan).order_by(models.Scan.started_at.desc()).first()
    recent_scans = db.query(models.Scan).order_by(models.Scan.started_at.desc()).limit(5).all()
    pending_scan_request = (
        db.query(models.ScanRequest).filter(models.ScanRequest.consumed_at.is_(None)).first()
    )
    demo_active = db.query(models.DemoRecord).first() is not None

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "hosts": hosts,
            "events": events,
            "priorities": priorities,
            "attack_paths": attack_paths,
            "stats": stats,
            "severity_counts": severity_counts,
            "severity_order": severity_order,
            "max_severity_count": max_severity_count,
            "latest_scan": latest_scan,
            "recent_scans": recent_scans,
            "pending_scan_request": pending_scan_request is not None,
            "demo_active": demo_active,
            "is_authenticated": current_user is not None,
            "is_admin": current_user is not None and current_user.role == "admin",
            "username": current_user.username if current_user else None,
        },
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
