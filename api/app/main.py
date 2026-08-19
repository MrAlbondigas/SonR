import math
import os
import shlex
from datetime import datetime, timedelta, timezone

import paramiko
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
SERVICE_REMOVAL_THRESHOLD = 3
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "").strip()


def send_webhook_alert(
    db: Session, message: str, vulnerability_id: int | None = None, host_id: int | None = None
) -> bool:
    success = False
    if ALERT_WEBHOOK_URL:
        try:
            resp = requests.post(
                ALERT_WEBHOOK_URL,
                json={"content": message, "text": message},
                timeout=6,
            )
            success = resp.status_code < 300
        except requests.RequestException:
            success = False
    db.add(
        models.Alert(
            vulnerability_id=vulnerability_id,
            host_id=host_id,
            channel="webhook",
            description=message,
            success=success,
        )
    )
    db.commit()
    return success


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
            "software_count": len([s for s in h.software if s.removed_at is None]),
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


# --- Politica de escaneo ---


def get_or_create_policy(db: Session) -> models.ScanPolicy:
    policy = db.query(models.ScanPolicy).filter(models.ScanPolicy.id == 1).first()
    if policy is None:
        policy = models.ScanPolicy(id=1)
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy


def policy_to_dict(policy: models.ScanPolicy) -> dict:
    return {
        "enabled": policy.enabled,
        "interval_seconds": policy.interval_seconds,
        "excluded_ips": [ip for ip in policy.excluded_ips.split(",") if ip],
        "quiet_hours_start": policy.quiet_hours_start,
        "quiet_hours_end": policy.quiet_hours_end,
        "updated_at": policy.updated_at,
        "updated_by": policy.updated_by,
    }


@app.get("/scan/policy")
def get_scan_policy(db: Session = Depends(get_db)):
    return policy_to_dict(get_or_create_policy(db))


@app.post("/scan/policy")
def set_scan_policy(
    payload: schemas.ScanPolicyUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(auth.require_admin),
):
    if not (60 <= payload.interval_seconds <= 86400):
        raise HTTPException(status_code=400, detail="El intervalo debe estar entre 60 y 86400 segundos")
    for hour in (payload.quiet_hours_start, payload.quiet_hours_end):
        if hour is not None and not (0 <= hour <= 23):
            raise HTTPException(status_code=400, detail="Las horas deben estar entre 0 y 23")

    policy = get_or_create_policy(db)
    policy.enabled = payload.enabled
    policy.interval_seconds = payload.interval_seconds
    clean_ips = sorted({ip.strip() for ip in payload.excluded_ips if ip.strip()})
    policy.excluded_ips = ",".join(clean_ips)
    policy.quiet_hours_start = payload.quiet_hours_start
    policy.quiet_hours_end = payload.quiet_hours_end
    policy.updated_at = func.now()
    policy.updated_by = admin.username
    db.commit()
    return {"ok": True, **policy_to_dict(policy)}


@app.get("/scan/config", dependencies=[Depends(verify_scanner_key)])
def get_scan_config(db: Session = Depends(get_db)):
    return policy_to_dict(get_or_create_policy(db))


# --- Escaneo bajo demanda ---


@app.post("/scan/request")
def request_scan(
    db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)
):
    policy = get_or_create_policy(db)
    if not policy.enabled:
        raise HTTPException(
            status_code=409, detail="El escaneo esta desactivado por politica del administrador"
        )
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

    excluded_ips = set(policy_to_dict(get_or_create_policy(db))["excluded_ips"])

    for host_in in payload.hosts:
        if host_in.ip in excluded_ips:
            continue
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

        seen_keys = set()
        for sw_in in host_in.software:
            seen_keys.add((sw_in.name, sw_in.port))
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
                existing.missed_scans = 0
                if existing.removed_at is not None:
                    existing.removed_at = None
                    db.add(
                        models.Event(
                            host_id=host.id,
                            event_type="new_service",
                            description=f"Servicio vuelve a estar activo en {host_in.ip}: {sw_in.name} (puerto {sw_in.port})",
                        )
                    )
                if sw_in.version and existing.version != sw_in.version:
                    resolved_count = 0
                    for v in open_vulns(existing):
                        v.resolved_at = func.now()
                        v.status = "resuelta"
                        resolved_count += 1
                    db.add(
                        models.Event(
                            host_id=host.id,
                            event_type="version_change",
                            description=(
                                f"{sw_in.name} en {host_in.ip} cambio de version: "
                                f"{existing.version or 'desconocida'} -> {sw_in.version}"
                                + (f" ({resolved_count} vulnerabilidad(es) marcada(s) como resueltas, pendiente de reverificar)" if resolved_count else "")
                            ),
                        )
                    )
                    existing.version = sw_in.version
                    existing.cve_checked_at = None
                existing.scan_id = scan.id
                existing.detected_at = func.now()

        if not is_new_host:
            still_present = (
                db.query(models.Software)
                .filter(models.Software.host_id == host.id, models.Software.removed_at.is_(None))
                .all()
            )
            for sw in still_present:
                if (sw.name, sw.port) in seen_keys:
                    continue
                sw.missed_scans += 1
                # exige varios escaneos consecutivos sin verlo antes de darlo por caido: un solo
                # escaneo con -T4/top-ports puede fallar en detectar un puerto que sigue abierto
                if sw.missed_scans < SERVICE_REMOVAL_THRESHOLD:
                    continue
                sw.removed_at = func.now()
                resolved_count = 0
                for v in open_vulns(sw):
                    v.resolved_at = func.now()
                    v.status = "resuelta"
                    resolved_count += 1
                db.add(
                    models.Event(
                        host_id=host.id,
                        event_type="service_removed",
                        description=(
                            f"Servicio ya no detectado en {host_in.ip} tras {sw.missed_scans} escaneos seguidos: "
                            f"{sw.name} (puerto {sw.port})"
                            + (f" — {resolved_count} vulnerabilidad(es) asociada(s) marcada(s) como resuelta(s)" if resolved_count else "")
                        ),
                    )
                )

    scan.status = "completed"
    scan.finished_at = func.now()
    db.commit()
    record_risk_snapshot(db)
    return {"scan_id": scan.id, "hosts_ingested": len(payload.hosts)}


# --- Vulnerability enrichment (usado por el servicio enricher) ---


@app.get("/software/pending", dependencies=[Depends(verify_scanner_key)])
def software_pending(db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    rows = (
        db.query(models.Software)
        .filter(
            models.Software.removed_at.is_(None),
            (models.Software.cve_checked_at.is_(None)) | (models.Software.cve_checked_at < cutoff),
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

    existing_by_cve = {v.cve_id: v for v in software.vulnerabilities}
    new_count = 0
    reopened_count = 0
    pending_alerts = []
    for vuln_in in payload.vulnerabilities:
        existing = existing_by_cve.get(vuln_in.cve_id)
        if existing is not None:
            if existing.resolved_at is not None:
                existing.resolved_at = None
                existing.status = "abierta"
                reopened_count += 1
                db.add(
                    models.Event(
                        host_id=software.host_id,
                        event_type="vuln_reopened",
                        description=(
                            f"{vuln_in.cve_id} vuelve a detectarse en {software.name}: "
                            f"la version instalada sigue siendo vulnerable"
                        ),
                    )
                )
            continue
        new_vuln = models.Vulnerability(software_id=software.id, **vuln_in.model_dump())
        db.add(new_vuln)
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
            pending_alerts.append(
                (
                    new_vuln,
                    f"🚨 Vulnerabilidad critica con exploit publico conocido en "
                    f"{software.host.ip} ({software.name}): {vuln_in.cve_id}",
                )
            )
    software.cve_checked_at = datetime.now(timezone.utc)
    db.commit()
    if new_count or reopened_count:
        record_risk_snapshot(db)
    for vuln_obj, message in pending_alerts:
        send_webhook_alert(db, message, vulnerability_id=vuln_obj.id, host_id=software.host_id)
    return {"software_id": software.id, "new_vulnerabilities": new_count, "reopened": reopened_count}


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
        record_risk_snapshot(db)
        send_webhook_alert(
            db,
            f"🔑 Credenciales por defecto validas en {host.ip if host else payload.host_id} "
            f"puerto {payload.port} ({payload.service}): {payload.username}/{payload.password}",
            host_id=payload.host_id,
        )
    return {"ok": True}


# --- Alertas (webhook saliente) ---


@app.get("/webhook/status")
def webhook_status(db: Session = Depends(get_db)):
    last = db.query(models.Alert).order_by(models.Alert.id.desc()).first()
    return {
        "configured": bool(ALERT_WEBHOOK_URL),
        "last_sent_at": last.sent_at if last else None,
        "last_success": last.success if last else None,
    }


@app.post("/webhook/test")
def webhook_test(db: Session = Depends(get_db), admin: models.User = Depends(auth.require_admin)):
    success = send_webhook_alert(
        db, f"✅ Prueba de webhook desde Proyecto Cyber, enviada por {admin.username}."
    )
    return {"ok": True, "configured": bool(ALERT_WEBHOOK_URL), "delivered": success}


@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    alerts = db.query(models.Alert).order_by(models.Alert.id.desc()).limit(20).all()
    return [
        {
            "id": a.id,
            "description": a.description,
            "channel": a.channel,
            "success": a.success,
            "sent_at": a.sent_at,
        }
        for a in alerts
    ]


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
        .filter(models.Vulnerability.resolved_at.is_(None), models.Software.removed_at.is_(None))
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


@app.post("/vulnerabilities/{vuln_id}/status")
def update_vulnerability_status(
    vuln_id: int,
    payload: schemas.VulnStatusUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(auth.require_admin),
):
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    if payload.status not in VULN_STATUS_LABELS:
        raise HTTPException(status_code=400, detail="Invalid status")

    vuln.status = payload.status
    if payload.status in VULN_CLOSED_STATUSES:
        if vuln.resolved_at is None:
            vuln.resolved_at = func.now()
    else:
        vuln.resolved_at = None

    db.add(
        models.Event(
            host_id=vuln.software.host_id,
            event_type="vuln_status_change",
            description=(
                f"{vuln.cve_id or vuln.software.name} en {vuln.software.host.ip} marcado como "
                f"'{VULN_STATUS_LABELS[payload.status]}' por {admin.username}"
            ),
        )
    )
    db.commit()
    record_risk_snapshot(db)
    return {"ok": True, "status": vuln.status}


SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}
KEV_BONUS = 8
CREDENTIAL_BONUS = 12
VULN_STATUS_LABELS = {
    "abierta": "Abierta",
    "reconocida": "Reconocida",
    "en_progreso": "En progreso",
    "resuelta": "Resuelta",
    "ignorada": "Ignorada (riesgo aceptado)",
}
VULN_CLOSED_STATUSES = {"resuelta", "ignorada"}
RISK_LEVELS = [
    (18, "critico", "Crítico", "var(--status-critical)"),
    (8, "alto", "Alto", "var(--status-serious)"),
    (1, "medio", "Medio", "var(--status-warning)"),
    (0, "bajo", "Bajo", "var(--status-good)"),
]


def open_vulns(software: models.Software) -> list[models.Vulnerability]:
    return [v for v in software.vulnerabilities if v.resolved_at is None]


def risk_level_for_score(score: int) -> tuple[str, str, str]:
    for threshold, key, label, color in RISK_LEVELS:
        if score >= threshold:
            return key, label, color
    return RISK_LEVELS[-1][1], RISK_LEVELS[-1][2], RISK_LEVELS[-1][3]


def compute_security_grade(
    severity_counts: dict,
    credential_count: int,
    attack_path_count: int,
    aging_count: int,
    kev_count: int,
) -> dict:
    score = 100.0
    breakdown = []

    def deduct(points: float, count: int, label: str) -> None:
        nonlocal score
        if not count:
            return
        total = round(points * count, 1)
        score -= total
        breakdown.append({"points": total, "text": f"{count} {label}"})

    deduct(8, severity_counts.get("critical", 0), "vulnerabilidad(es) crítica(s)")
    deduct(4, severity_counts.get("high", 0), "vulnerabilidad(es) alta(s)")
    deduct(2, severity_counts.get("medium", 0), "vulnerabilidad(es) media(s)")
    deduct(0.5, severity_counts.get("low", 0), "vulnerabilidad(es) baja(s)")
    deduct(10, kev_count, "vulnerabilidad(es) con exploit público conocido")
    deduct(15, credential_count, "credencial(es) por defecto")
    deduct(10, attack_path_count, "ruta(s) de ataque activa(s)")
    deduct(3, aging_count, "vulnerabilidad(es) abierta(s) hace más de 14 días")

    score = max(0, min(100, round(score)))
    if score >= 90:
        letter, color = "A", "var(--status-good)"
    elif score >= 80:
        letter, color = "B", "var(--series-aqua)"
    elif score >= 70:
        letter, color = "C", "var(--status-warning)"
    elif score >= 60:
        letter, color = "D", "var(--status-serious)"
    else:
        letter, color = "F", "var(--status-critical)"

    return {"score": score, "letter": letter, "color": color, "breakdown": breakdown}


ROUTER_VENDOR_HINTS = (
    "tp-link", "netgear", "d-link", "asus", "ubiquiti", "mikrotik", "huawei technologies",
    "cisco", "linksys", "zyxel", "technicolor", "arris", "sagemcom", "fritz", "avm audiovis",
)
PRINTER_VENDOR_HINTS = ("hewlett packard", "hp inc", "canon", "epson", "brother", "lexmark", "xerox")
IOT_VENDOR_HINTS = (
    "google", "amazon", "sonos", "philips", "espressif", "xiaomi", "roku", "belkin",
    "shelly", "tuya", "nest labs", "ring llc", "wyze", "chromecast", "sonoff", "tp-link",
)
APPLE_VENDOR_HINTS = ("apple",)
DEVICE_TYPE_LABELS = {
    "router": "Router / Gateway",
    "printer": "Impresora",
    "iot": "IoT / Domótica",
    "server": "Servidor",
    "windows": "PC Windows",
    "linux": "PC / Servidor Linux",
    "mac": "Mac",
    "mobile": "Móvil / Tablet",
    "unknown": "Sin clasificar",
}


def classify_device(host: models.Host) -> dict:
    vendor = (host.vendor or "").lower()
    os_guess = (host.os_guess or "").lower()
    hostname = (host.hostname or "").lower()
    ports = {s.port for s in host.software if s.removed_at is None and s.port}

    key = "unknown"
    if (
        (host.ip.endswith(".1") or any(h in vendor for h in ROUTER_VENDOR_HINTS) or "embedded" in os_guess)
        and not ({631, 9100, 515} & ports)
    ):
        key = "router"
    elif any(h in vendor for h in PRINTER_VENDOR_HINTS) or ({631, 9100, 515} & ports):
        key = "printer"
    elif "windows" in os_guess or ({135, 139, 445, 3389} & ports):
        key = "windows"
    elif any(h in vendor for h in APPLE_VENDOR_HINTS):
        key = "mobile" if any(h in hostname for h in ("iphone", "ipad", "ios")) else "mac"
    elif any(h in hostname for h in ("iphone", "android", "galaxy", "-phone", "redmi", "pixel")):
        key = "mobile"
    elif any(h in vendor for h in IOT_VENDOR_HINTS) or (
        ({8008, 8009, 1900, 8123, 8443} & ports) and len(ports) <= 3
    ):
        key = "iot"
    elif "linux" in os_guess:
        server_ports = {22, 80, 443, 3306, 5432, 8080, 21, 25}
        if len(server_ports & ports) >= 2 or "server" in hostname or "srv" in hostname:
            key = "server"
        else:
            key = "linux"

    return {"key": key, "label": DEVICE_TYPE_LABELS[key]}


def compute_host_risk(host: models.Host) -> dict:
    score = 0
    open_vuln_count = 0
    for s in host.software:
        if s.removed_at is not None:
            continue
        for v in open_vulns(s):
            open_vuln_count += 1
            score += SEVERITY_WEIGHTS.get(v.severity, 2)
            if v.known_exploited:
                score += KEV_BONUS
    score += CREDENTIAL_BONUS * len(host.credential_findings)
    level_key, level_label, level_color = risk_level_for_score(score)
    return {
        "host_id": host.id,
        "ip": host.ip,
        "hostname": host.hostname,
        "score": score,
        "open_vulns": open_vuln_count,
        "credential_findings": len(host.credential_findings),
        "level_key": level_key,
        "level_label": level_label,
        "level_color": level_color,
    }


def record_risk_snapshot(db: Session) -> None:
    hosts = db.query(models.Host).all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_score = 0
    for host in hosts:
        risk = compute_host_risk(host)
        total_score += risk["score"]
        for s in host.software:
            if s.removed_at is not None:
                continue
            for v in open_vulns(s):
                if v.severity in counts:
                    counts[v.severity] += 1
    credential_count = db.query(models.CredentialFinding).count()

    last = db.query(models.RiskSnapshot).order_by(models.RiskSnapshot.id.desc()).first()
    if (
        last is not None
        and last.host_count == len(hosts)
        and last.critical_count == counts["critical"]
        and last.high_count == counts["high"]
        and last.medium_count == counts["medium"]
        and last.low_count == counts["low"]
        and last.credential_findings == credential_count
        and last.total_score == total_score
    ):
        return

    db.add(
        models.RiskSnapshot(
            host_count=len(hosts),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            credential_findings=credential_count,
            total_score=total_score,
        )
    )
    db.commit()


def compute_attack_paths(db: Session) -> list[dict]:
    hosts = db.query(models.Host).all()
    total_hosts = len(hosts)
    paths = []

    for host in hosts:
        critical_vulns = [
            v
            for s in host.software
            if s.removed_at is None
            for v in open_vulns(s)
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


# --- Parcheo automatico por SSH (solo equipos con SSH abierto y credenciales guardadas) ---

PACKAGE_NAME_OVERRIDES = {
    "openssh": "openssh-server",
    "apache": "apache2",
    "apache httpd": "apache2",
    "mysql": "mysql-server",
    "mariadb": "mariadb-server",
    "postgresql": "postgresql",
    "proftpd": "proftpd-basic",
}
DEBIAN_LIKE = ("ubuntu", "debian", "kali", "mint")
REDHAT_LIKE = ("centos", "red hat", "rhel", "fedora", "rocky", "alma")


def host_has_ssh(host: models.Host) -> bool:
    return any(s.port == 22 and s.removed_at is None for s in host.software)


def generate_patch_command(os_guess: str | None, software_name: str) -> str | None:
    pkg_raw = PACKAGE_NAME_OVERRIDES.get(software_name.lower(), software_name.lower().split(" ")[0])
    pkg = "".join(ch for ch in pkg_raw if ch.isalnum() or ch in "-+.")
    if not pkg:
        return None
    os_l = (os_guess or "").lower()
    if any(k in os_l for k in REDHAT_LIKE):
        return f"yum update -y {pkg}"
    # sin os_guess fiable, la mayoria de equipos domesticos/practicas son Debian-like: usamos apt como mejor estimacion
    if any(k in os_l for k in DEBIAN_LIKE) or not os_l or "linux" in os_l:
        return f"apt-get update -qq && apt-get install --only-upgrade -y {pkg}"
    return None


def run_ssh_patch(host_ip: str, username: str, password: str, command: str) -> tuple[bool, str]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host_ip, username=username, password=password, timeout=10, banner_timeout=10)
        # sudo -S via stdin: mas simple que configurar NOPASSWD, a costa de que la contrasena
        # queda un instante visible en la lista de procesos remota (aceptable en este contexto de laboratorio)
        full_cmd = f"echo {shlex.quote(password)} | sudo -S {command}"
        _, stdout, stderr = client.exec_command(full_cmd, timeout=90)
        exit_status = stdout.channel.recv_exit_status()
        output = (stdout.read().decode(errors="replace") + "\n" + stderr.read().decode(errors="replace")).strip()
        return exit_status == 0, output[-2000:]
    except Exception as exc:
        return False, str(exc)
    finally:
        client.close()


@app.get("/ssh/hosts")
def list_ssh_hosts(db: Session = Depends(get_db), admin: models.User = Depends(auth.require_admin)):
    hosts = db.query(models.Host).order_by(models.Host.ip).all()
    creds_by_host = {c.host_id: c for c in db.query(models.SSHCredential).all()}
    return [
        {
            "host_id": h.id,
            "ip": h.ip,
            "hostname": h.hostname,
            "username": creds_by_host[h.id].username if h.id in creds_by_host else None,
            "has_credentials": h.id in creds_by_host,
        }
        for h in hosts
        if host_has_ssh(h)
    ]


@app.post("/hosts/{host_id}/ssh-credentials")
def save_ssh_credentials(
    host_id: int,
    payload: schemas.SSHCredentialIn,
    db: Session = Depends(get_db),
    admin: models.User = Depends(auth.require_admin),
):
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = db.query(models.SSHCredential).filter(models.SSHCredential.host_id == host_id).first()
    if cred is None:
        cred = models.SSHCredential(host_id=host_id, username=payload.username, password=payload.password)
        db.add(cred)
    else:
        cred.username = payload.username
        cred.password = payload.password
    cred.updated_at = func.now()
    cred.updated_by = admin.username
    db.commit()
    return {"ok": True}


@app.delete("/hosts/{host_id}/ssh-credentials")
def delete_ssh_credentials(
    host_id: int, db: Session = Depends(get_db), admin: models.User = Depends(auth.require_admin)
):
    db.query(models.SSHCredential).filter(models.SSHCredential.host_id == host_id).delete()
    db.commit()
    return {"ok": True}


@app.get("/patch/log")
def get_patch_log(db: Session = Depends(get_db), admin: models.User = Depends(auth.require_admin)):
    rows = db.query(models.PatchLog).order_by(models.PatchLog.id.desc()).limit(20).all()
    return [
        {
            "id": r.id,
            "host_ip": r.host.ip if r.host else None,
            "command": r.command,
            "success": r.success,
            "output": r.output,
            "executed_at": r.executed_at,
            "executed_by": r.executed_by,
        }
        for r in rows
    ]


@app.post("/vulnerabilities/{vuln_id}/patch")
def patch_vulnerability(
    vuln_id: int, db: Session = Depends(get_db), admin: models.User = Depends(auth.require_admin)
):
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    software = vuln.software
    host = software.host
    if not host_has_ssh(host):
        raise HTTPException(status_code=400, detail="Este equipo no tiene el puerto SSH (22) detectado")
    cred = db.query(models.SSHCredential).filter(models.SSHCredential.host_id == host.id).first()
    if cred is None:
        raise HTTPException(status_code=400, detail="Guarda credenciales SSH para este equipo antes de parchear")

    command = generate_patch_command(host.os_guess, software.name)
    if command is None:
        raise HTTPException(
            status_code=400,
            detail="No se pudo generar un comando de parcheo automatico para este software/SO. Aplica el parche manualmente.",
        )

    success, output = run_ssh_patch(host.ip, cred.username, cred.password, command)

    db.add(
        models.PatchLog(
            vulnerability_id=vuln.id,
            host_id=host.id,
            command=command,
            success=success,
            output=output,
            executed_by=admin.username,
        )
    )
    if success:
        vuln.status = "resuelta"
        vuln.resolved_at = func.now()
        db.add(
            models.Event(
                host_id=host.id,
                event_type="vuln_patched",
                description=(
                    f"{vuln.cve_id or software.name} parcheado automaticamente por SSH en {host.ip} "
                    f"por {admin.username}: {command}"
                ),
            )
        )
    db.commit()
    if success:
        record_risk_snapshot(db)
        send_webhook_alert(
            db,
            f"🛠️ Parche aplicado automaticamente en {host.ip} ({software.name}): {vuln.cve_id or ''}".strip(),
            vulnerability_id=vuln.id,
            host_id=host.id,
        )
    return {"ok": True, "success": success, "command": command, "output": output}


# --- Reportes ---


@app.get("/reports/data", dependencies=[Depends(verify_scanner_key)])
def report_data(db: Session = Depends(get_db)):
    hosts = db.query(models.Host).order_by(models.Host.ip).all()
    priorities = (
        db.query(models.Vulnerability)
        .join(models.Software)
        .filter(models.Vulnerability.resolved_at.is_(None), models.Software.removed_at.is_(None))
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
    record_risk_snapshot(db)
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
    record_risk_snapshot(db)
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
        .filter(models.Vulnerability.resolved_at.is_(None), models.Software.removed_at.is_(None))
        .order_by(models.Vulnerability.known_exploited.desc(), models.Vulnerability.cvss.desc().nullslast())
        .limit(5)
        .all()
    )
    attack_paths = compute_attack_paths(db)

    all_vulns = (
        db.query(models.Vulnerability)
        .join(models.Software)
        .filter(models.Vulnerability.resolved_at.is_(None), models.Software.removed_at.is_(None))
        .all()
    )
    severity_order = ["critical", "high", "medium", "low"]
    severity_counts = {s: 0 for s in severity_order}
    for v in all_vulns:
        if v.severity in severity_counts:
            severity_counts[v.severity] += 1
    max_severity_count = max(severity_counts.values()) if any(severity_counts.values()) else 1

    credential_count = db.query(models.CredentialFinding).count()
    critical_vuln_count = sum(
        1 for v in all_vulns if v.known_exploited or (v.cvss or 0) >= 9.0
    )

    # --- Flujo de remediacion ---
    open_vulns_sorted = sorted(
        all_vulns, key=lambda v: (0 if v.known_exploited else 1, -(v.cvss or 0))
    )
    remediation_status_counts = {"abierta": 0, "reconocida": 0, "en_progreso": 0}
    aging_cutoff = datetime.now(timezone.utc) - timedelta(days=14)
    aging_count = 0
    for v in all_vulns:
        remediation_status_counts[v.status] = remediation_status_counts.get(v.status, 0) + 1
        if v.detected_at and v.detected_at < aging_cutoff:
            aging_count += 1
    resolved_vulns_all = (
        db.query(models.Vulnerability).filter(models.Vulnerability.resolved_at.isnot(None)).all()
    )
    if resolved_vulns_all:
        avg_remediation_days = round(
            sum((v.resolved_at - v.detected_at).total_seconds() for v in resolved_vulns_all)
            / len(resolved_vulns_all)
            / 86400,
            1,
        )
    else:
        avg_remediation_days = None

    kev_count = sum(1 for v in all_vulns if v.known_exploited)
    security_grade = compute_security_grade(
        severity_counts, credential_count, len(attack_paths), aging_count, kev_count
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
    recent_alerts = db.query(models.Alert).order_by(models.Alert.id.desc()).limit(10).all()
    scan_policy = policy_to_dict(get_or_create_policy(db))
    scan_policy["interval_minutes"] = max(1, scan_policy["interval_seconds"] // 60)

    # --- Parcheo automatico por SSH ---
    ssh_creds_by_host = {c.host_id: c for c in db.query(models.SSHCredential).all()}
    ssh_hosts = [
        {
            "host_id": h.id,
            "ip": h.ip,
            "hostname": h.hostname,
            "username": ssh_creds_by_host[h.id].username if h.id in ssh_creds_by_host else None,
            "has_credentials": h.id in ssh_creds_by_host,
        }
        for h in hosts
        if host_has_ssh(h)
    ]
    patchable_host_ids = {h["host_id"] for h in ssh_hosts if h["has_credentials"]}
    patch_log = db.query(models.PatchLog).order_by(models.PatchLog.id.desc()).limit(15).all()

    device_types = {h.id: classify_device(h) for h in hosts}

    # --- Riesgo y tendencia ---
    host_risks = sorted((compute_host_risk(h) for h in hosts), key=lambda r: r["score"], reverse=True)
    host_risk_by_id = {r["host_id"]: r for r in host_risks}
    network_score = sum(r["score"] for r in host_risks)
    network_avg = round(network_score / len(hosts)) if hosts else 0
    network_level_key, network_level_label, network_level_color = risk_level_for_score(network_avg)
    stats["risk_score"] = network_score

    snapshots = (
        db.query(models.RiskSnapshot).order_by(models.RiskSnapshot.id.desc()).limit(40).all()
    )
    snapshots.reverse()
    risk_delta = None
    if len(snapshots) >= 2:
        risk_delta = snapshots[-1].total_score - snapshots[-2].total_score

    chart_w, chart_h, pad = 640, 160, 12
    max_snap_score = max((s.total_score for s in snapshots), default=0) or 1
    step_x = (chart_w - 2 * pad) / (len(snapshots) - 1) if len(snapshots) > 1 else 0
    trend_points = []
    for i, s in enumerate(snapshots):
        x = pad + i * step_x
        y = chart_h - pad - (s.total_score / max_snap_score) * (chart_h - 2 * pad)
        trend_points.append(f"{x:.1f},{y:.1f}")
    trend_line = " ".join(trend_points)
    trend_area = ""
    if trend_points:
        first_x = trend_points[0].split(",")[0]
        last_x = trend_points[-1].split(",")[0]
        trend_area = f"{first_x},{chart_h - pad} " + trend_line + f" {last_x},{chart_h - pad}"

    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    new_vulns_7d = (
        db.query(models.Vulnerability).filter(models.Vulnerability.detected_at >= week_ago).count()
    )
    resolved_vulns_7d = (
        db.query(models.Vulnerability).filter(models.Vulnerability.resolved_at >= week_ago).count()
    )
    new_hosts_7d = db.query(models.Host).filter(models.Host.first_seen >= week_ago).count()

    # --- Topologia de red ---
    topo_w, topo_h = 640, 420
    topo_cx, topo_cy = topo_w / 2, topo_h / 2
    topo_radius = min(topo_w, topo_h) / 2 - 70
    topo_nodes = []
    n = len(hosts)
    for i, h in enumerate(hosts):
        angle = (2 * math.pi * i / n) - (math.pi / 2) if n else 0
        risk = host_risk_by_id[h.id]
        topo_nodes.append(
            {
                "id": h.id,
                "ip": h.ip,
                "label": h.ip.rsplit(".", 1)[-1],
                "hostname": h.hostname,
                "x": round(topo_cx + topo_radius * math.cos(angle), 1),
                "y": round(topo_cy + topo_radius * math.sin(angle), 1),
                "score": risk["score"],
                "level_label": risk["level_label"],
                "level_color": risk["level_color"],
                "software_count": len(h.software),
                "type_label": device_types[h.id]["label"],
            }
        )
    attack_path_host_ids = {p["host_id"] for p in attack_paths}
    topo_lateral_edges = []
    if attack_path_host_ids and n <= 15:
        for node in topo_nodes:
            if node["id"] not in attack_path_host_ids:
                continue
            for other in topo_nodes:
                if other["id"] == node["id"]:
                    continue
                topo_lateral_edges.append(
                    {"x1": node["x"], "y1": node["y"], "x2": other["x"], "y2": other["y"]}
                )

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
            "webhook_configured": bool(ALERT_WEBHOOK_URL),
            "recent_alerts": recent_alerts,
            "is_authenticated": current_user is not None,
            "is_admin": current_user is not None and current_user.role == "admin",
            "username": current_user.username if current_user else None,
            "host_risks": host_risks,
            "host_risk_by_id": host_risk_by_id,
            "network_score": network_score,
            "network_avg": network_avg,
            "network_level_label": network_level_label,
            "network_level_color": network_level_color,
            "risk_delta": risk_delta,
            "snapshot_count": len(snapshots),
            "chart_w": chart_w,
            "chart_h": chart_h,
            "trend_line": trend_line,
            "trend_area": trend_area,
            "new_vulns_7d": new_vulns_7d,
            "resolved_vulns_7d": resolved_vulns_7d,
            "new_hosts_7d": new_hosts_7d,
            "topo_w": topo_w,
            "topo_h": topo_h,
            "topo_cx": topo_cx,
            "topo_cy": topo_cy,
            "topo_nodes": topo_nodes,
            "topo_lateral_edges": topo_lateral_edges,
            "attack_path_host_ids": attack_path_host_ids,
            "open_vulns_sorted": open_vulns_sorted,
            "remediation_status_counts": remediation_status_counts,
            "aging_count": aging_count,
            "avg_remediation_days": avg_remediation_days,
            "vuln_status_labels": VULN_STATUS_LABELS,
            "scan_policy": scan_policy,
            "ssh_hosts": ssh_hosts,
            "patchable_host_ids": patchable_host_ids,
            "patch_log": patch_log,
            "security_grade": security_grade,
            "device_types": device_types,
        },
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
