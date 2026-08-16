import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from . import auth, models, schemas
from .database import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Proyecto Cyber - Network Vulnerability Scanner")
templates = Jinja2Templates(directory="app/templates")

SCANNER_API_KEY = os.environ["SCANNER_API_KEY"]


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
def list_hosts(db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    hosts = db.query(models.Host).order_by(models.Host.ip).all()
    return [
        {
            "id": h.id,
            "ip": h.ip,
            "mac": h.mac,
            "hostname": h.hostname,
            "os_guess": h.os_guess,
            "last_seen": h.last_seen,
            "software_count": len(h.software),
        }
        for h in hosts
    ]


@app.get("/hosts/{host_id}")
def get_host(
    host_id: int, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)
):
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return {
        "id": host.id,
        "ip": host.ip,
        "mac": host.mac,
        "hostname": host.hostname,
        "os_guess": host.os_guess,
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
        host.mac = host_in.mac or host.mac
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


# --- Timeline y priorizacion ---


@app.get("/events")
def list_events(db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
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
def list_priorities(db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
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


# --- Dashboard ---


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("session_token")
    if not token:
        return RedirectResponse("/login")
    try:
        payload = auth.decode_access_token(token)
    except HTTPException:
        return RedirectResponse("/login")

    hosts = db.query(models.Host).order_by(models.Host.ip).all()
    events = db.query(models.Event).order_by(models.Event.occurred_at.desc()).limit(15).all()
    priorities = (
        db.query(models.Vulnerability)
        .join(models.Software)
        .order_by(models.Vulnerability.known_exploited.desc(), models.Vulnerability.cvss.desc().nullslast())
        .limit(5)
        .all()
    )
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "hosts": hosts,
            "events": events,
            "priorities": priorities,
            "username": payload["sub"],
        },
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
