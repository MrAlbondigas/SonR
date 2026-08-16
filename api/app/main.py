import os

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

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
            {"id": s.id, "name": s.name, "version": s.version, "port": s.port}
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
        if host is None:
            host = models.Host(ip=host_in.ip)
            db.add(host)
            db.flush()
        host.mac = host_in.mac or host.mac
        host.hostname = host_in.hostname or host.hostname
        host.os_guess = host_in.os_guess or host.os_guess

        for sw_in in host_in.software:
            db.add(
                models.Software(
                    host_id=host.id,
                    scan_id=scan.id,
                    name=sw_in.name,
                    version=sw_in.version,
                    port=sw_in.port,
                )
            )

    scan.status = "completed"
    db.commit()
    return {"scan_id": scan.id, "hosts_ingested": len(payload.hosts)}


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
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "hosts": hosts, "username": payload["sub"]}
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
