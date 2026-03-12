#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           ServerHardenPro — Backend API (FastAPI)               ║
║                          Fase 5                                  ║
║  + Auth JWT (login / registro / roles)                           ║
║  + Inventario de hardware                                        ║
╚══════════════════════════════════════════════════════════════════╝
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import json, asyncio, datetime, os, hmac, hashlib, base64, time

from report_generator import generate_pdf, generate_excel
from database import (
    init_db, get_db,
    save_audit_result, get_all_servers,
    get_server_detail, get_audit_history,
    get_global_summary,
    create_user, verify_user, get_user_by_id,
    list_users, users_exist,
    save_log_analysis, get_log_analysis, get_log_history
)

# ══════════════════════════════════════════════════════════════════
#  JWT (implementación manual sin dependencias extra)
# ══════════════════════════════════════════════════════════════════
JWT_SECRET  = os.environ.get("SHP_JWT_SECRET", "shp-super-secret-key-change-in-production")
JWT_EXPIRY  = 60 * 60 * 24  # 24 horas en segundos

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _sign(payload: dict) -> str:
    header  = _b64url(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    body    = _b64url(json.dumps(payload).encode())
    sig     = _b64url(hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"

def create_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "sub": user_id, "username": username, "role": role,
        "iat": int(time.time()), "exp": int(time.time()) + JWT_EXPIRY
    }
    return _sign(payload)

def decode_token(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Token inválido")
        header, body, sig = parts
        expected = _b64url(hmac.new(JWT_SECRET.encode(),
                                    f"{header}.{body}".encode(),
                                    hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise ValueError("Firma inválida")
        padding = 4 - len(body) % 4
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * padding))
        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expirado")
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# ── Bearer auth dependency ────────────────────────────────────────
bearer = HTTPBearer(auto_error=False)

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    if not creds:
        raise HTTPException(status_code=401, detail="Token requerido")
    return decode_token(creds.credentials)

def require_admin(user = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Se requiere rol admin")
    return user

# ══════════════════════════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════════════════════════
app = FastAPI(
    title="ServerHardenPro API",
    description="API de auditoría de hardening — con Auth JWT e Inventario",
    version="0.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
    async def broadcast(self, message: dict):
        data = json.dumps(message, ensure_ascii=False)
        for ws in self.active.copy():
            try:    await ws.send_text(data)
            except: self.active.remove(ws)

manager = ConnectionManager()

# ══════════════════════════════════════════════════════════════════
#  MODELOS
# ══════════════════════════════════════════════════════════════════
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "viewer"

class LoginRequest(BaseModel):
    username: str
    password: str

class CheckItem(BaseModel):
    name: str; category: str; description: str
    status: str; severity: str; detail: str

class ServerInfo(BaseModel):
    hostname: str; os: str; ip: str
    audit_date: str; agent_version: str
    platform: Optional[str] = "linux"
    os_full: Optional[str] = ""

class LogAnalysisRequest(BaseModel):
    hostname: str
    period_hours: Optional[int] = 24
    summary: dict
    top_ips: Optional[list] = []
    top_users: Optional[list] = []
    brute_events: Optional[list] = []
    syslog_errors: Optional[list] = []

class AuditResult(BaseModel):
    server: ServerInfo
    summary: dict
    checks: List[CheckItem]
    inventory: Optional[dict] = {}

# ══════════════════════════════════════════════════════════════════
#  STARTUP
# ══════════════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup():
    init_db()
    print("✅ Base de datos inicializada")
    print("🚀 ServerHardenPro API v0.3 en http://0.0.0.0:8000")

# ══════════════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.get("/auth/status", summary="Estado del sistema de usuarios")
async def auth_status():
    """Informa si ya hay usuarios registrados (para mostrar pantalla de setup)."""
    return {"users_exist": users_exist()}

@app.post("/auth/register", summary="Registrar nuevo usuario")
async def register(req: RegisterRequest):
    """
    Registra un nuevo usuario.
    El primer usuario registrado es automáticamente admin.
    Los siguientes son viewer a menos que un admin los cree con otro rol.
    """
    try:
        user = create_user(req.username, req.email, req.password, req.role)
        token = create_token(user["id"], user["username"], user["role"])
        return {
            "ok": True,
            "token": token,
            "user":  {"id": user["id"], "username": user["username"],
                      "email": user["email"], "role": user["role"]}
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/login", summary="Iniciar sesión")
async def login(req: LoginRequest):
    """Autentica usuario y devuelve token JWT válido por 24hs."""
    user = verify_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    token = create_token(user["id"], user["username"], user["role"])
    return {
        "ok": True,
        "token": token,
        "user": {"id": user["id"], "username": user["username"],
                 "email": user["email"], "role": user["role"]}
    }

@app.get("/auth/me", summary="Perfil del usuario actual")
async def me(user = Depends(get_current_user)):
    """Devuelve el perfil del usuario autenticado."""
    full = get_user_by_id(user["sub"])
    return full or user

@app.get("/auth/users", summary="Listar usuarios (solo admin)")
async def get_users(admin = Depends(require_admin)):
    return {"users": list_users()}

# ══════════════════════════════════════════════════════════════════
#  AUDIT ENDPOINT (público — los agentes no usan JWT)
# ══════════════════════════════════════════════════════════════════
@app.post("/audit", summary="Recibir resultado de auditoría")
async def receive_audit(result: AuditResult):
    try:
        save_audit_result(result.dict())
        await manager.broadcast({
            "event":     "new_audit",
            "hostname":  result.server.hostname,
            "score":     result.summary.get("score_percent", 0),
            "status":    _score_to_status(result.summary.get("score_percent", 0)),
            "timestamp": datetime.datetime.now().isoformat()
        })
        return {"ok": True, "message": f"Auditoría de {result.server.hostname} guardada"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ══════════════════════════════════════════════════════════════════
#  ENDPOINTS PROTEGIDOS (requieren JWT)
# ══════════════════════════════════════════════════════════════════
@app.get("/servers", summary="Listar servidores")
async def list_servers(user = Depends(get_current_user)):
    return {"servers": get_all_servers()}

@app.get("/servers/{hostname}", summary="Detalle de servidor")
async def server_detail(hostname: str, user = Depends(get_current_user)):
    detail = get_server_detail(hostname)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Servidor '{hostname}' no encontrado")
    return detail

@app.get("/servers/{hostname}/history", summary="Historial")
async def server_history(hostname: str, limit: int = 20, user = Depends(get_current_user)):
    return {"hostname": hostname, "history": get_audit_history(hostname, limit)}

@app.get("/servers/{hostname}/inventory", summary="Inventario de hardware")
async def server_inventory(hostname: str, user = Depends(get_current_user)):
    detail = get_server_detail(hostname)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Servidor '{hostname}' no encontrado")
    return {"hostname": hostname, "inventory": detail.get("inventory", {})}

@app.get("/summary", summary="Resumen global")
async def global_summary(user = Depends(get_current_user)):
    return get_global_summary()

@app.get("/health", summary="Healthcheck")
async def health():
    return {"status": "ok", "version": "0.3.0", "time": datetime.datetime.now().isoformat()}

# ── Reportes (solo admin puede descargar) ─────────────────────────
@app.get("/servers/{hostname}/report/pdf")
async def report_pdf(hostname: str, admin = Depends(require_admin)):
    data = get_server_detail(hostname)
    if not data:
        raise HTTPException(status_code=404)
    pdf_bytes = generate_pdf(data)
    filename  = f"reporte_{hostname}_{datetime.date.today()}.pdf"
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@app.get("/servers/{hostname}/report/excel")
async def report_excel(hostname: str, admin = Depends(require_admin)):
    data = get_server_detail(hostname)
    if not data:
        raise HTTPException(status_code=404)
    xlsx_bytes = generate_excel(data)
    filename   = f"reporte_{hostname}_{datetime.date.today()}.xlsx"
    return Response(content=xlsx_bytes,
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

# ── POST /logs — recibe análisis de logs del agente ──────────────
@app.post("/logs", summary="Recibir análisis de logs")
async def receive_logs(req: LogAnalysisRequest):
    try:
        save_log_analysis(req.hostname, req.dict())
        # Notificar panel en tiempo real
        bf = req.summary.get("brute_force_count", 0)
        await manager.broadcast({
            "event":    "new_logs",
            "hostname": req.hostname,
            "brute_force": bf,
            "auth_fail":   req.summary.get("auth_fail_total", 0),
            "alert":    bf > 0,
            "timestamp": datetime.datetime.now().isoformat()
        })
        return {"ok": True, "message": f"Logs de {req.hostname} guardados"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── GET /servers/{hostname}/logs ──────────────────────────────────
@app.get("/servers/{hostname}/logs", summary="Análisis de logs de un servidor")
async def server_logs(hostname: str, user = Depends(get_current_user)):
    data = get_log_analysis(hostname)
    if not data:
        return {"hostname": hostname, "data": None, "message": "Sin datos de logs aún"}
    return {"hostname": hostname, "data": data}

# ── GET /servers/{hostname}/logs/history ─────────────────────────
@app.get("/servers/{hostname}/logs/history", summary="Historial de logs")
async def server_logs_history(hostname: str, limit: int = 14,
                               user = Depends(get_current_user)):
    return {"hostname": hostname, "history": get_log_history(hostname, limit)}

# ── WebSocket ─────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        summary = get_global_summary()
        await websocket.send_text(json.dumps({"event":"connected","summary":summary}))
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"event":"ping"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ── Frontend ──────────────────────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_frontend():
        return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))

def _score_to_status(score: int) -> str:
    if score >= 80: return "OK"
    if score >= 60: return "WARN"
    return "CRIT"
