#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           ServerHardenPro — Backend API (FastAPI)               ║
║                          Fase 4                                  ║
║  Uso: uvicorn main:app --reload --host 0.0.0.0 --port 8000      ║
╚══════════════════════════════════════════════════════════════════╝
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel
from typing import List, Optional
import json
import asyncio
import datetime
import os

from report_generator import generate_pdf, generate_excel

from database import (
    init_db, get_db,
    save_audit_result, get_all_servers,
    get_server_detail, get_audit_history,
    get_global_summary
)

# ── App ───────────────────────────────────────────────────────────
app = FastAPI(
    title="ServerHardenPro API",
    description="API de auditoría de hardening para servidores Windows y Linux",
    version="0.1.0"
)

# ── CORS (permite que el frontend se comunique con el backend) ────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket Manager ─────────────────────────────────────────────
class ConnectionManager:
    """Gestiona conexiones WebSocket activas para tiempo real."""
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: dict):
        """Envía un mensaje a todos los clientes conectados."""
        data = json.dumps(message, ensure_ascii=False)
        for ws in self.active.copy():
            try:
                await ws.send_text(data)
            except Exception:
                self.active.remove(ws)

manager = ConnectionManager()

# ══════════════════════════════════════════════════════════════════
#  MODELOS (Pydantic)
# ══════════════════════════════════════════════════════════════════

class CheckItem(BaseModel):
    name: str
    category: str
    description: str
    status: str          # PASS | FAIL | WARN
    severity: str        # ALTA | MEDIA | BAJA
    detail: str

class ServerInfo(BaseModel):
    hostname: str
    os: str
    ip: str
    audit_date: str
    agent_version: str
    platform: Optional[str] = "linux"

class AuditSummary(BaseModel):
    total: int
    pass_: int
    fail: int
    warn: int
    score_percent: int

    class Config:
        fields = {"pass_": "pass"}

class AuditResult(BaseModel):
    server: ServerInfo
    summary: dict
    checks: List[CheckItem]

# ══════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup():
    """Inicializa la base de datos al arrancar."""
    init_db()
    print("✅ Base de datos inicializada")
    print("🚀 ServerHardenPro API corriendo en http://0.0.0.0:8000")

# ── POST /audit — recibe resultado de un agente ───────────────────
@app.post("/audit", summary="Recibir resultado de auditoría")
async def receive_audit(result: AuditResult):
    """
    Endpoint principal — los agentes (Linux/Windows) envían
    su resultado JSON aquí después de correr los checks.
    """
    try:
        save_audit_result(result.dict())

        # Notificar a todos los clientes WebSocket en tiempo real
        await manager.broadcast({
            "event": "new_audit",
            "hostname": result.server.hostname,
            "score": result.summary.get("score_percent", 0),
            "status": _score_to_status(result.summary.get("score_percent", 0)),
            "timestamp": datetime.datetime.now().isoformat()
        })

        return {"ok": True, "message": f"Auditoría de {result.server.hostname} guardada"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── GET /servers — lista todos los servidores ─────────────────────
@app.get("/servers", summary="Listar todos los servidores")
async def list_servers():
    """
    Devuelve la lista de servidores con su último score
    y estado. Usado por el panel para el sidebar.
    """
    servers = get_all_servers()
    return {"servers": servers}

# ── GET /servers/{hostname} — detalle de un servidor ─────────────
@app.get("/servers/{hostname}", summary="Detalle de un servidor")
async def server_detail(hostname: str):
    """
    Devuelve el detalle completo de la última auditoría
    de un servidor específico, incluyendo todos los checks.
    """
    detail = get_server_detail(hostname)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Servidor '{hostname}' no encontrado")
    return detail

# ── GET /servers/{hostname}/history — historial ───────────────────
@app.get("/servers/{hostname}/history", summary="Historial de auditorías")
async def server_history(hostname: str, limit: int = 10):
    """
    Devuelve el historial de scores de un servidor.
    Útil para graficar la evolución del hardening.
    """
    history = get_audit_history(hostname, limit)
    return {"hostname": hostname, "history": history}

# ── GET /summary — resumen global ────────────────────────────────
@app.get("/summary", summary="Resumen global del sistema")
async def global_summary():
    """
    Estadísticas globales: total de servidores,
    checks pasados/fallidos, score promedio.
    """
    return get_global_summary()

# ── GET /health — healthcheck ────────────────────────────────────
@app.get("/health", summary="Healthcheck")
async def health():
    return {"status": "ok", "version": "0.1.0", "time": datetime.datetime.now().isoformat()}

# ── WebSocket /ws — tiempo real ───────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Canal WebSocket para el panel web.
    Recibe notificaciones en tiempo real cuando
    un agente envía una nueva auditoría.
    """
    await manager.connect(websocket)
    try:
        # Enviar estado inicial al conectarse
        summary = get_global_summary()
        await websocket.send_text(json.dumps({
            "event": "connected",
            "summary": summary
        }))
        # Mantener conexión viva
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ── GET /servers/{hostname}/report/pdf ───────────────────────────
@app.get("/servers/{hostname}/report/pdf", summary="Descargar reporte PDF")
async def report_pdf(hostname: str):
    """Genera y descarga un reporte PDF de la última auditoría."""
    data = get_server_detail(hostname)
    if not data:
        raise HTTPException(status_code=404, detail=f"Servidor '{hostname}' no encontrado")
    pdf_bytes = generate_pdf(data)
    filename  = f"reporte_{hostname}_{datetime.date.today()}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# ── GET /servers/{hostname}/report/excel ─────────────────────────
@app.get("/servers/{hostname}/report/excel", summary="Descargar reporte Excel")
async def report_excel(hostname: str):
    """Genera y descarga un reporte Excel de la última auditoría."""
    data = get_server_detail(hostname)
    if not data:
        raise HTTPException(status_code=404, detail=f"Servidor '{hostname}' no encontrado")
    xlsx_bytes = generate_excel(data)
    filename   = f"reporte_{hostname}_{datetime.date.today()}.xlsx"
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# ── Servir el panel frontend ──────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_frontend():
        return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))

# ── Helper ────────────────────────────────────────────────────────
def _score_to_status(score: int) -> str:
    if score >= 80:
        return "OK"
    elif score >= 60:
        return "WARN"
    return "CRIT"
