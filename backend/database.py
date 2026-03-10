"""
╔══════════════════════════════════════════════════════════════════╗
║           ServerHardenPro — Base de Datos (SQLite)              ║
║                          Fase 4                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sqlite3
import json
import os
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "shp_database.db")

# ══════════════════════════════════════════════════════════════════
#  INICIALIZACIÓN
# ══════════════════════════════════════════════════════════════════

def init_db():
    """Crea las tablas si no existen."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Tabla de servidores
    c.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname    TEXT UNIQUE NOT NULL,
            ip          TEXT,
            os          TEXT,
            platform    TEXT DEFAULT 'linux',
            first_seen  TEXT,
            last_seen   TEXT
        )
    """)

    # Tabla de auditorías (una por ejecución del agente)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id    INTEGER NOT NULL,
            audit_date   TEXT NOT NULL,
            score        INTEGER DEFAULT 0,
            total        INTEGER DEFAULT 0,
            pass_count   INTEGER DEFAULT 0,
            fail_count   INTEGER DEFAULT 0,
            warn_count   INTEGER DEFAULT 0,
            raw_json     TEXT,
            FOREIGN KEY (server_id) REFERENCES servers(id)
        )
    """)

    # Tabla de checks individuales
    c.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id    INTEGER NOT NULL,
            name        TEXT,
            category    TEXT,
            description TEXT,
            status      TEXT,
            severity    TEXT,
            detail      TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits(id)
        )
    """)

    conn.commit()
    conn.close()

# ══════════════════════════════════════════════════════════════════
#  ESCRITURA
# ══════════════════════════════════════════════════════════════════

def save_audit_result(data: dict):
    """
    Guarda el resultado completo de una auditoría.
    Crea o actualiza el servidor, inserta la auditoría y sus checks.
    """
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    now  = datetime.datetime.now().isoformat()

    srv  = data["server"]
    summ = data["summary"]

    # Upsert servidor
    c.execute("""
        INSERT INTO servers (hostname, ip, os, platform, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            ip        = excluded.ip,
            os        = excluded.os,
            platform  = excluded.platform,
            last_seen = excluded.last_seen
    """, (
        srv["hostname"], srv["ip"], srv["os"],
        srv.get("platform", "linux"), now, now
    ))

    # Obtener server_id
    c.execute("SELECT id FROM servers WHERE hostname = ?", (srv["hostname"],))
    server_id = c.fetchone()[0]

    # Insertar auditoría
    c.execute("""
        INSERT INTO audits
            (server_id, audit_date, score, total, pass_count, fail_count, warn_count, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        server_id,
        srv.get("audit_date", now),
        summ.get("score_percent", 0),
        summ.get("total", 0),
        summ.get("pass", 0),
        summ.get("fail", 0),
        summ.get("warn", 0),
        json.dumps(data, ensure_ascii=False)
    ))

    audit_id = c.lastrowid

    # Insertar checks individuales
    for chk in data.get("checks", []):
        c.execute("""
            INSERT INTO checks
                (audit_id, name, category, description, status, severity, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_id,
            chk.get("name", ""),
            chk.get("category", ""),
            chk.get("description", ""),
            chk.get("status", ""),
            chk.get("severity", ""),
            chk.get("detail", "")
        ))

    conn.commit()
    conn.close()
    print(f"✅ Auditoría guardada — {srv['hostname']} — Score: {summ.get('score_percent')}%")

# ══════════════════════════════════════════════════════════════════
#  LECTURA
# ══════════════════════════════════════════════════════════════════

def get_db():
    """Dependency para FastAPI (no usado directamente pero disponible)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def get_all_servers() -> list:
    """
    Devuelve todos los servidores con su último score y estado.
    Usado por el panel para mostrar el sidebar.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT
            s.hostname,
            s.ip,
            s.os,
            s.platform,
            s.last_seen,
            a.score,
            a.total,
            a.pass_count,
            a.fail_count,
            a.warn_count,
            a.audit_date
        FROM servers s
        LEFT JOIN audits a ON a.id = (
            SELECT id FROM audits
            WHERE server_id = s.id
            ORDER BY audit_date DESC LIMIT 1
        )
        ORDER BY s.last_seen DESC
    """)

    rows = c.fetchall()
    conn.close()

    result = []
    for r in rows:
        score = r["score"] or 0
        result.append({
            "hostname":   r["hostname"],
            "ip":         r["ip"],
            "os":         r["os"],
            "platform":   r["platform"],
            "last_seen":  r["last_seen"],
            "score":      score,
            "status":     _score_to_status(score),
            "total":      r["total"] or 0,
            "pass":       r["pass_count"] or 0,
            "fail":       r["fail_count"] or 0,
            "warn":       r["warn_count"] or 0,
            "audit_date": r["audit_date"]
        })
    return result

def get_server_detail(hostname: str) -> dict:
    """
    Devuelve el detalle completo de la última auditoría
    de un servidor, incluyendo todos los checks.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Obtener servidor
    c.execute("SELECT * FROM servers WHERE hostname = ?", (hostname,))
    srv = c.fetchone()
    if not srv:
        conn.close()
        return None

    # Última auditoría
    c.execute("""
        SELECT * FROM audits
        WHERE server_id = ?
        ORDER BY audit_date DESC LIMIT 1
    """, (srv["id"],))
    audit = c.fetchone()
    if not audit:
        conn.close()
        return {"server": dict(srv), "checks": [], "summary": {}}

    # Checks de esa auditoría
    c.execute("""
        SELECT * FROM checks WHERE audit_id = ?
        ORDER BY
            CASE severity
                WHEN 'ALTA'  THEN 1
                WHEN 'MEDIA' THEN 2
                WHEN 'BAJA'  THEN 3
                ELSE 4
            END,
            CASE status
                WHEN 'FAIL' THEN 1
                WHEN 'WARN' THEN 2
                WHEN 'PASS' THEN 3
                ELSE 4
            END
    """, (audit["id"],))
    checks = [dict(r) for r in c.fetchall()]

    # Agrupar por categoría
    categories = {}
    for chk in checks:
        cat = chk["category"]
        if cat not in categories:
            categories[cat] = {"pass": 0, "fail": 0, "warn": 0, "total": 0}
        categories[cat][chk["status"].lower()] += 1
        categories[cat]["total"] += 1

    # Score por categoría
    cat_scores = {}
    for cat, vals in categories.items():
        total = vals["total"]
        cat_scores[cat] = round((vals["pass"] / total) * 100) if total else 0

    conn.close()

    return {
        "server": {
            "hostname": srv["hostname"],
            "ip":       srv["ip"],
            "os":       srv["os"],
            "platform": srv["platform"],
            "last_seen": srv["last_seen"]
        },
        "summary": {
            "score":  audit["score"],
            "total":  audit["total"],
            "pass":   audit["pass_count"],
            "fail":   audit["fail_count"],
            "warn":   audit["warn_count"],
            "status": _score_to_status(audit["score"]),
            "audit_date": audit["audit_date"]
        },
        "category_scores": cat_scores,
        "checks": checks
    }

def get_audit_history(hostname: str, limit: int = 10) -> list:
    """
    Devuelve el historial de scores de un servidor.
    Útil para graficar la evolución en el tiempo.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT id FROM servers WHERE hostname = ?", (hostname,))
    srv = c.fetchone()
    if not srv:
        conn.close()
        return []

    c.execute("""
        SELECT audit_date, score, total, pass_count, fail_count, warn_count
        FROM audits
        WHERE server_id = ?
        ORDER BY audit_date DESC
        LIMIT ?
    """, (srv["id"], limit))

    history = [dict(r) for r in c.fetchall()]
    conn.close()
    return history

def get_global_summary() -> dict:
    """
    Estadísticas globales de toda la plataforma.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT COUNT(*) as total FROM servers")
    total_servers = c.fetchone()["total"]

    c.execute("""
        SELECT
            SUM(pass_count)  as total_pass,
            SUM(fail_count)  as total_fail,
            SUM(warn_count)  as total_warn,
            AVG(score)       as avg_score
        FROM audits a
        WHERE a.id IN (
            SELECT MAX(id) FROM audits GROUP BY server_id
        )
    """)
    row = c.fetchone()

    # Contar estados
    servers = get_all_servers()
    ok   = sum(1 for s in servers if s["status"] == "OK")
    warn = sum(1 for s in servers if s["status"] == "WARN")
    crit = sum(1 for s in servers if s["status"] == "CRIT")

    conn.close()

    return {
        "servers": {
            "total": total_servers,
            "ok":    ok,
            "warn":  warn,
            "crit":  crit
        },
        "checks": {
            "pass": int(row["total_pass"] or 0),
            "fail": int(row["total_fail"] or 0),
            "warn": int(row["total_warn"] or 0),
        },
        "avg_score": round(row["avg_score"] or 0)
    }

# ── Helper ────────────────────────────────────────────────────────
def _score_to_status(score: int) -> str:
    if score >= 80:
        return "OK"
    elif score >= 60:
        return "WARN"
    return "CRIT"
