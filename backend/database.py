"""
╔══════════════════════════════════════════════════════════════════╗
║           ServerHardenPro — Base de Datos (SQLite)              ║
║                          Fase 5                                  ║
║  + Tabla usuarios (auth JWT)                                     ║
║  + Inventario hardware (CPU/RAM/Disco/VM)                        ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sqlite3, json, os, datetime, hashlib, secrets

DB_PATH = os.path.join(os.path.dirname(__file__), "shp_database.db")

# ══════════════════════════════════════════════════════════════════
#  INICIALIZACIÓN
# ══════════════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname      TEXT UNIQUE NOT NULL,
            ip            TEXT,
            os            TEXT,
            os_full       TEXT,
            platform      TEXT DEFAULT 'linux',
            first_seen    TEXT,
            last_seen     TEXT,
            cpu_model     TEXT,
            cpu_cores     INTEGER,
            cpu_threads   INTEGER,
            cpu_freq_mhz  REAL,
            ram_total_gb  REAL,
            ram_used_gb   REAL,
            ram_free_gb   REAL,
            disk_total_gb REAL,
            disk_used_gb  REAL,
            disk_free_gb  REAL,
            is_vm         INTEGER DEFAULT 0,
            vm_type       TEXT,
            uptime_hours  REAL,
            kernel        TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id  INTEGER NOT NULL,
            audit_date TEXT NOT NULL,
            score      INTEGER DEFAULT 0,
            total      INTEGER DEFAULT 0,
            pass_count INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0,
            warn_count INTEGER DEFAULT 0,
            raw_json   TEXT,
            FOREIGN KEY (server_id) REFERENCES servers(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id    INTEGER NOT NULL,
            name        TEXT, category TEXT, description TEXT,
            status      TEXT, severity TEXT, detail TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL,
            role          TEXT DEFAULT 'viewer',
            active        INTEGER DEFAULT 1,
            created_at    TEXT NOT NULL,
            last_login    TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS log_analysis (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id          INTEGER NOT NULL,
            analyzed_at        TEXT NOT NULL,
            period_hours       INTEGER DEFAULT 24,
            auth_fail_total    INTEGER DEFAULT 0,
            auth_ok_total      INTEGER DEFAULT 0,
            brute_force_count  INTEGER DEFAULT 0,
            syslog_error_count INTEGER DEFAULT 0,
            syslog_crit_count  INTEGER DEFAULT 0,
            top_ips            TEXT,
            top_users          TEXT,
            brute_events       TEXT,
            syslog_errors      TEXT,
            raw_json           TEXT,
            FOREIGN KEY (server_id) REFERENCES servers(id)
        )
    """)

    # Migración segura: agregar columnas nuevas si DB ya existe
    inventory_cols = [
        ("os_full","TEXT"),("cpu_model","TEXT"),("cpu_cores","INTEGER"),
        ("cpu_threads","INTEGER"),("cpu_freq_mhz","REAL"),
        ("ram_total_gb","REAL"),("ram_used_gb","REAL"),("ram_free_gb","REAL"),
        ("disk_total_gb","REAL"),("disk_used_gb","REAL"),("disk_free_gb","REAL"),
        ("is_vm","INTEGER DEFAULT 0"),("vm_type","TEXT"),
        ("uptime_hours","REAL"),("kernel","TEXT"),
    ]
    c.execute("PRAGMA table_info(servers)")
    existing = {row[1] for row in c.fetchall()}
    for col, coltype in inventory_cols:
        if col not in existing:
            c.execute(f"ALTER TABLE servers ADD COLUMN {col} {coltype}")

    conn.commit()
    conn.close()

# ══════════════════════════════════════════════════════════════════
#  AUTH — USUARIOS
# ══════════════════════════════════════════════════════════════════
def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

def users_exist() -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]
    conn.close()
    return count > 0

def create_user(username: str, email: str, password: str, role: str = "viewer") -> dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Primer usuario siempre admin
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        role = "admin"
    salt     = secrets.token_hex(16)
    pwd_hash = _hash_password(password, salt)
    now      = datetime.datetime.now().isoformat()
    try:
        c.execute("""
            INSERT INTO users (username, email, password_hash, salt, role, created_at)
            VALUES (?,?,?,?,?,?)
        """, (username, email, pwd_hash, salt, role, now))
        conn.commit()
        uid = c.lastrowid
    except sqlite3.IntegrityError as e:
        conn.close()
        raise ValueError(str(e))
    conn.close()
    return {"id": uid, "username": username, "email": email, "role": role}

def verify_user(username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND active=1", (username,))
    user = c.fetchone()
    if not user or _hash_password(password, user["salt"]) != user["password_hash"]:
        conn.close()
        return None
    c.execute("UPDATE users SET last_login=? WHERE id=?",
              (datetime.datetime.now().isoformat(), user["id"]))
    conn.commit()
    result = {"id": user["id"], "username": user["username"],
              "email": user["email"], "role": user["role"]}
    conn.close()
    return result

def get_user_by_id(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id,username,email,role,created_at,last_login FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def list_users() -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id,username,email,role,active,created_at,last_login FROM users ORDER BY created_at")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

# ══════════════════════════════════════════════════════════════════
#  ESCRITURA — AUDITORÍAS
# ══════════════════════════════════════════════════════════════════
def save_audit_result(data: dict):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    now  = datetime.datetime.now().isoformat()
    srv  = data["server"]
    summ = data["summary"]
    inv  = data.get("inventory", {})

    c.execute("""
        INSERT INTO servers (
            hostname,ip,os,os_full,platform,first_seen,last_seen,
            cpu_model,cpu_cores,cpu_threads,cpu_freq_mhz,
            ram_total_gb,ram_used_gb,ram_free_gb,
            disk_total_gb,disk_used_gb,disk_free_gb,
            is_vm,vm_type,uptime_hours,kernel
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(hostname) DO UPDATE SET
            ip=excluded.ip, os=excluded.os, os_full=excluded.os_full,
            platform=excluded.platform, last_seen=excluded.last_seen,
            cpu_model=excluded.cpu_model, cpu_cores=excluded.cpu_cores,
            cpu_threads=excluded.cpu_threads, cpu_freq_mhz=excluded.cpu_freq_mhz,
            ram_total_gb=excluded.ram_total_gb, ram_used_gb=excluded.ram_used_gb,
            ram_free_gb=excluded.ram_free_gb,
            disk_total_gb=excluded.disk_total_gb, disk_used_gb=excluded.disk_used_gb,
            disk_free_gb=excluded.disk_free_gb,
            is_vm=excluded.is_vm, vm_type=excluded.vm_type,
            uptime_hours=excluded.uptime_hours, kernel=excluded.kernel
    """, (
        srv["hostname"], srv["ip"], srv["os"], srv.get("os_full",""),
        srv.get("platform","linux"), now, now,
        inv.get("cpu_model",""), inv.get("cpu_cores",0),
        inv.get("cpu_threads",0), inv.get("cpu_freq_mhz",0.0),
        inv.get("ram_total_gb",0.0), inv.get("ram_used_gb",0.0), inv.get("ram_free_gb",0.0),
        inv.get("disk_total_gb",0.0), inv.get("disk_used_gb",0.0), inv.get("disk_free_gb",0.0),
        1 if inv.get("is_vm") else 0, inv.get("vm_type",""),
        inv.get("uptime_hours",0.0), inv.get("kernel","")
    ))

    c.execute("SELECT id FROM servers WHERE hostname=?", (srv["hostname"],))
    server_id = c.fetchone()[0]

    c.execute("""
        INSERT INTO audits (server_id,audit_date,score,total,pass_count,fail_count,warn_count,raw_json)
        VALUES (?,?,?,?,?,?,?,?)
    """, (server_id, srv.get("audit_date",now),
          summ.get("score_percent",0), summ.get("total",0),
          summ.get("pass",0), summ.get("fail",0), summ.get("warn",0),
          json.dumps(data, ensure_ascii=False)))

    audit_id = c.lastrowid
    for chk in data.get("checks",[]):
        c.execute("""
            INSERT INTO checks (audit_id,name,category,description,status,severity,detail)
            VALUES (?,?,?,?,?,?,?)
        """, (audit_id, chk.get("name",""), chk.get("category",""),
              chk.get("description",""), chk.get("status",""),
              chk.get("severity",""), chk.get("detail","")))

    conn.commit()
    conn.close()
    print(f"✅ Auditoría guardada — {srv['hostname']} — Score: {summ.get('score_percent')}%")

# ══════════════════════════════════════════════════════════════════
#  LECTURA
# ══════════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:    yield conn
    finally: conn.close()

def get_all_servers() -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT s.hostname,s.ip,s.os,s.platform,s.last_seen,
               s.cpu_model,s.cpu_cores,s.ram_total_gb,s.is_vm,s.vm_type,s.uptime_hours,
               a.score,a.total,a.pass_count,a.fail_count,a.warn_count,a.audit_date
        FROM servers s
        LEFT JOIN audits a ON a.id=(
            SELECT id FROM audits WHERE server_id=s.id ORDER BY audit_date DESC LIMIT 1
        )
        ORDER BY s.last_seen DESC
    """)
    rows = c.fetchall()
    conn.close()
    result = []
    for r in rows:
        score = r["score"] or 0
        result.append({
            "hostname":    r["hostname"], "ip":          r["ip"],
            "os":          r["os"],       "platform":    r["platform"],
            "last_seen":   r["last_seen"],"score":       score,
            "status":      _score_to_status(score),
            "total":       r["total"] or 0, "pass":      r["pass_count"] or 0,
            "fail":        r["fail_count"] or 0, "warn": r["warn_count"] or 0,
            "audit_date":  r["audit_date"],
            "cpu_model":   r["cpu_model"] or "",  "cpu_cores":   r["cpu_cores"] or 0,
            "ram_total_gb":r["ram_total_gb"] or 0,"is_vm":       bool(r["is_vm"]),
            "vm_type":     r["vm_type"] or "",    "uptime_hours":r["uptime_hours"] or 0,
        })
    return result

def get_server_detail(hostname: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM servers WHERE hostname=?", (hostname,))
    srv = c.fetchone()
    if not srv:
        conn.close()
        return None
    c.execute("SELECT * FROM audits WHERE server_id=? ORDER BY audit_date DESC LIMIT 1", (srv["id"],))
    audit = c.fetchone()
    if not audit:
        conn.close()
        return {"server": dict(srv), "checks":[], "summary":{}, "inventory":{}}
    c.execute("""
        SELECT * FROM checks WHERE audit_id=?
        ORDER BY
            CASE severity WHEN 'ALTA' THEN 1 WHEN 'MEDIA' THEN 2 WHEN 'BAJA' THEN 3 ELSE 4 END,
            CASE status   WHEN 'FAIL' THEN 1 WHEN 'WARN'  THEN 2 WHEN 'PASS' THEN 3 ELSE 4 END
    """, (audit["id"],))
    checks = [dict(r) for r in c.fetchall()]
    categories = {}
    for chk in checks:
        cat = chk["category"]
        if cat not in categories:
            categories[cat] = {"pass":0,"fail":0,"warn":0,"total":0}
        categories[cat][chk["status"].lower()] += 1
        categories[cat]["total"] += 1
    cat_scores = {cat: round((v["pass"]/v["total"])*100) if v["total"] else 0
                  for cat, v in categories.items()}
    conn.close()
    return {
        "server":    {"hostname":srv["hostname"],"ip":srv["ip"],"os":srv["os"],
                      "os_full":srv["os_full"] or "","platform":srv["platform"],
                      "last_seen":srv["last_seen"]},
        "summary":   {"score":audit["score"],"total":audit["total"],
                      "pass":audit["pass_count"],"fail":audit["fail_count"],
                      "warn":audit["warn_count"],"status":_score_to_status(audit["score"]),
                      "audit_date":audit["audit_date"]},
        "inventory": {"cpu_model":srv["cpu_model"] or "","cpu_cores":srv["cpu_cores"] or 0,
                      "cpu_threads":srv["cpu_threads"] or 0,"cpu_freq_mhz":srv["cpu_freq_mhz"] or 0,
                      "ram_total_gb":srv["ram_total_gb"] or 0,"ram_used_gb":srv["ram_used_gb"] or 0,
                      "ram_free_gb":srv["ram_free_gb"] or 0,
                      "disk_total_gb":srv["disk_total_gb"] or 0,"disk_used_gb":srv["disk_used_gb"] or 0,
                      "disk_free_gb":srv["disk_free_gb"] or 0,
                      "is_vm":bool(srv["is_vm"]),"vm_type":srv["vm_type"] or "",
                      "uptime_hours":srv["uptime_hours"] or 0,"kernel":srv["kernel"] or ""},
        "category_scores": cat_scores,
        "checks": checks
    }

def get_audit_history(hostname: str, limit: int = 10) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id FROM servers WHERE hostname=?", (hostname,))
    srv = c.fetchone()
    if not srv:
        conn.close()
        return []
    c.execute("""
        SELECT audit_date, score as score_percent, total,
               pass_count as pass, fail_count as fail, warn_count as warn
        FROM audits WHERE server_id=? ORDER BY audit_date DESC LIMIT ?
    """, (srv["id"], limit))
    history = [dict(r) for r in c.fetchall()]
    conn.close()
    return history

def get_global_summary() -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as total FROM servers")
    total_servers = c.fetchone()["total"]
    c.execute("""
        SELECT SUM(pass_count) as total_pass, SUM(fail_count) as total_fail,
               SUM(warn_count) as total_warn, AVG(score) as avg_score
        FROM audits WHERE id IN (SELECT MAX(id) FROM audits GROUP BY server_id)
    """)
    row = c.fetchone()
    servers = get_all_servers()
    conn.close()
    return {
        "servers":   {"total":total_servers,
                      "ok":  sum(1 for s in servers if s["status"]=="OK"),
                      "warn":sum(1 for s in servers if s["status"]=="WARN"),
                      "crit":sum(1 for s in servers if s["status"]=="CRIT")},
        "checks":    {"pass":int(row["total_pass"] or 0),
                      "fail":int(row["total_fail"] or 0),
                      "warn":int(row["total_warn"] or 0)},
        "avg_score": round(row["avg_score"] or 0)
    }


# ══════════════════════════════════════════════════════════════════
#  LOGS
# ══════════════════════════════════════════════════════════════════
def save_log_analysis(hostname: str, data: dict):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    now  = datetime.datetime.now().isoformat()

    c.execute("SELECT id FROM servers WHERE hostname=?", (hostname,))
    row = c.fetchone()
    if not row:
        conn.close()
        return
    server_id = row[0]

    s = data.get("summary", {})
    c.execute("""
        INSERT INTO log_analysis (
            server_id, analyzed_at, period_hours,
            auth_fail_total, auth_ok_total, brute_force_count,
            syslog_error_count, syslog_crit_count,
            top_ips, top_users, brute_events, syslog_errors, raw_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        server_id, now, data.get("period_hours", 24),
        s.get("auth_fail_total", 0), s.get("auth_ok_total", 0),
        s.get("brute_force_count", 0),
        s.get("syslog_error_count", 0), s.get("syslog_crit_count", 0),
        json.dumps(data.get("top_ips", []),      ensure_ascii=False),
        json.dumps(data.get("top_users", []),    ensure_ascii=False),
        json.dumps(data.get("brute_events", []), ensure_ascii=False),
        json.dumps(data.get("syslog_errors", []),ensure_ascii=False),
        json.dumps(data, ensure_ascii=False)
    ))
    conn.commit()
    conn.close()
    print(f"✅ Logs guardados — {hostname}")

def get_log_analysis(hostname: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id FROM servers WHERE hostname=?", (hostname,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {}
    c.execute("""
        SELECT * FROM log_analysis WHERE server_id=?
        ORDER BY analyzed_at DESC LIMIT 1
    """, (row[0],))
    r = c.fetchone()
    conn.close()
    if not r:
        return {}
    return {
        "analyzed_at":        r["analyzed_at"],
        "period_hours":       r["period_hours"],
        "summary": {
            "auth_fail_total":    r["auth_fail_total"],
            "auth_ok_total":      r["auth_ok_total"],
            "brute_force_count":  r["brute_force_count"],
            "syslog_error_count": r["syslog_error_count"],
            "syslog_crit_count":  r["syslog_crit_count"],
        },
        "top_ips":      json.loads(r["top_ips"]      or "[]"),
        "top_users":    json.loads(r["top_users"]    or "[]"),
        "brute_events": json.loads(r["brute_events"] or "[]"),
        "syslog_errors":json.loads(r["syslog_errors"]or "[]"),
    }

def get_log_history(hostname: str, limit: int = 14) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id FROM servers WHERE hostname=?", (hostname,))
    row = c.fetchone()
    if not row:
        conn.close()
        return []
    c.execute("""
        SELECT analyzed_at, auth_fail_total, auth_ok_total,
               brute_force_count, syslog_error_count, syslog_crit_count
        FROM log_analysis WHERE server_id=?
        ORDER BY analyzed_at DESC LIMIT ?
    """, (row[0], limit))
    history = [dict(r) for r in c.fetchall()]
    conn.close()
    return history

def _score_to_status(score: int) -> str:
    if score >= 80: return "OK"
    if score >= 60: return "WARN"
    return "CRIT"
