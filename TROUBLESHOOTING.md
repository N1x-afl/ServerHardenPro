# 🔧 Troubleshooting — ServerHardenPro

Solución a los errores más comunes / Solutions to common issues.

---

## ❌ "No se puede conectar al backend"

**Causa:** El browser no puede llegar al backend en el puerto 8010.

**Solución 1 — Verificar que Docker esté corriendo:**
```bash
docker ps | grep shp_backend
# Si no aparece:
cd ~/ServerHardenPro && docker compose up -d
```

**Solución 2 — Verificar el firewall:**
```bash
sudo ufw allow 8010/tcp
sudo ufw status
```

**Solución 3 — Acceder con la IP correcta:**
- Usar `http://IP_DEL_SERVIDOR:8010` (no `localhost` si accedés desde otra máquina)

---

## ❌ Dashboard no carga / no puedo logearme

**Causa:** El browser tiene datos en caché de una versión anterior.

**Solución:**
```javascript
// Abrir F12 → Console → pegar:
localStorage.clear(); location.reload();
```

---

## ❌ Error 500 en /logs

**Causa:** La tabla `log_analysis` no existe en la DB (DB creada antes de v0.3).

**Solución rápida:**
```bash
docker exec shp_backend python3 -c "
import sqlite3
conn = sqlite3.connect('/app/shp_database.db')
conn.execute('''CREATE TABLE IF NOT EXISTS log_analysis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id INTEGER NOT NULL,
  analyzed_at TEXT NOT NULL,
  period_hours INTEGER DEFAULT 24,
  auth_fail_total INTEGER DEFAULT 0,
  auth_ok_total INTEGER DEFAULT 0,
  brute_force_count INTEGER DEFAULT 0,
  syslog_error_count INTEGER DEFAULT 0,
  syslog_crit_count INTEGER DEFAULT 0,
  top_ips TEXT, top_users TEXT,
  brute_events TEXT, syslog_errors TEXT, raw_json TEXT,
  FOREIGN KEY (server_id) REFERENCES servers(id))''')
conn.commit()
print('OK')
"
```

**Solución definitiva:** Rebuild completo
```bash
docker compose down && docker compose up -d --build
```

---

## ❌ Inventario vacío / "SIN DATOS DE INVENTARIO"

**Causa 1:** DB incorrecta — `DB_PATH` apunta a una DB vacía.

**Verificar:**
```bash
# Debe decir /app/shp_database.db
docker exec shp_backend env | grep DB_PATH
```

**Fix en docker-compose.yml:**
```yaml
environment:
  - DB_PATH=/app/shp_database.db   # ✅ Correcto
  # NO: - DB_PATH=/app/data/shp_database.db
```

**Causa 2:** El agente no reportó el inventario aún.
```bash
sudo python3 agents/linux/agent_linux.py
```

---

## ❌ El agente reporta al servidor equivocado

**Causa:** `SHP_API` no está configurado — apunta a `localhost` por defecto.

**Solución:**
```bash
# Un servidor diferente al backend
SHP_API=http://192.168.1.100:8010/audit sudo -E python3 agent_linux.py

# Cambio permanente — editar el agente:
# Línea: API_URL = os.environ.get("SHP_API", "http://localhost:8010/audit")
# Cambiar a: API_URL = os.environ.get("SHP_API", "http://IP_DEL_BACKEND:8010/audit")
```

---

## ❌ Healthcheck failing / Container restarting

**Verificar logs:**
```bash
docker logs shp_backend --tail 30
```

**Healthcheck correcto en docker-compose.yml:**
```yaml
healthcheck:
  test: ["CMD-SHELL", "python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/health')\" || exit 1"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 15s
```

---

## ❌ Puerto 8010 en uso

```bash
# Ver qué usa el puerto
sudo lsof -i :8010

# Cambiar puerto en docker-compose.yml
ports:
  - "8020:8000"   # Usar 8020 en lugar de 8010
```

---

## ❌ "targets is not iterable" en DevSecOps

**Causa:** Versión anterior del dashboard — el endpoint `/servers` devuelve un objeto en vez de array.

**Solución:** Actualizar `dashboard.html` desde el repo:
```bash
git pull && docker compose restart
```

---

## ❌ Syntax error en el dashboard (login no funciona)

**Causa:** Caracteres Unicode en comentarios JS (`═══`) incompatibles con algunos browsers.

**Solución:** Actualizar al dashboard v11+:
```bash
git pull && docker compose restart
```

---

## ℹ️ Comandos útiles

```bash
# Ver estado del contenedor
docker ps | grep shp_backend

# Ver logs en tiempo real
docker logs shp_backend -f

# Reiniciar sin rebuild
docker compose restart

# Rebuild completo
docker compose down && docker compose up -d --build

# Acceder a la DB
docker exec -it shp_backend sqlite3 /app/shp_database.db

# Ver usuarios registrados
docker exec shp_backend python3 -c "
import sqlite3; conn = sqlite3.connect('/app/shp_database.db')
print(conn.execute('SELECT username, role FROM users').fetchall())"

# Ver servidores en DB
docker exec shp_backend python3 -c "
import sqlite3; conn = sqlite3.connect('/app/shp_database.db')
print(conn.execute('SELECT hostname, os, last_seen FROM servers').fetchall())"
```

---

## 💬 ¿Seguís con problemas? / Still having issues?

Abrí un Issue en GitHub: [github.com/N1x-afl/ServerHardenPro/issues](https://github.com/N1x-afl/ServerHardenPro/issues)

Incluí: versión de Docker, OS, logs del contenedor y descripción del error.
