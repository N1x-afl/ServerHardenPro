# ServerHardenPro

<div align="center">

![Version](https://img.shields.io/badge/version-0.5.0-cyan?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![SQLite](https://img.shields.io/badge/SQLite-embedded-lightgrey?style=for-the-badge&logo=sqlite)

**Plataforma profesional de auditoría de hardening para servidores Linux y Windows**

*Professional hardening audit platform for Linux and Windows servers*

![Dashboard](docs/dashboard.png)

</div>

---

## 📋 ¿Qué es ServerHardenPro?

ServerHardenPro ejecuta checklists de hardening en servidores Linux y Windows, envía los resultados a un panel web centralizado en tiempo real y permite visualizar el estado de seguridad de toda tu infraestructura desde un solo lugar.

---

## ✨ Características

| Feature | Descripción |
|---------|-------------|
| 🔐 Auth JWT | Login y registro con roles Admin / Viewer |
| 📊 Panel DevSecOps | CVEs, Timeline, Comparativa, Recomendaciones |
| 📈 Gráficos en tiempo real | Auth events, Score trend, Top IPs atacantes |
| 🐧 Agente Linux | 22 checks — SSH, Firewall, Usuarios, Red, Servicios |
| 🪟 Agente Windows | 25 checks — Contraseñas, RDP, SMB, Defender, UAC |
| 🖥️ Inventario | CPU, RAM, Disco, Uptime, detección VM/Físico |
| 📋 Análisis de Logs | auth.log + syslog, detección de fuerza bruta |
| 🛡️ CVEs | Consulta NVD/NIST con fallback local |
| 📄 Reportes PDF/Excel | Descargables (solo Admin) |
| 🔍 Búsqueda | Filtrado de servidores en tiempo real |
| 🐳 Docker | Listo para desplegar con un solo comando |
| 🌐 Multi-servidor | Un backend centralizado para toda la red |

---

## 🖼️ Capturas

| Login | Dashboard |
|-------|-----------|
| ![Login](docs/login.png) | ![Dashboard](docs/dashboard.png) |

---

## 🏗️ Arquitectura

```
ServerHardenPro/
├── frontend/
│   └── dashboard.html
├── agents/
│   ├── linux/agent_linux.py
│   └── windows/agent_windows.py
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── report_generator.py
│   ├── requirements.txt
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🚀 Instalación rápida

### Requisitos
- Docker + Docker Compose
- Python 3.9+ (para los agentes)

### 1. Clonar el repositorio
```bash
git clone https://github.com/N1x-afl/ServerHardenPro.git
cd ServerHardenPro
```

### 2. Levantar el backend
```bash
docker compose up -d --build
```

### 3. Acceder al panel
```
http://TU_IP:8010
```

> 💡 El dashboard detecta automáticamente la IP del servidor — no requiere configuración adicional.

### 4. Primer acceso
Al abrir el panel hacé clic en **REGISTRARSE**.

> ⚠️ El **primer usuario registrado** es automáticamente **Admin**. Los siguientes son **Viewer**.

---

## 🤖 Ejecutar los agentes

### Agente Linux

```bash
# En el mismo servidor del backend
sudo python3 agents/linux/agent_linux.py

# En un servidor diferente de la red
SHP_API=http://IP_DEL_BACKEND:8010/audit sudo -E python3 agents/linux/agent_linux.py
```

> ⚠️ Ejecutar con `sudo` para acceder a `/var/log/auth.log`

### Agente Windows

```powershell
$env:SHP_API = "http://IP_DEL_BACKEND:8010/audit"
python agent_windows.py
```

### Múltiples servidores → un solo backend

```bash
# En cada servidor adicional
SHP_API=http://192.168.1.100:8010/audit sudo -E python3 agent_linux.py
```

---

## ⚙️ Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `DB_PATH` | Ruta SQLite | `/app/shp_database.db` |
| `SHP_JWT_SECRET` | Clave JWT | `shp-change-this-secret` |
| `SHP_API` | URL backend (agente) | `http://localhost:8010/audit` |

> ⚠️ Cambiá `SHP_JWT_SECRET` antes de usar en producción.

---

## 🔐 Sistema de roles

| Acción | Admin | Viewer |
|--------|-------|--------|
| Ver servidores y checks | ✅ | ✅ |
| Ver inventario / logs | ✅ | ✅ |
| Panel DevSecOps | ✅ | ✅ |
| Descargar PDF / Excel | ✅ | ❌ |

---

## 📡 API Endpoints

| Método | Endpoint | Auth | Descripción |
|--------|----------|------|-------------|
| GET | `/health` | No | Healthcheck |
| POST | `/auth/register` | No | Registrar usuario |
| POST | `/auth/login` | No | Iniciar sesión |
| POST | `/audit` | No | Recibir auditoría |
| POST | `/logs` | No | Recibir logs |
| GET | `/servers` | JWT | Listar servidores |
| GET | `/servers/{hostname}/inventory` | JWT | Inventario |
| GET | `/servers/{hostname}/logs` | JWT | Logs |
| GET | `/servers/{hostname}/report/pdf` | Admin | PDF |
| GET | `/servers/{hostname}/report/excel` | Admin | Excel |
| WS | `/ws` | No | WebSocket |
| GET | `/docs` | No | Swagger |

---

## 🛡️ Panel DevSecOps

| Sección | Descripción |
|---------|-------------|
| **CVEs** | NVD/NIST en tiempo real + fallback local |
| **Timeline** | Eventos de seguridad cronológicos |
| **Comparativa** | Hardening entre servidores |
| **Recomendaciones** | Comandos correctivos por check fallido |

---

## 🔄 Actualizar

```bash
cd ~/ServerHardenPro
git pull
docker compose down && docker compose up -d --build

# Solo frontend:
git pull && docker compose restart
```

---

## 🔧 Troubleshooting

Ver [TROUBLESHOOTING.md](TROUBLESHOOTING.md) para errores detallados.

**No conecta al backend:**
```bash
docker ps | grep shp_backend
docker compose up -d
```

**Error 500 en /logs:**
```bash
docker compose down && docker compose up -d --build
```

**No puedo logearme:**
```bash
# En consola del browser (F12)
localStorage.clear(); location.reload();
```

**Inventario vacío:**
Verificar que `DB_PATH=/app/shp_database.db` en `docker-compose.yml`

---

## 🛠️ Stack tecnológico

| Capa | Tecnología |
|------|-----------|
| Backend | FastAPI + Uvicorn |
| Auth | JWT HS256 |
| DB | SQLite |
| Frontend | HTML5 + CSS3 + JS vanilla |
| Gráficos | Chart.js |
| Reportes | ReportLab + OpenPyXL |
| Tiempo real | WebSockets |
| Contenedores | Docker + Compose |

---

## 🤝 Contribuciones

1. Fork → branch → commit → PR

Áreas: nuevos checks, soporte RHEL/Alpine/macOS, traducciones.

---

## 📄 Licencia

MIT © 2025 — ServerHardenPro

---

*// ServerHardenPro v0.5.0 — FastAPI + SQLite + WebSockets + Chart.js*
