# 🛡️ ServerHardenPro

**Plataforma profesional de auditoría de hardening para servidores Linux y Windows**

![Version](https://img.shields.io/badge/version-0.4.0-cyan?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

---

![Dashboard](docs/dashboard.png)

---

## 📋 ¿Qué es ServerHardenPro?

ServerHardenPro ejecuta checklists de hardening en servidores Linux y Windows, envía los resultados a un **panel web centralizado en tiempo real** y permite visualizar el estado de seguridad de toda tu infraestructura desde un solo lugar.

---

## ✨ Características

| Feature | Descripción |
|---------|-------------|
| 🔐 **Auth JWT** | Login y registro con roles Admin / Viewer |
| 📊 **Panel web** | Dashboard en tiempo real via WebSockets |
| 🐧 **Agente Linux** | 22 checks — SSH, Firewall, Usuarios, Red, Servicios |
| 🪟 **Agente Windows** | 25 checks — Contraseñas, RDP, SMB, Defender, UAC |
| 🖥️ **Inventario** | CPU, RAM, Disco, Uptime, detección VM/Físico |
| 📋 **Análisis de Logs** | auth.log + syslog, detección de fuerza bruta |
| 📈 **Evolución** | Gráfico histórico del score de hardening |
| 📄 **Reportes PDF** | Reporte profesional descargable (solo Admin) |
| 📊 **Reportes Excel** | Exportación completa de checks (solo Admin) |
| 🐳 **Docker** | Listo para desplegar con un solo comando |
| 🌙 **Modo oscuro/claro** | Interfaz adaptable |

---

## 🖼️ Capturas

### Panel de Login
![Login](docs/login.png)

### Dashboard Principal
![Dashboard](docs/dashboard.png)

---

## 🏗️ Arquitectura

```
ServerHardenPro/
├── 📁 frontend/
│   └── dashboard.html          # Panel web (HTML + CSS + JS vanilla)
├── 📁 agents/
│   ├── 📁 linux/
│   │   └── agent_linux.py      # Agente Linux
│   └── 📁 windows/
│       └── agent_windows.py    # Agente Windows
├── 📁 backend/
│   ├── main.py                 # API REST + WebSockets (FastAPI)
│   ├── database.py             # SQLite — auditorías, usuarios, logs
│   ├── report_generator.py     # Generador PDF / Excel
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

El panel queda disponible en: **`http://TU_IP:8010`**

### 3. Primer acceso

Al abrir el panel por primera vez verás la pantalla de login.
Hacé clic en **"REGISTRARSE"** — el primer usuario registrado es automáticamente **Admin**.

> ⚠️ El segundo usuario en adelante se registra como **Viewer** (solo lectura).

---

## 🤖 Ejecutar los agentes

### Agente Linux

```bash
# En el mismo servidor donde corre el backend
sudo python3 agents/linux/agent_linux.py

# En un servidor diferente de la red
export SHP_API=http://IP_DEL_BACKEND:8010/audit
sudo -E python3 agents/linux/agent_linux.py
```

> ⚠️ Se recomienda ejecutar con `sudo` para que el agente pueda leer `/var/log/auth.log` y realizar todos los checks correctamente.

### Agente Windows

```powershell
# Ejecutar como Administrador en PowerShell
$env:SHP_API = "http://IP_DEL_BACKEND:8010/audit"
python agent_windows.py
```

### Variable de entorno SHP_API

Por defecto el agente apunta a `http://localhost:8010/audit`.
Si el backend corre en otro servidor de la red, configurá la variable antes de ejecutar:

```bash
# Linux
export SHP_API=http://192.168.1.100:8010/audit

# Windows (PowerShell)
$env:SHP_API = "http://192.168.1.100:8010/audit"
```

---

## ⚙️ Variables de entorno del backend

| Variable | Descripción | Default |
|----------|-------------|---------|
| `DB_PATH` | Ruta de la base de datos SQLite | `/app/data/shp_database.db` |
| `SHP_JWT_SECRET` | Clave secreta para tokens JWT | `shp-change-this-secret` |

> ⚠️ **Importante:** Cambiá `SHP_JWT_SECRET` por una clave segura antes de usar en producción.

```yaml
# docker-compose.yml
environment:
  - DB_PATH=/app/data/shp_database.db
  - SHP_JWT_SECRET=tu-clave-super-secreta-aqui
```

---

## 🔐 Sistema de roles

| Acción | Admin | Viewer |
|--------|-------|--------|
| Ver servidores y checks | ✅ | ✅ |
| Ver inventario de hardware | ✅ | ✅ |
| Ver análisis de logs | ✅ | ✅ |
| Ver historial y evolución | ✅ | ✅ |
| Descargar PDF | ✅ | ❌ |
| Descargar Excel | ✅ | ❌ |
| Gestionar usuarios | ✅ | ❌ |

---

## 📡 API Endpoints

| Método | Endpoint | Auth | Descripción |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Healthcheck |
| `GET` | `/auth/status` | No | Estado del sistema |
| `POST` | `/auth/register` | No | Registrar usuario |
| `POST` | `/auth/login` | No | Iniciar sesión |
| `GET` | `/auth/me` | JWT | Perfil del usuario |
| `POST` | `/audit` | No | Recibir auditoría de agente |
| `POST` | `/logs` | No | Recibir análisis de logs |
| `GET` | `/servers` | JWT | Listar servidores |
| `GET` | `/servers/{hostname}` | JWT | Detalle + checks |
| `GET` | `/servers/{hostname}/history` | JWT | Historial de scores |
| `GET` | `/servers/{hostname}/inventory` | JWT | Inventario de hardware |
| `GET` | `/servers/{hostname}/logs` | JWT | Análisis de logs |
| `GET` | `/servers/{hostname}/report/pdf` | Admin | Reporte PDF |
| `GET` | `/servers/{hostname}/report/excel` | Admin | Reporte Excel |
| `GET` | `/summary` | JWT | Estadísticas globales |
| `WS` | `/ws` | No | WebSocket tiempo real |
| `GET` | `/docs` | No | Documentación Swagger |

---

## ✅ Checks incluidos

### 🐧 Linux (22 checks)

| Categoría | Checks |
|-----------|--------|
| SSH | Root login, Password auth, Puerto 22, Max intentos, Protocolo SSH2 |
| Firewall | UFW activo, Reglas iptables |
| Usuarios | Contraseñas vacías, UID 0 duplicado, Sudo, Expiración |
| Sistema | Updates pendientes, SUID, World-writable, Core dumps |
| Auditoría | auditd, rsyslog |
| Red | IP forwarding, ICMP redirects, SYN cookies |
| Servicios | Telnet, FTP |

### 🪟 Windows (25 checks)

| Categoría | Checks |
|-----------|--------|
| Contraseñas | Complejidad, Longitud mínima, Expiración, Bloqueo de cuenta, Guest, Admin renombrado |
| Firewall | Perfil Dominio, Privado, Público |
| Actualizaciones | Servicio Windows Update, Updates pendientes |
| RDP | Network Level Authentication, RDP innecesario |
| SMB | SMBv1 deshabilitado, SMB Signing |
| Auditoría | Logon events, Gestión de cuentas, Tamaño de logs |
| Servicios | Telnet, Print Spooler (PrintNightmare), WinRM |
| Antivirus | Defender activo, Firmas actualizadas |
| Sistema | UAC habilitado, UAC prompt nivel |

---

## 📋 Análisis de Logs

El agente analiza automáticamente al ejecutarse:

- **`/var/log/auth.log`** — Intentos de login fallidos y exitosos
- **`/var/log/syslog`** — Errores y eventos críticos del sistema

El panel muestra:
- Top 10 IPs con más intentos fallidos
- Top 10 usuarios más atacados
- 🚨 Alertas de fuerza bruta (≥10 intentos en 5 minutos desde la misma IP)
- Errores críticos del sistema con timestamp

---

## 🖥️ Inventario de hardware

El agente detecta y reporta:

- **CPU** — Modelo, núcleos, threads, frecuencia
- **RAM** — Total, usada, libre
- **Disco** — Uso de la partición raíz
- **Uptime** — Tiempo en línea en días y horas
- **Kernel** — Versión del kernel
- **VM/Físico** — Detecta VMware, KVM, VirtualBox, Xen, Hyper-V, QEMU

---

## 🛠️ Stack tecnológico

| Capa | Tecnología |
|------|-----------|
| Agente Linux | Python 3 + Bash |
| Agente Windows | Python 3 + PowerShell |
| Backend / API | FastAPI + Uvicorn |
| Auth | JWT HS256 (implementación nativa sin librerías extra) |
| Base de datos | SQLite |
| Panel web | HTML5 + CSS3 + JavaScript vanilla |
| Gráficos | Chart.js |
| Reportes | ReportLab (PDF) + OpenPyXL (Excel) |
| Tiempo real | WebSockets |
| Contenedores | Docker + Docker Compose |

---

## 🔄 Actualizar desde GitHub

```bash
cd ~/ServerHardenPro
git pull
docker compose down
docker compose up -d --build
```

---

## 🧪 Entorno de prueba recomendado

Para testear sin servidores físicos:

- **VM Linux:** Ubuntu 22.04 Server (512 MB RAM, 10 GB disco)
- **VM Windows:** Windows Server 2019 Evaluation (2 GB RAM, 30 GB disco)
- **Virtualización:** VirtualBox, VMware o Proxmox
- **Red:** Modo "Red NAT" o "Red interna" para comunicación entre VMs

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Abrí un Issue o Pull Request.

Áreas donde podés contribuir:
- Nuevos checks de hardening
- Soporte para otras distros (RHEL, Alpine, Arch)
- Agente para macOS
- Traducciones (inglés, portugués)

---

## 📄 Licencia

MIT © 2025 — ServerHardenPro
