# 🛡️ ServerHardenPro

> **Plataforma profesional de auditoría de hardening para servidores Windows y Linux**

![Version](https://img.shields.io/badge/version-0.1.0-00e5ff?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ed?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-39ff6e?style=flat-square)

---

## 📋 Descripción

**ServerHardenPro** es una herramienta de auditoría de seguridad que ejecuta checklists de hardening en servidores **Linux** y **Windows**, envía los resultados a un panel web centralizado en tiempo real y permite generar reportes en **PDF** y **Excel**.

### ✨ Características

- ✅ **47 checks** de hardening (22 Linux + 25 Windows)
- 📊 **Panel web** con resultados en tiempo real via WebSockets
- 🐧 **Agente Linux** (Python + Bash) — SSH, Firewall, Usuarios, Sistema, Red
- 🪟 **Agente Windows** (Python + PowerShell) — Contraseñas, Firewall, RDP, SMB, Defender
- 📄 **Reportes PDF** profesionales con diseño oscuro
- 📊 **Reportes Excel** con múltiples hojas y colores por estado
- 🐳 **Docker** listo para desplegar
- 🗄️ **SQLite** como base de datos (sin configuración extra)

---

## 🏗️ Arquitectura

```
ServerHardenPro/
├── 📁 frontend/
│   └── dashboard.html          # Panel web (HTML + CSS + JS)
├── 📁 agents/
│   ├── 📁 linux/
│   │   └── agent_linux.py      # Agente de auditoría Linux
│   └── 📁 windows/
│       └── agent_windows.py    # Agente de auditoría Windows
├── 📁 backend/
│   ├── main.py                 # API REST + WebSockets (FastAPI)
│   ├── database.py             # Capa de datos (SQLite)
│   ├── report_generator.py     # Generador PDF / Excel
│   ├── requirements.txt
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🚀 Instalación y uso

### Opción 1: Con Docker (recomendado)

```bash
# 1. Clonar el repositorio
git clone https://github.com/N1x-afl/ServerHardenPro.git
cd ServerHardenPro

# 2. Levantar el backend + panel
docker compose up -d

# 3. Abrir el panel
# http://localhost:8000
```

### Opción 2: Sin Docker

```bash
# 1. Instalar dependencias del backend
cd backend
pip install -r requirements.txt

# 2. Levantar el servidor
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 3. Abrir frontend/dashboard.html en el navegador
```

---

## 🤖 Ejecutar los agentes

### En un servidor Linux (VM o físico)

```bash
# Copiar el agente al servidor
scp agents/linux/agent_linux.py usuario@servidor:/tmp/

# Ejecutar como root para máxima cobertura
ssh usuario@servidor
sudo python3 /tmp/agent_linux.py
```

El agente genera `resultado_<hostname>.json` y puede enviarlo al backend:

```bash
# Enviar resultado al panel (cuando el backend está corriendo)
curl -X POST http://TU_IP:8000/audit \
     -H "Content-Type: application/json" \
     -d @resultado_<hostname>.json
```

### En un servidor Windows (VM o físico)

```powershell
# Ejecutar como Administrador en PowerShell
python agent_windows.py
```

---

## 📡 API Endpoints

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `POST` | `/audit` | Recibir resultado de auditoría |
| `GET`  | `/servers` | Listar todos los servidores |
| `GET`  | `/servers/{hostname}` | Detalle + checks de un servidor |
| `GET`  | `/servers/{hostname}/history` | Historial de scores |
| `GET`  | `/servers/{hostname}/report/pdf` | Descargar reporte PDF |
| `GET`  | `/servers/{hostname}/report/excel` | Descargar reporte Excel |
| `GET`  | `/summary` | Estadísticas globales |
| `WS`   | `/ws` | WebSocket tiempo real |
| `GET`  | `/docs` | Documentación Swagger UI |

---

## ✅ Checks incluidos

### 🐧 Linux (22 checks)

| Categoría | Checks |
|-----------|--------|
| SSH | Root login, Password auth, Puerto, Max intentos, Protocolo |
| Firewall | UFW activo, Reglas iptables |
| Usuarios | Contraseñas vacías, UID 0, Sudo, Expiración |
| Sistema | Updates, SUID, World-writable, Core dumps |
| Auditoría | auditd, rsyslog |
| Red | IP forward, ICMP redirects, SYN cookies |
| Servicios | Telnet, FTP |

### 🪟 Windows (25 checks)

| Categoría | Checks |
|-----------|--------|
| Contraseñas | Complejidad, Longitud, Expiración, Bloqueo, Guest, Admin renombrado |
| Firewall | Perfil Dominio, Privado, Público |
| Actualizaciones | Servicio WU, Updates pendientes |
| RDP | NLA, RDP innecesario |
| SMB | SMBv1 deshabilitado, SMB Signing |
| Auditoría | Logon, Gestión de cuentas, Tamaño de logs |
| Servicios | Telnet, Print Spooler (PrintNightmare), WinRM |
| Antivirus | Defender activo, Firmas actualizadas |
| Sistema | UAC, UAC prompt |

---

## 🖥️ Entorno de prueba recomendado

Para testear sin servidores físicos, usar **VirtualBox** con:

- **VM Linux**: Ubuntu 22.04 Server (512 MB RAM, 10 GB disco)
- **VM Windows**: Windows Server 2019 Evaluation (2 GB RAM, 30 GB disco)
- **Red**: Adaptador en modo "Red NAT" o "Red interna" para comunicación entre VMs

---

## 🛠️ Stack tecnológico

| Capa | Tecnología |
|------|-----------|
| Agente Linux | Python 3 + Bash |
| Agente Windows | Python 3 + PowerShell |
| Backend / API | FastAPI + Uvicorn |
| Base de datos | SQLite |
| Panel web | HTML + CSS + JavaScript vanilla |
| Reportes | ReportLab (PDF) + OpenPyXL (Excel) |
| Tiempo real | WebSockets |
| Contenedores | Docker + Docker Compose |

---

## 📄 Licencia

MIT © 2024 — ServerHardenPro

---

> Desarrollado con ❤️ y Python · Proyecto educativo de ciberseguridad
