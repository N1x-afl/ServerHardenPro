# Changelog — ServerHardenPro

Todos los cambios notables del proyecto / All notable changes.

---

## [v0.5.0] — 2026-03-12

### ✨ Nuevas features
- **Panel DevSecOps** — Nueva sección con 4 tabs:
  - CVEs via NVD/NIST en tiempo real + fallback a DB local
  - Timeline de eventos de seguridad cronológicos
  - Comparativa de hardening entre servidores
  - Recomendaciones automáticas con comandos por check fallido
- **Gráficos reales** en el dashboard:
  - Auth Events — Login fallidos / exitosos / fuerza bruta
  - Score Trend — Tendencia histórica de hardening
  - Top IPs atacantes / Errores de syslog
- **Barra de búsqueda** de servidores en el header
- **Modal de configuración** (Settings) con URL backend e intervalo de refresh
- **Navegación top-level** Dashboard / DevSecOps con badge de CVEs críticos

### 🎨 Mejoras de UI
- Login rediseñado con partículas de red animadas (Canvas)
- Shield SVG en login y header (consistencia visual)
- Glassmorphism en todas las cards y panels del dashboard
- Header mejorado con botones SVG

### 🐛 Fixes
- Fix syntax error con caracteres Unicode en script (`═══`) que rompía en Brave/Chrome
- Fix `targets is not iterable` en panel DevSecOps
- Fix modo claro eliminado (causaba textos invisibles)
- Fix referencias nulas a `theme-icon` / `theme-label`
- Fix scroll-to-top con transición suave

---

## [v0.4.1] — 2026-03-11

### 🐛 Fixes
- Fix dashboard auto-detecta IP del servidor (`window.location.hostname`)
- Fix loadInventory usando endpoint `/servers/{hostname}/inventory` dedicado
- Fix scroll-to-top button display none/flex
- Fix sidebar siempre visible al recargar (eliminada persistencia en localStorage)

---

## [v0.4.0] — 2026-03-10

### ✨ Nuevas features
- **Auth JWT** — Sistema de login y registro con roles Admin / Viewer
- **Inventario de hardware** — CPU, RAM, Disco, Uptime, detección VM/Físico
- **Análisis de logs** — auth.log + syslog, detección de fuerza bruta
- **Glassmorphism** en el dashboard (cards semi-transparentes)
- **Sidebar colapsable** con slide + fade animation
- **Fecha y hora** en tiempo real en el header
- **Tab Logs** con análisis de intentos de acceso
- **Tab Inventario** con datos del hardware

### 🐛 Fixes
- Fix tabla `log_analysis` creada automáticamente en `init_db()`
- Fix `DB_PATH` apuntando a `/app/shp_database.db`
- Fix healthcheck usando `python3` en lugar de `curl`
- Fix puerto `8010` en docker-compose.yml

---

## [v0.3.0] — 2026-02-20

### ✨ Nuevas features
- **Reportes PDF** con ReportLab (solo Admin)
- **Reportes Excel** con OpenPyXL (solo Admin)
- **WebSockets** para actualizaciones en tiempo real
- **Modo oscuro/claro** en el dashboard
- **Logos SVG** por distribución Linux

---

## [v0.2.0] — 2026-02-01

### ✨ Nuevas features
- **Agente Windows** — 25 checks de hardening
- **Historial de scores** por servidor
- **Gráfico de evolución** del score de hardening
- **Cumplimiento por categoría** con barras de progreso

---

## [v0.1.0] — 2026-01-15

### 🎉 Lanzamiento inicial

- **Agente Linux** — 22 checks de hardening
- **Backend FastAPI** con SQLite
- **Panel web** básico con lista de servidores
- **Docker Compose** para despliegue rápido

---

## [v0.6.0] — 2026-03-15

### ✨ Nuevas features
- **Nginx reverse proxy** — HTTPS con certificado self-signed, redirect HTTP→HTTPS
- **Sistema de notificaciones** — panel lateral deslizable con alertas de CRIT, nuevo servidor y checks críticos
- **Filtros en sidebar** — TODOS / CRIT / WARN / OK en tiempo real
- **Comparativa lado a lado** — modal con tabla comparativa entre dos servidores
- **Uptime del backend** — contador en tiempo real en el header
- **Buscador de checks** — filtrado en tiempo real dentro del detalle del servidor
- **Cron automático Linux** — `install_cron.sh` interactivo con intervalos configurables
- **Task Scheduler Windows** — `install_task.ps1` con soporte de SHP_IP
- **Agente Windows** — inventario de hardware + análisis de Event Logs (4625/4624)
- **Soporte HTTPS en agentes** — SSL_CTX acepta certificados self-signed
- **SHP_IP** — variable de entorno para forzar IP correcta en ambos agentes

### 🐛 Fixes
- Fix Mixed Content al pasar de HTTP a HTTPS
- Fix API URL auto-detecta protocolo y puerto (HTTP/HTTPS)
- Fix IP 127.0.0.1 en agentes con detección via `ip route`
- Fix dropdown EXPORTAR cerrándose antes de seleccionar
- Fix `start_time` en endpoint `/health` para uptime real
