#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║     ServerHardenPro — Instalador de Cron (Linux)               ║
# ║  Uso: sudo bash install_cron.sh                                 ║
# ║  Instala tarea cron para auditoría automática cada 6 horas      ║
# ╚══════════════════════════════════════════════════════════════════╝

set -e

# ── Colores ──────────────────────────────────────────────────────
CYAN="\033[96m"; GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; RESET="\033[0m"

echo -e "\n${CYAN}  ╔══════════════════════════════════════╗"
echo -e "  ║  ServerHardenPro — Cron Installer   ║"
echo -e "  ╚══════════════════════════════════════╝${RESET}\n"

# ── Verificar root ────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}  ❌ Ejecutar como root: sudo bash install_cron.sh${RESET}\n"
  exit 1
fi

# ── Detectar ruta del agente ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_PATH="$SCRIPT_DIR/agent_linux.py"

if [ ! -f "$AGENT_PATH" ]; then
  echo -e "${RED}  ❌ No se encontró agent_linux.py en $SCRIPT_DIR${RESET}"
  echo -e "${YELLOW}  Ejecutá este script desde la carpeta agents/linux/${RESET}\n"
  exit 1
fi

# ── Pedir configuración ───────────────────────────────────────────
echo -e "${CYAN}  URL del backend${RESET} (Enter para usar https://localhost):"
read -r API_INPUT
API_URL="${API_INPUT:-https://localhost}"

echo -e "\n${CYAN}  Intervalo de auditoría:${RESET}"
echo "  1) Cada 1 hora"
echo "  2) Cada 6 horas (recomendado)"
echo "  3) Cada 12 horas"
echo "  4) Una vez al día (medianoche)"
read -r -p "  Opción [2]: " INTERVAL_OPT
INTERVAL_OPT="${INTERVAL_OPT:-2}"

case "$INTERVAL_OPT" in
  1) CRON_SCHEDULE="0 * * * *";    INTERVAL_TEXT="cada 1 hora" ;;
  3) CRON_SCHEDULE="0 */12 * * *"; INTERVAL_TEXT="cada 12 horas" ;;
  4) CRON_SCHEDULE="0 0 * * *";    INTERVAL_TEXT="una vez al día" ;;
  *) CRON_SCHEDULE="0 */6 * * *";  INTERVAL_TEXT="cada 6 horas" ;;
esac

# ── Crear directorio de logs ──────────────────────────────────────
LOG_DIR="/var/log/shp"
mkdir -p "$LOG_DIR"
echo -e "\n${GREEN}  ✅ Directorio de logs: $LOG_DIR${RESET}"

# ── Instalar cron ─────────────────────────────────────────────────
CRON_CMD="$CRON_SCHEDULE SHP_API=$API_URL python3 $AGENT_PATH --cron >> $LOG_DIR/agent.log 2>&1"

# Eliminar entrada anterior si existe
crontab -l 2>/dev/null | grep -v "agent_linux.py" | crontab - 2>/dev/null || true

# Agregar nueva entrada
(crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -

echo -e "${GREEN}  ✅ Cron instalado: ${INTERVAL_TEXT}${RESET}"
echo -e "${CYAN}  → $CRON_CMD${RESET}"

# ── Verificar instalación ─────────────────────────────────────────
echo -e "\n${CYAN}  Verificando cron instalado:${RESET}"
crontab -l | grep "agent_linux"

# ── Ejecutar ahora una vez para verificar ────────────────────────
echo -e "\n${YELLOW}  ¿Ejecutar auditoría ahora para verificar? (s/N):${RESET}"
read -r RUN_NOW
if [[ "$RUN_NOW" =~ ^[sS]$ ]]; then
  echo -e "${CYAN}  Ejecutando auditoría...${RESET}\n"
  SHP_API="$API_URL" python3 "$AGENT_PATH"
fi

echo -e "\n${GREEN}  ✅ Instalación completa!${RESET}"
echo -e "  📋 Logs en: ${CYAN}$LOG_DIR/agent.log${RESET}"
echo -e "  🔧 Para desinstalar: ${CYAN}crontab -e${RESET} y eliminar la línea\n"
