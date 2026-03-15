#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║     ServerHardenPro — Setup CrowdSec Bouncer                   ║
# ║  Correr DESPUÉS de docker compose up -d --build                 ║
# ╚══════════════════════════════════════════════════════════════════╝

echo -e "\n\033[96m  Configurando CrowdSec Bouncer...\033[0m"

# Esperar que CrowdSec esté listo
echo "  Esperando que CrowdSec inicie..."
sleep 10

# Generar API key para el bouncer
echo -e "\n\033[96m  Generando API key...\033[0m"
API_KEY=$(docker exec shp_crowdsec cscli bouncers add shp-nginx-bouncer -o raw 2>/dev/null)

if [ -z "$API_KEY" ]; then
    echo "  Key ya existe, obteniendo..."
    docker exec shp_crowdsec cscli bouncers delete shp-nginx-bouncer 2>/dev/null
    API_KEY=$(docker exec shp_crowdsec cscli bouncers add shp-nginx-bouncer -o raw)
fi

echo -e "  \033[92m✅ API Key generada: $API_KEY\033[0m"

# Actualizar docker-compose con la key real
sed -i "s/shp-bouncer-key-change-this/$API_KEY/g" docker-compose.yml

echo -e "\n  Reiniciando bouncer con la key correcta..."
docker compose restart crowdsec-bouncer

echo -e "\n\033[92m  ✅ CrowdSec configurado!\033[0m"
echo -e "  📊 Ver IPs baneadas:    \033[96mdocker exec shp_crowdsec cscli decisions list\033[0m"
echo -e "  📋 Ver alertas:         \033[96mdocker exec shp_crowdsec cscli alerts list\033[0m"
echo -e "  🔍 Ver métricas:        \033[96mdocker exec shp_crowdsec cscli metrics\033[0m"
echo -e "  🚫 Banear IP manual:    \033[96mdocker exec shp_crowdsec cscli decisions add --ip IP\033[0m"
echo -e "  ✅ Desbanear IP:        \033[96mdocker exec shp_crowdsec cscli decisions delete --ip IP\033[0m\n"
