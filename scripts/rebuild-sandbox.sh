#!/bin/sh
# Ricostruisce in locale l'immagine dei sandbox senza cache (alternativa alla rebuild della CI,
# che la pubblica ogni lunedì: con le immagini di GHCR basta scripts/update.sh).
# Da cron sulla VM, ogni domenica alle 05:00 (dopo la run notturna):
#   0 5 * * 0  cd /opt/autofix && ./scripts/rebuild-sandbox.sh >> /var/log/autofix-rebuild.log 2>&1
set -eu
cd "$(dirname "$0")/.."
docker compose --profile sandbox build --pull --no-cache sandbox-image
docker image prune -f --filter label!=keep >/dev/null
echo "$(date -Is) autofix-sandbox ricostruita"
