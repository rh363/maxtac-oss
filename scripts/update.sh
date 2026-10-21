#!/bin/sh
# Aggiorna Autofix sulla VM: scarica le immagini (sandbox compreso), riavvia i servizi e
# toglie le immagini vecchie. Richiede `docker login ghcr.io` fatto una volta.
# Chrome aggiornato ogni settimana: meglio che nel distretto, e senza effetti collaterali.
# Il sandbox viene ricostruito dalla CI ogni lunedì alle 04:17 UTC: un cron dopo quell'ora
# lo porta sulla VM, per esempio il lunedì alle 08:00:
#   0 8 * * 1  cd /opt/autofix && ./scripts/update.sh >> /var/log/autofix-update.log 2>&1
set -eu
cd "$(dirname "$0")/.."
# la dashboard si aggiorna solo se è in uso
web=""
docker compose --profile web ps --services --status running 2>/dev/null | grep -qx web && web="--profile web"
# il sandbox va scaricato ma non avviato: lo lancia l'orchestrator a ogni task
docker compose --profile sandbox $web pull
docker compose $web up -d --remove-orphans
docker image prune -f >/dev/null
echo "$(date -Is) autofix aggiornato"
