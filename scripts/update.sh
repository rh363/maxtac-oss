#!/bin/sh
# Aggiorna Autofix sulla VM: scarica le immagini (sandbox compreso), riavvia i servizi e
# toglie le immagini vecchie. Le immagini sono pubbliche: non serve `docker login`.
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
# immagini dei sandbox per repo (sandbox.images): sandbox/local/<nome>.Dockerfile diventa
# autofix-sandbox-<nome>:local, ricostruita sopra l'immagine standard appena scaricata
base=$(docker compose --profile sandbox config --images 2>/dev/null | grep autofix-sandbox | head -n1)
for f in sandbox/local/*.Dockerfile; do
  [ -e "$f" ] || continue
  name=$(basename "$f" .Dockerfile)
  # una build fallita non blocca l'aggiornamento: resta l'immagine precedente, se c'è
  if docker build -q --build-arg "BASE=${base:-ghcr.io/rh363/autofix-sandbox:main}" \
    -t "autofix-sandbox-$name:local" -f "$f" sandbox/local >/dev/null; then
    echo "immagine autofix-sandbox-$name:local ricostruita"
  else
    echo "ATTENZIONE: build di $f fallita, autofix-sandbox-$name:local non aggiornata" >&2
  fi
done
docker compose $web up -d --remove-orphans
docker image prune -f >/dev/null
echo "$(date -Is) autofix aggiornato"
