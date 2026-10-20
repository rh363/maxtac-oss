#!/bin/sh
# Risolve i tag delle immagini base in digest sha256 e li scrive nei Dockerfile e nel
# compose (`image:tag@sha256:...`), così un tag spostato non cambia cosa si costruisce.
# Da lanciare sulla VM (serve accesso ai registry), poi committare il risultato.
#   ./scripts/pin-digests.sh          # pinna
#   ./scripts/pin-digests.sh --check  # esce con 1 se qualche immagine non è pinnata
set -eu
cd "$(dirname "$0")/.."
FILES="Dockerfile sandbox/Dockerfile docker-compose.yml"
CHECK="${1:-}"

refs() {
  # FROM <img> [AS x]  e  image: <img>; si saltano gli stage interni e le immagini locali
  grep -hoE '^(FROM|[[:space:]]*image:)[[:space:]]+[^[:space:]]+' $FILES \
    | awk '{print $NF}' | grep -E '[:/]' | grep -v '^autofix-' | sort -u
}

missing=0
for ref in $(refs); do
  case "$ref" in
    *@sha256:*) continue ;;
    *'${'*) echo "salto $ref (contiene ARG: pinnare a mano la versione e il digest)"; continue ;;
  esac
  missing=1
  [ "$CHECK" = "--check" ] && { echo "non pinnata: $ref"; continue; }
  digest=$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}' | tr -d '"')
  echo "$ref -> $digest"
  for f in $FILES; do
    sed -i "s|$ref\$|$ref@$digest|; s|$ref |$ref@$digest |" "$f"
  done
done
[ "$CHECK" = "--check" ] && exit "$missing"
exit 0
