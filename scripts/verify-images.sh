#!/bin/sh
# Verifica la firma cosign delle immagini scaricate: devono essere state firmate dal
# workflow release.yml di questo repo su GitHub Actions (firma keyless, Sigstore).
#   ./scripts/verify-images.sh            # le immagini del compose
#   ./scripts/verify-images.sh <ref>...   # immagini a scelta (tag o digest)
set -eu
cd "$(dirname "$0")/.."
REPO="${AUTOFIX_SOURCE_REPO:-rh363/maxtac-oss}"
IDENTITY="^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/(heads/main|tags/v.+)$"
ISSUER="https://token.actions.githubusercontent.com"

command -v cosign >/dev/null || { echo "serve cosign: https://docs.sigstore.dev/cosign/system_config/installation/" >&2; exit 2; }
if [ "$#" -eq 0 ]; then
  set -- $(DOCKER_GID="${DOCKER_GID:-0}" docker compose --profile web --profile sandbox config --images | grep '^ghcr.io/')
fi
for ref in "$@"; do
  echo "== $ref"
  cosign verify --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
    "$ref" >/dev/null
  echo "firma valida"
done
