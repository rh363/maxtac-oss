#!/bin/sh
# Rigenera sandbox/tools-requirements.txt con gli hash di tutte le dipendenze (anche
# transitive) degli scanner Python. L'immagine li installa con --require-hashes.
set -eu
cd "$(dirname "$0")/.."
uv pip compile sandbox/tools.in --generate-hashes --python-version 3.13 \
  --python-platform x86_64-manylinux_2_28 -o sandbox/tools-requirements.txt -q
sed -i '2s|.*|#    scripts/lock-sandbox-tools.sh (uv pip compile --generate-hashes, Python 3.13, manylinux_2_28 x86_64)|' \
  sandbox/tools-requirements.txt
echo "sandbox/tools-requirements.txt aggiornato"
