#!/bin/sh
# Mostra lo SHA del commit di ogni azione usata nei workflow alla versione indicata nel
# commento (`uses: owner/repo@<sha> # vX.Y.Z`), per controllare o aggiornare i pin a mano.
#   ./scripts/pin-actions.sh          # elenca pin attuali e SHA risolti
#   ./scripts/pin-actions.sh --fix    # riscrive i pin che non corrispondono
set -eu
cd "$(dirname "$0")/.."
FIX="${1:-}"
grep -ho 'uses: [^ ]*@[0-9a-f]\{40\} # v[0-9.]*' .github/workflows/*.yml | sort -u |
while read -r _ ref _ version; do
  action="${ref%@*}"; pinned="${ref#*@}"
  sha=$(git ls-remote "https://github.com/${action}" "refs/tags/${version}^{}" "refs/tags/${version}" | awk 'NR==1{print $1}')
  [ -n "$sha" ] || { echo "?? $action $version: tag non trovato"; continue; }
  if [ "$sha" = "$pinned" ]; then echo "ok $action $version"; continue; fi
  echo "!! $action $version: pin $pinned, tag $sha"
  [ "$FIX" = "--fix" ] && sed -i "s|${action}@${pinned} # ${version}|${action}@${sha} # ${version}|" .github/workflows/*.yml
done
