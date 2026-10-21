#!/bin/sh
# Prova le immagini appena costruite, senza rete e con rootfs in sola lettura come a runtime.
# Usato dalla CI dopo la build; utile anche sulla VM dopo un pull.
#   ./scripts/smoke-images.sh <orchestrator> <web> <sandbox>
set -eu
ORCH="$1"; WEB="$2"; SBX="$3"
RUN="docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true"

echo "== orchestrator: CLI"
$RUN "$ORCH" --help >/dev/null
$RUN --entrypoint git "$ORCH" --version

echo "== web: CLI e build della SPA"
$RUN "$WEB" web --help >/dev/null
$RUN --entrypoint python "$WEB" -c '
from maxtac.web.spa import default_static_dir
p = default_static_dir() / "index.html"
assert p.is_file(), p
print("spa:", p)'

echo "== sandbox: strumenti"
SB="$RUN --tmpfs /home/sandbox --tmpfs /work:uid=1000,gid=1000 --user 1000:1000 $SBX"
for cmd in "python --version" "go version" "node --version" "npm --version" "git --version" \
           "/usr/local/bin/semgrep --version" "/usr/local/bin/bandit --version" \
           "/usr/local/bin/gosec -version" "/usr/local/bin/osv-scanner --version"; do
  echo "\$ $cmd"; $SB sh -c "$cmd"
done

echo "== sandbox: osv-scanner offline trova una CVE nota"
$SB sh -c '
cd /work && printf "requests==2.19.0\n" > requirements.txt && : > /tmp/empty.toml
/usr/local/bin/osv-scanner scan source --recursive --offline-vulnerabilities \
  --config /tmp/empty.toml --format json --output /tmp/osv.json /work; rc=$?
[ "$rc" -eq 1 ] || { echo "exit inatteso: $rc"; exit 1; }
grep -q "GHSA-" /tmp/osv.json && echo "ok: vulnerabilità trovate offline"'

echo "== sandbox: semgrep offline con i ruleset dell immagine"
$SB sh -c '
ls -l /opt/semgrep-rules && cd /work \
&& printf "import subprocess\nsubprocess.call(input(), shell=True)\n" > app.py \
&& /usr/local/bin/semgrep scan --metrics=off --disable-version-check --quiet --disable-nosem \
     --json --output /tmp/sg.json --config /opt/semgrep-rules/p-python.yml . \
&& python -c "import json; r=json.load(open(\"/tmp/sg.json\"))[\"results\"]; assert r, r; print(\"ok:\", len(r), \"finding\")"'

echo "== sandbox: bandit"
$SB sh -c 'cd /work && printf "import subprocess\nsubprocess.call(input(), shell=True)\n" > app.py \
&& /usr/local/bin/bandit -r . -f json -o /tmp/b.json -q --ignore-nosec; [ $? -le 1 ] \
&& grep -q B602 /tmp/b.json && echo "ok: B602"'
echo "tutto ok"
