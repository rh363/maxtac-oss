#!/bin/sh
# Il proxy dei sandbox parte con proxy/squid.conf, resta su e applica l'allowlist:
# un registry passa, un host dell'allowlist locale (proxy/local) passa, il resto riceve 403.
set -eu
cd "$(dirname "$0")/.."
IMAGE=$(docker compose config --images proxy 2>/dev/null || true)
IMAGE=${IMAGE:-ubuntu/squid:6.6-24.04_beta}
NET=autofix-smoke-proxy
LOCAL=""
cleanup() {
  docker rm -f autofix-smoke-proxy >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  [ -z "$LOCAL" ] || rm -rf "$LOCAL"
}
trap cleanup EXIT
cleanup
LOCAL=$(mktemp -d)
docker network create "$NET" >/dev/null
printf '# registry interni\nexample.com\n' > "$LOCAL/extra-registries.txt"
chmod 755 "$LOCAL" && chmod 644 "$LOCAL/extra-registries.txt"
docker run -d --name autofix-smoke-proxy --network "$NET" --network-alias proxy \
  -v "$PWD/proxy/squid.conf:/etc/squid/squid.conf:ro" -v "$LOCAL:/etc/squid/local:ro" \
  "$IMAGE" >/dev/null
sleep 5
state=$(docker inspect autofix-smoke-proxy -f '{{.State.Status}}')
[ "$state" = running ] || { docker logs autofix-smoke-proxy; echo "squid non è in esecuzione: $state"; exit 1; }

connect() {
  docker run --rm --network "$NET" --entrypoint bash "$IMAGE" -c \
    "exec 3<>/dev/tcp/proxy/3128; printf 'CONNECT $1:443 HTTP/1.1\r\nHost: $1:443\r\n\r\n' >&3; head -1 <&3"
}
connect pypi.org | grep -q " 200 " || { echo "pypi.org non passa dal proxy"; exit 1; }
# l'allowlist locale decide il permesso: conta che non sia 403 (il sito può non rispondere)
connect example.com | grep -q " 403 " && { echo "l'allowlist locale non viene letta"; exit 1; }
connect github.com | grep -q " 403 " || { echo "github.com non è bloccato"; exit 1; }
# i log passano dal file all'stdout con `tail -F`: qualche secondo di ritardo
for _ in 1 2 3 4 5 6 7 8 9 10; do
  docker logs autofix-smoke-proxy 2>&1 | grep -q "TCP_DENIED/403" && break
  sleep 1
done
docker logs autofix-smoke-proxy 2>&1 | grep -q "TCP_DENIED/403" || { echo "log del proxy assenti"; exit 1; }
echo "proxy ok"
