#!/usr/bin/env bash
# Regenerates the screenshots in docs/images/screenshots/ from the real agent UI (not run in CI).
# Same setup as e2e.sh: agent + TLS backend + pebble/challtestsrv + fake myaddr.tools/NPM (fake_lan.py) on one
# bridge network, without Proton. A headless Chromium container (shot.mjs) shares the network namespace of the
# agent and drives its UI over the DevTools protocol; no published ports, no local port binding.
# Example values only: name familie-muster.myaddr.tools, LAN 192.168.1.0/24, backend 192.168.1.10, entry
# start.example.ch. The certificate comes from pebble (test CA), so it shows a "Pebble" issuer.
# Usage: build portnook:ci (see tests.yml), then run .github/scripts/screenshots.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AGENT_IMAGE="${AGENT_IMAGE:-portnook:ci}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.17.0}"
BACKEND_IMAGE="${BACKEND_IMAGE:-nginx:1.30.6-alpine}"
PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:2.10.3}"
CHALL_IMAGE="${CHALL_IMAGE:-ghcr.io/letsencrypt/pebble-challtestsrv:2.10.3}"
CHROME_IMAGE="${CHROME_IMAGE:-zenika/alpine-chrome:124-with-node}"
OPT_IMAGE="${OPT_IMAGE:-alpine:3.24}"
DEST="${DEST:-$ROOT/docs/images/screenshots}"
WORK="$(mktemp -d "${SHOT_TMP:-${E2E_TMP:-${TMPDIR:-/tmp}}}/pf-shots.XXXXXX")"
chmod 777 "$WORK"
mkdir -m 777 "$WORK/out"

export AGENT_PW="Beispiel-Agent-$RANDOM$RANDOM"
MYKEY="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' | cut -c1-43)"
NPM_USER="portnook@example.ch"; NPM_SECRET="Beispiel-NPM-$RANDOM$RANDOM"
NAME=familie-muster; FQDN=$NAME.myaddr.tools
NET=pfs; SUBNET=192.168.1.0/24
PEBBLE_IP=192.168.1.2; CHALL_IP=192.168.1.3; NPM_IP=192.168.1.5; BACKEND_IP=192.168.1.10; AGENT_IP=192.168.1.20
CONTAINERS=(pfs-agent pfs-backend pfs-pebble pfs-chall pfs-fake)

step() { printf '\n=== %s\n' "$*"; }
cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    for c in "${CONTAINERS[@]}"; do echo "--- docker logs $c"; docker logs "$c" 2>&1 | tail -n 40 || true; done
    if [ -n "${DEBUG_DIR:-}" ]; then mkdir -p "$DEBUG_DIR" && cp "$WORK"/out/*.png "$DEBUG_DIR"/ 2>/dev/null || true; fi
  fi
  docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

ccurl() { docker run --rm --network container:pfs-agent -v "$WORK:/w" "$CURL_IMAGE" "$@"; }
api() {
  if [ -n "${3:-}" ]; then
    ccurl -fsS -b /w/jar -c /w/jar -X "$1" -H 'Content-Type: application/json' -d "$3" "http://127.0.0.1:8090$2"
  else
    ccurl -fsS -b /w/jar -c /w/jar -X "$1" "http://127.0.0.1:8090$2"
  fi
}
shoot() {
  docker run --rm --network container:pfs-agent --shm-size=256m -e AGENT_PW \
    -v "$ROOT/.github/scripts/screenshots:/s:ro" -v "$WORK/out:/out" \
    --entrypoint node "$CHROME_IMAGE" --experimental-websocket --no-warnings /s/shot.mjs "$@"
}

for img in "$CURL_IMAGE" "$CHROME_IMAGE" "$BACKEND_IMAGE" "$OPT_IMAGE" "$PEBBLE_IMAGE" "$CHALL_IMAGE"; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null
done

step "LAN $SUBNET: pebble, challtestsrv, fake myaddr/NPM, backend, agent"
docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker run -d --name pfs-chall --network "$NET" --ip "$CHALL_IP" "$CHALL_IMAGE" -defaultIPv6 "" -defaultIPv4 "$CHALL_IP" >/dev/null
docker run -d --name pfs-pebble --network "$NET" --ip "$PEBBLE_IP" --network-alias pebble -e PEBBLE_VA_NOSLEEP=1 \
  -e PEBBLE_WFE_NONCEREJECT=0 "$PEBBLE_IMAGE" -config test/config/pebble-config.json -dnsserver "$CHALL_IP:8053" >/dev/null
mkdir -p "$WORK/ca" "$WORK/fake" "$WORK/zoraxy"
docker cp pfs-pebble:/test/certs/pebble.minica.pem "$WORK/ca/minica.pem" >/dev/null
cp "$ROOT/.github/scripts/e2e/fake_lan.py" "$WORK/fake/"
chmod -R a+rX "$WORK/ca" "$WORK/fake"
docker run -d --name pfs-fake --network "$NET" --ip "$NPM_IP" -v "$WORK/fake:/fake:ro" --entrypoint python3 \
  "$AGENT_IMAGE" /fake/fake_lan.py "$MYKEY" "$FQDN" "http://$CHALL_IP:8055" "$NPM_USER" "$NPM_SECRET" >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$FQDN" -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
chmod 644 "$WORK/key.pem"
printf 'server {\n listen 443 ssl;\n ssl_certificate /c/cert.pem;\n ssl_certificate_key /c/key.pem;\n location / { return 200 "ok"; }\n}\n' \
  > "$WORK/default.conf"
docker run -d --name pfs-backend --network "$NET" --ip "$BACKEND_IP" -v "$WORK/cert.pem:/c/cert.pem:ro" \
  -v "$WORK/key.pem:/c/key.pem:ro" -v "$WORK/default.conf:/etc/nginx/conf.d/default.conf:ro" "$BACKEND_IMAGE" >/dev/null
docker run -d --name pfs-agent --network "$NET" --ip "$AGENT_IP" --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -e PF_MYADDR_URL="http://$NPM_IP:8000" -e PF_ACME_DIRECTORY="https://pebble:14000/dir" \
  -e PF_ACME_CA_FILE=/ca/minica.pem -v "$WORK/ca:/ca:ro" -v "$WORK/zoraxy:/zoraxy-certs" "$AGENT_IMAGE" >/dev/null
for ((i = 0; i < 60; i++)); do ccurl -fs -o /dev/null http://127.0.0.1:8090/ && break; sleep 1; done

step "Wizard (browser)"
shoot wizard "$BACKEND_IP:443" "$SUBNET"

step "Name, certificate, delivery, redirect via API"
api POST /api/login "{\"password\":\"$AGENT_PW\"}" >/dev/null
api POST /api/myaddr "{\"name\":\"$NAME\",\"domain\":\"myaddr.tools\",\"key\":\"$MYKEY\",\"ddns\":true,\"ip_mode\":\"vpn\",\"fallback_ip\":\"203.0.113.10\"}" >/dev/null
api POST /api/delivery "{\"npm\":{\"url\":\"http://$NPM_IP:8081\",\"identity\":\"$NPM_USER\",\"secret\":\"$NPM_SECRET\"},\"zoraxy\":{\"dir\":\"/zoraxy-certs\"}}" >/dev/null
api POST /api/cert/settings '{"staging":false,"delay":2,"tos":true,"auto":true,"email":"admin@example.ch"}' >/dev/null
api POST /api/action/cert-issue '{}' >/dev/null
for ((i = 0; i < 60; i++)); do api GET /api/status | grep -q '"present": true' && break; sleep 2; done
api GET /api/status | grep -q '"present": true' || { echo "no certificate"; exit 1; }
# no automatic follow-up order for the names added below: it races the fake DNS and leaves an ACME error on the shots
api POST /api/cert/settings '{"staging":false,"delay":2,"tos":true,"auto":false,"email":"admin@example.ch"}' >/dev/null
SCRIPT='# Beispiel: hier stuende z. B. ssh ... (siehe Beispiel-Skripte)
echo "Redirect gesetzt ($PF_STATUS_CODE):"
echo "$PF_RULES"'
api POST /api/myaddr/names "{\"names\":[{\"name\":\"$NAME-tv\",\"domain\":\"myaddr.io\",\"role\":\"entry\",\"ip\":\"1.2.3.70\",\"key\":\"$MYKEY\"},{\"name\":\"$NAME-2\",\"domain\":\"myaddr.dev\",\"role\":\"endpoint\",\"key\":\"$MYKEY\"}]}" >/dev/null
body=$(docker exec pfs-agent python3 -c 'import json, sys; print(json.dumps({"provider": "script",
  "entry_host": "start.example.ch", "sub": "app", "status": 302, "fixed_port": 8443, "script": sys.argv[1],
  "rules": [{"entry": "familie-muster-tv.myaddr.io", "sub": "app"},
            {"entry": "*.familie-muster-tv.myaddr.io", "sub": "*", "to": "familie-muster-2.myaddr.dev"}]}))' "$SCRIPT")
api POST /api/redirect "$body" >/dev/null
api POST /api/redirect/ssh-key '{"generate":true}' >/dev/null
api POST /api/action/redirect-run '{}' >/dev/null
api POST /api/action/backend-test '{}' >/dev/null
api POST /api/push "{\"reminder\":30,\"gotify\":{\"url\":\"http://$NPM_IP:8082\",\"token\":\"AexampleToken01\"},\"ntfy\":{\"url\":\"https://ntfy.sh\",\"topic\":\"portnook-beispiel\"}}" >/dev/null
api POST /api/action/push-test '{}' >/dev/null || true

step "Status, certificate, redirect, push (browser)"
shoot status
shoot vpn
shoot myaddr
shoot cert
shoot redirect
shoot push
shoot settings

step "Optimise and copy to $DEST"
docker run --rm -v "$WORK/out:/out" "$OPT_IMAGE" sh -c \
  'apk add -q --no-cache pngquant >/dev/null && cd /out && for f in *.png; do pngquant --force --skip-if-larger --quality 70-95 --strip --output "$f" "$f" || true; done'
mkdir -p "$DEST"
cp "$WORK"/out/*.png "$DEST"/
ls -l "$DEST"
step "Screenshots OK"
