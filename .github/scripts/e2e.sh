#!/usr/bin/env bash
# End-to-end test of the standalone agent on one Docker host (CI runner or Docker Desktop), without Proton:
#   wizard via API (password, "ohne VPN", TLS backend) -> myaddr DDNS (fake myaddr.tools: by default no update
#   without VPN and never ip=self; then the fallback IP)
#   -> Let's Encrypt wildcard certificate via ACME DNS-01 against pebble + pebble-challtestsrv (the fake
#      myaddr.tools forwards every acme_challenge value as TXT record to challtestsrv)
#   -> delivery to a fake Nginx Proxy Manager (create + upload, renewal re-uploads the same id) and to a
#      Zoraxy certificate folder -> downloads with session and with the pull token
#   -> redirect host with the script provider (environment of the script) -> no secrets in the logs.
# All HTTP calls from the test run in helper containers inside the network namespace of the agent, so the
# script needs no published ports and no local port binding.
set -euo pipefail

AGENT_IMAGE="${AGENT_IMAGE:-portnook:ci}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.17.0}"
BACKEND_IMAGE="${BACKEND_IMAGE:-nginx:1.30.6-alpine}"
PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:2.10.3}"
CHALL_IMAGE="${CHALL_IMAGE:-ghcr.io/letsencrypt/pebble-challtestsrv:2.10.3}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d "${E2E_TMP:-${TMPDIR:-/tmp}}/pf-e2e.XXXXXX")"
chmod 777 "$WORK"
PASSWORD="ci-test-password-$RANDOM$RANDOM"
MYKEY="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' | cut -c1-43)"
NPM_USER="pf@example.ch"
NPM_SECRET="npm-secret-$RANDOM$RANDOM"
NAME=e2e-test; FQDN=$NAME.myaddr.tools
NET=pfci; SUBNET=192.168.77.0/24
PEBBLE_IP=192.168.77.2; CHALL_IP=192.168.77.3; FAKE_IP=192.168.77.4; BACKEND_IP=192.168.77.10; AGENT_IP=192.168.77.20
CONTAINERS=(portnook pf-backend pf-pebble pf-chall pf-fake)

step() { printf '\n=== %s\n' "$*"; }
dump() {
  step "FAILURE - diagnostics"
  for c in "${CONTAINERS[@]}"; do echo "--- docker logs $c"; docker logs "$c" 2>&1 | tail -n 60 || true; done
}
cleanup() {
  rc=$?
  [ "$rc" -eq 0 ] || dump
  docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

ccurl() { docker run --rm --network container:portnook -v "$WORK:/w" "$CURL_IMAGE" "$@"; }
api() { # $1 = method, $2 = path, $3 = JSON body (optional)
  if [ -n "${3:-}" ]; then
    ccurl -fsS -b /w/jar -c /w/jar -X "$1" -H 'Content-Type: application/json' -d "$3" "http://127.0.0.1:8090$2"
  else
    ccurl -fsS -b /w/jar -c /w/jar -X "$1" "http://127.0.0.1:8090$2"
  fi
}
fake_state() { ccurl -fsS "http://$FAKE_IP:$1/state"; }
# JSON from stdin, prints the Python expression $1 over it (d = the parsed JSON), using the agent's python
jget() { docker exec -i portnook python3 -c 'import json, sys; d = json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
wait_http() {
  local i code
  for ((i = 0; i < 60; i++)); do
    code=$(ccurl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8090/" 2>/dev/null || true)
    [ -n "$code" ] && [ "$code" != "000" ] && return 0
    sleep 1
  done
  echo "timeout waiting for the agent"; return 1
}

for img in "$CURL_IMAGE" "$BACKEND_IMAGE" "$PEBBLE_IMAGE" "$CHALL_IMAGE"; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null
done

step "LAN network, pebble + challtestsrv, fake myaddr/NPM, TLS backend"
docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker run -d --name pf-chall --network "$NET" --ip "$CHALL_IP" "$CHALL_IMAGE" \
  -defaultIPv6 "" -defaultIPv4 "$CHALL_IP" >/dev/null
docker run -d --name pf-pebble --network "$NET" --ip "$PEBBLE_IP" --network-alias pebble -e PEBBLE_VA_NOSLEEP=1 "$PEBBLE_IMAGE" \
  -config test/config/pebble-config.json -dnsserver "$CHALL_IP:8053" >/dev/null
mkdir -p "$WORK/ca" "$WORK/zoraxy" "$WORK/fake"
docker cp pf-pebble:/test/certs/pebble.minica.pem "$WORK/ca/minica.pem" >/dev/null
cp "$ROOT/.github/scripts/e2e/fake_lan.py" "$WORK/fake/"
chmod -R a+rX "$WORK/ca" "$WORK/fake"
docker run -d --name pf-fake --network "$NET" --ip "$FAKE_IP" -v "$WORK/fake:/fake:ro" --entrypoint python3 \
  "$AGENT_IMAGE" /fake/fake_lan.py "$MYKEY" "$FQDN" "http://$CHALL_IP:8055" "$NPM_USER" "$NPM_SECRET" >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=backend" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
chmod 644 "$WORK/key.pem"
printf 'server {\n listen 443 ssl;\n ssl_certificate /c/cert.pem;\n ssl_certificate_key /c/key.pem;\n location / { return 200 "ok"; }\n}\n' \
  > "$WORK/default.conf"
docker run -d --name pf-backend --network "$NET" --ip "$BACKEND_IP" -v "$WORK/cert.pem:/c/cert.pem:ro" \
  -v "$WORK/key.pem:/c/key.pem:ro" -v "$WORK/default.conf:/etc/nginx/conf.d/default.conf:ro" "$BACKEND_IMAGE" >/dev/null

step "Agent"
docker run -d --name portnook --network "$NET" --ip "$AGENT_IP" --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -e PF_MYADDR_URL="http://$FAKE_IP:8000" -e PF_ACME_DIRECTORY="https://pebble:14000/dir" \
  -e PF_ACME_CA_FILE=/ca/minica.pem -v "$WORK/ca:/ca:ro" -v "$WORK/zoraxy:/zoraxy-certs" "$AGENT_IMAGE" >/dev/null
wait_http

step "Wizard via API: password, without Proton, backend"
api POST /api/setup/password "{\"password\":\"$PASSWORD\"}" >/dev/null
api POST /api/setup/proton '{"enabled":false}' >/dev/null
api POST /api/setup/backend "{\"backend\":\"$BACKEND_IP:443\",\"lan_nets\":[\"$SUBNET\"]}" | grep -q '"tls": true' \
  || { echo "backend test failed"; exit 1; }
api GET /api/status | jget 'd["setup"]["done"]' | grep -qx True

step "myaddr.tools name and DDNS (default vpn mode without VPN: no update, never ip=self)"
api POST /api/myaddr "{\"name\":\"$NAME\",\"domain\":\"myaddr.tools\",\"key\":\"$MYKEY\",\"ddns\":true}" >/dev/null
api POST /api/action/ddns-update '{}' | grep -q "keine Ersatz-IP" || { echo "expected a skipped update"; exit 1; }
sleep 3
fake_state 8000 | jget 'd["ips"] == [] and d["self"] == 0' | grep -qx True || { echo "DDNS sent without VPN"; fake_state 8000; exit 1; }
api GET /api/status | jget 'd["ddns"]["waiting"]' | grep -q "kein Update"
api POST /api/myaddr "{\"name\":\"$NAME\",\"domain\":\"myaddr.tools\",\"ip_mode\":\"line\"}" 2>/dev/null \
  | grep -q '"ok": true' && { echo "mode line accepted"; exit 1; }
api POST /api/myaddr "{\"name\":\"$NAME\",\"domain\":\"myaddr.tools\",\"ip_mode\":\"vpn\",\"fallback_ip\":\"203.0.113.9\"}" >/dev/null
for ((i = 0; i < 30; i++)); do fake_state 8000 | grep -q '203.0.113.9' && break; sleep 1; done
fake_state 8000 | jget 'd["ips"] == ["203.0.113.9"] and d["self"] == 0' | grep -qx True \
  || { echo "fallback IP not sent"; fake_state 8000; exit 1; }
api GET /api/status | grep -q "$MYKEY" && { echo "key in status"; exit 1; }
echo "ddns ok"

step "Delivery targets (fake NPM, Zoraxy folder) and certificate settings"
api POST /api/delivery "{\"npm\":{\"url\":\"http://$FAKE_IP:8081\",\"identity\":\"$NPM_USER\",\"secret\":\"$NPM_SECRET\"},\"zoraxy\":{\"dir\":\"/zoraxy-certs\"}}" >/dev/null
api POST /api/cert/settings '{"staging":true,"delay":1,"tos":true,"auto":true}' >/dev/null

issue() { # waits until the order has finished; prints the cert status
  api POST /api/action/cert-issue '{}' >/dev/null
  local i st
  for ((i = 0; i < 120; i++)); do
    sleep 2
    st=$(api GET /api/status)
    if echo "$st" | jget 'd["cert"]["running"]' | grep -qx False; then break; fi
  done
  echo "$st" | jget 'd["cert"]'
}

step "ACME DNS-01 against pebble: wildcard certificate"
out=$(issue)
echo "$out"
grep -q "'present': True" <<<"$out" || { echo "no certificate"; exit 1; }
grep -q "'last_error': ''" <<<"$out" || { echo "order reported an error"; exit 1; }
grep -q "\['$FQDN', '\*.$FQDN'\]\|\['\*.$FQDN', '$FQDN'\]" <<<"$out" || { echo "wrong names"; exit 1; }
fake_state 8000 | jget 'd["challenges"]' | grep -qx 2 || { echo "expected 2 TXT values"; exit 1; }
docker exec portnook sh -c 'stat -c "%a %n" /data/certs/privkey.pem /data/acme/account.key' \
  | awk '{print} $1 != "600" {bad = 1} END {exit bad}'
docker exec portnook sh -c '[ "$(openssl x509 -in /data/certs/fullchain.pem -noout -pubkey)" = "$(openssl pkey -in /data/certs/privkey.pem -pubout)" ]'
echo "certificate and key match"

step "Delivery: fake NPM and Zoraxy folder"
npm=$(fake_state 8081)
echo "$npm" | jget '[(u["id"], u["files"]) for u in d["uploads"]]'
echo "$npm" | jget 'len(d["certs"]) == 1 and d["certs"][0]["provider"] == "other" and len(d["uploads"]) == 1' | grep -qx True
echo "$npm" | jget 'd["uploads"][0]["files"]' | grep -q "intermediate_certificate"
leaf=$(docker exec portnook cat /data/certs/cert.pem)
echo "$npm" | jget 'd["uploads"][0]["certificate"].strip()' > "$WORK/npm_leaf.pem"
[ "$(cat "$WORK/npm_leaf.pem")" = "$leaf" ] || { echo "NPM got another certificate"; exit 1; }
[ -f "$WORK/zoraxy/$FQDN.pem" ] && [ -f "$WORK/zoraxy/$FQDN.key" ] || { echo "Zoraxy files missing"; ls -l "$WORK/zoraxy"; exit 1; }
cmp -s "$WORK/zoraxy/$FQDN.pem" <(docker exec portnook cat /data/certs/fullchain.pem) || { echo "Zoraxy pem differs"; exit 1; }
echo "npm + zoraxy ok"

step "Downloads: session and pull token"
api GET /api/cert/download/fullchain.pem | grep -q "BEGIN CERTIFICATE"
ccurl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/api/cert/download/privkey.pem | grep -qx 401
TOKEN=$(api POST /api/cert/pull-token '{}' | jget 'd["token"]')
[ "${#TOKEN}" -ge 40 ]
ccurl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8090/api/cert/download/privkey.pem | grep -q "PRIVATE KEY"
ccurl -fsS -H "Authorization: Bearer $TOKEN" -o /w/cert.zip http://127.0.0.1:8090/api/cert/download/cert.zip
head -c 2 "$WORK/cert.zip" | grep -q PK
ccurl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer wrong" \
  http://127.0.0.1:8090/api/cert/download/fullchain.pem | grep -qx 401
echo "downloads ok"

step "Renewal: same NPM certificate id is re-uploaded"
out=$(issue)
grep -q "'last_error': ''" <<<"$out" || { echo "second order failed: $out"; exit 1; }
fake_state 8081 | jget 'len(d["certs"]) == 1 and [u["id"] for u in d["uploads"]] == [40, 40]' | grep -qx True \
  || { echo "renewal did not reuse the NPM certificate"; fake_state 8081; exit 1; }
echo "renewal ok"

step "Redirect host: script provider gets the target in its environment"
SCRIPT='env | grep "^PF_" | grep -v SSH | sort'
body=$(docker exec portnook python3 -c 'import json, sys; print(json.dumps({"provider": "script",
  "entry_host": "start.example.ch", "sub": "app", "status": 302, "fixed_port": 8443, "script": sys.argv[1]}))' "$SCRIPT")
api POST /api/redirect "$body" >/dev/null
res=$(api POST /api/action/redirect-run '{}')
echo "$res" | jget '"\n".join(d["output"])'
for want in "PF_TARGET_URL=https://app.$FQDN:8443" "PF_TARGET_HOST=app.$FQDN" "PF_PORT=8443" "PF_IP=203.0.113.9" \
            "PF_STATUS_CODE=302" "PF_ENTRY_HOST=start.example.ch"; do
  echo "$res" | grep -q "$want" || { echo "missing $want"; exit 1; }
done
api POST /api/redirect/ssh-key '{"generate":true}' | grep -q '"public_key": "ssh-ed25519 '
echo "redirect ok"

step "Never ip=self at the fake myaddr.tools"
fake_state 8000 | jget '"self" not in d["ips"] and d["self"] == 0' | grep -qx True || { echo "ip=self was sent"; exit 1; }
echo "no ip=self"

step "No secrets in logs or status"
logs=$(docker logs portnook 2>&1; api GET /api/logs; api GET /api/status)
for secret in "$MYKEY" "$NPM_SECRET" "$PASSWORD" "$TOKEN" "PRIVATE KEY"; do
  if grep -qF -- "$secret" <<<"$logs"; then echo "secret found in logs/status"; exit 1; fi
done
echo "no secrets"

step "E2E OK"
