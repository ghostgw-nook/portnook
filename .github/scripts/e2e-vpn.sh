#!/usr/bin/env bash
# End-to-end test of VPN profiles with failover (0.10.0) with two real WireGuard peers in containers.
#   LAN 192.168.78.0/24: agent, TLS backend, peer A and peer B (WireGuard servers, provider type "fester Port")
#   "Internet" 100.64.200.0/24 (not a private range): only the peers and the fake myaddr.tools / ACME / ntfy;
#   the agent reaches it only through wg0. A LAN Gotify stand-in runs on 192.168.78.30.
# Each peer masquerades the tunnel and serves an IP echo on 10.99.0.1:8088 that answers its own fake exit IP
# (A 198.51.100.11, B 198.51.100.12), so the agent's exit IP shows which peer it uses.
# Checked: profile 1 up, DNAT of its fixed port to the backend, DDNS = exit IP A; peer A down -> failover to B
# (DNAT for B's port, DDNS = exit IP B); peer A back -> back to the preferred profile after the hold time;
# both down -> "alle Profile gestört", no DDNS update (no fallback IP), never ip=self; no keys in logs.
# 0.10.1: while all are down zero requests reach the internet fakes (myaddr, ACME), the PF_OUT chain
# rejects direct connections through eth0, the LAN Gotify gets the alarm and a reminder; after the recovery
# the queued manual DDNS address and the queued certificate order arrive.
# 0.18.0: push goes direct through eth0 with the socket mark 0x5046 (no ntfy fake: this test bed has no direct
# internet); checked: PF_OUT lets a marked socket out and still rejects an unmarked one.
# 0.10.2: LAN entry: a LAN client reaches the backend via the agent's LAN IP on the current forwarded port; after
# the failover (port change) the old port is closed and the new one open; switching it off closes it.
# 0.19.0: standby tunnel: profile 2 runs on wg1 next to the active one (its port answers through it); on the
# failover it is promoted (no rebuild), the list order stays (fixed priority, 0.24.0), no way back to a "preferred" one;
# the old profile comes back as the standby once its peer is up again.
# Simulated: the provider side (port forwarding = a direct connection from the peer to the agent's tunnel IP).
set -euo pipefail

AGENT_IMAGE="${AGENT_IMAGE:-portnook:ci}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.17.0}"
BACKEND_IMAGE="${BACKEND_IMAGE:-nginx:1.30.6-alpine}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d "${E2E_TMP:-${TMPDIR:-/tmp}}/pf-e2e-vpn.XXXXXX")"
chmod 777 "$WORK"
PASSWORD="ci-test-password-$RANDOM$RANDOM"
MYKEY="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' | cut -c1-43)"
NAME=e2e-vpn; FQDN=$NAME.myaddr.tools
LAN=pfvlan; LAN_NET=192.168.78.0/24; INET=pfvinet; INET_NET=100.64.200.0/24
PEER_A=192.168.78.2; PEER_B=192.168.78.3; BACKEND_IP=192.168.78.10; AGENT_IP=192.168.78.20; FAKE_IP=100.64.200.4; LANPUSH_IP=192.168.78.30
EXIT_A=198.51.100.11; EXIT_B=198.51.100.12
CONTAINERS=(pfv-agent pfv-backend pfv-peer-a pfv-peer-b pfv-fake pfv-lanpush)
GOTIFY_TOKEN="Agotify$RANDOM$RANDOM"; NTFY_TOKEN="tk_ntfy$RANDOM$RANDOM$RANDOM"

step() { printf '\n=== %s\n' "$*"; }
cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    step "FAILURE - diagnostics"
    for c in "${CONTAINERS[@]}"; do echo "--- docker logs $c"; docker logs "$c" 2>&1 | tail -n 60 || true; done
  fi
  docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
  docker network rm "$LAN" "$INET" >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

ccurl() { docker run --rm --network container:pfv-agent -v "$WORK:/w" "$CURL_IMAGE" "$@"; }
api() {
  if [ -n "${3:-}" ]; then
    ccurl -fsS -b /w/jar -c /w/jar -X "$1" -H 'Content-Type: application/json' -d "$3" "http://127.0.0.1:8090$2"
  else
    ccurl -fsS -b /w/jar -c /w/jar -X "$1" "http://127.0.0.1:8090$2"
  fi
}
jget() { docker exec -i pfv-agent python3 -c 'import json, sys; d = json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
fake_state() { docker exec "$1" python3 -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/state").read().decode())'; }
inet_hits() { fake_state pfv-fake | jget 'd["hits"]'; }
lan_titles() { fake_state pfv-lanpush | jget '"|".join(o["title"] for o in d["other"])'; }
fake_ips() { docker exec pfv-fake python3 -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/state").read().decode())' | jget '",".join(d["ips"]) + "|" + str(d["self"])'; }
status() { api GET /api/status; }
wg0_mtu() { docker exec pfv-agent cat /sys/class/net/wg0/mtu; }
active_mtu() { status | jget 'd["proton"]["mtu"]'; }
standby_ready() { # $1 = profile id
  wait_for 'd["proton"]["failover"]["standby_tunnel"]["profile"] == "'"$1"'" and d["proton"]["failover"]["standby_tunnel"]["ready"]' 90 "standby $1 ready"
}
mss_rules() { # $1 = MSS: PF_MSS clamps wg0 (both directions); the LAN entry is a proxy since 0.18.1
  local rules; rules=$(docker exec pfv-agent iptables -t mangle -S PF_MSS)
  for r in "-i wg+" "-o wg+"; do
    grep -q -- "-A PF_MSS $r -p tcp .*--tcp-flags SYN,RST SYN .*-j TCPMSS --set-mss $1" <<<"$rules" ||
      { echo "PF_MSS without '$r ... --set-mss $1':"; echo "$rules"; exit 1; }
  done
}
wait_for() { # $1 = python expression over the status, $2 = seconds, $3 = what
  local i
  for ((i = 0; i < $2; i += 3)); do
    if status | jget "$1" 2>/dev/null | grep -qx True; then return 0; fi
    sleep 3
  done
  echo "timeout: $3"; status | jget 'd["proton"]'; return 1
}
# TLS handshake from a peer to the agent's tunnel IP and port = an inbound connection via the provider
tls_from() {
  docker exec "$1" python3 -c 'import socket, ssl, sys
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
s = socket.create_connection(("10.99.0.2", int(sys.argv[1])), timeout=5); c.wrap_socket(s).close(); print("tls ok")' "$2"
}
# TLS handshake from a LAN client (pfv-lanpush) to the agent's own LAN IP = the LAN entry
tls_lan() {
  docker exec pfv-lanpush python3 -c 'import socket, ssl, sys
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5); c.wrap_socket(s).close(); print("lan tls ok", sys.argv[2])' "$AGENT_IP" "$1"
}
lan_closed() {
  if docker exec pfv-lanpush python3 -c 'import socket, sys
socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5).close()' "$AGENT_IP" "$1" 2>/dev/null; then
    echo "LAN port $1 still open"; return 1
  fi
  echo "lan port $1 closed"
}
genkey() { docker run --rm --entrypoint sh "$AGENT_IMAGE" -c 'k=$(wg genkey); echo "$k $(echo "$k" | wg pubkey)"'; }

for img in "$CURL_IMAGE" "$BACKEND_IMAGE"; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null
done

step "Networks, backend, fake myaddr.tools (internet side), two WireGuard peers"
docker network create --subnet "$LAN_NET" "$LAN" >/dev/null
docker network create --subnet "$INET_NET" "$INET" >/dev/null
mkdir -p "$WORK/fake" "$WORK/a" "$WORK/b"
cp "$ROOT/.github/scripts/e2e/fake_lan.py" "$WORK/fake/"
chmod -R a+rX "$WORK/fake"
docker run -d --name pfv-fake --network "$INET" --ip "$FAKE_IP" -v "$WORK/fake:/fake:ro" --entrypoint python3 \
  "$AGENT_IMAGE" /fake/fake_lan.py "$MYKEY" "$FQDN" "http://127.0.0.1:9" npm@example.ch unused >/dev/null
docker run -d --name pfv-lanpush --network "$LAN" --ip "$LANPUSH_IP" -v "$WORK/fake:/fake:ro" --entrypoint python3 \
  "$AGENT_IMAGE" /fake/fake_lan.py "$MYKEY" "$FQDN" "http://127.0.0.1:9" npm@example.ch unused >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=backend" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
chmod 644 "$WORK/key.pem"
printf 'server {\n listen 443 ssl;\n ssl_certificate /c/cert.pem;\n ssl_certificate_key /c/key.pem;\n location / { return 200 "ok"; }\n}\n' \
  > "$WORK/default.conf"
docker run -d --name pfv-backend --network "$LAN" --ip "$BACKEND_IP" -v "$WORK/cert.pem:/c/cert.pem:ro" \
  -v "$WORK/key.pem:/c/key.pem:ro" -v "$WORK/default.conf:/etc/nginx/conf.d/default.conf:ro" "$BACKEND_IMAGE" >/dev/null

read -r PEER_A_PRIV PEER_A_PUB <<<"$(genkey)"; read -r PEER_B_PRIV PEER_B_PUB <<<"$(genkey)"
read -r AG_A_PRIV AG_A_PUB <<<"$(genkey)"; read -r AG_B_PRIV AG_B_PUB <<<"$(genkey)"
cat > "$WORK/echo.py" <<'EOF'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = json.dumps({"ip": sys.argv[1], "asn": 64500}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
http.server.ThreadingHTTPServer(("0.0.0.0", 8088), H).serve_forever()
EOF
peer() { # $1 = a|b, $2 = LAN IP, $3 = peer private key, $4 = agent public key, $5 = exit IP
  printf '[Interface]\nPrivateKey = %s\nAddress = 10.99.0.1/24\nListenPort = 51820\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.99.0.2/32\n' \
    "$3" "$4" > "$WORK/$1/wg0.conf"
  chmod -R a+rX "$WORK/$1" "$WORK/echo.py"
  docker run -d --name "pfv-peer-$1" --network "$LAN" --ip "$2" --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
    -v "$WORK/$1:/peer:ro" -v "$WORK/echo.py:/echo.py:ro" --entrypoint sh "$AGENT_IMAGE" -c \
    "mkdir -p /etc/wireguard && cp /peer/wg0.conf /etc/wireguard/wg0.conf && chmod 600 /etc/wireguard/wg0.conf &&
     wg-quick up wg0 && iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -j MASQUERADE && exec python3 /echo.py $5" >/dev/null
  docker network connect "$INET" "pfv-peer-$1"
}
peer a "$PEER_A" "$PEER_A_PRIV" "$AG_A_PUB" "$EXIT_A"
peer b "$PEER_B" "$PEER_B_PRIV" "$AG_B_PUB" "$EXIT_B"
agent_conf() { # $1 = agent private key, $2 = peer public key, $3 = peer LAN IP, $4 = MTU line (optional)
  printf '[Interface]\nPrivateKey = %s\nAddress = 10.99.0.2/32\n%bDNS = 10.99.0.1\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s:51820\nPersistentKeepalive = 15\n' "$1" "${4:-}" "$2" "$3"
}
CONF_A="$(agent_conf "$AG_A_PRIV" "$PEER_A_PUB" "$PEER_A")"
CONF_B="$(agent_conf "$AG_B_PRIV" "$PEER_B_PUB" "$PEER_B" 'MTU = 1380\n')"
json_conf() { docker run --rm -i --entrypoint python3 "$AGENT_IMAGE" -c 'import json, sys; print(json.dumps(sys.stdin.read()))'; }

step "Agent"
docker run -d --name pfv-agent --network "$LAN" --ip "$AGENT_IP" --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -e PF_MYADDR_URL="http://$FAKE_IP:8000" -e PF_IPECHO_URL="http://10.99.0.1:8088/" \
  -e PF_ACME_DIRECTORY="http://$FAKE_IP:8082/acme/dir" \
  -e PF_MONITOR_INTERVAL=5 -e PF_EXIT_CHECK=5 "$AGENT_IMAGE" >/dev/null
for ((i = 0; i < 60; i++)); do
  code=$(ccurl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8090/" 2>/dev/null || true)
  [ -n "$code" ] && [ "$code" != "000" ] && break
  sleep 1
done
api POST /api/setup/password "{\"password\":\"$PASSWORD\"}" >/dev/null
api POST /api/setup/backend "{\"backend\":\"$BACKEND_IP:443\",\"lan_nets\":[\"$LAN_NET\"]}" | grep -q '"tls": true'

step "Profile 1 (peer A, fixed port 43210) via the wizard, profile 2 (peer B, 43211) via the profile API"
res=$(api POST /api/setup/proton "{\"enabled\":true,\"provider\":\"fixed\",\"ports\":\"43210\",\"conf\":$(json_conf <<<"$CONF_A"),\"lan_nets\":[\"$LAN_NET\"]}")
echo "$res" | jget '(d["ok"], d["test"]["exit_ip"])'
echo "$res" | jget 'd["test"]["exit_ip"]' | grep -qx "$EXIT_A"
api POST /api/vpn/profile "{\"name\":\"Peer B\",\"provider\":\"fixed\",\"ports\":\"43211\",\"mtu\":\"conf\",\"conf\":$(json_conf <<<"$CONF_B")}" >/dev/null
api POST /api/vpn/failover '{"fails":2,"prefer_primary":true,"hold":40}' >/dev/null
status | jget '[(p["id"], p["active"]) for p in d["proton"]["profiles"]] == [("p1", True), ("p2", False)]' | grep -qx True
tls_from pfv-peer-a 43210
tls_lan 43210
standby_ready p2
tls_from pfv-peer-b 43211  # the standby tunnel (wg1) answers on its port, replies go back through wg1
tls_lan 43211
status | jget 'd["lan_entry"]["active"] and d["lan_entry"]["ips"] == ["'"$AGENT_IP"'"] and d["lan_entry"]["ports"] == [43210, 43211]' | grep -qx True
echo "standby ok"
step "MTU: profile 1 default 1340 on wg0, MSS 1300 (smaller of both tunnels)"
[ "$(wg0_mtu)" = 1340 ] || { echo "wg0 mtu $(wg0_mtu), expected 1340"; exit 1; }
status | jget '(d["proton"]["mtu"], d["proton"]["mtu_setting"])' | grep -qx "(1340, 1340)"
mss_rules 1300
ccurl -sS -b /w/jar -X POST -H 'Content-Type: application/json' -d '{"id":"p1","mtu":1700}' \
  http://127.0.0.1:8090/api/vpn/profile | grep -q "MTU muss" || { echo "MTU 1700 accepted"; exit 1; }
api POST /api/vpn/profile '{"id":"p1","mtu":"1500"}' | jget 'd["ok"]' | grep -qx True
[ "$(wg0_mtu)" = 1500 ] || { echo "wg0 mtu $(wg0_mtu) after the change, expected 1500"; exit 1; }
mss_rules 1340  # standby p2 runs with 1380
echo "mtu ok"

step "DDNS (default mode vpn) publishes exit IP A through the tunnel"
api POST /api/myaddr "{\"name\":\"$NAME\",\"domain\":\"myaddr.tools\",\"key\":\"$MYKEY\",\"ddns\":true}" >/dev/null
for ((i = 0; i < 30; i++)); do fake_ips | grep -q "$EXIT_A" && break; sleep 1; done
fake_ips | grep -qx "$EXIT_A|0"

step "Push: LAN Gotify, test message"
api POST /api/push "{\"reminder\":1,\"gotify\":{\"url\":\"http://$LANPUSH_IP:8082\",\"token\":\"$GOTIFY_TOKEN\"}}" >/dev/null
api POST /api/action/push-test '{}' | jget 'd["ok"]' | grep -qx True
lan_titles | grep -q "portnook: Test"
api POST /api/cert/settings '{"staging":true,"delay":0,"tos":true,"auto":false}' >/dev/null
echo "push ok"

step "Peer A down -> failover: the standby (profile 2, peer B) takes over"
docker exec pfv-peer-a wg-quick down wg0 >/dev/null 2>&1
wait_for 'd["proton"]["profile"] == "p2" and d["proton"]["exit_ip"] == "'"$EXIT_B"'"' 120 "failover to p2"
status | jget 'd["proton"]["ports"]' | grep -qx "\[43211\]"
[ "$(active_mtu)" = 1380 ] || { echo "active mtu after failover $(active_mtu), expected 1380 (from the config)"; exit 1; }
mss_rules 1340
tls_from pfv-peer-b 43211
tls_lan 43211
status | jget '[p["id"] for p in d["proton"]["profiles"]]' | grep -qx "\['p1', 'p2'\]"
status | jget '[e["text"] for e in d["proton"]["failover"]["events"]]' | grep -q "Reserve übernommen"
for ((i = 0; i < 30; i++)); do fake_ips | grep -q "$EXIT_B" && break; sleep 1; done
fake_ips | grep -qx "$EXIT_A,$EXIT_B|0"
status | jget '[e["text"] for e in d["proton"]["failover"]["events"]]' | grep -q "Failover"
api POST /api/lan-entry '{"enabled":false}' | jget 'd["lan_entry"]["active"]' | grep -qx False
lan_closed 43211
tls_from pfv-peer-b 43211
api POST /api/lan-entry '{"enabled":true}' >/dev/null
tls_lan 43211
echo "failover ok (LAN entry follows the port)"

step "Peer A back -> profile 1 is the standby again, profile 2 stays active"
docker exec pfv-peer-a wg-quick up wg0 >/dev/null 2>&1
standby_ready p1
tls_from pfv-peer-a 43210
status | jget 'd["proton"]["profile"]' | grep -qx p2
fake_ips | grep -qx "$EXIT_A,$EXIT_B|0"
echo "no way back, standby again ok"

step "Both peers down -> all profiles failed, no DDNS update, light red"
docker exec pfv-peer-a wg-quick down wg0 >/dev/null 2>&1
docker exec pfv-peer-b wg-quick down wg0 >/dev/null 2>&1
wait_for 'd["proton"]["failover"]["all_down"] > 0' 180 "all profiles failed"
status | jget 'd["light"]["checks"]["proton"]' | grep -qx error
api POST /api/action/ddns-update '{}' | grep -q "keine Ersatz-IP"
sleep 10
fake_ips | grep -qx "$EXIT_A,$EXIT_B|0" || { echo "unexpected DDNS update"; fake_ips; exit 1; }
echo "kill switch ok"

step "All down: nothing to the internet, updates queued, LAN alarm"
for ((i = 0; i < 20; i++)); do lan_titles | grep -q "Alle VPNs ausgefallen" && break; sleep 2; done
lan_titles | grep -q "Alle VPNs ausgefallen"
H0=$(inet_hits)
api POST /api/myaddr "{\"name\":\"$NAME\",\"domain\":\"myaddr.tools\",\"ddns\":true,\"ip_mode\":\"manual\",\"manual_ip\":\"203.0.113.50\"}" >/dev/null
api POST /api/action/ddns-update '{}' | jget 'd["queued"]' | grep -qx 203.0.113.50
api POST /api/action/cert-issue '{}' | jget 'd.get("queued")' | grep -qx True
api POST /api/action/push-test '{}' | jget 'd["results"]["gotify"]["ok"]' | grep -qx True
docker exec pfv-agent iptables -S PF_OUT | grep -q -- "-A PF_OUT -o eth0 -j REJECT"
docker exec pfv-agent python3 -c 'import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, 25, b"eth0"); s.settimeout(5); t = time.time()
try:
    s.connect((sys.argv[1], 8000)); print("connected through eth0"); sys.exit(1)
except socket.timeout:
    print("timeout instead of reject"); sys.exit(1)
except OSError as err:
    print("eth0 blocked: %s (%.1f s)" % (err.strerror, time.time() - t))' "$FAKE_IP"
docker exec pfv-agent iptables -S PF_OUT | grep -q -- "-A PF_OUT -o eth0 -m mark --mark 0x5046 -j ACCEPT"
docker exec pfv-agent python3 -c 'import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, 36, 0x5046); s.setsockopt(socket.SOL_SOCKET, 25, b"eth0"); s.settimeout(3)
try:
    s.connect((sys.argv[1], 8000)); print("push mark: connected")
except socket.timeout:
    print("push mark: passes PF_OUT (no direct route in this test bed)")
except OSError as err:
    print("push mark rejected: %s" % err.strerror); sys.exit(1)' "$FAKE_IP"
sleep 75  # reminder interval 1 min
[ "$(inet_hits)" = "$H0" ] || { echo "internet fake contacted without tunnel"; fake_state pfv-fake; exit 1; }
lan_titles | grep -q "Alle VPNs weiterhin ausgefallen"
fake_ips | grep -qx "$EXIT_A,$EXIT_B|0"
echo "zero internet requests while down"

step "Recovery: queued DDNS address and certificate order arrive through wg0"
docker exec pfv-peer-a wg-quick up wg0 >/dev/null 2>&1
docker exec pfv-peer-b wg-quick up wg0 >/dev/null 2>&1
wait_for 'd["proton"]["failover"]["all_down"] == 0 and d["egress"]["tunnel_up"]' 240 "recovery"
for ((i = 0; i < 40; i++)); do fake_ips | grep -q "203.0.113.50" && break; sleep 2; done
fake_ips | grep -qx "$EXIT_A,$EXIT_B,203.0.113.50|0"
for ((i = 0; i < 30; i++)); do lan_titles | grep -q "VPN wieder verfügbar" && break; sleep 2; done
lan_titles | grep -q "VPN wieder verfügbar"
fake_state pfv-fake | jget '[o["path"] for o in d["other"]]' | grep -q "/acme/dir"
echo "queued updates delivered"

step "No keys in logs or status"
logs=$(docker logs pfv-agent 2>&1; api GET /api/logs; api GET /api/status)
for secret in "$MYKEY" "$PASSWORD" "$AG_A_PRIV" "$AG_B_PRIV" "$GOTIFY_TOKEN" "$NTFY_TOKEN"; do
  if grep -qF -- "$secret" <<<"$logs"; then echo "secret found in logs/status"; exit 1; fi
done
echo "no secrets"

step "E2E VPN failover OK"
