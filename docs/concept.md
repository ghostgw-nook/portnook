# portnook – concept

Architecture and decisions of portnook. Since 0.9.0 the project is a single product, **portnook**: a Docker
container in the home network. Releases up to 0.8.0 (VPS edge + agent) stay in the git history and on the
releases page.

## Decision log

| Date | Decision |
|---|---|
| 2026-11-16 | M0–M8: edge on a VPS (SNI routing, wg-mgmt, health/failover) + agent per tenant (0.1–0.8). |
| **2026-11-18** | **(A) The VPS part is dropped** (0.9.0): `edge/` and everything only it needed (enrollment, wg-mgmt, reporter, `/edge/` proxy, tenant roles, edge image/CI/screenshots) are removed. The agent is a standalone product: Proton tunnel with NAT-PMP, port forward/DNAT to the reverse proxy, traffic light, own web UI + login. |
| 2026-11-18 | **(B) DDNS via myaddr.tools**: `<name>.<domain>` points at the Proton exit IP (updated on change and at least every 30 days). |
| 2026-11-18 | **(C) ACME DNS-01 wildcard certificate** (`<name>.<domain>` + `*.<name>.<domain>`) from Let's Encrypt with an own minimal RFC 8555 client (stdlib + openssl CLI). This replaces the old rule "no ACME in the project"; TLS still ends at the home reverse proxy, portnook only obtains and hands over the certificate. |
| 2026-11-18 | **(D) Delivery**: download in the UI and a token-protected pull API (`docs/pull-cert.sh`), push to Nginx Proxy Manager via its API, write into the Zoraxy certificate folder. |
| 2026-11-18 | **(F) The home IP is never published** (0.9.1): DDNS `ip_mode` `vpn` (default: VPN exit IP, while the VPN is down or the exit IP unknown the optional fallback IP, without one no update) or `manual` (fixed IP, IPv4/IPv6). `ip=self` is never sent, there is no opt-in (owner correction of the same day: no "line" mode). 0.9.0 state migrates to `vpn` without fallback. The redirect target follows the same rule. |
| 2026-11-18 | **(G) VPN providers with fixed ports** (0.9.1): besides Proton (NAT-PMP) any WireGuard config with provider-assigned ports (e.g. AirVPN, `provider: fixed`, 1–10 TCP ports entered in the UI). No NAT-PMP; DNAT only for those ports; the exit IP is read through `wg0` from the addr.tools IP echo (`PF_IPECHO_URL`, every 5 min, every minute while unknown). DDNS, certificate and redirect (first port) use it. |
| 2026-11-18 | **(H) Several VPN profiles with failover** (0.10.0; standby tunnel and "active on top" since 0.19.0, see H2; owner request "mehrere VPNs ermöglichen falls einer mal down geht"): profiles (name, Proton or fixed ports, WireGuard config, enabled) in priority order, exactly one runs as `wg0`. The monitor checks it every 30 s (wg0 up, handshake < 180 s, NAT-PMP renewals / exit IP via wg0); after `fails` failed checks (default 3) the next enabled profile starts (new DNAT ports; DDNS and redirect follow the exit IP/port). Optional return to the preferred profile after `hold` (default 600 s) with an immediate rollback if its test fails. All profiles down: stay on the last one, traffic light red, no traffic over the home line, DDNS fallback IP or no update, new round after `hold`. Events in the UI and the log (push notifications since 0.10.1, see J). 0.9.x state migrates to profile p1. |
| 2026-11-18 | **(I) No internet without a VPN tunnel** (0.10.1, owner decision): while no tunnel is up (VPN off, wg0 down, no fresh handshake or all profiles failed) the agent contacts no internet service at all — myaddr.tools (also fallback and manual IP), Let's Encrypt, Cloudflare, the IP echo, the redirect script (with a VPN), internet push servers. Pending work waits (latest state only: DDNS address, redirect target, certificate order, push messages) and goes out through `wg0` in the monitor cycle in which a tunnel is up again. Only private (RFC 1918) destinations stay reachable through `eth0` (NPM, Zoraxy folder, LAN push server). Enforced by one egress policy (`egress.py`) and, as defence in depth, the `PF_OUT` iptables chain. Consequence: without any VPN the agent is LAN-only (no DDNS, no certificate, no Cloudflare). |
| 2026-11-18 | **(J) Push notifications** (0.10.1): Gotify (URL + app token) and ntfy (server + topic + optional token), tokens write-only. Events: failover switch, back to the preferred profile, all VPNs down (reminder every 30 min, configurable), recovered, DDNS/certificate/redirect/NPM/Zoraxy errors, certificate renewed. Same event + text at most once per hour, at most 20 per hour. Internet push servers only through `wg0`; the all-down alarm therefore needs a push server in the LAN. |
| 2026-11-18 | **(K) Same Proton port after restarts** (0.10.2, owner request: Watchtower restarts changed the port): every NAT-PMP request asks for the port the active profile held last (`natpmpc -a <port> 0 …`, last port per profile in `/data/natpmp.json`, renewals ask for the current port); if that request fails it is repeated with `-a 1 0`, and if Proton hands out another port that one is used as before. Proton decides, so this is best effort. The compose files carry `com.centurylinklabs.watchtower.enable=false`; recommendation: a fixed-port provider (AirVPN) as profile 1, Proton as fallback. |
| 2026-11-18 | **(L) LAN entry** (0.10.2, owner request "intern direkt, extern über VPN"): the current forwarded port(s) (NAT-PMP or fixed, the same list as the `wg0` DNAT) are also DNATed on the agent's own `eth0` address(es) to the same backend (`-i eth0 -d <own IP>`), so LAN and home-VPN clients use the same URL `https://<sub>.<name>.myaddr.tools:<PORT>` without the tunnel. Follows port changes and failover (rebuilt with every firewall apply); inbound from the LAN only, `PF_OUT` unchanged; replies of these connections are dropped instead of entering `wg0` (`--ctorigdst <own IP>`), so a home-VPN subnet must be listed in the LAN networks. Never on the UI port. UI toggle (default on, `backend.lan_entry`), `POST /api/lan-entry`. Internal DNS (e.g. Technitium) points `*.<name>.myaddr.tools` statically at the agent's LAN IP and the redirect entry name at the reverse proxy; DNS carries no ports. Needs an own LAN IP for the container (macvlan/ipvlan, Unraid custom br0). |
| 2026-11-21 | **(L2) LAN entry as a TCP proxy** (0.18.1, owner report "Port vom LAN blockiert"): on an ipvlan network whose parent is a Linux bridge with `bridge-nf-call-iptables=1` (Unraid `br0`) the host's conntrack already tracks the client's SYN while it crosses the bridge and gives it a null NAT binding; the packet reaches the container with that entry attached, the container's `nat PREROUTING` is skipped and the kernel refuses the connection (raw, mangle and INPUT count it, nat does not). The LAN entry is therefore no DNAT any more: `app.lanproxy` listens on the agent's own `eth0` address(es) and the current forwarded port(s) and relays each connection to the backend (threads, at most 256 at once). Both sockets are bound to `eth0` (`SO_BINDTODEVICE`), so replies and the backend connection never use `wg0`, and home-VPN clients no longer need their subnet in the LAN networks for the LAN entry. The eth0 DNAT, the eth0 -> eth0 forward/MSS rules and the `--ctorigdst` drop are gone; listeners follow port changes and failover with every firewall apply. Status `lan_entry.errors` lists listeners that could not bind. |
| 2026-11-22 | **Fixed profile priority** (0.24.0, owner: "Prioritäten ... setzen", "liste bleibt fix, ein zurückwechseln soll nicht sein; wenn z.B. auf 2 ist und sich 1 erholt soll 1 schon vorbereitet sein"; replaces "active on top" of H2): the list order is the priority and no switch reorders it. The standby and first failover candidate is the highest-priority enabled profile that is not active; there is no automatic return. Rotation goes round robin to the next profile below the active one. |
| 2026-11-21 | **(H2) Standby tunnel, active profile on top** (0.19.0, owner request "1+n VPNs geöffnet mit verschiedenen DNS-Namen, damit das Umschalten auf eine andere IP schnell geht"; owner choices: active + 1 standby, an own myaddr name per profile, switching through the redirect, certificates as always, the active profile always on top, no preferred profile): wg-quick runs every tunnel with `Table = off` and its own socket mark (`wg0` 0xca6c, `wg1` 0xca6d); the agent owns the routing: table 51820/51821 per interface (`default dev wgX`, `unreachable` as kill switch), ip rules 10000+ = WireGuard sockets -> main, connmark of inbound tunnel connections (`PF_MARK`, set on NEW, restored on eth0) -> that tunnel's table (before main: both tunnels may share a subnet), main without its default route (LAN), `oif wgX` (bound sockets), and one rule for everything else to the active tunnel's table. The standby (`app.standby`) is the enabled profile that ran longest ago (the last one); it keeps its own NAT-PMP mapping (a Python NAT-PMP client bound to its interface, natpmpc cannot pick one), port, exit IP and DNAT. A failover, a rotation or a manual switch to it only swaps that last ip rule (new before old), moves the profile to the top and tears the old tunnel down; the old profile comes back as the standby. Without a ready standby the old rebuild path runs. Endpoint names may belong to a profile (`profile`): A record = that profile's exit IP, and the redirect target uses it while the profile is active. One certificate covers the main name and all endpoint names (DNS-01 TXT published with each name's key; a missing name triggers a new order). PF_MSS uses the smaller MTU of both tunnels. `prefer_primary` is gone (always off); `failover.standby` (default on) switches the standby off. |
| 2026-11-18 | **(M) Tunnel MTU per profile, MSS clamping** (0.10.3, owner request "MTU fix und konfigurierbar"): every profile has `mtu_setting` = 1280-1500 or `"conf"` (the MTU of the uploaded wg.conf, `mtu`; none there = wg-quick's 1420). Default **1340** = room for WireGuard nested twice over an IPv6 outer path (1500 - 80 - 80); 1420 = single tunnel; 1280 against stalling video (PMTU black holes). The MTU is written into the rendered wg0 config (`protonconf.with_mtu`), so a changed MTU changes the config digest and rebuilds wg0 (start, failover, activate, save). `PF_MSS` sets the MSS to MTU - 40 (`--set-mss`, the kernel never raises an MSS) for SYN and SYN/ACK in and out of `wg+` and for the LAN entry (eth0 -> eth0, `--ctstate DNAT`); without a VPN it clamps to the path MTU. Migration: profiles without `mtu_setting` get 1340, or `"conf"` if their wg.conf has an MTU. API `POST /api/vpn/profile` `{mtu}`; status `proton.mtu` (live wg0), `mtu_setting`, `mtu_effective`. |
| 2026-11-18 | **(E) Redirect host**: a stable entry URL redirects (302) to `https://<sub>.<name>.myaddr.tools:<current Proton port>`; providers Cloudflare (Single Redirect rule) or a user shell script (e.g. Plesk over SSH, `openssh-client` in the image); optional second myaddr name kept alive for a redirect server with a fixed IP. |

Later milestones (not in 0.9.0):

- **Direct path / apps:** some clients store the redirect *target*, so after a Proton port change
  the user has to enter the entry URL again. A client-side solution is up to each app.
- All myaddr subnames (`*.<name>.myaddr.tools`) resolve to the same IP (the exit IP). A redirect host therefore
  needs its own DNS name elsewhere (e.g. a Cloudflare domain) or a **second** myaddr name pointing at the
  redirect server.

## Architecture

```
Visitor ──https://app.<name>.myaddr.tools:<port>──> Proton exit IP:<port> (NAT-PMP mapping)
                                                             │ wg0 (Proton WireGuard, outbound from home)
                                                        portnook (Docker, NET_ADMIN)
                                                             │ DNAT wg0 tcp/<port> -> BACKEND
                                                        reverse proxy (NPM / Zoraxy / …, TLS ends here)
                                                             │
                                                        web service

stable entry (optional): https://start.example.ch ──302──> https://app.<name>.myaddr.tools:<port>
```

- No port is open at home; the ISP only sees WireGuard to Proton.
- Without VPN the agent still does certificates and delivery; DDNS only publishes a fallback or manual IP (never
  the home IP); the entry is then a port forward on the home router (not managed by portnook).

## Repository layout

```
agent/        Dockerfile, compose files, app/ (python package), web/index.html, examples/, tests/
docs/         concept.md (this file), installation.md (German), pull-cert.sh, images/
.github/      tests, auto-merge, build, releases, dependabot; scripts/e2e.sh, screenshots.sh, logos.sh
reference/v1/ earlier prototype, read only
```

Image: `ghcr.io/ghostgw-nook/portnook`, `alpine:3.24` + `python3 libnatpmp wireguard-tools
iproute2 iptables openssl ca-certificates openssh-client`.

## Modules (`agent/app/`)

| Module | Job |
|---|---|
| `agent.py` | setup steps, network apply (routes → firewall → wg0), egress policy, actions, status |
| `net.py` | routes via eth0, `wg0` via `wg-quick`, iptables chains `PF_PRE/PF_POST/PF_MSS/PF_IN/PF_FWD/PF_OUT` |
| `natpmp.py` | NAT-PMP loop (45 s), exit IP + TCP port, DNAT update, 5 failures → rebuild wg0 |
| `monitor.py` | 30 s loop: exit IP, failover, tunnel state, backend TLS check, DDNS tick, certificate renewal check, redirect tick, push |
| `egress.py` | single egress policy: internet only through a working `wg0`, private (LAN) addresses through `eth0` |
| `notify.py` | push notifications (Gotify, ntfy): events, dedupe/rate limit, all-down reminder, queue per target |
| `myaddr.py` | myaddr.tools client + DDNS state machine |
| `acme.py` | RFC 8555 client (ES256 via openssl), DNS-01 |
| `certs.py` | certificate manager: settings, order worker, files, renewal, pull token, downloads, delivery |
| `delivery.py` | Nginx Proxy Manager API, Zoraxy folder |
| `redirect.py` | redirect providers (Cloudflare, script), SSH key, second myaddr name |
| `httpc.py` | HTTP(S) client with interface binding (`SO_BINDTODEVICE`), CA file, size limit |
| `api.py`, `auth.py`, `store.py`, `lights.py` | web API + static UI, sessions, `/data/agent.json`, traffic light |

## VPN profiles and failover (`agent/app/failover.py`)

- State: `proton.profiles` (list = priority; secrets: the WireGuard private keys, never returned by the API),
  `proton.active`, `proton.failover` `{fails, prefer_primary, hold}`; `proton.enabled` switches the VPN as a whole.
- API: `POST /api/vpn/profile` (add/change, `mtu` 1280-1500 or "conf"; rebuilds wg0 if the running profile got a new config or MTU),
  `/api/vpn/profile/delete`, `/api/vpn/order` `{ids}`, `/api/vpn/activate` `{id}`, `/api/vpn/failover`;
  `GET /api/status` → `proton.profiles`, `proton.profile`, `proton.failover` (settings, current failures, events).
- A switch is `wg-quick down` + `up` with the next config, then the usual test (handshake, exit IP); the NAT-PMP
  loop only runs for Proton profiles. A failed IP echo (fixed ports) is retried on every check while failing.
- Known limit: if the IP echo (addr.tools) itself is down, fixed-port profiles look unhealthy; after one round
  the agent waits `hold` before trying again instead of switching continuously.
- E2E `.github/scripts/e2e-vpn.sh`: two real WireGuard peers in containers (fixed ports), a fake internet
  network only reachable through the tunnel; the provider's port forwarding is simulated by connecting from
  the peer to the agent's tunnel IP.

## Egress policy (where requests leave the container)

Since 0.10.1 (decision I) every HTTP request goes through one policy (`egress.py`, passed to `httpc.request` as
`device`); it decides per resolved address before connecting:

- **Internet** (myaddr.tools, ACME, Cloudflare, IP echo): bound to `wg0` (`SO_BINDTODEVICE`) while a VPN is on
  and `wg0` exists. Otherwise only private addresses (RFC 1918, loopback, link-local; e.g. test stand-ins) are
  allowed, everything else raises `EgressBlocked` — also without any VPN. DNS lookups use the container resolver.
- **LAN** (Nginx Proxy Manager, push): private addresses through `eth0`, never the tunnel (the NPM host must
  resolve to RFC 1918 addresses only); other push servers only through `wg0`. Zoraxy is a mounted folder.
- **Queue:** before a request, DDNS, certificate, redirect and push ask `egress.allowed(url)`: true while the
  tunnel is up (VPN on, `wg0`, handshake < 180 s, not "all profiles failed") or the host is private. If false the
  latest pending state is kept (`ddns.queued`, `redirect.queued`, `cert.queued`, push outbox per event) without
  counting a failure; the monitor sends it in the cycle the tunnel is up again (backoff reset).
- **Redirect script:** cannot be bound; with a VPN it only runs while the tunnel is up; without any VPN it runs
  and `PF_OUT` limits it to private addresses.
- **`PF_OUT`** (filter OUTPUT, defence in depth): new connections of the container through `eth0` are accepted
  only to RFC 1918 / link-local destinations, the DNS servers from `/etc/resolv.conf` (port 53), the WireGuard
  endpoints of all profiles (UDP) and packets with the wg-quick fwmark `0xca6c`; everything else is rejected.

## myaddr.tools (verified in the open source github.com/brianshea2/addr.tools, `internal/zones/myaddr/api.go`)

- `POST https://myaddr.tools/update`, form fields `key` and **either** `ip` **or** `acme_challenge` (both → 400).
  `ip=self` uses the source address of the request (never used by portnook, see decision F). 200 with body `OK` on success, 4xx/5xx with a short text.
- Key: 43 (base64url of 32 bytes) or 64 characters. Name: 6–40 chars, starts with a letter, `[a-z0-9-]`, no
  trailing hyphen. Domains `myaddr.tools`, `myaddr.dev`, `myaddr.io`.
- `acme_challenge`: 43 chars base64url; every added value is served as TXT on all `_acme-challenge` names below
  the registered name, several values coexist and expire after a few minutes (`challenges.ChallengeTtl`).
- IP records become inactive after 90 days without update, registrations are deleted after 120 days.
- The myaddr TLS certificate could not be checked from the build environment; the base URL is configurable
  (`PF_MYADDR_URL`, used by the E2E test).

**DDNS in portnook** (`myaddr.Ddns.resolve`): mode `vpn` publishes the VPN exit IP (Proton: NAT-PMP; fixed
ports: IP echo through `wg0`) while `wg0` is up; otherwise the fallback IP if one is set, else nothing (the old
record stays, the status says why). Mode `manual` always publishes the manual IP. Update when the IP changes and
at least every 30 days (keepalive). `myaddr.update` refuses anything that is not an IP address, so `ip=self`
cannot be sent. With a VPN configured every request still goes through `wg0` only (fail closed), also with a
fallback IP. Failures back off 5 min → 1 h. Key stored in `/data/agent.json` (mode 600),
write-only in the API/UI.

## ACME (RFC 8555)

- Account key `/data/acme/account.key` (EC P-256, PKCS#8, mode 600) is kept across orders and CAs
  (`newAccount` returns the existing account). The account URL per directory is stored in `acme.accounts`.
- JWS ES256: `openssl dgst -sha256 -sign` gives DER `ECDSA-Sig-Value`, converted to raw `r || s` (32+32 bytes).
  JWK thumbprint per RFC 7638. `badNonce` is retried up to 3 times.
- Order for `[fqdn, *.fqdn]` → two `dns-01` authorizations on the same `_acme-challenge.<fqdn>` name → both TXT
  values added via myaddr → wait (setting "Wartezeit DNS", default 60 s, 0–600) → respond → poll authz →
  finalize with a CSR (new P-256 key per order, `openssl req -addext subjectAltName`) → download the chain.
- Files in `/data/certs/`: `fullchain.pem`, `cert.pem`, `chain.pem`, `privkey.pem` (600).
- Staging/production toggle (staging default). `PF_ACME_DIRECTORY` / `PF_ACME_CA_FILE` override the directory
  and CA bundle (E2E with pebble). Terms of service must be accepted in the UI.
- Renewal: monitor loop, when fewer than 30 days are left and "auto" is on; after a failure retry in 6 h.

## Delivery

**Nginx Proxy Manager** (verified against github.com/NginxProxyManager/nginx-proxy-manager, `backend/routes/
tokens.js`, `backend/routes/nginx/certificates.js`, `backend/internal/certificate.js`):

1. `POST /api/tokens {identity, secret}` → `{token, expires}`; a user with 2FA gets `requires_2fa` → error
   (use a dedicated NPM user without 2FA).
2. `GET /api/nginx/certificates` → find `provider == "other"` and `nice_name` (default `portnook <fqdn>`).
3. If missing: `POST /api/nginx/certificates {provider: "other", nice_name}` → id.
4. `POST /api/nginx/certificates/<id>/upload`, multipart files `certificate` (leaf), `certificate_key`,
   `intermediate_certificate` (chain); NPM concatenates certificate + intermediate for nginx, checks that key
   and certificate match and reloads. Renewals re-upload to the **same id**, so proxy hosts keep their binding.

**Zoraxy** (verified against github.com/tobychui/zoraxy, `src/mod/tlscert/`, `docker/entrypoint.go`):
certificates are pairs `<name>.pem` + `<name>.key` in `conf/certs` (Docker: workdir `/opt/zoraxy/config`, so
`<appdata>/zoraxy/config/conf/certs`); wildcards are named `_.<domain>` by Zoraxy itself. portnook writes
`<fqdn>.pem` (full chain) and `<fqdn>.key` (600) atomically into the mounted folder. Zoraxy reads the files at
each handshake: the exact host matches by file name, subdomains by an SNI scan over a cached list of pairs.
Renewals (same file names) are picked up at once; a **new** pair is found for subdomains after Zoraxy refreshes
the list (restart or a certificate action in its UI). The Zoraxy API needs a session/CSRF login and is not used.

**Download / pull:** `GET /api/cert/download/{fullchain.pem,cert.pem,chain.pem,privkey.pem,cert.zip}` with the
UI session, or with `Authorization: Bearer <pull token>` (token shown once, stored as SHA-256, compared with
`hmac.compare_digest`, failures rate limited per IP like logins). Script: `docs/pull-cert.sh`.

## Redirect host

- Target: `https://<sub>.<fqdn>:<port>` with the NAT-PMP port (without Proton: a fixed port from the settings).
  The provider runs when the target changes, once after saving, and with "Jetzt ausführen"; failures retry
  after 5 min.
- **Cloudflare** (Rulesets API, phase `http_request_dynamic_redirect`, token permission Zone → Single Redirect
  → Edit): `GET /zones/<zone>/rulesets/phases/http_request_dynamic_redirect/entrypoint`; 404 → `PUT` the same
  path with `{rules: [rule]}`; otherwise `PATCH .../rulesets/<id>/rules/<rule id>` for the rule whose
  description is `portnook redirect <entry host>`, or `POST .../rules`. Rule: expression
  `(http.host eq "<entry>")`, action `redirect`, `from_value: {status_code, target_url: {expression:
  concat("<target>", http.request.uri.path)}, preserve_query_string: true}`. Zone by ID or by name
  (`GET /zones?name=`, needs Zone Read). Verified against the Cloudflare docs pages for single redirects and
  the rulesets API endpoints; the concat with `http.request.uri.path` and the PUT-creates-entrypoint behaviour
  are not shown verbatim there and are not tested against the real API.
- **Script**: `/data/redirect/script.sh` (edited in the UI, ≤ 32 KiB), run as `/bin/sh` in `/data/redirect`
  with only `PATH`, `HOME` and `PF_TARGET_URL`, `PF_TARGET_HOST`, `PF_PORT`, `PF_IP`, `PF_STATUS_CODE`,
  `PF_ENTRY_HOST`, `PF_SSH_KEY`, `PF_KNOWN_HOSTS`; timeout 60 s; exit code and the last 50 output lines are
  shown in the UI, the last 5 lines are logged. SSH key `/data/redirect/id_ed25519` (600), generated
  (`ssh-keygen -t ed25519`) or uploaded (no passphrase); only the public key is shown. Examples in
  `agent/examples/` (Plesk `.htaccess` with `RewriteRule` keeping the path and leaving `/.well-known/` for the
  host's own HTTP-01; `index.php` with `Location`).
- **Second myaddr name** (optional): `key2` + fixed public IP of the redirect server; set and refreshed every
  30 days, so that server can get its own Let's Encrypt certificate via HTTP-01.

## API (agent, `:8090`)

| Method + path | Purpose |
|---|---|
| `GET /api/session`, `POST /api/login`, `POST /api/logout` | session (cookie `HttpOnly`, `SameSite=Strict`) |
| `POST /api/setup/password`, `/api/setup/proton`, `/api/setup/backend` | wizard |
| `GET /api/status`, `GET /api/logs` | dashboard (no secrets) |
| `POST /api/action/<proton-reconnect\|natpmp-renew\|backend-test\|ddns-update\|cert-issue\|cert-deliver\|redirect-run\|push-test>` | actions (queued while no tunnel: `queued` in the answer) |
| `POST /api/lan-entry` | LAN entry `{enabled}` (0.10.2); status `lan_entry` = `{enabled, active, ips, ports, urls, skipped, errors}` (proxy since 0.18.1) |
| `POST /api/push` | Gotify `{url, token}`, ntfy `{url, topic, token}` (tokens write-only; a new URL needs the token again), `reminder` (minutes) |
| `POST /api/myaddr` | name, domain, key (write-only), DDNS on/off |
| `POST /api/cert/settings` | staging, e-mail, DNS wait, auto renew, terms accepted |
| `POST /api/delivery` | NPM (url, identity, secret write-only, nice_name), Zoraxy folder |
| `POST /api/cert/pull-token` | new token (shown once) or `{revoke: true}` |
| `GET /api/cert/download/<file>` | session or bearer pull token |
| `POST /api/redirect`, `GET /api/redirect/script`, `GET /api/redirect/example/<name>`, `POST /api/redirect/ssh-key` | redirect host |

Body ≤ 48 KiB, JSON only. State `/data/agent.json` (600). On load, the 0.8 sections `mgmt` and `edge`
(including the old wg-mgmt key and token) are dropped.

## Traffic light

`proton` (handshake < 3 min), `natpmp` (port mapped; failing with a known port → warn), `backend` (TLS, > 300 ms
→ warn), `ddns` (last update ok; failing < 1 day → warn), `cert` (≥ 30 days ok, 14–30 warn, < 14 or missing
after an error → error), `delivery` (all targets ok), `redirect` (current target applied; new target pending →
warn). Overall = worst known state.

## Open assumptions

1. `apk info -L libnatpmp` lists `natpmpc` – confirmed (CI smoke test).
2. `natpmpc` output parsing – tested with a recorded sample; to confirm against Proton at acceptance.
3. Proton delivers inbound traffic with destination port = the mapped public port (documented behaviour); the
   agent DNATs only that TCP port on `wg0`. Providers with fixed ports (AirVPN) are assumed to do the same for the
   forwarded ports (not tested live).
5. `https://ip.addr.tools/` answers JSON with the field `ip` (checked 2026-11-18); plain text is accepted too.
4. Not tested live: real Let's Encrypt (only pebble in CI), real myaddr.tools, real NPM, real Zoraxy, real
   Cloudflare, real Proton.

## Manual acceptance

```bash
docker exec portnook wg show wg0
docker exec portnook iptables-save -t nat | grep PF_PRE
dig +short <name>.myaddr.tools                 # = Proton exit IP
openssl s_client -connect <name>.myaddr.tools:<port> -servername app.<name>.myaddr.tools </dev/null \
  | grep -E 'subject|issuer'                   # certificate of the reverse proxy = the portnook wildcard
curl -sI https://start.example.ch/web/ | grep -i location   # redirect host
```
