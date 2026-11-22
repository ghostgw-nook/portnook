# Troubleshooting

> **Applies to:** portnook 0.27 (rc1) · [Versions](Versions)

First look at the status page: the card with the coloured dot names the cause; details are in the log.

## Checks

```bash
docker exec portnook wg show wg0                       # handshake with the VPN
dig +short <name>.myaddr.tools                         # = exit IP
openssl s_client -connect <name>.myaddr.tools:<port> \
  -servername app.<name>.myaddr.tools </dev/null | grep -E 'subject|issuer'
curl -sI https://start.example.com/ | grep -i location     # redirect host
```

## Common problems

| Symptom | Cause and fix |
|---|---|
| Web UI not reachable from the LAN | `PF_BIND` missing or wrong in `.env`; then `docker compose up -d` |
| Web UI drops after the VPN starts | LAN networks missing (default: all private networks) |
| VPN test: "created without NAT-PMP" | Create a new Proton WireGuard file with NAT-PMP for a P2P server |
| DDNS: "VPN off or exit IP unknown, no fallback IP" | Check the VPN or set a fallback IP |
| DDNS: `HTTP 400: invalid value for "key"` | Wrong key, or the name was deleted at myaddr.tools (120 days without update) |
| "No VPN tunnel … queued" | On purpose: without a tunnel nothing goes to the internet; sent once a VPN is up |
| Certificate: `unauthorized` / `dns` | TXT value not visible yet: raise **DNS wait time** (e.g. 120 s) |
| Certificate: `rateLimited` | Too many production tries; test with staging and retry later |
| NPM / Zoraxy errors | See [Nginx Proxy Manager](Nginx-Proxy-Manager#troubleshooting), [Zoraxy](Zoraxy#troubleshooting) |
| Backend red, proxy works in the LAN | Backend port does not match the proxy listener, see [Port 443 or a dedicated port](Reverse-proxy-port) |
| Internal host reachable from outside | Access rule trusts "LAN"; deny portnook's IP, see [Port 443 or a dedicated port](Reverse-proxy-port) |
| Redirect: "target unknown" | No port or exit IP yet |
| Redirect script: code 255 / `Permission denied (publickey)` | Add the public key at the hosting, enable SSH |
| Videos stall, large pages do not finish | Set the profile MTU to 1280 |
| Push: `HTTP 401` / `403` | Wrong Gotify app token or ntfy token/topic |
