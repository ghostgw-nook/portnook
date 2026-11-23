# Real visitor IP (PROXY protocol)

> **Applies to:** portnook 0.30 (rc1) · [Versions](Versions)

Without this option your reverse proxy sees every connection from the VPN as coming from **portnook's LAN IP**.
The connection is plain TCP (TLS ends at your reverse proxy), so portnook cannot add an `X-Forwarded-For` header.
With the **PROXY protocol** portnook puts a short header with the visitor's real IP in front of each connection;
the reverse proxy reads it and uses that IP for its logs, access rules, fail2ban, geo blocking and the
`X-Forwarded-For` / `X-Real-IP` it passes on to your services.

**Important:** once it is on, the reverse proxy must expect the header on the port portnook connects to. A port
with the PROXY protocol rejects connections without header and vice versa. So: **first** set up the reverse
proxy, **then** turn it on in portnook.

| Reverse proxy | Works? | How |
|---|---|---|
| Zoraxy | yes | one switch, see [Zoraxy](#zoraxy) |
| Nginx Proxy Manager | yes, with a dedicated port | custom `listen` line per host, see [Nginx Proxy Manager](#nginx-proxy-manager) |
| nginx | yes | `listen … proxy_protocol`, see [nginx](#nginx) |
| Traefik, Caddy, HAProxy | yes | their PROXY protocol option for the entry point / listener (not described here) |

## What portnook does

- **Connection** → **Real visitor IP (PROXY protocol)** → tick **Pass the real IP via PROXY protocol**.
- portnook sends a **PROXY protocol v2** header (binary, TCP over IPv4) on every connection it forwards: the
  active tunnel, the standby tunnel and the LAN entry. The header of the LAN entry carries the LAN client's IP.
- For this portnook accepts the tunnel ports itself instead of forwarding them in the kernel (DNAT). That needs
  a bit more CPU; for normal home use (streaming included) it is fine. Turn it off and the kernel forwarding is
  back.
- The backend check in the overview sends the header too (with portnook's own IP), so the light stays green.
- HTTP/3 (QUIC, UDP) never reaches you through portnook anyway: only TCP is forwarded.

## Zoraxy

1. **Ingress** → **Advance Settings** → **PROTOCOLS** → switch **PROXY Protocol** on and save.
   Zoraxy then turns HTTP/3 off (it cannot do both); see above, through portnook you lose nothing.
2. In portnook turn the option on (see above).
3. Check: open a service from outside (mobile data, not Wi-Fi) and look at Zoraxy's access log or the service's
   log: it should show your mobile IP, not portnook's.

Devices in your LAN that connect to Zoraxy **directly** (not through portnook) send no header. Zoraxy's PROXY
protocol listener should accept such connections as before; if your LAN clients fail after step 1, point them to
portnook's [LAN entry](Home-network-and-LAN-entry) instead, which sends the header.

> The Zoraxy switch was not tested live by the project; menu names can differ between Zoraxy versions.

## Nginx Proxy Manager

NPM has no switch for it, but its custom configuration can add a second `listen` line with `proxy_protocol`.
Use the **dedicated port** of [Nginx Proxy Manager, approach B](Nginx-Proxy-Manager#b-dedicated-port-8443):
port 443 stays as it is for your LAN, only 8443 expects the header.

1. Publish port 8443 on the NPM container (see approach B).
2. On **each public** proxy host, tab **Advanced** → **Custom Nginx Configuration** (instead of the two lines of
   approach B):

   ```nginx
   listen 8443 ssl proxy_protocol;
   listen [::]:8443 ssl proxy_protocol;
   set_real_ip_from 192.168.1.51;   # portnook's LAN IP
   real_ip_header proxy_protocol;
   ```

   Use the **same** `listen` lines on every host that answers on 8443. `set_real_ip_from` must be portnook's LAN
   IP (page **Connection** → LAN entry → LAN address), so nobody else can claim another IP.
3. portnook backend: `<NPM IP>:8443`, then turn the option on in portnook.
4. Check: the proxy host's access log (`/data/logs/proxy-host-<id>_access.log`) shows the visitor's IP.
   Your services get it in `X-Real-IP` and `X-Forwarded-For` as usual.

## nginx

Same as for NPM, in the `server` block of each public host:

```nginx
server {
    listen 443 ssl;                   # LAN, unchanged
    listen 8443 ssl proxy_protocol;   # from portnook
    server_name app.familie-muster.myaddr.tools;

    set_real_ip_from 192.168.1.51;    # portnook's LAN IP
    real_ip_header proxy_protocol;

    location / {
        proxy_pass http://192.168.1.20:8096;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

portnook backend: `<nginx IP>:8443`. This setup was tested with nginx 1.31 and portnook's header: 8443 shows the
visitor IP, 443 keeps working without header.

## Troubleshooting

| Symptom | Fix |
|---|---|
| After turning it on nothing is reachable, backend light red | The reverse proxy does not expect the header on that port: set it up as above, or turn the option off |
| nginx log: `broken header … while reading PROXY protocol` | Something connects to the PROXY port without header (e.g. a LAN client on 8443): use 443 in the LAN |
| Logs still show portnook's IP | nginx/NPM: `set_real_ip_from` is not portnook's LAN IP, or `real_ip_header proxy_protocol` is missing |
| Status shows an error at "Tunnel ports" | The port is taken by something else in the container (e.g. the WebUI port 8090) |
