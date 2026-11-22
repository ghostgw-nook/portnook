# Zoraxy

> **Applies to:** portnook 0.27 (rc1) · [Versions](Versions)

portnook writes its certificate as files into Zoraxy's certificate folder. Zoraxy picks a certificate by file
name and reads the files on each connection, so renewals need no restart (only the first time, see below).

## 1. Mount the certificate folder

portnook needs Zoraxy's folder `/opt/zoraxy/config/conf/certs`. Add it to the portnook container:

```yaml
volumes:
  - ./data:/data
  - /path/to/zoraxy/config/conf/certs:/zoraxy-certs
```

On Unraid, if Zoraxy maps `/opt/zoraxy/config` to `/mnt/user/appdata/zoraxy/config`, the left side is
`/mnt/user/appdata/zoraxy/config/conf/certs`. Recreate the container afterwards.

## 2. Delivery in portnook

Page **Certificate** → **Deliver automatically** → **Zoraxy**: folder `/zoraxy-certs`, **Save**, **Deliver now**.

portnook writes one file pair per name, e.g. `<name>.myaddr.tools.pem` (full chain) and
`<name>.myaddr.tools.key`, and also for further endpoint names.

**Restart Zoraxy once** after the first delivery, so it also uses the wildcard for subnames. Later renewals are
picked up without a restart.

## 3. Proxy rules (HTTP proxy)

For each service a new proxy rule:

- **Matching keyword / domain:** `app.<name>.myaddr.tools` (add further endpoint names as aliases if you use
  one name per VPN profile),
- **Target:** `192.168.1.30:8080` (the service), TLS to target off for plain HTTP backends,
- in **TLS / SSL certificates** you should see the portnook certificate listed.

## 4. Backend port

Read [Port 443 or a dedicated port](Reverse-proxy-port) first.

Zoraxy serves all HTTP proxy rules on its one **incoming port** (page **Status**, usually 443 with "Use TLS to
serve proxy request" on). So with Zoraxy use approach **A**:

- portnook backend: `<Zoraxy IP>:<incoming port>` (usually 443).
- Internal-only rules: **Access Control** → create a rule that **blacklists** `<portnook LAN IP>` and assign it
  to those rules. A whitelist of "LAN" alone does not help, because portnook is in the LAN.
- **Default site** (page **Status** → default site / fallback): "Not found" or "Blank", not a real service.

If you need strict separation, run the public hosts on a second reverse proxy (e.g. NPM with a
[dedicated port](Nginx-Proxy-Manager#b-dedicated-port-8443)) and point portnook's backend to it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| portnook: "folder does not exist" | Volume `…/conf/certs:/zoraxy-certs` missing; recreate the container |
| Subnames show the wrong certificate | Restart Zoraxy once after the first delivery |
| Status: backend red | Backend port in portnook is not Zoraxy's incoming port |

> Menu names can differ between Zoraxy versions. The file delivery is tested in CI against a folder; Zoraxy
> itself is not tested live.
