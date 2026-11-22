# Nginx Proxy Manager

> **Applies to:** portnook 0.27 (rc1) · [Versions](Versions)

portnook uploads its certificate to NPM as a **Custom** certificate and replaces that same certificate on every
renewal. Your proxy hosts keep pointing to it.

## 1. User for portnook

In NPM under **Users** add a user for portnook:

- **no 2FA** (portnook cannot answer a 2FA prompt),
- permission **Certificates: Manage**; everything else may be "Hidden".

## 2. Delivery in portnook

Page **Certificate** → **Deliver automatically** → **Nginx Proxy Manager**:

- NPM address with the admin port, e.g. `http://192.168.1.10:81` (must be a private LAN address),
- e-mail and password of that user,
- certificate name (free text, default `portnook <name>.myaddr.tools`).

**Save**, then **Deliver now**. The certificate now appears under **SSL Certificates**.

## 3. Proxy hosts

For each service a proxy host, e.g. `app.<name>.myaddr.tools`:

- **Details:** scheme `http`, forward host/IP and port of the service (e.g. `192.168.1.30:8080`),
  **Websockets support** on.
- **SSL:** choose the portnook certificate. "Force SSL" and HTTP/2 may be on.
- If the certificate also covers further endpoint names (one per VPN profile), add them as more domain names on
  the same proxy host.

## 4. Backend port

Read [Port 443 or a dedicated port](Reverse-proxy-port) first.

### A. Port 443

- portnook backend: `<NPM IP>:443`.
- Internal hosts: **Access Lists** → add a list with **deny** `<portnook LAN IP>` above **allow**
  `192.168.0.0/16` (your LAN), and assign it to those hosts.
- **Settings** → **Default Site** → "404 Page" or "No Response".

### B. Dedicated port 8443

1. Publish the extra port on the NPM container, e.g. in its compose file:

   ```yaml
   ports:
     - "80:80"
     - "81:81"
     - "443:443"
     - "8443:8443"
   ```

2. On each **public** proxy host, tab **Advanced** → **Custom Nginx Configuration**:

   ```nginx
   listen 8443 ssl;
   listen [::]:8443 ssl;
   ```

   The host then answers on 443 and on 8443 with the same certificate. Internal hosts get no such line and stay
   on 443 only.
3. portnook backend: `<NPM IP>:8443`.
4. **Default Site** to "404 Page" or "No Response", so any other name on 8443 gets nothing.

Check from a LAN machine:

```bash
curl -sk --resolve app.<name>.myaddr.tools:8443:<NPM IP> https://app.<name>.myaddr.tools:8443/ -o /dev/null -w '%{http_code}\n'
```

> The `listen` lines are standard nginx and not tested live with every NPM version. If NPM refuses to save,
> check its log for a duplicate `listen` and use approach A.

## Troubleshooting

| Symptom | Fix |
|---|---|
| portnook: "2FA" | Use a separate NPM user without 2FA |
| portnook: "not a private LAN address" | NPM address must be in 10.x, 172.16–31.x or 192.168.x |
| Browser shows the NPM default certificate | Choose the portnook certificate on the proxy host (tab SSL) |
| Works on 443, not via the VPN port | Backend port in portnook does not match the NPM listener |
