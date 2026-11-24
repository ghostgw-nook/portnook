# Names and certificate

> **Applies to:** portnook 0.35 (rc1) · [Versions](Versions)

## myaddr.tools name

1. At [myaddr.tools](https://myaddr.tools) reserve a name (e.g. `family-example`) and keep the key.
2. In portnook, page **Names**: name, domain (`myaddr.tools`, `myaddr.dev` or `myaddr.io`), use and key,
   **Save**. The key is stored with mode 600 and never shown again.

**IP for the A record:** by default the **VPN exit IP**, on every change and at least every 30 days (myaddr
disables records after 90 days without an update and deletes names after 120). Optional:

- **Fallback IP**, sent while the exit IP is unknown. Without one, nothing is sent and the old record stays.
- **Manual IP**, always sent.

Your home IP is never sent (no `ip=self`). All subnames (`app.<name>…`, `cloud.<name>…`) point to the same
IP, so you add services only in the reverse proxy.

## Several names and the "Use" column

All names are in one list on the **Names** page, sorted: entry names first, then by use, then alphabetically.

| Use | Points to |
|---|---|
| **Entry / rewrite** | A fixed IP, e.g. your web hosting that serves the [redirect](Redirect-host), a LAN IP or `127.0.0.1` (keeps an unused name alive). Or a **host name** like a CNAME (e.g. `web.example.com`): myaddr.tools has no CNAME records, so portnook looks up its IPv4 every 5 minutes and updates the A record when it changes. |
| **Connection / endpoint** | The VPN exit IP. With a **profile**, the exit IP of that VPN profile. |

A name with **several profiles** points to the active one of them, else to the one ready as standby. This lets
you keep, say, one name per VPN account and switch without waiting for DNS, see
[VPN profiles and failover](VPN-profiles-and-failover).

## Let's Encrypt certificate

Page **Certificate** → **Let's Encrypt certificate**:

1. Choose **Staging (test)**, accept the terms, optional e-mail, **Get certificate now**. portnook puts the
   DNS-01 values at myaddr.tools, waits (default 60 s) and lets Let's Encrypt check.
2. If that works, switch to **Production** and get it again. Staging certificates are not trusted but have
   generous rate limits.

The certificate covers every ticked name with a key: `<name>.myaddr.tools` and `*.<name>.myaddr.tools` each.
With **Renew automatically** portnook renews at 30 days left and delivers it at once.

## Delivery

- [Nginx Proxy Manager](Nginx-Proxy-Manager): upload as a custom certificate.
- [Zoraxy](Zoraxy): files in its certificate folder.
- **Download** (`fullchain.pem`, `privkey.pem`, ZIP) or **Fetch by script (token)** with
  [`docs/pull-cert.sh`](https://github.com/ghostgw-nook/portnook/blob/main/docs/pull-cert.sh):

  ```bash
  echo '<token>' > /root/.pf-token && chmod 600 /root/.pf-token
  PF_AGENT=http://192.168.1.20:8090 PF_TOKEN_FILE=/root/.pf-token DEST=/etc/ssl/pf \
    RELOAD="systemctl reload nginx" ./pull-cert.sh
  ```
