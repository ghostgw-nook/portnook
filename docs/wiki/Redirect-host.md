# Redirect host

> **Applies to:** portnook 0.31 (rc1) · [Versions](Versions)

The VPN port changes now and then, and a URL with a port is hard to remember. A **redirect host** is a fixed
address, e.g. `https://start.example.com`, that answers with a **302** to the current
`https://<sub>.<name>.myaddr.tools:<port>`. Path and query are kept. portnook updates it on every change of exit
IP or port.

> The redirect does not hide the target: every visitor sees name and port in the `Location` header.

Page **Redirect**. Two providers:

## Cloudflare

1. The entry domain is at Cloudflare. For `start.example.com` add a **proxied** DNS record (orange cloud), e.g.
   `AAAA 100::`.
2. API token: **My Profile → API Tokens → Create Token**, permission **Zone → Single Redirect → Edit**, only for
   that zone (with a zone ID no other permission is needed; with a domain name also **Zone → Zone → Read**).
3. In portnook: provider Cloudflare, entry host, target subname (e.g. `app`), zone and token, **Save and
   run**. portnook creates one rule "portnook redirect start.example.com" and only updates that one.

## Round robin (share clients between both tunnels)

**Redirect** → **Mode** → **Share clients (round robin)**: the clients are spread by their IP over the active and
the standby tunnel; one client always gets the same tunnel. Each tunnel needs its own connection name (see
[VPN profiles and failover](VPN-profiles-and-failover)); if the standby fails, it is taken out until it is ready
again.

- **Script:** the `.htaccess` / `index.php` gets one target per tunnel.
- **Cloudflare (0.31):** a redirect rule has only one target, so portnook uploads a **Worker** named
  `portnook-redirect` instead and adds one **route** per entry host (`start.example.com/*`, also `*.host/*`). It
  removes its own redirect rules, as Cloudflare would run them before the Worker. Routes of other Workers are left
  alone; a route on the same host that belongs to another Worker is reported as an error.
  The token needs in addition **Zone → Zone → Read**, **Zone → Workers Routes → Edit** and
  **Account → Workers Scripts → Edit**. The free Workers plan is enough for home use (100 000 requests a day).
- Back to **Only active tunnel (failover)**: portnook removes its Worker routes and sets the redirect rule again.
  The Worker script itself stays in your account, unused; delete it there if you like.

## Script (e.g. web hosting via SSH)

1. Provider **Script**, where to write: ".htaccess via SSH" (or "index.php via SSH"), SSH user, host, port and web
   folder (e.g. `httpdocs`). portnook generates the script; the preview shows it.
2. **Create new key** and add the public key at your hosting (Plesk: SSH keys / SSH access).
3. Entry host and target subname, **Save and run**. The script writes a `.htaccess` with a 302 rewrite;
   `/.well-known/` is left out so the hosting can renew its own certificate for the entry host.
   **Test connection** writes, reads and deletes a test file first.

## More rules

| Entry | Target | Result |
|---|---|---|
| `media.example.com` | `tv` | `https://tv.<name>.myaddr.tools:<port>` |
| `*.media.example.com` | `*` | `x.media.example.com` → `https://x.<name>.myaddr.tools:<port>` |

`*.` rules work with the script, and with Cloudflare only in round robin (Worker). The entry host itself needs a certificate (wildcard for `*.` rules).

## Apps

Some apps remember the redirect target instead of the entry address. After a port change, enter
the entry address there again.
