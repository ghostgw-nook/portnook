# Redirect host

> **Applies to:** portnook 0.34 (rc1) · [Versions](Versions)

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

## Page layout (0.34)

- **General:** mode (failover or round robin), status code, fixed port, SSH key for the scripts.
- **Start URLs:** one collapsible section **per entry name** with all its subdomains (empty = the name itself,
  `*` = any subdomain, e.g. `app`; **Add subdomain** for more). Collapsed it shows a light, the name, the number of
  entries and the provider. The first section is the main entry. **Every name with the use "entry"** on the page
  **Names** gets a section automatically (marked "new from Names"); **Save and run** takes it over. Your own
  hosts (e.g. `start.example.com`) with **Add start URL**.
- **Provider at the bottom of each section:** an own one with a name of your choice (e.g. "Web hosting Plesk")
  and its type and access data, or **Same as …** another section's provider. Names on the same web hosting use
  "Same as", so they share one `.htaccess`.

## Further providers (0.32)

Each section can use its own provider: Cloudflare (zone and token, e.g. a second account), `.htaccess` or
`index.php` via SSH (another web hosting), or your own script. The main entry always goes via provider 1 (the
one in the first section). Several names on the same web hosting share one provider ("Same as"), or one
overwrites the other's `.htaccess`.

| Entry | Via | Example |
|---|---|---|
| `start.example.com` (main) | Provider 1: Cloudflare | redirect rule in the zone `example.com` |
| `start.example.org` | Provider 2: `.htaccess` via SSH | file on another web hosting |
| `media.example.net` | Provider 3: Cloudflare | second Cloudflare account |

- Each provider runs on its own with its own state and retry; if one fails, the others are still updated. The
  overview shows each one.
- All scripts use the same SSH key (card **Script**); add its public key at every hosting.
- In round robin a further Cloudflare provider gets its own Worker `portnook-redirect-<id>`, so two in one
  account don't overwrite each other.

## Apps

Some apps remember the redirect target instead of the entry address. After a port change, enter
the entry address there again.
