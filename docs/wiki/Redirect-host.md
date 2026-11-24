# Redirect host

> **Applies to:** portnook 0.39 (rc1) · [Versions](Versions)

The VPN port changes now and then, and a URL with a port is hard to remember. A **redirect host** is a fixed
address, e.g. `https://start.example.com`, that answers with a **302** to the current
`https://<sub>.<name>.myaddr.tools:<port>`. Path and query are kept. portnook updates it on every change of exit
IP or port.

> The redirect does not hide the target: every visitor sees name and port in the `Location` header.

Page **Redirect**. Two providers:

## Cloudflare

Cloudflare can redirect for a domain that is **fully** at Cloudflare (its name servers point to Cloudflare), or,
without any domain, on the free **workers.dev** address of your account (see below). Pointing a record of a domain
elsewhere to a Cloudflare IP does not work: Cloudflare does not know the host then (error 1000/1001).

### 1. Domain at Cloudflare (skip for workers.dev)

1. Dashboard → **Add a domain** (also "Connect a domain"), plan **Free**. Cloudflare shows two name servers,
   e.g. `name.ns.cloudflare.com`; enter them **at the registrar of the domain** (not in portnook). Check the
   imported records (e.g. MX for mail) first. After a while the domain is **Active**.
2. **DNS → Records → Add record**: type `AAAA`, name `start`, IPv6 `100::`, **proxy on** (orange cloud). `100::`
   is only a placeholder: Cloudflare answers with the redirect itself.

### 2. API token

Open **https://dash.cloudflare.com/profile/api-tokens** (in the new dashboard: profile menu → **Settings** →
**API Tokens**) → **Create Token** → **Start from scratch** / **Create Custom Token** (not a template). Add:

| Scope | Permission | Level | For |
|---|---|---|---|
| Zone | Single Redirect (also shown as "Dynamic Redirect") | Edit | own domain |
| Zone | Zone | Read | round robin |
| Zone | Workers Routes | Edit | round robin |
| Account | Workers Scripts | Edit | round robin and workers.dev |

Resources: **Zone** = only your domain, **Account** = your account. Expiration "1 year" is safer than none.
Copy the token at once, it is shown only once.

### 3. In portnook

**Redirect** → section of the start URL (or **Add start URL**, entry host e.g. `start.example.com`) → provider
**Cloudflare**, zone (domain or zone ID, from the domain's **Overview**, box "API") and token → **Save and run**.
In failover portnook creates one rule "portnook redirect start.example.com" per entry and only updates those.

### Without a domain: workers.dev (0.36)

Every Cloudflare account has a free name below `workers.dev`. Set it once: **Workers & Pages** → your
subdomain (e.g. `familie-muster` → `familie-muster.workers.dev`). Then enter the start URL
`<worker>.<account>.workers.dev`, e.g. `tv.familie-muster.workers.dev`, with provider Cloudflare and an **empty
zone**. portnook uploads a Worker named `tv` and switches it on at workers.dev; no route and no own domain are
needed. The token needs only **Account → Workers Scripts → Edit**. Only that exact address works (no `app.` or
`*.` in front). It works in failover and in round robin.

## Round robin (share clients between the tunnels)

**Redirect** → **Mode** → **Share clients (round robin)**: the clients are spread by their IP over the active
tunnel and the reserves (up to 4 tunnels since 0.37); one client always gets the same tunnel. Each tunnel needs its own connection name (see
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

How the IP picks the tunnel: `index.php` and the Worker use a hash of the whole address (even shares).
`.htaccess` cannot calculate, it only looks at the last character of the address; with IPv4 that is a digit, so
with 3 tunnels the shares are about 40/30/30 %, with 4 about 30/30/20/20 %.

### Even out by load (0.39)

**Even out by load** (under the mode, round robin only): every 30 minutes portnook compares the new connections
per tunnel (see the tunnel tiles) with each tunnel's share. A tunnel that got clearly more than its share (1.5×)
gives one step of weight away; otherwise the one far below (0.67×) gets one more. Weights go from 1 to 4, one
step per round and only with at least 30 new connections in the period. **Shares** under the switch shows the
current split. A change moves part of the clients to another tunnel, where they may have to log in again; that is
why it changes slowly. Switching it off goes back to equal shares.

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
