# Port 443 or a dedicated port

> **Applies to:** portnook 0.27 (rc1) · [Versions](Versions)

portnook forwards the public VPN port to **one** backend: `IP:port` of your reverse proxy (wizard step 3, later
page **Connection** → **Backend**). The visitor always uses the VPN port (`:51234`); the backend port is only the
port inside your LAN. You have two choices.

| | **Port 443** (shared) | **Dedicated port** (e.g. 8443) |
|---|---|---|
| Setup | Nothing extra, the normal HTTPS listener | One more listener in the proxy (and in Docker) |
| Which hosts are reachable from outside | **Every** host of the proxy, if a visitor sends its name | Only the hosts you put on the dedicated port |
| Internal-only hosts (NAS, router, admin UIs) | Must be protected by access rules | Not on that port, not reachable |
| Works with | NPM, Zoraxy, Caddy, … | NPM (custom `listen`), Caddy, Traefik (own entrypoint); Zoraxy has one incoming port |

## Why it matters: everyone looks like portnook

The reverse proxy sees **portnook's LAN IP** as the source of every visitor from the internet. A rule such as
"allow 192.168.0.0/16" (NPM access list, Zoraxy access rule, "LAN only") therefore also lets outside visitors
in, because portnook's address is in the LAN.

And since the proxy chooses the host by name (SNI and `Host` header), a visitor who knows or guesses the name of
an internal host (`nas.home.example`) can ask for it through the VPN port.

So pick one:

### A. Port 443, with rules (simple, works everywhere)

- Backend: `<proxy IP>:443`.
- On every **internal-only** host, **deny portnook's LAN IP** (and allow your LAN). Do not rely on "LAN only".
- Set the proxy's **default site** (unknown host names) to "404" or "no response", not to a real service.
- Public hosts (`app.<name>.myaddr.tools`, …) need no special rule.

### B. Dedicated port (clean separation)

- The proxy listens on an extra port, e.g. `8443`, only for the public hosts.
- Backend: `<proxy IP>:8443`.
- Internal hosts stay on 443 only; requests on 8443 for any other name hit the default site.
- See [Nginx Proxy Manager](Nginx-Proxy-Manager#b-dedicated-port-8443) for the NPM steps.

## Same port inside and outside

The backend port has nothing to do with the URL. Outside and with the [LAN entry](Home-network-and-LAN-entry)
the URL is always `https://<sub>.<name>.myaddr.tools:<VPN port>`; portnook passes both to the backend port.

## Other notes

- **Client IPs:** logs, fail2ban and rate limits in the proxy see one IP (portnook) for all outside visitors. Do
  not ban by IP on the public hosts, or you block everyone.
- **Health check:** portnook checks the backend every 30 s with a TLS handshake (SNI = your myaddr name). The
  status light turns yellow/red if the proxy does not answer on that port.
- **HTTP/80** is not needed; Let's Encrypt uses DNS-01.
