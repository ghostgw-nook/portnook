# Home network and LAN entry

> **Applies to:** portnook 0.27 (rc1) · [Versions](Versions)

Goal: the same URL `https://<sub>.<name>.myaddr.tools:<port>` works everywhere, but devices at home (and in your
home VPN) go **directly** to the reverse proxy, not through the VPN provider.

## LAN entry

portnook also accepts the current VPN port on its **own LAN IP** and passes it to the same backend as the tunnel.
When the port changes, the LAN entry follows. It only accepts connections from the LAN; nothing is opened to the
internet. Status → **LAN entry** shows address and port and can switch it off.

Requirements:

- portnook has its **own LAN IP** (Docker network `ipvlan`/`macvlan`, Unraid "Custom: br0" with a fixed IP). In
  the bridge network the container IP is only reachable from the Docker host. The Docker host itself cannot reach
  the container in these networks (Docker limitation).
- The reverse proxy accepts connections from portnook's IP.

## Home DNS (example: Technitium)

DNS has no ports: the port stays in the URL, only the IP differs at home.

1. **Zones** → **Add Zone** → **Primary Zone** `<name>.myaddr.tools`.
2. Two A records to portnook's LAN IP: `@` and `*`.
3. For the [redirect host](Redirect-host) (e.g. `start.example.com`) an A record to the **reverse proxy's** LAN
   IP; at home it is served directly on 443, without redirect (the proxy needs a host and certificate for it).

Let's Encrypt is not affected; it checks the public DNS of myaddr.tools.

**Home VPN** (WireGuard, Tailscale, …): give clients the home DNS (`DNS = <Technitium IP>`, Tailscale "Override
local DNS"), otherwise they get the exit IP and go through the VPN provider.

| Where is the device? | DNS answer | Path |
|---|---|---|
| LAN | portnook LAN IP | portnook (LAN entry) → reverse proxy |
| Home VPN with home DNS | portnook LAN IP | home VPN → portnook → reverse proxy |
| Outside | exit IP | VPN provider → portnook (wg0) → reverse proxy |
