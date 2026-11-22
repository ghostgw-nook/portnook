# Installation

> **Applies to:** portnook 0.27 (rc1) · [Versions](Versions)

## Requirements

- A Docker host at home with Linux ≥ 5.6 (WireGuard in the kernel): Unraid, Debian, Ubuntu, Synology Container
  Manager, …
- A reverse proxy in the LAN that speaks TLS: [Nginx Proxy Manager](Nginx-Proxy-Manager), [Zoraxy](Zoraxy),
  Caddy, …
- A VPN with port forwarding:
  - **Proton VPN** with a plan that allows port forwarding: in the Proton account under **Downloads → WireGuard**
    create a config with **NAT-PMP (Port Forwarding)** for a P2P server.
  - or a provider with **fixed ports** (e.g. AirVPN): open a port in your account and create a WireGuard file.
- Optional: a name at [myaddr.tools](https://myaddr.tools). Keep the key it shows; it is shown only once.

## 1. Start the container

```bash
mkdir portnook && cd portnook
curl -fsSLO https://raw.githubusercontent.com/ghostgw-nook/portnook/main/agent/docker-compose.yml
echo "PF_BIND=192.168.1.20" > .env   # LAN IP of the Docker host
docker compose up -d
```

Without `PF_BIND` the web UI is only reachable on the host itself (`127.0.0.1`). For Zoraxy also mount its
certificate folder, see [Zoraxy](Zoraxy).

### Unraid

Use `agent/compose.unraid.yaml` with the **Docker Compose Manager** plugin: create a stack `portnook`, paste the
file, set `PF_BIND` to the Unraid LAN IP, **Compose Up**. Data lives in `/mnt/user/appdata/portnook`.

**Without the Compose plugin:** copy [`agent/unraid/portnook.xml`](https://github.com/ghostgw-nook/portnook/blob/main/agent/unraid/portnook.xml)
to `/boot/config/plugins/dockerMan/templates-user/my-portnook.xml` (flash share or `nano` in the terminal), then
**Docker** → **Add Container** → template `portnook`. It sets `NET_ADMIN`, the sysctls, the Watchtower label and
`/data` for you; leave **Zoraxy certificates** empty if you do not use Zoraxy.

For the [LAN entry](Home-network-and-LAN-entry) the container needs its own LAN IP (network "Custom: br0" with a
fixed IP) instead of the bridge network.

## 2. Wizard

Open `http://<PF_BIND>:8090`.

1. **Password** (at least 8 characters). It protects the web UI.
2. **VPN:** upload or paste the WireGuard file, **Save and test**. portnook builds `wg0`, waits for the
   handshake and reads exit IP and port. `DNS`, IPv6 and script lines (`PostUp`, …) are removed. For a provider
   with fixed ports, enter the ports (several with commas).
3. **Backend:** IP and TLS port of your reverse proxy, e.g. `192.168.1.10:443`. Which port to use:
   [Port 443 or a dedicated port](Reverse-proxy-port). Also the **LAN networks** (default: all private networks);
   replies to them never go into the tunnel.
4. **Summary.** The status page now shows the port, e.g. `51234`.

## 3. Next steps

1. [Names and certificate](Names-and-certificate): name, key, certificate.
2. Certificate delivery and proxy hosts: [Nginx Proxy Manager](Nginx-Proxy-Manager) or [Zoraxy](Zoraxy).
3. Optional: [Redirect host](Redirect-host), [VPN profiles and failover](VPN-profiles-and-failover),
   push notifications (Gotify/ntfy, page **System**).

## Updates and backup

```bash
docker compose pull && docker compose up -d
```

The compose file sets `com.centurylinklabs.watchtower.enable=false`, so Watchtower does not restart portnook
(a restart can change the Proton port). Back up the `./data` folder; it holds secrets, never commit it.
