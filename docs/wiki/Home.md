# portnook wiki

> **Applies to:** portnook 0.27 (rc1) · [Versions](Versions)

**portnook** makes any web service at home (anything with a web UI or HTTP API) reachable from anywhere, without an open port on
your router, under your own name and with a valid certificate. It is one Docker container next to your reverse
proxy.

This wiki explains how it works and how to set it up. The README is available in
[German](https://github.com/ghostgw-nook/portnook/blob/main/README.md) and
[English](https://github.com/ghostgw-nook/portnook/blob/main/README.en.md); the detailed German guide is
[docs/installation.md](https://github.com/ghostgw-nook/portnook/blob/main/docs/installation.md).

## Start here

1. [How it works](How-it-works): the path of a request, from the visitor to your web service.
2. [Installation](Installation): start the container and run the wizard.
3. Reverse proxy: decide between [port 443 or a dedicated port](Reverse-proxy-port), then follow
   [Nginx Proxy Manager](Nginx-Proxy-Manager) or [Zoraxy](Zoraxy).
4. [Names and certificate](Names-and-certificate): myaddr.tools name, DDNS and Let's Encrypt.

## Then, as needed

- [VPN profiles and failover](VPN-profiles-and-failover): several VPN accounts, standby tunnel, fixed priority.
- [Redirect host](Redirect-host): one fixed, easy address that always points to the current port.
- [Home network and LAN entry](Home-network-and-LAN-entry): the same URL at home, without the VPN detour.
- [Troubleshooting](Troubleshooting).

## Language of the web UI

The web UI is German by default. **System** → **Display** → **Language** switches to **English** (or Auto, which
follows the browser). The choice is stored per browser.
