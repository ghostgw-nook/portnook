"""portnook: VPN tunnel (Proton with NAT-PMP or fixed ports) with port forward, DNAT to the reverse proxy, myaddr.tools DDNS,
Let's Encrypt wildcard certificate with delivery to NPM/Zoraxy, redirect host, web UI."""

import os

__version__ = os.environ.get("PF_VERSION", "0.10.0")
