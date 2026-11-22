"""Single egress policy for every outgoing HTTP request (owner decision 2026-11-18, 0.10.1).

Without a working VPN tunnel the agent contacts no internet service at all: nothing may leave through the
home line (``eth0``). Allowed then are LAN targets only, i.e. private addresses (NPM, a LAN push server,
test stand-ins). Internet requests wait (DDNS, certificate, redirect and push keep the latest pending state)
and are sent through ``wg0`` once a tunnel is up again.

* ``Route`` is passed as ``device`` to ``httpc.request``; it decides per resolved address and raises
  ``httpc.EgressBlocked`` before any connection is made.
* ``internet`` routes (myaddr.tools, ACME, Cloudflare, IP echo, internet push): ``wg0`` while the tunnel is
  up, else only private addresses (via ``eth0``).
* ``lan`` routes (NPM, push): private addresses via ``eth0`` (never through the tunnel); other addresses only
  through ``wg0`` while the tunnel is up.
* ``push`` routes (owner decision 2026-11-19, 0.18.0): push messages need not hide the home IP. Private
  addresses as ``lan``; every other address straight through ``eth0`` with the socket mark ``PUSH_MARK``,
  with or without a tunnel (so the "all VPNs down" alarm reaches ntfy.sh too).
* Defence in depth: the ``PF_OUT`` iptables chain (``net.py``) rejects new connections from the container to
  non-private addresses through ``eth0`` (except the WireGuard endpoints, the DNS servers and sockets with
  ``PUSH_MARK``).
"""

import ipaddress
import urllib.parse

from . import httpc

WG_IF = "wg0"  # default; the active tunnel is ``agent.active_if`` (0.19.0: wg0 or wg1)
LAN_IF = "eth0"
PUSH_MARK = 0x5046  # socket mark of direct push connections, accepted by the PF_OUT firewall chain
HANDSHAKE_FRESH = 180
# "private" = LAN: RFC 1918, loopback, link-local
LAN_NETS = tuple(ipaddress.IPv4Network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"))
BLOCKED = "Kein VPN-Tunnel aktiv: Anfrage an %s zurückgehalten (nie über die Heimleitung)"


def is_lan(ip):
    try:
        addr = ipaddress.IPv4Address(str(ip))
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(addr in n for n in LAN_NETS)


class Route:
    """Route policy for ``httpc.request(device=...)``: ``kind`` is ``internet``, ``lan`` or ``push``."""

    def __init__(self, egress, kind):
        self.egress = egress
        self.kind = kind

    def __call__(self, host, ip):
        return self.egress.device_for(host, ip, self.kind)

    def __repr__(self):
        return "<route %s>" % self.kind


class Egress:
    def __init__(self, agent, resolve=None):
        self.agent = agent
        self._resolve = resolve  # tests: replaces DNS

    def resolve(self, host):
        if self._resolve:
            return self._resolve(host)
        from .agent import resolve_ipv4
        return resolve_ipv4(host)

    def wg_ready(self):
        """A VPN is on and wg0 exists: a socket bound to wg0 can never leave through eth0."""
        a = self.agent
        return a._proton_on() and a.net.link_exists(a.active_if)

    def tunnel_up(self):
        """The tunnel works: VPN on, wg0 up, fresh handshake, failover not in "all profiles failed"."""
        a = self.agent
        if not a._proton_on() or a.failover.rt.get("all_down"):
            return False
        if not a.net.link_exists(a.active_if):
            return False
        age = a.handshake_age()
        return age is not None and age < HANDSHAKE_FRESH

    def device_for(self, host, ip, kind="internet"):
        vpn = self.agent._proton_on()
        if kind == "push" and not is_lan(ip):
            return (LAN_IF, PUSH_MARK)
        if kind == "internet" and vpn and self.wg_ready():
            return self.agent.active_if
        if is_lan(ip):
            return LAN_IF if vpn else None
        if vpn and self.wg_ready():
            return self.agent.active_if
        raise httpc.EgressBlocked(BLOCKED % host)

    def route(self, kind="internet"):
        return Route(self, kind)

    def host_is_lan(self, url):
        """All addresses of the URL's host are private (LAN)."""
        try:
            host = urllib.parse.urlsplit(url).hostname or ""
        except ValueError:
            return False
        ips = self.resolve(host) if host else []
        return bool(ips) and all(is_lan(i) for i in ips)

    def allowed(self, url):
        """May a request to ``url`` be sent now? Internet only with a working tunnel, LAN always.

        Callers queue the update (latest state) when this is false; ``Route`` enforces it anyway.
        """
        return self.tunnel_up() or self.host_is_lan(url)
