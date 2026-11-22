"""Network plumbing inside the agent container: routes, the VPN tunnels (wg0, wg1), policy routing, iptables.

All commands go through ``sysrun.run`` with argument lists. Secrets are
written to a mode-600 file (``/etc/wireguard/wg0.conf``), never passed as
arguments.
"""

import ipaddress
import os

from . import parsers, sysrun
from .log import log

LAN_IF = "eth0"
PROTON_IF = "wg0"  # first tunnel interface; the active tunnel may also run on wg1 (0.19.0)
TUNNEL_IFS = ("wg0", "wg1")
# 0.19.0, two tunnels at once (active + standby): wg-quick runs with "Table = off", the routing is ours.
# Per interface: the fwmark of its WireGuard socket, its routing table and the mark of connections that came
# in through it (replies go back through the same tunnel).
TUNNEL_FWMARK = {"wg0": "0xca6c", "wg1": "0xca6d"}
TUNNEL_TABLE = {"wg0": 51820, "wg1": 51821}
TUNNEL_CONNMARK = {"wg0": "0x5100", "wg1": "0x5101"}
RULE_PRIO = 10000  # our ip rules: 10000..10099

# (table, builtin chain, own chain)
CHAINS = [
    ("nat", "PREROUTING", "PF_PRE"),
    ("nat", "POSTROUTING", "PF_POST"),
    ("mangle", "PREROUTING", "PF_MARK"),
    ("mangle", "FORWARD", "PF_MSS"),
    ("filter", "INPUT", "PF_IN"),
    ("filter", "FORWARD", "PF_FWD"),
    ("filter", "OUTPUT", "PF_OUT"),
]
# private (LAN) destinations the container may reach through eth0 (same list as app.egress.LAN_NETS)
LAN_DESTS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
PUSH_FWMARK = "0x5046"  # app.egress.PUSH_MARK
WG_FWMARK = TUNNEL_FWMARK["wg0"]  # fwmark of the WireGuard socket of wg0 (the value wg-quick used before 0.19.0)


class NetError(Exception):
    pass


def split_out(nets, exclude):
    """LAN networks minus other networks (e.g. 10.0.0.0/8 minus Proton 10.2.0.0/24). The routes via eth0 sit in
    the main table, which wins over the wg-quick table, so a covering LAN net would send the NAT-PMP gateway and
    the tunnel addresses to the LAN."""
    out = list(nets)
    for ex in exclude:
        nxt = []
        for n in out:
            if not n.overlaps(ex):
                nxt.append(n)
            elif ex.subnet_of(n) and ex != n:
                nxt.extend(sorted(n.address_exclude(ex)))
        out = nxt
    return out


class Net:
    def __init__(self, wg_dir="/etc/wireguard"):
        self.wg_dir = wg_dir
        self.gateway = ""
        self.routes = []  # networks we added via eth0
        self.policy = None  # (active interface, tunnels) the ip rules were last set for

    # -- helpers ------------------------------------------------------
    @staticmethod
    def _run(args, **kw):
        return sysrun.run(args, **kw)

    def link_exists(self, name):
        return self._run(["ip", "link", "show", "dev", name], check=False).returncode == 0

    def default_gateway(self):
        """IPv4 default gateway on eth0. Cached: wg-quick never touches the main table default."""
        if not self.gateway:
            out = self._run(["ip", "-4", "route", "show", "default"]).stdout
            self.gateway = parsers.default_gateway(out, LAN_IF)
            if not self.gateway:
                raise NetError("no IPv4 default route on %s" % LAN_IF)
        return self.gateway

    def lan_if_networks(self):
        out = self._run(["ip", "-4", "-o", "addr", "show", "dev", LAN_IF], check=False).stdout
        return parsers.interface_networks(out)

    def lan_if_addresses(self):
        """Own IPv4 addresses on eth0 (the LAN entry listens on these)."""
        out = self._run(["ip", "-4", "-o", "addr", "show", "dev", LAN_IF], check=False).stdout
        return parsers.interface_addresses(out)

    def link_mtu(self, name):
        """Current MTU of a link, 0 if unknown."""
        out = self._run(["ip", "-o", "link", "show", "dev", name], check=False).stdout or ""
        parts = out.split()
        try:
            return int(parts[parts.index("mtu") + 1])
        except (ValueError, IndexError):
            return 0

    def wg_dump(self, iface):
        proc = self._run(["wg", "show", iface, "dump"], check=False)
        if proc.returncode != 0:
            return None
        return parsers.wg_dump(proc.stdout)

    # -- routes -------------------------------------------------------
    def apply_routes(self, lan_nets, backend_ip=None, extra_hosts=(), exclude=()):
        """LAN networks and the backend /32 via the eth0 gateway.

        Must run before ``wg-quick up`` so replies to the LAN (UI, backend)
        never go into wg0. Routes that are no longer wanted are removed.
        """
        gw = self.default_gateway()
        connected = self.lan_if_networks()
        nets = [ipaddress.IPv4Network(n) for n in lan_nets]
        # directly connected nets (docker bridge) are reachable already: never replace or delete the connected
        # route, the rest of a covering LAN net still gets a route; the tunnel's own nets stay out (split_out)
        wanted = [str(n) for n in split_out(nets, list(connected) + [ipaddress.IPv4Network(e) for e in exclude])]
        for host in ([backend_ip] if backend_ip else []) + list(extra_hosts):
            addr = ipaddress.IPv4Address(str(host))
            if any(addr in n for n in nets + connected):
                continue
            if str(addr) + "/32" not in wanted:
                wanted.append(str(addr) + "/32")
        for old in self.routes:
            if old not in wanted:
                self._run(["ip", "-4", "route", "del", old, "via", gw, "dev", LAN_IF], check=False)
        for net in wanted:
            self._run(["ip", "-4", "route", "replace", net, "via", gw, "dev", LAN_IF])
        self.routes = wanted
        return wanted

    def clear_routes(self):
        if not self.routes:
            return
        gw = self.gateway
        for net in self.routes:
            args = ["ip", "-4", "route", "del", net] + (["via", gw] if gw else []) + ["dev", LAN_IF]
            self._run(args, check=False)
        self.routes = []

    # -- tunnels (wg0, wg1) -------------------------------------------
    def conf_path(self, iface=PROTON_IF):
        return os.path.join(self.wg_dir, iface + ".conf")

    @property
    def proton_conf_path(self):
        return self.conf_path(PROTON_IF)

    @staticmethod
    def tunnel_conf(conf_text, iface):
        """The config wg-quick gets: ``Table = off`` and the interface's socket mark; the routing is ours."""
        if iface not in TUNNEL_IFS:
            raise ValueError("invalid tunnel %r" % (iface,))
        out = []
        for line in conf_text.splitlines():
            key = line.split("=", 1)[0].strip().lower()
            if key in ("table", "fwmark"):
                continue
            out.append(line)
            if line.strip().lower() == "[interface]":
                out += ["Table = off", "FwMark = %s" % TUNNEL_FWMARK[iface]]
        return "\n".join(out) + "\n"

    def tunnel_up(self, iface, conf_text):
        """(Re)build ``iface`` with ``conf_text`` and its routing table (default route through it)."""
        os.makedirs(self.wg_dir, mode=0o700, exist_ok=True)
        path = self.conf_path(iface)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(self.tunnel_conf(conf_text, iface))
        os.chmod(path, 0o600)
        if self.link_exists(iface):
            self._run(["wg-quick", "down", iface], check=False)
        self._run(["wg-quick", "up", iface], timeout=45)
        table = str(TUNNEL_TABLE[iface])
        self._run(["ip", "-4", "route", "replace", "default", "dev", iface, "table", table])
        # kill switch: without the tunnel its table answers "unreachable" instead of falling through to eth0
        self._run(["ip", "-4", "route", "replace", "unreachable", "default", "metric", "4096", "table", table])
        self._loose_rp_filter(iface)
        log("%s up", iface)

    @staticmethod
    def _loose_rp_filter(iface, root="/proc/sys/net/ipv4/conf"):
        """Inbound connections on the standby tunnel come from addresses routed through the other one: loose
        reverse path check on the tunnel (the effective value is the higher of "all" and the interface)."""
        try:
            with open(os.path.join(root, iface, "rp_filter"), "w") as fh:
                fh.write("2")
        except OSError:
            pass

    def tunnel_down(self, iface):
        if self.link_exists(iface):
            if os.path.exists(self.conf_path(iface)):
                self._run(["wg-quick", "down", iface], check=False, timeout=45)
            if self.link_exists(iface):
                self._run(["ip", "link", "del", "dev", iface], check=False)
            log("%s down", iface)
        try:
            os.unlink(self.conf_path(iface))
        except FileNotFoundError:
            pass

    def proton_up(self, conf_text, iface=PROTON_IF):
        self.tunnel_up(iface, conf_text)

    def proton_down(self, iface=None):
        for name in ([iface] if iface else TUNNEL_IFS):
            self.tunnel_down(name)

    @staticmethod
    def policy_rules(active, tunnels):
        """ip rules (priority, selector) for the tunnels in ``tunnels`` with ``active`` carrying the traffic.

        * the WireGuard sockets (their fwmark) use the main table, i.e. eth0;
        * replies of connections that came in through a tunnel go back through it (connmark restored on
          eth0 -> fwmark), before the main table: both tunnels may have the same address/subnet;
        * LAN routes of the main table win (backend, LAN clients), never its default route;
        * a socket bound to a tunnel (SO_BINDTODEVICE: NAT-PMP, IP echo) uses that tunnel's table;
        * everything else goes through the active tunnel.
        """
        tunnels = [t for t in TUNNEL_IFS if t in (tunnels or ())]
        rules = []
        for i, t in enumerate(tunnels):
            rules.append((RULE_PRIO + i, ["fwmark", TUNNEL_FWMARK[t], "lookup", "main"]))
        for i, t in enumerate(tunnels):
            rules.append((RULE_PRIO + 5 + i, ["fwmark", TUNNEL_CONNMARK[t], "lookup", str(TUNNEL_TABLE[t])]))
        if tunnels:
            rules.append((RULE_PRIO + 10, ["lookup", "main", "suppress_prefixlength", "0"]))
        for i, t in enumerate(tunnels):
            rules.append((RULE_PRIO + 30 + i, ["oif", t, "lookup", str(TUNNEL_TABLE[t])]))
        if active in tunnels:
            rules.append((RULE_PRIO + 40, ["lookup", str(TUNNEL_TABLE[active])]))
        return rules

    def policy_apply(self, active, tunnels):
        """Set our ip rules (only when the wanted state changed). ``tunnels`` empty: remove them all."""
        want = (active, tuple(t for t in TUNNEL_IFS if t in (tunnels or ())))
        if want == self.policy:
            return False
        old = dict(self.policy_rules(*self.policy)) if self.policy else {}
        new = dict(self.policy_rules(*want))
        for prio in sorted(set(old) | set(new)):
            if old.get(prio) == new.get(prio):
                continue
            if prio in new and prio == RULE_PRIO + 40 and old.get(prio):
                # switch the active tunnel without a gap: add the new rule before the old one goes
                self._run(["ip", "-4", "rule", "add", "priority", str(prio)] + new[prio])
                self._run(["ip", "-4", "rule", "del", "priority", str(prio)] + old[prio], check=False)
                continue
            if prio in old or self.policy is None:
                self._run(["ip", "-4", "rule", "del", "priority", str(prio)], check=False)
            if prio in new:
                self._run(["ip", "-4", "rule", "add", "priority", str(prio)] + new[prio])
        self.policy = want
        if old.get(RULE_PRIO + 40) != new.get(RULE_PRIO + 40):
            log("active tunnel: %s", active if new.get(RULE_PRIO + 40) else "none")
        return True

    # -- iptables -----------------------------------------------------
    def _ipt(self, table, *args, check=True):
        return self._run(["iptables", "-w", "5", "-t", table] + list(args), check=check)

    @staticmethod
    def firewall_rules(backend_ip=None, backend_port=None, proton=False, proton_port=0, out_allow=None, mss=None):
        """iptables-restore input for all PF_* chains (applied in one transaction).

        * with a VPN: DNAT wg0 tcp/<port> to the backend for each port (NAT-PMP port or fixed ports);
          ``proton_port`` is one port or a list
        * masquerade DNAT connections towards eth0
        * nothing else reachable from wg0 (only replies)
        * clamp TCP MSS for traffic forwarded through wg0, both directions (SYN and SYN/ACK): ``mss`` (0.10.3, tunnel MTU - 40) sets it explicitly, else clamp to the path MTU; the kernel
          never raises an MSS, so smaller values of the peers stay
        * PF_OUT (0.10.1, defence in depth for the egress policy): new connections of the container through
          eth0 only to private addresses, the DNS servers and the WireGuard endpoints (``out_allow`` =
          ``{"dns": [ip], "endpoints": [(ip, port)]}``); everything else to the internet is rejected, so
          nothing leaves through the home line even if wg0 is gone
        * the LAN entry is no firewall rule since 0.18.1 but a TCP proxy bound to eth0 (``app.lanproxy``):
          DNAT on eth0 never fired behind an ipvlan network on a bridge whose host tracks the SYN first
        """
        rules = {"nat": [], "mangle": [], "filter": []}
        if backend_ip:
            dest = "%s:%d" % (backend_ip, int(backend_port))
            for iface, ports in (_tunnel_ports(proton_port) if proton else []):
                for p in ports:
                    rules["nat"].append("-A PF_PRE -i %s -p tcp --dport %d -j DNAT --to-destination %s"
                                        % (iface, p, dest))
        rules["nat"].append("-A PF_POST -o %s -m conntrack --ctstate DNAT -j MASQUERADE" % LAN_IF)
        target = "--set-mss %d" % _mss(mss) if mss else "--clamp-mss-to-pmtu"
        for flag in ("-i", "-o"):
            rules["mangle"].append("-A PF_MSS %s wg+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS %s" % (flag, target))
        if proton:  # 0.19.0: replies go back through the tunnel the connection came in on
            # only the connection is marked: the forwarded packet itself must still find the backend via eth0
            for t in TUNNEL_IFS:
                rules["mangle"].append("-A PF_MARK -i %s -m conntrack --ctstate NEW -j CONNMARK --set-mark %s"
                                       % (t, TUNNEL_CONNMARK[t]))
            rules["mangle"].append("-A PF_MARK -i %s -m connmark ! --mark 0x0 -j CONNMARK --restore-mark" % LAN_IF)
        rules["filter"].append("-A PF_IN -i wg+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
        rules["filter"].append("-A PF_IN -i wg+ -j DROP")
        if backend_ip:
            rules["filter"].append("-A PF_FWD -i wg+ -o %s -p tcp -d %s --dport %d -m conntrack --ctstate DNAT "
                                   "-j ACCEPT" % (LAN_IF, backend_ip, int(backend_port)))
        rules["filter"] += [
            "-A PF_FWD -i %s -o wg+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" % LAN_IF,
            "-A PF_FWD -i wg+ -j DROP",
            "-A PF_FWD -o wg+ -j DROP",
        ]
        allow = out_allow or {}
        out = ["-A PF_OUT -o %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" % LAN_IF]
        out += ["-A PF_OUT -o %s -d %s -j ACCEPT" % (LAN_IF, n) for n in LAN_DESTS]
        for ip in allow.get("dns") or []:
            ip = str(ipaddress.IPv4Address(ip))
            out += ["-A PF_OUT -o %s -d %s -p %s --dport 53 -j ACCEPT" % (LAN_IF, ip, proto) for proto in ("udp", "tcp")]
        for mark in TUNNEL_FWMARK.values():
            out.append("-A PF_OUT -o %s -m mark --mark %s -j ACCEPT" % (LAN_IF, mark))
        out.append("-A PF_OUT -o %s -m mark --mark %s -j ACCEPT" % (LAN_IF, PUSH_FWMARK))  # direct push (0.18.0)
        for ip, port in allow.get("endpoints") or []:
            out.append("-A PF_OUT -o %s -d %s -p udp --dport %d -j ACCEPT"
                       % (LAN_IF, ipaddress.IPv4Address(ip), _port(port)))
        out.append("-A PF_OUT -o %s -j REJECT --reject-with icmp-net-prohibited" % LAN_IF)
        rules["filter"] += out
        out = []
        for table in ("nat", "mangle", "filter"):
            out.append("*" + table)
            out += [":%s - [0:0]" % chain for t, _, chain in CHAINS if t == table]
            out += rules[table]
            out.append("COMMIT")
        return "\n".join(out) + "\n"

    def firewall_apply(self, backend_ip=None, backend_port=None, proton=False, proton_port=0, out_allow=None,
                       mss=None):
        """Replace the content of all PF_* chains atomically, then make sure the jumps exist.

        ``iptables-restore --noflush`` declares (creates or flushes) only our own
        chains and refills them in one commit per table, so there is no moment
        without the DROP rules. Built-in chains are not flushed.
        """
        text = self.firewall_rules(backend_ip, backend_port, proton, proton_port, out_allow, mss)
        self._run(["iptables-restore", "-w", "5", "--noflush"], input=text)
        for table, parent, chain in CHAINS:
            if self._ipt(table, "-C", parent, "-j", chain, check=False).returncode != 0:
                self._ipt(table, "-I", parent, "1", "-j", chain)

    def firewall_clear(self):
        for table, parent, chain in CHAINS:
            for _ in range(5):  # remove duplicate jumps too, bounded
                if self._ipt(table, "-D", parent, "-j", chain, check=False).returncode != 0:
                    break
            self._ipt(table, "-F", chain, check=False)
            self._ipt(table, "-X", chain, check=False)


def resolv_nameservers(path="/etc/resolv.conf"):
    """IPv4 name servers from resolv.conf (Docker: 127.0.0.11 on lo, or the host's servers)."""
    out = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    try:
                        ip = str(ipaddress.IPv4Address(parts[1]))
                    except (ipaddress.AddressValueError, ValueError):
                        continue
                    if not ip.startswith("127.") and ip not in out:
                        out.append(ip)
    except OSError:
        pass
    return out


def _mss(value):
    mss = int(value)
    if not 1240 <= mss <= 1460 or isinstance(value, bool):
        raise ValueError("invalid MSS %r" % (value,))
    return mss


def _tunnel_ports(value):
    """``[(iface, [port])]`` from a port, a list of ports (on wg0) or a list of ``(iface, ports)`` pairs."""
    if not value:
        return []
    if isinstance(value, (list, tuple)) and value and all(isinstance(v, (list, tuple)) for v in value):
        out = []
        for iface, ports in value:
            if iface not in TUNNEL_IFS:
                raise ValueError("invalid tunnel %r" % (iface,))
            ports = ports if isinstance(ports, (list, tuple)) else [ports]
            out.append((iface, [_port(p) for p in ports if p]))
        return out
    ports = value if isinstance(value, (list, tuple)) else [value]
    return [(PROTON_IF, [_port(p) for p in ports])]


def _port(value):
    port = int(value)
    if not 1 <= port <= 65535 or isinstance(value, bool):
        raise ValueError("invalid port %r" % (value,))
    return port
