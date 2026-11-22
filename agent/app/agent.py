"""Agent core: setup steps, network apply, status. Used by the API and the monitor loop."""

import hashlib
import ipaddress
import os
import socket
import threading
import time

from . import auth, lights, net as netmod, probe, protonconf, validate
from .log import log
from .validate import ValidationError

HANDSHAKE_WAIT = 15
PROVIDERS = ("proton", "fixed")  # proton: NAT-PMP port; fixed: ports forwarded by the provider (e.g. AirVPN)
MAX_FIXED_PORTS = 10
EXIT_CHECK = int(os.environ.get("PF_EXIT_CHECK") or 300)  # fixed: exit IP via IP echo through wg0 every 5 min
EXIT_RETRY = 60        # ... every minute while unknown
POKE_ADDR = ("192.0.2.1", 9)  # fixed: any address routed into wg0 starts the handshake
# per VPN profile (0.10.0); 0.9.x kept these directly in the "proton" section
PROFILE_FIELDS = ("conf", "server", "endpoint", "natpmp_hint", "mtu", "provider", "ports")
HANDSHAKE_FRESH = 180
RESOLVE_TIMEOUT = 5
UI_PORT = int(os.environ.get("PF_PORT") or 8090)  # never taken over by the LAN entry


def resolve_ipv4(host, timeout=RESOLVE_TIMEOUT):
    """IPv4 addresses of ``host`` (literal or DNS) with a hard timeout; ``[]`` on failure."""
    try:
        return [str(ipaddress.IPv4Address(host))]
    except (ipaddress.AddressValueError, ValueError):
        pass
    result = {}

    def work():
        try:
            result["ips"] = sorted({i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET)})
        except (OSError, UnicodeError):
            result["ips"] = []

    t = threading.Thread(target=work, name="resolve", daemon=True)
    t.start()
    t.join(timeout)
    ips = result.get("ips", [])
    return ips


class SetupError(Exception):
    """A setup step cannot run now; German message for the UI."""


class PasswordError(ValidationError):
    """Wrong current password on a password change."""


class Agent:
    def __init__(self, store, net=None, version="0.0.0", clock=time.time, sleep=time.sleep, data_dir=None,
                 lanproxy=None):
        self.store = store
        self.data_dir = data_dir or os.path.dirname(os.path.abspath(store.path))
        self.net = net or netmod.Net()
        if lanproxy is None:
            from .lanproxy import LanProxy
            lanproxy = LanProxy()
        self.lanproxy = lanproxy  # LAN entry (0.18.1): TCP proxy on the own eth0 address(es)
        self.version = version
        self.clock = clock
        self.sleep = sleep
        self.op_lock = threading.RLock()  # serialises network changes
        self._pw_lock = threading.Lock()
        self.monitor = None
        self.natpmp = None
        self.forward_port = 0  # NAT-PMP mapped TCP port of the active tunnel (0 = none)
        self.active_if = netmod.PROTON_IF  # interface of the active tunnel (0.19.0: wg0 or wg1)
        self.ui_hosts = set()  # LAN client IPs seen during setup (routes kept via eth0)
        self._proton_applied = ""  # sha256 of the conf that wg0 runs with
        self.rt = {
            "net": {"applied": False, "error": ""},
            "proton": {"exit_ip": "", "error": "", "tested": 0, "natpmp": None},
            "backend": {},
        }
        from .certs import CertManager
        from .egress import Egress
        from .failover import Failover
        from .notify import Notifier
        from .myaddr import Ddns, Names
        from .redirect import Redirect
        self.ddns = Ddns(self, clock=clock)
        self.names = Names(self, clock=clock)
        self.certs = CertManager(self, clock=clock)
        self.redirect = Redirect(self, clock=clock)
        self.failover = Failover(self, clock=clock)
        from .standby import Standby
        self.standby = Standby(self, clock=clock)
        self.egress = Egress(self)
        self.notify = Notifier(self, clock=clock)

    # -- state helpers ----------------------------------------------
    def password_set(self):
        return bool(self.store.section("ui").get("pw_hash"))

    def check_password(self, password):
        stored = self.store.section("ui").get("pw_hash", "")
        return bool(stored) and auth.verify_password(str(password or ""), stored)

    def set_password(self, password, old_password=None, first=False):
        """Set the UI password. ``first``: only if none exists yet (check-and-set);
        otherwise the current password must be given."""
        err = auth.check_new_password(password)
        if err:
            raise ValidationError(err)
        new_hash = auth.hash_password(password)
        with self._pw_lock:
            stored = self.store.section("ui").get("pw_hash", "")
            if stored and first:
                raise SetupError("Das Passwort ist bereits gesetzt. Bitte anmelden.")
            if stored and not auth.verify_password(str(old_password or ""), stored):
                raise PasswordError("Das bisherige Passwort ist falsch.")
            self.store.update("ui", {"pw_hash": new_hash})
        log("ui password %s", "changed" if stored else "set")

    def setup_state(self):
        st = self.store.get()
        s = {
            "password": bool(st["ui"].get("pw_hash")),
            "proton": bool(st["proton"].get("decided")),
            "backend": bool(st["backend"].get("addr")),
        }
        s["done"] = all(s.values())
        return s

    @staticmethod
    def profiles(st):
        """VPN profiles in priority order (0.10.0). A 0.9.x state without profiles counts as profile p1."""
        p = st["proton"]
        profs = p.get("profiles") or []
        if not profs and p.get("conf"):
            profs = [dict({k: p.get(k) for k in PROFILE_FIELDS}, id="p1", name=p.get("server") or "Profil 1",
                          enabled=True)]
        return profs

    def active_profile(self, st=None):
        """The profile wg0 runs with: the stored active one if enabled, else the first enabled one."""
        st = st or self.store.get()
        usable = [x for x in self.profiles(st) if x.get("conf") and x.get("enabled", True)]
        for x in usable:
            if x["id"] == st["proton"].get("active"):
                return x
        return usable[0] if usable else None

    def _proton_on(self, st=None):
        """A VPN (wg0) is switched on and has a usable profile (Proton or fixed ports)."""
        st = st or self.store.get()
        return bool(st["proton"].get("enabled") and self.active_profile(st))

    def vpn_provider(self, st=None):
        prof = self.active_profile(st) or {}
        return prof.get("provider") if prof.get("provider") in PROVIDERS else "proton"

    def forward_ports(self, st=None):
        """TCP ports of the active tunnel DNATed to the backend: the NAT-PMP port or the fixed ports."""
        st = st or self.store.get()
        if not self._proton_on(st):
            return []
        if self.vpn_provider(st) == "fixed":
            return list((self.active_profile(st) or {}).get("ports") or [])
        return [self.forward_port] if self.forward_port else []

    def public_port(self, st=None):
        """Port reachable from outside through the VPN (first one), 0 = none."""
        ports = self.forward_ports(st)
        return ports[0] if ports else 0

    def remember_client(self, client_ip):
        try:
            addr = ipaddress.IPv4Address(client_ip)
        except (ipaddress.AddressValueError, ValueError):
            return
        if addr.is_private and not addr.is_loopback:
            with self.op_lock:
                self.ui_hosts.add(str(addr))

    # -- network ----------------------------------------------------
    def apply_network(self):
        """Idempotently bring routes, firewall and wg0 to the stored state.

        Order: routes (LAN + backend via eth0, before wg-quick so LAN replies never enter wg0)
        -> firewall -> wg0 (Proton).
        """
        with self.op_lock:
            try:
                self._apply()
            except Exception as err:
                self.rt["net"] = {"applied": False, "error": str(err)[:200]}
                log("network apply failed: %s", err)
                raise
            self.rt["net"] = {"applied": True, "error": ""}

    def tunnel_nets(self, st=None):
        """Networks inside the tunnel that LAN routes must not cover: the /24 of every tunnel address (Proton:
        gateway and NAT-PMP at 10.2.0.1) and the Proton gateway itself."""
        out = {probe.PROTON_GATEWAY + "/32"}
        for prof in (self.active_profile(st), self.standby.wanted(st)):
            try:
                for addr in protonconf.parse(prof["conf"]).addresses if prof and prof.get("conf") else []:
                    net = ipaddress.IPv4Interface(addr).network
                    out.add(str(net.supernet(new_prefix=24) if net.prefixlen > 24 else net))
            except (ValueError, ValidationError):
                pass
        return sorted(out)

    def _apply(self):
        st = self.store.get()
        proton_on = self._proton_on(st)
        bip = bport = None
        if st["backend"].get("addr"):
            bip, bport = validate.backend(st["backend"]["addr"])
        self.net.apply_routes(st["backend"].get("lan_nets") or validate.DEFAULT_LAN, bip, sorted(self.ui_hosts),
                              exclude=self.tunnel_nets(st) if proton_on else ())
        self._firewall(st, bip, bport)
        if proton_on:
            prof = self.active_profile(st)
            conf = protonconf.with_mtu(prof["conf"], protonconf.profile_mtu(prof)[1])  # 0.10.3: MTU per profile
            digest = hashlib.sha256(conf.encode()).hexdigest()
            if digest != self._proton_applied or not self.net.link_exists(self.active_if):
                if self.standby.state.get("profile") == prof["id"]:
                    self.standby.down()  # the standby's profile becomes the active one by a rebuild
                if self._proton_applied:
                    self.net.tunnel_down(self.active_if)  # another profile (failover) or a new config
                self.net.tunnel_up(self.active_if, conf)
                self._proton_applied = digest
                log("%s mtu %d (profile %s, setting %s)", self.active_if, protonconf.profile_mtu(prof)[1],
                    prof.get("id"), protonconf.profile_mtu(prof)[0])
            try:
                self.standby.ensure(st)
            except Exception as err:  # the standby never breaks the active tunnel
                self.standby.state.update({"error": str(err)[:200], "ok": False})
                log("standby tunnel failed: %s", err)
            running = [t for t in netmod.TUNNEL_IFS if t == self.active_if or t == self.standby.state.get("iface")]
            self.net.policy_apply(self.active_if, running)
            self._firewall(st, bip, bport)  # again: the standby's ports may have changed
        else:
            self.standby.down()
            self.net.proton_down()
            self.net.policy_apply(None, [])
            self._proton_applied = ""
            self.active_if = netmod.PROTON_IF

    def _firewall(self, st, bip, bport):
        lan = self.lan_entry(st)
        prof = self.active_profile(st) if self._proton_on(st) else None
        mss = protonconf.profile_mtu(prof)[1] - 40 if prof else None  # 0.10.3: MSS = tunnel MTU - IPv4/TCP headers
        sb = self.standby.profile(st) if prof else None
        if sb:  # one PF_MSS rule set for wg+: the smaller tunnel MTU of active and standby (0.19.0)
            mss = min(mss, protonconf.profile_mtu(sb)[1] - 40)
        tunnels = [(self.active_if, self.forward_ports(st))]
        if self.standby.state.get("iface"):
            tunnels.append((self.standby.state["iface"], self.standby.ports(st)))
        self.net.firewall_apply(bip, bport, self._proton_on(st), tunnels, self.out_allow(st), mss=mss)
        # 0.18.1: a proxy instead of DNAT on eth0 (an ipvlan/bridge host can skip the container's nat table)
        self.lanproxy.update(lan["ips"], lan["ports"], (str(bip), int(bport)) if lan["active"] else None)
        if lan["active"] and (lan["ips"], lan["ports"]) != self.rt.get("lan_entry"):
            log("lan entry: %s port %s", ", ".join(lan["ips"]), ", ".join(map(str, lan["ports"])))
        self.rt["lan_entry"] = (lan["ips"], lan["ports"]) if lan["active"] else None

    def lan_entry(self, st=None):
        """LAN entry (0.10.2): the current forwarded port(s) on the agent's own eth0 address, relayed to the
        same backend (a TCP proxy since 0.18.1), so LAN and home-VPN clients reach the same URL without the
        tunnel. Inbound only."""
        st = st or self.store.get()
        enabled = st["backend"].get("lan_entry", True) is not False
        every = list(dict.fromkeys(self.forward_ports(st) + (self.standby.ports(st) if self._proton_on(st) else [])))
        ports = [p for p in every if p != UI_PORT]
        ips = []
        if enabled and st["backend"].get("addr"):
            try:
                ips = self.net.lan_if_addresses()
            except Exception:
                ips = []
        return {"enabled": enabled, "ips": ips, "ports": ports,
                "skipped": [p for p in every if p == UI_PORT],
                "active": bool(enabled and ips and ports)}

    def set_lan_entry(self, body):
        enabled = (body or {}).get("enabled")
        if not isinstance(enabled, bool):
            raise ValidationError("Feld 'enabled' fehlt (true oder false).")
        self.store.update("backend", {"lan_entry": enabled})
        log("lan entry %s", "on" if enabled else "off")
        if self.rt["net"].get("applied"):
            self.apply_network()
        return {"ok": True, "lan_entry": self.lan_entry_status()}

    def lan_entry_status(self, st=None):
        lan = self.lan_entry(st)
        fqdn = self.fqdn()
        errors = dict(self.lanproxy.errors) if lan["active"] else {}
        return dict(lan, urls=["https://<sub>.%s:%d" % (fqdn, p) for p in lan["ports"]] if fqdn else [],
                    errors=errors)

    def out_allow(self, st):
        """Exceptions of the PF_OUT chain: DNS servers and the WireGuard endpoints of all VPN profiles."""
        endpoints = []
        for prof in self.profiles(st):
            host, _, port = str(prof.get("endpoint") or "").rpartition(":")
            if not host or not port.isdigit():
                continue
            for ip in resolve_ipv4(host.strip("[]")):
                if (ip, int(port)) not in endpoints:
                    endpoints.append((ip, int(port)))
        return {"dns": netmod.resolv_nameservers(), "endpoints": endpoints}

    def egress_device(self):
        """Route policy for requests to the internet (myaddr.tools, ACME, Cloudflare): ``wg0`` while a
        tunnel exists, private (LAN) addresses only otherwise, never the home line (``app.egress``)."""
        return self.egress.route("internet")

    def vpn_exit_ip(self):
        """Proton exit IP while the tunnel is configured and up, else ``""``."""
        if not self._proton_on():
            return ""
        ip = self.rt["proton"].get("exit_ip", "")
        return ip if ip and self.net.link_exists(self.active_if) else ""

    def lan_device(self):
        """Route policy for requests into the LAN (NPM, LAN push): private addresses via eth0, never wg0."""
        return self.egress.route("lan")

    def set_forward_port(self, port):
        """New NAT-PMP port: re-apply the firewall (DNAT wg0 tcp/<port>) if it changed."""
        port = int(port or 0)
        with self.op_lock:
            if port == self.forward_port:
                return False
            self.forward_port = port
            if not self.rt["net"].get("applied"):
                return True  # the next apply_network picks it up
            st = self.store.get()
            bip = bport = None
            if st["backend"].get("addr"):
                bip, bport = validate.backend(st["backend"]["addr"])
            if self.vpn_provider(st) == "fixed":
                return True  # fixed ports: NAT-PMP is idle, the firewall does not depend on it
            try:
                self._firewall(st, bip, bport)
                log("firewall: wg0 forward port %s", port or "none")
            except Exception as err:
                self.rt["net"] = {"applied": False, "error": str(err)[:200]}
                log("firewall update for port %s failed: %s", port or "none", err)
            return True

    # -- standby tunnel (0.19.0) -------------------------------------
    def agent_poke(self, iface):
        """One datagram into ``iface`` (bound to it) so its WireGuard handshake starts."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), iface.encode())
                sock.sendto(b"\x00\x00", (probe.PROTON_GATEWAY, 5351))
            finally:
                sock.close()
        except OSError:
            pass

    def remembered_port(self, pid):
        return self.natpmp._remembered().get(pid, 0) if self.natpmp is not None else 0

    def remember_port(self, pid, port):
        if self.natpmp is not None:
            self.natpmp._remember(pid, port)

    def standby_changed(self):
        """The standby's port or exit IP changed: new DNAT/LAN entry, its myaddr name follows."""
        with self.op_lock:
            st = self.store.get()
            if not self.rt["net"].get("applied") or not self._proton_on(st):
                return
            bip = bport = None
            if st["backend"].get("addr"):
                bip, bport = validate.backend(st["backend"]["addr"])
            try:
                self._firewall(st, bip, bport)
            except Exception as err:
                log("firewall update for the standby failed: %s", err)
        self.trigger_check()

    def profile_exit_ip(self, pid):
        """Exit IP of the tunnel that runs profile ``pid`` (active or standby), ``""`` if none.
        0.25.0: ``pid`` may name several profiles (``"p1,p2"`` or a list): the active one of them wins, else
        the standby. For the myaddr names use ``name_exit_ip`` (0.27.8): it never gives both tunnels one name."""
        from .myaddr import pids
        ids = pids(pid)
        if not ids or not self._proton_on():
            return ""
        if (self.active_profile() or {}).get("id") in ids:
            return self.vpn_exit_ip()
        s = self.standby.state
        if s.get("profile") in ids and self.net.link_exists(s.get("iface") or ""):
            return s.get("exit_ip") or ""
        return ""

    def running_tunnels(self):
        """``[(role, profile id, exit ip)]`` of the tunnels that run now: ``active`` first, then ``standby``."""
        if not self._proton_on():
            return []
        out = []
        act = (self.active_profile() or {}).get("id")
        if act and self.vpn_exit_ip():
            out.append(("active", act, self.vpn_exit_ip()))
        s = self.standby.state
        if s.get("profile") and s.get("profile") != act and s.get("exit_ip") and \
                self.net.link_exists(s.get("iface") or ""):
            out.append(("standby", s["profile"], s["exit_ip"]))
        return out

    def tunnel_names(self):
        """Which myaddr name serves which running tunnel (0.27.8, owner): a name may belong to several profiles,
        but active and standby never share a name. Returns ``{role: key}`` with key ``"base"`` (main name) or a
        name id; a role without a free name is missing.

        Every way to give each tunnel a different name (or none) is tried. The best one serves the most tunnels,
        the active one first, then keeps names on the address they already have (no needless DNS change), then
        prefers names higher in the list."""
        from .myaddr import mode_of, pids
        tunnels = self.running_tunnels()
        if not tunnels:
            return {}
        names = []  # (key, profile ids, address it has now)
        m = self.store.section("myaddr")
        if m.get("name") and m.get("profile") and mode_of(m) != "manual":
            names.append(("base", set(pids(m["profile"])), m.get("last_ip", "")))
        for n in self.names.items():
            if n["role"] == "endpoint" and n.get("profile"):
                names.append((n["id"], set(pids(n["profile"])), n.get("sent_ip", "")))
        best, best_score = {}, None

        def walk(i, used, pick):
            nonlocal best, best_score
            if i == len(tunnels):
                order = {k: j for j, (k, _, _) in enumerate(names)}
                byk = {k: sent for k, _, sent in names}
                ips = dict((r, ip) for r, _, ip in tunnels)
                score = (len(pick), "active" in pick,
                         sum(1 for r, k in pick.items() if byk[k] == ips[r]),
                         -sum(order[k] for k in pick.values()))
                if best_score is None or score > best_score:
                    best, best_score = dict(pick), score
                return
            role, pid, _ = tunnels[i]
            walk(i + 1, used, pick)
            for key, ids, _ in names:
                if pid in ids and key not in used:
                    pick[role] = key
                    walk(i + 1, used | {key}, pick)
                    del pick[role]

        walk(0, frozenset(), {})
        return best

    def name_exit_ip(self, key):
        """Exit IP for the myaddr name ``key`` (``"base"`` or a name id) that belongs to VPN profiles: the tunnel
        it serves according to ``tunnel_names``, ``""`` if it serves none (then its record is left alone)."""
        ips = {r: ip for r, _, ip in self.running_tunnels()}
        for role, k in self.tunnel_names().items():
            if k == key:
                return ips.get(role, "")
        return ""

    def tunnel_fqdn(self, role):
        """``name.domain`` that serves the ``active`` or ``standby`` tunnel, ``""`` if none."""
        key = self.tunnel_names().get(role)
        if key == "base":
            m = self.store.section("myaddr")
            return "%s.%s" % (m["name"], m.get("domain"))
        for n in self.names.items():
            if n["id"] == key:
                return "%s.%s" % (n["name"], n["domain"])
        return ""

    def promote_standby(self):
        """Make the standby tunnel the active one at once (failover, rotation, manual switch).

        Only the policy rule for "everything else" changes; the standby already holds its port and exit IP,
        so redirect and DDNS follow right away. The old active tunnel goes down and the next profile becomes
        the standby. Returns the new active profile or ``None`` if the standby was not ready."""
        with self.op_lock:
            ok, reason = self.standby.health()
            if not ok:
                log("standby not ready: %s", reason)
                return None
            snap = self.standby.take()
            old_if = self.active_if
            self.failover.set_active(snap["profile"])
            self.active_if = snap["iface"]
            self._proton_applied = snap["digest"]
            prof = self.active_profile()
            if prof.get("provider") == "fixed":
                self.forward_port = 0
            else:
                self.forward_port = snap["port"]
                if self.natpmp is not None:
                    self.natpmp.state.update({"port": snap["port"], "profile": snap["profile"], "ok": True,
                                              "exit_ip": snap["exit_ip"], "fails": 0, "error": ""})
            self.rt["proton"].update({"exit_ip": snap["exit_ip"], "error": "", "tested": int(self.clock()),
                                      "natpmp": prof.get("provider") != "fixed"})
            self.rt["exit_check"] = int(self.clock())
            log("standby %s '%s' is the active tunnel now (%s, exit ip %s, port %s)", prof["id"],
                prof.get("name", ""), self.active_if, snap["exit_ip"] or "-", snap["port"] or "-")
            st = self.store.get()
            running = [self.active_if] + ([old_if] if self.net.link_exists(old_if) else [])
            self.net.policy_apply(self.active_if, running)  # the switch itself
            self.net.tunnel_down(old_if)
            self.apply_network()  # firewall for the new ports, the next standby on the old interface
        self.ddns.reset()
        self.trigger_check()
        if self.natpmp is not None:
            self.natpmp.trigger()
        return prof

    def rebuild_proton(self):
        """Tear wg0 down and bring it up again, then test it (proton-reconnect, NAT-PMP failures)."""
        if not self._proton_on():
            raise SetupError("Kein VPN aktiviert.")
        with self.op_lock:
            self._proton_applied = ""
            self.net.tunnel_down(self.active_if)
            self.apply_network()
            result = self.proton_test()
        self.trigger_check()
        if self.natpmp is not None:
            self.natpmp.trigger()
        return result

    def teardown(self):
        with self.op_lock:
            self.standby.down()
            self.net.proton_down()
            self.net.policy_apply(None, [])
            self.lanproxy.stop()
            self.net.firewall_clear()
            self.net.clear_routes()
            self._proton_applied = ""

    def startup(self):
        """Re-apply the stored network config and start the reporter (non-blocking)."""
        def work():
            st = self.setup_state()
            if st["proton"] or st["backend"]:
                try:
                    self.apply_network()
                    log("network re-applied")
                except Exception:
                    pass
            self.start_monitor()
            self.start_natpmp()
            self.notify.start()
        threading.Thread(target=work, name="startup", daemon=True).start()

    def start_natpmp(self):
        from .natpmp import NatPmp
        if self.natpmp is None:
            self.natpmp = NatPmp(self)
            self.natpmp.start()

    def start_monitor(self):
        from .monitor import Monitor
        if self.monitor is None:
            self.monitor = Monitor(self)
            self.monitor.start()

    def trigger_check(self):
        """Run the monitor cycle now (exit IP or port changed: DDNS update)."""
        if self.monitor is not None:
            self.monitor.trigger()

    # -- Proton -----------------------------------------------------
    def setup_proton(self, body, client_ip=None):
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            raise ValidationError("Feld 'enabled' fehlt (true oder false).")
        self.remember_client(client_ip)
        if not enabled:
            self.store.update("proton", {"decided": True, "enabled": False})
            log("proton disabled")
            self.forward_port = 0
            self.apply_network()
            self.rt["proton"] = {"exit_ip": "", "error": "", "tested": 0, "natpmp": None}
            self.trigger_check()
            return {"ok": True, "enabled": False}

        st = self.store.get()
        current = self.active_profile(st) or {}
        profile = {"name": current.get("name") or "", "provider": body.get("provider", current.get("provider") or "proton"),
                   "ports": body.get("ports", current.get("ports")), "enabled": True}
        if body.get("conf"):
            profile["conf"] = body["conf"]
        if "mtu" in body:
            profile["mtu"] = body["mtu"]
        if not profile.get("conf") and not current.get("conf"):
            raise ValidationError("Bitte die WireGuard-Datei (wg.conf) hochladen oder einfügen.")
        if current:
            profile["id"] = current["id"]
        if "lan_nets" in body:
            nets = validate.lan_nets(body.get("lan_nets") or [])
            self.store.update("backend", {"lan_nets": nets})
        if not self.store.section("backend").get("lan_nets"):
            self.store.update("backend", {"lan_nets": list(validate.DEFAULT_LAN)})
        prof, summary = self.failover.store_profile(profile)
        self.store.update("proton", {"decided": True, "enabled": True, "active": prof["id"]})
        return self.start_profile(prof, summary)

    def start_profile(self, prof, summary=None):
        """(Re)build wg0 with the active profile and test it."""
        summary = summary or {"server": prof.get("server"), "endpoint": prof.get("endpoint"),
                              "natpmp_hint": prof.get("natpmp_hint"), "removed": []}
        self.forward_port = 0
        self.rt["proton"]["exit_ip"] = ""
        self.rt["exit_check"] = 0
        with self.op_lock:
            try:
                self.apply_network()
            except Exception as err:
                result = {"ok": False, "error": "wg0 konnte nicht gestartet werden: %s" % str(err)[:200]}
                self.rt["proton"].update({"error": result["error"], "tested": int(self.clock())})
                return {"ok": False, "enabled": True, "summary": summary, "test": result}
            result = self.proton_test()
        self.ddns.reset()
        self.trigger_check()
        if self.natpmp is not None:
            self.natpmp.trigger()
        return {"ok": result["ok"], "enabled": True, "summary": summary, "test": result, "profile": prof["id"]}

    @staticmethod
    def _fixed_ports(value):
        if isinstance(value, (int, str)) and not isinstance(value, bool):
            value = [p for p in str(value).replace(";", ",").replace(" ", ",").split(",") if p]
        if not isinstance(value, list) or not value:
            raise ValidationError("Bitte mindestens einen beim Anbieter freigegebenen Port eintragen.")
        ports = []
        for item in value:
            port = validate.port(item, "Port")
            if port not in ports:
                ports.append(port)
        if len(ports) > MAX_FIXED_PORTS:
            raise ValidationError("Höchstens %d feste Ports." % MAX_FIXED_PORTS)
        return ports

    def handshake_age(self):
        """Seconds since the last wg0 handshake, ``None`` without wg0 or handshake."""
        dump = self.net.wg_dump(self.active_if)
        if not dump or not dump["peers"] or not dump["peers"][0]["handshake"]:
            return None
        return int(self.clock()) - dump["peers"][0]["handshake"]

    def refresh_exit_ip(self, force=False):
        """Provider with fixed ports: exit IP via the IP echo through wg0 (monitor loop)."""
        st = self.store.get()
        if not self._proton_on(st) or self.vpn_provider(st) != "fixed":
            return None
        now = int(self.clock())
        if not self.net.link_exists(self.active_if):
            if self.rt["proton"].get("exit_ip"):
                log("vpn exit ip unknown (wg0 down)")
            self.rt["proton"]["exit_ip"] = ""
            return ""
        current = self.rt["proton"].get("exit_ip", "")
        if not force and now - self.rt.get("exit_check", 0) < (EXIT_CHECK if current else EXIT_RETRY):
            return current
        self.rt["exit_check"] = now
        ip = probe.wg_public_ip(self.active_if)
        if ip != current:
            log("vpn exit ip %s (was %s)", ip or "unknown", current or "-")
            self.rt["proton"]["exit_ip"] = ip
        return ip

    def proton_test(self, wait=HANDSHAKE_WAIT):
        """Wait for a wg0 handshake, then query the exit IP (NAT-PMP or, fixed ports, IP echo via wg0)."""
        fixed = self.vpn_provider() == "fixed"
        start = self.clock()
        result = {"ok": False, "handshake": 0, "endpoint": "", "server": (self.active_profile() or {}).get("server", ""),
                  "exit_ip": "", "natpmp": False, "error": ""}
        peer = None
        while True:
            dump = self.net.wg_dump(self.active_if)
            if dump is None:
                result["error"] = "wg0 läuft nicht."
                break
            peer = dump["peers"][0] if dump["peers"] else None
            if peer and peer["handshake"] and self.clock() - peer["handshake"] < HANDSHAKE_FRESH:
                result["ok"] = True
                break
            if self.clock() - start >= wait:
                result["error"] = "Kein Handshake mit dem VPN-Server innert %d s." % wait
                break
            self._poke_proton(POKE_ADDR if fixed else (probe.PROTON_GATEWAY, 5351))
            self.sleep(1)
        if peer:
            result["handshake"] = peer["handshake"]
            result["endpoint"] = peer["endpoint"]
        if result["ok"] and fixed:
            result["exit_ip"] = probe.wg_public_ip(self.active_if)
            self.rt["exit_check"] = int(self.clock())
            if not result["exit_ip"]:
                result["warning"] = "Exit-IP über wg0 nicht ermittelbar (IP-Echo antwortet nicht)."
        elif result["ok"]:
            result["exit_ip"] = probe.proton_public_ip()
            result["natpmp"] = bool(result["exit_ip"])
            if not result["exit_ip"]:
                result["warning"] = ("NAT-PMP antwortet nicht: Exit-IP unbekannt. Für Port-Forwarding einen "
                                     "Proton-Server mit P2P und 'NAT-PMP' in der Konfiguration wählen.")
        self.rt["proton"] = {"exit_ip": result["exit_ip"], "error": result["error"],
                             "tested": int(self.clock()), "natpmp": result["natpmp"]}
        log("proton test: %s", "ok, endpoint %s, exit ip %s" % (result["endpoint"] or "-", result["exit_ip"] or "-")
            if result["ok"] else result["error"])
        return result

    @staticmethod
    def _poke_proton(addr=(probe.PROTON_GATEWAY, 5351)):
        """Send one datagram into wg0 (Proton: a NAT-PMP public-address request) to trigger a handshake."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(b"\x00\x00", addr)
            finally:
                sock.close()
        except OSError:
            pass

    # -- backend ----------------------------------------------------
    def setup_backend(self, body, client_ip=None):
        addr, port = validate.backend(body.get("backend"))
        nets = validate.lan_nets(body.get("lan_nets") or [])
        if self._proton_on() and not nets:
            raise ValidationError("Mit Proton sind LAN-Netze nötig, sonst gehen Antworten an das LAN "
                                  "(auch an dieses WebUI) in den Proton-Tunnel.")
        self.remember_client(client_ip)
        self.store.update("backend", {"addr": "%s:%d" % (addr, port), "lan_nets": nets})
        log("backend set to %s:%d, lan nets %s", addr, port, ", ".join(nets) or "-")
        try:
            self.apply_network()
        except Exception as err:
            return {"ok": False, "test": {"ok": False, "tcp": False, "tls": False, "latency_ms": 0,
                                          "error": "Netzwerk konnte nicht eingerichtet werden: %s" % str(err)[:200]}}
        test = self.backend_test()
        return {"ok": test["tcp"], "test": test}

    def backend_test(self):
        st = self.store.get()
        if not st["backend"].get("addr"):
            return {"ok": False, "tcp": False, "tls": False, "latency_ms": 0, "error": "Kein Backend gesetzt."}
        ip, port = validate.backend(st["backend"]["addr"])
        sni = self.fqdn()
        res = probe.backend_tls(ip, port, sni=sni or None)
        res["sni"] = sni
        previous = self.rt.get("backend") or {}
        self.rt["backend"] = res
        if previous.get("ok") != res["ok"]:
            log("backend %s:%d %s", ip, port, "ok (%d ms)" % res["latency_ms"] if res["ok"] else res["error"])
        return res

    def fqdn(self):
        """``<name>.<domain>`` at myaddr.tools, ``""`` if not configured."""
        m = self.store.section("myaddr")
        return "%s.%s" % (m["name"], m["domain"]) if m.get("name") and m.get("domain") else ""

    # -- actions ----------------------------------------------------
    def action(self, name):
        if name == "proton-reconnect":
            return self.rebuild_proton()
        if name == "backend-test":
            return self.backend_test()
        if name == "ddns-update":
            if not self.ddns.enabled():
                raise SetupError("DDNS ist nicht eingerichtet (Name, Schlüssel, DDNS an).")
            return self.ddns.tick(force=True)
        if name == "cert-issue":
            return self.certs.start("manual")
        if name == "push-test":
            return self.notify.test()
        if name == "cert-deliver":
            res = self.certs.deliver()
            if not res:
                raise SetupError("Kein Ziel eingerichtet (NPM oder Zoraxy).")
            return {"ok": all(r["ok"] for r in res.values()), "results": res}
        if name == "redirect-run":
            if not self.redirect.cfg().get("provider"):
                raise SetupError("Kein Redirect-Anbieter eingerichtet.")
            self.names.tick(force=True)
            res = self.redirect.apply(force=True)
            if res.get("queued"):
                return dict(res, ok=True, message="Kein VPN-Tunnel: Redirect auf %s vorgemerkt." % res["queued"])
            if res.get("skipped"):
                raise SetupError("Redirect nicht möglich: %s." % res["skipped"])
            return res
        if name == "natpmp-renew":
            if not self._proton_on() or self.vpn_provider() != "proton":
                raise SetupError("NAT-PMP gibt es nur mit Proton.")
            if self.natpmp is None:
                self.start_natpmp()
            res = self.natpmp.cycle()
            res["ok"] = bool(res["ok"])
            if not res["active"]:
                res["error"] = "wg0 läuft nicht."
            return res
        raise KeyError(name)

    # -- status -----------------------------------------------------
    def proton_runtime(self, st=None):
        """Live wg0 info (handshake, endpoint)."""
        st = st or self.store.get()
        prof = self.active_profile(st) or {}
        info = {"enabled": bool(st["proton"].get("enabled")), "configured": bool(prof.get("conf")),
                "server": prof.get("server", ""), "profile": prof.get("id", ""), "profile_name": prof.get("name", ""),
                "up": False, "endpoint": "", "handshake": 0, "iface": self.active_if,
                "rx": 0, "tx": 0, "mtu_setting": protonconf.profile_mtu(prof)[0] if prof else None,
                "mtu_effective": protonconf.profile_mtu(prof)[1] if prof else None, "mtu": 0}
        if info["enabled"]:
            dump = self.net.wg_dump(self.active_if)
            if dump is not None:
                info["up"] = True
                info["mtu"] = self.net.link_mtu(self.active_if)
                if dump["peers"]:
                    p = dump["peers"][0]
                    info.update({"endpoint": p["endpoint"], "handshake": p["handshake"], "rx": p["rx"], "tx": p["tx"]})
        return info

    def status(self):
        st = self.store.get()
        now = int(self.clock())
        proton = self.proton_runtime(st)
        nat = self.natpmp.snapshot() if self.natpmp is not None else {}
        proton.update({"exit_ip": self.rt["proton"].get("exit_ip", ""),
                       "provider": self.vpn_provider(st), "ports": self.forward_ports(st) if proton["enabled"] else [],
                       "port": self.public_port(st) if proton["enabled"] else 0,
                       "natpmp": {k: nat.get(k) for k in ("active", "ok", "udp_port", "lifetime", "last_ok",
                                                          "fails", "error")},
                       "natpmp_hint": (self.active_profile(st) or {}).get("natpmp_hint"),
                       "error": self.rt["proton"].get("error", ""),
                       "config_endpoint": (self.active_profile(st) or {}).get("endpoint", ""),
                       "profiles": self.failover.listing(st), "failover": self.failover.status()})
        proton["handshake_age"] = now - proton["handshake"] if proton["handshake"] else None
        backend = {"addr": st["backend"].get("addr", ""), "lan_nets": st["backend"].get("lan_nets", [])}
        backend.update({k: v for k, v in (self.rt.get("backend") or {}).items()
                        if k in ("ok", "tcp", "tls", "latency_ms", "error", "checked", "sni")})
        m = st.get("myaddr") or {}
        myaddr = {"name": m.get("name", ""), "domain": m.get("domain", ""), "fqdn": self.fqdn(),
                  "key_set": bool(m.get("key")), "profile": m.get("profile", ""),
                  "tunnel_names": {r: self.tunnel_fqdn(r) for r in ("active", "standby")}}
        out = {"version": self.version, "time": now, "setup": self.setup_state(), "proton": proton,
               "backend": backend, "myaddr": myaddr, "ddns": self.ddns.status(), "names": self.names.status(), "cert": self.certs.status(),
               "delivery": self.certs.delivery_status(), "redirect": self.redirect.status(), "net": dict(self.rt["net"]),
               "natpmpc": probe.natpmpc_available(), "push": self.notify.status(),
               "egress": {"tunnel_up": self.egress.tunnel_up()}, "lan_entry": self.lan_entry_status(st)}
        out["light"] = lights.evaluate(out)
        return out
