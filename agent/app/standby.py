"""Standby tunnel (0.19.0, owner request: "1+n VPNs geöffnet ... damit das Umschalten auf eine andere IP auch
schnell geht").

Besides the active tunnel a second enabled profile runs all the time on the other interface (``wg0``/``wg1``)
with its own NAT-PMP port (or its fixed ports), its own exit IP and, if assigned, its own myaddr name that
always points at that exit IP. Inbound connections on its port are DNATed to the backend like on the active
tunnel; their replies go back through it (connmark, ``app.net``). Nothing else uses it: requests to the
internet (DDNS, ACME, Cloudflare) only use the active tunnel.

When the active tunnel fails, the failover promotes the standby (``Agent.promote_standby``): the policy rule
for "everything else" switches to its table, the redirect points at its name and port at once, nothing has
to be built or resolved anew. The old active tunnel is torn down and the next profile becomes the standby.

0.37.0 (owner): up to 3 reserves at once (``tunnels`` in the failover settings = how many tunnels are open,
2 to 4). Each reserve is one ``Standby`` slot (roles ``standby``, ``standby2``, ``standby3``). ``plan`` keeps a
running reserve on its profile and interface as long as that profile is still among the wanted ones, so a
change elsewhere never rebuilds it (its exit IP and port stay).
"""

import hashlib
import threading
import time

from . import net as netmod, natpmp as natpmpmod, probe, protonconf
from .log import log

HANDSHAKE_FRESH = 180
EXIT_CHECK = 300
REBUILD_AFTER = 4  # failed standby cycles in a row before its tunnel is rebuilt
MAX_TUNNELS = len(netmod.TUNNEL_IFS)  # 0.37.0: active + up to 3 reserves


def conf_digest(prof):
    conf = protonconf.with_mtu(prof["conf"], protonconf.profile_mtu(prof)[1])
    return conf, hashlib.sha256(conf.encode()).hexdigest()


def reserves_wanted(agent, st):
    """How many reserves should run (0.37.0): ``tunnels`` - 1, none when the standby is off or no VPN."""
    cfg = agent.failover.settings(st)
    if not cfg.get("standby", True) or not agent._proton_on(st):
        return 0
    return max(1, min(MAX_TUNNELS, int(cfg.get("tunnels", 2) or 2))) - 1


def plan(agent, st):
    """``[(profile or None, iface)]`` per reserve slot (0.37.0). The wanted profiles are the highest-priority
    enabled ones that are not active (the list order is the priority); a slot keeps its running profile and its
    interface while that profile is still wanted, free slots get the rest in order and the free interfaces."""
    slots = agent.standbys
    n = min(reserves_wanted(agent, st), len(slots))
    act = (agent.active_profile(st) or {}).get("id")
    byid = {p["id"]: p for p in agent.profiles(st) if p["id"] != act and p.get("conf") and p.get("enabled", True)}
    ids = list(byid)[:n]
    pick = [None] * len(slots)
    for i, sb in enumerate(slots):  # any slot keeps a wanted profile it runs (fewer reserves: no rebuild)
        pid = sb.state.get("profile")
        if pid in ids and pid not in pick:
            pick[i] = pid
    rest = [pid for pid in ids if pid not in pick]
    for i in range(len(slots)):
        if pick[i] is None and rest:
            pick[i] = rest.pop(0)
    free = [t for t in netmod.TUNNEL_IFS if t != agent.active_if]
    ifs = [""] * len(slots)
    for i, sb in enumerate(slots):
        cur = sb.state.get("iface")
        if pick[i] and cur in free and cur not in ifs:
            ifs[i] = cur
    for i in range(len(slots)):
        if pick[i] and not ifs[i]:
            ifs[i] = next((t for t in free if t not in ifs), "")
    return [(byid[pick[i]] if pick[i] and ifs[i] else None, ifs[i] if pick[i] else "") for i in range(len(slots))]


class Standby:
    def __init__(self, agent, clock=time.time, request=natpmpmod.bound_request, ip_echo=probe.wg_public_ip,
                 slot=0):
        self.agent = agent
        self.slot = slot  # 0.37.0: reserve 1..3
        self.role = "standby" if slot == 0 else "standby%d" % (slot + 1)
        self.clock = clock
        self.request = request
        self.ip_echo = ip_echo
        self.lock = threading.RLock()
        self.state = self._empty()

    @staticmethod
    def _empty():
        return {"profile": "", "iface": "", "digest": "", "port": 0, "udp_port": 0, "exit_ip": "", "ok": False,
                "fails": 0, "error": "", "since": 0, "last_ok": 0, "exit_check": 0, "lifetime": 0}

    # -- which profile ---------------------------------------------------
    def enabled(self, st=None):
        st = st or self.agent.store.get()
        return self.slot < reserves_wanted(self.agent, st)

    def wanted(self, st=None):
        """The profile of this reserve slot (``plan``): the highest-priority enabled profiles that are not active
        (0.24.0, the list order is a fixed priority)."""
        st = st or self.agent.store.get()
        return plan(self.agent, st)[self.slot][0]

    def iface(self, st=None):
        st = st or self.agent.store.get()
        return plan(self.agent, st)[self.slot][1] or next(t for t in netmod.TUNNEL_IFS if t != self.agent.active_if)

    # -- tunnel ------------------------------------------------------------
    def ensure(self, st=None):
        """Bring the standby tunnel to the wanted state (called by ``Agent._apply`` under its op lock)."""
        with self.lock:
            st = st or self.agent.store.get()
            prof, iface = plan(self.agent, st)[self.slot]
            s = self.state
            if prof is None:
                old = s["iface"] if s["iface"] != self.agent.active_if else ""
                if old and (s["profile"] or self.agent.net.link_exists(old)):
                    self.agent.net.tunnel_down(old)
                if s["profile"]:
                    log("%s off", self.role)
                self.state = self._empty()
                return False
            if s["iface"] and s["iface"] != iface:
                self.state = s = self._empty()  # the interface became the active one (promotion)
            conf, digest = conf_digest(prof)
            if s["profile"] == prof["id"] and s["digest"] == digest and self.agent.net.link_exists(iface):
                return False
            self.agent.net.tunnel_up(iface, conf)
            self.state = dict(self._empty(), profile=prof["id"], iface=iface, digest=digest,
                              since=int(self.clock()))
            if prof.get("provider") == "fixed":
                self.state["port"] = 0  # the fixed ports apply right away (ports())
            log("%s: profile %s '%s' on %s", self.role, prof["id"], prof.get("name", ""), iface)
            self.agent.agent_poke(iface)
            return True

    def down(self):
        with self.lock:
            iface = self.state.get("iface")
            if iface:
                self.agent.net.tunnel_down(iface)
            self.state = self._empty()

    def profile(self, st=None):
        st = st or self.agent.store.get()
        pid = self.state.get("profile")
        return next((p for p in self.agent.profiles(st) if p["id"] == pid), None) if pid else None

    def ports(self, st=None):
        """TCP ports of the standby tunnel (DNAT on its interface, LAN entry)."""
        prof = self.profile(st)
        if not prof:
            return []
        if prof.get("provider") == "fixed":
            return list(prof.get("ports") or [])
        return [self.state["port"]] if self.state["port"] else []

    def handshake_age(self):
        iface = self.state.get("iface")
        dump = self.agent.net.wg_dump(iface) if iface else None
        if not dump or not dump["peers"] or not dump["peers"][0]["handshake"]:
            return None
        return int(self.clock()) - dump["peers"][0]["handshake"]

    # -- NAT-PMP / exit IP (runs in the NAT-PMP loop) ----------------------
    def cycle(self):
        """One check/renewal. Firewall updates and rebuilds run after the lock is released (they take the
        agent's op lock, which ``ensure`` holds while it takes this one)."""
        with self.lock:
            actions = []
            if self._drifted():
                actions.append("rebuild")  # 0.22.0: self-healing, no manual start needed
                out = None
            else:
                out = self._cycle(actions)
        for act in actions:
            if act == "rebuild":
                self.agent.apply_network()
            elif act == "changed":
                self.agent.standby_changed()
        return out

    def _drifted(self):
        """True when the standby is not what it should be: the wanted profile changed, or its tunnel is gone
        (deleted profile, failed rebuild, interface lost). The NAT-PMP loop then re-applies the network."""
        try:
            prof = self.wanted()
        except Exception:  # store not ready
            return False
        s = self.state
        if prof is None:
            return bool(s["profile"])
        if s["profile"] != prof["id"] or s["digest"] != conf_digest(prof)[1]:
            if s["profile"] or not s["error"] or int(self.clock()) - s.get("since", 0) >= 60:
                log("%s: wanted %s '%s', running %s: rebuilding", self.role, prof["id"], prof.get("name", ""),
                    s["profile"] or "none")
                s["since"] = int(self.clock())
                return True
            return False
        if not self.agent.net.link_exists(s["iface"]):
            log("%s: %s is gone, rebuilding", self.role, s["iface"])
            s["digest"] = ""
            return True
        return False

    def _cycle(self, actions):
        prof = self.profile()
        s = self.state
        if not prof or not s["iface"] or not self.agent.net.link_exists(s["iface"]):
            return None
        now = int(self.clock())
        if self.handshake_age() is None:
            self.agent.agent_poke(s["iface"])
        if prof.get("provider") == "fixed":
            if not s["exit_ip"] or now - s["exit_check"] >= EXIT_CHECK:
                s["exit_check"] = now
                ip = self.ip_echo(s["iface"])
                if ip != s["exit_ip"]:
                    log("%s exit ip %s (was %s)", self.role, ip or "unknown", s["exit_ip"] or "-")
                    s["exit_ip"] = ip
                    actions.append("changed")
            ok = bool(s["exit_ip"])
            self._result(ok, "" if ok else "Exit-IP über %s nicht ermittelbar" % s["iface"], actions)
            return dict(s)
        want = s["port"] or self.agent.remembered_port(prof["id"])
        try:
            try:
                self.request("udp", s["iface"], public=want or 1)
            except natpmpmod.NatPmpError:
                pass
            tcp = self.request("tcp", s["iface"], public=want or 1)
        except natpmpmod.NatPmpError as err:
            self._result(False, str(err)[:200], actions)
            return dict(s)
        changed = (tcp["port"], tcp["public_ip"]) != (s["port"], s["exit_ip"])
        if tcp["port"] != s["port"]:
            log("%s natpmp port %d (was %s), exit ip %s", self.role, tcp["port"], s["port"] or "-",
                tcp["public_ip"] or "-")
        s.update({"port": tcp["port"], "exit_ip": tcp["public_ip"] or s["exit_ip"], "lifetime": tcp["lifetime"]})
        self.agent.remember_port(prof["id"], tcp["port"])
        self._result(True, "", actions)
        if changed:
            actions.append("changed")
        return dict(s)

    def _result(self, ok, error, actions):
        s = self.state
        if ok:
            if not s["ok"]:
                log("%s ok: %s, exit ip %s", self.role, s["iface"], s["exit_ip"] or "-")
            s.update({"ok": True, "fails": 0, "error": "", "last_ok": int(self.clock())})
            return
        s["fails"] += 1
        if s["ok"] or s["error"] != error:
            log("%s check failed (%d in a row): %s", self.role, s["fails"], error)
        s.update({"ok": False, "error": error})
        if s["fails"] >= REBUILD_AFTER:
            s["fails"] = 0
            s["digest"] = ""  # the next ensure() rebuilds it
            log("%s: %d failures in a row, rebuilding %s", self.role, REBUILD_AFTER, s["iface"])
            actions.append("rebuild")

    # -- health / promotion ------------------------------------------------
    def health(self):
        """``(ok, reason)``: may the standby take over now?"""
        s = self.state
        prof = self.profile()
        if not prof:
            return False, "keine Reserve"
        if not self.agent.net.link_exists(s["iface"]):
            return False, "%s läuft nicht" % s["iface"]
        age = self.handshake_age()
        if age is None or age >= HANDSHAKE_FRESH:
            return False, "Reserve ohne frischen Handshake"
        if not s["exit_ip"]:
            return False, "Exit-IP der Reserve unbekannt"
        if not self.ports():
            return False, "Reserve ohne Port"
        return True, ""

    def take(self):
        """Hand the standby over to the active side; the caller makes its interface the active one."""
        with self.lock:
            out = dict(self.state)
            self.state = self._empty()
            return out

    def status(self, st=None):
        prof = self.profile(st) or {}
        s = self.state
        ok, reason = self.health() if prof else (False, "")
        return {"enabled": self.enabled(st), "role": self.role, "slot": self.slot + 1, "profile": prof.get("id", ""), "profile_name": prof.get("name", ""),
                "iface": s["iface"], "port": (self.ports(st) or [0])[0], "ports": self.ports(st),
                "exit_ip": s["exit_ip"], "ready": ok, "reason": reason, "error": s["error"],
                "handshake_age": self.handshake_age() if prof else None, "last_ok": s["last_ok"],
                "provider": prof.get("provider") or ("proton" if prof else ""), **self._wire(prof)}

    def _wire(self, prof):
        """Server, endpoint, transfer and MTU like the active tunnel shows them (0.23.0)."""
        out = {"server": prof.get("server", ""), "config_endpoint": prof.get("endpoint", ""), "endpoint": "",
               "rx": 0, "tx": 0, "mtu": 0, "mtu_setting": None, "mtu_effective": None}
        if not prof:
            return out
        out["mtu_setting"], out["mtu_effective"] = protonconf.profile_mtu(prof)
        iface = self.state.get("iface")
        dump = self.agent.net.wg_dump(iface) if iface else None
        if dump is not None:
            out["mtu"] = self.agent.net.link_mtu(iface)
            if dump["peers"]:
                p = dump["peers"][0]
                out.update({"endpoint": p["endpoint"], "rx": p["rx"], "tx": p["tx"]})
        return out
