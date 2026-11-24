"""Load per tunnel and CPU (0.37.0, owner: "Anzahl Verbindungen pro VPN" and "CPU-Verbrauch sichtbar machen,
da jeder WireGuard auf die CPU schlägt").

* Connections: the packet counters of our firewall rules that take new connections in (``PF_PRE`` DNAT, or
  ``PF_IN`` with the PROXY protocol) count exactly one packet per new TCP connection and tunnel. The chains are
  refilled on every firewall change (counters start at 0 again), so the sampler adds up the increases per
  profile. With the PROXY protocol the relays also know how many connections are open right now.
* CPU: WireGuard encrypts in the kernel of the host (kernel threads), not in the container, so the useful number
  is the host's CPU load (``/proc/stat``, the container sees the host's), next to what portnook itself uses (its
  cgroup). Per tunnel the CPU cannot be told apart; the traffic per tunnel shows which one causes it.
"""
import os
import re
import threading
import time

from . import sysrun

WINDOW = 900  # new connections of the last 15 minutes
MIN_GAP = 5  # sample at most every 5 s (the UI asks every 5 s)
_RULE_RE = re.compile(r"^\s*(\d+)\s+\d+\s+\S+\s+\S+\s+\S+\s+(wg\d)\s+\S+\s+\S+\s+\S+.*dpt:(\d+)")


def read_counters(run=sysrun.run):
    """``{(iface, port): packets}`` of the rules that take new connections in on the tunnels."""
    out = {}
    for table, chain in (("nat", "PF_PRE"), ("filter", "PF_IN")):
        try:
            text = run(["iptables", "-w", "5", "-t", table, "-L", chain, "-v", "-x", "-n"], check=False).stdout
        except Exception:
            continue
        for line in (text or "").splitlines():
            m = _RULE_RE.match(line)
            if m and ("DNAT" in line or "ACCEPT" in line) and ("NEW" in line or "DNAT" in line):
                key = (m.group(2), int(m.group(3)))
                out[key] = out.get(key, 0) + int(m.group(1))
    return out


def host_cpu(path="/proc/stat"):
    """``(busy, total)`` jiffies of all CPUs of the host."""
    try:
        with open(path, encoding="ascii") as fh:
            vals = [int(v) for v in fh.readline().split()[1:]]
    except (OSError, ValueError):
        return None
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return sum(vals) - idle, sum(vals)


def own_cpu_usec(root="/sys/fs/cgroup"):
    """CPU time of the container in microseconds (cgroup v2 ``cpu.stat``, v1 ``cpuacct.usage``)."""
    try:
        with open(os.path.join(root, "cpu.stat"), encoding="ascii") as fh:
            for line in fh:
                if line.startswith("usage_usec "):
                    return int(line.split()[1])
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(root, "cpuacct", "cpuacct.usage"), encoding="ascii") as fh:
            return int(fh.read().strip()) // 1000
    except (OSError, ValueError):
        return None


class Usage:
    def __init__(self, agent, clock=time.time, counters=read_counters, host=host_cpu, own=own_cpu_usec):
        self.agent = agent
        self.clock = clock
        self.counters = counters
        self.host = host
        self.own = own
        self.lock = threading.Lock()
        self.last = {}  # (iface, port) -> packets at the last sample
        self.total = {}  # profile id -> new connections since the start
        self.events = []  # (time, profile id, count) for the window
        self.cpu_prev = None  # (time, host busy, host total, own usec)
        self.cpu = {"host": None, "own": None, "cores": os.cpu_count() or 1}
        self.at = 0

    def _owners(self):
        """``{iface: profile id}`` of the tunnels that run now."""
        out = {}
        act = (self.agent.active_profile() or {}).get("id")
        if act:
            out[self.agent.active_if] = act
        for sb in self.agent.standbys:
            if sb.state.get("profile") and sb.state.get("iface"):
                out[sb.state["iface"]] = sb.state["profile"]
        return out

    def sample(self):
        now = self.clock()
        with self.lock:
            if now - self.at < MIN_GAP:
                return
            self.at = now
            cur = self.counters() if self.agent._proton_on() else {}
            owners = self._owners()
            for key, n in cur.items():
                prev = self.last.get(key, 0)
                new = n - prev if n >= prev else n  # rules refilled: counters started at 0
                pid = owners.get(key[0])
                if new > 0 and pid:
                    self.total[pid] = self.total.get(pid, 0) + new
                    self.events.append((now, pid, new))
            self.last = cur
            self.events = [e for e in self.events if now - e[0] < WINDOW]
            host, own = self.host(), self.own()
            if self.cpu_prev and host and self.cpu_prev[2] is not None:
                t0, busy0, total0, own0 = self.cpu_prev
                if host[1] > total0:
                    self.cpu["host"] = round((host[0] - busy0) * 100.0 / (host[1] - total0), 1)
                if own is not None and own0 is not None and now > t0:
                    self.cpu["own"] = round((own - own0) / 1e6 / (now - t0) * 100.0, 1)
            if host:
                self.cpu_prev = (now, host[0], host[1], own)

    def status(self):
        """``{"cpu": {...}, "connections": {profile id: {"total", "recent", "open"}}}``."""
        try:
            self.sample()
        except Exception:
            pass
        open_now = {}
        for relay in (getattr(self.agent, "tunnelproxy", None),):
            for ent in (getattr(relay, "open_by_device", lambda: {})() or {}).items():
                open_now[ent[0]] = ent[1]
        owners = self._owners()
        with self.lock:
            conns = {}
            for pid in set(self.total) | set(owners.values()):
                conns[pid] = {"total": self.total.get(pid, 0),
                              "recent": sum(n for _, p, n in self.events if p == pid), "open": None}
            for iface, n in open_now.items():
                if owners.get(iface) in conns:
                    conns[owners[iface]]["open"] = n
            return {"cpu": dict(self.cpu), "connections": conns, "window": WINDOW}
