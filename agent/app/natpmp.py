"""NAT-PMP loop: keep the Proton port mapping alive and track exit IP and mapped port.

Every 45 s (only while Proton is enabled and ``wg0`` is up) it requests a
60 s mapping for UDP and TCP from the Proton gateway. The TCP result is
authoritative: its public port is what clients connect to on the exit IP
and what the agent DNATs on ``wg0`` to the backend. A failed cycle sets the port
to 0 and is retried on the next cycle; 5 failures in a row rebuild ``wg0``.

0.10.2: every request asks for the port the profile held last (``natpmpc -a <port> 0``; the last port per
profile is kept in ``/data/natpmp.json``), so a container restart (Watchtower) usually gets the same public
port back. If Proton hands out another port, that one is used as before.
"""

import ipaddress
import json
import os
import socket
import struct
import threading
import time

from . import net as netmod, parsers, probe, sysrun
from .log import log

INTERVAL = 45
LIFETIME = 60
MAX_FAILS = 5
TIMEOUT = 15


class NatPmpError(Exception):
    pass


def request(proto, gateway=probe.PROTON_GATEWAY, lifetime=LIFETIME, timeout=TIMEOUT, public=1):
    """One ``natpmpc -a <public> 0 <proto> <lifetime> -g <gw>``; parsed result or ``NatPmpError``.

    ``public`` is the wished public port (1 = any). Returns ``{"public_ip", "port", "protocol", "lifetime"}``
    with ``port > 0``; the port may differ from the wish.
    """
    public = int(public) if 1 <= int(public or 0) <= 65535 else 1
    args = ["natpmpc", "-a", str(public), "0", proto, str(int(lifetime)), "-g", gateway]
    try:
        proc = sysrun.run(args, check=False, timeout=timeout)
    except sysrun.SysRunError as err:
        raise NatPmpError(str(err))
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    res = parsers.natpmpc(text)
    if not res["port"]:
        lines = [l.strip() for l in text.splitlines() if "fail" in l.lower() or "error" in l.lower()]
        detail = lines[-1] if lines else "exit %s, no mapping in output" % proc.returncode
        raise NatPmpError("natpmpc %s: %s" % (proto, detail[:160]))
    return res


SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
OPCODES = {"udp": 1, "tcp": 2}


def _exchange(packet, gateway, device, timeout, sock_factory=socket.socket):
    """Send one NAT-PMP request bound to ``device`` with the RFC 6886 retry schedule (250 ms doubling)."""
    sock = sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if device:
            sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode())
        sock.connect((gateway, 5351))
        wait, deadline = 0.25, time.monotonic() + timeout
        while True:
            sock.send(packet)
            sock.settimeout(max(0.05, min(wait, deadline - time.monotonic())))
            try:
                data = sock.recv(64)
                if len(data) >= 8 and data[0] == 0 and data[1] == 128 + packet[1]:
                    return data
            except socket.timeout:
                pass
            wait *= 2
            if time.monotonic() >= deadline:
                raise NatPmpError("no NAT-PMP answer from %s via %s" % (gateway, device or "default route"))
    except OSError as err:
        raise NatPmpError("NAT-PMP via %s: %s" % (device or "default route", err))
    finally:
        sock.close()


def bound_request(proto, device, gateway=probe.PROTON_GATEWAY, lifetime=LIFETIME, timeout=TIMEOUT, public=1,
                  sock_factory=socket.socket):
    """NAT-PMP mapping like ``request`` but in Python and bound to ``device`` (0.19.0, the standby tunnel:
    natpmpc cannot pick the interface and both tunnels have the same gateway address)."""
    public = int(public) if 1 <= int(public or 0) <= 65535 else 1
    data = _exchange(b"\x00\x00", gateway, device, timeout, sock_factory)
    if len(data) < 12 or struct.unpack("!H", data[2:4])[0] != 0:
        raise NatPmpError("NAT-PMP public address via %s: result %s" % (device, data[2:4].hex()))
    public_ip = str(ipaddress.IPv4Address(data[8:12]))
    op = OPCODES[proto]
    data = _exchange(struct.pack("!BBHHHI", 0, op, 0, 0, public, int(lifetime)), gateway, device, timeout,
                     sock_factory)
    if len(data) < 16:
        raise NatPmpError("NAT-PMP %s via %s: short answer" % (proto, device))
    result, _, _, port, life = struct.unpack("!HIHHI", data[2:16])
    if result != 0 or not port:
        raise NatPmpError("NAT-PMP %s via %s: result %d" % (proto, device, result))
    return {"public_ip": public_ip, "port": port, "protocol": proto.upper(), "lifetime": life}


class NatPmp(threading.Thread):
    def __init__(self, agent, interval=INTERVAL, clock=time.time, req=request):
        super().__init__(name="natpmp", daemon=True)
        self.agent = agent
        self.interval = interval
        self.clock = clock
        self.request = req
        self._wake = threading.Event()
        self._halt = threading.Event()
        self._cycle_lock = threading.Lock()
        self.path = os.path.join(agent.data_dir, "natpmp.json")
        self.state = {"active": False, "ok": False, "port": 0, "profile": "", "wanted": 0, "exit_ip": "", "udp_port": 0, "lifetime": 0,
                      "last": 0, "last_ok": 0, "fails": 0, "error": ""}

    def trigger(self):
        self._wake.set()

    def stop(self):
        self._halt.set()
        self._wake.set()

    def run(self):
        log("natpmp loop started")
        while not self._halt.is_set():
            try:
                self.cycle()
            except Exception as err:  # keep the loop alive
                log("natpmp cycle failed: %s", err)
            for standby in getattr(self.agent, "standbys", None) or []:
                try:
                    standby.cycle()  # 0.19.0: the standby tunnel's mapping, same rhythm (0.37.0: every reserve)
                except Exception as err:
                    log("standby natpmp cycle failed: %s", err)
            self._wake.wait(self.interval)
            self._wake.clear()

    def snapshot(self):
        return dict(self.state)

    # -- last port per profile (survives restarts) -------------------
    def _remembered(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                ports = json.load(fh).get("ports") or {}
            return {str(k): int(v) for k, v in ports.items() if 1 <= int(v) <= 65535}
        except (OSError, ValueError, TypeError, AttributeError):
            return {}

    _file_lock = threading.Lock()  # the standby tunnel's mappings are remembered in the same file (0.19.0)

    def _remember(self, profile, port):
        with self._file_lock:
            self._remember_locked(profile, port)

    def _remember_locked(self, profile, port):
        ports = self._remembered()
        if not profile or ports.get(profile) == port:
            return
        ports[profile] = port
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"ports": ports}, fh)
            os.replace(tmp, self.path)
        except OSError as err:
            log("natpmp: last port not saved: %s", err)

    def _map(self, proto, want):
        """Mapping with the wished port; if that request fails, once more with any port."""
        if want > 1:
            try:
                return self.request(proto, public=want)
            except NatPmpError:
                pass
        return self.request(proto)

    # ------------------------------------------------------------------
    def _active(self):
        return (self.agent._proton_on() and self.agent.vpn_provider() == "proton"
                and self.agent.net.link_exists(self.agent.active_if))

    def cycle(self):
        """One renewal. Returns a copy of the state."""
        with self._cycle_lock:
            s = self.state
            if not self._active():
                if s["active"]:
                    log("natpmp idle (proton off or wg0 down)")
                s.update({"active": False, "ok": False, "udp_port": 0, "lifetime": 0, "fails": 0, "error": ""})
                self._publish(0, "")
                return self.snapshot()
            s["active"] = True
            s["last"] = int(self.clock())
            profile = (self.agent.active_profile() or {}).get("id", "")
            if s["port"] and s["profile"] == profile:
                want = s["port"]
            else:
                want = self._remembered().get(profile, 0)
            s["wanted"] = want
            try:
                udp = self._map("udp", want)
                s["udp_port"] = udp["port"]
            except NatPmpError as err:
                s["udp_port"] = 0
                if s["ok"]:
                    log("natpmp udp mapping failed: %s", err)
            try:
                tcp = self._map("tcp", want)
            except NatPmpError as err:
                s["fails"] += 1
                if s["ok"] or s["error"] != str(err):
                    log("natpmp failed (%d in a row): %s", s["fails"], err)
                s.update({"ok": False, "lifetime": 0, "error": str(err)})
                self._publish(0, s["exit_ip"])
                if s["fails"] >= MAX_FAILS:
                    s["fails"] = 0
                    log("natpmp: %d failures in a row, rebuilding wg0", MAX_FAILS)
                    try:
                        self.agent.rebuild_proton()
                    except Exception as e:
                        log("wg0 rebuild failed: %s", e)
                return self.snapshot()
            exit_ip = tcp["public_ip"] or (udp["public_ip"] if s["udp_port"] else "") or s["exit_ip"]
            if not s["ok"]:
                log("natpmp ok: exit ip %s, tcp port %d", exit_ip or "-", tcp["port"])
            if want and tcp["port"] != want:
                log("natpmp: asked for port %d, got %d", want, tcp["port"])
            s["profile"] = profile
            self._remember(profile, tcp["port"])
            s.update({"ok": True, "fails": 0, "error": "", "lifetime": tcp["lifetime"], "last_ok": s["last"]})
            self._publish(tcp["port"], exit_ip)
            return self.snapshot()

    def _publish(self, port, exit_ip):
        """Store port/exit IP; on change re-apply the firewall (port) and run the monitor (DDNS) at once."""
        s = self.state
        changed = (port, exit_ip) != (s["port"], s["exit_ip"])
        if port != s["port"] and port:
            log("natpmp port %d (was %s)", port, s["port"] or "-")
        s["port"], s["exit_ip"] = port, exit_ip
        if self.agent.vpn_provider() != "proton":
            pass  # fixed ports: the exit IP comes from Agent.refresh_exit_ip
        elif exit_ip or not self.agent._proton_on():
            self.agent.rt["proton"]["exit_ip"] = exit_ip
        self.agent.set_forward_port(port)
        if changed:
            self.agent.trigger_check()
