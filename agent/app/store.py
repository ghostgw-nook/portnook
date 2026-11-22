"""Persistent agent state in ``/data/agent.json`` (atomic write, mode 600)."""

import copy
import json
import os
import threading
import time

from .log import log

DEFAULT = {
    "ui": {"pw_hash": ""},
    # decided: the wizard step was answered (with or without Proton)
    # provider (0.9.1): proton (NAT-PMP port) | fixed (ports forwarded by the provider, e.g. AirVPN)
    # profiles (0.10.0): [{id, name, provider, ports, conf, server, endpoint, natpmp_hint, mtu, mtu_setting,
    # enabled}]; mtu = MTU of the wg.conf, mtu_setting (0.10.3) = 1280-1500 or "conf" in
    # priority order, active = id of the profile wg0 runs with; failover = {fails, prefer_primary, hold}
    "proton": {"decided": False, "enabled": False, "profiles": [], "active": "", "failover": {}, "last_rotate": 0},
    # lan_entry (0.10.2): the forwarded port(s) are reachable on the agent's own LAN IP too (default on)
    "backend": {"addr": "", "lan_nets": [], "lan_entry": True},
    # myaddr.tools name + key (secret, never returned by the API); last_ip/last_ok of the DDNS update
    # ip_mode (0.9.1): vpn (default: exit IP, else fallback_ip, else no update) | manual (manual_ip);
    # the home IP (ip=self) is never sent. Files of 0.9.0 have no ip_mode -> vpn without fallback.
    "myaddr": {"name": "", "domain": "myaddr.tools", "key": "", "ddns": True, "ip_mode": "vpn",
               "fallback_ip": "", "manual_ip": ""},
    # Let's Encrypt (ACME DNS-01) settings and the state of the last run; pull_token_sha256 for the pull API
    "cert": {"enabled": False, "staging": True, "email": "", "delay": 60, "auto": True},
    # where new certificates go: Nginx Proxy Manager (secret = password, never returned), Zoraxy directory
    "delivery": {"npm": {}, "zoraxy": {}},
    # push notifications (0.10.1): gotify {url, token (secret), lan}, ntfy {url, topic, token (secret), lan},
    # reminder = minutes between reminders while all VPNs are down
    "push": {"gotify": {}, "ntfy": {}, "reminder": 30},
}
LEGACY_VPN = ("conf", "server", "endpoint", "natpmp_hint", "mtu", "provider", "ports")


def migrate(data):
    """0.9.x kept one VPN config in the "proton" section; 0.10.0 has a list of profiles (profile p1)."""
    p = data.get("proton") or {}
    if p.get("conf") and not p.get("profiles"):
        prof = {k: p.get(k) for k in LEGACY_VPN}
        prof.update({"id": "p1", "name": p.get("server") or "Profil 1", "enabled": True,
                     "provider": p.get("provider") or "proton", "ports": p.get("ports") or []})
        p["profiles"] = [prof]
        p["active"] = "p1"
        log("vpn config migrated to profile p1")
    if p.get("profiles"):
        for key in LEGACY_VPN:
            p.pop(key, None)
        for prof in p["profiles"]:
            if "mtu_setting" not in prof:  # 0.10.3: explicit MTU in the wg.conf -> keep it, else 1340
                prof["mtu_setting"] = "conf" if prof.get("mtu") else 1340
                log("vpn profile %s: MTU setting %s (migrated)", prof.get("id"), prof["mtu_setting"])
    return data


# sections of 0.8 and older (VPS edge, removed in 0.9.0); dropped on load, secrets included
OBSOLETE = ("mgmt", "edge")


class Store:
    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()
        self._data = self._load()

    def _load(self):
        data = copy.deepcopy(DEFAULT)
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                raise ValueError("not a JSON object")
        except FileNotFoundError:
            return data
        except (ValueError, UnicodeDecodeError) as err:
            # keep the broken file for inspection and start with the wizard instead of crash-looping
            target = "%s.corrupt-%d" % (self.path, int(time.time()))
            os.replace(self.path, target)
            log("state file corrupt (%s), moved to %s, starting setup again", err.__class__.__name__, target)
            return data
        for key, val in loaded.items():
            if key in OBSOLETE:
                continue
            if isinstance(data.get(key), dict) and isinstance(val, dict):
                data[key].update(val)
            else:
                data[key] = val
        return migrate(data)

    def get(self):
        """Return a deep copy of the whole state."""
        with self._lock:
            return copy.deepcopy(self._data)

    def section(self, name):
        with self._lock:
            return copy.deepcopy(self._data.get(name, {}))

    def update(self, name, values=None, replace=False):
        """Merge ``values`` into section ``name`` (or replace it) and save."""
        with self._lock:
            if replace:
                self._data[name] = copy.deepcopy(values or {})
            else:
                self._data.setdefault(name, {}).update(copy.deepcopy(values or {}))
            self._save()

    def _save(self):
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
