"""Several VPN profiles with failover (0.10.0, owner request: "mehrere VPNs ermöglichen falls einer mal down geht").

Profiles live in ``proton.profiles`` (list order = priority); exactly one runs as ``wg0`` (``proton.active``).
``tick()`` runs in the monitor loop (every 30 s) and checks the active profile:

* wg0 up and a WireGuard handshake younger than 180 s,
* Proton: NAT-PMP renewals not failing; fixed ports: the exit IP through wg0 is known (after a failed check the
  IP echo is asked on every check).

After ``fails`` failed checks in a row (default 3) the next enabled profile is started (rebuild wg0, DNAT for its
ports, test). DDNS and redirect follow on their own (exit IP / port changed). When every profile was tried
without success the agent stays on the last one, reports "alle Profile gestört" (traffic light red) and starts a
new round after ``hold``.

0.24.0 (owner decision 2026-11-22, replaces "active on top" of 0.19.0): the list order is a fixed priority
(1 = most important) and never changes on a switch. With ``standby`` (default on) the highest-priority enabled
profile that is not active runs as a standby tunnel all the time (``app.standby``); a failover or a manual switch
to it only promotes it (no rebuild, its port and exit IP are known). There is no automatic return: running on 2,
a recovered 1 is the standby, ready to take over when 2 fails. Failover candidates follow the list from the top;
rotation goes round robin to the next profile below the active one (wrapping around).
The kill switch is unchanged: requests to the internet only leave through wg0, never through the home line.
"""

import re
import threading
import time

from . import protonconf, validate
from .log import log
from .validate import ValidationError

DEFAULTS = {"fails": 2, "prefer_primary": False, "standby": True, "hold": 600, "rotate": "off", "rotate_at": "04:00", "rotate_hours": 24}
ROTATE_MODES = ("off", "daily", "hours")
ROTATE_AT_RE = re.compile(r"([01]\d|2[0-3]):[0-5]\d")
VERIFY_TIMEOUT = 300  # after a switch: DNS and rewrite must follow within this time
FAST_RECHECK = 5  # seconds between checks while a profile is failing or a switch is being verified
MAX_PROFILES = 8
HANDSHAKE_FRESH = 180
EVENTS = 50
NAME_MAX = 40


class Failover:
    def __init__(self, agent, clock=time.time):
        self.agent = agent
        self.clock = clock
        self.lock = threading.RLock()
        self.rt = {"fails": 0, "reason": "", "healthy": None, "last_switch": 0, "last_try_back": 0,
                   "tried": [], "all_down": 0, "events": []}

    # -- settings and profiles -----------------------------------------
    def settings(self, st=None):
        st = st or self.agent.store.get()
        out = dict(DEFAULTS)
        out.update({k: v for k, v in (st["proton"].get("failover") or {}).items() if k in DEFAULTS})
        return out

    def set_settings(self, body):
        cur = self.settings()
        try:
            fails = int(body.get("fails", cur["fails"]))
            hold = int(body.get("hold", cur["hold"]))
        except (TypeError, ValueError):
            raise ValidationError("Fehlversuche und Wartezeit müssen Zahlen sein.")
        if not 1 <= fails <= 20:
            raise ValidationError("Fehlversuche: 1 bis 20.")
        if not 0 <= hold <= 86400:
            raise ValidationError("Wartezeit: 0 bis 86400 Sekunden.")
        rotate = str(body.get("rotate", cur["rotate"]))
        rotate_at = str(body.get("rotate_at", cur["rotate_at"])).strip()
        try:
            rotate_hours = int(body.get("rotate_hours", cur["rotate_hours"]))
        except (TypeError, ValueError):
            raise ValidationError("Rotation: Stunden müssen eine Zahl sein.")
        if rotate not in ROTATE_MODES:
            raise ValidationError("Rotation: aus, täglich oder alle N Stunden.")
        if not ROTATE_AT_RE.fullmatch(rotate_at):
            raise ValidationError("Rotation: Uhrzeit als HH:MM, z. B. 04:00.")
        if not 1 <= rotate_hours <= 168:
            raise ValidationError("Rotation: 1 bis 168 Stunden.")
        new = {"fails": fails, "hold": hold, "prefer_primary": False, "standby": bool(body.get("standby", cur["standby"])),
               "rotate": rotate, "rotate_at": rotate_at, "rotate_hours": rotate_hours}
        upd = {"failover": new}
        if (rotate, rotate_at, rotate_hours) != (cur["rotate"], cur["rotate_at"], cur["rotate_hours"]):
            upd["last_rotate"] = int(self.clock())  # count from now, no rotation right after saving
        self.agent.store.update("proton", upd)
        if rotate != "off":
            log("vpn rotation: %s", "daily at %s" % rotate_at if rotate == "daily" else "every %d h" % rotate_hours)
        log("vpn failover: switch after %d failed checks, standby tunnel %s (hold %d s)",
            fails, "on" if new["standby"] else "off", hold)
        if new["standby"] != cur["standby"] and self.agent.rt["net"].get("applied"):
            self.agent.apply_network()  # standby tunnel up or down
        return {"ok": True, "failover": new}

    def _profiles(self, st=None):
        return [dict(p) for p in self.agent.profiles(st or self.agent.store.get())]

    def _save(self, profs, extra=None):
        values = {"profiles": profs}
        for key in ("conf", "server", "endpoint", "natpmp_hint", "mtu", "provider", "ports"):
            values[key] = None  # 0.9.x single-config fields: migrated into the profiles
        values.update(extra or {})
        with self.agent.store._lock:
            sec = self.agent.store.section("proton")
            sec.update(values)
            for key in [k for k, v in sec.items() if v is None]:
                del sec[key]
            self.agent.store.update("proton", sec, replace=True)

    def store_profile(self, body):
        """Add (no ``id``) or change a profile. Returns ``(profile, summary)``."""
        from .agent import PROVIDERS, Agent
        with self.lock:
            profs = self._profiles()
            pid = body.get("id") or ""
            cur = next((p for p in profs if p["id"] == pid), None)
            if pid and cur is None:
                raise ValidationError("Profil nicht gefunden.")
            if cur is None and len(profs) >= MAX_PROFILES:
                raise ValidationError("Höchstens %d VPN-Profile." % MAX_PROFILES)
            prof = dict(cur or {})
            provider = body.get("provider", prof.get("provider") or "proton")
            if provider not in PROVIDERS:
                raise ValidationError("Anbieter muss 'proton' oder 'fixed' (fester Port) sein.")
            prof["provider"] = provider
            prof["ports"] = Agent._fixed_ports(body.get("ports", prof.get("ports"))) if provider == "fixed" else []
            summary = {"server": prof.get("server"), "endpoint": prof.get("endpoint"),
                       "natpmp_hint": prof.get("natpmp_hint"), "removed": []}
            if body.get("conf"):
                cfg = protonconf.parse(body["conf"])
                prof.update({"conf": cfg.render(), "server": cfg.server, "endpoint": cfg.endpoint,
                             "natpmp_hint": cfg.natpmp_hint, "mtu": cfg.mtu})
                summary = cfg.summary()
            if "mtu" in body and body["mtu"] not in (None, ""):
                prof["mtu_setting"] = protonconf.mtu_setting(body["mtu"])
            prof.setdefault("mtu_setting", protonconf.MTU_DEFAULT)
            if not prof.get("conf"):
                raise ValidationError("Bitte die WireGuard-Datei (wg.conf) hochladen oder einfügen.")
            name = str(body.get("name") or prof.get("name") or prof.get("server") or "").strip()
            if not name:
                name = "Profil %d" % (len(profs) + (0 if cur else 1))
            if len(name) > NAME_MAX or any(ord(c) < 32 for c in name):
                raise ValidationError("Name: höchstens %d Zeichen." % NAME_MAX)
            prof["name"] = name
            if "enabled" in body:
                prof["enabled"] = bool(body["enabled"])
            prof.setdefault("enabled", True)
            if cur is None:
                used = {p["id"] for p in profs}
                prof["id"] = next("p%d" % i for i in range(1, 100) if "p%d" % i not in used)
                profs.append(prof)
            else:
                profs[profs.index(cur)] = prof
            self._save(profs)
        log("vpn profile %s '%s' stored (%s%s, server %s, endpoint %s, dropped: %s)", prof["id"], prof["name"],
            provider, " ports " + ",".join(map(str, prof["ports"])) if prof["ports"] else "",
            summary.get("server") or "-", summary.get("endpoint") or "-",
            ", ".join(summary.get("removed") or []) or "-")
        return prof, summary

    def save_profile(self, body):
        """API: store a profile; rebuild wg0 if the running profile changed or got a new config or MTU."""
        self.pin_active()
        act = self.agent.active_profile() or {}
        before, before_mtu = act.get("id"), protonconf.profile_mtu(act)[1]
        prof, summary = self.store_profile(body)
        after = self.agent.active_profile()
        out = {"ok": True, "profile": self._public(prof)}
        if not self.agent._proton_on():
            return out
        if after["id"] != before:
            res = self._standby_takes_over(act, "Profil '%s' ausgeschaltet" % act.get("name", "-"))
            if res:
                out.update(res)
                return out
        if after["id"] != before or (after["id"] == prof["id"] and (
                body.get("conf") or protonconf.profile_mtu(prof)[1] != before_mtu)):
            out.update(self.agent.start_profile(after, summary if after["id"] == prof["id"] else None))
            self.event("Profil '%s' aktiv (Einstellungen geändert)" % after["name"])
        else:
            self.agent.apply_network()  # ports changed (new DNAT) or another standby (0.19.0)
        return out

    def delete_profile(self, pid):
        self.pin_active()
        with self.lock:
            profs = self._profiles()
            prof = next((p for p in profs if p["id"] == pid), None)
            if prof is None:
                raise ValidationError("Profil nicht gefunden.")
            was_active = (self.agent.active_profile() or {}).get("id") == pid
            profs.remove(prof)
            self._save(profs)
        log("vpn profile %s '%s' deleted", pid, prof["name"])
        if was_active:
            res = self._standby_takes_over(prof, "Profil '%s' gelöscht" % prof["name"])
            if res:
                return dict(res, deleted=pid)
            nxt = self.agent.active_profile()
            if nxt and self.agent._proton_on():
                self.event("Profil '%s' gelöscht, weiter mit '%s'" % (prof["name"], nxt["name"]))
                return dict(self.agent.start_profile(nxt), deleted=pid)
        self.agent.apply_network()  # 0.22.0: also when the standby was deleted, the next one comes up
        return {"ok": True, "deleted": pid}

    def _standby_takes_over(self, prev, why):
        """The running profile was switched off or deleted (0.27.9, owner): the ready standby becomes the active
        tunnel, as on a failover, instead of rebuilding wg0 with the top profile of the list (no jump up, the
        list order stays the priority for the next standby). ``None`` if there is no ready standby."""
        sb = self.agent.standby.state.get("profile")
        usable = {p["id"] for p in self.agent.profiles(self.agent.store.get()) if p.get("conf") and p.get("enabled", True)}
        if not sb or sb == (prev or {}).get("id") or sb not in usable or not self.agent.standby.health()[0]:
            return None
        res = self._promoted(prev, why)
        return res if res.get("ok") else None

    def set_active(self, pid):
        """Store ``pid`` as the active profile; the list order (priority) stays as it is (0.24.0)."""
        with self.lock:
            st = self.agent.store.get()
            if not st["proton"].get("profiles"):
                self._save(self._profiles(st))
            self.agent.store.update("proton", {"active": pid})

    def pin_active(self):
        """Store the profile that really runs as the active one (0.27.9). Before, a switched-off active profile
        stayed stored, so the running one was "the first enabled one" and moved with every change of the list
        order or of another profile (the owner saw it jump to the top)."""
        with self.lock:
            st = self.agent.store.get()
            act = (self.agent.active_profile(st) or {}).get("id")
            if act and st["proton"].get("active") != act:
                self.set_active(act)

    def set_order(self, ids):
        self.pin_active()  # the order is the priority of the standby, it never moves the running profile
        with self.lock:
            profs = self._profiles()
            if not isinstance(ids, list) or sorted(map(str, ids)) != sorted(p["id"] for p in profs):
                raise ValidationError("Reihenfolge muss alle Profile genau einmal enthalten.")
            by_id = {p["id"]: p for p in profs}
            self._save([by_id[i] for i in ids])
        log("vpn profile order: %s", ", ".join(ids))
        if self.agent.rt["net"].get("applied"):
            self.agent.apply_network()  # the standby is the highest-priority profile that is not active
        return {"ok": True}

    def activate(self, pid, why="manuell"):
        """Make ``pid`` the running profile, rebuild wg0 and test it. Returns the start result."""
        with self.lock:
            st = self.agent.store.get()
            prof = next((p for p in self.agent.profiles(st) if p["id"] == pid), None)
            if prof is None or not prof.get("conf"):
                raise ValidationError("Profil nicht gefunden.")
            if not prof.get("enabled", True):
                raise ValidationError("Profil ist ausgeschaltet.")
            prev = self.agent.active_profile(st)
            now = int(self.clock())
            if self.agent.standby.state.get("profile") == pid and self.agent.standby.health()[0]:
                return self._promoted(prev, why)
            self.set_active(pid)
            self.rt.update({"fails": 0, "reason": "", "last_switch": now})
            res = self.agent.start_profile(prof)
            ok = bool(res.get("ok") and res["test"].get("exit_ip"))
            self.event("%s: %s -> %s (%s)" % (why, (prev or {}).get("name", "-"), prof["name"],
                                              "ok, Exit-IP %s" % res["test"]["exit_ip"] if ok
                                              else "Test fehlgeschlagen: %s" % (res["test"].get("error")
                                                                               or "Exit-IP unbekannt")))
            res["ok"] = ok
            self.rt["verify"] = {"since": now, "profile": prof["name"]} if ok else None
            if why.startswith("Failover"):
                self.agent.notify.event("vpn_switch", "VPN-Profilwechsel", "%s -> %s (%s)" % (
                    (prev or {}).get("name", "-"), prof["name"], "ok" if ok else "Test fehlgeschlagen"))
            elif why.startswith("Zurück zum bevorzugten") and ok:
                self.agent.notify.event("vpn_back", "Zurück zum bevorzugten VPN-Profil",
                                        "Profil '%s' läuft wieder" % prof["name"])
            return res

    def _promoted(self, prev, why):
        """Switch to the standby tunnel (it is ready). Returns a result like ``activate``."""
        now = int(self.clock())
        prof = self.agent.promote_standby()
        if prof is None:
            return {"ok": False, "test": {"ok": False, "error": "Reserve nicht bereit"}}
        self.rt.update({"fails": 0, "reason": "", "last_switch": now, "tried": [], "all_down": 0})
        ip = self.agent.rt["proton"].get("exit_ip", "")
        self.event("%s: %s -> %s (Reserve übernommen, Exit-IP %s)" % (why, (prev or {}).get("name", "-"),
                                                                     prof["name"], ip or "?"))
        self.rt["verify"] = {"since": now, "profile": prof["name"]}
        if why.startswith("Failover"):
            self.agent.notify.event("vpn_switch", "VPN-Profilwechsel", "%s -> %s (Reserve übernommen)" % (
                (prev or {}).get("name", "-"), prof["name"]))
        return {"ok": True, "enabled": True, "profile": prof["id"], "promoted": True,
                "test": {"ok": True, "exit_ip": ip, "server": prof.get("server", ""), "handshake": 0,
                         "endpoint": prof.get("endpoint", ""), "natpmp": prof.get("provider") != "fixed",
                         "error": ""}}

    def rotation_due(self, cfg, now, st):
        """Scheduled change to the next profile: daily at ``rotate_at`` (container time) or every N hours."""
        last = int(st["proton"].get("last_rotate") or 0)
        if cfg["rotate"] == "hours":
            return now - last >= cfg["rotate_hours"] * 3600
        if cfg["rotate"] != "daily":
            return False
        h, m = (int(x) for x in cfg["rotate_at"].split(":"))
        lt = time.localtime(now)
        slot = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, h, m, 0, 0, 0, -1)))
        if slot > now:
            slot -= 86400
        return last < slot

    def wait_hint(self):
        """Seconds until the next check: short while a profile is failing or a switch is being verified."""
        return FAST_RECHECK if (self.rt["fails"] and self.rt["healthy"] is False) or self.rt.get("verify") else None

    def verify(self, now=None):
        """After a switch: is the DNS record on the new exit IP and the rewrite on the new target?"""
        v = self.rt.get("verify")
        if not v:
            return None
        now = int(self.clock()) if now is None else now
        a, done, pending = self.agent, [], []
        if a.ddns.enabled():
            ip = a.ddns.resolve()[0]
            (done if ip and a.ddns.config().get("last_ip") == ip else pending).append("DNS %s" % (ip or "?"))
        for n in a.names.status():
            if n["role"] == "endpoint" and n["key_set"]:
                ok = bool(n["target"] and n["sent_ip"] == n["target"])
                (done if ok else pending).append("%s.%s %s" % (n["name"], n["domain"], n["target"] or "?"))
        rcfg = a.redirect.cfg()
        if rcfg.get("provider"):
            tgt = a.redirect.target(rcfg)
            ok = bool(tgt and rcfg.get("last_target") == tgt["url"])
            (done if ok else pending).append("Rewrite %s" % (tgt["url"] if tgt else "?"))
        if not pending:
            self.rt["verify"] = None
            if done:
                self.event("Nach Wechsel geprüft: %s" % ", ".join(done))
            return "verified"
        if now - v["since"] >= VERIFY_TIMEOUT:
            self.rt["verify"] = None
            text = "Nach Wechsel auf '%s' nicht nachgeführt: %s" % (v["profile"], ", ".join(pending))
            self.event(text)
            a.notify.event("vpn_verify", "VPN-Wechsel nicht vollständig", text)
            return "unverified"
        return "pending"

    # -- health and switching -------------------------------------------
    def health(self, st=None):
        """``(ok, reason)`` of the running profile; ``(None, "")`` without VPN."""
        a = self.agent
        st = st or a.store.get()
        if not a._proton_on(st):
            return None, ""
        if not a.net.link_exists(a.active_if):
            return False, "%s läuft nicht" % a.active_if
        age = a.handshake_age()
        if age is None or age >= HANDSHAKE_FRESH:
            return False, "kein frischer Handshake"
        if a.vpn_provider(st) == "proton":
            nat = a.natpmp.state if a.natpmp is not None else {}
            if nat.get("fails"):
                return False, "NAT-PMP antwortet nicht"
            if not a.rt["proton"].get("exit_ip"):
                return False, "Exit-IP unbekannt"
        elif not a.rt["proton"].get("exit_ip"):
            return False, "Exit-IP über wg0 nicht ermittelbar"
        return True, ""

    def tick(self):
        with self.lock:
            a = self.agent
            st = a.store.get()
            if not a._proton_on(st):
                self.rt.update({"fails": 0, "reason": "", "healthy": None, "tried": [], "all_down": 0})
                return None
            cfg = self.settings(st)
            now = int(self.clock())
            act = a.active_profile(st)
            usable = [p for p in a.profiles(st) if p.get("conf") and p.get("enabled", True)]
            if self.rt["fails"] and a.vpn_provider(st) == "fixed":
                a.refresh_exit_ip(force=True)
            ok, reason = self.health(st)
            if ok:
                if self.rt["healthy"] is False or self.rt["all_down"]:
                    self.event("Profil '%s' wieder in Ordnung" % act["name"])
                self.agent.notify.vpn_up(act["name"])
                self.rt.update({"fails": 0, "reason": "", "healthy": True, "tried": [], "all_down": 0})
                self.verify(now)
                if len(usable) > 1 and self.rotation_due(cfg, now, st):
                    a.store.update("proton", {"last_rotate": now})
                    # round robin: the next profile below the active one, wrapping around (0.24.0)
                    ids = [p["id"] for p in usable]
                    pos = ids.index(act["id"]) if act["id"] in ids else -1
                    nxt = usable[(pos + 1) % len(usable)]
                    res = self.activate(nxt["id"], "Rotation")
                    if res["ok"]:
                        a.notify.event("vpn_rotate", "VPN-Rotation", "%s -> %s" % (act["name"], nxt["name"]))
                    else:
                        self.activate(act["id"], "Rotation: '%s' gestört, zurück" % nxt["name"])
                    return "rotated"
                return "ok"
            self.rt["fails"] += 1
            self.rt["reason"] = reason
            self.rt["healthy"] = False
            if self.rt["fails"] < cfg["fails"]:
                return "failing"
            if a.standby.state.get("profile") and a.standby.health()[0]:
                res = self._promoted(act, "Failover nach %d Fehlern (%s)" % (self.rt["fails"], reason))
                if res["ok"]:
                    return "switched"
            if act["id"] not in self.rt["tried"]:
                self.rt["tried"].append(act["id"])
            ids = [p["id"] for p in usable]
            # priority order from the top, the active profile last (0.24.0)
            order = [i for i in ids if i != act["id"]] + ([act["id"]] if act["id"] in ids else [])
            candidates = [i for i in order if i not in self.rt["tried"]]
            if not candidates:
                if not self.rt["all_down"]:
                    self.rt["all_down"] = now
                    text = ("Alle VPN-Profile gestört (%s). Kein Verkehr über die Heimleitung; neuer Versuch "
                            "in %d s" % (reason, cfg["hold"]) if len(ids) > 1 else
                            "VPN-Profil '%s' gestört (%s), kein weiteres Profil" % (act["name"], reason))
                    self.event(text)
                    self.agent.notify.vpn_down(text + ". Updates werden vorgemerkt.")
                if len(ids) < 2 or now - self.rt["all_down"] < cfg["hold"]:
                    return "all-down"
                self.rt.update({"tried": [act["id"]], "all_down": 0})
                candidates = [i for i in order if i != act["id"]]
            nxt = next(p for p in usable if p["id"] == candidates[0])
            self.activate(nxt["id"], "Failover nach %d Fehlern (%s)" % (self.rt["fails"] or cfg["fails"], reason))
            return "switched"

    # -- status -----------------------------------------------------------
    def event(self, text):
        log("vpn: %s", text)
        self.rt["events"] = ([{"time": int(self.clock()), "text": text}] + self.rt["events"])[:EVENTS]

    @staticmethod
    def _public(p):
        return {"id": p["id"], "name": p.get("name", ""), "provider": p.get("provider") or "proton",
                "ports": p.get("ports") or [], "enabled": p.get("enabled", True), "server": p.get("server", ""),
                "endpoint": p.get("endpoint", ""), "natpmp_hint": p.get("natpmp_hint"),
                "mtu": protonconf.profile_mtu(p)[0], "mtu_effective": protonconf.profile_mtu(p)[1],
                "conf_mtu": p.get("mtu")}

    def listing(self, st=None):
        st = st or self.agent.store.get()
        act = (self.agent.active_profile(st) or {}).get("id")
        sb = self.agent.standby.state.get("profile")
        ready, reason = self.agent.standby.health() if sb else (False, "")
        if sb and not ready:
            reason = self.agent.standby.state.get("error") or reason
        return [dict(self._public(p), active=p["id"] == act, standby=p["id"] == sb,
                     standby_ready=p["id"] == sb and ready, standby_reason=reason if p["id"] == sb else "")
                for p in self.agent.profiles(st)]

    def status(self):
        out = self.settings()
        out.update({"fails_now": self.rt["fails"], "reason": self.rt["reason"], "healthy": self.rt["healthy"],
                    "last_switch": self.rt["last_switch"], "all_down": self.rt["all_down"],
                    "events": list(self.rt["events"]), "next_rotate": self.next_rotate(out),
                    "verifying": bool(self.rt.get("verify")), "standby_tunnel": self.agent.standby.status()})
        return out

    def next_rotate(self, cfg, st=None):
        """Timestamp of the next scheduled rotation, 0 when off."""
        st = st or self.agent.store.get()
        now = int(self.clock())
        if cfg["rotate"] == "hours":
            return max(now, int(st["proton"].get("last_rotate") or 0) + cfg["rotate_hours"] * 3600)
        if cfg["rotate"] != "daily":
            return 0
        h, m = (int(x) for x in cfg["rotate_at"].split(":"))
        lt = time.localtime(now)
        slot = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, h, m, 0, 0, 0, -1)))
        return slot if slot > now else slot + 86400


__all__ = ["Failover", "DEFAULTS", "validate"]
