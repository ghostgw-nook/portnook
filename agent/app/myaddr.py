"""myaddr.tools: DDNS (A record = Proton exit IP) and ACME DNS-01 challenge values.

API (verified in the open source github.com/brianshea2/addr.tools, internal/zones/myaddr/api.go):
``POST <base>/update`` with form fields ``key`` and either ``ip`` (an address or ``self`` = the
source address of the request) or ``acme_challenge`` (43 chars base64url), never both. Success is
HTTP 200 with the body ``OK``; errors are 4xx/5xx with a short text. The key is 43 or 64 characters.
Every added challenge value is served as TXT on all ``_acme-challenge`` names below the registered
name; several values coexist and expire by themselves after a few minutes. IP records become
inactive after 90 days without an update and the registration is deleted after 120 days, hence the
keepalive (an update at least every 30 days even if the IP did not change).

Which address is published (owner decision 2026-11-18, 0.9.1): the home line's public IP is never
sent, there is no opt-in. ``ip=self`` is never used (``update()`` refuses it). ``ip_mode``:

* ``vpn`` (default): the VPN exit IP (Proton or a provider with fixed ports); while the VPN is down or
  the exit IP unknown the optional ``fallback_ip`` (e.g. a hoster IP or 127.0.0.1); without one no
  update at all (the old record stays).
* ``manual``: always ``manual_ip``.
"""

import ipaddress
import os
import socket
import re
import threading
import time
import urllib.parse

from . import httpc, validate
from .log import log
from .validate import ValidationError

DEFAULT_URL = "https://myaddr.tools"
DOMAINS = ("myaddr.tools", "myaddr.dev", "myaddr.io")
# name rules from the myaddr source: 6-40 chars, starts with a letter, letters/digits/hyphens, no trailing hyphen
NAME_RE = re.compile(r"[a-z][a-z0-9-]{4,38}[a-z0-9]")
KEY_RE = re.compile(r"[A-Za-z0-9_-]{43}|[A-Za-z0-9_-]{64}")
CHALLENGE_RE = re.compile(r"[A-Za-z0-9_-]{43}")

KEEPALIVE = 30 * 86400          # update at least every 30 days
MODES = ("vpn", "manual")
DEFAULT_MODE = "vpn"
RETRY_MIN, RETRY_MAX = 300, 3600


class MyaddrError(Exception):
    """myaddr.tools refused or could not be reached; message is safe to show (no key)."""


def base_url():
    return (os.environ.get("PF_MYADDR_URL") or DEFAULT_URL).rstrip("/")


def check_name(name, domain):
    name = str(name or "").strip().lower()
    domain = str(domain or "").strip().lower()
    if not NAME_RE.fullmatch(name):
        raise ValidationError("Name: 6 bis 40 Zeichen, mit einem Buchstaben beginnend, nur a-z, 0-9 und '-'.")
    if domain not in DOMAINS:
        raise ValidationError("Domain muss eine von %s sein." % ", ".join(DOMAINS))
    return name, domain


def check_key(key):
    key = str(key or "").strip()
    if not KEY_RE.fullmatch(key):
        raise ValidationError("Der myaddr-Schlüssel hat 43 oder 64 Zeichen (Buchstaben, Ziffern, '-' und '_').")
    return key


def check_ip(value, what="IP-Adresse"):
    """IPv4 or IPv6 address as text (``ip=self`` is not an address)."""
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        raise ValidationError("%s ist keine gültige IPv4- oder IPv6-Adresse." % what)


def pids(value):
    """VPN profile ids of a name (0.25.0: several per name, stored comma separated; a list is accepted too)."""
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value or "").split(",")
    out = []
    for i in items:
        i = str(i or "").strip()
        if i and i not in out:
            out.append(i)
    return out


def check_pids(agent, value, label):
    """Validated profile ids as the stored string ``"p1,p2"`` (``""`` = none)."""
    ids = pids(value)
    known = {p["id"] for p in agent.profiles(agent.store.get())}
    for i in ids:
        if i not in known:
            raise ValidationError("VPN-Profil für %s nicht gefunden." % label)
    return ",".join(ids)


def mode_of(cfg):
    """Configured IP mode; anything unknown counts as ``vpn``."""
    mode = cfg.get("ip_mode")
    return mode if mode in MODES else DEFAULT_MODE


def update(key, ip=None, challenge=None, device=None, url=None, timeout=20, request=httpc.request):
    """One ``POST /update``. Exactly one of ``ip`` (an IPv4/IPv6 address) / ``challenge``.
    Raises ``MyaddrError``. ``ip=self`` (= the home IP without VPN) is refused.
    """
    if bool(ip) == bool(challenge):
        raise ValueError("ip xor challenge")
    if ip:
        ip = check_ip(ip)  # never "self"
    if challenge and not CHALLENGE_RE.fullmatch(challenge):
        raise ValueError("invalid challenge value")
    fields = {"key": key}
    if ip:
        fields["ip"] = ip
    else:
        fields["acme_challenge"] = challenge
    body = urllib.parse.urlencode(fields)
    try:
        resp = request("POST", (url or base_url()) + "/update", body=body, device=device, timeout=timeout,
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
    except httpc.HttpError as err:
        raise MyaddrError(str(err))
    text = " ".join(resp.text(200).split())
    if resp.status == 200 and text == "OK":
        return True
    raise MyaddrError("myaddr.tools antwortete HTTP %d%s" % (resp.status, (": " + text[:120]) if text else ""))


class Ddns:
    """Keeps ``<name>.<domain>`` pointing at the address chosen by ``ip_mode`` (see module docstring).

    ``tick()`` is called by the monitor loop (every 30 s) and on exit IP changes; it sends an update
    when the IP changed, the keepalive is due, or a retry after a failure is due.
    """

    def __init__(self, agent, clock=time.time, send=update):
        self.agent = agent
        self.clock = clock
        self.send = send
        self.lock = threading.Lock()
        self.rt = {"error": "", "last_try": 0, "next_try": 0, "fails": 0, "waiting": "", "queued": ""}

    def config(self):
        return self.agent.store.section("myaddr")

    def enabled(self, cfg=None):
        cfg = cfg if cfg is not None else self.config()
        return bool(cfg.get("ddns") and cfg.get("key") and cfg.get("name"))

    def resolve(self, cfg=None):
        """``(ip, source, reason)``: the address to publish and where it comes from
        (``vpn``, ``fallback``, ``manual``); ``ip == ""`` = do not update, ``reason`` says why.
        """
        cfg = cfg if cfg is not None else self.config()
        if mode_of(cfg) == "manual":
            ip = cfg.get("manual_ip") or ""
            return (ip, "manual", "") if ip else ("", "", "Keine manuelle IP gesetzt: kein Update")
        # 0.22.0: the base name can belong to a VPN profile like any other name: then always that exit IP
        if cfg.get("profile"):
            # 0.27.8: the tunnel this name serves; active and standby never share one name
            ip = self.agent.name_exit_ip("base")
            if not ip and self.agent.running_tunnels():
                return "", "", ("Kein freier Tunnel für die VPN-Profile dieses Namens (die laufenden Tunnel haben "
                                "schon einen Namen): kein Update, alter Eintrag bleibt")
        else:
            ip = self.agent.vpn_exit_ip()
        if ip:
            return ip, "vpn", ""
        if cfg.get("fallback_ip"):
            return cfg["fallback_ip"], "fallback", ""
        return "", "", "VPN aus oder Exit-IP unbekannt, keine Ersatz-IP: kein Update, alter Eintrag bleibt"

    def target_ip(self):
        return self.resolve()[0]

    def due(self, cfg, ip, now):
        if self.rt["fails"] and now < self.rt["next_try"]:
            return False
        last_ok = int(cfg.get("last_ok") or 0)
        return ip != cfg.get("last_ip") or now - last_ok >= KEEPALIVE

    def tick(self, force=False):
        with self.lock:
            cfg = self.config()
            if not self.enabled(cfg):
                self.rt.update({"error": "", "fails": 0, "waiting": ""})
                return {"ok": False, "skipped": "nicht eingerichtet"}
            now = int(self.clock())
            ip, source, reason = self.resolve(cfg)
            if not ip:
                self.rt["waiting"] = reason
                return {"ok": False, "skipped": reason}
            self.rt["waiting"] = ""
            if not force and not self.due(cfg, ip, now):
                self.rt["queued"] = ""
                return {"ok": True, "skipped": "aktuell"}
            if not self.agent.egress.allowed(base_url()):
                # no VPN tunnel: nothing to the internet; keep only the latest pending address (0.10.1)
                if self.rt["queued"] != ip:
                    log("ddns update for %s.%s to %s queued: no vpn tunnel", cfg["name"], cfg.get("domain"), ip)
                self.rt.update({"queued": ip, "waiting": "Kein VPN-Tunnel: Update auf %s vorgemerkt, wird "
                                                         "gesendet, sobald ein Tunnel steht" % ip})
                return {"ok": False, "queued": ip, "skipped": self.rt["waiting"]}
            self.rt["last_try"] = now
            self.rt["queued"] = ""
            try:
                device = self.agent.egress_device()
                self.send(cfg["key"], ip=ip, device=device)
            except Exception as err:  # MyaddrError, HttpError (EgressBlocked included)
                self.rt["fails"] += 1
                delay = min(RETRY_MAX, RETRY_MIN * 2 ** (self.rt["fails"] - 1))
                self.rt.update({"error": str(err)[:200], "next_try": now + delay})
                log("ddns update for %s.%s failed (%d in a row): %s", cfg["name"], cfg.get("domain"),
                    self.rt["fails"], self.rt["error"])
                self.agent.notify.event("ddns_error", "DDNS-Update fehlgeschlagen",
                                        "%s.%s: %s" % (cfg["name"], cfg.get("domain"), self.rt["error"]))
                return {"ok": False, "error": self.rt["error"]}
            if cfg.get("last_ip") != ip or self.rt["fails"]:
                log("ddns %s.%s -> %s (%s)", cfg["name"], cfg.get("domain"), ip, source)
            self.rt.update({"error": "", "fails": 0, "next_try": 0})
            self.agent.store.update("myaddr", {"last_ip": ip, "last_ok": now, "last_source": source})
            return {"ok": True, "ip": ip, "source": source}

    def reset(self):
        """Settings changed: retry at once."""
        self.rt.update({"error": "", "fails": 0, "next_try": 0, "waiting": ""})

    def retry_now(self):
        """Tunnel back: send a queued or failed update at once (no backoff)."""
        self.rt.update({"fails": 0, "next_try": 0})

    def status(self):
        cfg = self.config()
        ip, source, _ = self.resolve(cfg)
        last_ok = int(cfg.get("last_ok") or 0)
        return {"enabled": bool(cfg.get("ddns")), "configured": self.enabled(cfg),
                "ip_mode": mode_of(cfg), "fallback_ip": cfg.get("fallback_ip", ""),
                "manual_ip": cfg.get("manual_ip", ""), "target": ip, "source": source,
                "last_ip": cfg.get("last_ip", ""), "last_source": cfg.get("last_source", ""), "last_ok": last_ok,
                "last_try": self.rt["last_try"], "error": self.rt["error"], "waiting": self.rt["waiting"], "queued": self.rt["queued"],
                "next_update": last_ok + KEEPALIVE if last_ok else 0}


MAX_NAMES = 8
ROLES = ("entry", "endpoint")


class Names:
    """More myaddr names besides the main one, each with a role (0.13.0):

    * ``entry``: the stable entry (redirect/rewrite host), A record = fixed IP of that host (0.30.1: also a LAN IP).
      0.35.0 (owner): instead of an IP a host name (``host``), like a CNAME: myaddr has no CNAME records, so the
      name is looked up regularly and the A record follows its IPv4 address;
    * ``endpoint``: a further name of the connection, A record = the same address as the main name (VPN exit IP).
      0.19.0: an endpoint name may belong to a VPN profile (``profile``); its A record is then always the exit
      IP of that profile's tunnel (active or standby), and the redirect uses it while that profile is active.
      0.25.0 (owner): a name may belong to several profiles (``"p1,p2"``); its A record follows the one of them
      that is active, else the one that is the standby (ready to take over).
      0.27.8 (owner): active and standby never share a name; ``Agent.tunnel_names`` gives each running tunnel
      its own name, a name that serves no tunnel keeps its record.

    Every name gets an update when its address changes and at least every 30 days (myaddr deletes idle names).
    The second name of the redirect page (before 0.13.0) becomes the first ``entry`` name.
    """

    def __init__(self, agent, clock=time.time, send=update):
        self.agent = agent
        self.clock = clock
        self.send = send
        self.lock = threading.Lock()
        self.next_try = {}
        self.resolved = {}  # host -> (time, [IPv4]) of the last lookup (0.35.0)

    def items(self):
        self.migrate()
        return [dict(n) for n in self.agent.store.section("myaddr").get("extra") or []]

    def migrate(self):
        m2 = self.agent.store.section("redirect").get("myaddr2") or {}
        if not m2.get("name") or self.agent.store.section("myaddr").get("extra"):
            return
        entry = {"id": "n1", "role": "entry", **{k: m2[k] for k in ("name", "domain", "ip", "key", "last_ok",
                                                                    "sent_ip", "error") if k in m2}}
        self.agent.store.update("myaddr", {"extra": [entry]})
        self.agent.store.update("redirect", {"myaddr2": {}})
        log("myaddr: second redirect name %s.%s moved to the myaddr names (entry)", m2["name"], m2.get("domain"))

    def save(self, body):
        """Replace the list. Keys are write-only: an empty key keeps the stored one of the same id and name."""
        rows = body.get("names") if isinstance(body, dict) else None
        if not isinstance(rows, list) or len(rows) > MAX_NAMES:
            raise ValidationError("Höchstens %d weitere Namen." % MAX_NAMES)
        cur = {n["id"]: n for n in self.items()}
        out, seen = [], set()
        for row in rows:
            if not isinstance(row, dict):
                raise ValidationError("Ungültiger Eintrag.")
            name, domain = check_name(row.get("name"), row.get("domain"))
            if (name, domain) in seen:
                raise ValidationError("%s.%s ist doppelt." % (name, domain))
            seen.add((name, domain))
            role = str(row.get("role") or "")
            if role not in ROLES:
                raise ValidationError("Verwendung: Eingang oder Endpunkt.")
            old = cur.get(str(row.get("id") or ""), {})
            n = {"id": old.get("id") or self._new_id(cur, out), "name": name, "domain": domain, "role": role,
                 "cert": bool(row.get("cert", True))}  # 0.20.1: in the certificate (with *.), per name
            pid = check_pids(self.agent, row.get("profile"), "%s.%s" % (name, domain)) if role == "endpoint" else ""
            if pid:  # 0.27.8 (owner): several names may share profiles; Agent.tunnel_names keeps them apart
                n["profile"] = pid
            if role == "entry":
                value = str(row.get("ip") or "").strip().lower().rstrip(".")
                try:
                    n["ip"] = str(ipaddress.IPv4Address(value))  # 0.30.1: any IPv4, LAN too (owner)
                except ValueError:
                    # 0.35.0 (owner): a host name, like a CNAME; its IPv4 is looked up regularly
                    if not (validate.is_hostname(value) and "." in value):
                        raise ValidationError("Eingang %s.%s: IPv4-Adresse oder Hostname (z. B. 192.0.2.10 oder "
                                              "web.example.ch)." % (name, domain))
                    n["host"] = value
            if row.get("key"):
                n["key"] = check_key(row["key"])
            elif old.get("key") and (old.get("name"), old.get("domain")) == (name, domain):
                n["key"] = old["key"]
            else:
                raise ValidationError("Schlüssel für %s.%s fehlt." % (name, domain))
            if old and (old.get("name"), old.get("domain")) == (name, domain):
                n.update({k: old[k] for k in ("last_ok", "sent_ip", "error") if k in old})
            out.append(n)
        self.agent.store.update("myaddr", {"extra": out})
        self.next_try.clear()
        log("myaddr names: %s", ", ".join("%s.%s (%s)" % (n["name"], n["domain"], n["role"]) for n in out) or "none")
        self.agent.trigger_check()
        return {"ok": True}

    def save_all(self, body):
        """0.20.0, owner: all myaddr names in one list, each row says what it is for (entry or connection).
        The base name is chosen as described below and stored as the main myaddr name; the others are extra names.
        Keys stay write-only: an empty key keeps the stored key of that row (id ``main`` = the main name), also
        when a row changes its role, so the main name can move to another row without typing its key again."""
        rows = body.get("names") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            raise ValidationError("Ungültige Namensliste.")
        rows = [dict(r, role="endpoint") if isinstance(r, dict) and r.get("role") == "main" else r for r in rows]
        # 0.20.2, owner: no "main" role any more. The base name (DDNS without profile, certificate file name,
        # redirect fallback) is the first connection name without a VPN profile, else the first connection name.
        # 0.24.0: the UI sorts the names (entry first, then by role and alphabetically), so the row that already
        # is the base name (id ``main``) keeps that role when it still qualifies; the order alone never moves it.
        conn = [r for r in rows if isinstance(r, dict) and r.get("role") == "endpoint"]
        noprof = [r for r in conn if not r.get("profile")]
        group = noprof or conn
        mains = [r for r in group if r.get("id") == "main"][:1] or group[:1]
        if not mains:
            raise ValidationError("Mindestens ein Name braucht die Verwendung «Verbindung».")
        m = self.agent.store.section("myaddr")
        cur = {n["id"]: n for n in self.items()}
        if m.get("name"):
            cur["main"] = {"id": "main", "name": m["name"], "domain": m.get("domain"), "key": m.get("key", "")}

        def stored_key(row, name, domain):
            old = cur.get(str(row.get("id") or ""), {})
            return old.get("key") if (old.get("name"), old.get("domain")) == (name, domain) else ""

        main = mains[0]
        name, domain = check_name(main.get("name"), main.get("domain"))
        key = check_key(main["key"]) if main.get("key") else stored_key(main, name, domain)
        if not key:
            raise ValidationError("Schlüssel für %s.%s fehlt." % (name, domain))
        extra = []
        for row in rows:
            if row is main or not isinstance(row, dict):
                continue
            row = dict(row)
            if row.get("id") == "main" or (row.get("id") in cur and row.get("role") != cur[row["id"]].get("role")):
                n2, d2 = check_name(row.get("name"), row.get("domain"))
                row["key"] = row.get("key") or stored_key(row, n2, d2)  # carried over to the new place
                if row.get("id") == "main":
                    row["id"] = ""
            if (str(row.get("name") or "").strip().lower(), row.get("domain")) == (name, domain):
                raise ValidationError("%s.%s ist doppelt." % (name, domain))
            extra.append(row)
        main_body = {k: main[k] for k in ("ddns", "ip_mode", "fallback_ip", "manual_ip") if k in main}
        mode = main_body.get("ip_mode", m.get("ip_mode", DEFAULT_MODE))
        if mode == "manual" and not str(main_body.get("manual_ip", m.get("manual_ip")) or "").strip():
            raise ValidationError("Bitte die manuelle IP eintragen.")  # checked before anything is stored
        main_body.update(name=name, domain=domain,
                         profile=check_pids(self.agent, main.get("profile"), "%s.%s" % (name, domain)))
        if key != m.get("key") or (name, domain) != (m.get("name"), m.get("domain")):
            main_body["key"] = key
        self.save({"names": extra, "_main_profile": main_body["profile"]})
        out = self.agent.certs.set_myaddr(main_body)
        return {"ok": True, "fqdn": out["fqdn"]}

    @staticmethod
    def _new_id(cur, out):
        used = set(cur) | {n["id"] for n in out}
        return next("n%d" % i for i in range(1, 100) if "n%d" % i not in used)

    RESOLVE_EVERY = 300  # seconds between lookups of an entry host name

    def lookup(self, host):
        """IPv4 addresses of ``host`` (system resolver), sorted; ``[]`` if it has none."""
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            return []
        return sorted({i[4][0] for i in infos})

    def host_ip(self, n):
        """0.35.0: IPv4 of an entry's host name, looked up at most every ``RESOLVE_EVERY`` seconds. The address
        sent last stays as long as the name still has it (no flapping between several A records); an empty
        answer keeps the record (``""`` = nothing to send)."""
        host, now = n["host"], self.clock()
        at, ips = self.resolved.get(host, (None, []))
        if at is None or now - at >= self.RESOLVE_EVERY:
            had, ips = ips, self.lookup(host)
            self.resolved[host] = (now, ips)
            if not ips and (at is None or had):  # once, not every lookup
                log("myaddr %s.%s: %s has no IPv4 address", n["name"], n["domain"], host)
        if not ips:
            return ""
        return n.get("sent_ip") if n.get("sent_ip") in ips else ips[0]

    def ip_for(self, n):
        if n["role"] == "entry":
            return self.host_ip(n) if n.get("host") else n.get("ip", "")
        if n.get("profile"):
            # 0.19.0: the exit IP of that profile's tunnel; 0.27.8: of the tunnel this name serves (never both)
            return self.agent.name_exit_ip(n["id"])
        return self.agent.ddns.resolve()[0]

    def for_profile(self, pid):
        """``name.domain`` of the endpoint name that belongs to profile ``pid``, ``""`` if none.
        0.27.8: for a running profile the name that serves its tunnel (``Agent.tunnel_names``)."""
        for role, rpid, _ in self.agent.running_tunnels():
            if rpid == pid:
                fqdn = self.agent.tunnel_fqdn(role)
                if fqdn:
                    return fqdn
        m = self.agent.store.section("myaddr")
        if pid and m.get("name") and pid in pids(m.get("profile")):
            return "%s.%s" % (m["name"], m.get("domain"))
        for n in self.items():
            if pid and n["role"] == "endpoint" and pid in pids(n.get("profile")):
                return "%s.%s" % (n["name"], n["domain"])
        return ""

    def tick(self, force=False):
        with self.lock:
            names = self.items()
            if not names:
                return None
            now, changed = int(self.clock()), False
            for n in names:
                ip = self.ip_for(n)
                if not ip or not n.get("key"):
                    continue
                if not force and (now < self.next_try.get(n["id"], 0) or (
                        n.get("sent_ip") == ip and now - int(n.get("last_ok") or 0) < KEEPALIVE)):
                    continue
                if not self.agent.egress.allowed(base_url()):
                    return None  # no VPN tunnel: waits for the tunnel (0.10.1)
                try:
                    self.send(n["key"], ip=ip, device=self.agent.egress_device())
                    n.update({"last_ok": now, "sent_ip": ip, "error": ""})
                    self.next_try.pop(n["id"], None)
                    log("myaddr %s.%s (%s) -> %s", n["name"], n["domain"], n["role"], ip)
                except Exception as err:  # MyaddrError, HttpError
                    n["error"] = str(err)[:200]
                    self.next_try[n["id"]] = now + RETRY_MIN
                    log("myaddr %s.%s update failed: %s", n["name"], n["domain"], n["error"])
                    self.agent.notify.event("ddns_error", "myaddr-Update fehlgeschlagen",
                                            "%s.%s: %s" % (n["name"], n["domain"], n["error"]))
                changed = True
            if changed:
                self.agent.store.update("myaddr", {"extra": names})
            return changed

    def status(self):
        out = []
        for n in self.items():
            last = int(n.get("last_ok") or 0)
            out.append({"id": n["id"], "name": n["name"], "domain": n["domain"], "role": n["role"],
                        "cert": n.get("cert", True),
                        "profile": n.get("profile", ""),
                        "ip": n.get("host") or n.get("ip", ""), "host": n.get("host", ""), "key_set": bool(n.get("key")), "target": self.ip_for(n),
                        "sent_ip": n.get("sent_ip", ""), "last_ok": last, "error": n.get("error", ""),
                        "next_update": last + KEEPALIVE if last else 0})
        return out
