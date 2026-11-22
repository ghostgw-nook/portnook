"""Redirect host: a stable entry URL that answers 302 to ``https://<sub>.<fqdn>:<current VPN port>``.

myaddr.tools only serves DNS, it cannot redirect, and the Proton port changes now and then. On every change
of the target (exit IP / NAT-PMP port), once after saving and on demand the configured provider is run:

* ``cloudflare``: Single Redirect rule in the zone entry point ruleset of phase
  ``http_request_dynamic_redirect`` (Rulesets API). The agent finds its own rule by its description and
  updates it (PATCH) or adds it (POST); if the zone has no entry point ruleset yet it is created with PUT.
  Token permission: Zone > Single Redirect > Edit.
* ``script``: a shell script edited in the UI (stored in ``/data/redirect/script.sh``), run with
  ``PF_TARGET_URL``, ``PF_TARGET_HOST``, ``PF_PORT``, ``PF_IP``, ``PF_STATUS_CODE``, ``PF_ENTRY_HOST`` and
  ``PF_SSH_KEY`` / ``PF_KNOWN_HOSTS`` (key made or uploaded in the UI), timeout 60 s. Examples in
  ``agent/examples/`` (e.g. SSH to a Plesk web space and write ``.htaccess``).
  plus ``PF_RULES`` (one ``<entry host> <target URL>`` per line), ``PF_HTACCESS`` and ``PF_PHP`` (ready files
  for all rules, caching off).
More rules (0.13.0): further entry hosts, also ``*.<host>`` to ``*.<fqdn>`` (subdomain to subdomain, script only).
Further myaddr names (entry/endpoint) live in ``myaddr.Names``.
"""

import json
import os
import re
import subprocess
import threading
import time
import urllib.parse

from . import httpc, myaddr, sysrun, validate
from .agent import SetupError
from .log import log
from .validate import ValidationError

CF_API = "https://api.cloudflare.com/client/v4"
PHASE = "http_request_dynamic_redirect"
SCRIPT_TIMEOUT = 60
MAX_SCRIPT = 32 * 1024
OUTPUT_LINES = 50
RETRY = 300
MAX_RULES = 10
_ZONE_ID = re.compile(r"[0-9a-f]{32}")
_SUB = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def _host_re(entry):
    """Apache/PCRE host pattern; ``*.example.ch`` captures one label."""
    if entry.startswith("*."):
        return r"^([a-z0-9-]+)\." + entry[2:].replace(".", r"\.") + r"(:[0-9]+)?$"
    return "^" + entry.replace(".", r"\.") + r"(:[0-9]+)?$"


ADDR_CHARS = "0123456789abcdef"  # last character of an IPv4 (digit) or IPv6 (hex) client address


def _urls(url):
    return list(url) if isinstance(url, (list, tuple)) else [url]


def addr_groups(n):
    """0.28.0 round robin in ``.htaccess``: the clients are split by the last character of their address into
    ``n`` groups (digits and hex letters dealt out in turn), so one client always gets the same tunnel."""
    groups = [""] * n
    for i, ch in enumerate(ADDR_CHARS):
        groups[i % n] += ch
    return groups


def htaccess(rules, status):
    """``.htaccess`` for all rules: /.well-known/ stays local (certificate of the entry host), no caching.
    A rule with several target URLs (round robin, 0.28.0) gets one block per target with a condition on the
    client address; the last target takes the rest."""
    out = ["# managed by portnook, do not edit", "RewriteEngine On"]
    for entry, url in rules:
        urls = _urls(url)
        groups = addr_groups(len(urls))
        for i, u in enumerate(urls):
            # host condition last: %1 refers to the last matched condition
            out.append(r"RewriteCond %{REQUEST_URI} !^/\.well-known/")
            if i < len(urls) - 1:
                out.append("RewriteCond %%{REMOTE_ADDR} [%s]$ [NC]" % groups[i])
            out += ["RewriteCond %%{HTTP_HOST} %s [NC]" % _host_re(entry),
                    "RewriteRule ^(.*)$ %s/$1 [R=%d,L]" % (u.replace("*", "%1", 1), int(status))]
    out += ["", "<IfModule mod_headers.c>",
            '  Header always set Cache-Control "no-store, no-cache, must-revalidate, max-age=0"',
            '  Header always set Pragma "no-cache"', '  Header always set Expires "0"', "</IfModule>", ""]
    return "\n".join(out)


def php(rules, status):
    """``index.php`` for all rules (web spaces without .htaccess)."""
    # 0.28.0: every rule has a list of targets; with several, crc32 of the client address picks one (round robin,
    # the same client always gets the same tunnel)
    rows = ",\n".join("  ['/%s/i', [%s]]" % (_host_re(e).replace("/", r"\/"),
                                             ", ".join("'%s'" % x.replace("*", "$1", 1) for x in _urls(u))) for e, u in rules)
    return ("<?php\n// managed by portnook, do not edit\n"
            "header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');\n"
            "header('Pragma: no-cache');\nheader('Expires: 0');\n"
            "$host = strtolower($_SERVER['HTTP_HOST'] ?? '');\n$rules = [\n%s\n];\n"
            "foreach ($rules as $r) {\n  if (preg_match($r[0], $host)) {\n"
            "    $t = $r[1][count($r[1]) > 1 ? sprintf('%%u', crc32($_SERVER['REMOTE_ADDR'] ?? '')) %% count($r[1]) : 0];\n"
            "    header('Location: ' . preg_replace($r[0], $t, explode(':', $host)[0]) . $_SERVER['REQUEST_URI'], true, %d);\n"
            "    exit;\n  }\n}\nhttp_response_code(404);\n" % (rows, int(status)))


class RedirectError(Exception):
    """Provider failed; message safe for the UI (no tokens)."""


# -- script generator (0.16.0) -----------------------------------------
GEN_KINDS = {"htaccess": (".htaccess", "PF_HTACCESS"), "php": ("index.php", "PF_PHP")}
_SSH_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
_WEB_ROOT = re.compile(r"[A-Za-z0-9_.~][A-Za-z0-9_.~/-]{0,199}")


def check_gen(body):
    """Validate the generator fields. The values end up in single quotes in a shell script, so only plain
    characters are allowed (no quotes, spaces, ``$`` or ``..``)."""
    body = body if isinstance(body, dict) else {}
    kind = str(body.get("kind") or "")
    if not kind:
        return {"kind": ""}
    if kind not in GEN_KINDS:
        raise ValidationError("Unbekannte Skript-Art.")
    user = str(body.get("user") or "").strip()
    host = str(body.get("host") or "").strip().lower().rstrip(".")
    root = str(body.get("root") or "").strip().rstrip("/") or "."
    if not _SSH_USER.fullmatch(user):
        raise ValidationError("SSH-Benutzer: nur Buchstaben, Ziffern, '.', '_' und '-'.")
    if not validate.is_hostname(host):
        raise ValidationError("SSH-Host ungültig (z. B. server.example.ch).")
    if not _WEB_ROOT.fullmatch(root) or ".." in root.split("/"):
        raise ValidationError("Webverzeichnis: relativer Pfad wie httpdocs (ohne Leerzeichen und '..').")
    return {"kind": kind, "user": user, "host": host, "port": validate.port(body.get("port") or 22, "SSH-Port"),
            "root": root}


def _gen_head(g):
    return ("#!/bin/sh\n# Made by portnook (script generator). Change the values on the Weiterleitung page.\nset -eu\n"
            "SSH_USER='%s'\nSSH_HOST='%s'\nSSH_PORT='%d'\nWEB_ROOT='%s'\n"
            "ssh_run() {\n  ssh -i \"$PF_SSH_KEY\" -p \"$SSH_PORT\" -o BatchMode=yes -o ConnectTimeout=15 \\\n"
            "    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=\"$PF_KNOWN_HOSTS\" \"$SSH_USER@$SSH_HOST\" \"$1\"\n}\n"
            % (g["user"], g["host"], g["port"], g["root"]))


def generate(g):
    """The redirect script for generator settings ``g`` (from ``check_gen``)."""
    name, var = GEN_KINDS[g["kind"]]
    return (_gen_head(g) + "FILE='%s'\n" % name +
            "printf '%%s' \"$%s\" | ssh_run \"cat > '$WEB_ROOT/$FILE.pf-tmp' && mv '$WEB_ROOT/$FILE.pf-tmp' '$WEB_ROOT/$FILE'\"\n" % var +
            "echo \"Redirect gesetzt ($PF_STATUS_CODE):\"\nprintf '%s\\n' \"$PF_RULES\" | sed 's/ / -> /'\n")


def generate_test(g):
    """Write, read back and remove a test file in the web root; print the server key fingerprint."""
    return (_gen_head(g) +
            "ssh_run \"test -d '$WEB_ROOT' && echo portnook > '$WEB_ROOT/.pf-test' && cat '$WEB_ROOT/.pf-test' && rm '$WEB_ROOT/.pf-test'\"\n"
            "echo \"Verbindung ok, $WEB_ROOT ist beschreibbar.\"\n"
            "ssh-keygen -lf \"$PF_KNOWN_HOSTS\" | tail -n 1 | sed 's/^/Server-Schluessel: /' || true\n")


def cf_base():
    return (os.environ.get("PF_CLOUDFLARE_API") or CF_API).rstrip("/")


LEGACY_RULE_PREFIX = "pf-agent redirect "


def rule_description(entry_host):
    return "portnook redirect %s" % entry_host


def cf_rule(entry_host, target_base, status):
    """Redirect rule: host = entry_host -> target_base + path, query string kept."""
    return {
        "description": rule_description(entry_host),
        "expression": '(http.host eq "%s")' % entry_host,
        "action": "redirect",
        "action_parameters": {"from_value": {
            "status_code": int(status),
            "target_url": {"expression": 'concat("%s", http.request.uri.path)' % target_base},
            "preserve_query_string": True,
        }},
        "enabled": True,
    }


def _cf(request, method, url, token, device, body=None, ok404=False):
    try:
        resp = request(method, url, body=body, device=device, timeout=20,
                       headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    except httpc.HttpError as err:
        raise RedirectError("Cloudflare: %s" % err)
    if ok404 and resp.status == 404:
        return None
    data = resp.json()
    if resp.status >= 400 or not isinstance(data, dict) or data.get("success") is False:
        errs = data.get("errors") if isinstance(data, dict) else None
        msg = "; ".join(" ".join(str(e.get("message", "")).split())[:120] for e in errs[:2]
                        if isinstance(e, dict)) if isinstance(errs, list) else ""
        raise RedirectError("Cloudflare HTTP %d%s" % (resp.status, (": " + msg) if msg else ""))
    return data.get("result")


def cloudflare_apply(token, zone, entry_host, target_base, status, device=None, request=httpc.request):
    """Create or update the agent's redirect rule. Returns a short description."""
    base = cf_base()
    if not _ZONE_ID.fullmatch(zone):
        zones = _cf(request, "GET", base + "/zones?" + urllib.parse.urlencode({"name": zone}), token, device)
        if not zones:
            raise RedirectError("Cloudflare: Zone %s nicht gefunden (oder Zone-ID eintragen)." % zone)
        zone = zones[0]["id"]
    entry = "%s/zones/%s/rulesets/phases/%s/entrypoint" % (base, zone, PHASE)
    rule = cf_rule(entry_host, target_base, status)
    ruleset = _cf(request, "GET", entry, token, device, ok404=True)
    if ruleset is None:
        _cf(request, "PUT", entry, token, device, body={"rules": [rule]})
        return "Regel angelegt (neues Ruleset)"
    rid = ruleset.get("id")
    # rules made before the rename to portnook (0.27.0) carry the old description; they are taken over
    names = (rule["description"], LEGACY_RULE_PREFIX + rule["description"][len("portnook redirect "):])
    mine = [r for r in ruleset.get("rules") or [] if r.get("description") in names]
    if mine:
        _cf(request, "PATCH", "%s/zones/%s/rulesets/%s/rules/%s" % (base, zone, rid, mine[0]["id"]), token, device,
            body=rule)
        return "Regel aktualisiert"
    _cf(request, "POST", "%s/zones/%s/rulesets/%s/rules" % (base, zone, rid), token, device, body=rule)
    return "Regel angelegt"


class Redirect:
    def __init__(self, agent, clock=time.time, request=None):
        self.agent = agent
        self.clock = clock
        self.request = request
        self.lock = threading.Lock()
        self.rt = {"running": False, "next_try": 0, "next_try2": 0, "queued": ""}

    @property
    def dir(self):
        return os.path.join(self.agent.data_dir, "redirect")

    def _p(self, name):
        return os.path.join(self.dir, name)

    def cfg(self):
        return self.agent.store.section("redirect")

    # -- target ---------------------------------------------------------
    def target(self, cfg=None):
        """``{"url", "host", "port", "ip"}`` or ``None`` while port/IP are unknown.

        The target host is a name below ``<name>.<domain>``, so it resolves to what the DDNS publishes;
        the same rule as name 1 applies (``Ddns.resolve``): without an address (mode ``vpn``, VPN down,
        no fallback IP) nothing is applied, so the target never points at the home IP.
        """
        cfg = cfg if cfg is not None else self.cfg()
        fqdn = self.agent.fqdn()
        if not fqdn:
            return None
        own = self.active_name()
        # 0.19.0: the active profile's own name points at its exit IP all the time, no DNS change to wait for
        ip = self.agent.vpn_exit_ip() if own else self.agent.ddns.resolve()[0]
        if not ip:
            return None
        port = self.agent.public_port() if self.agent._proton_on() else int(cfg.get("fixed_port") or 0)
        if not port:
            return None
        base = self.base_for(cfg.get("to"), own)
        host = ("%s.%s" % (cfg["sub"], base)) if cfg.get("sub") else base
        return {"url": "https://%s:%d" % (host, port), "host": host, "port": port, "ip": ip}

    def active_name(self):
        """Name of the active VPN profile (``""`` without VPN or without a name for that profile)."""
        if not self.agent._proton_on():
            return ""
        return self.agent.names.for_profile((self.agent.active_profile() or {}).get("id"))

    def profile_names(self):
        """Endpoint names that belong to a VPN profile; they follow the active profile (0.23.1)."""
        m = self.agent.store.section("myaddr")
        out = {self.agent.fqdn()} if m.get("profile") else set()
        return out | {"%s.%s" % (n["name"], n["domain"]) for n in self.agent.names.status()
                      if n["role"] == "endpoint" and n.get("profile")}

    def base_for(self, to, own=None):
        """Target name of a rule: a profile's name (or the main name) becomes the active profile's name,
        so the host matches the port of the active tunnel after a failover; other names stay fixed."""
        own = self.active_name() if own is None else own
        base = self.fqdn_for(to)
        return own if own and (not to or base in self.profile_names()) else base

    def endpoints(self):
        """Names a target may use: the main name and every further myaddr name with the role endpoint."""
        return [self.agent.fqdn()] + ["%s.%s" % (n["name"], n["domain"]) for n in self.agent.names.status()
                                      if n["role"] == "endpoint"]

    def fqdn_for(self, to):
        """Target name: ``to`` if it is still an endpoint name, else the main name."""
        return to if to and to in self.endpoints()[1:] else self.agent.fqdn()

    def _to(self, value):
        to = str(value or "").strip().lower()
        if to and to not in self.endpoints()[1:]:
            raise ValidationError("Ziel-Name %s ist kein myaddr-Name mit Verwendung Endpunkt." % to)
        return to

    # -- settings -------------------------------------------------------
    def set_config(self, body):
        cur = self.cfg()
        provider = str(body.get("provider") or "")
        if provider not in ("", "cloudflare", "script"):
            raise ValidationError("Unbekannter Anbieter.")
        new = {"provider": provider}
        sub = str(body.get("sub") or "").strip().lower()
        if sub and not _SUB.fullmatch(sub):
            raise ValidationError("Subdomain des Ziels: nur a-z, 0-9 und '-'.")
        new["sub"] = sub
        new["to"] = self._to(body.get("to"))
        mode = str(body.get("mode") or cur.get("mode") or "failover")
        if mode not in ("failover", "roundrobin"):
            raise ValidationError("Modus: failover oder roundrobin.")
        if mode == "roundrobin" and provider != "script":
            raise ValidationError("Clients verteilen (Round Robin) geht nur mit Skript (.htaccess oder index.php), "
                                  "nicht mit Cloudflare.")
        new["mode"] = mode
        try:
            new["status"] = int(body.get("status") or 302)
        except (TypeError, ValueError):
            new["status"] = 0
        if new["status"] not in (301, 302, 307, 308):
            raise ValidationError("Statuscode 301, 302, 307 oder 308.")
        fixed = body.get("fixed_port")
        new["fixed_port"] = validate.port(fixed, "Fester Port") if fixed not in (None, "", 0) else 0
        entry = str(body.get("entry_host") or "").strip().lower().rstrip(".")
        if provider and not (validate.is_hostname(entry) and "." in entry):
            raise ValidationError("Eingangs-Host (z. B. start.example.ch) fehlt oder ist ungültig.")
        new["entry_host"] = entry
        cf = dict(cur.get("cf") or {})
        if provider == "cloudflare":
            zone = str((body.get("cf") or {}).get("zone") or "").strip().lower()
            if not (_ZONE_ID.fullmatch(zone) or validate.is_hostname(zone)):
                raise ValidationError("Cloudflare-Zone: Zone-ID oder Domain.")
            token = str((body.get("cf") or {}).get("token") or "").strip()
            if token:
                if not re.fullmatch(r"[A-Za-z0-9_-]{20,200}", token):
                    raise ValidationError("Cloudflare-API-Token ungültig.")
                cf["token"] = token
            elif not cf.get("token"):
                raise ValidationError("Cloudflare-API-Token fehlt.")
            cf["zone"] = zone
        new["cf"] = cf
        gen = check_gen(body["gen"]) if "gen" in body else (cur.get("gen") or {"kind": ""})
        new["gen"] = gen
        if provider == "script" and gen.get("kind"):
            self._write("script.sh", generate(gen), 0o700)
        elif "script" in body:
            text = str(body.get("script") or "").replace("\r\n", "\n")
            if len(text.encode()) > MAX_SCRIPT:
                raise ValidationError("Skript zu gross (max. 32 KiB).")
            self._write("script.sh", text, 0o700)
        if provider == "script" and not os.path.exists(self._p("script.sh")):
            raise ValidationError("Bitte ein Skript eintragen.")
        new["rules"] = self._rules(body.get("rules", cur.get("rules") or []), provider)
        for r in new["rules"]:
            r["to"] = self._to(r.get("to"))
        for k in ("last_target", "last_ok", "last_try", "last_error", "last_detail", "last_rc", "last_output"):
            if k in cur:
                new[k] = cur[k]
        new["last_target"] = ""  # run once after saving
        self.agent.store.update("redirect", new, replace=True)
        log("redirect: provider %s, entry %s", provider or "off", entry or "-")
        self.rt.update({"next_try": 0, "next_try2": 0})
        self.agent.trigger_check()
        return {"ok": True}

    @staticmethod
    def _rules(rows, provider):  # "to" is checked by set_config
        """More entry hosts: ``{"entry": "eingang-muster.myaddr.io" or "*.eingang-muster.myaddr.io", "sub": "tv" / "" / "*"}``."""
        if not isinstance(rows, list) or len(rows) > MAX_RULES:
            raise ValidationError("Höchstens %d weitere Regeln." % MAX_RULES)
        out = []
        for row in rows:
            row = row if isinstance(row, dict) else {}
            entry = str(row.get("entry") or "").strip().lower().rstrip(".")
            sub = str(row.get("sub") or "").strip().lower()
            if not entry:
                continue
            wild = entry.startswith("*.")
            base = entry[2:] if wild else entry
            if not (validate.is_hostname(base) and "." in base):
                raise ValidationError("Eingang %s ungültig (z. B. eingang-muster.myaddr.io oder *.eingang-muster.myaddr.io)." % entry)
            if sub == "*" and not wild:
                raise ValidationError("Ziel * (gleiche Subdomain) nur mit Eingang *.host.")
            if sub not in ("", "*") and not _SUB.fullmatch(sub):
                raise ValidationError("Ziel-Subdomain %s: nur a-z, 0-9 und '-'." % sub)
            if wild and provider == "cloudflare":
                raise ValidationError("Cloudflare: nur feste Eingangs-Hosts, *.host nur mit Skript.")
            out.append({"entry": entry, "sub": sub, "to": row.get("to")})
        return out

    def mappings(self, cfg, tgt):
        """``[(entry host, target URL)]``: the main entry first, then the rules (``*`` = same subdomain)."""
        return [(e, urls[0]) for e, urls in self.mappings_multi(cfg, tgt, rr=False)]

    def rr_standby(self, cfg=None):
        """0.28.0 (owner): ``(name, port)`` of the standby tunnel when the clients are shared between the active
        tunnel and the standby (mode ``roundrobin``), ``None`` when it does not take part: mode off, standby not
        ready, no TCP port, or no name of its own (every tunnel needs its own connection name)."""
        cfg = cfg if cfg is not None else self.cfg()
        if cfg.get("mode") != "roundrobin" or not self.agent._proton_on():
            return None
        sb = self.agent.standby
        if not sb.state.get("profile") or not sb.health()[0]:
            return None
        name, ports = self.agent.tunnel_fqdn("standby"), sb.ports()
        if not name or not ports or name == self.active_name():
            return None
        return name, int(ports[0])

    def rr_state(self, cfg=None):
        """Why the round robin does (not) share right now, for the UI."""
        cfg = cfg if cfg is not None else self.cfg()
        if cfg.get("mode") != "roundrobin":
            return ""
        if self.rr_standby(cfg):
            return "on"
        sb = self.agent.standby
        if not sb.state.get("profile") or not sb.health()[0]:
            return "no_standby"
        if not self.agent.tunnel_fqdn("standby"):
            return "no_name"
        return "no_port"

    def mappings_multi(self, cfg, tgt, rr=True):
        """``[(entry host, [target URLs])]``. One URL per rule, or (round robin, 0.28.0) one per tunnel for rules
        that follow the profile names: the active tunnel first, then the standby. Fixed names stay single."""
        own = self.active_name()
        tunnels = [(own, tgt["port"])]
        extra = self.rr_standby(cfg) if rr else None
        if extra:
            tunnels.append(extra)

        def urls(to, sub, first_url=None):
            out = []
            for i, (name, port) in enumerate(tunnels):
                base = self.base_for(to, name) if (name or i == 0) else None
                if base is None:
                    continue
                host = ("%s.%s" % (sub, base)) if sub else base
                u = first_url if (i == 0 and first_url) else "https://%s:%d" % (host, port)
                if u not in out:
                    out.append(u)
            return out

        out = [(cfg.get("entry_host", ""), urls(cfg.get("to"), cfg.get("sub"), tgt["url"]))]
        # fixed hosts before *.host, so app.eingang-muster... wins over *.eingang-muster... (0.23.0)
        for r in sorted(cfg.get("rules") or [], key=lambda r: r["entry"].startswith("*.")):
            out.append((r["entry"], urls(r.get("to"), r["sub"])))
        return out

    def script_text(self):
        try:
            with open(self._p("script.sh"), encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    @staticmethod
    def example(name):
        if name not in ("plesk-htaccess", "php-index"):
            raise KeyError(name)
        with open(os.path.join(EXAMPLES, "redirect-%s.sh" % name), encoding="utf-8") as fh:
            return fh.read()

    def _write(self, name, text, mode):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        tmp = self._p(name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, self._p(name))

    # -- SSH key for the script ------------------------------------------
    def ssh_generate(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        for f in ("id_ed25519", "id_ed25519.pub"):
            try:
                os.unlink(self._p(f))
            except FileNotFoundError:
                pass
        sysrun.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "portnook", "-f", self._p("id_ed25519")])
        os.chmod(self._p("id_ed25519"), 0o600)
        log("redirect: ssh key generated")
        return {"ok": True, "public_key": self.ssh_public()}

    def ssh_upload(self, text):
        text = str(text or "").replace("\r\n", "\n").strip() + "\n"
        if len(text) > 16384 or not re.match(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\n", text):
            raise ValidationError("Kein privater SSH-Schlüssel (-----BEGIN ... PRIVATE KEY-----).")
        self._write("id_ed25519.tmpkey", text, 0o600)
        try:
            pub = sysrun.run(["ssh-keygen", "-y", "-f", self._p("id_ed25519.tmpkey")], input="").stdout.strip()
        except sysrun.SysRunError:
            os.unlink(self._p("id_ed25519.tmpkey"))
            raise ValidationError("Schlüssel nicht lesbar (mit Passphrase geschützt?). Bitte ohne Passphrase.")
        os.replace(self._p("id_ed25519.tmpkey"), self._p("id_ed25519"))
        self._write("id_ed25519.pub", pub + "\n", 0o644)
        log("redirect: ssh key uploaded")
        return {"ok": True, "public_key": self.ssh_public()}

    def ssh_public(self):
        try:
            with open(self._p("id_ed25519.pub"), encoding="ascii") as fh:
                return fh.read().strip()
        except OSError:
            return ""

    # -- run ------------------------------------------------------------
    def _base_env(self):
        return {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": self.dir,
                "PF_SSH_KEY": self._p("id_ed25519"), "PF_KNOWN_HOSTS": self._p("known_hosts")}

    def run_test(self, body):
        """Test the SSH connection of the generator settings in ``body`` (not saved)."""
        g = check_gen(body)
        if not g["kind"]:
            raise ValidationError("Bitte zuerst .htaccess oder index.php wählen.")
        if not self.ssh_public():
            raise ValidationError("Zuerst einen SSH-Schlüssel erzeugen oder hochladen.")
        self._write("test.sh", generate_test(g), 0o700)
        rc, lines = self._exec(self._p("test.sh"), self._base_env())
        log("redirect: ssh test %s@%s rc=%s", g["user"], g["host"], rc)
        return {"ok": rc == 0, "rc": rc, "output": lines}

    def run_script(self, tgt, cfg):
        path = self._p("script.sh")
        if not os.path.exists(path):
            raise RedirectError("Kein Skript gespeichert.")
        env = dict(self._base_env())
        env.update({"PF_TARGET_URL": tgt["url"], "PF_TARGET_HOST": tgt["host"], "PF_PORT": str(tgt["port"]),
               "PF_IP": tgt["ip"], "PF_STATUS_CODE": str(cfg.get("status", 302)),
               "PF_ENTRY_HOST": cfg.get("entry_host", "")})
        rules = self.mappings_multi(cfg, tgt)
        env.update({"PF_RULES": "\n".join("%s %s" % (e, " | ".join(u)) for e, u in rules),
                    "PF_HTACCESS": htaccess(rules, cfg.get("status", 302)), "PF_PHP": php(rules, cfg.get("status", 302))})
        return self._exec(path, env)

    def _exec(self, path, env):
        try:
            proc = subprocess.run(["/bin/sh", path], cwd=self.dir, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=SCRIPT_TIMEOUT)
            rc, out = proc.returncode, proc.stdout
        except subprocess.TimeoutExpired as err:
            rc, out = -1, (err.stdout or b"") + b"\n[portnook] timeout after %d s" % SCRIPT_TIMEOUT
        except OSError as err:
            raise RedirectError("Skript nicht startbar: %s" % (err.strerror or err))
        lines = out.decode("utf-8", "replace").splitlines()[-OUTPUT_LINES:]
        return rc, lines

    def apply(self, force=False):
        """Run the provider if the target changed (or ``force``). Returns a result dict."""
        with self.lock:
            cfg = self.cfg()
            provider = cfg.get("provider")
            if not provider:
                return {"ok": False, "skipped": "kein Anbieter"}
            tgt = self.target(cfg)
            if not tgt:
                return {"ok": False, "skipped": "Ziel unbekannt (Port, Name oder IP fehlt)"}
            now = int(self.clock())
            rules = json.dumps(self.mappings_multi(cfg, tgt) if provider == "script" else self.mappings(cfg, tgt))
            # 0.27.13 (owner): set the redirect once after every start, even if the stored target is the same, so
            # the entry host is surely right after an update or restart (one script run / Cloudflare call)
            fresh = not self.rt.get("set_since_start")  # a failed run still waits for RETRY
            if not force and ((not fresh and tgt["url"] == cfg.get("last_target") and rules == cfg.get("last_rules", rules))
                              or now < self.rt["next_try"]):
                return {"ok": True, "skipped": "aktuell"}
            if not self.may_run(provider):
                # no VPN tunnel: Cloudflare / the script are not contacted; the latest target waits (0.10.1)
                if self.rt.get("queued") != tgt["url"]:
                    log("redirect to %s queued: no vpn tunnel", tgt["url"])
                self.rt["queued"] = tgt["url"]
                return {"ok": False, "queued": tgt["url"],
                        "skipped": "kein VPN-Tunnel, Ziel %s vorgemerkt" % tgt["url"]}
            self.rt["queued"] = ""
            upd = {"last_try": now}
            try:
                if provider == "cloudflare":
                    cf = cfg.get("cf") or {}
                    kw = {"request": self.request} if self.request else {}
                    detail = "; ".join("%s: %s" % (e, cloudflare_apply(cf["token"], cf["zone"], e, u, cfg.get("status", 302),
                                                                        device=self.agent.egress_device(), **kw))
                                       for e, u in self.mappings(cfg, tgt))
                    upd.update({"last_rc": 0, "last_output": []})
                else:
                    rc, lines = self.run_script(tgt, cfg)
                    upd.update({"last_rc": rc, "last_output": lines})
                    for line in lines[-5:]:
                        log("redirect script: %s", line[:200])
                    if rc != 0:
                        raise RedirectError("Skript beendet mit Code %d" % rc)
                    detail = "Skript ok"
                upd.update({"last_target": tgt["url"], "last_rules": rules, "last_ok": now, "last_error": "", "last_detail": detail})
                self.rt["next_try"] = 0
                self.rt["set_since_start"] = True
                log("redirect %s -> %s (%s)", cfg.get("entry_host"), tgt["url"], detail)
                result = {"ok": True, "target": tgt["url"], "detail": detail}
            except (RedirectError, SetupError, myaddr.MyaddrError) as err:
                upd["last_error"] = str(err)[:200]
                self.rt["next_try"] = now + RETRY
                log("redirect failed: %s", upd["last_error"])
                self.agent.notify.event("redirect_error", "Redirect fehlgeschlagen", upd["last_error"])
                result = {"ok": False, "error": upd["last_error"], "rc": upd.get("last_rc")}
            if self.cfg().get("provider") == provider:
                self.agent.store.update("redirect", upd)
            result["output"] = upd.get("last_output", [])
            return result

    def may_run(self, provider):
        """Cloudflare only with a working tunnel (or a LAN test stand-in). The script cannot be bound to an
        interface: with a VPN it runs only while the tunnel is up; without any VPN it runs, and the PF_OUT
        firewall chain limits it to private (LAN) addresses."""
        if provider == "cloudflare":
            return self.agent.egress.allowed(cf_base())
        return self.agent.egress.tunnel_up() or not self.agent._proton_on()

    def tick(self):
        return self.apply()

    def status(self):
        cfg = self.cfg()
        tgt = self.target(cfg)
        cf = cfg.get("cf") or {}
        return {"provider": cfg.get("provider", ""), "entry_host": cfg.get("entry_host", ""), "sub": cfg.get("sub", ""),
                "status": cfg.get("status", 302), "fixed_port": cfg.get("fixed_port", 0),
                "cf": {"zone": cf.get("zone", ""), "token_set": bool(cf.get("token"))},
                "target": tgt["url"] if tgt else "", "last_target": cfg.get("last_target", ""),
                "last_ok": cfg.get("last_ok", 0), "last_try": cfg.get("last_try", 0),
                "last_error": cfg.get("last_error", ""), "last_detail": cfg.get("last_detail", ""),
                "last_rc": cfg.get("last_rc"), "last_output": cfg.get("last_output", []),
                "queued": self.rt.get("queued", ""),
                "ssh_public_key": self.ssh_public(), "gen": cfg.get("gen") or {"kind": ""},
                "rules": cfg.get("rules") or [], "to": cfg.get("to", ""), "endpoints": self.endpoints(),
                "active_name": self.active_name(), "profile_names": sorted(self.profile_names()),
                "mode": cfg.get("mode", "failover"), "rr": self.rr_state(cfg),
                "mappings": [{"entry": e, "target": u[0], "targets": u}
                             for e, u in self.mappings_multi(cfg, tgt)] if tgt else []}
