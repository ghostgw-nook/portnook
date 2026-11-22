"""Let's Encrypt wildcard certificate for ``<name>.<domain>`` + ``*.<name>.<domain>`` (myaddr.tools).

* ACME DNS-01 (app/acme.py); the TXT values are published through myaddr.tools (``acme_challenge``).
* Files in ``/data/certs``: ``fullchain.pem``, ``cert.pem``, ``chain.pem``, ``privkey.pem`` (600).
  The account key ``/data/acme/account.key`` (600) is kept; a new certificate key is made for every order.
* Renewal when fewer than 30 days are left (checked by the monitor loop), retry after a failure in 6 h.
* After every new certificate: delivery to NPM and/or the Zoraxy folder (app/delivery.py).
* Settings and the configuration setters for myaddr, certificate and delivery are here as well.
"""

import hashlib
import hmac
import io
import os
import secrets
import threading
import time
import zipfile

from . import acme, delivery, myaddr, sysrun
from .agent import SetupError, resolve_ipv4
from .log import log
from .validate import ValidationError

RENEW_DAYS = 30
RETRY_AFTER = 6 * 3600
FILES = ("fullchain.pem", "cert.pem", "chain.pem", "privkey.pem")
MAX_DELAY = 600


def directory_url(staging):
    override = os.environ.get("PF_ACME_DIRECTORY")
    if override:
        return override
    return acme.LE_STAGING if staging else acme.LE_PRODUCTION


class CertManager:
    def __init__(self, agent, clock=time.time, sleep=time.sleep, publish=None, request=None):
        self.agent = agent
        self.clock = clock
        self.sleep = sleep
        self.publish_fn = publish  # tests: replaces the myaddr acme_challenge call
        self.request = request  # tests: replaces httpc.request for ACME and NPM
        self.lock = threading.Lock()
        self.worker = None
        self.rt = {"running": False, "step": "", "queued": ""}
        self._info = None  # cached cert_info of the current fullchain

    # -- paths ----------------------------------------------------------
    @property
    def cert_dir(self):
        return os.path.join(self.agent.data_dir, "certs")

    @property
    def account_key(self):
        return os.path.join(self.agent.data_dir, "acme", "account.key")

    def path(self, name):
        return os.path.join(self.cert_dir, name)

    def read(self, name):
        with open(self.path(name), "r", encoding="ascii") as fh:
            return fh.read()

    def have_cert(self):
        return all(os.path.exists(self.path(n)) for n in ("fullchain.pem", "privkey.pem"))

    def info(self):
        if self._info is None and self.have_cert():
            try:
                self._info = acme.cert_info(self.read("fullchain.pem"))
            except (OSError, sysrun.SysRunError, ValueError) as err:
                log("certificate unreadable: %s", err)
                self._info = {}
        return self._info or {}

    # -- settings -------------------------------------------------------
    def set_myaddr(self, body):
        name, domain = myaddr.check_name(body.get("name"), body.get("domain"))
        values = {"name": name, "domain": domain}
        if "ddns" in body:
            values["ddns"] = bool(body.get("ddns"))
        key = body.get("key")
        current = self.agent.store.section("myaddr")
        if key:
            values["key"] = myaddr.check_key(key)
        elif not current.get("key"):
            raise ValidationError("Bitte den myaddr-Schlüssel eingeben (wird nur einmal angezeigt bei myaddr.tools).")
        if "profile" in body:  # 0.22.0: the base name can belong to a VPN profile
            values["profile"] = myaddr.check_pids(self.agent, body.get("profile"), "%s.%s" % (name, domain))
        if "ip_mode" in body:
            mode = str(body.get("ip_mode") or myaddr.DEFAULT_MODE)
            if mode not in myaddr.MODES:
                raise ValidationError("IP-Modus muss vpn oder manual sein.")
            values["ip_mode"] = mode
        for field, what in (("fallback_ip", "Ersatz-IP"), ("manual_ip", "Manuelle IP")):
            if field in body:
                text = str(body.get(field) or "").strip()
                values[field] = myaddr.check_ip(text, what) if text else ""
        merged = dict(current, **values)
        if myaddr.mode_of(merged) == "manual" and not merged.get("manual_ip"):
            raise ValidationError("Bitte die manuelle IP eintragen.")
        if (name, domain) != (current.get("name"), current.get("domain")) or key or \
                values.get("profile", current.get("profile", "")) != current.get("profile", ""):
            values.update({"last_ip": "", "last_ok": 0})
        self.agent.store.update("myaddr", values)
        self.agent.ddns.reset()
        log("myaddr set to %s.%s (ddns %s, ip mode %s%s)", name, domain, "on" if merged.get("ddns") else "off",
            myaddr.mode_of(merged), ", new key" if key else "")
        self.agent.trigger_check()
        return {"ok": True, "fqdn": "%s.%s" % (name, domain)}

    def set_cert(self, body):
        cur = self.agent.store.section("cert")
        values = {}
        if "staging" in body:
            values["staging"] = bool(body["staging"])
        if "auto" in body:
            values["auto"] = bool(body["auto"])
        if "email" in body:
            email = str(body.get("email") or "").strip()
            if email and (len(email) > 254 or "@" not in email or any(c in email for c in " \t\r\n,;<>\"'")):
                raise ValidationError("E-Mail-Adresse ungültig.")
            values["email"] = email
        if "delay" in body:
            try:
                delay = int(body["delay"])
            except (TypeError, ValueError):
                raise ValidationError("Wartezeit muss eine Zahl sein.")
            if not 0 <= delay <= MAX_DELAY:
                raise ValidationError("Wartezeit 0 bis %d Sekunden." % MAX_DELAY)
            values["delay"] = delay
        if "tos" in body:
            values["tos"] = bool(body["tos"])
        values["enabled"] = True
        self.agent.store.update("cert", values)
        merged = dict(cur, **values)
        log("certificate settings: %s, auto renew %s", "staging" if merged.get("staging") else "production",
            "on" if merged.get("auto") else "off")
        return {"ok": True}

    def set_delivery(self, body):
        cur = self.agent.store.section("delivery")
        out = {"npm": dict(cur.get("npm") or {}), "zoraxy": dict(cur.get("zoraxy") or {})}
        if "npm" in body:
            npm = body["npm"] if isinstance(body["npm"], dict) else {}
            if not npm.get("url"):
                out["npm"] = {}
            else:
                url = delivery.check_npm_url(npm.get("url"))
                identity = str(npm.get("identity") or "").strip()
                if not identity or len(identity) > 254:
                    raise ValidationError("NPM-Benutzer (E-Mail) fehlt.")
                new = {"url": url, "identity": identity,
                       "nice_name": str(npm.get("nice_name") or "").strip()[:100]}
                secret = npm.get("secret")
                if secret:
                    if len(str(secret)) > 256:
                        raise ValidationError("NPM-Passwort zu lang.")
                    new["secret"] = str(secret)
                elif out["npm"].get("secret") and out["npm"].get("url") == url and out["npm"].get("identity") == identity:
                    new["secret"] = out["npm"]["secret"]
                else:
                    raise ValidationError("NPM-Passwort fehlt.")
                if out["npm"].get("nice_name") == new["nice_name"]:
                    new["cert_id"] = out["npm"].get("cert_id")
                for k in ("last_ok", "last_try", "error"):
                    if k in out["npm"]:
                        new[k] = out["npm"][k]
                out["npm"] = new
        if "zoraxy" in body:
            z = body["zoraxy"] if isinstance(body["zoraxy"], dict) else {}
            out["zoraxy"] = {"dir": delivery.check_zoraxy_dir(z["dir"])} if z.get("dir") else {}
        self.agent.store.update("delivery", out, replace=False)
        log("delivery: npm %s, zoraxy %s", "on" if out["npm"] else "off", out["zoraxy"].get("dir") or "off")
        return {"ok": True}

    # -- pull token -----------------------------------------------------
    def new_pull_token(self):
        token = secrets.token_urlsafe(32)
        self.agent.store.update("cert", {"pull_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                                         "pull_token_created": int(self.clock())})
        log("certificate pull token created")
        return token

    def drop_pull_token(self):
        self.agent.store.update("cert", {"pull_token_sha256": "", "pull_token_created": 0})
        log("certificate pull token revoked")

    def check_pull_token(self, token):
        stored = self.agent.store.section("cert").get("pull_token_sha256") or ""
        if not stored or not token:
            return False
        return hmac.compare_digest(stored, hashlib.sha256(str(token).encode()).hexdigest())

    # -- downloads ------------------------------------------------------
    def download(self, name):
        """``(filename, content_type, bytes)`` for fullchain.pem, cert.pem, chain.pem, privkey.pem, cert.zip."""
        if not self.have_cert():
            raise SetupError("Noch kein Zertifikat vorhanden.")
        fqdn = (self.info().get("names") or [self.agent.fqdn() or "cert"])[0]
        if name in FILES:
            return name, "application/x-pem-file", self.read(name).encode("ascii")
        if name == "cert.zip":
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in FILES:
                    zf.writestr(f, self.read(f))
            return "%s.zip" % fqdn, "application/zip", buf.getvalue()
        raise KeyError(name)

    # -- issuance -------------------------------------------------------
    def name_keys(self):
        """``{fqdn: myaddr key}``: the main name and every further myaddr name with a key, entry names too
        (0.19.1, owner: one certificate for all names; 0.19.0 left the entry names out)."""
        fqdn = self.agent.fqdn()
        if not fqdn:
            return {}
        out = {fqdn: self.agent.store.section("myaddr").get("key", "")}
        for n in self.agent.names.items():
            if n.get("key") and n.get("cert", True):  # 0.20.1: each name can be left out
                out.setdefault("%s.%s" % (n["name"], n["domain"]), n["key"])
        return out

    def domains(self):
        out = []
        for name in self.name_keys():
            out += [name, "*." + name]
        return out

    def missing_names(self):
        """Names the stored certificate does not cover (a name was added): order a new one."""
        have = set(self.info().get("names") or [])
        return [d for d in self.domains() if d not in have] if have else []

    def start(self, reason="manual"):
        """Start an order in the background; SetupError if it cannot run now."""
        m = self.agent.store.section("myaddr")
        c = self.agent.store.section("cert")
        if not (m.get("name") and m.get("key")):
            raise SetupError("Zuerst Name und Schlüssel von myaddr.tools speichern.")
        if not c.get("tos"):
            raise SetupError("Bitte die Nutzungsbedingungen von Let's Encrypt akzeptieren.")
        directory = directory_url(c.get("staging", True))
        if not (self.agent.egress.allowed(directory) and self.agent.egress.allowed(myaddr.base_url())):
            # no VPN tunnel: no request to Let's Encrypt or myaddr.tools; the order starts with the tunnel (0.10.1)
            if not self.rt["queued"]:
                log("certificate order (%s) queued: no vpn tunnel", reason)
            self.rt["queued"] = reason
            return {"ok": True, "queued": True, "message": "Kein VPN-Tunnel: Bestellung vorgemerkt, sie startet, "
                                                           "sobald ein Tunnel steht."}
        with self.lock:
            if self.rt["running"]:
                raise SetupError("Ein Zertifikat wird bereits bestellt.")
            self.rt.update({"running": True, "step": "Start", "queued": ""})
            self.worker = threading.Thread(target=self._run, args=(reason,), name="acme", daemon=True)
            self.worker.start()
        return {"ok": True, "started": True}

    def _step(self, text):
        self.rt["step"] = text

    def _run(self, reason):
        now = int(self.clock())
        self.agent.store.update("cert", {"last_try": now})
        try:
            self.issue(reason)
        except Exception as err:  # AcmeError, MyaddrError, SetupError, SysRunError, HttpError
            text = str(err)[:300]
            log("certificate order failed: %s", text)
            self.agent.store.update("cert", {"last_error": text})
            self.agent.notify.event("cert_error", "Zertifikat fehlgeschlagen", text)
        finally:
            self.rt.update({"running": False, "step": ""})

    def issue(self, reason="manual"):
        """Blocking: order, store, deliver."""
        domains = self.domains()
        c = self.agent.store.section("cert")
        m = self.agent.store.section("myaddr")
        directory = directory_url(c.get("staging", True))
        cafile = os.environ.get("PF_ACME_CA_FILE") or None
        log("certificate order (%s) for %s at %s", reason, ", ".join(domains), directory)
        os.makedirs(os.path.dirname(self.account_key), mode=0o700, exist_ok=True)
        os.makedirs(self.cert_dir, mode=0o700, exist_ok=True)
        if not os.path.exists(self.account_key):
            acme.generate_key(self.account_key)
            log("acme account key created")
        device = self.agent.egress_device()
        kw = {"request": self.request} if self.request else {}
        client = acme.Client(directory, self.account_key, device=device, cafile=cafile, sleep=self.sleep, log=log, **kw)
        self._step("Konto")
        accounts = dict(self.agent.store.section("acme").get("accounts") or {})
        client.account(c.get("email", ""), agree=True)
        if accounts.get(directory) != client.kid:
            accounts[directory] = client.kid
            self.agent.store.update("acme", {"accounts": accounts})
            log("acme account ready")
        key_tmp = self.path("privkey.pem.new")
        acme.generate_key(key_tmp)
        csr = acme.csr_der(key_tmp, domains)

        keys = self.name_keys()

        def publish(values):
            self._step("TXT-Einträge bei myaddr.tools")
            for item in values:
                name, v = item if isinstance(item, tuple) else ("", item)
                if self.publish_fn:
                    self.publish_fn(v)
                else:
                    key = keys.get(name[2:] if name.startswith("*.") else name) or m["key"]
                    myaddr.update(key, challenge=v, device=self.agent.egress_device())
            log("acme: %d TXT value(s) published at myaddr.tools", len(values))
        publish.by_name = True

        def wait():
            delay = int(c.get("delay", 60))
            self._step("Warten auf DNS (%d s)" % delay)
            if delay:
                log("acme: waiting %d s for DNS propagation", delay)
                self.sleep(delay)
            self._step("Prüfung durch Let's Encrypt")

        pem = client.issue(domains, csr, publish, wait)
        self._step("Speichern")
        leaf, chain = acme.split_chain(pem)
        if not acme.key_matches(leaf, key_tmp):
            raise acme.AcmeError("Zertifikat passt nicht zum Schlüssel.")
        for name, data in (("fullchain.pem", pem), ("cert.pem", leaf), ("chain.pem", chain)):
            self._write(name, data, 0o644)
        os.replace(key_tmp, self.path("privkey.pem"))
        self._info = None
        info = self.info()
        self.agent.store.update("cert", {"last_ok": int(self.clock()), "last_error": "",
                                         "issued_staging": bool(c.get("staging", True)),
                                         "not_after": info.get("not_after", 0)})
        log("certificate stored for %s, valid until %s", ", ".join(info.get("names") or domains),
            time.strftime("%Y-%m-%d", time.gmtime(info.get("not_after", 0))))
        self.agent.notify.event("cert_renewed", "Zertifikat erneuert",
                                "%s, gültig bis %s" % (", ".join(info.get("names") or domains),
                                                     time.strftime("%Y-%m-%d", time.gmtime(info.get("not_after", 0)))))
        self._step("Übertragen")
        self.deliver()

    def _write(self, name, data, mode):
        tmp = self.path(name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, self.path(name))

    # -- delivery -------------------------------------------------------
    def deliver(self, only=None):
        """Push the current certificate to every configured target. Returns {target: result}."""
        if not self.have_cert():
            raise SetupError("Noch kein Zertifikat vorhanden.")
        cfg = self.agent.store.section("delivery")
        fullchain, key = self.read("fullchain.pem"), self.read("privkey.pem")
        fqdn = self.agent.fqdn() or (self.info().get("names") or ["cert"])[0]
        results = {}
        for target in ("npm", "zoraxy"):
            tc = dict(cfg.get(target) or {})
            if (only and target != only) or not (tc.get("url") or tc.get("dir")):
                continue
            now = int(self.clock())
            tc["last_try"] = now
            try:
                if target == "npm":
                    host = tc["url"].split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[0]
                    if not delivery.lan_host_ok(host, resolve_ipv4):
                        raise delivery.DeliveryError("NPM-Host %s ist keine private LAN-Adresse." % host)
                    if not tc.get("nice_name"):
                        tc["nice_name"] = delivery.NICE_DEFAULT % fqdn
                    kw = {"request": self.request} if self.request else {}
                    tc["cert_id"] = delivery.npm_push(tc, fullchain, key, device=self.agent.lan_device(), **kw)
                    detail = "Zertifikat #%d" % tc["cert_id"]
                else:
                    # 0.21.2, owner: one file pair per name in the certificate, so Zoraxy matches every
                    # host by its file name at once (no re-scan of its certificate list needed)
                    hosts = [fqdn] + sorted({n for n in self.info().get("names") or []
                                             if not n.startswith("*.") and n != fqdn})
                    names = []
                    for host in hosts:
                        names += delivery.zoraxy_write(tc["dir"], host, fullchain, key)
                    detail = ", ".join(names)
                tc.update({"last_ok": now, "error": "", "detail": detail})
                log("delivery %s ok (%s)", target, detail)
                results[target] = {"ok": True, "detail": detail}
            except (delivery.DeliveryError, acme.AcmeError, OSError) as err:
                tc["error"] = str(err)[:200]
                log("delivery %s failed: %s", target, tc["error"])
                self.agent.notify.event(target + "_error", "Übertragung an %s fehlgeschlagen"
                                        % ("NPM" if target == "npm" else "Zoraxy"), tc["error"])
                results[target] = {"ok": False, "error": tc["error"]}
            cur = self.agent.store.section("delivery")
            if (cur.get(target) or {}).get("url") == tc.get("url") and (cur.get(target) or {}).get("dir") == tc.get("dir"):
                self.agent.store.update("delivery", {target: tc})
        return results

    # -- periodic -------------------------------------------------------
    def days_left(self):
        na = self.info().get("not_after") or 0
        return (na - self.clock()) / 86400.0 if na else None

    def tick(self):
        """Monitor loop: start a renewal when due."""
        c = self.agent.store.section("cert")
        if self.rt["queued"] and not self.rt["running"]:
            try:
                return bool(self.start(self.rt["queued"]).get("started"))
            except SetupError as err:
                self.rt["queued"] = ""
                log("queued certificate order dropped: %s", err)
                return False
        if not (c.get("auto", True) and c.get("tos") and self.have_cert()) or self.rt["running"]:
            return False
        left = self.days_left()
        missing = self.missing_names()
        if (left is None or left >= RENEW_DAYS) and not missing:
            return False
        if c.get("last_error") and self.clock() - int(c.get("last_try") or 0) < RETRY_AFTER:
            return False
        why = ("new names %s" % ", ".join(missing)) if missing else "renewal, %d days left" % max(0, int(left))
        try:
            return bool(self.start(why).get("started"))
        except SetupError as err:
            log("certificate renewal not started: %s", err)
            return False

    # -- status ---------------------------------------------------------
    def status(self):
        c = self.agent.store.section("cert")
        info = self.info()
        left = self.days_left()
        return {"enabled": bool(c.get("enabled")), "staging": bool(c.get("staging", True)),
                "auto": bool(c.get("auto", True)), "email": c.get("email", ""), "delay": int(c.get("delay", 60)),
                "tos": bool(c.get("tos")), "present": self.have_cert(), "names": info.get("names", []),
                "issuer": info.get("issuer", ""), "not_after": info.get("not_after", 0),
                "days_left": round(left, 1) if left is not None else None,
                "issued_staging": bool(c.get("issued_staging")), "last_ok": int(c.get("last_ok") or 0),
                "last_try": int(c.get("last_try") or 0), "last_error": c.get("last_error", ""),
                "running": self.rt["running"], "step": self.rt["step"], "queued": bool(self.rt["queued"]),
                "pull_token": bool(c.get("pull_token_sha256")), "pull_token_created": int(c.get("pull_token_created") or 0),
                "directory": directory_url(c.get("staging", True)),
                "wanted": self.domains(), "missing": self.missing_names()}

    def delivery_status(self):
        cfg = self.agent.store.section("delivery")
        npm = cfg.get("npm") or {}
        z = cfg.get("zoraxy") or {}
        pick = ("last_ok", "last_try", "error", "detail")
        return {"npm": dict({"configured": bool(npm.get("url")), "url": npm.get("url", ""),
                             "identity": npm.get("identity", ""), "secret_set": bool(npm.get("secret")),
                             "nice_name": npm.get("nice_name", "")}, **{k: npm.get(k) for k in pick if k in npm}),
                "zoraxy": dict({"configured": bool(z.get("dir")), "dir": z.get("dir", "")},
                               **{k: z.get(k) for k in pick if k in z})}
