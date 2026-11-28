"""Push ping: publish one sealed drop per device on the zero-trust host (WebDAV PUT/DELETE).

Runs in the monitor loop (``tick``). A device's drop is (re)published when

* the target changed (VPN exit IP, forwarded port, certificate fingerprint),
* the device is new or has a new key,
* or, if the setting ``refresh_hours`` is above 0, the last upload is older than that, so a host that forgets
  files gets them back. Default 0: only on a change.

Files of removed devices are deleted. The storage is a backend of ``pushstore`` (WebDAV or a Cloudflare Worker).
Uploads go through the VPN tunnel only (``internet`` route), never through the home line. The ``after_publish`` hooks (FCM ping) run only when a device's content changed (new
target or new key), not for a plain refresh: the app has nothing new to fetch then.

Settings (``pushping`` section): ``upload_url`` (WebDAV folder), ``upload_user``, ``upload_pass``
(write-only, never logged or returned).
"""

import base64
import json
import time

from . import httpc, pushcrypto, pushstore
from .log import log

RETRY = 300


class Publisher:
    def __init__(self, agent, devices, request=httpc.request, clock=time.time):
        self.agent = agent
        self.devices = devices
        self.request = request
        self.clock = clock
        self.after_publish = []
        self.rt = {"last_error": "", "last_ok": 0, "next_try": 0, "read_warning": ""}

    # -- target ---------------------------------------------------------------------
    def target(self):
        """``{"url", "cert"}`` the devices should use now, or ``None`` while it is unknown.

        The URL is the redirect target (``https://<name below the myaddr name>:<port>``): the proxy picks the
        media server by that name (SNI/Host) and serves its certificate. A bare ``https://IP:port`` would land
        on the proxy's default host. ``cert`` stays empty (system trust) until the pinned certificate (P9).
        """
        tgt = self.agent.redirect.target()
        if not tgt or not tgt.get("url"):
            return None
        return {"url": tgt["url"], "cert": self.cert_fingerprint()}

    def cert_fingerprint(self):
        """``sha256/<base64>`` of the self-signed certificate (step P9), ``""`` until there is one."""
        return ""

    # -- storage ------------------------------------------------------------------------
    def backend(self):
        kind = self.devices.settings()["storage"]
        return pushstore.BACKENDS.get(kind, pushstore.WebDav)(self)

    # -- loop ---------------------------------------------------------------------------
    def tick(self):
        s = self.devices.settings()
        store = self.backend()
        if not s["enabled"] or not store.ready() or self.devices.sign_pub() is None:
            return
        now = self.clock()
        if now < self.rt["next_try"]:
            return
        target = self.target()
        refresh = s["refresh_hours"] * 3600
        orphans = self.devices.orphans()
        done, news = [], 0
        try:
            for path in orphans:
                store.delete(path)
            if target is not None:
                key = json.dumps(target, sort_keys=True)
                for device in self.devices.list():
                    if device.get("blocked"):
                        continue
                    same = device.get("published_key") == key and device.get("published_pub") == device["pub"]
                    if same and (not refresh or now - device.get("published_at", 0) < refresh):
                        continue
                    drop = self.seal(device, target, now)
                    store.put(device["path"], drop)
                    done.append((device, key, drop))
                    news += 0 if same else 1
            if store.whole and (done or orphans):
                table = {d["path"]: base64.b64decode(d["published_drop"]) for d in self.devices.list()
                         if d.get("published_drop") and not d.get("blocked")}
                table.update({d["path"]: drop for d, _, drop in done})
                store.finish(table)
        except (httpc.HttpError, pushcrypto.DropError, OSError) as err:
            self.rt.update({"last_error": str(err)[:200], "next_try": now + RETRY})
            log("push ping upload failed: %s", self.rt["last_error"])
            return
        for path in orphans:
            self.devices.forget_orphan(path)
        for device, key, drop in done:
            self.devices.mark_published(device["id"], key, device["pub"], int(now),
                                        base64.b64encode(drop).decode())
        self.rt.update({"last_error": "", "next_try": 0})
        if done:
            self.rt["last_ok"] = now
            log("push ping: %d drop(s) published", len(done))
            self.check_read(done[0][0]["id"])
        if news:
            for hook in self.after_publish:
                try:
                    hook()
                except Exception as err:  # a ping problem never stops the uploads
                    log("push ping hook failed: %s", err)

    def check_read(self, device_id):
        """The app fetches its file without a login: warn when that fails (e.g. WebDAV that wants a login to
        read too). Only noted in the status, uploads go on."""
        url = self.devices.drop_url(device_id)
        if not url:
            self.rt["read_warning"] = "keine Abruf-Adresse"
            return
        try:
            res = self.request("GET", url, headers={"Cache-Control": "no-cache"},
                               device=self.agent.egress.route("internet"), timeout=15)
            status = res.status
        except Exception as err:  # only a warning, never stops the round
            status, reason = 0, str(err)[:120] or err.__class__.__name__
        warning = "" if status == 200 else (
            "Datei ohne Anmeldung nicht abrufbar (%s): öffentliche Abruf-Adresse eintragen"
            % ("HTTP %d" % status if status else reason))
        if warning != self.rt["read_warning"]:
            log("push ping: %s", warning or "files readable without login")
        self.rt["read_warning"] = warning

    def seal(self, device, target, now):
        seq = self.devices.next_seq(device["id"])
        plain = json.dumps({"v": 1, "seq": seq, "ts": int(now), "url": target["url"], "cert": target["cert"]},
                           sort_keys=True, separators=(",", ":")).encode()
        return pushcrypto.seal(plain, bytes.fromhex(device["pub"]), self.devices.sign_key)

    def resolve(self):
        """After saving the settings: find the public address of a Cloudflare drop Worker (errors only noted)."""
        store = self.backend()
        if store.kind == "cloudflare" and store.ready():
            try:
                store.resolve()
            except httpc.HttpError as err:
                self.rt["last_error"] = str(err)[:200]
        elif store.kind == "script":
            self.agent.store.update("pushping", {"script_base": store.base()})

    def status(self):
        st = self.agent.store.section("pushping")
        return {"storage": self.devices.settings()["storage"], "upload_url": st.get("upload_url") or "",
                "upload_user": st.get("upload_user") or "", "upload_pass_set": bool(st.get("upload_pass")),
                "cf_base": st.get("cf_base") or "", "cf_ready": pushstore.CloudflareWorker(self).ready(),
                "script_base": st.get("script_base") or "", "script_ready": pushstore.SshScript(self).ready(),
                "php_url": st.get("php_url") or "", "php_key_set": bool(st.get("php_key")),
                "last_ok": self.rt["last_ok"], "last_error": self.rt["last_error"],
                "read_warning": self.rt["read_warning"]}
