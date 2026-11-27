"""Push ping: publish one sealed drop per device on the zero-trust host (WebDAV PUT/DELETE).

Runs in the monitor loop (``tick``). A device's drop is (re)published when

* the target changed (VPN exit IP, forwarded port, certificate fingerprint),
* the device is new or has a new key,
* or the last upload is older than ``REFRESH`` (6 h), so a host that forgets files gets them back.

Files of removed devices are deleted. Uploads go through the VPN tunnel only (``internet`` route), never
through the home line. After every round with changes the ``after_publish`` hooks run (FCM ping).

Settings (``pushping`` section): ``upload_url`` (WebDAV folder), ``upload_user``, ``upload_pass``
(write-only, never logged or returned).
"""

import base64
import json
import time

from . import httpc, pushcrypto
from .log import log

REFRESH = 6 * 3600
RETRY = 300


class Publisher:
    def __init__(self, agent, devices, request=httpc.request, clock=time.time):
        self.agent = agent
        self.devices = devices
        self.request = request
        self.clock = clock
        self.after_publish = []
        self.rt = {"last_error": "", "last_ok": 0, "next_try": 0}

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

    # -- upload ---------------------------------------------------------------------
    def _config(self):
        st = self.agent.store.section("pushping")
        return st.get("upload_url") or "", st.get("upload_user") or "", st.get("upload_pass") or ""

    def _headers(self, user, password):
        headers = {"Content-Type": "application/octet-stream", "Cache-Control": "no-cache"}
        if user or password:
            raw = ("%s:%s" % (user, password)).encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        return headers

    def _send(self, method, name, body=None):
        url, user, password = self._config()
        res = self.request(method, "%s/%s.bin" % (url, name), body=body, headers=self._headers(user, password),
                           device=self.agent.egress.route("internet"), timeout=20)
        if method == "DELETE" and res.status == 404:
            return
        if res.status not in (200, 201, 204):
            raise httpc.HttpError("Zero-Trust-Seite antwortete %d" % res.status)

    # -- loop ---------------------------------------------------------------------------
    def tick(self):
        s = self.devices.settings()
        url, _, _ = self._config()
        if not s["enabled"] or not url or self.devices.sign_pub() is None:
            return
        now = self.clock()
        if now < self.rt["next_try"]:
            return
        target = self.target()
        changed = 0
        try:
            for path in self.devices.orphans():
                self._send("DELETE", path)
                self.devices.forget_orphan(path)
            if target is not None:
                key = json.dumps(target, sort_keys=True)
                for device in self.devices.list():
                    if (device.get("published_key") == key and device.get("published_pub") == device["pub"]
                            and now - device.get("published_at", 0) < REFRESH):
                        continue
                    self.publish(device, target, key, now)
                    changed += 1
        except (httpc.HttpError, pushcrypto.DropError, OSError) as err:
            self.rt.update({"last_error": str(err)[:200], "next_try": now + RETRY})
            log("push ping upload failed: %s", self.rt["last_error"])
            return
        self.rt.update({"last_error": "", "next_try": 0})
        if changed:
            self.rt["last_ok"] = now
            log("push ping: %d drop(s) published", changed)
            for hook in self.after_publish:
                try:
                    hook()
                except Exception as err:  # a ping problem never stops the uploads
                    log("push ping hook failed: %s", err)

    def publish(self, device, target, key, now):
        seq = self.devices.next_seq(device["id"])
        plain = json.dumps({"v": 1, "seq": seq, "ts": int(now), "url": target["url"], "cert": target["cert"]},
                           sort_keys=True, separators=(",", ":")).encode()
        drop = pushcrypto.seal(plain, bytes.fromhex(device["pub"]), self.devices.sign_key)
        self._send("PUT", device["path"], drop)
        self.devices.mark_published(device["id"], key, device["pub"], int(now))

    def status(self):
        url, user, password = self._config()
        return {"upload_url": url, "upload_user": user, "upload_pass_set": bool(password),
                "last_ok": self.rt["last_ok"], "last_error": self.rt["last_error"]}
