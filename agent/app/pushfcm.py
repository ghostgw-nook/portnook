"""Push ping: an empty FCM data message ("fetch your drop") to every Android device after a publish.

* Firebase service account (JSON from the Firebase console) uploaded in the web UI, write-only; its private
  key lives in ``<data>/push/fcm-key.pem`` (600), the rest in ``<data>/push/fcm.json`` (600, no key).
* OAuth 2 access token: JWT (RS256, ``openssl dgst -sha256 -sign``) for the ``firebase.messaging`` scope,
  exchanged at Google's token endpoint, cached until shortly before it expires.
* Message: ``{"data": {"t": "refresh"}}`` with Android priority ``high`` so the app wakes up. No address,
  no key, nothing else.
* Requests go through the VPN tunnel (``internet`` route). A token Firebase no longer knows
  (``UNREGISTERED``) is dropped from the device; the app sends a new one on its next start.
"""

import base64
import json
import os
import time
import urllib.parse

from . import httpc, sysrun
from .log import log
from .validate import ValidationError

TOKEN_URL = "https://oauth2.googleapis.com/token"
SEND_URL = "https://fcm.googleapis.com/v1/projects/%s/messages:send"
SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
PLATFORMS = ("android",)  # iOS/tvOS follow once Android works (owner, 2026-11-27)


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Fcm:
    def __init__(self, agent, devices, request=httpc.request, clock=time.time):
        self.agent = agent
        self.devices = devices
        self.request = request
        self.clock = clock
        self.key_path = os.path.join(devices.dir, "fcm-key.pem")
        self.meta_path = os.path.join(devices.dir, "fcm.json")
        self._token = ("", 0)
        self.rt = {"last_ok": 0, "last_error": "", "sent": 0}

    # -- settings ---------------------------------------------------------------------
    def meta(self):
        try:
            with open(self.meta_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def set_account(self, body):
        if body.get("clear"):
            for path in (self.key_path, self.meta_path):
                if os.path.exists(path):
                    os.unlink(path)
            self._token = ("", 0)
            log("push ping: firebase account removed")
            return self.status()
        try:
            acc = json.loads(str(body.get("service_account") or ""))
        except ValueError:
            raise ValidationError("Kein gültiges JSON.")
        if not isinstance(acc, dict) or acc.get("type") != "service_account":
            raise ValidationError("Kein Firebase-Dienstkonto (type service_account).")
        project, email, key = acc.get("project_id"), acc.get("client_email"), acc.get("private_key")
        if not all(isinstance(v, str) and v for v in (project, email, key)) or "PRIVATE KEY" not in key:
            raise ValidationError("Dienstkonto unvollständig.")
        os.makedirs(self.devices.dir, mode=0o700, exist_ok=True)
        for path, text in ((self.key_path, key), (self.meta_path, json.dumps({"project_id": project,
                                                                               "client_email": email}))):
            tmp = path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp, path)
        self._token = ("", 0)
        log("push ping: firebase account set (project %s)", project)
        return self.status()

    def status(self):
        meta = self.meta()
        return {"project_id": meta.get("project_id", ""), "account_set": bool(meta) and os.path.exists(self.key_path),
                "last_ok": self.rt["last_ok"], "last_error": self.rt["last_error"], "sent": self.rt["sent"]}

    # -- OAuth ------------------------------------------------------------------------------
    def _jwt(self, email, now):
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = _b64url(json.dumps({"iss": email, "scope": SCOPE, "aud": TOKEN_URL, "iat": now,
                                     "exp": now + 3600}).encode())
        signing_input = ("%s.%s" % (header, claims)).encode()
        sig = sysrun.run(["openssl", "dgst", "-sha256", "-sign", self.key_path], input=signing_input,
                         text=False).stdout
        return "%s.%s.%s" % (header, claims, _b64url(sig))

    def access_token(self):
        token, until = self._token
        now = int(self.clock())
        if token and now < until - 120:
            return token
        meta = self.meta()
        if not meta or not os.path.exists(self.key_path):
            raise httpc.HttpError("kein Firebase-Dienstkonto")
        body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                       "assertion": self._jwt(meta["client_email"], now)})
        res = self.request("POST", TOKEN_URL, body=body,
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           device=self.agent.egress.route("internet"), timeout=20)
        data = res.json() if res.status == 200 else {}
        if not data.get("access_token"):
            raise httpc.HttpError("Google-Anmeldung abgelehnt (%d)" % res.status)
        self._token = (data["access_token"], now + int(data.get("expires_in") or 3600))
        return self._token[0]

    # -- ping --------------------------------------------------------------------------------
    def ping_all(self):
        """Ping every Android device that has a push token (hook of ``pushdrop.Publisher``)."""
        targets = [d for d in self.devices.list() if d.get("push_token") and d.get("platform") in PLATFORMS]
        if not targets or not self.status()["account_set"]:
            return 0
        try:
            token = self.access_token()
        except (httpc.HttpError, sysrun.SysRunError) as err:
            self.rt["last_error"] = str(err)[:200]
            log("push ping: firebase login failed: %s", self.rt["last_error"])
            return 0
        url = SEND_URL % self.meta()["project_id"]
        sent = 0
        for device in targets:
            msg = {"message": {"token": device["push_token"], "data": {"t": "refresh"},
                               "android": {"priority": "high", "ttl": "3600s"}}}
            try:
                res = self.request("POST", url, body=msg, headers={"Authorization": "Bearer " + token},
                                   device=self.agent.egress.route("internet"), timeout=20)
            except httpc.HttpError as err:
                self.rt["last_error"] = str(err)[:200]
                continue
            if res.status == 200:
                sent += 1
            elif res.status in (400, 404) and "UNREGISTERED" in res.text(2000):
                self.devices.clear_push_token(device["id"])
                log("push ping: device %s push token no longer valid", device["id"])
            else:
                self.rt["last_error"] = "Firebase antwortete %d" % res.status
        if sent:
            self.rt.update({"last_ok": int(self.clock()), "sent": self.rt["sent"] + sent})
            if sent == len(targets):
                self.rt["last_error"] = ""
        log("push ping: %d of %d device(s) pinged", sent, len(targets))
        return sent
