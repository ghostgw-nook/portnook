"""Push ping devices: registry and checks against the media server.

A device registers once through the entry (302 -> Proton port -> proxy -> ``/_pn/``) with the access token of
its media server login. portnook checks that token against the media server (Jellyfin/Emby ``/Users/Me``) and
keeps per device: its X25519 public key, its push token, a random drop path and a sequence number.

* State in ``<data>/push/devices.json`` (600, atomic). The signing key is ``<data>/push/sign.pem`` (600).
* Settings (``pushping`` section of the store): ``enabled``, ``port`` (device API), ``media_url`` (LAN address
  of the media server), ``drop_base`` (public base URL of the zero-trust host), ``refresh_hours`` (rewrite the
  drops this often even without a change, 0 = only on a change; default 0, owner 2026-11-27).
* Tokens of the media server are never stored or logged; only the user id they belong to.
"""

import json
import os
import re
import secrets
import threading
import time

from . import httpc, pushcrypto
from .log import log
from .validate import ValidationError

MAX_DEVICES = 100
NAME_MAX = 40
PUSH_TOKEN_MAX = 4096
PLATFORMS = ("android", "ios", "tvos", "other")
DEFAULT_PORT = 8099
REFRESH_MAX_HOURS = 168
STORAGES = ("webdav", "cloudflare", "script")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[0-9a-f]{16}")
_TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{8,512}")


class AuthError(Exception):
    """The media server did not accept the token."""


def _clean_name(value):
    name = " ".join(str(value or "").split())[:NAME_MAX]
    return name or "Gerät"


def check_pub(value):
    pub = str(value or "").strip().lower()
    if not _HEX64.fullmatch(pub) or pub == "0" * 64:
        raise ValidationError("Geräteschlüssel ungültig.")
    return pub


def check_push_token(value):
    token = str(value or "").strip()
    if len(token) > PUSH_TOKEN_MAX or any(c.isspace() for c in token):
        raise ValidationError("Push-Token ungültig.")
    return token


def check_platform(value):
    platform = str(value or "other").strip().lower()
    return platform if platform in PLATFORMS else "other"


class Devices:
    def __init__(self, data_dir, store, route=None, request=httpc.request, clock=time.time):
        self.dir = os.path.join(data_dir, "push")
        self.path = os.path.join(self.dir, "devices.json")
        self.sign_key = os.path.join(self.dir, "sign.pem")
        self.store = store
        self.route = route
        self.request = request
        self.clock = clock
        self._lock = threading.Lock()
        self._orphans = []
        self._devices = self._load()
        self.fcm_options = None  # set by the agent: () -> Firebase client options for devices, or None

    # -- settings ----------------------------------------------------------------
    def settings(self):
        st = self.store.section("pushping")
        return {"enabled": st.get("enabled") is True, "port": int(st.get("port") or DEFAULT_PORT),
                "media_url": st.get("media_url") or "", "drop_base": st.get("drop_base") or "",
                "refresh_hours": int(st.get("refresh_hours") or 0),
                "storage": st.get("storage") if st.get("storage") in STORAGES else "webdav"}

    def set_settings(self, body):
        values = {"enabled": body.get("enabled") is True}
        port = int(body.get("port") or DEFAULT_PORT)
        if not 1024 <= port <= 65535:
            raise ValidationError("Port ungültig.")
        values["port"] = port
        try:
            hours = int(body.get("refresh_hours") or 0)
        except (TypeError, ValueError):
            hours = -1
        if not 0 <= hours <= REFRESH_MAX_HOURS:
            raise ValidationError("Erneuerung: 0 bis %d Stunden." % REFRESH_MAX_HOURS)
        values["refresh_hours"] = hours
        storage = str(body.get("storage") or "webdav")
        if storage not in STORAGES:
            raise ValidationError("Ablage unbekannt.")
        values["storage"] = storage
        for key in ("media_url", "drop_base"):
            url = str(body.get(key) or "").strip().rstrip("/")
            if url and not re.fullmatch(r"https?://[A-Za-z0-9.\-:\[\]]+(/[A-Za-z0-9._~/-]*)?", url):
                raise ValidationError("Adresse ungültig: %s" % key)
            values[key] = url
        upload = str(body.get("upload_url") or "").strip().rstrip("/")
        if upload and not re.fullmatch(r"https://[A-Za-z0-9.\-:\[\]]+(/[A-Za-z0-9._~/%-]*)?", upload):
            raise ValidationError("WebDAV-Adresse ungültig (nur https).")
        values["upload_url"] = upload
        values["upload_user"] = str(body.get("upload_user") or "").strip()[:200]
        password = str(body.get("upload_pass") or "")
        if password:  # write-only: empty keeps the stored one
            values["upload_pass"] = password[:500]
        elif not upload:
            values["upload_pass"] = ""
        if values["enabled"] and not values["media_url"]:
            raise ValidationError("Adresse des Mediaservers fehlt.")
        self.store.update("pushping", values)
        if values["enabled"]:
            self.ensure_key()
        log("push ping %s, device API port %d", "on" if values["enabled"] else "off", port)
        return self.overview()

    def ensure_key(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        if not os.path.exists(self.sign_key):
            pushcrypto.generate_signing_key(self.sign_key)
            log("push ping signing key created")
        return pushcrypto.public_raw(self.sign_key)

    def sign_pub(self):
        return pushcrypto.public_raw(self.sign_key) if os.path.exists(self.sign_key) else None

    # -- storage -----------------------------------------------------------------
    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._orphans = [p for p in data.get("orphans", []) if re.fullmatch(r"[0-9a-f]{32}", str(p))]
            return {d["id"]: d for d in data.get("devices", []) if _ID.fullmatch(str(d.get("id", "")))}
        except (OSError, ValueError, KeyError, TypeError):
            return {}

    def _save(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"devices": sorted(self._devices.values(), key=lambda d: d["created"]),
                       "orphans": self._orphans}, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def list(self):
        with self._lock:
            return [dict(d) for d in sorted(self._devices.values(), key=lambda d: d["created"])]

    def get(self, device_id):
        with self._lock:
            d = self._devices.get(device_id)
            return dict(d) if d else None

    def overview(self):
        """For the web UI: settings and devices without push tokens."""
        devices = [{k: v for k, v in d.items() if k != "push_token"} for d in self.list()]
        for d in devices:
            d["push"] = bool(self.get(d["id"]).get("push_token"))
        pub = self.sign_pub()
        hidden = ("push_token", "published_key", "published_drop")
        devices = [{k: v for k, v in d.items() if k not in hidden} for d in devices]
        return {"settings": self.settings(), "devices": devices, "sign_pub": pub.hex() if pub else ""}

    # -- media server check --------------------------------------------------------
    def check_token(self, token):
        """``(user_id, user_name)`` for a media server access token, else ``AuthError``."""
        token = str(token or "").strip()
        if not _TOKEN.fullmatch(token):
            raise AuthError("token format")
        url = self.settings()["media_url"]
        if not url:
            raise AuthError("no media server set")
        headers = {"Authorization": 'MediaBrowser Token="%s"' % token, "X-Emby-Token": token,
                   "Accept": "application/json"}
        try:
            res = self.request("GET", url + "/Users/Me", headers=headers, device=self.route, timeout=10)
        except httpc.HttpError as err:
            raise AuthError("media server not reachable: %s" % str(err)[:120])
        if res.status != 200:
            raise AuthError("media server answered %d" % res.status)
        try:
            user = res.json()
        except (ValueError, httpc.HttpError):
            raise AuthError("media server answer not JSON")
        user_id = str(user.get("Id") or "")
        if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", user_id):
            raise AuthError("media server answer without user id")
        return user_id.lower(), _clean_name(user.get("Name"))

    # -- device changes ----------------------------------------------------------------
    def _answer(self, device):
        st = self.store.section("pushping")
        kind = self.settings()["storage"]
        own = {"cloudflare": st.get("cf_base"), "script": st.get("script_base")}.get(kind, st.get("upload_url"))
        base = self.settings()["drop_base"] or own or ""  # empty = where the storage serves it
        pub = self.sign_pub()
        answer = {"device_id": device["id"], "drop_url": "%s/%s.bin" % (base, device["path"]) if base else "",
                  "sign_pub": pub.hex() if pub else "", "seq": device["seq"]}
        fcm = self.fcm_options() if self.fcm_options and device.get("platform") == "android" else None
        if fcm:
            answer["fcm"] = fcm
        return answer

    def register(self, token, body):
        user_id, user_name = self.check_token(token)
        pub = check_pub(body.get("device_pub"))
        now = int(self.clock())
        with self._lock:
            if len(self._devices) >= MAX_DEVICES:
                raise ValidationError("Zu viele Geräte.")
            device = {"id": secrets.token_hex(8), "path": secrets.token_hex(16), "pub": pub,
                      "push_token": check_push_token(body.get("push_token")),
                      "platform": check_platform(body.get("platform")), "name": _clean_name(body.get("name")),
                      "user_id": user_id, "user_name": user_name, "seq": 0, "created": now, "updated": now}
            self._devices[device["id"]] = device
            self._save()
        log("push ping device %s registered (%s, %s, user %s)", device["id"], device["platform"], device["name"],
            user_name)
        return self._answer(device)

    def update(self, token, body):
        """New device key (rotation) and/or push token, for the same media server user."""
        user_id, _ = self.check_token(token)
        device_id = str(body.get("device_id") or "")
        changes = {}
        if body.get("device_pub") is not None:
            changes["pub"] = check_pub(body.get("device_pub"))
        if body.get("push_token") is not None:
            changes["push_token"] = check_push_token(body.get("push_token"))
        with self._lock:
            device = self._devices.get(device_id) if _ID.fullmatch(device_id) else None
            if device is None or device["user_id"] != user_id:
                raise AuthError("unknown device")
            device.update(changes)
            device["updated"] = int(self.clock())
            self._save()
            answer = self._answer(device)
        log("push ping device %s updated (%s)", device_id, ", ".join(sorted(changes)) or "nothing")
        return answer

    def remove(self, device_id):
        with self._lock:
            device = self._devices.pop(str(device_id or ""), None)
            if device is None:
                raise ValidationError("Gerät nicht gefunden.")
            self._orphans.append(device["path"])
            self._save()
        log("push ping device %s removed", device_id)
        return device

    # -- publishing (app/pushdrop.py) ------------------------------------------------------
    def next_seq(self, device_id):
        with self._lock:
            device = self._devices[device_id]
            device["seq"] = int(device.get("seq", 0)) + 1
            self._save()
            return device["seq"]

    def mark_published(self, device_id, key, pub, when, drop=""):
        with self._lock:
            device = self._devices.get(device_id)
            if device is not None:
                device.update({"published_key": key, "published_pub": pub, "published_at": when,
                               "published_drop": drop})
                self._save()

    def orphans(self):
        with self._lock:
            return list(self._orphans)

    def forget_orphan(self, path):
        with self._lock:
            if path in self._orphans:
                self._orphans.remove(path)
                self._save()

    def clear_push_token(self, device_id):
        with self._lock:
            device = self._devices.get(device_id)
            if device is not None and device.get("push_token"):
                device["push_token"] = ""
                self._save()
