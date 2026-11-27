"""Push ping: sign in to the media server through portnook (password or code), for devices without a login.

The app (or the neutral page at ``/_pn/``) never talks to the media server directly during setup. portnook
passes the login on over the LAN route and hands back the media server's answer: access token, user id, user
name and server id. The app then registers with that token (``/_pn/register``) and can stream with it.

* Password: Jellyfin ``POST /Users/AuthenticateByName``.
* Code: Jellyfin Quick Connect. ``start`` asks the media server for a code and a secret
  (``/QuickConnect/Initiate``), the user confirms the code in a client that is already signed in, ``check``
  polls ``/QuickConnect/Connect`` and, once confirmed, signs in with ``/Users/AuthenticateWithQuickConnect``.

The device data in the ``Authorization`` header (client, device, device id, version) comes from the app, so the
media server lists the token under the app's own device, not under portnook. Passwords, secrets and tokens are
never stored or logged.
"""

import re

from . import httpc
from .pushdevices import AuthError

_FIELD = re.compile(r"[^A-Za-z0-9 ._()+-]")
_SECRET = re.compile(r"[A-Za-z0-9]{16,128}")


class LoginUnavailable(Exception):
    """The media server does not offer this way of signing in (e.g. Quick Connect switched off)."""


def _clean(value, default, size=64):
    text = _FIELD.sub("", str(value or "")).strip()[:size]
    return text or default


def auth_header(body):
    """``MediaBrowser`` header with the app's own device data (sanitised, no quotes)."""
    client = _clean(body.get("client"), "Push")
    device = _clean(body.get("device"), "Device")
    device_id = _clean(body.get("device_id"), "", 128)
    version = _clean(body.get("version"), "1.0", 20)
    parts = ['Client="%s"' % client, 'Device="%s"' % device, 'Version="%s"' % version]
    if device_id:
        parts.insert(2, 'DeviceId="%s"' % device_id)
    return "MediaBrowser " + ", ".join(parts)


class Login:
    def __init__(self, devices):
        self.devices = devices

    def _call(self, method, path, body, payload=None):
        url = self.devices.settings()["media_url"]
        if not url:
            raise AuthError("no media server set")
        headers = {"Authorization": auth_header(body), "X-Emby-Authorization": auth_header(body),
                   "Accept": "application/json"}
        try:
            return self.devices.request(method, url + path, body=payload, headers=headers, device=self.devices.route,
                                        timeout=10)
        except httpc.HttpError as err:
            raise AuthError("media server not reachable: %s" % str(err)[:120])

    @staticmethod
    def _result(res):
        if res.status != 200:
            raise AuthError("media server answered %d" % res.status)
        try:
            data = res.json()
        except (ValueError, httpc.HttpError):
            raise AuthError("media server answer not JSON")
        user = data.get("User") or {}
        token, user_id = str(data.get("AccessToken") or ""), str(user.get("Id") or "")
        if not token or not re.fullmatch(r"[0-9a-fA-F-]{8,64}", user_id):
            raise AuthError("media server answer without token")
        return {"token": token, "user_id": user_id.lower(), "user_name": str(user.get("Name") or "")[:64],
                "server_id": str(data.get("ServerId") or "")[:64]}

    # -- password ---------------------------------------------------------------------
    def password(self, body):
        user = str(body.get("user") or "").strip()
        if not user or len(user) > 128 or len(str(body.get("password") or "")) > 512:
            raise AuthError("user or password missing")
        res = self._call("POST", "/Users/AuthenticateByName", body,
                         {"Username": user, "Pw": str(body.get("password") or "")})
        return self._result(res)

    # -- code (Quick Connect) -------------------------------------------------------------
    def code_start(self, body):
        res = self._call("POST", "/QuickConnect/Initiate", body)
        if res.status == 405:  # Jellyfin before 10.9 used GET
            res = self._call("GET", "/QuickConnect/Initiate", body)
        if res.status in (401, 403):
            raise LoginUnavailable("code sign-in switched off")
        if res.status != 200:
            raise AuthError("media server answered %d" % res.status)
        try:
            data = res.json()
        except (ValueError, httpc.HttpError):
            raise AuthError("media server answer not JSON")
        code, secret = str(data.get("Code") or ""), str(data.get("Secret") or "")
        if not code or not _SECRET.fullmatch(secret):
            raise AuthError("media server answer without code")
        return {"code": code, "secret": secret}

    def code_check(self, body):  # Jellyfin keeps a code 10 minutes (QuickConnectManager.Timeout); signin.html waits ~9.75
        """``{"pending": true}`` until the code is confirmed, then the login result."""
        secret = str(body.get("secret") or "")
        if not _SECRET.fullmatch(secret):
            raise AuthError("secret format")
        res = self._call("GET", "/QuickConnect/Connect?secret=" + secret, body)
        if res.status != 200:
            raise AuthError("code unknown or expired (%d)" % res.status)
        try:
            state = res.json()
        except (ValueError, httpc.HttpError):
            raise AuthError("media server answer not JSON")
        if not state.get("Authenticated"):
            return {"pending": True}
        return self._result(self._call("POST", "/Users/AuthenticateWithQuickConnect", body, {"Secret": secret}))
