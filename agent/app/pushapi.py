"""Device API for push ping, on its own port so the proxy can expose ``/_pn/`` without the web UI.

The proxy (NPM or Zoraxy) forwards ``https://<entry>/_pn/`` to ``http://<portnook>:<port>/_pn/``. A proxy that
strips the prefix works too: ``/hello`` is the same as ``/_pn/hello``.

* ``GET  /_pn/``: neutral sign-in page (code or user and password); it names neither portnook nor the media
  server. Device data for the media server (``client``, ``device``, ``device_id``, ``version``) come as query.
* ``GET  /_pn/hello``: ``{"ok": true}`` (lets the app tell this API from the media server).
* ``POST /_pn/login``: ``{user, password, client?, device?, device_id?, version?}`` -> media server token.
* ``POST /_pn/code/start``: ``{client?, ...}`` -> ``{code, secret}`` (Quick Connect).
* ``POST /_pn/code/check``: ``{secret, client?, ...}`` -> ``{pending: true}`` or the media server token.
* ``POST /_pn/register``: ``{token, device_pub, push_token?, platform?, name?}`` -> device id, drop URL,
  signing key.
* ``POST /_pn/device``: ``{token, device_id, device_pub?, push_token?}`` -> key rotation / new push token.

``token`` is the media server access token of the app's login; it is checked against the media server and
never stored or logged. Failed checks are rate limited per client address.
"""

import http.server
import ipaddress
import json
import os
import socketserver
import threading

from .auth import Sessions
from .log import log
from .pushdevices import AuthError
from .pushlogin import Login, LoginUnavailable
from .validate import ValidationError

MAX_BODY = 16 * 1024
PAGE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "signin.html")
PAGE_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; "
            "base-uri 'none'; form-action 'none'")


def _route(raw):
    """Request path without query and without the ``/_pn`` prefix (a proxy may strip it or keep it)."""
    path = raw.split("?", 1)[0]
    return path[len("/_pn"):] if path.startswith("/_pn/") else path


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, devices, limiter):
        super().__init__(addr, _Handler)
        self.devices = devices
        self.limiter = limiter
        self.login = Login(devices)


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "web"
    sys_version = ""

    def log_message(self, fmt, *args):  # no request log (tokens travel in bodies)
        pass

    @property
    def client_ip(self):
        peer = self.client_address[0]
        forwarded = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        try:
            if forwarded and ipaddress.ip_address(peer).is_private:
                return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
        return peer

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            raise ValidationError("Anfrage zu gross oder leer.")
        try:
            data = json.loads(self.rfile.read(length))
        except ValueError:
            raise ValidationError("Kein JSON.")
        if not isinstance(data, dict):
            raise ValidationError("Kein JSON-Objekt.")
        return data

    def _page(self):
        try:
            with open(PAGE, "rb") as fh:
                data = fh.read()
        except OSError:
            return self._send(404, {"error": "not found"})
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", PAGE_CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        raw = self.path.split("?", 1)[0]
        if raw == "/_pn":
            self.send_response(301)
            self.send_header("Location", "/_pn/" + ("?" + self.path.split("?", 1)[1] if "?" in self.path else ""))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = _route(self.path)
        if path in ("/", "/index.html"):
            return self._page()
        if path == "/hello":
            return self._send(200, {"ok": True, "v": 1})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = _route(self.path)
        if path not in ("/register", "/device", "/login", "/code/start", "/code/check"):
            self.close_connection = True
            return self._send(404, {"error": "not found"})
        ip = self.client_ip
        limiter = self.server.limiter
        if limiter.blocked(ip):
            self.close_connection = True
            return self._send(429, {"error": "too many attempts"})
        try:
            body = self._body()
            login = self.server.login
            if path == "/login":
                answer = login.password(body)
            elif path == "/code/start":  # counts as an attempt: every start makes the media server keep a code
                limiter.fail(ip)
                return self._send(200, login.code_start(body))
            elif path == "/code/check":
                answer = login.code_check(body)
                if answer.get("pending"):
                    return self._send(200, answer)
            else:
                token = body.pop("token", "")
                if path == "/register":
                    answer = self.server.devices.register(token, body)
                else:
                    answer = self.server.devices.update(token, body)
        except LoginUnavailable:
            return self._send(409, {"error": "not available"})
        except AuthError as err:
            limiter.fail(ip)
            log("push ping refused for %s: %s", ip, str(err)[:120])
            return self._send(401, {"error": "not authorised"})
        except ValidationError as err:
            return self._send(400, {"error": str(err)})
        except Exception as err:  # never leak details
            log("push ping request crashed: %s: %s", err.__class__.__name__, str(err)[:200])
            return self._send(500, {"error": "internal error"})
        limiter.reset(ip)
        self._send(200, answer)


class PushApi:
    """Starts/stops the device API to match the ``pushping`` settings."""

    def __init__(self, devices, listen="0.0.0.0"):
        self.devices = devices
        self.listen = listen
        self.limiter = Sessions()
        self._server = None
        self._port = None
        self._lock = threading.Lock()

    def sync(self):
        s = self.devices.settings()
        with self._lock:
            want = s["port"] if s["enabled"] else None
            if want == self._port:
                return
            self._stop()
            if want is None:
                return
            try:
                self._server = _Server((self.listen, want), self.devices, self.limiter)
            except OSError as err:
                log("push ping device API could not listen on %d: %s", want, err)
                return
            self._port = want
            threading.Thread(target=self._server.serve_forever, name="pushapi", daemon=True).start()
            log("push ping device API listening on %s:%d", self.listen, want)

    def _stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            log("push ping device API stopped")
        self._server = None
        self._port = None

    @property
    def port(self):
        return self._port

    def stop(self):
        with self._lock:
            self._stop()
