"""Device API for push ping, on its own port so the proxy can expose ``/_pn/`` without the web UI.

The proxy (NPM or Zoraxy) forwards ``https://<entry>/_pn/`` to ``http://<portnook>:<port>/_pn/``.

* ``GET  /_pn/hello``: ``{"ok": true}`` (lets the app tell portnook from the media server).
* ``POST /_pn/register``: ``{token, device_pub, push_token?, platform?, name?}`` -> device id, drop URL,
  signing key.
* ``POST /_pn/device``: ``{token, device_id, device_pub?, push_token?}`` -> key rotation / new push token.

``token`` is the media server access token of the app's login; it is checked against the media server and
never stored or logged. Failed checks are rate limited per client address.
"""

import http.server
import ipaddress
import json
import socketserver
import threading

from .auth import Sessions
from .log import log
from .pushdevices import AuthError
from .validate import ValidationError

MAX_BODY = 16 * 1024


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, devices, limiter):
        super().__init__(addr, _Handler)
        self.devices = devices
        self.limiter = limiter


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "portnook"
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

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/_pn/hello":
            return self._send(200, {"ok": True, "service": "portnook push"})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/_pn/register", "/_pn/device"):
            self.close_connection = True
            return self._send(404, {"error": "not found"})
        ip = self.client_ip
        limiter = self.server.limiter
        if limiter.blocked(ip):
            self.close_connection = True
            return self._send(429, {"error": "too many attempts"})
        try:
            body = self._body()
            token = body.pop("token", "")
            if path == "/_pn/register":
                answer = self.server.devices.register(token, body)
            else:
                answer = self.server.devices.update(token, body)
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
