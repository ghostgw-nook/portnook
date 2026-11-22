"""HTTP API and static UI of the agent (stdlib ``http.server``)."""

import http.server
import json
import os
import re
import socketserver
import threading
from http.cookies import SimpleCookie

from . import acme, auth, delivery, httpc, log as logmod, myaddr, net as netmod, redirect, sysrun
from .agent import PasswordError, SetupError
from .log import log
from .validate import ValidationError

MAX_BODY = 48 * 1024
MAX_CONNS = 32
ACTIONS = ("proton-reconnect", "natpmp-renew", "backend-test", "ddns-update", "cert-issue", "cert-deliver",
           "redirect-run", "push-test", "speedtest-active", "speedtest-standby",
           "speedtest-active-1", "speedtest-standby-1")
_EXAMPLE_RE = re.compile(r"/api/redirect/example/([a-z-]{1,32})")
_LANG_RE = re.compile(r"[a-z]{2}(-[A-Z]{2})?\.json")
_DOWNLOAD_RE = re.compile(r"/api/cert/download/([a-z.]{1,20})")
_ACTION_RE = re.compile(r"/api/action/([a-z-]{1,32})")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, agent, web_dir, sessions=None, max_conns=MAX_CONNS):
        self.agent = agent
        self.web_dir = web_dir
        self.sessions = sessions or auth.Sessions()
        self.slots = threading.BoundedSemaphore(max_conns)
        super().__init__(addr, Handler)

    def process_request(self, request, client_address):
        """Cap concurrent connections; answer 503 when all slots are busy."""
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
                                b"Content-Length: 30\r\nConnection: close\r\n\r\n"
                                b'{"error": "zu viele Anfragen"}')
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class HTTPError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "portnook"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30  # socket timeout: slow or idle clients cannot hold a slot forever

    def log_message(self, fmt, *args):  # request logging off (no noise, no secrets)
        pass

    # -- plumbing ---------------------------------------------------
    @property
    def agent(self):
        return self.server.agent

    @property
    def client_ip(self):
        return self.client_address[0]

    def _session_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        try:
            cookie = SimpleCookie(raw)
        except Exception:
            return ""
        morsel = cookie.get(auth.COOKIE)
        return morsel.value if morsel else ""

    def _logged_in(self):
        return self.server.sessions.valid(self._session_token())

    def _send(self, status, body, ctype="application/json; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; "
                         "frame-ancestors 'none'")
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _set_cookie(self, token, clear=False):
        value = "%s=%s; Path=/; HttpOnly; SameSite=Strict" % (auth.COOKIE, "" if clear else token)
        if clear:
            value += "; Max-Age=0"
        return {"Set-Cookie": value}

    def _read_json(self):
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self.close_connection = True
            raise HTTPError(415, "Content-Type muss application/json sein.")
        length = self.headers.get("Content-Length")
        if length is None:
            self.close_connection = True
            raise HTTPError(411, "Content-Length fehlt.")
        try:
            length = int(length)
        except ValueError:
            raise HTTPError(400, "Content-Length ungültig.")
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            raise HTTPError(413, "Anfrage zu gross (max. 48 KiB).")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            raise HTTPError(400, "Ungültiges JSON.")
        if not isinstance(data, dict):
            raise HTTPError(400, "JSON-Objekt erwartet.")
        return data

    # -- dispatch ---------------------------------------------------
    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        path = self.path.split("?", 1)[0]
        try:
            self._route(method, path)
        except HTTPError as err:
            self._send(err.status, {"error": err.message})
        except ValidationError as err:
            self._send(400, {"error": str(err)})
        except SetupError as err:
            self._send(409, {"error": str(err)})
        except (acme.AcmeError, myaddr.MyaddrError, delivery.DeliveryError, httpc.HttpError, redirect.RedirectError) as err:
            self._send(502, {"error": str(err)[:300]})
        except (netmod.NetError, sysrun.SysRunError) as err:
            log("request %s %s failed: %s", method, path, err)
            self._send(502, {"error": "Systemfehler: %s" % str(err)[:200]})
        except Exception as err:  # never leak details beyond the message type
            log("request %s %s crashed: %s: %s", method, path, err.__class__.__name__, str(err)[:200])
            self._send(500, {"error": "Interner Fehler, siehe Log."})

    def _route(self, method, path):
        if method == "GET" and path in ("/", "/index.html"):
            return self._static()
        if method == "GET" and _DOWNLOAD_RE.fullmatch(path) and self.headers.get("Authorization"):
            return self._pull(path)  # token-protected certificate download (scripts), no session
        if not path.startswith("/api/"):
            if method != "GET":
                self.close_connection = True  # body not read
            raise HTTPError(404, "Nicht gefunden.")

        if method == "GET" and path == "/api/session":
            return self._send(200, {"password_set": self.agent.password_set(), "logged_in": self._logged_in(),
                                    "version": self.agent.version, "client_ip": self.client_ip})
        if method != "GET":
            body = self._read_json()  # also enforces JSON content type for every mutating request
        else:
            body = None

        if not self.agent.password_set():
            if method == "POST" and path == "/api/setup/password":
                return self._set_password(body, first=True)
            raise HTTPError(403, "Zuerst ein Passwort setzen.")

        if method == "POST" and path == "/api/login":
            return self._login(body)
        if method == "POST" and path == "/api/logout":
            self.server.sessions.drop(self._session_token())
            return self._send(200, {"ok": True}, headers=self._set_cookie("", clear=True))
        if not self._logged_in():
            raise HTTPError(401, "Bitte anmelden.")

        if method == "GET" and path == "/api/status":
            return self._send(200, self.agent.status())
        if method == "GET" and path == "/api/logs":
            return self._send(200, {"lines": logmod.lines()})
        if method == "GET":
            m = _DOWNLOAD_RE.fullmatch(path)
            if m:
                return self._download(m.group(1))
            if path == "/api/redirect/script":
                return self._send(200, {"script": self.agent.redirect.script_text()})
            m = _EXAMPLE_RE.fullmatch(path)
            if m:
                try:
                    return self._send(200, {"script": self.agent.redirect.example(m.group(1))})
                except KeyError:
                    raise HTTPError(404, "Nicht gefunden.")
        if method == "POST":
            if path == "/api/setup/password":
                return self._set_password(body)
            if path == "/api/setup/proton":
                return self._send(200, self.agent.setup_proton(body, self.client_ip))
            if path == "/api/vpn/profile":
                return self._send(200, self.agent.failover.save_profile(body))
            if path == "/api/vpn/profile/delete":
                return self._send(200, self.agent.failover.delete_profile(str(body.get("id") or "")))
            if path == "/api/vpn/order":
                return self._send(200, self.agent.failover.set_order(body.get("ids")))
            if path == "/api/vpn/activate":
                if not self.agent.store.section("proton").get("enabled"):
                    raise SetupError("VPN ist ausgeschaltet.")
                return self._send(200, self.agent.failover.activate(str(body.get("id") or ""), "Manuell"))
            if path == "/api/vpn/failover":
                return self._send(200, self.agent.failover.set_settings(body))
            if path == "/api/lan-entry":
                return self._send(200, self.agent.set_lan_entry(body))
            if path == "/api/setup/backend":
                return self._send(200, self.agent.setup_backend(body, self.client_ip))
            if path == "/api/myaddr/all":
                return self._send(200, self.agent.names.save_all(body))
            if path == "/api/myaddr/names":
                return self._send(200, self.agent.names.save(body))
            if path == "/api/myaddr":
                return self._send(200, self.agent.certs.set_myaddr(body))
            if path == "/api/cert/settings":
                return self._send(200, self.agent.certs.set_cert(body))
            if path == "/api/delivery":
                return self._send(200, self.agent.certs.set_delivery(body))
            if path == "/api/redirect/preview":
                return self._send(200, {"script": redirect.generate(redirect.check_gen(body))})
            if path == "/api/redirect/test":
                return self._send(200, self.agent.redirect.run_test(body))
            if path == "/api/redirect":
                return self._send(200, self.agent.redirect.set_config(body))
            if path == "/api/push":
                return self._send(200, self.agent.notify.set_config(body))
            if path == "/api/redirect/ssh-key":
                if body.get("generate"):
                    return self._send(200, self.agent.redirect.ssh_generate())
                return self._send(200, self.agent.redirect.ssh_upload(body.get("key")))
            if path == "/api/cert/pull-token":
                if body.get("revoke"):
                    self.agent.certs.drop_pull_token()
                    return self._send(200, {"ok": True})
                return self._send(200, {"ok": True, "token": self.agent.certs.new_pull_token()})
            m = _ACTION_RE.fullmatch(path)
            if m:
                if m.group(1) not in ACTIONS:
                    raise HTTPError(404, "Unbekannte Aktion.")
                log("action %s", m.group(1))
                return self._send(200, self.agent.action(m.group(1)))
        if path.startswith("/api/"):
            raise HTTPError(404 if method in ("GET", "POST") else 405, "Nicht gefunden.")

    def _download(self, name):
        try:
            filename, ctype, data = self.agent.certs.download(name)
        except KeyError:
            raise HTTPError(404, "Nicht gefunden.")
        headers = {"Content-Disposition": 'attachment; filename="%s"' % filename}
        return self._send(200, data, ctype=ctype, headers=headers)

    def _pull(self, path):
        """GET /api/cert/download/<file> with ``Authorization: Bearer <pull token>`` (rate limited per IP)."""
        ip = self.client_ip
        if self.server.sessions.blocked(ip):
            raise HTTPError(429, "Zu viele Fehlversuche. Bitte 10 Minuten warten.")
        auth_header = self.headers.get("Authorization") or ""
        token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
        if not self.agent.certs.check_pull_token(token):
            self.server.sessions.fail(ip)
            log("certificate pull refused for %s", ip)
            raise HTTPError(401, "Token ungültig.")
        self.server.sessions.reset(ip)
        name = _DOWNLOAD_RE.fullmatch(path).group(1)
        log("certificate pull (%s) by %s", name, ip)
        return self._download(name)

    def _static(self):
        path = os.path.join(self.server.web_dir, "index.html")
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            raise HTTPError(404, "UI fehlt.")
        data = data.replace(b"/*PF_I18N*/{}/*PF_I18N*/", self._texts(), 1)
        self._send(200, data, ctype="text/html; charset=utf-8")

    def _texts(self):
        """UI texts from web/lang/<code>.json as a JS object literal for the page (no extra request, CSP stays)."""
        folder, out = os.path.join(self.server.web_dir, "lang"), {}
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            names = []
        for name in names:
            if not _LANG_RE.fullmatch(name):
                continue
            try:
                with open(os.path.join(folder, name), encoding="utf-8") as fh:
                    texts = json.load(fh)
            except (OSError, ValueError):
                continue
            if isinstance(texts, dict):
                out[name[:-5]] = {str(k): str(v) for k, v in texts.items()}
        # "<" escaped so no text can close the script element
        return json.dumps(out, ensure_ascii=False).replace("<", "\\u003c").encode("utf-8")

    def _set_password(self, body, first=False):
        ip = self.client_ip
        if not first and self.server.sessions.blocked(ip):
            raise HTTPError(429, "Zu viele Fehlversuche. Bitte 10 Minuten warten.")
        try:
            self.agent.set_password(body.get("password"), body.get("old_password"), first=first)
        except PasswordError:
            self.server.sessions.fail(ip)
            raise
        self.server.sessions.drop_all()
        token = self.server.sessions.create()
        self._send(200, {"ok": True}, headers=self._set_cookie(token))

    def _login(self, body):
        ip = self.client_ip
        if self.server.sessions.blocked(ip):
            log("login blocked for %s (too many failures)", ip)
            raise HTTPError(429, "Zu viele Fehlversuche. Bitte 10 Minuten warten.")
        if not self.agent.check_password(body.get("password")):
            self.server.sessions.fail(ip)
            log("login failed from %s", ip)
            raise HTTPError(401, "Passwort falsch.")
        self.server.sessions.reset(ip)
        token = self.server.sessions.create()
        log("login from %s", ip)
        self._send(200, {"ok": True}, headers=self._set_cookie(token))
