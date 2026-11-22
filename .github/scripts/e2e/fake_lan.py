"""E2E stand-ins (run with python3 inside the agent image, stdlib only):
  :8000  myaddr.tools  POST /update (key + ip | acme_challenge; ip=self is counted and refused); challenges are forwarded as TXT records to
                       pebble-challtestsrv (all values on _acme-challenge.<name>.<domain>, like myaddr.tools)
  :8081  Nginx Proxy Manager  POST /api/tokens, GET/POST /api/nginx/certificates, POST .../<id>/upload
  :8082  catch-all "internet" (ACME directory, Cloudflare, Gotify POST /message, ntfy JSON POST /): answers
         200 {} and records method, path and the push title in "other"
  GET /state on any port: what was received (JSON); "hits" counts every other request on all ports.
Usage: python3 fake_lan.py <key> <fqdn> <challtestsrv mgmt URL> <npm identity> <npm secret>
"""
import json
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY, FQDN, CHALL, NPM_ID, NPM_SECRET = sys.argv[1:6]
STATE = {"ips": [], "self": 0, "challenges": 0, "bad": 0, "certs": [], "uploads": [], "hits": 0, "other": []}
LOCK = threading.Lock()


def multipart_files(ctype, body):
    boundary = ctype.split("boundary=", 1)[1].encode()
    out = {}
    for part in body.split(b"--" + boundary):
        if b"\r\n\r\n" not in part:
            continue
        head, data = part.split(b"\r\n\r\n", 1)
        name = head.split(b'name="', 1)[1].split(b'"', 1)[0].decode()
        out[name] = data.rsplit(b"\r\n", 1)[0].decode()
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, obj):
        data = (obj if isinstance(obj, str) else json.dumps(obj)).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain" if isinstance(obj, str) else "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def count(self, body=b""):
        with LOCK:
            STATE["hits"] += 1
            if self.server.server_port == 8082:
                try:
                    title = json.loads(body or b"{}").get("title", "")
                except (ValueError, AttributeError):
                    title = ""
                STATE["other"].append({"method": self.command, "path": self.path, "title": title})

    def do_GET(self):
        if self.path == "/state":
            with LOCK:
                return self.reply(200, STATE)
        self.count()
        if self.server.server_port == 8082:
            return self.reply(200, {})
        if self.path == "/api/nginx/certificates" and self.server.server_port == 8081:
            if self.headers.get("Authorization") != "Bearer fake-jwt":
                return self.reply(401, {"error": {"message": "Unauthorized"}})
            return self.reply(200, STATE["certs"])
        self.reply(404, {"error": {"message": "not found"}})

    def do_POST(self):
        body = self.body()
        self.count(body)
        if self.server.server_port == 8082:
            return self.reply(200, {})
        if self.server.server_port == 8000 and self.path == "/update":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            if form.get("key") != KEY:
                with LOCK:
                    STATE["bad"] += 1
                return self.reply(400, 'invalid value for "key"\n')
            if bool(form.get("ip")) == bool(form.get("acme_challenge")):
                return self.reply(400, 'must specify either "ip" or "acme_challenge"\n')
            if form.get("ip", "").lower() == "self":  # the home IP must never be published (0.9.1)
                with LOCK:
                    STATE["self"] += 1
                return self.reply(400, 'ip=self is not allowed in this test\n')
            if form.get("ip"):
                with LOCK:
                    STATE["ips"].append(form["ip"])
                return self.reply(200, "OK\n")
            req = urllib.request.Request(CHALL + "/set-txt", method="POST", data=json.dumps(
                {"host": "_acme-challenge.%s." % FQDN, "value": form["acme_challenge"]}).encode())
            urllib.request.urlopen(req, timeout=10).read()
            with LOCK:
                STATE["challenges"] += 1
            return self.reply(200, "OK\n")
        if self.server.server_port == 8081:
            if self.path == "/api/tokens":
                data = json.loads(body)
                if data != {"identity": NPM_ID, "secret": NPM_SECRET}:
                    return self.reply(401, {"error": {"message": "Invalid email or password"}})
                return self.reply(200, {"token": "fake-jwt", "expires": "2099-01-01T00:00:00.000Z"})
            if self.headers.get("Authorization") != "Bearer fake-jwt":
                return self.reply(401, {"error": {"message": "Unauthorized"}})
            if self.path == "/api/nginx/certificates":
                data = json.loads(body)
                with LOCK:
                    cert = {"id": 40 + len(STATE["certs"]), "provider": data["provider"], "nice_name": data["nice_name"]}
                    STATE["certs"].append(cert)
                return self.reply(201, cert)
            if self.path.endswith("/upload"):
                files = multipart_files(self.headers["Content-Type"], body)
                with LOCK:
                    STATE["uploads"].append({"id": int(self.path.split("/")[4]), "files": sorted(files),
                                             "certificate": files.get("certificate", "")})
                return self.reply(200, {"certificate": True})
        self.reply(404, {"error": {"message": "not found"}})


for port in (8000, 8081, 8082):
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
print("fake myaddr :8000, fake npm :8081, catch-all :8082", flush=True)
threading.Event().wait()
