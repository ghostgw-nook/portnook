"""Push ping storage backends: where the sealed drops live (``pushping`` setting ``storage``).

* ``webdav``: one file per device, ``PUT``/``DELETE`` on a WebDAV folder (``upload_url``, user, password).
* ``cloudflare``: no extra host. The Cloudflare token of the redirect host uploads a small Worker
  ``portnook-drops`` that carries all drops and serves them on ``https://portnook-drops.<account>.workers.dev``.
  Every publish uploads the whole Worker (a drop is ~250 bytes, 100 devices ~35 KB). Token permission:
  Workers Scripts: Edit (as for round robin / workers.dev).

* ``script``: the web space of the redirect script (generator settings: SSH user, host, port, web root, and the
  SSH key made for the redirect). Files go to ``<web root>/_pnd/<path>.bin`` over SSH and are served by the
  entry host itself: ``https://<entry host>/_pnd/<path>.bin``. The generated ``.htaccess`` leaves ``/_pnd/``
  alone (no redirect there).

* ``php``: a single ``pn.php`` made by portnook (``php_script``) on any web space with PHP 7+, no SSH or WebDAV
  needed. Uploads and deletes are HTTPS POSTs signed with a key only portnook and that file know
  (HMAC-SHA256 over action, path, time and body hash; 5 minutes skew). The app fetches
  ``pn.php?d=<path>`` without a login.

All requests go through the VPN tunnel (``internet`` route; SSH runs from the container, whose default route
is the tunnel). A backend raises ``httpc.HttpError`` on failure.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import subprocess
import time

from . import httpc

DROP_WORKER = "portnook-drops"
_PATH = re.compile(r"[0-9a-f]{32}")


class WebDav:
    kind = "webdav"
    whole = False  # uploads one file at a time

    def __init__(self, pub):
        self.pub = pub

    def _cfg(self):
        st = self.pub.agent.store.section("pushping")
        return st.get("upload_url") or "", st.get("upload_user") or "", st.get("upload_pass") or ""

    def ready(self):
        return bool(self._cfg()[0])

    def base(self):
        return self._cfg()[0]

    def _send(self, method, name, body=None):
        url, user, password = self._cfg()
        headers = {"Content-Type": "application/octet-stream", "Cache-Control": "no-cache"}
        if user or password:
            headers["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        res = self.pub.request(method, "%s/%s.bin" % (url, name), body=body, headers=headers,
                               device=self.pub.agent.egress.route("internet"), timeout=20)
        if method == "DELETE" and res.status == 404:
            return
        if res.status not in (200, 201, 204):
            raise httpc.HttpError("Zero-Trust-Seite antwortete %d" % res.status)

    def put(self, name, data):
        self._send("PUT", name, data)

    def delete(self, name):
        self._send("DELETE", name)

    def finish(self, table):
        pass


def drop_worker_js(table):
    """Worker that serves ``/<path>.bin`` from ``table`` ({path: drop bytes}); everything else is 404."""
    rows = json.dumps({p: base64.b64encode(d).decode() for p, d in sorted(table.items()) if _PATH.fullmatch(p)},
                      separators=(",", ":"))
    return ("// managed by portnook, do not edit\nconst D = %s;\n"
            "export default {\n  async fetch(req) {\n"
            "    const m = new URL(req.url).pathname.match(/^\\/([0-9a-f]{32})\\.bin$/);\n"
            "    const d = m && req.method === \"GET\" ? D[m[1]] : undefined;\n"
            "    if (!d) return new Response(\"\", { status: 404 });\n"
            "    const b = Uint8Array.from(atob(d), (c) => c.charCodeAt(0));\n"
            "    return new Response(b, { headers: { \"content-type\": \"application/octet-stream\",\n"
            "      \"cache-control\": \"no-store\", \"access-control-allow-origin\": \"*\" } });\n"
            "  },\n};\n" % rows)


class CloudflareWorker:
    kind = "cloudflare"
    whole = True  # every publish uploads all drops

    def __init__(self, pub):
        self.pub = pub

    def _cred(self):
        """``{token, zone}`` of the first Cloudflare provider of the redirect host, else ``None``."""
        cfg = self.pub.agent.store.section("redirect")
        if cfg.get("provider") == "cloudflare" and (cfg.get("cf") or {}).get("token"):
            return cfg["cf"]
        for x in cfg.get("providers") or []:
            if x.get("kind") == "cloudflare" and (x.get("cf") or {}).get("token"):
                return x["cf"]
        return None

    def ready(self):
        return self._cred() is not None

    def base(self):
        return self.pub.agent.store.section("pushping").get("cf_base") or ""

    def _account(self, cf):
        from . import redirect  # late: redirect imports agent
        req, dev, base = self.pub.request, self.pub.agent.egress.route("internet"), redirect.cf_base()
        try:
            if cf.get("zone"):
                zone = redirect._zone_id(req, base, cf["token"], cf["zone"], dev)
                account = ((redirect._cf(req, "GET", "%s/zones/%s" % (base, zone), cf["token"], dev) or {})
                           .get("account") or {}).get("id")
            else:
                accounts = redirect._cf(req, "GET", base + "/accounts", cf["token"], dev) or []
                account = accounts[0].get("id") if accounts and isinstance(accounts[0], dict) else None
            if not account:
                raise httpc.HttpError("Cloudflare: Konto nicht gefunden")
            sub = (redirect._cf(req, "GET", "%s/accounts/%s/workers/subdomain" % (base, account), cf["token"], dev,
                                ok404=True) or {}).get("subdomain")
        except redirect.RedirectError as err:
            raise httpc.HttpError(str(err))
        if not sub:
            raise httpc.HttpError("Cloudflare: workers.dev-Subdomain fehlt (Workers & Pages einmal öffnen)")
        return base, account, sub

    def resolve(self):
        """Find and store the public base URL (``cf_base``); returns it."""
        cf = self._cred()
        if cf is None:
            raise httpc.HttpError("kein Cloudflare-Token beim Redirect-Host")
        _, _, sub = self._account(cf)
        url = "https://%s.%s.workers.dev" % (DROP_WORKER, sub)
        if url != self.base():
            self.pub.agent.store.update("pushping", {"cf_base": url})
        return url

    def put(self, name, data):
        pass

    def delete(self, name):
        pass

    def finish(self, table):
        from . import redirect
        cf = self._cred()
        if cf is None:
            raise httpc.HttpError("kein Cloudflare-Token beim Redirect-Host")
        base, account, sub = self._account(cf)
        req, dev = self.pub.request, self.pub.agent.egress.route("internet")
        body, ctype = redirect._multipart(drop_worker_js(table))
        res = req("PUT", "%s/accounts/%s/workers/scripts/%s" % (base, account, DROP_WORKER), body=body, device=dev,
                  timeout=30, headers={"Authorization": "Bearer " + cf["token"], "Accept": "application/json",
                                       "Content-Type": ctype})
        if res.status >= 400:
            raise httpc.HttpError("Cloudflare Worker HTTP %d (Token braucht Workers Scripts: Edit)" % res.status)
        try:
            redirect._cf(req, "POST", "%s/accounts/%s/workers/scripts/%s/subdomain" % (base, account, DROP_WORKER),
                         cf["token"], dev, body={"enabled": True, "previews_enabled": False})
        except redirect.RedirectError as err:
            raise httpc.HttpError(str(err))
        url = "https://%s.%s.workers.dev" % (DROP_WORKER, sub)
        if url != self.base():
            self.pub.agent.store.update("pushping", {"cf_base": url})


_run = subprocess.run  # tests replace this
DROP_DIR = "_pnd"
SSH_TIMEOUT = 30
# no "Options" (some hosts forbid it in .htaccess and answer 500); an empty index.html stops listings
DIR_HTACCESS = "<IfModule mod_headers.c>\n  Header always set Cache-Control \"no-store\"\n</IfModule>\n"


class SshScript:
    kind = "script"
    whole = False

    def __init__(self, pub):
        self.pub = pub

    def _source(self):
        """``(gen settings, entry host)`` of the first script provider made with the generator, else ``None``."""
        red = self.pub.agent.redirect
        cfg = self.pub.agent.store.section("redirect")
        if cfg.get("provider") == "script" and (cfg.get("gen") or {}).get("kind"):
            hosts = [cfg.get("entry_host") or ""]
        else:
            x = next((x for x in cfg.get("providers") or []
                      if x.get("kind") == "script" and (x.get("gen") or {}).get("kind")), None)
            if x is None:
                return None
            tgt = red.target() or {"url": "https://x"}
            try:
                hosts = [e for e, _ in red.mappings(cfg, tgt, via=x["id"])]
            except Exception:  # an unknown target only hides the address, the upload still works
                hosts = []
            cfg = x
        host = next((h for h in hosts if h and not h.startswith("*.")), "")
        return cfg["gen"], host

    def ready(self):
        return self._source() is not None and self.pub.agent.redirect.ssh_public() != ""

    def base(self):
        src = self._source()
        return "https://%s/%s" % (src[1], DROP_DIR) if src and src[1] else ""

    def _ssh(self, command, data=b""):
        g, _ = self._source()
        red = self.pub.agent.redirect
        args = ["ssh", "-i", red._p("id_ed25519"), "-p", str(g["port"]), "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "UserKnownHostsFile=" + red._p("known_hosts"), "%s@%s" % (g["user"], g["host"]), command]
        try:
            res = _run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=SSH_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as err:
            raise httpc.HttpError("SSH: %s" % (getattr(err, "strerror", None) or err.__class__.__name__))
        if res.returncode != 0:
            raise httpc.HttpError("SSH rc %d: %s" % (res.returncode, res.stderr.decode("utf-8", "replace").strip()[-160:]))

    def _dir(self):
        g, _ = self._source()
        return "%s/%s" % (g["root"], DROP_DIR)  # root is checked by redirect.check_gen (no quotes, no ..)

    def put(self, name, data):
        if not _PATH.fullmatch(name):
            raise httpc.HttpError("Dateiname ungültig")
        d = self._dir()
        # the .htaccess text has no single quote, % or backslash, so printf's format can carry it with \n
        self._ssh("mkdir -p '{d}' && touch '{d}/index.html' && printf '{h}' > '{d}/.htaccess' && "
                  "cat > '{d}/{n}.bin.tmp' && mv '{d}/{n}.bin.tmp' '{d}/{n}.bin'"
                  .format(d=d, n=name, h=DIR_HTACCESS.replace("\n", "\\n")), data)

    def delete(self, name):
        if _PATH.fullmatch(name):
            self._ssh("rm -f '%s/%s.bin'" % (self._dir(), name))

    def finish(self, table):
        pass


PHP_TEMPLATE = r"""<?php
// portnook push ping storage. Made by portnook, do not edit; replace it with a new download when portnook
// shows a new key. Files: one sealed, signed file per device (only that device can read it).
//   GET  pn.php?d=<path>                       -> the file (no login, no cache)
//   POST pn.php?a=put&d=<path>  (body = file)  -> store it   } signed: X-PN-Time, X-PN-Sig =
//   POST pn.php?a=del&d=<path>                 -> delete it  } HMAC-SHA256(key, "a\nd\ntime\nsha256(body)")
//   GET  pn.php?ping                           -> {"ok":true}
const PN_KEY = '__KEY__';
const PN_DIR = __DIR__ . '/pn-drops';
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
function pn_out($code, $text = '') { http_response_code($code); header('Content-Type: application/json'); echo $text; exit; }
$d = isset($_GET['d']) ? preg_replace('/\.bin$/', '', (string) $_GET['d']) : '';
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['ping'])) pn_out(200, '{"ok":true,"v":1}');
    if (!preg_match('/^[0-9a-f]{32}$/', $d) || !is_file(PN_DIR . "/$d.bin")) pn_out(404);
    header('Content-Type: application/octet-stream');
    header('Access-Control-Allow-Origin: *');
    readfile(PN_DIR . "/$d.bin");
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') pn_out(405);
$a = isset($_GET['a']) ? (string) $_GET['a'] : '';
$t = isset($_SERVER['HTTP_X_PN_TIME']) ? (string) $_SERVER['HTTP_X_PN_TIME'] : '';
$sig = isset($_SERVER['HTTP_X_PN_SIG']) ? (string) $_SERVER['HTTP_X_PN_SIG'] : '';
$body = file_get_contents('php://input', false, null, 0, 8192);
if (!in_array($a, array('put', 'del'), true) || !preg_match('/^[0-9a-f]{32}$/', $d) || !ctype_digit($t)
    || abs(time() - (int) $t) > 300) pn_out(400);
$want = hash_hmac('sha256', "$a\n$d\n$t\n" . hash('sha256', $body), PN_KEY);
if (!hash_equals($want, $sig)) pn_out(403);
if (!is_dir(PN_DIR)) {
    @mkdir(PN_DIR, 0755);
    @file_put_contents(PN_DIR . '/.htaccess', "Require all denied\n");
    @file_put_contents(PN_DIR . '/index.html', '');
}
if ($a === 'del') { @unlink(PN_DIR . "/$d.bin"); pn_out(200, '{"ok":true}'); }
if (strlen($body) < 100 || substr($body, 0, 4) !== 'PNP1') pn_out(400);
$tmp = PN_DIR . "/$d.tmp";
if (file_put_contents($tmp, $body) === false || !rename($tmp, PN_DIR . "/$d.bin")) pn_out(500);
pn_out(200, '{"ok":true}');
"""


def php_script(key):
    return PHP_TEMPLATE.replace("__KEY__", key)


def php_sign(key, action, path, when, body):
    msg = "%s\n%s\n%d\n%s" % (action, path, when, hashlib.sha256(body).hexdigest())
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


class PhpPage:
    kind = "php"
    whole = False

    def __init__(self, pub):
        self.pub = pub

    def _cfg(self):
        st = self.pub.agent.store.section("pushping")
        return st.get("php_url") or "", st.get("php_key") or ""

    def ready(self):
        url, key = self._cfg()
        return bool(url and key)

    def base(self):
        return self._cfg()[0]

    def _send(self, action, name, body=b""):
        if not _PATH.fullmatch(name):
            raise httpc.HttpError("Dateiname ungültig")
        url, key = self._cfg()
        when = int(time.time())
        res = self.pub.request("POST", "%s?a=%s&d=%s" % (url, action, name), body=body,
                               headers={"Content-Type": "application/octet-stream", "X-PN-Time": str(when),
                                        "X-PN-Sig": php_sign(key, action, name, when, body)},
                               device=self.pub.agent.egress.route("internet"), timeout=20)
        if res.status != 200:
            hint = {403: " (Schlüssel passt nicht: pn.php neu herunterladen)", 400: " (Uhrzeit oder Anfrage)",
                    404: " (pn.php nicht gefunden)"}.get(res.status, "")
            raise httpc.HttpError("pn.php antwortete %d%s" % (res.status, hint))

    def put(self, name, data):
        self._send("put", name, data)

    def delete(self, name):
        self._send("del", name)

    def finish(self, table):
        pass


def new_php_key():
    return secrets.token_hex(32)


BACKENDS = {"webdav": WebDav, "cloudflare": CloudflareWorker, "script": SshScript, "php": PhpPage}
