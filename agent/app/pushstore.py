"""Push ping storage backends: where the sealed drops live (``pushping`` setting ``storage``).

* ``webdav``: one file per device, ``PUT``/``DELETE`` on a WebDAV folder (``upload_url``, user, password).
* ``cloudflare``: no extra host. The Cloudflare token of the redirect host uploads a small Worker
  ``portnook-drops`` that carries all drops and serves them on ``https://portnook-drops.<account>.workers.dev``.
  Every publish uploads the whole Worker (a drop is ~250 bytes, 100 devices ~35 KB). Token permission:
  Workers Scripts: Edit (as for round robin / workers.dev).

All requests go through the VPN tunnel (``internet`` route). A backend raises ``httpc.HttpError`` on failure.
"""

import base64
import json
import re

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


BACKENDS = {"webdav": WebDav, "cloudflare": CloudflareWorker}
