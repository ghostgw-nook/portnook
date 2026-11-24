"""0.31.0: round robin with Cloudflare runs as a Worker (``portnook-redirect``) with one route per entry host."""
import json
import unittest
from unittest import mock

from app import httpc, redirect

ZONE = "0123456789abcdef0123456789abcdef"
TOKEN = "cf-token-1234567890abcdef"
ACCOUNT = "acc0123"
BASE = "https://cf.test/client/v4"


class FakeCf:
    """Records the calls; keeps routes and the redirect ruleset of one zone."""

    def __init__(self, routes=None, rules=None, script_status=200, subdomain="familie-muster"):
        self.routes = routes or []
        self.ruleset = {"id": "rs1", "rules": rules or []}
        self.script = None
        self.script_status = script_status
        self.calls = []
        self.subdomain = subdomain
        self.scripts = {}
        self.dev_on = {}

    def __call__(self, method, url, body=None, headers=None, device=None, timeout=20, **kw):
        path = url[len(BASE):]
        self.calls.append((method, path))
        ok = lambda result: httpc.Response(200, {}, json.dumps({"success": True, "result": result}).encode())
        if path == "/zones/%s" % ZONE:
            return ok({"id": ZONE, "account": {"id": ACCOUNT}})
        if path == "/accounts":
            return ok([{"id": ACCOUNT, "name": "Muster"}])
        if path == "/accounts/%s/workers/subdomain" % ACCOUNT:
            if not self.subdomain:
                return httpc.Response(404, {}, b'{"success": false, "errors": [{"message": "no subdomain"}]}')
            return ok({"subdomain": self.subdomain})
        if path.startswith("/accounts/%s/workers/scripts/" % ACCOUNT) and path.endswith("/subdomain") and method == "POST":
            self.dev_on[path.split("/")[-2]] = body
            return ok({})
        if path.startswith("/accounts/%s/workers/scripts/" % ACCOUNT) and method == "PUT":
            self.scripts[path.rsplit("/", 1)[1]] = body
            self.script = (body, headers.get("Content-Type"))
            return httpc.Response(self.script_status, {}, json.dumps({"success": self.script_status < 400}).encode())
        if path == "/zones/%s/workers/routes" % ZONE:
            if method == "GET":
                return ok(self.routes)
            data = body if isinstance(body, dict) else json.loads(body)
            self.routes.append(dict(data, id="r%d" % len(self.routes)))
            return ok(self.routes[-1])
        if path.startswith("/zones/%s/workers/routes/" % ZONE) and method == "DELETE":
            rid = path.rsplit("/", 1)[1]
            self.routes = [r for r in self.routes if r["id"] != rid]
            return ok({"id": rid})
        if path == "/zones/%s/rulesets/phases/%s/entrypoint" % (ZONE, redirect.PHASE):
            return ok(self.ruleset)
        if path == "/zones/%s/rulesets/rs1/rules" % ZONE and method == "POST":
            self.ruleset["rules"].append(dict(body, id="n%d" % len(self.ruleset["rules"])))
            return ok(self.ruleset)
        if path.startswith("/zones/%s/rulesets/rs1/rules/" % ZONE) and method == "PATCH":
            rid = path.rsplit("/", 1)[1]
            self.ruleset["rules"] = [dict(body, id=rid) if r["id"] == rid else r for r in self.ruleset["rules"]]
            return ok(self.ruleset)
        if path.startswith("/zones/%s/rulesets/rs1/rules/" % ZONE) and method == "DELETE":
            rid = path.rsplit("/", 1)[1]
            self.ruleset["rules"] = [r for r in self.ruleset["rules"] if r["id"] != rid]
            return ok(self.ruleset)
        return httpc.Response(404, {}, b'{"success": false, "errors": [{"message": "no route"}]}')


class WorkerTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict("os.environ", {"PF_CLOUDFLARE_API": BASE})
        p.start()
        self.addCleanup(p.stop)

    RULES = [("start.example.ch", ["https://tv.a.example.ch:41000", "https://tv.b.example.ch:51000"]),
             ("*.eingang-muster.myaddr.io", ["https://*.a.example.ch:41000"])]

    def test_script_routes_and_rules(self):
        cf = FakeCf(routes=[{"id": "x", "pattern": "old.example.ch/*", "script": redirect.WORKER_NAME},
                            {"id": "y", "pattern": "shop.example.ch/*", "script": "someone-else"}],
                    rules=[{"id": "p1", "description": "portnook redirect start.example.ch"},
                           {"id": "p2", "description": "pf-agent redirect start.example.ch"},
                           {"id": "f1", "description": "someone else"}])
        self.assertEqual(redirect.cloudflare_worker_apply(TOKEN, ZONE, self.RULES, 307, request=cf),
                         "Worker aktualisiert, 2 Route(n)")
        body, ctype = cf.script
        self.assertTrue(ctype.startswith("multipart/form-data; boundary=portnook"))
        text = body.decode()
        self.assertIn('"main_module": "worker.js"', text)
        self.assertIn("const STATUS = 307;", text)
        self.assertIn("https://tv.b.example.ch:51000", text)
        self.assertNotIn(TOKEN, text)
        self.assertEqual(sorted((r["pattern"], r["script"]) for r in cf.routes),
                         [("*.eingang-muster.myaddr.io/*", redirect.WORKER_NAME),
                          ("shop.example.ch/*", "someone-else"), ("start.example.ch/*", redirect.WORKER_NAME)])
        # portnook's redirect rules would run before the Worker: removed, foreign rules stay
        self.assertEqual([r["id"] for r in cf.ruleset["rules"]], ["f1"])
        # again: nothing new to create
        n = len(cf.routes)
        redirect.cloudflare_worker_apply(TOKEN, ZONE, self.RULES, 307, request=cf)
        self.assertEqual(len(cf.routes), n)

    def test_route_of_other_worker_is_an_error(self):
        cf = FakeCf(routes=[{"id": "y", "pattern": "start.example.ch/*", "script": "someone-else"}])
        with self.assertRaises(redirect.RedirectError) as ctx:
            redirect.cloudflare_worker_apply(TOKEN, ZONE, self.RULES, 302, request=cf)
        self.assertIn("anderen Worker", str(ctx.exception))

    def test_missing_permission(self):
        cf = FakeCf(script_status=403)
        with self.assertRaises(redirect.RedirectError) as ctx:
            redirect.cloudflare_worker_apply(TOKEN, ZONE, self.RULES, 302, request=cf)
        self.assertIn("Workers Scripts: Edit", str(ctx.exception))
        self.assertNotIn(TOKEN, str(ctx.exception))

    def test_remove_keeps_foreign_routes(self):
        cf = FakeCf(routes=[{"id": "x", "pattern": "start.example.ch/*", "script": redirect.WORKER_NAME},
                            {"id": "y", "pattern": "shop.example.ch/*", "script": "someone-else"}])
        redirect.cloudflare_worker_remove(TOKEN, ZONE, request=cf)
        self.assertEqual([r["id"] for r in cf.routes], ["y"])

    def test_workers_dev_without_zone(self):
        """0.36.0: <worker>.<account>.workers.dev: Worker named after the first label, switched on there."""
        cf = FakeCf()
        rules = [("tv.familie-muster.workers.dev", ["https://tv.a.example.ch:41000", "https://tv.b.example.ch:51000"])]
        self.assertEqual(redirect.workers_dev_apply(TOKEN, "", rules[0][0], rules, 302, request=cf),
                         "tv.familie-muster.workers.dev: Worker aktualisiert")
        self.assertIn("tv", cf.scripts)
        self.assertIn("tv.b.example.ch:51000", cf.scripts["tv"].decode())
        self.assertEqual(cf.dev_on["tv"], {"enabled": True, "previews_enabled": False})
        self.assertEqual(cf.routes, [])
        for bad, sub in (("tv.anderer.workers.dev", "familie-muster"), ("tv.familie-muster.workers.dev", "")):
            cf = FakeCf(subdomain=sub)
            with self.assertRaises(redirect.RedirectError) as ctx:
                redirect.workers_dev_apply(TOKEN, "", bad, rules, 302, request=cf)
            self.assertIn("Konto-Subdomain", str(ctx.exception))

    def test_host_patterns(self):
        self.assertEqual(redirect._js_re("start.example.ch"), r"^start\.example\.ch$")
        self.assertEqual(redirect._js_re("*.eingang-muster.myaddr.io"), r"^([a-z0-9-]+)\.eingang-muster\.myaddr\.io$")


if __name__ == "__main__":
    unittest.main()
