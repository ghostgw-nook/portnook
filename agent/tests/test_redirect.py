import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from app import myaddr, net as netmod, redirect
from app.agent import Agent
from app.store import Store
from app.validate import ValidationError
from tests.fakes import FakeHttp, FakeRun, base_responses

ZONE = "0123456789abcdef0123456789abcdef"
TOKEN = "cf-token-1234567890abcdef"


class FakeCloudflare:
    def __init__(self, existing=None):
        self.ruleset = existing  # None = no entry point ruleset (404)
        self.calls = []
        self.srv = FakeHttp(self.handle)

    def handle(self, method, path, headers, body):
        self.calls.append((method, path))
        if headers.get("Authorization") != "Bearer " + TOKEN:
            return 403, {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}
        entry = "/zones/%s/rulesets/phases/%s/entrypoint" % (ZONE, redirect.PHASE)
        data = json.loads(body) if body else None
        if path.startswith("/zones?name="):
            return 200, {"success": True, "result": [{"id": ZONE, "name": "example.ch"}]}
        if path == entry and method == "GET":
            if self.ruleset is None:
                return 404, {"success": False, "errors": [{"code": 10003, "message": "not found"}]}
            return 200, {"success": True, "result": self.ruleset}
        if path == entry and method == "PUT":
            self.ruleset = {"id": "rs1", "phase": redirect.PHASE,
                            "rules": [dict(r, id="r%d" % i) for i, r in enumerate(data["rules"])]}
            return 200, {"success": True, "result": self.ruleset}
        base = "/zones/%s/rulesets/%s/rules" % (ZONE, self.ruleset["id"] if self.ruleset else "-")
        if path == base and method == "POST":
            self.ruleset["rules"].append(dict(data, id="new"))
            return 200, {"success": True, "result": self.ruleset}
        if path.startswith(base + "/") and method == "PATCH":
            rid = path.rsplit("/", 1)[1]
            self.ruleset["rules"] = [dict(data, id=rid) if r["id"] == rid else r for r in self.ruleset["rules"]]
            return 200, {"success": True, "result": self.ruleset}
        return 404, {"success": False, "errors": [{"message": "no route"}]}


class CloudflareTest(unittest.TestCase):
    def setUp(self):
        try:
            self.cf = FakeCloudflare()
        except OSError as err:
            self.skipTest("cannot bind local port: %s" % err)
        self.addCleanup(self.cf.srv.close)
        p = mock.patch.dict(os.environ, {"PF_CLOUDFLARE_API": self.cf.srv.url})
        p.start()
        self.addCleanup(p.stop)

    def test_create_update_idempotent(self):
        self.assertIn("neues Ruleset", redirect.cloudflare_apply(TOKEN, ZONE, "start.example.ch", "https://a.b:1", 302))
        rule = self.cf.ruleset["rules"][0]
        self.assertEqual(rule["expression"], '(http.host eq "start.example.ch")')
        fv = rule["action_parameters"]["from_value"]
        self.assertEqual(fv["status_code"], 302)
        self.assertEqual(fv["target_url"]["expression"], 'concat("https://a.b:1", http.request.uri.path)')
        self.assertTrue(fv["preserve_query_string"])
        self.assertEqual(redirect.cloudflare_apply(TOKEN, ZONE, "start.example.ch", "https://a.b:2", 307),
                         "Regel aktualisiert")
        self.assertEqual(len(self.cf.ruleset["rules"]), 1)
        self.assertIn("https://a.b:2", json.dumps(self.cf.ruleset["rules"][0]))

    def test_rule_from_before_rename_taken_over(self):
        self.cf.ruleset = {"id": "rs9", "rules": [{"id": "old", "description": "pf-agent redirect start.example.ch",
                                                   "expression": "true"}]}
        self.assertEqual(redirect.cloudflare_apply(TOKEN, ZONE, "start.example.ch", "https://a.b:1", 302),
                         "Regel aktualisiert")
        self.assertEqual([(r["id"], r["description"]) for r in self.cf.ruleset["rules"]],
                         [("old", "portnook redirect start.example.ch")])

    def test_foreign_rules_kept_and_zone_by_name(self):
        self.cf.ruleset = {"id": "rs9", "rules": [{"id": "x", "description": "someone else", "expression": "true"}]}
        self.assertEqual(redirect.cloudflare_apply(TOKEN, "example.ch", "start.example.ch", "https://a.b:1", 302),
                         "Regel angelegt")
        self.assertEqual([r["id"] for r in self.cf.ruleset["rules"]], ["x", "new"])

    def test_error_without_token_text(self):
        with self.assertRaises(redirect.RedirectError) as ctx:
            redirect.cloudflare_apply("wrong-token-1234567890", ZONE, "start.example.ch", "https://a.b:1", 302)
        self.assertIn("Authentication error", str(ctx.exception))
        self.assertNotIn("wrong-token", str(ctx.exception))


class RedirectAgentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = base_responses(FakeRun(), wg0=True)
        p = mock.patch("app.sysrun.run", self.fake)
        p.start()
        self.addCleanup(p.stop)
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.store.update("proton", {"decided": True, "enabled": True, "conf": "[Interface]\n"})
        self.store.update("myaddr", {"name": "familie-muster", "domain": "myaddr.tools", "key": "A" * 43})
        self.now = [1763300000]
        self.agent = Agent(self.store, netmod.Net(wg_dir=self.tmp), clock=lambda: self.now[0])
        self.agent.forward_port = 51234
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.7"
        self.up = [True]
        self.agent.egress.tunnel_up = lambda: self.up[0]
        self.agent.egress._resolve = lambda host: ["203.0.113.80"]
        self.r = self.agent.redirect

    def test_target(self):
        self.assertEqual(self.r.target({"sub": "app"}),
                         {"url": "https://app.familie-muster.myaddr.tools:51234",
                          "host": "app.familie-muster.myaddr.tools", "port": 51234, "ip": "198.51.100.7"})
        self.agent.forward_port = 0
        self.assertIsNone(self.r.target({}))

    def test_target_never_home_ip(self):
        self.store.update("proton", {"enabled": False})
        cfg = {"sub": "", "fixed_port": 8443}
        self.assertIsNone(self.r.target(cfg))  # vpn mode, no VPN, no fallback: nothing applied
        self.store.update("myaddr", {"fallback_ip": "203.0.113.9"})
        self.assertEqual(self.r.target(cfg)["ip"], "203.0.113.9")
        self.store.update("myaddr", {"ip_mode": "manual", "manual_ip": "203.0.113.5"})
        self.assertEqual(self.r.target(cfg)["ip"], "203.0.113.5")
        self.store.update("myaddr", {"ip_mode": "line"})  # dropped mode: treated as vpn
        self.assertEqual(self.r.target(cfg)["ip"], "203.0.113.9")

    def test_target_fixed_port_provider(self):
        self.store.update("proton", {"provider": "fixed", "ports": [43210, 43211]})
        self.agent.forward_port = 0
        self.assertEqual(self.r.target({"fixed_port": 8443})["url"], "https://familie-muster.myaddr.tools:43210")

    def test_validation(self):
        with self.assertRaises(ValidationError):
            self.r.set_config({"provider": "cloudflare", "entry_host": "start.example.ch", "cf": {"zone": ZONE}})
        with self.assertRaises(ValidationError):
            self.r.set_config({"provider": "script", "entry_host": "x"})
        with self.assertRaises(ValidationError):
            self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "status": 200, "script": "true"})
        with self.assertRaises(ValidationError):
            self.r.set_config({"provider": "script", "entry_host": "start.example.ch"})  # no script yet

    def test_script_env_runs_once_per_target(self):
        script = 'echo "url=$PF_TARGET_URL host=$PF_TARGET_HOST port=$PF_PORT ip=$PF_IP code=$PF_STATUS_CODE"\n' \
                 'echo "entry=$PF_ENTRY_HOST key=$PF_SSH_KEY"\n'
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "sub": "app", "status": 307,
                           "script": script})
        res = self.r.tick()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["output"][0], "url=https://app.familie-muster.myaddr.tools:51234 "
                                           "host=app.familie-muster.myaddr.tools port=51234 ip=198.51.100.7 code=307")
        self.assertIn("entry=start.example.ch key=%s" % os.path.join(self.tmp, "redirect", "id_ed25519"), res["output"][1])
        self.assertEqual(self.r.tick()["skipped"], "aktuell")
        self.agent.forward_port = 40000
        self.assertTrue(self.r.tick()["ok"])
        st = self.r.status()
        self.assertEqual(st["last_target"], "https://app.familie-muster.myaddr.tools:40000")
        self.assertEqual(st["last_rc"], 0)
        self.assertEqual(self.r.script_text(), script)

    def test_generator_validation(self):
        self.assertEqual(redirect.check_gen({"kind": ""}), {"kind": ""})
        ok = {"kind": "htaccess", "user": "web_1", "host": "server.example.ch", "port": "2222", "root": "httpdocs/tv/"}
        self.assertEqual(redirect.check_gen(ok), {"kind": "htaccess", "user": "web_1", "host": "server.example.ch",
                                                  "port": 2222, "root": "httpdocs/tv"})
        for bad in ({"user": "a'b"}, {"user": "a b"}, {"host": "x;y"}, {"root": "../etc"}, {"root": "a/../b"},
                    {"root": "$HOME"}, {"root": "/abs"}, {"kind": "ftp"}, {"port": "0"}):
            with self.assertRaises(ValidationError, msg=bad):
                redirect.check_gen(dict(ok, **bad))

    def test_generator_writes_script(self):
        gen = {"kind": "php", "user": "web", "host": "server.example.ch", "port": 22, "root": "httpdocs"}
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "gen": gen, "script": "ignored"})
        text = self.r.script_text()
        self.assertIn("SSH_USER='web'", text)
        self.assertIn('"$PF_PHP"', text)
        self.assertIn("FILE='index.php'", text)
        self.assertEqual(self.r.status()["gen"]["kind"], "php")
        for script in (text, redirect.generate_test(redirect.check_gen(gen))):
            self.assertEqual(subprocess.run(["/bin/sh", "-n"], input=script.encode()).returncode, 0)
        # back to an own script: the text is kept and editable again
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "gen": {"kind": ""}, "script": "true\n"})
        self.assertEqual(self.r.script_text(), "true\n")
        with self.assertRaises(ValidationError):  # no SSH key yet
            self.r.run_test(gen)

    def test_set_once_after_start(self):
        """0.27.13 (owner): after a start the redirect is set once even if the stored target is the same."""
        marker = os.path.join(self.tmp, "runs")
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "script": "echo x >> %s\n" % marker})
        self.assertTrue(self.r.tick()["ok"])
        self.assertEqual(self.r.tick()["skipped"], "aktuell")
        self.r.rt.pop("set_since_start")  # as after a restart: same target stored
        self.assertTrue(self.r.tick()["ok"])
        self.assertEqual(self.r.tick()["skipped"], "aktuell")
        with open(marker) as f:
            self.assertEqual(len(f.read().split()), 2)

    def test_script_failure_and_retry(self):
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "script": "echo boom; exit 3\n"})
        res = self.r.tick()
        self.assertFalse(res["ok"])
        self.assertEqual(res["rc"], 3)
        self.assertIn("Code 3", self.r.status()["last_error"])
        self.assertEqual(self.r.tick()["skipped"], "aktuell")  # waits RETRY
        self.now[0] += redirect.RETRY
        self.assertFalse(self.r.tick()["ok"])

    def test_tunnel_down_queues_script_cloudflare_and_name2(self):
        """0.10.1: without a tunnel neither the script nor Cloudflare nor myaddr.tools are contacted."""
        self.up[0] = False
        marker = os.path.join(self.tmp, "ran")
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "script": "touch %s\n" % marker})
        self.agent.names.save({"names": [{"name": "familie-tv", "domain": "myaddr.io", "key": "B" * 43,
                                          "ip": "1.2.3.70", "role": "entry"}]})
        self.agent.names.send = lambda *a, **k: self.fail("myaddr contacted without tunnel")
        if True:
            res = self.r.tick()
            self.assertEqual(res["queued"], "https://familie-muster.myaddr.tools:51234")
            self.assertFalse(os.path.exists(marker))
            self.assertEqual(self.agent.action("redirect-run")["queued"], res["queued"])
        self.assertTrue(self.r.status()["queued"])
        self.up[0] = True
        self.assertTrue(self.r.tick()["ok"])
        self.assertTrue(os.path.exists(marker))


    def test_examples_exist(self):
        for name in ("plesk-htaccess", "php-index"):
            text = redirect.Redirect.example(name)
            self.assertIn("PF_RULES", text)
            self.assertIn("CHANGE_ME", text)
        with self.assertRaises(KeyError):
            redirect.Redirect.example("../x")

    def test_example_refuses_placeholders(self):
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch",
                           "script": redirect.Redirect.example("plesk-htaccess")})
        res = self.r.tick()
        self.assertEqual(res["rc"], 2)
        self.assertIn("anpassen", res["output"][-1])

    def test_rules_subdomains_and_generated_files(self):
        out = os.path.join(self.tmp, "env")
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "status": 307,
                           "script": 'printf "%%s\\n---\\n%%s" "$PF_RULES" "$PF_HTACCESS" > %s\n' % out,
                           "rules": [{"entry": "eingang-muster.myaddr.io", "sub": "tv"},
                                     {"entry": "*.eingang-muster.myaddr.io", "sub": "*"}, {"entry": "", "sub": ""},
                                     {"entry": "app.eingang-muster.myaddr.io", "sub": "app"}]})
        self.assertTrue(self.r.tick()["ok"])
        rules, ht = open(out).read().split("\n---\n")
        self.assertEqual(rules.splitlines(), [
            "start.example.ch https://familie-muster.myaddr.tools:51234",
            "eingang-muster.myaddr.io https://tv.familie-muster.myaddr.tools:51234",
            "app.eingang-muster.myaddr.io https://app.familie-muster.myaddr.tools:51234",
            "*.eingang-muster.myaddr.io https://*.familie-muster.myaddr.tools:51234"])
        self.assertIn(r"RewriteCond %{HTTP_HOST} ^([a-z0-9-]+)\.eingang-muster\.myaddr\.io(:[0-9]+)?$ [NC]", ht)
        self.assertIn("RewriteRule ^(.*)$ https://%1.familie-muster.myaddr.tools:51234/$1 [R=307,L]", ht)
        self.assertIn("no-store", ht)
        self.assertIn("$1.familie-muster", redirect.php(self.r.mappings(self.r.cfg(), self.r.target()), 302))
        self.assertEqual(self.r.tick()["skipped"], "aktuell")
        self.assertEqual(len(self.r.status()["mappings"]), 4)
        for bad in ([{"entry": "eingang-muster.myaddr.io", "sub": "*"}], [{"entry": "-x", "sub": ""}],
                    [{"entry": "a.b.ch", "sub": "x_y"}]):
            with self.assertRaises(ValidationError):
                self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "rules": bad})
        with self.assertRaises(ValidationError):
            self.r.set_config({"provider": "cloudflare", "entry_host": "start.example.ch",
                               "cf": {"zone": "example.ch", "token": "T" * 40},
                               "rules": [{"entry": "*.eingang-muster.myaddr.io", "sub": "*"}]})

    def test_cloudflare_round_robin_uses_a_worker_and_back(self):
        """0.31.0: round robin with Cloudflare deploys the Worker; back to failover, its routes go and the rule
        comes back."""
        from tests.test_cf_worker import BASE, FakeCf
        cf = FakeCf()
        self.r.request = cf
        with mock.patch.dict(os.environ, {"PF_CLOUDFLARE_API": BASE}), \
                mock.patch.object(self.r, "may_run", return_value=True):
            self.r.set_config({"provider": "cloudflare", "entry_host": "start.example.ch", "mode": "roundrobin",
                               "cf": {"zone": ZONE, "token": TOKEN},
                               "rules": [{"entry": "*.eingang-muster.myaddr.io", "sub": "*"}]})
            res = self.r.apply()
            self.assertTrue(res["ok"], res)
            self.assertEqual(res["detail"], "Worker aktualisiert, 2 Route(n)")
            self.assertTrue(self.r.cfg()["cf_worker"])
            self.assertIn("https://familie-muster.myaddr.tools:51234", cf.script[0].decode())
            self.assertEqual(sorted(r["pattern"] for r in cf.routes),
                             ["*.eingang-muster.myaddr.io/*", "start.example.ch/*"])
            self.r.set_config({"provider": "cloudflare", "entry_host": "start.example.ch", "mode": "failover",
                               "cf": {"zone": ZONE}, "rules": []})
            self.assertTrue(self.r.cfg()["cf_worker"])  # kept until the routes are gone
            res = self.r.apply()
            self.assertTrue(res["ok"], res)
            self.assertEqual(cf.routes, [])
            self.assertFalse(self.r.cfg()["cf_worker"])
            self.assertEqual([r["description"] for r in cf.ruleset["rules"]], ["portnook redirect start.example.ch"])

    def test_further_providers_each_with_their_hosts(self):
        """0.32.0: every entry host picks its provider; a further Cloudflare and a further script run on their own,
        and an error at one doesn't stop the others."""
        from tests.test_cf_worker import BASE, FakeCf
        cf = FakeCf()
        self.r.request = cf
        marker = os.path.join(self.tmp, "rules2")
        with mock.patch.dict(os.environ, {"PF_CLOUDFLARE_API": BASE}), \
                mock.patch.object(self.r, "may_run", return_value=True):
            self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "script": "true\n",
                               "providers": [{"kind": "cloudflare", "cf": {"zone": ZONE, "token": TOKEN}},
                                             {"kind": "script", "script": 'printf "%%s" "$PF_RULES" > %s\n' % marker}],
                               "rules": [{"entry": "cf.example.ch", "sub": "app", "via": "a2"},
                                         {"entry": "web.example.org", "sub": "", "via": "a3"},
                                         {"entry": "main2.example.ch", "sub": ""}]})
            self.assertEqual([x["id"] for x in self.r.cfg()["providers"]], ["a2", "a3"])
            res = self.r.apply()
            self.assertTrue(res["ok"], res)
            self.assertEqual([(x["id"], x["ok"]) for x in res["extra"]], [("a2", True), ("a3", True)])
            # Cloudflare a2 only got its host
            self.assertEqual([r["description"] for r in cf.ruleset["rules"]], ["portnook redirect cf.example.ch"])
            with open(marker) as fh:
                self.assertEqual(fh.read(), "web.example.org https://familie-muster.myaddr.tools:51234")
            vias = {m["entry"]: m["via"] for m in self.r.status()["mappings"]}
            self.assertEqual(vias, {"start.example.ch": "", "main2.example.ch": "", "cf.example.ch": "a2",
                                    "web.example.org": "a3"})
            st = {x["id"]: x for x in self.r.status()["providers"]}
            self.assertTrue(st["a2"]["cf"]["token_set"])
            self.assertNotIn(TOKEN, json.dumps(self.r.status()))
            self.assertIn("PF_RULES", st["a3"]["script"])
            # nothing changed: all skipped
            res = self.r.apply()
            self.assertEqual([x.get("skipped") for x in res["extra"]], ["aktuell", "aktuell"])
            # a failing further provider fails the result but the main one still ran
            self.r.set_config({"provider": "script", "entry_host": "start.example.ch",
                               "providers": [{"id": "a2", "kind": "cloudflare", "cf": {"zone": ZONE}},
                                             {"id": "a3", "kind": "script", "script": "exit 3\n"}],
                               "rules": [{"entry": "cf.example.ch", "sub": "app", "via": "a2"},
                                         {"entry": "web.example.org", "sub": "", "via": "a3"}]})
            res = self.r.apply(force=True)
            self.assertFalse(res["ok"])
            self.assertEqual(res["detail"], "Skript ok")
            self.assertIn("a3", res["error"])
            self.assertEqual(self.r.status()["providers"][1]["last_rc"], 3)
            # removed: its script goes, its rules can't point at it any more
            with self.assertRaises(ValidationError):
                self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "providers": [],
                                   "rules": [{"entry": "web.example.org", "sub": "", "via": "a3"}]})
            self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "providers": [], "rules": []})
            self.assertFalse(os.path.exists(os.path.join(self.r.dir, "script-a3.sh")))

    def test_further_provider_validation(self):
        for bad in ([{"kind": "x"}], [{"kind": "cloudflare", "cf": {"zone": ZONE}}],
                    [{"kind": "cloudflare", "cf": {"zone": "bad zone", "token": TOKEN}}], [{"kind": "script"}],
                    [{"kind": "script", "script": "true"}] * (redirect.MAX_PROVIDERS + 1)):
            with self.assertRaises(ValidationError):
                self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "script": "true\n",
                                   "providers": bad})
        # a provider added in the same save is named by its position
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "script": "true\n",
                           "providers": [{"kind": "script", "script": "true\n"}],
                           "rules": [{"entry": "web.example.org", "sub": "", "via": "new0"}]})
        self.assertEqual(self.r.cfg()["rules"][0]["via"], "a2")
        # 0.34.0: providers carry a name of their own
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "script": "true\n",
                           "provider_name": "Webhosting  Plesk", "rules": [],
                           "providers": [{"kind": "script", "name": "Zweites", "script": "true\n"}]})
        st = self.r.status()
        self.assertEqual((st["provider_name"], st["providers"][0]["name"]), ("Webhosting Plesk", "Zweites"))
        with self.assertRaises(ValidationError):
            self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "provider_name": "<b>"})
        # *.host with a further Cloudflare only in round robin
        with self.assertRaises(ValidationError):
            self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "script": "true\n",
                               "providers": [{"kind": "cloudflare", "cf": {"zone": ZONE, "token": TOKEN}}],
                               "rules": [{"entry": "*.example.org", "sub": "*", "via": "a2"}]})

    def test_cloudflare_workers_dev_entry(self):
        """0.36.0: a Cloudflare provider without zone serves workers.dev entries only, in both modes."""
        from tests.test_cf_worker import BASE, FakeCf
        cf = FakeCf()
        self.r.request = cf
        with mock.patch.dict(os.environ, {"PF_CLOUDFLARE_API": BASE}), \
                mock.patch.object(self.r, "may_run", return_value=True):
            self.r.set_config({"provider": "cloudflare", "entry_host": "go.familie-muster.workers.dev", "sub": "tv",
                               "cf": {"zone": "", "token": TOKEN}, "rules": []})
            res = self.r.apply()
            self.assertTrue(res["ok"], res)
            self.assertEqual(res["detail"], "go.familie-muster.workers.dev: Worker aktualisiert")
            self.assertIn("https://tv.familie-muster.myaddr.tools:51234", cf.scripts["go"].decode())
            self.assertEqual((cf.routes, cf.ruleset["rules"]), ([], []))
            # an own-domain entry needs the zone
            self.r.set_config({"provider": "cloudflare", "entry_host": "go.familie-muster.workers.dev",
                               "cf": {"zone": ""}, "rules": [{"entry": "start.example.ch", "sub": ""}]})
            res = self.r.apply(force=True)
            self.assertFalse(res["ok"])
            self.assertIn("Zone fehlt", res["error"])
        for bad in ("*.familie-muster.workers.dev", "a.b.familie-muster.workers.dev"):
            with self.assertRaises(ValidationError):
                self.r.set_config({"provider": "cloudflare", "entry_host": "go.familie-muster.workers.dev", "mode": "roundrobin",
                                   "cf": {"zone": ""}, "rules": [{"entry": bad, "sub": ""}]})
        with self.assertRaises(ValidationError):  # workers.dev only through Cloudflare
            self.r.set_config({"provider": "script", "entry_host": "go.familie-muster.workers.dev", "script": "true\n"})

    def test_rules_follow_the_active_profile(self):
        """0.23.1: after a failover every rule uses the active profile's name (its port is the active one)."""
        self.store.update("myaddr", {"profile": "p1"})
        with mock.patch.object(self.agent, "profiles", return_value=[{"id": "p1"}, {"id": "p2"}]):
            self.agent.names.save({"names": [{"name": "muster-2", "domain": "myaddr.io", "key": "B" * 43,
                                              "role": "endpoint", "profile": "p2"},
                                             {"name": "festname", "domain": "myaddr.io", "key": "C" * 43, "role": "endpoint"}]})
        self.r.set_config({"provider": "script", "entry_host": "eingang-muster.myaddr.io", "sub": "tv", "script": "true\n",
                           "rules": [{"entry": "*.eingang-muster.myaddr.io", "sub": "*", "to": "muster-2.myaddr.io"},
                                     {"entry": "x.eingang-muster.myaddr.io", "sub": "x", "to": "festname.myaddr.io"}]})
        urls = lambda: [u for _, u in self.r.mappings(self.r.cfg(), self.r.target())]
        with mock.patch.object(self.agent, "active_profile", return_value={"id": "p1"}):
            self.assertEqual(urls(), ["https://tv.familie-muster.myaddr.tools:51234", "https://x.festname.myaddr.io:51234",
                                      "https://*.familie-muster.myaddr.tools:51234"])
            self.assertEqual(self.r.status()["active_name"], "familie-muster.myaddr.tools")
        with mock.patch.object(self.agent, "active_profile", return_value={"id": "p2"}):
            self.assertEqual(urls(), ["https://tv.muster-2.myaddr.io:51234", "https://x.festname.myaddr.io:51234",
                                      "https://*.muster-2.myaddr.io:51234"])

    def test_target_name_from_endpoint_names(self):
        self.agent.names.save({"names": [{"name": "familie-2", "domain": "myaddr.dev", "key": "C" * 43, "role": "endpoint"},
                                         {"name": "familie-tv", "domain": "myaddr.io", "key": "B" * 43, "role": "entry",
                                          "ip": "1.2.3.70"}]})
        self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "sub": "app", "to": "familie-2.myaddr.dev",
                           "script": "true\n", "rules": [{"entry": "*.familie-tv.myaddr.io", "sub": "*", "to": ""}]})
        self.assertEqual(self.r.status()["endpoints"], ["familie-muster.myaddr.tools", "familie-2.myaddr.dev"])
        self.assertEqual([u for _, u in self.r.mappings(self.r.cfg(), self.r.target())],
                         ["https://app.familie-2.myaddr.dev:51234", "https://*.familie-muster.myaddr.tools:51234"])
        with self.assertRaises(ValidationError):  # entry names are no target
            self.r.set_config({"provider": "script", "entry_host": "start.example.ch", "to": "familie-tv.myaddr.io"})
        self.agent.names.save({"names": []})  # endpoint name gone: back to the main name
        self.assertEqual(self.r.target()["url"], "https://app.familie-muster.myaddr.tools:51234")

    def test_names_roles_keepalive_and_migration(self):
        self.store.update("redirect", {"myaddr2": {"name": "familie-tv", "domain": "myaddr.io", "key": "B" * 43,
                                                   "ip": "1.2.3.70"}})
        names = self.agent.names
        self.assertEqual([(n["name"], n["role"]) for n in names.status()], [("familie-tv", "entry")])
        self.assertEqual(self.store.section("redirect").get("myaddr2"), {})
        sent = []
        names.send = lambda key, ip=None, device=None: sent.append((key[0], ip))
        names.save({"names": [{"id": "n1", "name": "familie-tv", "domain": "myaddr.io", "ip": "1.2.3.70",
                               "role": "entry"},
                              {"name": "familie-2", "domain": "myaddr.dev", "key": "C" * 43, "role": "endpoint"}]})
        names.tick()
        names.tick()
        self.now[0] += myaddr.KEEPALIVE
        names.tick()
        exit_ip = self.agent.ddns.resolve()[0]
        self.assertEqual(sent, [("B", "1.2.3.70"), ("C", exit_ip)] * 2)
        st = json.dumps(names.status())
        self.assertNotIn("B" * 43, st)
        for ip in ("192.168.1.5", "127.0.0.1"):  # 0.30.1: any IPv4 (127.0.0.1 keeps an unused name alive)
            names.save({"names": [{"id": "n1", "name": "familie-tv", "domain": "myaddr.io", "ip": ip, "role": "entry"}]})
            self.now[0] += myaddr.KEEPALIVE
            names.tick()
            self.assertEqual(sent[-1], ("B", ip))
        # 0.35.0: a host name instead of an IP, like a CNAME: its IPv4 is looked up and follows changes
        answers = {"web.example.ch": ["203.0.113.5", "203.0.113.9"]}
        names.lookup = lambda host: answers.get(host, [])
        names.save({"names": [{"id": "n1", "name": "familie-tv", "domain": "myaddr.io", "ip": "Web.Example.ch.",
                               "role": "entry"}]})
        self.assertEqual(names.status()[0]["ip"], "web.example.ch")
        self.now[0] += myaddr.KEEPALIVE
        names.tick()
        self.assertEqual(sent[-1], ("B", "203.0.113.5"))
        n = len(sent)
        answers["web.example.ch"] = ["203.0.113.9", "203.0.113.5"]  # same set in another order: no update
        self.now[0] += names.RESOLVE_EVERY
        names.tick()
        self.assertEqual(len(sent), n)
        answers["web.example.ch"] = ["198.51.100.4"]  # moved: followed after the next lookup
        names.tick()
        self.assertEqual(len(sent), n)  # still cached
        self.now[0] += names.RESOLVE_EVERY
        names.tick()
        self.assertEqual(sent[-1], ("B", "198.51.100.4"))
        answers["web.example.ch"] = []  # no answer: the record stays as it is
        self.now[0] += names.RESOLVE_EVERY
        n = len(sent)
        names.tick()
        self.assertEqual(len(sent), n)
        for bad in ({"names": [{"name": "familie-3", "domain": "myaddr.io", "role": "endpoint"}]},
                    {"names": [{"name": "familie-3", "domain": "myaddr.io", "role": "entry", "key": "D" * 43,
                                "ip": "kein host"}]},
                    {"names": [{"name": "familie-3", "domain": "myaddr.io", "role": "x", "key": "D" * 43}]}):
            with self.assertRaises(ValidationError):
                names.save(bad)

    def test_one_key_per_name_on_every_domain(self):
        """0.38.0 (owner): the myaddr key belongs to the name; .io, .tools and .dev share it."""
        names = self.agent.names
        names.save({"names": [{"name": "familie-tv", "domain": "myaddr.io", "key": "B" * 43, "ip": "1.2.3.70",
                               "role": "entry"},
                              {"name": "familie-tv", "domain": "myaddr.dev", "ip": "1.2.3.70", "role": "entry"}]})
        self.assertEqual([n["key"] for n in names.items()], ["B" * 43] * 2)
        n1 = names.items()[0]["id"]
        # another domain without typing the key again
        names.save({"names": [{"id": n1, "name": "familie-tv", "domain": "myaddr.tools", "ip": "1.2.3.70", "role": "entry"}]})
        self.assertEqual(names.items()[0]["key"], "B" * 43)
        # the main name's key serves the same name on another domain
        names.save({"names": [{"name": self.store.section("myaddr")["name"], "domain": "myaddr.dev", "ip": "1.2.3.71",
                               "role": "entry"}]})
        self.assertEqual(names.items()[0]["key"], self.store.section("myaddr")["key"])
        # a new key typed once goes to every row of that name
        names.save({"names": [{"name": "familie-tv", "domain": "myaddr.io", "key": "C" * 43, "ip": "1.2.3.70", "role": "entry"},
                              {"name": "familie-tv", "domain": "myaddr.dev", "ip": "1.2.3.70", "role": "entry"}]})
        self.assertEqual([n["key"] for n in names.items()], ["C" * 43] * 2)
        self.assertEqual(names.key_of(names.items()[1]["id"]), ("familie-tv.myaddr.dev", "C" * 43))
        with self.assertRaises(KeyError):
            names.key_of("n99")


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen missing")
class SshKeyTest(unittest.TestCase):
    def test_generate_and_upload(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        agent = Agent(Store(os.path.join(tmp, "agent.json")), netmod.Net(wg_dir=tmp))
        pub = agent.redirect.ssh_generate()["public_key"]
        self.assertTrue(pub.startswith("ssh-ed25519 "))
        path = os.path.join(tmp, "redirect", "id_ed25519")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path) as fh:
            priv = fh.read()
        self.assertNotIn("PRIVATE", json.dumps(agent.status()))
        self.assertEqual(agent.redirect.ssh_upload(priv)["public_key"].split()[:2], pub.split()[:2])
        with self.assertRaises(ValidationError):
            agent.redirect.ssh_upload("not a key")



class RoundRobinGeneratorTest(unittest.TestCase):
    """0.28.0 (owner): clients shared between the active tunnel and the standby."""
    RULES = [("start.example.ch", ["https://tv.a.myaddr.io:41000", "https://tv.b.myaddr.io:42000"]),
             ("*.start.example.ch", ["https://*.a.myaddr.io:41000", "https://*.b.myaddr.io:42000"]),
             ("fix.example.ch", ["https://fix.myaddr.io:41000"])]

    def test_groups_cover_every_address_character_once(self):
        for n in (2, 3, 4):
            g = redirect.addr_groups(n)
            self.assertEqual(sorted("".join(g)), sorted(redirect.ADDR_CHARS))
            self.assertTrue(all(g))

    def test_htaccess_one_block_per_tunnel(self):
        text = redirect.htaccess(self.RULES, 302)
        self.assertEqual(text.count("RewriteRule"), 5)
        self.assertIn("RewriteCond %{REMOTE_ADDR} [02468ace]$ [NC]", text)
        lines = text.splitlines()
        i = lines.index("RewriteRule ^(.*)$ https://tv.a.myaddr.io:41000/$1 [R=302,L]")
        self.assertTrue(lines[i - 1].startswith("RewriteCond %{HTTP_HOST}"))  # host condition last (%1)
        self.assertIn("RewriteRule ^(.*)$ https://%1.b.myaddr.io:42000/$1 [R=302,L]", text)

    def test_single_target_unchanged(self):
        one = [("start.example.ch", "https://tv.a.myaddr.io:41000")]
        self.assertEqual(redirect.htaccess(one, 302), redirect.htaccess([(e, [u]) for e, u in one], 302))
        self.assertNotIn("REMOTE_ADDR", redirect.htaccess(one, 302))

    def test_php_picks_by_client_address(self):
        text = redirect.php(self.RULES, 302)
        self.assertIn("['https://tv.a.myaddr.io:41000', 'https://tv.b.myaddr.io:42000']", text)
        self.assertIn("crc32($_SERVER['REMOTE_ADDR']", text)
        self.assertIn("'https://$1.b.myaddr.io:42000'", text)


if __name__ == "__main__":
    unittest.main()
