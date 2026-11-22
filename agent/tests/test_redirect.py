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
        self.assertEqual(self.r.status()["queued"], "")

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
        for bad in ({"names": [{"name": "familie-3", "domain": "myaddr.io", "role": "entry", "key": "D" * 43,
                                "ip": "192.168.1.5"}]},
                    {"names": [{"name": "familie-3", "domain": "myaddr.io", "role": "endpoint"}]},
                    {"names": [{"name": "familie-3", "domain": "myaddr.io", "role": "x", "key": "D" * 43}]}):
            with self.assertRaises(ValidationError):
                names.save(bad)


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


if __name__ == "__main__":
    unittest.main()
