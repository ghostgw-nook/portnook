import http.client
import json
import os
import shutil
import stat
import tempfile
import threading
import unittest
from unittest import mock

from app import auth, log, net as netmod
from app.agent import Agent
from app.api import Server
from app.store import Store
from tests.fakes import PRIV, PROTON_SAMPLE, FakeRun, base_responses

MYKEY = "K" * 43

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


class StoreAuthTest(unittest.TestCase):
    def test_store_atomic_600(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "data", "agent.json")
            s = Store(path)
            s.update("cert", {"staging": False})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertFalse(os.path.exists(path + ".tmp"))
            self.assertFalse(Store(path).section("cert")["staging"])
            self.assertEqual(Store(path).section("backend"), {"addr": "", "lan_nets": [], "lan_entry": True})
        finally:
            shutil.rmtree(tmp)

    def test_password_hash(self):
        h = auth.hash_password("geheim123", iterations=1000)
        self.assertTrue(auth.verify_password("geheim123", h))
        self.assertFalse(auth.verify_password("geheim124", h))
        self.assertFalse(auth.verify_password("x", "garbage"))
        self.assertGreaterEqual(auth.ITERATIONS, 200000)
        self.assertIsNotNone(auth.check_new_password("kurz"))


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = base_responses(FakeRun())
        self.patches = [mock.patch("app.sysrun.run", self.fake),
                        mock.patch("app.auth.ITERATIONS", 1000),
                        mock.patch("app.probe.natpmpc_available", return_value=False)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.agent = Agent(self.store, netmod.Net(wg_dir=self.tmp), version="0.2.0")
        try:
            self.server = Server(("127.0.0.1", 0), self.agent, WEB)
        except OSError as err:  # sandbox without local binding
            self.skipTest("cannot bind local port: %s" % err)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = ""

    def tearDown(self):
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()

    def req(self, method, path, body=None, ctype="application/json", cookie=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if cookie is None:
            cookie = self.cookie
        if cookie:
            headers["Cookie"] = cookie
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = ctype
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode()
        set_cookie = resp.getheader("Set-Cookie")
        conn.close()
        try:
            payload = json.loads(text)
        except ValueError:
            payload = text
        return resp.status, payload, set_cookie

    def setup_password(self):
        status, _, cookie = self.req("POST", "/api/setup/password", {"password": "geheim123"})
        self.assertEqual(status, 200)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.cookie = cookie.split(";")[0]

    def test_index(self):
        status, text, _ = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("portnook", text)

    def test_index_inlines_texts(self):
        _, text, _ = self.req("GET", "/")
        self.assertNotIn("/*PF_I18N*/", text)
        self.assertIn('"_name": "Deutsch"', text)
        self.assertNotIn("{{", text.split("const PF_I18N", 1)[1].split("</script>", 1)[0])

    def test_flow_before_and_after_password(self):
        status, data, _ = self.req("GET", "/api/session")
        self.assertEqual((status, data["password_set"]), (200, False))
        self.assertEqual(self.req("GET", "/api/status")[0], 403)
        self.assertEqual(self.req("POST", "/api/setup/backend", {"backend": "1.2.3.4:443"})[0], 403)
        self.assertEqual(self.req("POST", "/api/setup/password", {"password": "kurz"})[0], 400)
        self.setup_password()
        status, data, _ = self.req("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(data["setup"]["password"])
        self.assertEqual(self.req("GET", "/api/status", cookie="portnook_session=wrong")[0], 401)
        self.assertEqual(self.req("GET", "/api/logs", cookie="")[0], 401)
        # password cannot be overwritten without login
        self.assertEqual(self.req("POST", "/api/setup/password", {"password": "anderes123"}, cookie="")[0], 401)
        # logout invalidates the session
        self.assertEqual(self.req("POST", "/api/logout", {})[0], 200)
        self.assertEqual(self.req("GET", "/api/status")[0], 401)

    def test_login_and_rate_limit(self):
        self.setup_password()
        status, _, cookie = self.req("POST", "/api/login", {"password": "geheim123"}, cookie="")
        self.assertEqual(status, 200)
        self.assertEqual(self.req("GET", "/api/status", cookie=cookie.split(";")[0])[0], 200)
        for _ in range(5):
            self.assertEqual(self.req("POST", "/api/login", {"password": "falsch"}, cookie="")[0], 401)
        self.assertEqual(self.req("POST", "/api/login", {"password": "geheim123"}, cookie="")[0], 429)

    def test_content_type_and_size(self):
        self.setup_password()
        self.assertEqual(self.req("POST", "/api/action/backend-test", raw=b"{}", ctype="text/plain")[0], 415)
        self.assertEqual(self.req("POST", "/api/setup/proton", raw=b"x" * (49 * 1024))[0], 413)
        self.assertEqual(self.req("POST", "/api/setup/proton", raw=b"[1]")[0], 400)
        self.assertEqual(self.req("POST", "/api/action/nope", {})[0], 404)
        status, data, _ = self.req("POST", "/api/action/natpmp-renew", {})
        self.assertEqual(status, 409)
        self.assertIn("Proton", data["error"])

    def test_wgconf_fits_and_validation_message(self):
        self.setup_password()
        conf = PROTON_SAMPLE.replace(PRIV, "bad") + "# padding\n" * 900  # ~10 KiB
        status, data, _ = self.req("POST", "/api/setup/proton", {"enabled": True, "conf": conf,
                                                                 "lan_nets": ["192.168.1.0/24"]})
        self.assertEqual(status, 400)
        self.assertIn("PrivateKey", data["error"])

    def test_edge_paths_are_gone(self):
        self.setup_password()
        for path in ("/edge/", "/edge/api/tenant/self", "/api/setup/enroll"):
            self.assertEqual(self.req("GET", path)[0], 404, path)

    def test_myaddr_key_write_only(self):
        self.setup_password()
        self.assertEqual(self.req("POST", "/api/myaddr", {"name": "x", "domain": "myaddr.tools", "key": MYKEY})[0], 400)
        self.assertEqual(self.req("POST", "/api/myaddr", {"name": "familie-muster", "domain": "myaddr.tools"})[0], 400)
        self.assertEqual(self.req("POST", "/api/myaddr", {"name": "familie-muster", "domain": "evil.example",
                                                          "key": MYKEY})[0], 400)
        status, data, _ = self.req("POST", "/api/myaddr", {"name": "familie-muster", "domain": "myaddr.io",
                                                           "key": MYKEY, "ddns": True})
        self.assertEqual((status, data["fqdn"]), (200, "familie-muster.myaddr.io"))
        # name change without a new key keeps the stored key
        self.assertEqual(self.req("POST", "/api/myaddr", {"name": "familie-muster", "domain": "myaddr.dev"})[0], 200)
        self.assertEqual(self.store.section("myaddr")["key"], MYKEY)
        st = self.req("GET", "/api/status")[1]
        self.assertEqual(st["myaddr"], {"name": "familie-muster", "domain": "myaddr.dev",
                                        "fqdn": "familie-muster.myaddr.dev", "key_set": True, "profile": "",
                                        "tunnel_names": {"active": "", "standby": ""}})
        self.assertNotIn(MYKEY, json.dumps(st))
        self.assertNotIn(MYKEY, json.dumps(self.req("GET", "/api/logs")[1]))

    def test_myaddr_key_shown_after_password(self):
        """0.38.0 (owner): the key is shown only with the password typed again; failures count like logins."""
        self.setup_password()
        self.req("POST", "/api/myaddr", {"name": "familie-muster", "domain": "myaddr.io", "key": MYKEY, "ddns": True})
        self.assertEqual(self.req("POST", "/api/myaddr/key", {"id": "main", "password": "falsch"})[0], 401)
        status, data, _ = self.req("POST", "/api/myaddr/key", {"id": "main", "password": "geheim123"})
        self.assertEqual((status, data["key"], data["name"]), (200, MYKEY, "familie-muster.myaddr.io"))
        self.assertEqual(self.req("POST", "/api/myaddr/key", {"id": "n9", "password": "geheim123"})[0], 404)
        self.assertEqual(self.req("POST", "/api/myaddr/key", {"id": "main", "password": "geheim123"}, cookie="")[0], 401)
        self.assertNotIn(MYKEY, json.dumps(self.req("GET", "/api/logs")[1]))
        for _ in range(5):
            self.req("POST", "/api/myaddr/key", {"id": "main", "password": "falsch"})
        self.assertEqual(self.req("POST", "/api/myaddr/key", {"id": "main", "password": "geheim123"})[0], 429)

    def test_cert_download_and_pull_token(self):
        self.setup_password()
        self.assertEqual(self.req("GET", "/api/cert/download/fullchain.pem")[0], 409)  # no cert yet
        certdir = os.path.join(self.tmp, "certs")
        os.makedirs(certdir)
        for name in ("fullchain.pem", "cert.pem", "chain.pem", "privkey.pem"):
            with open(os.path.join(certdir, name), "w") as fh:
                fh.write("-----BEGIN %s-----\n" % name)
        status, text, _ = self.req("GET", "/api/cert/download/privkey.pem")
        self.assertEqual((status, text), (200, "-----BEGIN privkey.pem-----\n"))
        self.assertEqual(self.req("GET", "/api/cert/download/privkey.pem", cookie="")[0], 401)
        self.assertEqual(self.req("GET", "/api/cert/download/../agent.json")[0], 404)
        self.assertEqual(self.req("GET", "/api/cert/download/agent.json")[0], 404)
        status, data, _ = self.req("POST", "/api/cert/pull-token", {})
        token = data["token"]
        self.assertGreaterEqual(len(token), 40)
        self.assertNotIn(token, json.dumps(self.store.get()))
        self.assertNotIn(token, json.dumps(self.req("GET", "/api/status")[1]))

        def pull(tok, name="fullchain.pem"):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.request("GET", "/api/cert/download/" + name, headers={"Authorization": "Bearer " + tok})
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            return resp.status, body, resp.getheader("Content-Disposition")

        status, body, disp = pull(token)
        self.assertEqual((status, body), (200, b"-----BEGIN fullchain.pem-----\n"))
        self.assertIn("attachment", disp)
        status, body, disp = pull(token, "cert.zip")
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"PK"))
        self.assertEqual(pull("wrong")[0], 401)
        self.assertNotIn(token, json.dumps(self.req("GET", "/api/logs")[1]))
        self.req("POST", "/api/cert/pull-token", {"revoke": True})
        self.assertEqual(pull(token)[0], 401)
        for _ in range(4):
            pull("wrong")
        self.assertEqual(pull("wrong")[0], 429)

    def test_status_carries_light(self):
        self.setup_password()
        status, data, _ = self.req("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertIn(data["light"]["overall"], ("ok", "warn", "error", "unknown"))
        self.assertEqual(set(data["light"]["checks"]), {"proton", "natpmp", "backend", "ddns", "cert", "delivery", "redirect"})

    def test_status_and_logs_contain_no_secrets(self):
        self.setup_password()
        self.store.update("proton", {"decided": True, "enabled": True,
                                     "conf": "[Interface]\nPrivateKey = %s\n" % PRIV, "server": "CH#12"})
        self.store.update("backend", {"addr": "192.168.1.10:443", "lan_nets": ["192.168.1.0/24"]})
        self.store.update("myaddr", {"name": "familie-muster", "key": "SECRETTOKEN" * 4})
        self.store.update("delivery", {"npm": {"url": "http://192.168.1.5:81", "identity": "a@b.ch",
                                               "secret": "NPMSECRETPW"}})
        self.store.update("redirect", {"provider": "cloudflare", "cf": {"token": "CFSECRETTOKEN", "zone": "a.ch"}})
        log.log("some event")
        status, data, _ = self.req("GET", "/api/status")
        self.assertEqual(status, 200)
        text = json.dumps(data)
        for secret in (PRIV, "SECRETTOKEN", "NPMSECRETPW", "CFSECRETTOKEN", "PrivateKey", "pw_hash", "pbkdf2"):
            self.assertNotIn(secret, text)
        self.assertEqual(data["proton"]["server"], "CH#12")
        self.assertTrue(data["delivery"]["npm"]["secret_set"])
        self.assertTrue(data["redirect"]["cf"]["token_set"])
        text = json.dumps(self.req("GET", "/api/logs")[1])
        for secret in (PRIV, "SECRETTOKEN", "geheim123"):
            self.assertNotIn(secret, text)


if __name__ == "__main__":
    unittest.main()
