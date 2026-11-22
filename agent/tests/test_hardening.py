"""Tests for the review findings: validation, auth, store, API limits."""

import http.client
import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from app import api, auth, net as netmod, validate
from app.agent import Agent
from app.store import Store
from app.validate import ValidationError
from tests.fakes import FakeRun, base_responses

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
class ValidationHardeningTest(unittest.TestCase):
    def test_no_trailing_newline_tricks(self):
        self.assertFalse(validate.is_hostname("example.com\n"))
        self.assertFalse(validate.is_b64url("abc\n"))
        self.assertTrue(validate.is_hostname("pf-api.local"))

    def test_backend_rfc1918_only(self):
        for bad in ("8.8.8.8:443", "100.64.0.1:443", "127.0.0.1:443", "169.254.1.1:443"):
            with self.assertRaises(ValidationError):
                validate.backend(bad)
        self.assertEqual(str(validate.backend("172.20.0.5:8443")[0]), "172.20.0.5")

    def test_upgrade_drops_edge_sections(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "agent.json")
        with open(path, "w") as fh:
            json.dump({"mgmt": {"token": "OLDTOKEN", "private_key": "OLDKEY"}, "edge": {"tenant": "a"},
                       "backend": {"addr": "192.168.1.10:443"}}, fh)
        store = Store(path)
        store.update("ui", {"pw_hash": "x"})
        with open(path) as fh:
            text = fh.read()
        self.assertNotIn("OLDTOKEN", text)
        self.assertNotIn("OLDKEY", text)
        self.assertEqual(store.section("backend")["addr"], "192.168.1.10:443")

class AuthStoreHardeningTest(unittest.TestCase):
    def test_iterations_and_old_hashes(self):
        self.assertGreaterEqual(auth.ITERATIONS, 600000)
        old = auth.hash_password("geheim123", iterations=1000)
        self.assertTrue(auth.verify_password("geheim123", old))

    def test_session_absolute_age(self):
        now = [1000.0]
        s = auth.Sessions(ttl=100, max_age=250, clock=lambda: now[0])
        tok = s.create()
        for _ in range(4):
            now[0] += 60
            self.assertTrue(s.valid(tok))
        now[0] += 60  # 300 s after creation, idle only 60 s
        self.assertFalse(s.valid(tok))

    def test_global_login_ceiling(self):
        s = auth.Sessions()
        for i in range(auth.LOGIN_FAILS_GLOBAL):
            s.fail("10.0.%d.1" % i)
        self.assertTrue(s.blocked("10.9.9.9"))

    def test_corrupt_store_is_moved(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "agent.json")
        with open(path, "w") as fh:
            fh.write("{broken")
        store = Store(path)
        self.assertEqual(store.section("ui"), {"pw_hash": ""})
        self.assertTrue(any(n.startswith("agent.json.corrupt-") for n in os.listdir(tmp)))
        self.assertFalse(os.path.exists(path))

    def test_password_check_and_set(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch("app.auth.ITERATIONS", 1000):
            agent = Agent(Store(os.path.join(tmp, "a.json")), netmod.Net(wg_dir=tmp))
            agent.set_password("geheim123", first=True)
            from app.agent import PasswordError, SetupError
            with self.assertRaises(SetupError):
                agent.set_password("anderes123", first=True)
            with self.assertRaises(PasswordError):
                agent.set_password("anderes123", old_password="falsch")
            agent.set_password("anderes123", old_password="geheim123")
            self.assertTrue(agent.check_password("anderes123"))

class ApiLimitsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for p in (mock.patch("app.sysrun.run", base_responses(FakeRun())), mock.patch("app.auth.ITERATIONS", 1000)):
            p.start()
            self.addCleanup(p.stop)
        self.agent = Agent(Store(os.path.join(self.tmp, "a.json")), netmod.Net(wg_dir=self.tmp))

    def start(self, **kw):
        try:
            server = api.Server(("127.0.0.1", 0), self.agent, WEB, **kw)
        except OSError as err:
            self.skipTest("cannot bind local port: %s" % err)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    @staticmethod
    def req(port, method, path, body=None, cookie=""):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data, resp.getheader("Set-Cookie")

    def test_timeout_set(self):
        self.assertEqual(api.Handler.timeout, 30)

    def test_503_when_full(self):
        port = self.start(max_conns=1)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.connect()  # holds the only slot (idle keep-alive)
        try:
            status, data, _ = self.req(port, "GET", "/api/session")
            self.assertEqual(status, 503)
        finally:
            conn.close()

    def test_password_change_needs_old(self):
        port = self.start()
        status, _, cookie = self.req(port, "POST", "/api/setup/password", {"password": "geheim123"})
        self.assertEqual(status, 200)
        cookie = cookie.split(";")[0]
        self.assertEqual(self.req(port, "POST", "/api/setup/password", {"password": "anderes123"}, cookie)[0], 400)
        self.assertEqual(self.req(port, "POST", "/api/setup/password",
                                  {"password": "anderes123", "old_password": "geheim123"}, cookie)[0], 200)
        self.assertEqual(self.req(port, "POST", "/x", {})[0], 404)

if __name__ == "__main__":
    unittest.main()
