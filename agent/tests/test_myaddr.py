import os
import shutil
import tempfile
import unittest
import urllib.parse
from unittest import mock

from app import myaddr, net as netmod
from app.agent import Agent
from app.store import Store
from app.validate import ValidationError
from tests.fakes import FakeHttp, FakeRun, base_responses

KEY = "A" * 43


class UpdateTest(unittest.TestCase):
    def setUp(self):
        self.answer = (200, "OK\n")
        try:
            self.srv = FakeHttp(lambda m, p, h, b: self.answer)
        except OSError as err:
            self.skipTest("cannot bind local port: %s" % err)
        self.addCleanup(self.srv.close)

    def form(self, i=-1):
        method, path, headers, body = self.srv.requests[i]
        self.assertEqual((method, path), ("POST", "/update"))
        self.assertEqual(headers["Content-Type"], "application/x-www-form-urlencoded")
        return dict(urllib.parse.parse_qsl(body.decode()))

    def test_ip_and_challenge(self):
        self.assertTrue(myaddr.update(KEY, ip="198.51.100.7", url=self.srv.url))
        self.assertEqual(self.form(), {"key": KEY, "ip": "198.51.100.7"})
        self.assertTrue(myaddr.update(KEY, challenge="c" * 43, url=self.srv.url))
        self.assertEqual(self.form(), {"key": KEY, "acme_challenge": "c" * 43})
        with self.assertRaises(ValueError):
            myaddr.update(KEY, ip="1.2.3.4", challenge="c" * 43, url=self.srv.url)
        with self.assertRaises(ValueError):
            myaddr.update(KEY, challenge="short", url=self.srv.url)

    def test_errors_without_key(self):
        self.answer = (400, 'invalid value for "key"\n')
        with self.assertRaises(myaddr.MyaddrError) as ctx:
            myaddr.update(KEY, ip="198.51.100.7", url=self.srv.url)
        self.assertIn("HTTP 400", str(ctx.exception))
        self.assertNotIn(KEY, str(ctx.exception))
        self.answer = (200, "something else")
        with self.assertRaises(myaddr.MyaddrError):
            myaddr.update(KEY, ip="198.51.100.7", url=self.srv.url)

    def test_env_base_url(self):
        with mock.patch.dict(os.environ, {"PF_MYADDR_URL": self.srv.url + "/"}):
            self.assertEqual(myaddr.base_url(), self.srv.url)
            myaddr.update(KEY, ip="2001:db8::7")
        self.assertEqual(self.form()["ip"], "2001:db8::7")

    def test_self_is_never_sent(self):
        n = len(self.srv.requests)
        for bad in ("self", "SELF", "home", "1.2.3"):
            with self.assertRaises(ValueError):
                myaddr.update(KEY, ip=bad, url=self.srv.url)
        self.assertEqual(len(self.srv.requests), n)


class IpEchoTest(unittest.TestCase):
    def test_parse_and_bound_to_wg0(self):
        from app import httpc, probe
        calls = []

        def req(body, status=200):
            def fn(method, url, device=None, **kw):
                calls.append((method, url, device))
                return httpc.Response(status, {}, body.encode())
            return fn
        self.assertEqual(probe.wg_public_ip("wg0", request=req('{"ip": "203.0.113.44", "asn": 1}')), "203.0.113.44")
        self.assertEqual(calls[-1], ("GET", probe.IPECHO_URL, "wg0"))
        self.assertEqual(probe.wg_public_ip("wg0", request=req("2001:db8::4\n")), "2001:db8::4")
        for body, status in (('{"ip": "self"}', 200), ("<html>", 200), ('{"ip": "1.2.3.4"}', 500)):
            self.assertEqual(probe.wg_public_ip("wg0", request=req(body, status)), "")
        self.assertEqual(probe.wg_public_ip(None, request=req('{"ip": "1.2.3.4"}')), "")  # never without wg0
        self.assertEqual(len(calls), 5)


class ValidationTest(unittest.TestCase):
    def test_name_and_key(self):
        self.assertEqual(myaddr.check_name(" Familie-Muster ", "myaddr.dev"), ("familie-muster", "myaddr.dev"))
        for bad in ("abc", "1abcdef", "abcdef-", "a" * 41, "ab_cdef", "ab.cdef"):
            with self.assertRaises(ValidationError, msg=bad):
                myaddr.check_name(bad, "myaddr.tools")
        with self.assertRaises(ValidationError):
            myaddr.check_name("familie", "example.com")
        self.assertEqual(myaddr.check_key(KEY), KEY)
        self.assertEqual(myaddr.check_key("f" * 64), "f" * 64)
        for bad in ("A" * 42, "A" * 44, "A" * 42 + "=", ""):
            with self.assertRaises(ValidationError):
                myaddr.check_key(bad)


class DdnsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = base_responses(FakeRun(), wg0=True)
        p = mock.patch("app.sysrun.run", self.fake)
        p.start()
        self.addCleanup(p.stop)
        self.now = [1763300000]
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.store.update("proton", {"decided": True, "enabled": True, "conf": "[Interface]\n"})
        self.store.update("myaddr", {"name": "familie-muster", "domain": "myaddr.tools", "key": KEY, "ddns": True})
        self.agent = Agent(self.store, netmod.Net(wg_dir=self.tmp), clock=lambda: self.now[0])
        self.sent = []
        self.fail = [None]
        self.up = [True]  # VPN tunnel state for the egress policy
        self.agent.egress.tunnel_up = lambda: self.up[0]
        self.agent.egress._resolve = lambda host: ["203.0.113.80"]  # myaddr.tools: an internet address

        def send(key, ip=None, device=None):
            if ip == "self":
                raise AssertionError("ip=self must never be sent")
            self.sent.append((ip, getattr(device, "kind", device)))
            if self.fail[0]:
                raise myaddr.MyaddrError(self.fail[0])
        self.agent.ddns.send = send

    def test_waits_for_exit_ip_then_updates_on_change_and_keepalive(self):
        self.assertIn("Exit-IP", self.agent.ddns.tick()["skipped"])
        self.assertEqual(self.sent, [])
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.7"
        self.assertTrue(self.agent.ddns.tick()["ok"])
        self.assertEqual(self.sent, [("198.51.100.7", "internet")])
        self.now[0] += 3600
        self.assertEqual(self.agent.ddns.tick()["skipped"], "aktuell")
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.8"
        self.agent.ddns.tick()
        self.assertEqual(self.sent[-1][0], "198.51.100.8")
        self.now[0] += myaddr.KEEPALIVE - 1
        self.agent.ddns.tick()
        self.assertEqual(len(self.sent), 2)
        self.now[0] += 1
        self.agent.ddns.tick()  # 30 days unchanged: keepalive
        self.assertEqual(len(self.sent), 3)
        self.assertEqual(self.store.section("myaddr")["last_ip"], "198.51.100.8")

    def test_backoff_after_failure(self):
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.7"
        self.fail[0] = "myaddr.tools antwortete HTTP 500"
        self.assertFalse(self.agent.ddns.tick()["ok"])
        self.now[0] += myaddr.RETRY_MIN - 1
        self.agent.ddns.tick()
        self.assertEqual(len(self.sent), 1)
        self.now[0] += 1
        self.agent.ddns.tick()
        self.assertEqual(len(self.sent), 2)
        self.fail[0] = None
        self.now[0] += 2 * myaddr.RETRY_MIN
        self.assertTrue(self.agent.ddns.tick()["ok"])
        self.assertEqual(self.agent.ddns.status()["error"], "")

    def test_tunnel_down_without_fallback_no_update(self):
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.7"
        base_responses(self.fake, wg0=False)
        res = self.agent.ddns.tick()
        self.assertFalse(res["ok"])
        self.assertIn("keine Ersatz-IP", res["skipped"])
        self.assertEqual(self.sent, [])
        self.assertIn("kein Update", self.agent.ddns.status()["waiting"])

    def test_tunnel_down_with_fallback_is_queued_and_sent_with_the_tunnel(self):
        """0.10.1: no tunnel -> no request at all; the latest pending address goes out once a tunnel is up."""
        self.store.update("myaddr", {"fallback_ip": "203.0.113.9"})
        base_responses(self.fake, wg0=False)
        self.up[0] = False
        for _ in range(3):
            res = self.agent.ddns.tick()
            self.now[0] += 60
        self.assertFalse(res["ok"])
        self.assertEqual(res["queued"], "203.0.113.9")
        self.assertIn("vorgemerkt", self.agent.ddns.status()["waiting"])
        self.store.update("myaddr", {"fallback_ip": "203.0.113.10"})  # newer state replaces the queued one
        self.assertEqual(self.agent.ddns.tick(force=True)["queued"], "203.0.113.10")
        self.assertEqual(self.sent, [])
        self.assertEqual(self.agent.ddns.rt["fails"], 0)  # queued, not failed: no backoff
        base_responses(self.fake, wg0=True)
        self.up[0] = True
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.7"
        self.assertTrue(self.agent.ddns.tick()["ok"])
        self.assertEqual(self.sent, [("198.51.100.7", "internet")])  # only the latest state
        self.assertEqual(self.agent.ddns.status()["queued"], "")

    def fail_test(self, msg):
        raise AssertionError(msg)

    def test_vpn_exit_ip_unknown_uses_fallback_then_exit_ip(self):
        self.store.update("myaddr", {"fallback_ip": "127.0.0.1"})
        self.assertEqual(self.agent.ddns.tick()["source"], "fallback")
        self.assertEqual(self.sent, [("127.0.0.1", "internet")])
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.7"
        self.assertEqual(self.agent.ddns.tick()["source"], "vpn")
        self.assertEqual(self.sent[-1], ("198.51.100.7", "internet"))

    def test_without_proton_default_never_sends_home_ip(self):
        self.store.update("proton", {"enabled": False})
        for _ in range(3):
            self.assertIn("kein Update", self.agent.ddns.tick()["skipped"])
            self.now[0] += myaddr.KEEPALIVE
        self.assertIn("kein Update", self.agent.ddns.tick(force=True)["skipped"])
        self.assertEqual(self.sent, [])

    def test_without_proton_nothing_to_the_internet(self):
        self.store.update("proton", {"enabled": False})
        self.up[0] = False
        self.store.update("myaddr", {"fallback_ip": "2001:db8::9"})
        self.assertEqual(self.agent.ddns.tick(force=True)["queued"], "2001:db8::9")
        self.assertEqual(self.sent, [])

    def test_without_proton_lan_stand_in_and_keepalive(self):
        """A private (LAN) myaddr stand-in (tests, E2E) is reachable without a tunnel."""
        self.store.update("proton", {"enabled": False})
        self.up[0] = False
        self.agent.egress._resolve = lambda host: ["192.168.77.4"]
        self.store.update("myaddr", {"fallback_ip": "2001:db8::9"})
        self.agent.ddns.tick()
        self.assertEqual(self.sent, [("2001:db8::9", "internet")])
        self.now[0] += myaddr.KEEPALIVE - 1
        self.agent.ddns.tick()
        self.assertEqual(len(self.sent), 1)
        self.now[0] += 1
        self.agent.ddns.tick()
        self.assertEqual(len(self.sent), 2)

    def test_manual_ignores_vpn_and_keepalive(self):
        self.store.update("myaddr", {"ip_mode": "manual", "manual_ip": "203.0.113.5"})
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.7"
        self.agent.ddns.tick()
        self.assertEqual(self.sent, [("203.0.113.5", "internet")])
        self.now[0] += myaddr.KEEPALIVE - 1
        self.agent.ddns.tick()
        self.now[0] += 1
        self.agent.ddns.tick()
        self.assertEqual(self.sent, [("203.0.113.5", "internet")] * 2)
        self.store.update("myaddr", {"manual_ip": ""})
        self.assertIn("manuelle IP", self.agent.ddns.tick(force=True)["skipped"])

    def test_self_never_sent(self):
        """Every mode (also unknown ones like the dropped "line") and VPN state: never ip=self."""
        for mode in ("vpn", "manual", "line", "", "bogus"):
            for proton in (True, False):
                for exit_ip in ("", "198.51.100.7"):
                    for fallback in ("", "127.0.0.1"):
                        self.sent.clear()
                        self.agent.ddns.reset()
                        self.store.update("proton", {"enabled": proton})
                        self.store.update("myaddr", {"ip_mode": mode, "manual_ip": "203.0.113.5",
                                                     "fallback_ip": fallback, "last_ok": 0})
                        self.agent.rt["proton"]["exit_ip"] = exit_ip
                        self.agent.ddns.tick(force=True)
                        self.assertNotIn("self", [ip for ip, _ in self.sent], (mode, proton, exit_ip, fallback))
                        if not proton and not fallback and mode != "manual":
                            self.assertEqual(self.sent, [])
                        tgt = self.agent.redirect.target({"fixed_port": 8443})
                        self.assertTrue(tgt is None or tgt["ip"] in ("198.51.100.7", "127.0.0.1", "203.0.113.5"))

    def test_settings_validation(self):
        certs = self.agent.certs
        base = {"name": "familie-muster", "domain": "myaddr.tools"}
        for mode in ("line", "self", "other"):
            with self.assertRaises(ValidationError):
                certs.set_myaddr(dict(base, ip_mode=mode))
        with self.assertRaises(ValidationError):
            certs.set_myaddr(dict(base, ip_mode="manual"))
        with self.assertRaises(ValidationError):
            certs.set_myaddr(dict(base, ip_mode="manual", manual_ip="999.1.1.1"))
        with self.assertRaises(ValidationError):
            certs.set_myaddr(dict(base, fallback_ip="self"))
        certs.set_myaddr(dict(base, ip_mode="manual", manual_ip=" 2001:DB8::1 "))
        self.assertEqual(self.agent.ddns.status()["manual_ip"], "2001:db8::1")
        certs.set_myaddr(dict(base, ip_mode="vpn", fallback_ip="127.0.0.1"))
        st = self.agent.ddns.status()
        self.assertEqual((st["ip_mode"], st["fallback_ip"]), ("vpn", "127.0.0.1"))

    def test_migration_from_090(self):
        path = os.path.join(self.tmp, "old.json")
        with open(path, "w") as fh:
            fh.write('{"myaddr": {"name": "familie-muster", "domain": "myaddr.tools", "key": "%s", "ddns": true,'
                     ' "last_ip": "self", "last_ok": 1763000000}}' % KEY)
        m = Store(path).section("myaddr")
        self.assertEqual((m["ip_mode"], m["fallback_ip"], m["last_ip"]), ("vpn", "", "self"))

    def test_disabled(self):
        self.store.update("myaddr", {"ddns": False})
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.7"
        self.agent.ddns.tick()
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()
