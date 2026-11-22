"""Push notifications (Gotify, ntfy) and the egress policy for them (0.10.1)."""

import json
import os
import shutil
import tempfile
import unittest
import urllib.parse
from unittest import mock

from app import egress as egressmod, httpc, log as logmod, net as netmod, notify
from app.agent import Agent
from app.store import Store
from app.validate import ValidationError
from tests.fakes import PROTON_SAMPLE, FakeHttp, FakeRun, base_responses

HOSTS = {"gotify.lan": "192.168.1.20", "ntfy.sh": "203.0.113.90", "127.0.0.1": "127.0.0.1"}
GTOKEN = "AbCdEfGhIjKlMnO"
NTOKEN = "tk_secretsecretsecretsecret12345"


class Resp:
    def __init__(self, status=200):
        self.status = status


class NotifyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = base_responses(FakeRun(), wg0=True)
        p = mock.patch("app.sysrun.run", self.fake)
        p.start()
        self.addCleanup(p.stop)
        self.now = [1763300000]
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.store.update("backend", {"addr": "192.168.1.10:443", "lan_nets": ["192.168.1.0/24"]})
        self.agent = Agent(self.store, netmod.Net(wg_dir=self.tmp), clock=lambda: self.now[0])
        self.agent.failover.store_profile({"name": "Proton CH", "conf": PROTON_SAMPLE})
        self.store.update("proton", {"decided": True, "enabled": True, "active": "p1"})
        self.up = [True]
        self.agent.egress.tunnel_up = lambda: self.up[0]
        self.agent.egress._resolve = lambda host: [HOSTS[host]] if host in HOSTS else []
        self.sent = []  # (target host, payload, device chosen by the route)
        self.status = [200]
        self.n = self.agent.notify
        self.n.request = self.request
        logmod.clear()

    def request(self, method, url, body=None, headers=None, device=None, **kw):
        """Stand-in for httpc.request that applies the route policy like httpc's connector does."""
        host = urllib.parse.urlsplit(url).hostname
        dev = device(host, HOSTS[host])  # raises EgressBlocked
        self.sent.append((host, urllib.parse.urlsplit(url).path, dict(headers or {}), body, dev))
        return Resp(self.status[0])

    def configure(self, ntfy_url="http://ntfy.sh", reminder=30):
        return self.n.set_config({"reminder": reminder, "gotify": {"url": "http://gotify.lan/", "token": GTOKEN},
                                  "ntfy": {"url": ntfy_url, "topic": "pf-alarm", "token": NTOKEN}})

    def by_host(self, host):
        return [s for s in self.sent if s[0] == host]

    def test_config_is_validated_and_tokens_write_only(self):
        st = self.configure()["push"]
        self.assertEqual((st["gotify"]["url"], st["gotify"]["lan"], st["gotify"]["token_set"]),
                         ("http://gotify.lan", True, True))
        self.assertEqual((st["ntfy"]["lan"], st["ntfy"]["topic"]), (False, "pf-alarm"))
        text = json.dumps(self.agent.status())
        self.assertNotIn(GTOKEN, text)
        self.assertNotIn(NTOKEN, text)
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777, 0o600)
        # unchanged URL: the stored token is kept; a new URL needs the token again (no token leak to a new host)
        self.n.set_config({"gotify": {"url": "http://gotify.lan"}})
        self.assertTrue(self.n.status()["gotify"]["token_set"])
        with self.assertRaises(ValidationError):
            self.n.set_config({"gotify": {"url": "http://other.lan"}})
        for bad in ({"gotify": {"url": "ftp://x", "token": "a"}}, {"gotify": {"url": "http://u:p@x", "token": "a"}},
                    {"ntfy": {"url": "http://x", "topic": "a b"}}, {"reminder": 0}, {"reminder": "x"}):
            with self.assertRaises(ValidationError):
                self.n.set_config(bad)
        self.n.set_config({"gotify": {"url": ""}, "ntfy": {"url": "", "topic": ""}})
        self.assertEqual(self.n.configured(), [])

    def test_test_button_formats(self):
        self.configure()
        res = self.n.test()
        self.assertTrue(res["ok"], res)
        g, = self.by_host("gotify.lan")
        self.assertEqual((g[1], g[2]["X-Gotify-Key"], g[4]), ("/message", GTOKEN, "eth0"))
        self.assertEqual(g[3]["title"], "portnook: Test")
        n, = self.by_host("ntfy.sh")
        self.assertEqual((n[1], n[2]["Authorization"], n[4]), ("/", "Bearer " + NTOKEN, ("eth0", egressmod.PUSH_MARK)))
        self.assertEqual((n[3]["topic"], n[3]["priority"]), ("pf-alarm", 3))
        self.status[0] = 401
        res = self.n.test()
        self.assertFalse(res["ok"])
        self.assertIn("HTTP 401", res["results"]["gotify"]["error"])
        logs = "\n".join(logmod.lines())
        for secret in (GTOKEN, NTOKEN, "pf-alarm"):
            self.assertNotIn(secret, logs)

    def test_test_button_without_tunnel_goes_direct(self):
        """Push need not hide the home IP (0.18.0): without a tunnel both servers are reached, ntfy.sh straight
        through eth0 with the push socket mark."""
        self.configure()
        self.up[0] = False
        base_responses(self.fake, wg0=False)
        res = self.n.test()
        self.assertTrue(res["ok"])
        self.assertEqual(sorted(s[0] for s in self.sent), ["gotify.lan", "ntfy.sh"])
        self.assertEqual(self.by_host("ntfy.sh")[0][4], ("eth0", egressmod.PUSH_MARK))

    def test_dedupe_and_rate_limit(self):
        self.configure()
        self.assertTrue(self.n.event("ddns_error", "DDNS", "HTTP 500"))
        self.assertFalse(self.n.event("ddns_error", "DDNS", "HTTP 500"))  # same text within an hour
        self.assertTrue(self.n.event("ddns_error", "DDNS", "HTTP 502"))
        self.n.flush()
        self.assertEqual(len(self.by_host("gotify.lan")), 1)  # latest message per event only
        self.now[0] += notify.DEDUPE
        self.assertTrue(self.n.event("ddns_error", "DDNS", "HTTP 500"))
        for i in range(notify.RATE * 2):
            self.n.event("cert_error", "Zertifikat", "Fehler %d" % i)
        self.assertLessEqual(len(self.n.sent_times), notify.RATE)

    def test_all_down_alarm_reminder_and_recovery(self):
        """All VPNs down: the LAN Gotify and ntfy.sh (directly through eth0) get the alarm and the reminders."""
        self.configure(reminder=30)
        self.up[0] = False
        base_responses(self.fake, wg0=False)
        self.n.vpn_down("Alle VPN-Profile gestört")
        self.n.tick()
        for host in ("gotify.lan", "ntfy.sh"):
            self.assertEqual([s[3]["title"] for s in self.by_host(host)], ["portnook: Alle VPNs ausgefallen"])
        self.now[0] += 29 * 60
        self.n.tick()
        self.assertEqual(len(self.by_host("ntfy.sh")), 1)
        self.now[0] += 60
        self.n.tick()
        self.now[0] += 30 * 60
        self.n.tick()
        titles = [s[3]["title"] for s in self.by_host("ntfy.sh")]
        self.assertEqual(titles[1:], ["portnook: Alle VPNs weiterhin ausgefallen"] * 2)
        self.assertEqual(self.n.status()["ntfy"]["queued"], 0)
        # recovered: still direct, never through wg0
        base_responses(self.fake, wg0=True)
        self.up[0] = True
        self.n.vpn_up("Proton CH")
        self.n.tick()
        self.assertIn("Ausfall 60 min", self.by_host("ntfy.sh")[-1][3]["message"])
        self.assertTrue(all(s[4] == ("eth0", egressmod.PUSH_MARK) for s in self.by_host("ntfy.sh")))
        self.now[0] += 3600
        self.n.tick()
        self.assertEqual(len(self.sent), 8)  # no reminder after the recovery

    def test_failover_events(self):
        self.configure()
        fo = self.agent.failover
        self.agent.failover.store_profile({"name": "AirVPN", "conf": PROTON_SAMPLE, "provider": "fixed",
                                           "ports": "43210"})
        healthy = {"p1": False, "p2": True}
        self.agent.start_profile = lambda prof, summary=None: {
            "ok": healthy[prof["id"]], "test": {"ok": healthy[prof["id"]], "exit_ip": "198.51.100.2", "error": ""}}
        fo.health = lambda st=None: (healthy[self.agent.active_profile()["id"]], "kein frischer Handshake")
        fo.set_settings({"fails": 1, "prefer_primary": False, "hold": 600})
        self.now[0] += 30
        self.assertEqual(fo.tick(), "switched")
        healthy["p2"] = False
        self.now[0] += 30
        self.assertEqual(fo.tick(), "all-down")
        self.assertTrue(self.n.down_since)
        healthy["p2"] = True
        self.now[0] += 30
        self.assertEqual(fo.tick(), "ok")
        self.n.flush()
        titles = [s[3]["title"] for s in self.by_host("gotify.lan")]
        self.assertEqual(titles, ["portnook: VPN-Profilwechsel", "portnook: Alle VPNs ausgefallen",
                                  "portnook: VPN wieder verfügbar"])

    def test_transport_error_keeps_message(self):
        self.configure(ntfy_url="http://127.0.0.1:9")
        self.n.request = httpc.request  # real client: nothing listens on port 9
        self.n.set_config({"gotify": {"url": ""}})
        self.n.event("cert_renewed", "Zertifikat erneuert", "ok")
        self.assertEqual(self.n.flush(), 0)
        self.assertEqual(self.n.status()["ntfy"]["queued"], 1)
        self.assertTrue(self.n.status()["ntfy"]["error"])


class NotifyHttpTest(unittest.TestCase):
    """Real HTTP against local fake Gotify/ntfy servers (loopback = LAN), without a VPN."""

    def test_real_requests(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        try:
            srv = FakeHttp(lambda m, p, h, b: (200, {"id": 1}))
        except OSError as err:
            self.skipTest("cannot bind local port: %s" % err)
        self.addCleanup(srv.close)
        agent = Agent(Store(os.path.join(tmp, "agent.json")), netmod.Net(wg_dir=tmp))
        agent.notify.set_config({"gotify": {"url": srv.url, "token": GTOKEN},
                                 "ntfy": {"url": srv.url, "topic": "pf-alarm"}})
        self.assertTrue(agent.notify.test()["ok"])
        paths = sorted(r[1] for r in srv.requests)
        self.assertEqual(paths, ["/", "/message"])
        body = json.loads([r for r in srv.requests if r[1] == "/"][0][3])
        self.assertEqual(body["topic"], "pf-alarm")


if __name__ == "__main__":
    unittest.main()
