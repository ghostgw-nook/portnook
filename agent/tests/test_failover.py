import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from app import failover, net as netmod
from app.agent import Agent
from app.store import Store
from app.validate import ValidationError
from tests.fakes import PRIV, PROTON_SAMPLE, FakeRun, base_responses

EXIT = {"p1": "198.51.100.1", "p2": "198.51.100.2", "p3": "198.51.100.3"}


class FailoverTest(unittest.TestCase):
    """Switching logic with fake probes: ``health`` and ``start_profile`` are replaced per profile."""

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
        self.fo = self.agent.failover
        for name, ports in (("Proton CH", None), ("AirVPN", "43210"), ("AirVPN 2", "43300, 43301")):
            body = {"name": name, "conf": PROTON_SAMPLE}
            if ports:
                body.update({"provider": "fixed", "ports": ports})
            self.fo.store_profile(body)
        self.store.update("proton", {"decided": True, "enabled": True, "active": "p1"})
        self.healthy = {"p1": True, "p2": True, "p3": True}
        self.started = []

        def start(prof, summary=None):
            self.started.append(prof["id"])
            ok = self.healthy[prof["id"]]
            self.agent.rt["proton"]["exit_ip"] = EXIT[prof["id"]] if ok else ""
            return {"ok": ok, "test": {"ok": ok, "exit_ip": EXIT[prof["id"]] if ok else "", "error": "" if ok else "x"}}
        self.agent.start_profile = start
        self.fo.health = lambda st=None: ((self.healthy[self.active()], "") if self.healthy[self.active()]
                                          else (False, "kein frischer Handshake"))
        self.agent.egress.tunnel_up = lambda: bool(self.healthy[self.active()] and not self.fo.rt["all_down"])

    def active(self):
        return self.agent.active_profile()["id"]

    def run_checks(self, n, step=30):
        out = []
        for _ in range(n):
            self.now[0] += step
            out.append(self.fo.tick())
        return out

    def test_switch_after_n_failures_and_dnat_ports(self):
        self.assertEqual(self.run_checks(2), ["ok", "ok"])
        self.healthy["p1"] = False
        self.assertEqual(self.run_checks(1), ["failing"])
        self.assertEqual(self.fo.wait_hint(), failover.FAST_RECHECK)
        self.assertEqual(self.active(), "p1")
        self.assertEqual(self.run_checks(1), ["switched"])
        # 0.24.0: the list is a fixed priority; the next profile from the top is tried first, the order stays
        self.assertEqual((self.active(), self.started), ("p2", ["p2"]))
        self.assertEqual([p["id"] for p in self.agent.profiles(self.store.get())], ["p1", "p2", "p3"])
        self.assertEqual(self.agent.forward_ports(), [43210])
        self.assertEqual(self.agent.public_port(), 43210)
        self.assertEqual(self.agent.vpn_exit_ip(), EXIT["p2"])
        self.assertIn("Failover", self.fo.status()["events"][0]["text"])
        rules = netmod.Net.firewall_rules("192.168.1.10", 443, True, self.agent.forward_ports())
        self.assertIn("--dport 43210 -j DNAT", rules)

    def test_configurable_threshold(self):
        self.fo.set_settings({"fails": 1, "prefer_primary": False, "hold": 0})
        self.healthy["p1"] = False
        self.assertEqual(self.run_checks(1), ["switched"])
        with self.assertRaises(ValidationError):
            self.fo.set_settings({"fails": 0})

    def test_rotation_every_n_hours_without_try_back(self):
        self.fo.set_settings({"rotate": "hours", "rotate_hours": 2})
        self.assertEqual(self.run_checks(1, step=3600), ["ok"])
        self.assertEqual(self.run_checks(1, step=3600), ["rotated"])
        self.assertEqual(self.active(), "p2")  # round robin: the next one below the active one
        self.assertIn("Rotation", self.fo.status()["events"][0]["text"])
        self.assertEqual(self.run_checks(3, step=600), ["ok", "ok", "ok"])  # no way back to p1 while rotating
        self.assertEqual(self.run_checks(1, step=7200), ["rotated"])
        self.assertEqual(self.active(), "p3")
        self.assertEqual(self.run_checks(1, step=7200), ["rotated"])
        self.assertEqual(self.active(), "p1")

    def test_rotation_daily_and_rollback(self):
        lt = time.localtime(self.now[0] + 3600)
        self.fo.set_settings({"rotate": "daily", "rotate_at": "%02d:%02d" % (lt.tm_hour, lt.tm_min)})
        self.assertGreater(self.fo.status()["next_rotate"], self.now[0])
        self.assertEqual(self.run_checks(1, step=1800), ["ok"])
        self.healthy["p2"] = False
        self.assertEqual(self.run_checks(1, step=1800), ["rotated"])
        self.assertEqual((self.active(), self.started), ("p1", ["p2", "p1"]))
        self.assertEqual(self.run_checks(1, step=1800), ["ok"])  # once per day

    def test_rotation_settings_validated(self):
        for body in ({"rotate": "weekly"}, {"rotate": "daily", "rotate_at": "25:00"}, {"rotate_hours": 0}):
            with self.assertRaises(ValidationError):
                self.fo.set_settings(body)
        self.assertEqual(self.fo.settings()["fails"], 2)

    def test_verify_after_switch(self):
        self.store.update("myaddr", {"name": "familie-muster", "domain": "myaddr.tools", "key": "A" * 43, "ddns": True})
        self.fo.activate("p2", "manuell")
        self.assertEqual(self.fo.verify(), "pending")
        self.assertEqual(self.fo.wait_hint(), failover.FAST_RECHECK)
        self.store.update("myaddr", {"last_ip": EXIT["p2"]})
        self.assertEqual(self.fo.verify(), "verified")
        self.assertIn("Nach Wechsel geprüft: DNS " + EXIT["p2"], self.fo.status()["events"][0]["text"])
        self.fo.activate("p3", "manuell")
        self.now[0] += failover.VERIFY_TIMEOUT
        self.assertEqual(self.fo.verify(), "unverified")
        self.assertIn("nicht nachgeführt", self.fo.status()["events"][0]["text"])
        self.assertIsNone(self.fo.wait_hint())

    def test_skips_disabled_and_failing_profiles(self):
        self.fo.store_profile({"id": "p2", "enabled": False})
        self.healthy.update({"p1": False, "p3": True})
        self.run_checks(3)
        self.assertEqual(self.active(), "p3")

    def test_all_down_stays_and_retries_after_hold(self):
        self.fo.set_settings({"fails": 1, "prefer_primary": False, "hold": 600})
        self.healthy.update({"p1": False, "p2": False, "p3": False})
        self.assertEqual(self.run_checks(3), ["switched", "switched", "all-down"])
        self.assertEqual(self.started, ["p2", "p3"])
        self.assertEqual(self.run_checks(5), ["all-down"] * 5)
        self.assertIn("Alle VPN-Profile gestört", self.fo.status()["events"][0]["text"])
        self.assertTrue(self.fo.status()["all_down"])
        self.assertEqual(self.agent.vpn_exit_ip(), "")  # DDNS: fallback IP or no update
        self.now[0] += 600
        self.assertEqual(self.fo.tick(), "switched")  # new round
        self.assertEqual(self.active(), "p1")

    def test_no_way_back_order_is_fixed(self):
        # 0.24.0 (owner): the list is a fixed priority, a switch does not reorder it and there is no try-back
        self.fo.set_settings({"fails": 1, "prefer_primary": True, "hold": 600})
        self.assertFalse(self.fo.settings()["prefer_primary"])
        self.healthy["p1"] = False
        self.run_checks(1)
        self.assertEqual(self.active(), "p2")
        self.healthy["p1"] = True
        self.assertEqual(self.run_checks(40), ["ok"] * 40)
        self.assertEqual(self.active(), "p2")
        self.assertEqual(self.started, ["p2"])
        self.fo.activate("p3", "manuell")
        self.assertEqual([p["id"] for p in self.agent.profiles(self.store.get())], ["p1", "p2", "p3"])

    def test_prefer_primary_off_stays(self):
        self.fo.set_settings({"fails": 1, "prefer_primary": False, "hold": 0})
        self.healthy["p1"] = False
        self.run_checks(1)
        self.healthy["p1"] = True
        self.assertEqual(self.run_checks(50), ["ok"] * 50)
        self.assertEqual(self.active(), "p2")

    def test_single_profile_never_switches(self):
        for pid in ("p2", "p3"):
            self.fo.delete_profile(pid)
        self.healthy["p1"] = False
        self.assertEqual(self.run_checks(5)[-1], "all-down")
        self.assertEqual(self.started, [])
        self.assertIn("kein weiteres Profil", self.fo.status()["events"][0]["text"])

    def test_without_vpn_nothing(self):
        self.store.update("proton", {"enabled": False})
        self.healthy["p1"] = False
        self.assertEqual(self.run_checks(5), [None] * 5)

    def test_ddns_follows_the_switch(self):
        self.store.update("myaddr", {"name": "familie-muster", "domain": "myaddr.tools", "key": "A" * 43})
        sent = []
        self.agent.ddns.send = lambda key, ip=None, device=None: sent.append(ip)
        self.agent.rt["proton"]["exit_ip"] = EXIT["p1"]
        self.agent.ddns.tick()
        self.healthy["p1"] = False
        self.run_checks(3)
        self.agent.ddns.tick()
        self.assertEqual(sent, [EXIT["p1"], EXIT["p2"]])


class HealthTest(unittest.TestCase):
    """The real health check (wg0, handshake age, NAT-PMP / exit IP)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = FakeRun()
        p = mock.patch("app.sysrun.run", self.fake)
        p.start()
        self.addCleanup(p.stop)
        self.now = 1763300000
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.agent = Agent(self.store, netmod.Net(wg_dir=self.tmp), clock=lambda: self.now)
        self.agent.failover.store_profile({"name": "A", "conf": PROTON_SAMPLE})
        self.store.update("proton", {"decided": True, "enabled": True, "active": "p1"})

    def test_health(self):
        h = self.agent.failover.health
        base_responses(self.fake, wg0=False)
        self.assertEqual(h(), (False, "wg0 läuft nicht"))
        base_responses(self.fake, wg0=True, handshake=self.now - 200)
        self.assertEqual(h(), (False, "kein frischer Handshake"))
        base_responses(self.fake, wg0=True, handshake=self.now - 20)
        self.assertEqual(h(), (False, "Exit-IP unbekannt"))
        self.agent.rt["proton"]["exit_ip"] = "198.51.100.1"
        self.assertEqual(h(), (True, ""))
        self.agent.natpmp = mock.Mock(state={"fails": 2})
        self.assertEqual(h(), (False, "NAT-PMP antwortet nicht"))
        self.store.update("proton", {"enabled": False})
        self.assertEqual(h(), (None, ""))


class ProfileStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = base_responses(FakeRun(), wg0=True)
        p = mock.patch("app.sysrun.run", self.fake)
        p.start()
        self.addCleanup(p.stop)
        self.path = os.path.join(self.tmp, "agent.json")

    def test_migration_of_single_config(self):
        with open(self.path, "w") as fh:
            json.dump({"proton": {"decided": True, "enabled": True, "conf": "[Interface]\nx\n", "server": "CH#12",
                                  "endpoint": "185.159.157.10:51820", "provider": "fixed", "ports": [43210]}}, fh)
        store = Store(self.path)
        p = store.section("proton")
        self.assertNotIn("conf", p)
        self.assertEqual(p["active"], "p1")
        self.assertEqual([(x["id"], x["name"], x["provider"], x["ports"], x["enabled"]) for x in p["profiles"]],
                         [("p1", "CH#12", "fixed", [43210], True)])
        agent = Agent(store, netmod.Net(wg_dir=self.tmp))
        self.assertEqual(agent.forward_ports(), [43210])

    def test_crud_order_and_secrets(self):
        store = Store(self.path)
        agent = Agent(store, netmod.Net(wg_dir=self.tmp))
        fo = agent.failover
        a, _ = fo.store_profile({"name": "A", "conf": PROTON_SAMPLE})
        b, _ = fo.store_profile({"name": "B", "provider": "fixed", "ports": [43210], "conf": PROTON_SAMPLE})
        self.assertEqual((a["id"], b["id"]), ("p1", "p2"))
        with self.assertRaises(ValidationError):
            fo.store_profile({"name": "C"})  # no config
        with self.assertRaises(ValidationError):
            fo.store_profile({"name": "C", "provider": "fixed", "conf": PROTON_SAMPLE})  # no ports
        with self.assertRaises(ValidationError):
            fo.set_order(["p2"])
        fo.set_order(["p2", "p1"])
        self.assertEqual([p["id"] for p in fo.listing()], ["p2", "p1"])
        store.update("proton", {"enabled": False})
        self.assertNotIn(PRIV, json.dumps(fo.listing()))
        self.assertNotIn(PRIV, json.dumps(agent.status()))
        fo.delete_profile("p2")
        self.assertEqual([p["id"] for p in fo.listing()], ["p1"])
        with self.assertRaises(ValidationError):
            fo.activate("p9")
        for _ in range(failover.MAX_PROFILES - 1):
            fo.store_profile({"conf": PROTON_SAMPLE})
        with self.assertRaises(ValidationError):
            fo.store_profile({"conf": PROTON_SAMPLE})


if __name__ == "__main__":
    unittest.main()
