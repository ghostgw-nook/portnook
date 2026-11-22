"""Tunnel MTU per VPN profile and MSS clamping (0.10.3)."""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from app import net as netmod, protonconf
from app.agent import Agent
from app.store import Store
from app.validate import ValidationError
from tests.fakes import PROTON_SAMPLE, FakeRun, base_responses

WITH_MTU = PROTON_SAMPLE.replace("Address = ", "MTU = 1400\r\nAddress = ")


class MtuSettingTest(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(protonconf.mtu_setting(1340), 1340)
        self.assertEqual(protonconf.mtu_setting("1280"), 1280)
        self.assertEqual(protonconf.mtu_setting(" Conf "), "conf")
        for bad in (1279, 1501, "abc", "", None, True, 9000):
            with self.assertRaises(ValidationError):
                protonconf.mtu_setting(bad)

    def test_effective_mtu(self):
        self.assertEqual(protonconf.profile_mtu({}), (1340, 1340))
        self.assertEqual(protonconf.profile_mtu({"mtu": 1400}), ("conf", 1400))
        self.assertEqual(protonconf.profile_mtu({"mtu_setting": 1280, "mtu": 1400}), (1280, 1280))
        self.assertEqual(protonconf.profile_mtu({"mtu_setting": "conf"}), ("conf", 1420))
        self.assertEqual(protonconf.profile_mtu({"mtu_setting": "conf", "mtu": 1380}), ("conf", 1380))

    def test_with_mtu_replaces_line(self):
        text = protonconf.parse(WITH_MTU).render()
        out = protonconf.with_mtu(text, 1300)
        self.assertEqual(out.count("MTU ="), 1)
        self.assertIn("MTU = 1300", out)
        plain = protonconf.with_mtu(protonconf.parse(PROTON_SAMPLE).render(), 1340)
        self.assertIn("Address = 10.2.0.2/32\nMTU = 1340\n", plain)


class MigrationTest(unittest.TestCase):
    def test_existing_profiles(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "agent.json")
        with open(path, "w") as fh:
            json.dump({"proton": {"enabled": True, "active": "p1", "profiles": [
                {"id": "p1", "name": "a", "conf": "x", "mtu": None},
                {"id": "p2", "name": "b", "conf": "x", "mtu": 1400},
                {"id": "p3", "name": "c", "conf": "x", "mtu": 1400, "mtu_setting": 1300}]}}, fh)
        profs = Store(path).get()["proton"]["profiles"]
        self.assertEqual([p["mtu_setting"] for p in profs], [1340, "conf", 1300])

    def test_legacy_single_config(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "agent.json")
        with open(path, "w") as fh:
            json.dump({"proton": {"enabled": True, "conf": "x", "mtu": 1412}}, fh)
        self.assertEqual(Store(path).get()["proton"]["profiles"][0]["mtu_setting"], "conf")


class FirewallMssTest(unittest.TestCase):
    def test_set_mss_wg(self):
        text = netmod.Net.firewall_rules("192.168.1.10", 443, True, 51234, mss=1300)
        self.assertIn("-A PF_MSS -i wg+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300", text)
        self.assertIn("-A PF_MSS -o wg+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300", text)
        self.assertNotIn("-i eth0 -o eth0", text)  # the LAN entry proxy ends TCP itself (0.18.1)

    def test_without_vpn_clamps_to_pmtu(self):
        text = netmod.Net.firewall_rules("192.168.1.10", 443, False)
        self.assertIn("-j TCPMSS --clamp-mss-to-pmtu", text)
        self.assertNotIn("-i eth0 -o eth0 -p tcp --tcp-flags", text)
        with self.assertRaises(ValueError):
            netmod.Net.firewall_rules("192.168.1.10", 443, True, 51234, mss="1300 -j ACCEPT")


class AgentMtuTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = base_responses(FakeRun())
        for p in (mock.patch("app.sysrun.run", self.fake),
                  mock.patch("app.probe.proton_public_ip", return_value="198.51.100.7"),
                  mock.patch("app.probe.natpmpc_available", return_value=True),
                  mock.patch("app.agent.Agent._poke_proton")):
            p.start()
            self.addCleanup(p.stop)

        def up(args):
            base_responses(self.fake, wg0=True, handshake=int(time.time()))
            return ""
        self.fake.on(["wg-quick", "up", "wg0"], 0, up)
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.net = netmod.Net(wg_dir=os.path.join(self.tmp, "wireguard"))
        self.agent = Agent(self.store, self.net, version="0.2.0", sleep=lambda s: None)

    def written(self):
        with open(self.net.proton_conf_path) as fh:
            return fh.read()

    def test_mtu_per_profile_on_start_and_switch(self):
        res = self.agent.setup_proton({"enabled": True, "conf": PROTON_SAMPLE, "lan_nets": ["192.168.1.0/24"]})
        self.assertTrue(res["ok"], res)
        self.assertIn("MTU = 1340", self.written())  # default
        self.assertIn("--set-mss 1300", self.fake.restores()[-1])
        fo = self.agent.failover
        fo.set_settings({"standby": False})  # MSS of the active tunnel alone (with a standby: the smaller MTU)
        p2, _ = fo.store_profile({"name": "B", "conf": WITH_MTU, "mtu": "conf", "provider": "fixed",
                                  "ports": "43210"})
        p3, _ = fo.store_profile({"name": "C", "conf": PROTON_SAMPLE, "mtu": 1280, "provider": "fixed",
                                  "ports": "43211"})
        fo.activate(p2["id"])
        self.assertIn("MTU = 1400", self.written())
        self.assertIn("--set-mss 1360", self.fake.restores()[-1])
        fo.activate(p3["id"])
        self.assertIn("MTU = 1280", self.written())
        self.assertIn("--set-mss 1240", self.fake.restores()[-1])
        fo.set_settings({"standby": True})
        self.assertIn("--set-mss 1240", self.fake.restores()[-1])  # C (1280) active, standby p1 (1340)
        fo.activate(p2["id"])
        self.assertIn("--set-mss 1300", self.fake.restores()[-1])  # B (1400) active, standby p1 (1340): smaller
        listing = {x["name"]: x for x in fo.listing()}
        self.assertEqual((listing["B"]["mtu"], listing["B"]["mtu_effective"], listing["B"]["conf_mtu"]),
                         ("conf", 1400, 1400))
        with self.assertRaises(ValidationError):
            fo.store_profile({"id": p3["id"], "mtu": 1600})

    def test_changed_mtu_rebuilds_wg0(self):
        self.agent.setup_proton({"enabled": True, "conf": PROTON_SAMPLE, "lan_nets": ["192.168.1.0/24"]})
        ups = self.fake.joined().count("wg-quick up wg0")
        self.agent.failover.save_profile({"id": "p1", "mtu": 1420})
        self.assertEqual(self.fake.joined().count("wg-quick up wg0"), ups + 1)
        self.assertIn("MTU = 1420", self.written())


if __name__ == "__main__":
    unittest.main()
