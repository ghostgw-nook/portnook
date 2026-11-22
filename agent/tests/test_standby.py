import os
import shutil
import socket
import struct
import tempfile
import unittest
from unittest import mock

from app import natpmp as natpmpmod
from app import net as netmod
from app import validate
from app.agent import Agent
from app.store import Store
from tests.fakes import PRIV, PROTON_SAMPLE, PUB, FakeLanProxy, FakeRun, base_responses, key

EXIT = {"p1": "185.159.157.1", "p2": "185.159.157.2", "p3": "185.159.157.3"}


class TunnelConfTest(unittest.TestCase):
    def test_table_off_and_mark_per_interface(self):
        conf = "[Interface]\nPrivateKey = x\nTable = auto\nFwMark = 0x1\n\n[Peer]\nPublicKey = y\n"
        out = netmod.Net.tunnel_conf(conf, "wg1")
        self.assertIn("[Interface]\nTable = off\nFwMark = 0xca6d\nPrivateKey = x", out)
        self.assertNotIn("Table = auto", out)
        self.assertNotIn("0x1\n", out)
        with self.assertRaises(ValueError):
            netmod.Net.tunnel_conf(conf, "eth0")

    def test_policy_rules(self):
        rules = dict(netmod.Net.policy_rules("wg1", ["wg0", "wg1"]))
        self.assertEqual(rules[10000], ["fwmark", "0xca6c", "lookup", "main"])
        self.assertEqual(rules[10001], ["fwmark", "0xca6d", "lookup", "main"])
        self.assertEqual(rules[10010], ["lookup", "main", "suppress_prefixlength", "0"])
        # direct push (bound to eth0) must reach the main table before the tunnel table (0.27.4)
        self.assertEqual(rules[10004], ["fwmark", "0x5046", "lookup", "main"])
        self.assertLess(10004, 10010)
        self.assertEqual(rules[10006], ["fwmark", "0x5101", "lookup", "51821"])
        self.assertLess(10006, 10010)  # replies before the main table (same tunnel subnet on both)
        self.assertEqual(rules[10030], ["oif", "wg0", "lookup", "51820"])
        self.assertEqual(rules[10040], ["lookup", "51821"])
        self.assertEqual(netmod.Net.policy_rules(None, []), [])

    def test_firewall_two_tunnels(self):
        text = netmod.Net.firewall_rules("192.168.1.10", 443, True, [("wg1", [40000]), ("wg0", [51234, 0])])
        self.assertIn("-A PF_PRE -i wg1 -p tcp --dport 40000 -j DNAT --to-destination 192.168.1.10:443", text)
        self.assertIn("-A PF_PRE -i wg0 -p tcp --dport 51234 -j DNAT --to-destination 192.168.1.10:443", text)
        self.assertIn("-A PF_MARK -i wg1 -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x5101", text)
        self.assertNotIn("-j MARK", text)  # the forwarded packet itself keeps no mark
        self.assertIn("-A PF_MARK -i eth0 -m connmark ! --mark 0x0 -j CONNMARK --restore-mark", text)
        self.assertIn("-A PF_OUT -o eth0 -m mark --mark 0xca6d -j ACCEPT", text)
        for bad in ([("eth0", [1])], [("wg1", ["1 -j ACCEPT"])]):
            with self.assertRaises(ValueError):
                netmod.Net.firewall_rules("192.168.1.10", 443, True, bad)
        self.assertNotIn("PF_MARK -i", netmod.Net.firewall_rules("192.168.1.10", 443, False))


class PolicySwitchTest(unittest.TestCase):
    def test_switch_adds_new_rule_before_dropping_old(self):
        fake = FakeRun()
        with mock.patch("app.sysrun.run", fake):
            n = netmod.Net(wg_dir=tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, n.wg_dir, True)
            self.assertTrue(n.policy_apply("wg0", ["wg0", "wg1"]))
            self.assertFalse(n.policy_apply("wg0", ["wg0", "wg1"]))  # unchanged: no command
            fake.calls.clear()
            n.policy_apply("wg1", ["wg0", "wg1"])
            self.assertEqual(fake.joined(), ["ip -4 rule add priority 10040 lookup 51821",
                                             "ip -4 rule del priority 10040 lookup 51820"])
            fake.calls.clear()
            n.policy_apply(None, [])
            self.assertIn("ip -4 rule del priority 10040", fake.joined())
            self.assertFalse(any(" add " in c for c in fake.joined()))


class FakeUdp:
    """Socket double for the NAT-PMP client: answers like a Proton gateway."""
    sent = []

    def __init__(self, *a):
        self.opts, self.out = [], []

    def setsockopt(self, *a):
        self.opts.append(a)

    def connect(self, addr):
        self.addr = addr

    def send(self, data):
        FakeUdp.sent.append(data)
        self.out.append(data)

    def settimeout(self, t):
        pass

    def recv(self, n):
        req = self.out[-1]
        if req[1] == 0:
            return struct.pack("!BBHI", 0, 128, 0, 1) + socket.inet_aton("185.159.157.9")
        op, public, life = req[1], struct.unpack("!H", req[6:8])[0], struct.unpack("!I", req[8:12])[0]
        return struct.pack("!BBHIHHI", 0, 128 + op, 0, 1, 0, public if public > 1 else 45678, life)

    def close(self):
        pass


class BoundNatPmpTest(unittest.TestCase):
    def test_mapping_bound_to_interface(self):
        FakeUdp.sent = []
        res = natpmpmod.bound_request("tcp", "wg1", public=41000, sock_factory=FakeUdp)
        self.assertEqual(res, {"public_ip": "185.159.157.9", "port": 41000, "protocol": "TCP", "lifetime": 60})
        self.assertEqual(FakeUdp.sent[0], b"\x00\x00")
        self.assertEqual(FakeUdp.sent[1], struct.pack("!BBHHHI", 0, 2, 0, 0, 41000, 60))
        self.assertEqual(natpmpmod.bound_request("udp", "wg1", sock_factory=FakeUdp)["port"], 45678)


class StandbyFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = base_responses(FakeRun())
        self.links = set()
        self.now = [1763300000]
        for iface in netmod.TUNNEL_IFS:
            self.fake.on(["ip", "link", "show", "dev", iface], lambda a: 0 if a[-1] in self.links else 1, "")
            self.fake.on(["wg-quick", "up", iface], 0, lambda a: self.links.add(a[-1]) or "")
            self.fake.on(["wg-quick", "down", iface], 0, lambda a: self.links.discard(a[-1]) or "")
            self.fake.on(["ip", "link", "del", "dev", iface], 0, lambda a: self.links.discard(a[-1]) or "")
            self.fake.on(["wg", "show", iface, "dump"], lambda a: 0 if a[2] in self.links else 1,
                         lambda a: self._dump(a[2]))
        p = mock.patch("app.sysrun.run", self.fake)
        p.start()
        self.addCleanup(p.stop)
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.store.update("backend", {"addr": "192.168.1.10:443", "lan_nets": ["192.168.1.0/24"]})
        self.store.update("myaddr", {"name": "familie-muster", "domain": "myaddr.tools", "key": "A" * 43})
        self.lanproxy = FakeLanProxy()
        self.agent = Agent(self.store, netmod.Net(wg_dir=self.tmp), clock=lambda: self.now[0], data_dir=self.tmp,
                           lanproxy=self.lanproxy)
        self.agent.agent_poke = lambda iface: None
        self.agent.proton_test = lambda wait=0: {"ok": True, "exit_ip": EXIT["p1"]}
        self.fo = self.agent.failover
        for name in ("Proton CH", "Proton DE"):
            self.fo.store_profile({"name": name, "conf": PROTON_SAMPLE})
        self.store.update("proton", {"decided": True, "enabled": True, "active": "p1"})
        self.agent.rt["proton"]["exit_ip"] = EXIT["p1"]
        self.agent.forward_port = 51234
        self.mapped = {"wg1": ("185.159.157.2", 40000), "wg0": ("185.159.157.1", 51234)}
        self.agent.standby.request = lambda proto, iface, public=1: {
            "public_ip": self.mapped[iface][0], "port": self.mapped[iface][1], "protocol": proto.upper(),
            "lifetime": 60}

    def _dump(self, iface):
        return "%s\t%s\t51820\toff\n%s\t(none)\t185.159.157.10:51820\t0.0.0.0/0\t%d\t1000\t2000\t25\n" % (
            PRIV, key(9), PUB, self.now[0] - 5)

    def apply(self):
        self.agent.apply_network()
        self.agent.rt["net"]["applied"] = True

    def test_standby_runs_next_to_the_active_tunnel(self):
        self.apply()
        self.assertEqual(self.links, {"wg0", "wg1"})
        self.assertEqual(self.agent.standby.state["profile"], "p2")
        with open(os.path.join(self.tmp, "wg1.conf")) as fh:
            self.assertIn("Table = off\nFwMark = 0xca6d", fh.read())
        self.assertIn("ip -4 rule add priority 10040 lookup 51820", self.fake.joined())
        self.agent.standby.cycle()
        st = self.agent.standby.status()
        self.assertEqual((st["port"], st["exit_ip"], st["ready"]), (40000, EXIT["p2"], True))
        restore = self.fake.restores()[-1]
        self.assertIn("-A PF_PRE -i wg1 -p tcp --dport 40000 -j DNAT", restore)
        self.assertIn("-A PF_PRE -i wg0 -p tcp --dport 51234 -j DNAT", restore)
        self.assertEqual(self.lanproxy.ports, [51234, 40000])
        self.assertEqual(self.agent.profile_exit_ip("p2"), EXIT["p2"])
        listing = {p["id"]: p for p in self.fo.listing()}
        self.assertTrue(listing["p1"]["active"] and listing["p2"]["standby"])
        self.assertEqual((listing["p2"]["standby_ready"], listing["p2"]["standby_reason"]), (True, ""))
        self.links.discard("wg1")  # tunnel gone: the list says so instead of a plain "Reserve"
        listing = {p["id"]: p for p in self.fo.listing()}
        self.assertEqual((listing["p2"]["standby_ready"], listing["p2"]["standby_reason"]), (False, "wg1 läuft nicht"))

    def test_failover_promotes_standby_without_rebuild(self):
        self.apply()
        self.agent.standby.cycle()
        self.store.update("myaddr", {"extra": [{"id": "n1", "name": "muster-de", "domain": "myaddr.tools",
                                                "role": "endpoint", "key": "B" * 43, "profile": "p2"}]})
        self.store.update("redirect", {"provider": "script", "sub": "tv"})
        self.fake.calls.clear()
        up_before = [c for c in self.fake.joined() if c.startswith("wg-quick up")]
        res = self.fo._promoted(self.agent.active_profile(), "Failover nach 2 Fehlern (x)")
        self.assertTrue(res["ok"] and res["promoted"])
        calls = self.fake.joined()
        self.assertEqual(self.agent.active_if, "wg1")
        self.assertEqual(self.agent.active_profile()["id"], "p2")
        self.assertEqual([p["id"] for p in self.agent.profiles(self.store.get())], ["p1", "p2"])  # 0.24.0: fixed
        self.assertLess(calls.index("ip -4 rule add priority 10040 lookup 51821"), calls.index("wg-quick down wg0"))
        self.assertNotIn("wg-quick up wg1", calls)  # no rebuild of the promoted tunnel
        self.assertEqual(up_before, [])
        self.assertIn("wg-quick up wg0", calls)  # the old one comes back as the standby
        self.assertEqual(self.agent.standby.state["profile"], "p1")
        self.assertEqual((self.agent.vpn_exit_ip(), self.agent.public_port()), (EXIT["p2"], 40000))
        self.assertEqual(self.agent.egress.device_for("myaddr.tools", "1.1.1.1"), "wg1")
        tgt = self.agent.redirect.target()
        self.assertEqual(tgt["url"], "https://tv.muster-de.myaddr.tools:40000")
        self.assertEqual(tgt["ip"], EXIT["p2"])
        self.assertIn("Reserve übernommen", self.fo.status()["events"][0]["text"])

    def test_recovered_higher_priority_is_the_standby(self):
        """0.24.0 (owner): running on 2, a recovered 1 is prepared as the standby; no switch back."""
        self.fo.store_profile({"name": "Proton IT", "conf": PROTON_SAMPLE})
        self.apply()
        self.fo.activate("p3", "manuell")
        self.assertEqual([p["id"] for p in self.agent.profiles(self.store.get())], ["p1", "p2", "p3"])
        self.assertEqual((self.agent.active_profile()["id"], self.agent.standby.state["profile"]), ("p3", "p1"))
        self.fo.store_profile({"id": "p1", "enabled": False})
        self.agent.apply_network()
        self.assertEqual(self.agent.standby.state["profile"], "p2")
        self.fo.store_profile({"id": "p1", "enabled": True})
        self.agent.apply_network()
        self.assertEqual((self.agent.active_profile()["id"], self.agent.standby.state["profile"]), ("p3", "p1"))

    def test_standby_not_ready_falls_back_to_rebuild(self):
        self.apply()  # no NAT-PMP cycle yet: standby has no port
        self.assertFalse(self.agent.standby.health()[0])
        self.assertIsNone(self.agent.promote_standby())
        self.assertEqual(self.agent.active_if, "wg0")

    def test_zoraxy_gets_one_pair_per_name(self):
        """0.21.2: every name of the certificate gets its own <name>.pem/.key in the Zoraxy folder."""
        from unittest import mock
        zdir = os.path.join(self.tmp, "zoraxy")
        os.makedirs(zdir)
        self.agent.store.update("delivery", {"zoraxy": {"dir": zdir}})
        c = self.agent.certs
        names = ["familie-muster.myaddr.tools", "*.familie-muster.myaddr.tools", "muster-de.myaddr.io",
                 "*.muster-de.myaddr.io"]
        with mock.patch.object(c, "have_cert", return_value=True), \
                mock.patch.object(c, "read", side_effect=lambda n: "KEY" if n == "privkey.pem" else "CHAIN"), \
                mock.patch.object(c, "info", return_value={"names": names}):
            out = c.deliver()
        self.assertTrue(out["zoraxy"]["ok"], out)
        self.assertEqual(sorted(os.listdir(zdir)), ["familie-muster.myaddr.tools.key", "familie-muster.myaddr.tools.pem",
                                                    "muster-de.myaddr.io.key", "muster-de.myaddr.io.pem"])

    def test_standby_heals_itself(self):
        """0.22.0: deleting the standby profile brings up the next one; a lost standby tunnel comes back."""
        self.fo.store_profile({"name": "Proton IT", "conf": PROTON_SAMPLE})
        self.apply()
        self.assertEqual(self.agent.standby.state["profile"], "p2")  # 0.24.0: highest priority not active
        self.fo.delete_profile("p2")
        self.assertEqual(self.agent.standby.state["profile"], "p3")
        self.assertIn("wg1", self.links)
        self.links.discard("wg1")  # tunnel lost
        self.agent.standby.cycle()
        self.assertIn("wg1", self.links)
        self.assertEqual(self.agent.standby.state["profile"], "p3")

    def test_name_with_several_profiles(self):
        """0.25.0 (owner): one name for several VPN profiles follows the active one of them, else the standby."""
        self.fo.store_profile({"name": "Proton IT", "conf": PROTON_SAMPLE})
        self.apply()
        self.agent.standby.cycle()
        self.agent.names.save_all({"names": [
            {"id": "main", "name": "familie-muster", "domain": "myaddr.tools", "role": "endpoint", "key": "A" * 43},
            {"name": "muster-ch", "domain": "myaddr.tools", "role": "endpoint", "key": "B" * 43,
             "profile": ["p1", "p2"]},
            {"name": "muster-is", "domain": "myaddr.tools", "role": "endpoint", "key": "C" * 43, "profile": "p3"}]})
        n = {x["name"]: x for x in self.agent.names.items()}
        self.assertEqual(n["muster-ch"]["profile"], "p1,p2")
        self.assertEqual(self.agent.names.ip_for(n["muster-ch"]), EXIT["p1"])  # p1 active
        self.assertEqual(self.agent.names.for_profile("p2"), "muster-ch.myaddr.tools")
        self.assertEqual(self.agent.redirect.active_name(), "muster-ch.myaddr.tools")
        self.fo.store_profile({"id": "p1", "enabled": False})
        self.fo.activate("p3", "manuell")
        self.agent.standby.cycle()
        self.assertEqual(self.agent.standby.state["profile"], "p2")
        self.assertEqual(self.agent.names.ip_for(n["muster-ch"]), EXIT["p2"])  # neither active: the standby
        self.assertEqual(self.agent.redirect.active_name(), "muster-is.myaddr.tools")

    def test_active_and_standby_never_share_a_name(self):
        """0.27.8 (owner): names may share profiles; the active tunnel and the standby always get different names."""
        self.apply()
        self.agent.standby.cycle()
        act, sb = self.agent.active_profile()["id"], self.agent.standby.state["profile"]
        self.agent.names.save_all({"names": [
            {"id": "main", "name": "familie-muster", "domain": "myaddr.tools", "role": "endpoint", "key": "A" * 43},
            {"name": "muster-a", "domain": "myaddr.tools", "role": "endpoint", "key": "B" * 43, "profile": "%s,%s" % (act, sb)},
            {"name": "muster-b", "domain": "myaddr.tools", "role": "endpoint", "key": "C" * 43, "profile": "%s,%s" % (act, sb)}]})
        n = {x["name"]: x for x in self.agent.names.items()}
        a_ip, b_ip = self.agent.names.ip_for(n["muster-a"]), self.agent.names.ip_for(n["muster-b"])
        self.assertEqual({a_ip, b_ip}, {EXIT[act], EXIT[sb]})  # one name each, never the same
        self.assertEqual(a_ip, EXIT[act])  # the active tunnel gets the first free name
        self.assertEqual(self.agent.names.for_profile(act), "muster-a.myaddr.tools")
        self.assertEqual(self.agent.names.for_profile(sb), "muster-b.myaddr.tools")
        self.assertEqual(self.agent.redirect.active_name(), "muster-a.myaddr.tools")
        tn = self.agent.status()["myaddr"]["tunnel_names"]
        self.assertEqual(tn, {"active": "muster-a.myaddr.tools", "standby": "muster-b.myaddr.tools"})
        # names keep their address after a switch: the former standby name now serves the active tunnel
        extra = self.agent.store.section("myaddr")["extra"]
        for x in extra:
            x["sent_ip"] = self.agent.names.ip_for(x)  # as after the DNS updates
        self.agent.store.update("myaddr", {"extra": extra})
        self.fo.activate(sb, "manual")
        self.assertEqual(self.agent.active_profile()["id"], sb)
        self.assertEqual(self.agent.redirect.active_name(), "muster-b.myaddr.tools")

    def test_name_without_free_tunnel_keeps_record(self):
        """0.27.8: two tunnels, one shared name: it serves the active tunnel, the standby has no name."""
        self.apply()
        self.agent.standby.cycle()
        act, sb = self.agent.active_profile()["id"], self.agent.standby.state["profile"]
        self.agent.names.save_all({"names": [
            {"id": "main", "name": "familie-muster", "domain": "myaddr.tools", "role": "endpoint", "key": "A" * 43},
            {"name": "muster-a", "domain": "myaddr.tools", "role": "endpoint", "key": "B" * 43,
             "profile": "%s,%s" % (act, sb)}]})
        self.assertEqual(self.agent.status()["myaddr"]["tunnel_names"], {"active": "muster-a.myaddr.tools", "standby": ""})
        self.assertEqual(self.agent.names.for_profile(sb), "muster-a.myaddr.tools")  # fallback: first name of it

    def test_base_name_not_moved_by_order(self):
        """0.24.0: the UI sends the names sorted alphabetically; the current base name stays the base name."""
        self.apply()
        self.agent.names.save_all({"names": [
            {"id": "main", "name": "zulu-muster", "domain": "myaddr.tools", "role": "endpoint", "key": "A" * 43, "profile": "p1"},
            {"name": "alpha-muster", "domain": "myaddr.tools", "role": "endpoint", "key": "B" * 43, "profile": "p2"}]})
        self.assertEqual(self.agent.store.section("myaddr")["name"], "zulu-muster")
        ids = {n["name"]: n.get("id") for n in self.agent.names.items()}
        self.agent.names.save_all({"names": [
            {"id": ids["alpha-muster"], "name": "alpha-muster", "domain": "myaddr.tools", "role": "endpoint", "profile": "p2"},
            {"id": "main", "name": "zulu-muster", "domain": "myaddr.tools", "role": "endpoint", "profile": "p1"}]})
        self.assertEqual(self.agent.store.section("myaddr")["name"], "zulu-muster")

    def test_base_name_with_profile(self):
        """0.22.0: the base name can belong to a VPN profile: its A record is that profile's exit IP."""
        self.apply()
        self.agent.standby.cycle()
        self.assertEqual(self.agent.ddns.resolve()[0], EXIT["p1"])  # no profile: the active tunnel
        self.agent.names.save_all({"names": [
            {"id": "main", "name": "familie-muster", "domain": "myaddr.tools", "role": "endpoint", "profile": "p2"},
            {"name": "muster-de", "domain": "myaddr.tools", "role": "endpoint", "key": "B" * 43, "profile": "p1"}]})
        self.assertEqual(self.agent.store.section("myaddr")["profile"], "p2")
        self.assertEqual(self.agent.ddns.resolve()[0], EXIT["p2"])
        self.assertEqual(self.agent.names.for_profile("p2"), "familie-muster.myaddr.tools")
        self.assertEqual(self.agent.names.for_profile("p1"), "muster-de.myaddr.tools")
        from app.validate import ValidationError
        with self.assertRaises(ValidationError):  # one name per profile
            self.agent.names.save_all({"names": [
                {"id": "main", "name": "familie-muster", "domain": "myaddr.tools", "role": "endpoint", "profile": "p1"},
                {"name": "muster-de", "domain": "myaddr.tools", "role": "endpoint", "profile": "p1"}]})

    def test_standby_off(self):
        self.apply()
        self.fo.set_settings({"standby": False})
        self.assertEqual(self.links, {"wg0"})
        self.assertEqual(self.agent.standby.status()["profile"], "")
        self.assertNotIn("10041", " ".join(self.fake.joined()[-6:]))

    def test_names_and_certificate_domains(self):
        self.apply()
        self.agent.standby.cycle()
        self.agent.names.save({"names": [{"name": "muster-de", "domain": "myaddr.tools", "role": "endpoint",
                                           "key": "B" * 43, "profile": "p2"}]})
        n = self.agent.names.items()[0]
        self.assertEqual(self.agent.names.ip_for(n), EXIT["p2"])
        self.assertEqual(self.agent.names.for_profile("p2"), "muster-de.myaddr.tools")
        self.assertEqual(self.agent.certs.domains(), ["familie-muster.myaddr.tools", "*.familie-muster.myaddr.tools",
                                                      "muster-de.myaddr.tools", "*.muster-de.myaddr.tools"])
        self.assertEqual(self.agent.certs.name_keys()["muster-de.myaddr.tools"], "B" * 43)
        # 0.19.1: every name with a key, entry names too
        self.agent.names.save({"names": [{"name": "muster-de", "domain": "myaddr.tools", "role": "endpoint",
                                           "key": "B" * 43, "profile": "p2"},
                                          {"name": "muster-in", "domain": "myaddr.tools", "role": "entry",
                                           "key": "C" * 43, "ip": "9.9.9.9"}]})
        self.assertIn("*.muster-in.myaddr.tools", self.agent.certs.domains())
        self.assertEqual(self.agent.certs.name_keys()["muster-in.myaddr.tools"], "C" * 43)
        from app.validate import ValidationError
        # 0.20.0: one list; the main name moves to another row, both keep their keys without retyping
        main_key = self.agent.store.section("myaddr")["key"]
        out = self.agent.names.save_all({"names": [
            {"id": self.agent.names.items()[0]["id"], "name": "muster-de", "domain": "myaddr.tools", "role": "endpoint",
             "ip_mode": "vpn"},
            {"id": "main", "name": "familie-muster", "domain": "myaddr.tools", "role": "endpoint", "profile": "p1"},
            {"id": self.agent.names.items()[1]["id"], "name": "muster-in", "domain": "myaddr.tools", "role": "entry",
             "ip": "9.9.9.9"}]})
        self.assertEqual(out["fqdn"], "muster-de.myaddr.tools")
        self.assertEqual(self.agent.store.section("myaddr")["key"], "B" * 43)
        keys = {n["name"]: (n["role"], n["key"]) for n in self.agent.names.items()}
        self.assertEqual(keys, {"familie-muster": ("endpoint", main_key), "muster-in": ("entry", "C" * 43)})
        with self.assertRaises(ValidationError):  # no connection name
            self.agent.names.save_all({"names": [{"name": "muster-in", "domain": "myaddr.tools", "role": "entry",
                                                  "ip": "9.9.9.9", "key": "C" * 43}]})
        with self.assertRaises(ValidationError):  # a new main name needs its key
            self.agent.names.save_all({"names": [{"name": "muster-neu", "domain": "myaddr.tools", "role": "endpoint"}]})
        self.assertEqual(self.agent.store.section("myaddr")["name"], "muster-de")
        # 0.20.1: a name can stay out of the certificate
        items = {n["name"]: n["id"] for n in self.agent.names.items()}
        self.agent.names.save_all({"names": [
            {"id": items["familie-muster"], "name": "familie-muster", "domain": "myaddr.tools", "role": "endpoint",
             "profile": "p1"},
            {"id": "main", "name": "muster-de", "domain": "myaddr.tools", "role": "endpoint"},
            {"id": items["muster-in"], "name": "muster-in", "domain": "myaddr.tools", "role": "entry",
             "ip": "9.9.9.9", "cert": False}]})
        self.assertNotIn("muster-in.myaddr.tools", self.agent.certs.domains())
        self.assertIn("*.familie-muster.myaddr.tools", self.agent.certs.domains())
        with self.assertRaises(ValidationError):
            self.agent.names.save({"names": [{"name": "muster-xx", "domain": "myaddr.tools", "role": "endpoint",
                                               "key": "B" * 43, "profile": "p9"}]})


if __name__ == "__main__":
    unittest.main()
