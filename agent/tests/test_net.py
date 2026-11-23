import ipaddress
import os
import shutil
import stat
import tempfile
import time
import unittest
from unittest import mock

from app import net as netmod
from app import agent as agentmod
from app.agent import Agent, SetupError
from app.httpc import EgressBlocked
from app.store import Store
from app.validate import ValidationError
from tests.fakes import PRIV, PROTON_SAMPLE, FakeLanProxy, FakeRun, FakeTunnelProxy, base_responses

IPT = "iptables -w 5 -t "


RESTORE_PROTON = """*nat
:PF_PRE - [0:0]
:PF_POST - [0:0]
-A PF_PRE -i wg0 -p tcp --dport 51234 -j DNAT --to-destination 192.168.1.10:443
-A PF_POST -o eth0 -m conntrack --ctstate DNAT -j MASQUERADE
COMMIT
*mangle
:PF_MARK - [0:0]
:PF_MSS - [0:0]
-A PF_MSS -i wg+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
-A PF_MSS -o wg+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
-A PF_MARK -i wg0 -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x5100
-A PF_MARK -i wg1 -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x5101
-A PF_MARK -i eth0 -m connmark ! --mark 0x0 -j CONNMARK --restore-mark
COMMIT
*filter
:PF_IN - [0:0]
:PF_FWD - [0:0]
:PF_OUT - [0:0]
-A PF_IN -i wg+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A PF_IN -i wg+ -j DROP
-A PF_FWD -i wg+ -o eth0 -p tcp -d 192.168.1.10 --dport 443 -m conntrack --ctstate DNAT -j ACCEPT
-A PF_FWD -i eth0 -o wg+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A PF_FWD -i wg+ -j DROP
-A PF_FWD -o wg+ -j DROP
-A PF_OUT -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A PF_OUT -o eth0 -d 10.0.0.0/8 -j ACCEPT
-A PF_OUT -o eth0 -d 172.16.0.0/12 -j ACCEPT
-A PF_OUT -o eth0 -d 192.168.0.0/16 -j ACCEPT
-A PF_OUT -o eth0 -d 169.254.0.0/16 -j ACCEPT
-A PF_OUT -o eth0 -m mark --mark 0xca6c -j ACCEPT
-A PF_OUT -o eth0 -m mark --mark 0xca6d -j ACCEPT
-A PF_OUT -o eth0 -m mark --mark 0x5046 -j ACCEPT
-A PF_OUT -o eth0 -j REJECT --reject-with icmp-net-prohibited
COMMIT
"""


class NetSequenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = base_responses(FakeRun())
        self.patch = mock.patch("app.sysrun.run", self.fake)
        self.patch.start()
        self.net = netmod.Net(wg_dir=os.path.join(self.tmp, "wireguard"))

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_routes(self):
        routes = self.net.apply_routes(["192.168.1.0/24"], "192.168.5.10", ["192.168.1.50", "10.0.0.7"])
        self.assertEqual(routes, ["192.168.1.0/24", "192.168.5.10/32", "10.0.0.7/32"])
        self.assertEqual(self.fake.joined(), [
            "ip -4 route show default",
            "ip -4 -o addr show dev eth0",
            "ip -4 route replace 192.168.1.0/24 via 172.18.0.1 dev eth0",
            "ip -4 route replace 192.168.5.10/32 via 172.18.0.1 dev eth0",
            "ip -4 route replace 10.0.0.7/32 via 172.18.0.1 dev eth0",
        ])
        self.fake.calls.clear()
        self.net.apply_routes(["192.168.1.0/24"], "192.168.1.10")
        self.assertEqual(self.fake.joined(), [
            "ip -4 -o addr show dev eth0",
            "ip -4 route del 192.168.5.10/32 via 172.18.0.1 dev eth0",
            "ip -4 route del 10.0.0.7/32 via 172.18.0.1 dev eth0",
            "ip -4 route replace 192.168.1.0/24 via 172.18.0.1 dev eth0",
        ])

    def test_backend_on_docker_net_needs_no_route(self):
        self.assertEqual(self.net.apply_routes([], "172.18.0.1"), [])

    def test_no_gateway(self):
        self.fake.on(["ip", "-4", "route", "show", "default"], 0, "")
        with self.assertRaises(netmod.NetError):
            self.net.apply_routes([], None)

    def test_proton_up_writes_600_file(self):
        self.net.proton_up("[Interface]\nPrivateKey = %s\n" % PRIV)
        path = self.net.proton_conf_path
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(self.fake.joined(), ["ip link show dev wg0", "wg-quick up wg0",
                                              "ip -4 route replace default dev wg0 table 51820",
                                              "ip -4 route replace unreachable default metric 4096 table 51820"])
        self.assertTrue(all(PRIV not in c for c in self.fake.joined()))

    def test_firewall_proton(self):
        self.net.firewall_apply("192.168.1.10", 443, proton=True, proton_port=51234)
        self.assertEqual(self.fake.restores(), [RESTORE_PROTON])
        jumps = []
        for table, parent, chain in netmod.CHAINS:
            jumps += [IPT + "%s -C %s -j %s" % (table, parent, chain), IPT + "%s -I %s 1 -j %s" % (table, parent, chain)]
        # one atomic restore first, then only jump checks (no flush of a live chain)
        self.assertEqual(self.fake.joined(), ["iptables-restore -w 5 --noflush"] + jumps)

    def test_firewall_proxy_in_accepts_instead_of_dnat(self):
        # 0.30.0: PROXY protocol -> the agent listens on the tunnel ports itself
        text = self.net.firewall_rules("192.168.1.10", 443, True, [("wg0", [51234]), ("wg1", [40000])], proxy_in=True)
        self.assertNotIn("DNAT --to-destination", text)
        accept = "-A PF_IN -i wg0 -p tcp --dport 51234 -m conntrack --ctstate NEW -j ACCEPT"
        self.assertIn(accept, text)
        self.assertIn("-A PF_IN -i wg1 -p tcp --dport 40000 -m conntrack --ctstate NEW -j ACCEPT", text)
        self.assertLess(text.index(accept), text.index("-A PF_IN -i wg+ -j DROP"))
        plain = self.net.firewall_rules("192.168.1.10", 443, True, [("wg0", [51234])])
        self.assertIn("-A PF_PRE -i wg0 -p tcp --dport 51234 -j DNAT --to-destination 192.168.1.10:443", plain)
        self.assertNotIn("--ctstate NEW -j ACCEPT", plain)

    def test_firewall_plain_is_idempotent(self):
        self.fake.on(["iptables", "-w", "5", "-t"], 0, "")  # jumps exist already
        self.fake.responses = [r for r in self.fake.responses if r[0][-1] != "-C"]
        self.net.firewall_apply("192.168.1.10", 443, proton=False)
        calls = self.fake.joined()
        self.assertFalse(any(" -I " in c or " -F " in c for c in calls))
        text = self.fake.restores()[0]
        self.assertNotIn("-i wg0 -p tcp -j DNAT", text)
        self.assertIn("-A PF_OUT -o eth0 -j REJECT", text)  # also without VPN: nothing to the internet
        self.assertIn("-A PF_IN -i wg+ -j DROP", text)

    def test_firewall_egress_exceptions(self):
        text = netmod.Net.firewall_rules("192.168.1.10", 443, True, 51234,
                                         {"dns": ["9.9.9.9"], "endpoints": [("185.159.157.10", 51820)]})
        out = [line for line in text.splitlines() if line.startswith("-A PF_OUT")]
        self.assertIn("-A PF_OUT -o eth0 -d 9.9.9.9 -p udp --dport 53 -j ACCEPT", out)
        self.assertIn("-A PF_OUT -o eth0 -d 185.159.157.10 -p udp --dport 51820 -j ACCEPT", out)
        self.assertEqual(out[-1], "-A PF_OUT -o eth0 -j REJECT --reject-with icmp-net-prohibited")
        self.assertFalse(any("-o wg" in line for line in out))  # traffic through the tunnel is not limited
        with self.assertRaises(ValueError):
            netmod.Net.firewall_rules(None, None, out_allow={"dns": ["9.9.9.9 -j ACCEPT"]})

    def test_resolv_nameservers(self):
        path = os.path.join(self.tmp, "resolv.conf")
        with open(path, "w") as fh:
            fh.write("# x\nnameserver 127.0.0.11\nnameserver 192.168.1.1\nnameserver 9.9.9.9\nnameserver ::1\n")
        self.assertEqual(netmod.resolv_nameservers(path), ["192.168.1.1", "9.9.9.9"])

    def test_firewall_fixed_ports(self):
        text = netmod.Net.firewall_rules("192.168.1.10", 443, True, [43210, 43211])
        for port in (43210, 43211):
            self.assertIn("-A PF_PRE -i wg0 -p tcp --dport %d -j DNAT --to-destination 192.168.1.10:443" % port, text)
        self.assertEqual(text.count("DNAT --to-destination"), 2)
        with self.assertRaises(ValueError):
            netmod.Net.firewall_rules("192.168.1.10", 443, True, [443, 70000])

    def test_firewall_proton_without_port_has_no_wg0_dnat(self):
        text = netmod.Net.firewall_rules("192.168.1.10", 443, True)
        self.assertNotIn("-i wg0 -p tcp", text)
        self.assertNotIn("wg-mgmt", text)
        # without Proton a stale port is ignored
        self.assertNotIn("-i wg0 -p tcp", netmod.Net.firewall_rules("192.168.1.10", 443, False, 51234))
        for bad in (0.5, 70000, -1, True, "1 -j ACCEPT"):
            with self.assertRaises((ValueError, TypeError)):
                netmod.Net.firewall_rules("192.168.1.10", 443, True, bad)

    def test_firewall_has_no_lan_entry_rules(self):
        # 0.18.1: the LAN entry is a proxy (app.lanproxy), no DNAT/forward rule on eth0 any more
        text = netmod.Net.firewall_rules("192.168.1.10", 443, True, 51234)
        self.assertIn("-A PF_PRE -i wg0 -p tcp --dport 51234 -j DNAT --to-destination 192.168.1.10:443", text)
        self.assertNotIn("-i eth0 -d", text)
        self.assertNotIn("-i eth0 -o eth0", text)
        self.assertNotIn("ctorigdst", text)

    def test_routes_skip_connected_lan(self):
        routes = self.net.apply_routes(["172.18.0.0/16", "172.18.5.0/24", "192.168.1.0/24"], None)
        self.assertEqual(routes, ["192.168.1.0/24"])
        self.assertFalse(any("replace 172.18" in c or "del 172.18" in c for c in self.fake.joined()))

    def test_firewall_clear(self):
        self.fake.on(["iptables", "-w", "5", "-t", "nat", "-D"], 1, "")
        self.fake.on(["iptables", "-w", "5", "-t", "filter", "-D"], 1, "")
        self.fake.on(["iptables", "-w", "5", "-t", "mangle", "-D"], 1, "")
        self.net.firewall_clear()
        expected = []
        for table, parent, chain in netmod.CHAINS:
            expected += [IPT + "%s -D %s -j %s" % (table, parent, chain), IPT + "%s -F %s" % (table, chain),
                         IPT + "%s -X %s" % (table, chain)]
        self.assertEqual(self.fake.joined(), expected)


class AgentFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = base_responses(FakeRun())
        self.patches = [mock.patch("app.sysrun.run", self.fake),
                        mock.patch("app.probe.proton_public_ip", return_value="198.51.100.7"),
                        mock.patch("app.probe.natpmpc_available", return_value=True),
                        mock.patch("app.agent.Agent._poke_proton")]
        for p in self.patches:
            p.start()
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.net = netmod.Net(wg_dir=os.path.join(self.tmp, "wireguard"))
        self.lanproxy = FakeLanProxy()
        self.tunnelproxy = FakeTunnelProxy()
        self.agent = Agent(self.store, self.net, version="0.2.0", sleep=lambda s: None, lanproxy=self.lanproxy,
                           tunnelproxy=self.tunnelproxy)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def wg0_ready(self):
        """After `wg-quick up` the fake reports wg0 with a fresh handshake."""
        def up(args):
            base_responses(self.fake, wg0=True, handshake=int(time.time()))
            return ""
        self.fake.on(["wg-quick", "up", "wg0"], 0, up)

    def test_proton_setup_sequence(self):
        self.wg0_ready()
        res = self.agent.setup_proton({"enabled": True, "conf": PROTON_SAMPLE, "lan_nets": ["192.168.1.0/24"]},
                                      client_ip="192.168.1.50")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["test"]["exit_ip"], "198.51.100.7")
        self.assertEqual(res["test"]["endpoint"], "185.159.157.10:51820")
        self.assertEqual(res["summary"]["server"], "CH#12")
        calls = self.fake.joined()
        i_route = calls.index("ip -4 route replace 192.168.1.0/24 via 172.18.0.1 dev eth0")
        i_fw = calls.index("iptables-restore -w 5 --noflush")
        i_up = calls.index("wg-quick up wg0")
        self.assertLess(i_route, i_fw)
        self.assertLess(i_fw, i_up)
        self.assertNotIn("ip -4 route replace 192.168.1.50/32 via 172.18.0.1 dev eth0", calls)  # covered by LAN net
        with open(self.net.proton_conf_path) as fh:
            written = fh.read()
        self.assertNotIn("PostUp", written)
        self.assertNotIn("DNS", written)
        self.assertNotIn(PRIV, str(res))

    def test_fixed_port_provider_sequence(self):
        self.wg0_ready()
        self.store.update("backend", {"addr": "192.168.1.10:443"})
        with mock.patch("app.probe.wg_public_ip", return_value="203.0.113.44") as echo:
            res = self.agent.setup_proton({"enabled": True, "provider": "fixed", "ports": "43210, 43211",
                                           "conf": PROTON_SAMPLE, "lan_nets": ["192.168.1.0/24"]})
        self.assertTrue(res["ok"], res)
        echo.assert_called_with("wg0")
        self.assertEqual(res["test"]["exit_ip"], "203.0.113.44")
        self.assertFalse(res["test"]["natpmp"])
        self.assertEqual(self.agent.forward_ports(), [43210, 43211])
        self.assertEqual(self.agent.public_port(), 43210)
        self.assertEqual(self.agent.vpn_exit_ip(), "203.0.113.44")
        st = self.agent.status()
        self.assertEqual((st["proton"]["provider"], st["proton"]["port"]), ("fixed", 43210))
        self.assertEqual(st["light"]["checks"]["natpmp"], "ok")
        text = self.fake.restores()[-1]
        self.assertIn("--dport 43211 -j DNAT", text)
        self.agent.set_forward_port(51234)  # a stray NAT-PMP port never opens anything in fixed mode
        self.assertNotIn("51234", self.fake.restores()[-1])
        self.assertFalse(any(c.startswith("natpmpc") for c in self.fake.joined()))

    def test_proxy_protocol_toggle(self):
        self.wg0_ready()
        self.store.update("backend", {"addr": "192.168.1.10:443"})
        self.agent.setup_proton({"enabled": True, "conf": PROTON_SAMPLE, "lan_nets": ["192.168.1.0/24"]})
        self.agent.set_forward_port(51234)
        self.assertIn("--dport 51234 -j DNAT", self.fake.restores()[-1])
        self.assertEqual(self.tunnelproxy.listening(), [])
        self.assertFalse(self.lanproxy.proxy_protocol)
        self.assertEqual(self.agent.status()["proxy_protocol"], {"enabled": False, "tunnel": [], "errors": {}})
        with self.assertRaises(ValidationError):
            self.agent.set_proxy_protocol({"enabled": "yes"})
        res = self.agent.set_proxy_protocol({"enabled": True})
        self.assertTrue(res["ok"])
        text = self.fake.restores()[-1]
        self.assertNotIn("DNAT --to-destination", text)
        self.assertIn("-A PF_IN -i wg0 -p tcp --dport 51234 -m conntrack --ctstate NEW -j ACCEPT", text)
        self.assertEqual(self.tunnelproxy.listening(), [("wg0", 51234)])
        self.assertEqual(self.tunnelproxy.backend, ("192.168.1.10", 443))
        self.assertTrue(self.lanproxy.proxy_protocol)  # the LAN entry sends the header too
        self.assertEqual(res["proxy_protocol"]["tunnel"], ["wg0:51234"])
        self.agent.set_forward_port(40000)  # follows the port
        self.assertEqual(self.tunnelproxy.listening(), [("wg0", 40000)])
        self.agent.set_proxy_protocol({"enabled": False})
        self.assertIn("--dport 40000 -j DNAT", self.fake.restores()[-1])
        self.assertEqual(self.tunnelproxy.listening(), [])
        self.assertFalse(self.lanproxy.proxy_protocol)

    def test_lan_entry_follows_port_and_toggle(self):
        self.wg0_ready()
        self.store.update("backend", {"addr": "192.168.1.10:443"})
        self.agent.setup_proton({"enabled": True, "conf": PROTON_SAMPLE, "lan_nets": ["192.168.1.0/24"]})
        backend = ("192.168.1.10", 443)
        self.assertEqual(self.lanproxy.listening(), [])  # no NAT-PMP port yet: nothing open
        self.agent.set_forward_port(51234)
        self.assertEqual(self.lanproxy.listening(), [("172.18.0.2", 51234)])
        self.assertEqual(self.lanproxy.backend, backend)
        self.assertNotIn("-i eth0 -d", self.fake.restores()[-1])  # a proxy, never a DNAT rule on eth0
        self.agent.set_forward_port(40000)  # port change: old one closed, new one open
        self.assertEqual(self.lanproxy.listening(), [("172.18.0.2", 40000)])
        self.store.update("myaddr", {"name": "muster"})
        st = self.agent.status()["lan_entry"]
        self.assertEqual((st["enabled"], st["active"], st["ips"], st["ports"]), (True, True, ["172.18.0.2"], [40000]))
        self.assertEqual(st["urls"], ["https://<sub>.muster.myaddr.tools:40000"])
        self.assertEqual(st["errors"], {})
        self.lanproxy.errors = {"172.18.0.2:40000": "Address in use"}
        self.assertEqual(self.agent.status()["lan_entry"]["errors"], {"172.18.0.2:40000": "Address in use"})
        self.lanproxy.errors = {}
        res = self.agent.set_lan_entry({"enabled": False})
        self.assertFalse(res["lan_entry"]["active"])
        self.assertEqual(self.lanproxy.listening(), [])
        self.assertIn("-i wg0 -p tcp --dport 40000", self.fake.restores()[-1])
        self.agent.set_lan_entry({"enabled": True})
        self.assertEqual(self.lanproxy.listening(), [("172.18.0.2", 40000)])
        with self.assertRaises(Exception):
            self.agent.set_lan_entry({"enabled": "ja"})
        self.agent.set_forward_port(agentmod.UI_PORT)  # never shadows the WebUI on the LAN
        self.assertEqual(self.lanproxy.listening(), [])
        self.assertEqual(self.agent.status()["lan_entry"]["skipped"], [agentmod.UI_PORT])
        self.agent.setup_proton({"enabled": False})  # no VPN: no forwarded port, nothing open on the LAN either
        self.assertEqual(self.lanproxy.listening(), [])
        self.agent.teardown()
        self.assertIsNone(self.lanproxy.backend)

    def test_fixed_port_validation(self):
        for ports in (None, [], "abc", [0], [70000], list(range(1000, 1011))):
            with self.assertRaises(Exception):
                self.agent.setup_proton({"enabled": True, "provider": "fixed", "ports": ports,
                                         "conf": PROTON_SAMPLE, "lan_nets": ["192.168.1.0/24"]})
        with self.assertRaises(Exception):
            self.agent.setup_proton({"enabled": True, "provider": "other", "conf": PROTON_SAMPLE,
                                     "lan_nets": ["192.168.1.0/24"]})

    def test_fixed_exit_ip_refresh(self):
        now = [5000]
        self.agent.clock = lambda: now[0]
        self.store.update("proton", {"decided": True, "enabled": True, "conf": "[Interface]\n",
                                     "provider": "fixed", "ports": [43210]})
        base_responses(self.fake, wg0=True)
        answers = ["", "203.0.113.44", "203.0.113.45"]
        with mock.patch("app.probe.wg_public_ip", side_effect=lambda dev: answers.pop(0)) as echo:
            self.assertEqual(self.agent.refresh_exit_ip(), "")
            now[0] += agentmod.EXIT_RETRY
            self.assertEqual(self.agent.refresh_exit_ip(), "203.0.113.44")
            now[0] += agentmod.EXIT_CHECK - 1
            self.assertEqual(self.agent.refresh_exit_ip(), "203.0.113.44")
            now[0] += 1
            self.assertEqual(self.agent.refresh_exit_ip(), "203.0.113.45")
            self.assertEqual(echo.call_count, 3)
            base_responses(self.fake, wg0=False)
            self.assertEqual(self.agent.refresh_exit_ip(), "")
            self.assertEqual(echo.call_count, 3)
        self.assertEqual(self.agent.vpn_exit_ip(), "")

    def test_proton_defaults_to_all_private_nets(self):
        self.agent.setup_proton({"enabled": True, "conf": PROTON_SAMPLE})
        self.assertEqual(self.store.section("backend")["lan_nets"], ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        routes = [c for c in self.fake.calls if c[:3] == ["ip", "-4", "route"]]
        self.assertFalse(any(c[4] in ("10.0.0.0/8", "10.2.0.0/24", "10.2.0.0/16") for c in routes if len(c) > 4))
        self.assertTrue(any(c[4] == "10.0.0.0/15" for c in routes if len(c) > 4))

    def test_proton_no_handshake_keeps_config(self):
        self.fake.on(["wg-quick", "up", "wg0"], 0,
                     lambda a: base_responses(self.fake, wg0=True, handshake=0) and "")
        clock = iter(range(1000, 2000))
        self.agent.clock = lambda: next(clock)
        res = self.agent.setup_proton({"enabled": True, "conf": PROTON_SAMPLE, "lan_nets": ["192.168.1.0/24"]})
        self.assertFalse(res["ok"])
        self.assertIn("Handshake", res["test"]["error"])
        self.assertTrue(self.store.section("proton")["enabled"])
        self.assertTrue(self.store.section("proton")["profiles"][0]["conf"])

    def test_without_proton_and_teardown(self):
        self.agent.setup_proton({"enabled": False})
        with mock.patch("app.probe.backend_tls", return_value={"ok": True, "tcp": True, "tls": True,
                                                               "latency_ms": 3, "error": "", "checked": 1}):
            res = self.agent.setup_backend({"backend": "192.168.1.10:443", "lan_nets": ["192.168.1.0/24"]})
        self.assertTrue(res["ok"])
        self.assertEqual(self.agent.setup_state(), {"password": False, "proton": True, "backend": True, "done": False})
        self.assertEqual(self.agent.egress_device().kind, "internet")
        self.assertEqual(self.agent.lan_device().kind, "lan")
        eg = self.agent.egress
        self.assertIsNone(eg.device_for("npm.lan", "192.168.1.10", "lan"))
        with self.assertRaises(EgressBlocked):
            eg.device_for("myaddr.tools", "203.0.113.80", "internet")  # without VPN: never the home line
        self.assertFalse(any("wg-quick up" in c for c in self.fake.joined()))
        self.fake.calls.clear()
        self.agent.teardown()
        calls = self.fake.joined()
        self.assertFalse(any("172.18.0.0" in c for c in calls))
        self.assertEqual(calls[-1], "ip -4 route del 192.168.1.0/24 via 172.18.0.1 dev eth0")

    def test_egress_fails_closed_without_wg0(self):
        self.store.update("proton", {"decided": True, "enabled": True, "conf": "[Interface]\n"})
        eg = self.agent.egress
        for kind in ("internet", "lan"):  # wg0 absent: never fall back to eth0
            with self.assertRaises(EgressBlocked):
                eg.device_for("myaddr.tools", "203.0.113.80", kind)
        self.assertEqual(eg.device_for("npm", "192.168.1.10", "lan"), "eth0")
        self.assertEqual(eg.device_for("test", "192.168.77.4", "internet"), "eth0")
        self.assertFalse(eg.tunnel_up())
        base_responses(self.fake, wg0=True)
        self.assertEqual(eg.device_for("myaddr.tools", "203.0.113.80", "internet"), "wg0")
        self.assertEqual(eg.device_for("ntfy.sh", "203.0.113.81", "lan"), "wg0")
        self.assertEqual(eg.device_for("npm", "192.168.1.10", "lan"), "eth0")  # LAN never into the tunnel
        self.assertFalse(eg.tunnel_up())  # no handshake yet
        base_responses(self.fake, wg0=True, handshake=int(time.time()) - 10)
        self.agent.clock = time.time
        self.assertTrue(eg.tunnel_up())
        self.agent.failover.rt["all_down"] = 1
        self.assertFalse(eg.tunnel_up())


if __name__ == "__main__":
    unittest.main()


class SplitOutTest(unittest.TestCase):
    def test_lan_nets_leave_the_tunnel_net(self):
        from app.net import split_out
        n = ipaddress.IPv4Network
        out = split_out([n("10.0.0.0/8"), n("192.168.0.0/16")], [n("10.2.0.0/24"), n("10.2.0.1/32")])
        self.assertNotIn(True, [n("10.2.0.1/32").subnet_of(x) for x in out])
        self.assertIn(n("192.168.0.0/16"), out)
        self.assertTrue(any(n("10.1.0.0/16").subnet_of(x) for x in out))
        self.assertEqual(split_out([n("172.17.0.0/16")], [n("172.17.0.0/16")]), [])
