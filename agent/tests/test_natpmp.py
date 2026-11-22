import os
import shutil
import tempfile
import unittest
from unittest import mock

from app import natpmp, net as netmod, sysrun
from app.agent import Agent, SetupError
from app.store import Store
from tests.fakes import FakeRun, base_responses

TCP = ["natpmpc", "-a", "1", "0", "tcp", "60", "-g", "10.2.0.1"]
UDP = ["natpmpc", "-a", "1", "0", "udp", "60", "-g", "10.2.0.1"]


def output(port, proto="TCP", ip="198.51.100.7"):
    return ("initnatpmp() returned 0 (SUCCESS)\nusing gateway : 10.2.0.1\n"
            "sendpublicaddressrequest returned 2 (SUCCESS)\nreadnatpmpresponseorretry returned 0 (OK)\n"
            "Public IP address : %s\nepoch = 58118\nsendnewportmappingrequest returned 12 (SUCCESS)\n"
            "readnatpmpresponseorretry returned 0 (OK)\n"
            "Mapped public port %d protocol %s to local port 0 liftime 60\nepoch = 58118\n"
            "closenatpmp() returned 0 (SUCCESS)\n" % (ip, port, proto))


FAIL = ("initnatpmp() returned 0 (SUCCESS)\nusing gateway : 10.2.0.1\n"
        "sendpublicaddressrequest returned 2 (SUCCESS)\n"
        "readnatpmpresponseorretry() failed : the gateway does not support nat-pmp\n"
        "  errno=111 'Connection refused'\n")


class RequestTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeRun()
        p = mock.patch("app.sysrun.run", self.fake)
        p.start()
        self.addCleanup(p.stop)

    def test_success(self):
        self.fake.on(TCP, 0, output(51234))
        self.assertEqual(natpmp.request("tcp"), {"public_ip": "198.51.100.7", "port": 51234, "protocol": "TCP",
                                                 "lifetime": 60})
        self.assertEqual(self.fake.calls, [TCP])

    def test_failure_output(self):
        self.fake.on(TCP, 1, FAIL)
        with self.assertRaises(natpmp.NatPmpError) as ctx:
            natpmp.request("tcp")
        self.assertIn("does not support nat-pmp", str(ctx.exception))

    def test_empty_output_and_tool_error(self):
        self.fake.on(TCP, 0, "")
        with self.assertRaises(natpmp.NatPmpError):
            natpmp.request("tcp")

        def boom(args, **kw):
            raise sysrun.SysRunError(args, -1, "timeout after 15s")
        with mock.patch("app.sysrun.run", boom):
            with self.assertRaises(natpmp.NatPmpError) as ctx:
                natpmp.request("udp")
        self.assertIn("timeout", str(ctx.exception))


class LoopTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = base_responses(FakeRun(), wg0=True, handshake=1763300000)
        self.port = [51234]
        self.honor = [False]  # Proton gives the wished port (natpmpc -a <port> 0) back

        def answer(a):
            port = int(a[2]) if self.honor[0] and a[2] != "1" else self.port[0]
            return output(port, a[4].upper()) if self.port[0] else FAIL
        self.fake.on(["natpmpc", "-a"], 0, answer)
        p = mock.patch("app.sysrun.run", self.fake)
        p.start()
        self.addCleanup(p.stop)
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.store.update("proton", {"decided": True, "enabled": True, "conf": "[Interface]\n"})
        self.store.update("backend", {"addr": "192.168.1.10:443", "lan_nets": ["192.168.1.0/24"]})
        self.agent = Agent(self.store, netmod.Net(wg_dir=os.path.join(self.tmp, "wg")), clock=lambda: 1763300100,
                           sleep=lambda s: None)
        self.agent.rt["net"]["applied"] = True
        self.reports = []
        self.agent.trigger_check = lambda: self.reports.append(1)
        self.loop = natpmp.NatPmp(self.agent, clock=lambda: 1763300100)
        self.agent.natpmp = self.loop

    def natpmp_calls(self):
        return [c for c in self.fake.calls if c[0] == "natpmpc"]

    def test_mapping_sets_port_dnat_and_report(self):
        st = self.loop.cycle()
        self.assertTrue(st["ok"])
        self.assertEqual((st["port"], st["exit_ip"], st["udp_port"]), (51234, "198.51.100.7", 51234))
        self.assertEqual(self.natpmp_calls(), [UDP, TCP])
        self.assertEqual(self.agent.forward_port, 51234)
        self.assertEqual(self.agent.rt["proton"]["exit_ip"], "198.51.100.7")
        restores = self.fake.restores()
        self.assertEqual(len(restores), 1)
        self.assertIn("-A PF_PRE -i wg0 -p tcp --dport 51234 -j DNAT --to-destination 192.168.1.10:443",
                      restores[0])
        self.assertEqual(len(self.reports), 1)
        status = self.agent.status()["proton"]
        self.assertEqual((status["port"], status["exit_ip"]), (51234, "198.51.100.7"))
        self.assertTrue(status["natpmp"]["ok"])

    def test_unchanged_port_does_not_reapply(self):
        self.loop.cycle()
        self.loop.cycle()
        self.assertEqual(len(self.fake.restores()), 1)
        self.assertEqual(len(self.reports), 1)
        self.assertEqual(len(self.natpmp_calls()), 4)

    def test_port_change_reapplies(self):
        self.loop.cycle()
        self.port[0] = 40000
        self.loop.cycle()
        restores = self.fake.restores()
        self.assertEqual(len(restores), 2)
        self.assertIn("--dport 40000", restores[1])
        self.assertNotIn("--dport 51234", restores[1])
        self.assertEqual(len(self.reports), 2)

    def test_failure_sets_port_zero_and_retries(self):
        self.loop.cycle()
        self.port[0] = 0
        st = self.loop.cycle()
        self.assertFalse(st["ok"])
        self.assertEqual((st["port"], st["fails"]), (0, 1))
        self.assertIn("does not support nat-pmp", st["error"])
        self.assertEqual(self.agent.forward_port, 0)
        self.assertNotIn("-i wg0 -p tcp", self.fake.restores()[-1])
        self.assertEqual(self.agent.status()["proton"]["port"], 0)
        self.port[0] = 51234
        st = self.loop.cycle()
        self.assertTrue(st["ok"])
        self.assertEqual((st["port"], st["fails"]), (51234, 0))

    def test_five_failures_rebuild_wg0(self):
        self.port[0] = 0
        with mock.patch.object(self.agent, "rebuild_proton") as rebuild:
            for _ in range(natpmp.MAX_FAILS - 1):
                self.loop.cycle()
            rebuild.assert_not_called()
            st = self.loop.cycle()
            rebuild.assert_called_once_with()
        self.assertEqual(st["fails"], 0)
        # no mapping ever: the firewall was never touched, no report needed
        self.assertEqual(self.fake.restores(), [])

    def test_restart_asks_for_last_port_of_the_profile(self):
        self.loop.cycle()
        self.assertEqual(self.loop._remembered(), {"p1": 51234})
        with open(os.path.join(self.tmp, "natpmp.json")) as fh:
            self.assertIn("51234", fh.read())
        # Watchtower restart: new loop, Proton would hand out 40000 but honours the wish
        self.port[0], self.honor[0] = 40000, True
        self.fake.calls.clear()
        loop = natpmp.NatPmp(self.agent, clock=lambda: 1763300200)
        st = loop.cycle()
        self.assertEqual(self.natpmp_calls()[0][:4], ["natpmpc", "-a", "51234", "0"])
        self.assertEqual((st["port"], st["wanted"]), (51234, 51234))
        # renewals keep asking for the current port
        loop.cycle()
        self.assertEqual(self.natpmp_calls()[-1][:4], ["natpmpc", "-a", "51234", "0"])

    def test_restart_with_another_port_proceeds(self):
        self.loop.cycle()
        self.port[0] = 40000  # Proton ignores the wish
        loop = natpmp.NatPmp(self.agent, clock=lambda: 1763300200)
        st = loop.cycle()
        self.assertEqual(st["port"], 40000)
        self.assertEqual(self.agent.forward_port, 40000)
        self.assertIn("--dport 40000", self.fake.restores()[-1])
        self.assertEqual(loop._remembered(), {"p1": 40000})

    def test_failing_wish_falls_back_to_any_port(self):
        self.loop.cycle()
        self.fake.on(["natpmpc", "-a", "51234"], 1, FAIL)
        self.port[0] = 40000
        loop = natpmp.NatPmp(self.agent, clock=lambda: 1763300200)
        st = loop.cycle()
        self.assertTrue(st["ok"])
        self.assertEqual(st["port"], 40000)
        self.assertEqual([c[2] for c in self.natpmp_calls()[-4:]], ["51234", "1", "51234", "1"])

    def test_other_profile_uses_its_own_last_port(self):
        self.loop.cycle()
        self.loop._remember("p2", 45555)
        self.loop.state["profile"] = "p0"  # wg0 now runs another profile than the one of the current port
        self.fake.calls.clear()
        self.loop.cycle()
        self.assertEqual(self.natpmp_calls()[0][2], "51234")  # p1 is still active: its remembered port
        self.assertEqual(self.loop._remembered(), {"p1": 51234, "p2": 45555})

    def test_tcp_ok_udp_failing_still_maps(self):
        self.fake.on(UDP, 1, FAIL)
        st = self.loop.cycle()
        self.assertTrue(st["ok"])
        self.assertEqual((st["port"], st["udp_port"]), (51234, 0))

    def test_idle_without_proton_or_wg0(self):
        self.loop.cycle()
        base_responses(self.fake, wg0=False)
        st = self.loop.cycle()
        self.assertFalse(st["active"])
        self.assertEqual((st["port"], st["exit_ip"]), (0, ""))
        self.assertEqual(self.agent.forward_port, 0)
        self.assertEqual(len(self.natpmp_calls()), 2)  # only the first cycle asked natpmpc
        self.store.update("proton", {"enabled": False})
        self.fake.calls.clear()
        self.loop.cycle()
        self.assertEqual(self.natpmp_calls(), [])

    def test_renew_action(self):
        res = self.agent.action("natpmp-renew")
        self.assertTrue(res["ok"])
        self.assertEqual(res["port"], 51234)
        self.store.update("proton", {"enabled": False})
        with self.assertRaises(SetupError):
            self.agent.action("natpmp-renew")

    def test_run_loop_waits_interval_and_stops(self):
        waits = []
        loop = natpmp.NatPmp(self.agent, interval=45, clock=lambda: 0)

        class Wake:
            def wait(self, timeout):
                waits.append(timeout)
                if len(waits) == 3:
                    loop._halt.set()

            def clear(self):
                pass

            def set(self):
                pass
        loop._wake = Wake()
        cycles = []

        def cycle():
            cycles.append(1)
            if len(cycles) == 1:
                raise RuntimeError("boom")
        loop.cycle = cycle
        loop.run()  # synchronous; an exception in one cycle does not end the loop
        self.assertEqual(waits, [45, 45, 45])
        self.assertEqual(len(cycles), 3)


    def test_ddns_uses_exit_ip(self):
        self.loop.cycle()
        sent = []
        self.agent.store.update("myaddr", {"name": "familie-muster", "domain": "myaddr.tools", "key": "k" * 43,
                                           "ddns": True})
        self.agent.ddns.send = lambda key, ip=None, device=None: sent.append((ip, device.kind))
        self.agent.egress.tunnel_up = lambda: True
        self.assertTrue(self.agent.ddns.tick()["ok"])
        self.assertEqual(sent, [("198.51.100.7", "internet")])

if __name__ == "__main__":
    unittest.main()
