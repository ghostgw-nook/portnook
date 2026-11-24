"""0.37.0: new connections per tunnel (firewall counters) and CPU."""
import unittest

from app import usage


class FakeSb:
    def __init__(self, pid, iface):
        self.state = {"profile": pid, "iface": iface}


class FakeAgent:
    def __init__(self):
        self.active_if = "wg0"
        self.standbys = [FakeSb("p2", "wg1"), FakeSb("", "")]
        self.tunnelproxy = None

    def active_profile(self):
        return {"id": "p1"}

    def _proton_on(self):
        return True


NAT = """Chain PF_PRE (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       3      180 DNAT       6    --  wg0    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:51234 to:192.168.1.10:443
       2      120 DNAT       6    --  wg1    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:40000 to:192.168.1.10:443
"""
FILTER = """Chain PF_IN (1 references)
    pkts      bytes target     prot opt in     out     source               destination
     900    50000 ACCEPT     0    --  wg+    *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
       4      240 ACCEPT     6    --  wg2    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:42000 ctstate NEW
      10      600 DROP       0    --  wg+    *       0.0.0.0/0            0.0.0.0/0
"""


class R:
    def __init__(self, out):
        self.stdout = out


class UsageTest(unittest.TestCase):
    def test_parse_counters(self):
        run = lambda args, check=True: R(NAT if "nat" in args else FILTER)
        self.assertEqual(usage.read_counters(run), {("wg0", 51234): 3, ("wg1", 40000): 2, ("wg2", 42000): 4})

    def test_totals_survive_refilled_rules_and_cpu(self):
        now, counts = [1000.0], [{("wg0", 51234): 3, ("wg1", 40000): 2}]
        cpu = [(100, 1000), 5_000_000]
        u = usage.Usage(FakeAgent(), clock=lambda: now[0], counters=lambda: counts[0], host=lambda: cpu[0],
                        own=lambda: cpu[1])
        u.sample()
        now[0] += 10
        counts[0] = {("wg0", 51234): 1, ("wg1", 40000): 7}  # wg0 rules refilled (counter restarted)
        cpu[:] = [(300, 2000), 6_000_000]
        st = u.status()
        self.assertEqual(st["connections"]["p1"]["total"], 4)
        self.assertEqual(st["connections"]["p2"]["total"], 7)
        self.assertEqual(st["cpu"]["host"], 20.0)  # 200 busy of 1000
        self.assertEqual(st["cpu"]["own"], 10.0)  # 1 s CPU in 10 s
        now[0] += usage.WINDOW + 1
        self.assertEqual(u.status()["connections"]["p1"]["recent"], 0)
        self.assertEqual(u.status()["connections"]["p1"]["total"], 4)


if __name__ == "__main__":
    unittest.main()
