import unittest

from app import parsers
from tests.fakes import EDGE_PUB, MGMT_PRIV, MGMT_PUB, PSK


class WgDumpTest(unittest.TestCase):
    def test_dump(self):
        text = ("%s\t%s\t40000\toff\n"
                "%s\t%s\t203.0.113.10:51820\t10.99.0.0/24\t1763300000\t1234\t5678\t25\n"
                "%s\t(none)\t(none)\t(none)\t0\t0\t0\toff\n") % (MGMT_PRIV, MGMT_PUB, EDGE_PUB, PSK, MGMT_PUB)
        d = parsers.wg_dump(text)
        self.assertEqual(d["public_key"], MGMT_PUB)
        self.assertEqual(d["listen_port"], 40000)
        self.assertEqual(d["peers"][0], {"public_key": EDGE_PUB, "endpoint": "203.0.113.10:51820",
                                         "allowed_ips": ["10.99.0.0/24"], "handshake": 1763300000,
                                         "rx": 1234, "tx": 5678, "keepalive": 25})
        self.assertEqual(d["peers"][1]["endpoint"], "")
        self.assertEqual(d["peers"][1]["keepalive"], 0)
        self.assertNotIn(MGMT_PRIV, str(d))
        self.assertNotIn(PSK, str(d))

    def test_empty(self):
        self.assertEqual(parsers.wg_dump(""), {"public_key": "", "listen_port": 0, "peers": []})


class NatpmpcTest(unittest.TestCase):
    SAMPLE = """initnatpmp() returned 0 (SUCCESS)
using gateway : 10.2.0.1
sendpublicaddressrequest returned 2 (SUCCESS)
readnatpmpresponseorretry returned 0 (OK)
Public IP address : 198.51.100.7
epoch = 58118
sendnewportmappingrequest returned 12 (SUCCESS)
readnatpmpresponseorretry returned 0 (OK)
Mapped public port 51234 protocol TCP to local port 0 liftime 60
epoch = 58118
closenatpmp() returned 0 (SUCCESS)
"""

    def test_full(self):
        self.assertEqual(parsers.natpmpc(self.SAMPLE),
                         {"public_ip": "198.51.100.7", "port": 51234, "protocol": "TCP", "lifetime": 60})

    def test_public_ip_only_and_failure(self):
        self.assertEqual(parsers.natpmpc("Public IP address : 198.51.100.7\n")["port"], 0)
        bad = parsers.natpmpc("readnatpmpresponseorretry() failed : the gateway does not support nat-pmp\n")
        self.assertEqual(bad["public_ip"], "")
        self.assertEqual(parsers.natpmpc("Public IP address : 999.1.1.1")["public_ip"], "")
        self.assertEqual(parsers.natpmpc("Mapped public port 1 protocol UDP to local port 0 lifetime 60")["lifetime"], 60)


class RouteTest(unittest.TestCase):
    def test_default_gateway(self):
        text = "default dev wg0 table 51820 scope link\ndefault via 172.18.0.1 dev eth0 \n"
        self.assertEqual(parsers.default_gateway(text), "172.18.0.1")
        self.assertEqual(parsers.default_gateway("default dev wg0 scope link\n"), "")

    def test_interface_networks(self):
        text = "12: eth0    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0\\       valid_lft forever\n"
        self.assertEqual([str(n) for n in parsers.interface_networks(text)], ["172.18.0.0/16"])


if __name__ == "__main__":
    unittest.main()
