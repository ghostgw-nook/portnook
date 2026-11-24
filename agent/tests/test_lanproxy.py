import socket
import threading
import time
import unittest

import struct
from unittest import mock

from app.lanproxy import PP2_SIGNATURE, LanProxy, TunnelProxy, proxy_v2_header


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EchoServer:
    """Backend stand-in: answers every connection with b'<prefix>' + what it received, then closes."""

    def __init__(self, prefix=b"A:"):
        self.prefix = prefix
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(self.prefix + data)

    def close(self):
        self.sock.close()


def roundtrip(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
        c.sendall(payload)
        c.shutdown(socket.SHUT_WR)  # half-close: the answer still comes back
        out = b""
        while True:
            chunk = c.recv(65536)
            if not chunk:
                return out
            out += chunk


class LanProxyTest(unittest.TestCase):
    def setUp(self):
        self.proxy = LanProxy(device=None)  # no SO_BINDTODEVICE on loopback in tests
        self.addCleanup(self.proxy.stop)

    def test_relays_both_ways_with_half_close(self):
        backend = EchoServer()
        self.addCleanup(backend.close)
        port = free_port()
        self.assertEqual(self.proxy.update(["127.0.0.1"], [port], ("127.0.0.1", backend.port)),
                         [("127.0.0.1", port)])
        payload = bytes(range(256)) * 4096  # 1 MiB
        self.assertEqual(roundtrip(port, payload), b"A:" + payload)

    def test_follows_port_and_backend(self):
        a, b = EchoServer(b"A:"), EchoServer(b"B:")
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        p1, p2 = free_port(), free_port()
        self.proxy.update(["127.0.0.1"], [p1], ("127.0.0.1", a.port))
        self.assertEqual(roundtrip(p1, b"x"), b"A:x")
        self.proxy.update(["127.0.0.1"], [p2], ("127.0.0.1", b.port))  # port change and another backend
        self.assertEqual(self.proxy.listening(), [("127.0.0.1", p2)])
        self.assertEqual(roundtrip(p2, b"y"), b"B:y")
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", p1), timeout=2).close()  # old port closed

    def test_off_without_backend_or_ports(self):
        port = free_port()
        self.proxy.update(["127.0.0.1"], [port], None)
        self.assertEqual(self.proxy.listening(), [])
        self.proxy.update(["127.0.0.1"], [], ("127.0.0.1", 1))
        self.assertEqual(self.proxy.listening(), [])

    def test_bind_error_is_reported_not_raised(self):
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        self.addCleanup(busy.close)
        port = busy.getsockname()[1]
        self.assertEqual(self.proxy.update(["127.0.0.1"], [port], ("127.0.0.1", 1)), [])
        self.assertIn("127.0.0.1:%d" % port, self.proxy.errors)
        self.proxy.stop()
        self.assertEqual(self.proxy.errors, {})

    def test_backend_down_closes_client(self):
        port = free_port()
        self.proxy.update(["127.0.0.1"], [port], ("127.0.0.1", free_port()))
        start = time.time()
        try:
            self.assertEqual(roundtrip(port, b"x"), b"")
        except OSError:
            pass  # closed before or with the request unread (reset, not connected): as good as an empty answer
        self.assertLess(time.time() - start, 5)


def parse_v2(data):
    """(src, dst, rest) of a PROXY v2 PROXY/TCP4 header at the start of ``data``."""
    assert data.startswith(PP2_SIGNATURE), data[:16]
    ver_cmd, fam, length = data[12], data[13], struct.unpack("!H", data[14:16])[0]
    assert (ver_cmd, fam, length) == (0x21, 0x11, 12)
    body = data[16:28]
    src = (".".join(map(str, body[0:4])), struct.unpack("!H", body[8:10])[0])
    dst = (".".join(map(str, body[4:8])), struct.unpack("!H", body[10:12])[0])
    return src, dst, data[28:]


class ProxyHeaderTest(unittest.TestCase):
    def test_v2_tcp4(self):
        h = proxy_v2_header(("203.0.113.9", 51000), ("10.2.0.2", 41763))
        self.assertEqual(len(h), 28)
        self.assertEqual(parse_v2(h + b"x"), (("203.0.113.9", 51000), ("10.2.0.2", 41763), b"x"))

    def test_not_ipv4_is_local(self):
        self.assertEqual(proxy_v2_header(("::1", 1, 0, 0), ("::1", 2, 0, 0)), PP2_SIGNATURE + b"\x20\x00\x00\x00")


class ProxyProtocolRelayTest(unittest.TestCase):
    def test_lan_entry_sends_header_when_on(self):
        proxy = LanProxy(device=None)
        self.addCleanup(proxy.stop)
        backend = EchoServer(b"")
        self.addCleanup(backend.close)
        port = free_port()
        proxy.update(["127.0.0.1"], [port], ("127.0.0.1", backend.port), proxy_protocol=True)
        src, dst, rest = parse_v2(roundtrip(port, b"hello"))
        self.assertEqual((src[0], dst), ("127.0.0.1", ("127.0.0.1", port)))
        self.assertNotEqual(src[1], port)
        self.assertEqual(rest, b"hello")
        proxy.update(["127.0.0.1"], [port], ("127.0.0.1", backend.port), proxy_protocol=False)
        self.assertEqual(roundtrip(port, b"plain"), b"plain")

    def test_tunnel_proxy_always_sends_header(self):
        proxy = TunnelProxy(upstream_device=None, bind_any="127.0.0.1", bind_devices=False)
        self.addCleanup(proxy.stop)
        backend = EchoServer(b"")
        self.addCleanup(backend.close)
        p0, p1 = free_port(), free_port()
        self.assertEqual(proxy.update([("wg0", [p0]), ("wg1", [p1])], ("127.0.0.1", backend.port)),
                         [("wg0", p0), ("wg1", p1)])
        for port in (p0, p1):
            src, dst, rest = parse_v2(roundtrip(port, b"x" * 70000))
            self.assertEqual(dst, ("127.0.0.1", port))
            self.assertEqual(rest, b"x" * 70000)
        proxy.update([("wg0", [p0])], ("127.0.0.1", backend.port))  # standby gone: its port closed
        self.assertEqual(proxy.listening(), [("wg0", p0)])
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", p1), timeout=2).close()
        proxy.stop()
        self.assertEqual(proxy.listening(), [])

    def test_rebuilt_tunnel_gets_a_new_listener(self):
        """0.36.1: a rebuilt wg0 has a new interface index; the listener bound to the old one is opened anew."""
        index = {"wg0": 7}
        proxy = TunnelProxy(upstream_device=None, bind_any="127.0.0.1")
        self.addCleanup(proxy.stop)
        backend = EchoServer(b"")
        self.addCleanup(backend.close)
        port = free_port()
        with mock.patch("app.lanproxy._bind_lan"), \
                mock.patch("app.lanproxy.socket.if_nametoindex", side_effect=lambda n: index[n]):
            proxy.update([("wg0", [port])], ("127.0.0.1", backend.port))
            first = proxy._listeners[("wg0", "127.0.0.1", port)]
            proxy.update([("wg0", [port])], ("127.0.0.1", backend.port))
            self.assertIs(proxy._listeners[("wg0", "127.0.0.1", port)], first)  # same tunnel: kept
            index["wg0"] = 9  # tunnel_down + tunnel_up
            proxy.update([("wg0", [port])], ("127.0.0.1", backend.port))
            self.assertIsNot(proxy._listeners[("wg0", "127.0.0.1", port)], first)
            self.assertEqual(first.fileno(), -1)
        self.assertEqual(parse_v2(roundtrip(port, b"hi"))[2], b"hi")


if __name__ == "__main__":
    unittest.main()
