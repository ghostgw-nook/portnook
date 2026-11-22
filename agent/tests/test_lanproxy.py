import socket
import threading
import time
import unittest

from app.lanproxy import LanProxy


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


if __name__ == "__main__":
    unittest.main()
