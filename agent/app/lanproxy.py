"""LAN entry as a TCP proxy (0.18.1).

Up to 0.18.0 the LAN entry was a DNAT rule on ``eth0``. That never fires when the container sits on an
ipvlan network whose parent is a Linux bridge with ``bridge-nf-call-iptables=1`` (Unraid ``br0``): the host
already tracks the client's SYN while it crosses the bridge, gives it a null NAT binding, and the packet
reaches the container with that conntrack entry attached, so the container's ``nat PREROUTING`` is skipped
and the kernel refuses the connection. A proxy in user space does not depend on conntrack at all.

The agent listens on its own ``eth0`` address(es) on the current forwarded port(s) and relays every
connection to the backend. Both sockets are bound to ``eth0`` (``SO_BINDTODEVICE``), so neither the replies
to the client nor the connection to the backend can ever go through ``wg0``. The backend sees the agent as
the sender, as it does for connections through the tunnel.

0.30.0, PROXY protocol (opt-in): the reverse proxy only ever sees the agent as sender. With
``proxy_protocol`` on, every relayed connection starts with a PROXY protocol v2 header that carries the
client's real address (nginx ``listen ... proxy_protocol``, Zoraxy "PROXY Protocol"). ``TunnelProxy`` does the
same for the forwarded ports on the tunnels: it listens on ``wg0``/``wg1`` itself (instead of the DNAT rule),
so the client address is known in user space; replies leave through the tunnel the socket is bound to.
"""
import ipaddress
import socket
import struct
import threading

from .log import log

LAN_IF = "eth0"
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
MAX_CONNS = 256  # relayed connections at once; more are refused until one ends
CONNECT_TIMEOUT = 5
CHUNK = 65536
PP2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def proxy_v2_header(src, dst):
    """PROXY protocol v2 header (command PROXY, TCP over IPv4) for ``src`` = client ``(ip, port)`` and ``dst`` =
    the address the client connected to. Not IPv4 (should not happen): command LOCAL, the receiver then uses
    the connection's own addresses."""
    try:
        s_ip, d_ip = ipaddress.IPv4Address(src[0]), ipaddress.IPv4Address(dst[0])
    except (ValueError, IndexError, TypeError):
        return PP2_SIGNATURE + b"\x20\x00\x00\x00"
    body = s_ip.packed + d_ip.packed + struct.pack("!HH", int(src[1]), int(dst[1]))
    return PP2_SIGNATURE + b"\x21\x11" + struct.pack("!H", len(body)) + body


def _bind_lan(sock, device):
    if device:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode())


class _Relay:
    """Keeps one listener per ``(device, ip, port)`` and relays every connection to the current backend."""

    what = "relay"

    def __init__(self, upstream_device=LAN_IF, max_conns=MAX_CONNS):
        self.upstream_device = upstream_device
        self._lock = threading.Lock()
        self._listeners = {}  # (device, ip, port) -> socket
        self._backend = None  # (ip, port)
        self._slots = threading.BoundedSemaphore(max_conns)
        self.proxy_protocol = False
        self.bind_devices = True  # tests on loopback: False
        self.errors = {}  # name of the listener -> last bind error

    @staticmethod
    def _name(key):
        return "%s:%d" % (key[1], key[2])

    def _sync(self, wanted, backend, proxy_protocol):
        with self._lock:
            self._backend = (str(backend[0]), int(backend[1])) if backend else None
            self.proxy_protocol = bool(proxy_protocol)
            for key in [k for k in self._listeners if k not in wanted]:
                self._close(key)
            names = {self._name(k) for k in wanted}
            self.errors = {k: v for k, v in self.errors.items() if k in names}
            for key in sorted(wanted - set(self._listeners), key=lambda k: (k[0] or "", k[1], k[2])):
                self._open(key)

    def _open(self, key):
        device, ip, port = key
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _bind_lan(sock, device if self.bind_devices else None)
            sock.bind((ip, port))
            sock.listen(64)
        except OSError as err:
            sock.close()
            self.errors[self._name(key)] = str(err)[:120]
            log("%s: cannot listen on %s: %s", self.what, self._name(key), err)
            return
        self.errors.pop(self._name(key), None)
        self._listeners[key] = sock
        threading.Thread(target=self._accept, args=(sock,), name="%s-%d" % (self.what, port), daemon=True).start()

    def _close(self, key):
        sock = self._listeners.pop(key)
        try:
            sock.shutdown(socket.SHUT_RDWR)  # wakes the accept() of its thread
        except OSError:
            pass
        sock.close()

    def _accept(self, lsock):
        while True:
            try:
                client, _ = lsock.accept()
            except OSError:
                return  # listener closed
            if not self._slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=self._relay, args=(client,), daemon=True).start()

    def _relay(self, client):
        upstream = None
        try:
            backend = self._backend
            if not backend:
                return
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _bind_lan(upstream, self.upstream_device)
            upstream.settimeout(CONNECT_TIMEOUT)
            upstream.connect(backend)
            upstream.settimeout(None)
            if self.proxy_protocol:
                upstream.sendall(proxy_v2_header(client.getpeername(), client.getsockname()))
            for s in (client, upstream):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            back = threading.Thread(target=_pump, args=(upstream, client), daemon=True)
            back.start()
            _pump(client, upstream)
            back.join()
        except OSError:
            pass
        finally:
            for s in (client, upstream):
                if s is not None:
                    s.close()
            self._slots.release()


class LanProxy(_Relay):
    """LAN entry: listeners on the own eth0 address(es), both sockets bound to eth0."""

    what = "lan entry"

    def __init__(self, device=LAN_IF, max_conns=MAX_CONNS):
        super().__init__(upstream_device=device, max_conns=max_conns)
        self.device = device

    def update(self, ips, ports, backend, proxy_protocol=False):
        """Listen on exactly ``ips`` x ``ports`` and relay to ``backend`` = ``(ip, port)``; empty: stop all."""
        wanted = {(self.device, str(ip), int(p)) for ip in ips or [] for p in ports or []} if backend else set()
        self._sync(wanted, backend, proxy_protocol)
        return self.listening()

    def stop(self):
        self.update([], [], None)

    def listening(self):
        with self._lock:
            return sorted((k[1], k[2]) for k in self._listeners)


class TunnelProxy(_Relay):
    """0.30.0: the forwarded ports on the tunnels (instead of DNAT) while the PROXY protocol is on. Listens on
    ``0.0.0.0:<port>`` bound to the tunnel (``SO_BINDTODEVICE``: replies use that tunnel's routing table),
    relays to the backend through eth0. ``bind_any`` is the address to listen on (tests: 127.0.0.1)."""

    what = "tunnel entry"

    def __init__(self, upstream_device=LAN_IF, max_conns=MAX_CONNS, bind_any="0.0.0.0", bind_devices=True):
        super().__init__(upstream_device=upstream_device, max_conns=max_conns)
        self.bind_any = bind_any
        self.bind_devices = bind_devices

    @staticmethod
    def _name(key):
        return "%s:%d" % (key[0] or key[1], key[2])

    def update(self, tunnels, backend):
        """``tunnels`` = ``[(iface, [port, ...])]``; always with the PROXY protocol header; empty: stop all."""
        wanted = {(iface, self.bind_any, int(p)) for iface, ports in tunnels or [] for p in ports or [] if p} \
            if backend else set()
        self._sync(wanted, backend, True)
        return self.listening()

    def stop(self):
        self.update([], None)

    def listening(self):
        with self._lock:
            return sorted((k[0], k[2]) for k in self._listeners)


def _pump(src, dst):
    """Copy ``src`` to ``dst`` until EOF, then half-close ``dst`` so the other direction can finish."""
    buf = bytearray(CHUNK)
    view = memoryview(buf)
    try:
        while True:
            n = src.recv_into(buf)
            if not n:
                break
            dst.sendall(view[:n])
    except OSError:
        pass
    for s, how in ((dst, socket.SHUT_WR), (src, socket.SHUT_RD)):
        try:
            s.shutdown(how)
        except OSError:
            pass
