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
"""
import socket
import threading

from .log import log

LAN_IF = "eth0"
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
MAX_CONNS = 256  # relayed connections at once; more are refused until one ends
CONNECT_TIMEOUT = 5
CHUNK = 65536


def _bind_lan(sock, device):
    if device:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode())


class LanProxy:
    """Keeps one listener per (own eth0 IP, port) and relays to the current backend."""

    def __init__(self, device=LAN_IF, max_conns=MAX_CONNS):
        self.device = device
        self._lock = threading.Lock()
        self._listeners = {}  # (ip, port) -> socket
        self._backend = None  # (ip, port)
        self._slots = threading.BoundedSemaphore(max_conns)
        self.errors = {}  # "ip:port" -> last bind error

    def update(self, ips, ports, backend):
        """Listen on exactly ``ips`` x ``ports`` and relay to ``backend`` = ``(ip, port)``; empty: stop all."""
        wanted = {(str(ip), int(p)) for ip in ips or [] for p in ports or []} if backend else set()
        with self._lock:
            self._backend = (str(backend[0]), int(backend[1])) if backend else None
            for key in [k for k in self._listeners if k not in wanted]:
                self._close(key)
            names = {"%s:%d" % k for k in wanted}
            self.errors = {k: v for k, v in self.errors.items() if k in names}
            for key in sorted(wanted - set(self._listeners)):
                self._open(key)
        return sorted(self._listeners)

    def stop(self):
        self.update([], [], None)

    def listening(self):
        with self._lock:
            return sorted(self._listeners)

    def _open(self, key):
        ip, port = key
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _bind_lan(sock, self.device)
            sock.bind((ip, port))
            sock.listen(64)
        except OSError as err:
            sock.close()
            self.errors["%s:%d" % key] = str(err)[:120]
            log("lan entry: cannot listen on %s:%d: %s", ip, port, err)
            return
        self.errors.pop("%s:%d" % key, None)
        self._listeners[key] = sock
        threading.Thread(target=self._accept, args=(sock,), name="lan-entry-%d" % port, daemon=True).start()

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
            _bind_lan(upstream, self.device)
            upstream.settimeout(CONNECT_TIMEOUT)
            upstream.connect(backend)
            upstream.settimeout(None)
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
