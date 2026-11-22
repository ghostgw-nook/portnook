"""Throughput test through one VPN tunnel (0.28.0, owner: "see how full the line is").

Download and upload against Cloudflare's speed test endpoints (``speed.cloudflare.com/__down`` and ``/__up``),
with every socket bound to the tunnel interface (``SO_BINDTODEVICE``), so Cloudflare only sees the VPN exit IP and
nothing goes through the home line. Several connections run at once for a few seconds each, like a browser speed
test; the result is in bit/s. It measures the path from the VPN exit to Cloudflare, not to a visitor, which is good
enough to compare profiles. While it runs the tunnel is busy (a stream may stutter briefly).
"""
import socket
import ssl
import threading
import time

HOST = "speed.cloudflare.com"
SECONDS = 6          # per direction
STREAMS = 4          # parallel connections
DOWN_BYTES = 50 * 1000 * 1000   # per download request; the server answers 403 above about 50-100 MB
UP_BYTES = 100 * 1000 * 1000    # per upload body; requests repeat until the time is up
CHUNK = 256 * 1024
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


class SpeedError(Exception):
    """Test not possible (no tunnel, DNS, connect); message safe for the UI."""


def _connect(ip, iface, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
        sock.settimeout(timeout)
        sock.connect((ip, 443))
        return ssl.create_default_context().wrap_socket(sock, server_hostname=HOST)
    except Exception:
        sock.close()
        raise


def _head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise SpeedError("Verbindung vorzeitig beendet")
        data += chunk
        if len(data) > 65536:
            raise SpeedError("ungültige Antwort")
    head, rest = data.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or not status[1].startswith(b"2"):
        raise SpeedError("Speedtest-Server antwortete %s" % status[1].decode("ascii", "replace") if len(status) > 1 else "?")
    return rest


def _download(ip, iface, deadline, counter, errors, clock):
    buf = bytearray(CHUNK)
    view = memoryview(buf)
    try:
        while clock() < deadline:
            sock = _connect(ip, iface, 10)
            try:
                sock.sendall(("GET /__down?bytes=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: portnook\r\n"
                              "Connection: close\r\n\r\n" % (DOWN_BYTES, HOST)).encode())
                counter.add(len(_head(sock)))
                while clock() < deadline:
                    n = sock.recv_into(view)
                    if not n:
                        break
                    counter.add(n)
            finally:
                sock.close()
    except (OSError, SpeedError) as err:
        errors.append(err)


def _upload(ip, iface, deadline, counter, errors, clock):
    block = b"\0" * CHUNK
    try:
        while clock() < deadline:
            sock = _connect(ip, iface, 10)
            try:
                sock.sendall(("POST /__up HTTP/1.1\r\nHost: %s\r\nUser-Agent: portnook\r\nContent-Type: "
                              "application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                              % (HOST, UP_BYTES)).encode())
                sent = 0
                while sent < UP_BYTES and clock() < deadline:
                    part = block[:min(CHUNK, UP_BYTES - sent)]
                    sock.sendall(part)
                    sent += len(part)
                    counter.add(len(part))
            finally:
                sock.close()
    except (OSError, SpeedError) as err:
        errors.append(err)


class _Counter:
    def __init__(self):
        self.n = 0
        self.lock = threading.Lock()

    def add(self, n):
        with self.lock:
            self.n += n


def _phase(fn, ip, iface, seconds, streams, clock):
    counter, errors = _Counter(), []
    start = clock()
    deadline = start + seconds
    threads = [threading.Thread(target=fn, args=(ip, iface, deadline, counter, errors, clock), daemon=True)
               for _ in range(streams)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(seconds + 15)
    elapsed = max(clock() - start, 0.001)
    if not counter.n and errors:
        raise SpeedError(str(errors[0])[:160] or errors[0].__class__.__name__)
    return int(counter.n * 8 / elapsed)


def run(iface, resolve, seconds=SECONDS, streams=STREAMS, clock=time.monotonic):
    """``{"down": bit/s, "up": bit/s}`` through ``iface``. ``resolve(host)`` -> list of IPv4 addresses."""
    ips = resolve(HOST)
    if not ips:
        raise SpeedError("%s nicht auflösbar" % HOST)
    down = _phase(_download, ips[0], iface, seconds, streams, clock)
    up = _phase(_upload, ips[0], iface, seconds, streams, clock)
    return {"down": down, "up": up}
