"""Small HTTP(S) client on ``http.client`` for myaddr.tools, ACME, NPM and similar.

* ``device``: the socket is bound to this interface (``SO_BINDTODEVICE``) before
  connecting. ``wg0`` makes a request fail instead of leaving through ``eth0``
  when the Proton tunnel is down; ``eth0`` keeps LAN requests out of the tunnel.
  ``device`` may also be a route policy (``app.egress.Route``): called with the host
  and each resolved address, it returns the interface or raises ``EgressBlocked``
  (no VPN tunnel: nothing to the internet, 0.10.1). A ``(interface, mark)`` tuple also sets ``SO_MARK``
  (push servers on the internet go straight through ``eth0``, 0.18.0; the firewall lets only this mark out).
* IPv4 only (the container has IPv6 off), certificates are verified (system CA
  store or ``cafile``), responses are size limited.
* Error messages never contain request bodies or headers (keys, tokens).
"""

import http.client
import json
import socket
import ssl
import urllib.parse

MAX_RESPONSE = 2 * 1024 * 1024
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
SO_MARK = getattr(socket, "SO_MARK", 36)


class HttpError(Exception):
    """Transport problem (DNS, connect, TLS, timeout, oversized answer)."""


class EgressBlocked(HttpError):
    """Refused before connecting: internet destination while no VPN tunnel is up (0.10.1)."""


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers  # lower-case names
        self.body = body

    def header(self, name, default=""):
        return self.headers.get(name.lower(), default)

    def text(self, limit=None):
        out = self.body.decode("utf-8", "replace")
        return out[:limit] if limit else out

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8")) if self.body else {}
        except (ValueError, UnicodeDecodeError):
            return None


def _connector(device):
    def create_connection(address, timeout=None, source_address=None):
        host, port = address
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        except (OSError, UnicodeError) as err:
            raise HttpError("%s nicht auflösbar (%s)" % (host, err.__class__.__name__))
        last = None
        for family, stype, proto, _, addr in infos:
            dev = device(host, addr[0]) if callable(device) else device  # EgressBlocked passes through
            sock = socket.socket(family, stype, proto)
            try:
                if isinstance(dev, tuple):
                    dev, mark = dev
                    sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
                if dev:
                    sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, dev.encode())
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect(addr)
                return sock
            except OSError as err:
                last = err
                sock.close()
        raise HttpError("Verbindung zu %s:%s fehlgeschlagen: %s" % (host, port, getattr(last, "strerror", None) or last))
    return create_connection


def split_url(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HttpError("ungültige URL")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.scheme, parts.hostname, parts.port, path


def request(method, url, body=None, headers=None, device=None, cafile=None, timeout=20, max_bytes=MAX_RESPONSE):
    """One request; returns ``Response``. ``body``: bytes, str, or dict (sent as JSON)."""
    scheme, host, port, path = split_url(url)
    hdrs = {"User-Agent": "portnook", "Accept": "*/*", "Connection": "close"}
    hdrs.update(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode("utf-8")
    if scheme == "https":
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port or 443, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port or 80, timeout=timeout)
    conn._create_connection = _connector(device)
    try:
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise HttpError("Antwort von %s zu gross" % host)
        return Response(resp.status, {k.lower(): v for k, v in resp.getheaders()}, data)
    except HttpError:
        raise
    except ssl.SSLError as err:
        raise HttpError("TLS-Fehler mit %s: %s" % (host, getattr(err, "reason", None) or err.__class__.__name__))
    except (OSError, http.client.HTTPException, ValueError) as err:
        raise HttpError("%s nicht erreichbar: %s" % (host, (str(err)[:120] or err.__class__.__name__)))
    finally:
        conn.close()


def multipart(fields):
    """``fields``: list of ``(name, filename or None, content bytes/str)``. Returns ``(body, content_type)``."""
    import secrets
    boundary = "portnook" + secrets.token_hex(12)
    out = []
    for name, filename, content in fields:
        if isinstance(content, str):
            content = content.encode("utf-8")
        disp = 'form-data; name="%s"' % name
        if filename:
            disp += '; filename="%s"' % filename
        head = "--%s\r\nContent-Disposition: %s\r\n" % (boundary, disp)
        if filename:
            head += "Content-Type: application/octet-stream\r\n"
        out.append(head.encode() + b"\r\n" + content + b"\r\n")
    out.append(("--%s--\r\n" % boundary).encode())
    return b"".join(out), "multipart/form-data; boundary=" + boundary
