"""Reachability probes: backend TLS handshake, Proton exit IP via natpmpc, exit IP via an IP echo (wg0)."""

import ipaddress
import json
import os
import shutil
import socket
import ssl
import time

from . import httpc, parsers, sysrun

PROTON_GATEWAY = "10.2.0.1"
# IP echo of addr.tools (same operator as myaddr.tools): JSON {"ip": ..., ...}; only ever asked through wg0
IPECHO_URL = "https://ip.addr.tools/"


def ipecho_url():
    return os.environ.get("PF_IPECHO_URL") or IPECHO_URL


def wg_public_ip(device, url=None, timeout=10, request=httpc.request):
    """Exit IP of the tunnel ``device`` (providers without NAT-PMP); ``""`` on any failure.

    The request is bound to ``device`` (SO_BINDTODEVICE), it never leaves through eth0.
    """
    if not device:
        return ""
    try:
        resp = request("GET", url or ipecho_url(), device=device, timeout=timeout,
                       headers={"Accept": "application/json"})
    except httpc.HttpError:
        return ""
    if resp.status != 200:
        return ""
    text = resp.text(2000).strip()
    try:
        data = json.loads(text)
        text = data.get("ip", "") if isinstance(data, dict) else ""
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return ""


def backend_tls(ip, port, sni=None, timeout=5.0, proxy_protocol=False):
    """TCP connect + TLS handshake (certificate not validated). ``proxy_protocol`` (0.30.0): send a PROXY v2
    header with the agent's own address first, as the relayed connections do.

    Returns ``{"ok", "tcp", "tls", "latency_ms", "error", "checked"}``;
    ``ok`` means the TLS handshake succeeded.
    """
    result = {"ok": False, "tcp": False, "tls": False, "latency_ms": 0, "error": "", "checked": int(time.time())}
    start = time.monotonic()
    try:
        sock = socket.create_connection((str(ip), int(port)), timeout=timeout)
    except OSError as err:
        result["error"] = "TCP-Verbindung fehlgeschlagen: %s" % (err.strerror or err.__class__.__name__)
        return result
    result["tcp"] = True
    if proxy_protocol:
        from .lanproxy import proxy_v2_header
        try:
            sock.sendall(proxy_v2_header(sock.getsockname(), sock.getpeername()))
        except OSError:
            pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(sock, server_hostname=sni or None):
            pass
        result["tls"] = result["ok"] = True
    except (OSError, ssl.SSLError) as err:
        result["error"] = "TLS-Handshake fehlgeschlagen: %s" % (getattr(err, "reason", None) or str(err)[:120])
    finally:
        try:
            sock.close()
        except OSError:
            pass
    result["latency_ms"] = int(round((time.monotonic() - start) * 1000))
    return result


def natpmpc_available():
    return shutil.which("natpmpc") is not None


def proton_public_ip(gateway=PROTON_GATEWAY, timeout=10):
    """Exit IP via ``natpmpc -g <gw>``; ``""`` if natpmpc is missing or fails."""
    if not natpmpc_available():
        return ""
    try:
        proc = sysrun.run(["natpmpc", "-g", gateway], check=False, timeout=timeout)
    except sysrun.SysRunError:
        return ""
    return parsers.natpmpc(proc.stdout + "\n" + proc.stderr)["public_ip"]
