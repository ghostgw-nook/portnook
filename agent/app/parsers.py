"""Parsers for system tool output (``wg show dump``, ``natpmpc``, ``ip route``)."""

import ipaddress
import re


def wg_dump(text):
    """Parse ``wg show <iface> dump``.

    Returns ``{"public_key", "listen_port", "peers": [...]}``; each peer has
    ``public_key, endpoint, allowed_ips, handshake, rx, tx, keepalive``.
    The interface private key and preshared keys are deliberately dropped.
    """
    result = {"public_key": "", "listen_port": 0, "peers": []}
    lines = [l for l in (text or "").splitlines() if l.strip()]
    if not lines:
        return result
    head = lines[0].split("\t")
    if len(head) >= 4:
        result["public_key"] = head[1]
        result["listen_port"] = _int(head[2])
    for line in lines[1:]:
        f = line.split("\t")
        if len(f) < 8:
            continue
        result["peers"].append({
            "public_key": f[0],
            "endpoint": "" if f[2] == "(none)" else f[2],
            "allowed_ips": [] if f[3] == "(none)" else f[3].split(","),
            "handshake": _int(f[4]),
            "rx": _int(f[5]),
            "tx": _int(f[6]),
            "keepalive": 0 if f[7] == "off" else _int(f[7]),
        })
    return result


_PUBLIC_IP = re.compile(r"Public IP address\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})")
_MAPPED = re.compile(r"Mapped public port\s+(\d+)\s+protocol\s+(\w+)\s+to local port\s+(\d+)\s+li[f]?e?time\s+(\d+)", re.I)


def natpmpc(text):
    """Parse ``natpmpc`` output. Returns ``{"public_ip", "port", "protocol", "lifetime"}``."""
    out = {"public_ip": "", "port": 0, "protocol": "", "lifetime": 0}
    text = text or ""
    m = _PUBLIC_IP.search(text)
    if m:
        try:
            out["public_ip"] = str(ipaddress.IPv4Address(m.group(1)))
        except ipaddress.AddressValueError:
            pass
    m = _MAPPED.search(text)
    if m:
        out["port"] = int(m.group(1))
        out["protocol"] = m.group(2).upper()
        out["lifetime"] = int(m.group(4))
    return out


def wg_endpoint_ip(text):
    """First IPv4 endpoint from ``wg show <iface> endpoints`` (``<pubkey>\\t<ip>:<port>``)."""
    for line in (text or "").splitlines():
        f = line.split("\t")
        if len(f) >= 2 and f[1] != "(none)":
            try:
                return str(ipaddress.IPv4Address(f[1].rsplit(":", 1)[0]))
            except ValueError:
                continue
    return ""


def default_gateway(text, dev="eth0"):
    """Gateway of the IPv4 default route on ``dev`` from ``ip -4 route show default``."""
    for line in (text or "").splitlines():
        f = line.split()
        if len(f) >= 5 and f[0] == "default" and "via" in f and "dev" in f:
            if f[f.index("dev") + 1] == dev:
                return f[f.index("via") + 1]
    return ""


def interface_networks(text):
    """IPv4 networks from ``ip -4 -o addr show dev X``."""
    nets = []
    for line in (text or "").splitlines():
        f = line.split()
        if "inet" in f:
            try:
                nets.append(ipaddress.IPv4Interface(f[f.index("inet") + 1]).network)
            except (ValueError, IndexError):
                pass
    return nets


def interface_addresses(text):
    """IPv4 addresses (without prefix) from ``ip -4 -o addr show dev X``."""
    out = []
    for line in (text or "").splitlines():
        f = line.split()
        if "inet" in f:
            try:
                out.append(str(ipaddress.IPv4Interface(f[f.index("inet") + 1]).ip))
            except (ValueError, IndexError):
                pass
    return out


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
