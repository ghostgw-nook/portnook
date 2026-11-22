"""Input validation helpers. Error messages are German (shown in the UI)."""

import base64
import binascii
import ipaddress
import re

_HOSTNAME = re.compile(r"(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
RFC1918 = [ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


class ValidationError(ValueError):
    """Invalid user input; ``str(err)`` is a German message for the UI."""


def is_wg_key(value):
    """WireGuard key: standard base64 of exactly 32 bytes (44 chars)."""
    if not isinstance(value, str) or len(value) != 44 or not value.endswith("="):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def is_hostname(value):
    return isinstance(value, str) and bool(_HOSTNAME.fullmatch(value))


def is_b64url(value, min_len=1, max_len=512):
    return isinstance(value, str) and min_len <= len(value) <= max_len and bool(_B64URL.fullmatch(value))


def ipv4(value, what="IP-Adresse"):
    try:
        addr = ipaddress.IPv4Address(str(value).strip())
    except (ipaddress.AddressValueError, ValueError):
        raise ValidationError("%s ist keine gültige IPv4-Adresse: %s" % (what, _short(value)))
    return addr


def ipv4_net(value, what="Netz"):
    """IPv4 network in CIDR notation (host bits are cleared)."""
    text = str(value).strip()
    if "/" not in text:
        raise ValidationError("%s braucht CIDR-Schreibweise, z. B. 192.168.1.0/24: %s" % (what, _short(text)))
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        raise ValidationError("%s ist kein gültiges IPv4-Netz: %s" % (what, _short(text)))


def port(value, what="Port"):
    try:
        num = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError("%s ist keine Zahl: %s" % (what, _short(value)))
    if not 1 <= num <= 65535:
        raise ValidationError("%s muss zwischen 1 und 65535 liegen." % what)
    return num


def host_port(value, what="Endpoint"):
    """``host:port`` with IPv4 or hostname. Returns ``(host, port)``."""
    text = str(value or "").strip()
    if text.startswith("["):
        raise ValidationError("%s: IPv6 wird nicht unterstützt (%s)." % (what, _short(text)))
    if text.count(":") != 1:
        raise ValidationError("%s muss die Form Host:Port haben: %s" % (what, _short(text)))
    host, port_text = text.split(":")
    if not is_hostname(host):
        raise ValidationError("%s: ungültiger Host %s" % (what, _short(host)))
    return host, port(port_text, what + "-Port")


def backend(value):
    """Backend ``IPv4:port``. Returns ``(IPv4Address, port)``."""
    text = str(value or "").strip()
    if text.count(":") != 1:
        raise ValidationError("Backend muss die Form IP:Port haben, z. B. 192.168.1.10:443.")
    ip_text, port_text = text.split(":")
    addr = ipv4(ip_text, "Backend")
    if not any(addr in n for n in RFC1918):
        raise ValidationError("Backend %s ist keine private LAN-Adresse (10.x, 172.16-31.x, 192.168.x)." % addr)
    return addr, port(port_text, "Backend-Port")


DEFAULT_LAN = [str(n) for n in RFC1918]  # all private networks (0.13.1)


def lan_nets(values):
    if isinstance(values, str):
        values = values.split()
    if not isinstance(values, list):
        raise ValidationError("LAN-Netze müssen eine Liste sein.")
    nets = []
    for item in values:
        if not str(item).strip():
            continue
        net = ipv4_net(item, "LAN-Netz")
        if net.prefixlen < 8:
            raise ValidationError("LAN-Netz %s ist zu gross (mindestens /8)." % net)
        if not any(net.subnet_of(n) for n in RFC1918):
            raise ValidationError("LAN-Netz %s ist kein privates Netz." % net)
        if str(net) not in nets:
            nets.append(str(net))
    if not nets:
        return list(DEFAULT_LAN)
    if len(nets) > 16:
        raise ValidationError("Höchstens 16 LAN-Netze.")
    return nets


def _short(value):
    text = str(value)
    return text if len(text) <= 60 else text[:57] + "..."
