"""Hand a new certificate to the reverse proxy in the LAN.

Nginx Proxy Manager (verified against github.com/NginxProxyManager/nginx-proxy-manager, backend/routes
and backend/internal/certificate.js): ``POST /api/tokens {identity, secret}`` -> ``{token}``;
``GET /api/nginx/certificates`` lists the certificates; a custom one is created with
``POST /api/nginx/certificates {provider: "other", nice_name}``; ``POST /api/nginx/certificates/<id>/upload``
(multipart: ``certificate``, ``certificate_key``, ``intermediate_certificate``) stores the files and writes
them for nginx (certificate + intermediate = fullchain). The same id is re-uploaded on renewal, so the proxy
hosts that use it keep working. A user with 2FA cannot log in through the API.

Zoraxy (verified against github.com/tobychui/zoraxy, src/mod/tlscert): certificates are file pairs
``<name>.pem`` (chain) + ``<name>.key`` in ``conf/certs`` (Docker: ``/opt/zoraxy/config/conf/certs``).
Files are read from disk at every TLS handshake (exact file name = host name, or the cached list of all
pairs for SNI matching, e.g. subdomains of a wildcard). A renewed file under the same name is used at once;
a new pair is found for subdomains after Zoraxy re-scans its list (restart, or any certificate action in
its UI). portnook writes ``<fqdn>.pem`` / ``<fqdn>.key``.

All LAN requests are bound to eth0 (never through the Proton tunnel) and the target must be a private
(RFC 1918) address.
"""

import ipaddress
import os
import re
import urllib.parse

from . import acme, httpc, validate
from .validate import ValidationError

NICE_DEFAULT = "portnook %s"
FORBIDDEN_DIRS = ("/", "/app", "/bin", "/data", "/dev", "/etc", "/lib", "/proc", "/root", "/sbin", "/sys",
                  "/usr", "/var")


class DeliveryError(Exception):
    """Target refused or not reachable; message safe for the UI (no passwords, tokens or keys)."""


# -- validation --------------------------------------------------------------
def check_npm_url(value):
    url = str(value or "").strip().rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path or parts.query:
        raise ValidationError("NPM-Adresse muss die Form http://192.168.1.10:81 haben.")
    if not validate.is_hostname(parts.hostname):
        raise ValidationError("NPM-Adresse: ungültiger Host.")
    try:
        parts.port
    except ValueError:
        raise ValidationError("NPM-Adresse: ungültiger Port.")
    try:
        addr = ipaddress.IPv4Address(parts.hostname)
        if not any(addr in n for n in validate.RFC1918):
            raise ValidationError("NPM muss im Heimnetz liegen (private IPv4-Adresse).")
    except ipaddress.AddressValueError:
        pass  # host name: resolved and checked before every push
    return url


def check_zoraxy_dir(value):
    path = os.path.normpath(str(value or "").strip())
    if not path.startswith("/") or path in FORBIDDEN_DIRS or any(path.startswith(d + "/") for d in FORBIDDEN_DIRS[1:]):
        raise ValidationError("Zoraxy-Ordner: absoluter Pfad eines eingebundenen Ordners, z. B. /zoraxy-certs.")
    return path


def lan_host_ok(host, resolve):
    """True if every IPv4 address of ``host`` is private (RFC 1918)."""
    ips = resolve(host)
    return bool(ips) and all(any(ipaddress.IPv4Address(i) in n for n in validate.RFC1918) for i in ips)


# -- Nginx Proxy Manager -----------------------------------------------------
def _npm_call(request, method, url, device, token=None, body=None, headers=None, what=""):
    hdrs = dict(headers or {})
    hdrs["Accept"] = "application/json"
    if token:
        hdrs["Authorization"] = "Bearer " + token
    try:
        resp = request(method, url, body=body, headers=hdrs, device=device, timeout=20)
    except httpc.HttpError as err:
        raise DeliveryError("NPM: %s" % err)
    data = resp.json()
    if resp.status >= 400:
        msg = ""
        if isinstance(data, dict):
            err = data.get("error")
            msg = err.get("message", "") if isinstance(err, dict) else str(err or "")
        raise DeliveryError("NPM %s: HTTP %d%s" % (what, resp.status, (" " + " ".join(msg.split())[:160]) if msg else ""))
    return data


def npm_push(cfg, fullchain, key_pem, device=None, request=httpc.request):
    """Upload to NPM. ``cfg``: url, identity, secret, nice_name, cert_id (optional). Returns the cert id."""
    base = cfg["url"].rstrip("/")
    tok = _npm_call(request, "POST", base + "/api/tokens", device,
                    body={"identity": cfg["identity"], "secret": cfg["secret"]}, what="Anmeldung")
    if not isinstance(tok, dict) or tok.get("requires_2fa"):
        raise DeliveryError("NPM: Der Benutzer hat 2FA aktiviert. Für portnook einen eigenen Benutzer ohne 2FA nutzen.")
    token = tok.get("token")
    if not isinstance(token, str) or not token:
        raise DeliveryError("NPM: keine Anmeldung möglich (kein Token).")
    nice = cfg.get("nice_name")
    certs = _npm_call(request, "GET", base + "/api/nginx/certificates", device, token=token, what="Zertifikate")
    certs = [c for c in (certs if isinstance(certs, list) else []) if isinstance(c, dict)]
    match = [c for c in certs if c.get("provider") == "other" and c.get("nice_name") == nice]
    by_id = [c for c in match if c.get("id") == cfg.get("cert_id")]
    if by_id or match:
        cert_id = (by_id or match)[0]["id"]
    else:
        made = _npm_call(request, "POST", base + "/api/nginx/certificates", device, token=token,
                         body={"provider": "other", "nice_name": nice}, what="Zertifikat anlegen")
        cert_id = made.get("id") if isinstance(made, dict) else None
    if not isinstance(cert_id, int):
        raise DeliveryError("NPM: Zertifikat-ID fehlt.")
    leaf, chain = acme.split_chain(fullchain)
    fields = [("certificate", "cert.pem", leaf),
              ("certificate_key", "privkey.pem", key_pem)]
    if chain:
        fields.append(("intermediate_certificate", "chain.pem", chain))
    body, ctype = httpc.multipart(fields)
    _npm_call(request, "POST", "%s/api/nginx/certificates/%d/upload" % (base, cert_id), device, token=token,
              body=body, headers={"Content-Type": ctype}, what="Upload")
    return cert_id


# -- Zoraxy ------------------------------------------------------------------
_SAFE = re.compile(r"[a-z0-9.-]+")


def zoraxy_write(directory, fqdn, fullchain, key_pem):
    """Write ``<fqdn>.pem`` (chain, 644) and ``<fqdn>.key`` (600) atomically. Returns the file names."""
    if not _SAFE.fullmatch(fqdn) or ".." in fqdn:
        raise DeliveryError("ungültiger Name")
    if not os.path.isdir(directory):
        raise DeliveryError("Zoraxy-Ordner %s existiert nicht (Volume eingebunden?)." % directory)
    names = []
    for ext, data, mode in ((".key", key_pem, 0o600), (".pem", fullchain, 0o644)):
        path = os.path.join(directory, fqdn + ext)
        tmp = os.path.join(directory, ".%s%s.tmp" % (fqdn, ext))
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        except OSError as err:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise DeliveryError("Zoraxy-Ordner nicht beschreibbar: %s" % (err.strerror or err.__class__.__name__))
        names.append(fqdn + ext)
    return names
