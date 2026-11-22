"""Minimal ACME client (RFC 8555) for DNS-01, standard library + openssl CLI.

Keys are EC P-256 (``openssl genpkey``), JWS signatures ES256: ``openssl dgst -sha256 -sign``
returns a DER ``ECDSA-Sig-Value``, which is converted to the raw ``r || s`` form (RFC 7518 3.4).
Key files are passed to openssl by path (mode 600), never as arguments or in logs.
"""

import base64
import calendar
import hashlib
import json
import os
import time

from . import httpc, sysrun

LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
POLL_TIMEOUT = 300


class AcmeError(Exception):
    """ACME server refused or could not be reached; message safe for the UI."""


def b64u(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# -- openssl helpers ---------------------------------------------------------
def generate_key(path):
    """New EC P-256 private key (PKCS#8 PEM) at ``path``, mode 600, atomic."""
    tmp = path + ".tmp"
    old = os.umask(0o077)
    try:
        sysrun.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", tmp])
    finally:
        os.umask(old)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def public_point(key_path):
    """``(x, y)`` of the P-256 public key (32 bytes each)."""
    der = sysrun.run(["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"], text=False).stdout
    point = der[-65:]
    if len(der) != 91 or point[:1] != b"\x04":
        raise AcmeError("Kontoschlüssel ist kein EC-P-256-Schlüssel.")
    return point[1:33], point[33:]


def _der_len(data, i):
    first = data[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    return int.from_bytes(data[i + 1:i + 1 + n], "big"), i + 1 + n


def der_to_raw(der, size=32):
    """DER ``SEQUENCE { INTEGER r, INTEGER s }`` -> ``r || s`` (fixed ``size`` bytes each)."""
    if not der or der[0] != 0x30:
        raise AcmeError("ungültige ECDSA-Signatur")
    _, i = _der_len(der, 1)
    out = b""
    for _ in range(2):
        if der[i] != 0x02:
            raise AcmeError("ungültige ECDSA-Signatur")
        n, i = _der_len(der, i + 1)
        val = int.from_bytes(der[i:i + n], "big")
        i += n
        out += val.to_bytes(size, "big")
    return out


def raw_to_der(raw):
    """Inverse of ``der_to_raw`` (tests: verify with ``openssl dgst -verify``)."""
    half = len(raw) // 2
    parts = b""
    for val in (raw[:half], raw[half:]):
        val = val.lstrip(b"\x00") or b"\x00"
        if val[0] & 0x80:
            val = b"\x00" + val
        parts += b"\x02" + bytes([len(val)]) + val
    return b"\x30" + bytes([len(parts)]) + parts


def sign(key_path, data):
    der = sysrun.run(["openssl", "dgst", "-sha256", "-sign", key_path], input=data, text=False).stdout
    return der_to_raw(der)


def csr_der(key_path, domains):
    """CSR (DER) for ``domains`` (first = CN), all as subjectAltName DNS entries."""
    san = ",".join("DNS:" + d for d in domains)
    return sysrun.run(["openssl", "req", "-new", "-key", key_path, "-subj", "/CN=" + domains[0],
                       "-addext", "subjectAltName=" + san, "-outform", "DER"], text=False).stdout


def cert_info(pem):
    """``{"not_after", "not_before", "names", "issuer"}`` of the first certificate in ``pem``."""
    out = sysrun.run(["openssl", "x509", "-noout", "-enddate", "-startdate", "-issuer", "-ext", "subjectAltName"],
                     input=pem, check=True).stdout
    info = {"not_after": 0, "not_before": 0, "names": [], "issuer": ""}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("notAfter="):
            info["not_after"] = _openssl_time(line.split("=", 1)[1])
        elif line.startswith("notBefore="):
            info["not_before"] = _openssl_time(line.split("=", 1)[1])
        elif line.startswith("issuer="):
            info["issuer"] = line.split("=", 1)[1].strip()[:200]
        elif "DNS:" in line:
            info["names"] = [p.strip()[4:] for p in line.split(",") if p.strip().startswith("DNS:")]
    return info


def _openssl_time(text):
    return calendar.timegm(time.strptime(" ".join(text.split()), "%b %d %H:%M:%S %Y %Z"))


def key_matches(cert_pem, key_path):
    a = sysrun.run(["openssl", "x509", "-noout", "-pubkey"], input=cert_pem).stdout.strip()
    b = sysrun.run(["openssl", "pkey", "-in", key_path, "-pubout"]).stdout.strip()
    return bool(a) and a == b


def split_chain(pem):
    """``(leaf, rest)`` PEM strings of a certificate chain."""
    marker = "-----END CERTIFICATE-----"
    blocks = [b.strip() + "\n" + marker + "\n" for b in pem.split(marker) if "BEGIN CERTIFICATE" in b]
    if not blocks:
        raise AcmeError("Antwort enthält kein Zertifikat.")
    return blocks[0], "".join(blocks[1:])


def dns01_value(token, thumbprint):
    return b64u(hashlib.sha256((token + "." + thumbprint).encode("ascii")).digest())


# -- client ------------------------------------------------------------------
class Client:
    def __init__(self, directory_url, key_path, device=None, cafile=None, request=httpc.request,
                 sleep=time.sleep, clock=time.monotonic, log=None):
        self.directory_url = directory_url
        self.key_path = key_path
        self.device = device
        self.cafile = cafile
        self.request = request
        self.sleep = sleep
        self.clock = clock
        self.log = log or (lambda *a: None)
        self.nonce = None
        self.kid = None
        self.dir = None
        x, y = public_point(key_path)
        self.jwk = {"crv": "P-256", "kty": "EC", "x": b64u(x), "y": b64u(y)}
        self.thumbprint = b64u(hashlib.sha256(_json(self.jwk).encode("ascii")).digest())

    def _http(self, method, url, body=None, headers=None):
        try:
            resp = self.request(method, url, body=body, headers=headers, device=self.device, cafile=self.cafile,
                                timeout=30)
        except httpc.HttpError as err:
            raise AcmeError("ACME-Server: %s" % err)
        nonce = resp.header("replay-nonce")
        if nonce:
            self.nonce = nonce
        return resp

    def directory(self):
        if self.dir is None:
            resp = self._http("GET", self.directory_url)
            data = resp.json()
            if resp.status != 200 or not isinstance(data, dict) or not all(
                    isinstance(data.get(k), str) for k in ("newNonce", "newAccount", "newOrder")):
                raise AcmeError("ACME-Verzeichnis ungültig (HTTP %d)." % resp.status)
            self.dir = data
        return self.dir

    def terms(self):
        return str((self.directory().get("meta") or {}).get("termsOfService") or "")

    def post(self, url, payload, use_jwk=False, accept="application/json"):
        """Signed POST (``payload=None`` = POST-as-GET). Retries ``badNonce`` up to 3 times."""
        for attempt in range(4):
            if not self.nonce:
                self._http("HEAD", self.directory()["newNonce"])
                if not self.nonce:
                    raise AcmeError("ACME-Server liefert keine Nonce.")
            protected = {"alg": "ES256", "nonce": self.nonce, "url": url}
            if use_jwk:
                protected["jwk"] = self.jwk
            else:
                protected["kid"] = self.kid
            self.nonce = None
            p64 = b64u(_json(protected))
            pl64 = "" if payload is None else b64u(_json(payload))
            sig = sign(self.key_path, (p64 + "." + pl64).encode("ascii"))
            body = _json({"protected": p64, "payload": pl64, "signature": b64u(sig)})
            resp = self._http("POST", url, body=body, headers={"Content-Type": "application/jose+json",
                                                               "Accept": accept})
            if resp.status < 400:
                return resp
            prob = resp.json() if resp.header("content-type").startswith("application/problem+json") or \
                resp.header("content-type").startswith("application/json") else None
            prob = prob if isinstance(prob, dict) else {}
            if str(prob.get("type", "")).endswith(":badNonce") and attempt < 3:
                continue
            raise AcmeError(problem_text(prob, resp.status))
        raise AcmeError("ACME: zu viele badNonce-Fehler")

    def account(self, email="", agree=False):
        payload = {"termsOfServiceAgreed": bool(agree)}
        if email:
            payload["contact"] = ["mailto:" + email]
        resp = self.post(self.directory()["newAccount"], payload, use_jwk=True)
        kid = resp.header("location")
        if not kid:
            raise AcmeError("ACME-Konto: keine Konto-URL erhalten.")
        self.kid = kid
        return kid

    def poll(self, url, done, fail=("invalid",), timeout=POLL_TIMEOUT):
        end = self.clock() + timeout
        while True:
            resp = self.post(url, None)
            obj = resp.json() or {}
            status = obj.get("status")
            if status in done:
                return obj
            if status in fail:
                raise AcmeError(object_error(obj, status))
            if self.clock() >= end:
                raise AcmeError("Zeitüberschreitung (Status %s)." % status)
            try:
                wait = int(resp.header("retry-after") or 2)
            except ValueError:
                wait = 2
            self.sleep(max(1, min(wait, 10)))

    def issue(self, domains, csr, publish, wait):
        """Order ``domains`` via DNS-01. ``publish(values)`` puts the TXT values in place,
        ``wait()`` waits for DNS propagation. Returns the PEM chain."""
        resp = self.post(self.directory()["newOrder"], {"identifiers": [{"type": "dns", "value": d} for d in domains]})
        order = resp.json() or {}
        order_url = resp.header("location")
        if not order_url or not isinstance(order.get("authorizations"), list):
            raise AcmeError("ACME-Bestellung ungültig.")
        todo = []
        for az_url in order["authorizations"]:
            az = self.post(az_url, None).json() or {}
            if az.get("status") == "valid":
                continue
            if az.get("status") != "pending":
                raise AcmeError(object_error(az, az.get("status")))
            ch = next((c for c in az.get("challenges", []) if c.get("type") == "dns-01"), None)
            if not ch:
                raise AcmeError("ACME-Server bietet keine DNS-01-Prüfung an.")
            ident = (az.get("identifier") or {}).get("value", "")
            todo.append((az_url, ch["url"], dns01_value(ch["token"], self.thumbprint),
                         ("*." if az.get("wildcard") else "") + ident))
        if todo:
            if getattr(publish, "by_name", False):  # 0.19.0: several myaddr names, each with its own key
                publish([(t[3], t[2]) for t in todo])
            else:
                publish(list(dict.fromkeys(t[2] for t in todo)))
            wait()
            for _, ch_url, _, name in todo:
                self.log("acme: challenge ready for %s", name)
                self.post(ch_url, {})
            for az_url, _, _, name in todo:
                self.poll(az_url, ("valid",))
                self.log("acme: %s validated", name)
        order = self.poll(order_url, ("ready", "valid"))
        if order.get("status") == "ready":
            self.post(order["finalize"], {"csr": b64u(csr)})
            order = self.poll(order_url, ("valid",))
        if not order.get("certificate"):
            raise AcmeError("ACME-Bestellung ohne Zertifikat.")
        pem = self.post(order["certificate"], None, accept="application/pem-certificate-chain").text()
        split_chain(pem)
        return pem


def problem_text(prob, status=None):
    detail = " ".join(str(prob.get("detail") or "").split())[:240]
    kind = str(prob.get("type") or "").rsplit(":", 1)[-1][:40]
    subs = prob.get("subproblems") or []
    if subs and isinstance(subs, list) and isinstance(subs[0], dict):
        detail += " / " + " ".join(str(subs[0].get("detail") or "").split())[:160]
    head = ", ".join(x for x in ("HTTP %d" % status if status else "", kind) if x)
    return "ACME-Fehler%s: %s" % (" (%s)" % head if head else "", detail or "ohne Details")


def object_error(obj, status):
    err = obj.get("error")
    if not err:
        for ch in obj.get("challenges", []) or []:
            if ch.get("error"):
                err = ch["error"]
                break
    if isinstance(err, dict):
        return problem_text(err)
    return "ACME: Status %s" % status
