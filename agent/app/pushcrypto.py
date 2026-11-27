"""Sealed address drops for push ping (standard library + openssl CLI).

A drop is one small file per device on an untrusted static host. Only that device can read it and only
portnook can have written it:

    magic "PNP1" (4) | ephemeral X25519 public key (32) | nonce (16) | ciphertext | tag (32) | signature (64)

* Key agreement: X25519 between a fresh ephemeral key and the device's public key (``openssl pkeyutl -derive``).
* Keys: HKDF-SHA256 (RFC 5869), salt = nonce, info = ``INFO || ephemeral pub || device pub`` -> 32 byte
  encryption key + 32 byte MAC key.
* Encryption: keystream block ``i`` = HMAC-SHA256(enc key, nonce || i as 4 byte big endian), XORed with the
  plaintext. A PRF in counter mode; the nonce and the ephemeral key are new for every drop.
* Tag: HMAC-SHA256(mac key, everything before it) (encrypt-then-MAC).
* Signature: Ed25519 by portnook's signing key over everything before it.

Secrets never go into command arguments: private keys are passed by path (mode 600), data via stdin.
"""

import hashlib
import hmac
import os
import secrets
import shutil
import tempfile

from . import sysrun

MAGIC = b"PNP1"
INFO = b"portnook push v1"
NONCE_LEN = 16
TAG_LEN = 32
SIG_LEN = 64
KEY_LEN = 32
HEADER_LEN = len(MAGIC) + KEY_LEN + NONCE_LEN
MIN_LEN = HEADER_LEN + TAG_LEN + SIG_LEN

# SubjectPublicKeyInfo prefixes for raw 32 byte keys (RFC 8410).
_SPKI_X25519 = bytes.fromhex("302a300506032b656e032100")
_SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")


class DropError(Exception):
    """A drop could not be built or does not verify."""


# -- keys ----------------------------------------------------------------------
def _genkey(algorithm, path):
    tmp = path + ".tmp"
    old = os.umask(0o077)
    try:
        sysrun.run(["openssl", "genpkey", "-algorithm", algorithm, "-out", tmp])
    finally:
        os.umask(old)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def generate_signing_key(path):
    """New Ed25519 private key (PKCS#8 PEM) at ``path``, mode 600, atomic."""
    _genkey("ED25519", path)


def generate_x25519_key(path):
    """New X25519 private key (PKCS#8 PEM) at ``path``, mode 600, atomic."""
    _genkey("X25519", path)


def public_raw(key_path):
    """Raw 32 byte public key of an Ed25519 or X25519 private key file."""
    der = sysrun.run(["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"], text=False).stdout
    if len(der) != 44 or der[:12] not in (_SPKI_X25519, _SPKI_ED25519):
        raise DropError("not an X25519/Ed25519 key")
    return der[12:]


def _write_spki(path, prefix, raw):
    if len(raw) != KEY_LEN:
        raise DropError("public key must be 32 bytes")
    with open(path, "wb") as fh:
        fh.write(prefix + raw)


# -- primitives ----------------------------------------------------------------
def hkdf(ikm, salt, info, length):
    """HKDF-SHA256 (RFC 5869)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def keystream_xor(key, nonce, data):
    """XOR ``data`` with HMAC-SHA256(key, nonce || counter) blocks."""
    out = bytearray()
    for i in range(0, len(data), 32):
        block = hmac.new(key, nonce + (i // 32).to_bytes(4, "big"), hashlib.sha256).digest()
        out += bytes(a ^ b for a, b in zip(data[i:i + 32], block))
    return bytes(out)


def _derive(own_key_path, peer_raw, workdir):
    peer = os.path.join(workdir, "peer.der")
    _write_spki(peer, _SPKI_X25519, peer_raw)
    secret = sysrun.run(["openssl", "pkeyutl", "-derive", "-inkey", own_key_path, "-peerkey", peer,
                         "-peerform", "DER"], text=False).stdout
    if len(secret) != KEY_LEN or not any(secret):
        raise DropError("key agreement failed")
    return secret


def _keys(shared, nonce, eph_pub, device_pub):
    okm = hkdf(shared, nonce, INFO + eph_pub + device_pub, 2 * KEY_LEN)
    return okm[:KEY_LEN], okm[KEY_LEN:]


def sign(key_path, data):
    """Ed25519 signature (64 bytes) of ``data``."""
    workdir = tempfile.mkdtemp()
    try:
        msg = os.path.join(workdir, "msg")
        with open(msg, "wb") as fh:
            fh.write(data)
        sig = sysrun.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key_path, "-in", msg],
                         text=False).stdout
    finally:
        shutil.rmtree(workdir, True)
    if len(sig) != SIG_LEN:
        raise DropError("signing failed")
    return sig


def verify(sign_pub_raw, data, sig):
    """True when ``sig`` is portnook's Ed25519 signature of ``data``."""
    workdir = tempfile.mkdtemp()
    try:
        pub = os.path.join(workdir, "pub.der")
        _write_spki(pub, _SPKI_ED25519, sign_pub_raw)
        msg = os.path.join(workdir, "msg")
        sig_path = os.path.join(workdir, "sig")
        with open(msg, "wb") as fh:
            fh.write(data)
        with open(sig_path, "wb") as fh:
            fh.write(sig)
        res = sysrun.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", pub,
                          "-in", msg, "-sigfile", sig_path], check=False)
        return res.returncode == 0
    finally:
        shutil.rmtree(workdir, True)


# -- drops ---------------------------------------------------------------------
def seal(plaintext, device_pub, sign_key_path, _eph_key_path=None, _nonce=None):
    """Drop for the device with X25519 public key ``device_pub`` (32 bytes), signed with ``sign_key_path``.

    ``_eph_key_path`` and ``_nonce`` are for test vectors only.
    """
    workdir = tempfile.mkdtemp()
    try:
        eph = _eph_key_path
        if eph is None:
            eph = os.path.join(workdir, "eph.pem")
            generate_x25519_key(eph)
        eph_pub = public_raw(eph)
        nonce = _nonce if _nonce is not None else secrets.token_bytes(NONCE_LEN)
        if len(nonce) != NONCE_LEN:
            raise DropError("nonce must be 16 bytes")
        enc_key, mac_key = _keys(_derive(eph, device_pub, workdir), nonce, eph_pub, device_pub)
    finally:
        shutil.rmtree(workdir, True)
    body = MAGIC + eph_pub + nonce + keystream_xor(enc_key, nonce, plaintext)
    body += hmac.new(mac_key, body, hashlib.sha256).digest()
    return body + sign(sign_key_path, body)


def open_drop(drop, device_key_path, sign_pub_raw):
    """Plaintext of ``drop`` for the device key ``device_key_path``; raises ``DropError`` when it does not verify."""
    if len(drop) < MIN_LEN or drop[:len(MAGIC)] != MAGIC:
        raise DropError("not a drop")
    body, sig = drop[:-SIG_LEN], drop[-SIG_LEN:]
    if not verify(sign_pub_raw, body, sig):
        raise DropError("bad signature")
    eph_pub = drop[len(MAGIC):len(MAGIC) + KEY_LEN]
    nonce = drop[len(MAGIC) + KEY_LEN:HEADER_LEN]
    ciphertext, tag = body[HEADER_LEN:-TAG_LEN], body[-TAG_LEN:]
    workdir = tempfile.mkdtemp()
    try:
        device_pub = public_raw(device_key_path)
        enc_key, mac_key = _keys(_derive(device_key_path, eph_pub, workdir), nonce, eph_pub, device_pub)
    finally:
        shutil.rmtree(workdir, True)
    if not hmac.compare_digest(hmac.new(mac_key, body[:-TAG_LEN], hashlib.sha256).digest(), tag):
        raise DropError("bad tag")
    return keystream_xor(enc_key, nonce, ciphertext)
