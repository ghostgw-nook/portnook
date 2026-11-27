#!/usr/bin/env python3
"""Test device for portnook push ping: does what the app will do, so the portnook side can be tested without it.

1. GET <entry>/_pn/hello (follows the 302 to the VPN port, the proxy passes /_pn/ to portnook)
2. sign in: by code (default; confirm it in a signed-in client) or with --password
3. create a device key (X25519), register, keep the state in --state (default ./pn-test-device)
4. wait for the device's file on the storage, fetch it, check portnook's signature, decrypt it, show it

Run it again with --fetch to only fetch and open the file (e.g. after a port change).

Needs Python 3.8+ and OpenSSL 3 (macOS: brew install openssl@3; the system LibreSSL cannot do X25519 here).
Set PN_OPENSSL to its path if it is not found. Without a terminal, PN_USER/PN_PASSWORD give the login. The access
token and the password are never written to disk.

    python3 push-test-device.py https://start.example.ch
    python3 push-test-device.py https://start.example.ch --password
    python3 push-test-device.py --fetch
"""

import argparse
import getpass
import glob
import hashlib
import hmac
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

MAGIC = b"PNP1"
INFO = b"portnook push v1"
SPKI_X25519 = bytes.fromhex("302a300506032b656e032100")
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")
UA = "pn-test-device/1"


def die(text):
    print("FEHLER: " + text, file=sys.stderr)
    sys.exit(1)


# -- openssl ------------------------------------------------------------------------
def find_openssl():
    cands = [os.environ.get("PN_OPENSSL", "")] + sorted(glob.glob("/opt/homebrew/opt/openssl@3*/bin/openssl"),
                                                       reverse=True)
    cands += ["/opt/homebrew/opt/openssl/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl",
              shutil.which("openssl") or ""]
    for path in cands:
        if not path or not os.path.exists(path):
            continue
        out = subprocess.run([path, "version"], capture_output=True, text=True).stdout
        if out.startswith("OpenSSL ") and not out.startswith(("OpenSSL 0.", "OpenSSL 1.0")):
            return path
    die("OpenSSL 3 nicht gefunden (brew install openssl@3, oder PN_OPENSSL=/pfad/zu/openssl).")


OPENSSL = None


def ossl(args, data=None):
    res = subprocess.run([OPENSSL] + args, input=data, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError("openssl %s: %s" % (args[0], res.stderr.decode(errors="replace").strip()[:200]))
    return res.stdout


def public_raw(key_path):
    der = ossl(["pkey", "-in", key_path, "-pubout", "-outform", "DER"])
    return der[12:]


# -- drop format (independent of portnook's code, on purpose) --------------------------------
def hkdf(ikm, salt, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def keystream_xor(key, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 32):
        block = hmac.new(key, nonce + (i // 32).to_bytes(4, "big"), hashlib.sha256).digest()
        out += bytes(a ^ b for a, b in zip(data[i:i + 32], block))
    return bytes(out)


def open_drop(drop, key_path, sign_pub):
    if len(drop) < 4 + 32 + 16 + 32 + 64 or drop[:4] != MAGIC:
        raise ValueError("keine portnook-Datei (Kennung PNP1 fehlt)")
    body, sig = drop[:-64], drop[-64:]
    work = tempfile.mkdtemp()
    try:
        for name, data in (("pub.der", SPKI_ED25519 + sign_pub), ("msg", body), ("sig", sig)):
            with open(os.path.join(work, name), "wb") as fh:
                fh.write(data)
        res = subprocess.run([OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey",
                              os.path.join(work, "pub.der"), "-in", os.path.join(work, "msg"), "-sigfile",
                              os.path.join(work, "sig")], capture_output=True)
        if res.returncode != 0:
            raise ValueError("Signatur stimmt nicht (nicht von diesem portnook)")
        eph_pub, nonce = drop[4:36], drop[36:52]
        with open(os.path.join(work, "peer.der"), "wb") as fh:
            fh.write(SPKI_X25519 + eph_pub)
        shared = ossl(["pkeyutl", "-derive", "-inkey", key_path, "-peerkey", os.path.join(work, "peer.der"),
                       "-peerform", "DER"])
    finally:
        shutil.rmtree(work, True)
    okm = hkdf(shared, nonce, INFO + eph_pub + public_raw(key_path), 64)
    enc_key, mac_key = okm[:32], okm[32:]
    if not hmac.compare_digest(hmac.new(mac_key, body[:-32], hashlib.sha256).digest(), body[-32:]):
        raise ValueError("Prüfsumme stimmt nicht (falscher Geräteschlüssel?)")
    return json.loads(keystream_xor(enc_key, nonce, body[52:-32]))


# -- http ---------------------------------------------------------------------------------
def http(method, url, body=None, soft=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": UA, "Accept": "*/*"})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as res:
            return res.status, res.geturl(), res.read()
    except urllib.error.HTTPError as err:
        return err.code, err.geturl(), err.read()
    except (urllib.error.URLError, OSError) as err:
        reason = "%s nicht erreichbar: %s" % (url, getattr(err, "reason", err))
        if soft:
            return 0, url, reason.encode()
        die(reason)


def api(base, path, body):
    status, _, data = http("POST", base + path, body)
    try:
        answer = json.loads(data or b"{}")
    except ValueError:
        answer = {}
    return status, answer


# -- steps --------------------------------------------------------------------------------
def find_api(entry):
    status, final, data = http("GET", entry.rstrip("/") + "/_pn/hello")
    print("1. Eingang: %s -> %s (HTTP %d)" % (entry, final.rsplit("/_pn/", 1)[0] or final, status))
    try:
        ok = status == 200 and json.loads(data).get("ok") is True
    except ValueError:
        ok = False
    if not ok:
        die("kein Push-Ping unter /_pn/ (Proxy-Pfad /_pn/ auf portnook Port 8099? Push-Ping eingeschaltet?)")
    return final.rsplit("hello", 1)[0]


def sign_in(base, use_password):
    dev = {"client": "pn-test-device", "device": "Test-Geraet", "device_id": "pn-test-device", "version": "1"}
    if use_password:
        try:
            user = os.environ.get("PN_USER") or input("   Benutzer: ").strip()
            password = os.environ.get("PN_PASSWORD") or getpass.getpass("   Passwort: ")
        except (EOFError, KeyboardInterrupt):
            die("keine Eingabe (oder PN_USER/PN_PASSWORD setzen)")
        status, answer = api(base, "login", dict(dev, user=user, password=password))
        if status != 200:
            die("Anmeldung abgelehnt (HTTP %d)" % status)
        return answer
    status, start = api(base, "code/start", dev)
    if status == 409:
        die("Anmeldung per Code ist aus (Quick Connect einschalten) - oder --password verwenden")
    if status != 200:
        die("Code anfordern fehlgeschlagen (HTTP %d)" % status)
    print("2. Code: %s  - in einem angemeldeten Client bestätigen (Quick Connect), warte bis 10 Minuten ..."
          % start["code"])
    for _ in range(195):
        time.sleep(3)
        status, answer = api(base, "code/check", dict(dev, secret=start["secret"]))
        if status != 200:
            die("Code abgelaufen oder abgelehnt (HTTP %d)" % status)
        if not answer.get("pending"):
            return answer
    die("Code nicht bestätigt")


def register(base, login, state_dir):
    key = os.path.join(state_dir, "device.pem")
    old = os.umask(0o077)
    try:
        ossl(["genpkey", "-algorithm", "X25519", "-out", key])
    finally:
        os.umask(old)
    status, answer = api(base, "register", {"token": login["token"], "device_pub": public_raw(key).hex(),
                                            "platform": "other", "name": "Test-Gerät"})
    if status != 200:
        die("Registrieren abgelehnt (HTTP %d: %s)" % (status, answer.get("error", "")))
    state = {"device_id": answer["device_id"], "drop_url": answer["drop_url"], "sign_pub": answer["sign_pub"],
             "user": login.get("user_name", "")}
    with open(os.path.join(state_dir, "state.json"), "w") as fh:
        json.dump(state, fh, indent=2)
    print("3. Registriert als Gerät %s (Benutzer %s)" % (state["device_id"], state["user"]))
    if not state["drop_url"]:
        die("portnook hat keine Abruf-Adresse (WebDAV-Ordner in portnook eintragen)")
    return state


def fetch(state, state_dir, wait):
    url, deadline = state["drop_url"], time.time() + wait
    print("4. Datei: %s" % url)
    while True:
        status, _, data = http("GET", url)
        if status == 200:
            break
        if time.time() >= deadline:
            die("Datei nicht abrufbar (HTTP %d). Upload in portnook ok? Ordner öffentlich lesbar?" % status)
        print("   noch nicht da (HTTP %d), neuer Versuch in 15 s ..." % status)
        time.sleep(15)
    try:
        plain = open_drop(data, os.path.join(state_dir, "device.pem"), bytes.fromhex(state["sign_pub"]))
    except ValueError as err:
        die(str(err))
    print("5. Signatur ok, entschlüsselt:")
    print("   Adresse:  %s" % plain.get("url"))
    print("   Nummer:   %s   Zeit: %s" % (plain.get("seq"), time.strftime("%d.%m.%Y %H:%M:%S",
                                                                         time.localtime(plain.get("ts", 0)))))
    if plain.get("cert"):
        print("   Zertifikat: %s" % plain["cert"])
    status, _, data = http("GET", plain["url"].rstrip("/") + "/_pn/hello", soft=True)
    if status:
        print("   Prüfung: %s/_pn/hello -> HTTP %d" % (plain["url"], status))
    else:
        print("   Warnung: %s" % data.decode())


def main():
    global OPENSSL
    ap = argparse.ArgumentParser(description="Test device for portnook push ping")
    ap.add_argument("entry", nargs="?", help="entry address, e.g. https://start.example.ch")
    ap.add_argument("--password", action="store_true", help="sign in with user and password instead of a code")
    ap.add_argument("--fetch", action="store_true", help="only fetch and open the file of the saved device")
    ap.add_argument("--state", default="pn-test-device", help="folder for key and state (default ./pn-test-device)")
    ap.add_argument("--wait", type=int, default=300, help="seconds to wait for the file (default 300)")
    args = ap.parse_args()
    OPENSSL = find_openssl()
    os.makedirs(args.state, mode=0o700, exist_ok=True)
    if args.fetch:
        try:
            with open(os.path.join(args.state, "state.json")) as fh:
                state = json.load(fh)
        except (OSError, ValueError):
            die("kein gespeichertes Gerät in %s, zuerst ohne --fetch starten" % args.state)
        return fetch(state, args.state, args.wait)
    if not args.entry:
        ap.error("entry address missing")
    base = find_api(args.entry)
    login = sign_in(base, args.password)
    if args.password:
        print("2. Angemeldet")
    state = register(base, login, args.state)
    fetch(state, args.state, args.wait)


if __name__ == "__main__":
    main()
