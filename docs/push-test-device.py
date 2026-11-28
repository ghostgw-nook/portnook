#!/usr/bin/env python3
"""Test device for portnook push ping: does what the app will do, so the portnook side can be tested without it.

1. GET <entry>/_pn/hello (follows the 302 to the VPN port, the proxy passes /_pn/ to portnook)
2. sign in: by code (default; confirm it in a signed-in client) or with --password
3. create a device key (X25519), register, keep the state in --state (default ./pn-test-device)
4. wait for the device's file on the storage, fetch it, check portnook's signature, decrypt it, show it

Run it again with --fetch to only fetch and open the file, or --watch to fetch it every 30 s and report each
change (port change test). Every run ends with a summary of all checks.

Needs Python 3.8+ and OpenSSL 3 (macOS: brew install openssl@3; the system LibreSSL cannot do X25519 here).
Set PN_OPENSSL to its path if it is not found. Without a terminal, PN_USER/PN_PASSWORD give the login. The access
token and the password are never written to disk.

    python3 push-test-device.py https://start.example.ch
    python3 push-test-device.py https://start.example.ch --password
    python3 push-test-device.py --fetch https://start.example.ch
    python3 push-test-device.py --watch https://start.example.ch
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
import urllib.parse
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


# -- report ------------------------------------------------------------------------------
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print("   %s %s%s" % ("OK  " if ok else "FAIL", name, (" - " + detail) if detail else ""))
    return ok


def summary():
    bad = [r for r in RESULTS if not r[1]]
    print("\nZusammenfassung: %d von %d Prüfungen ok" % (len(RESULTS) - len(bad), len(RESULTS)))
    for name, _, detail in bad:
        print("   FAIL %s%s" % (name, (" - " + detail) if detail else ""))
    return 1 if bad else 0


# -- http ---------------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kw):
        return None


def http(method, url, body=None, follow=True):
    """``(status, final url, body, location)``; status 0 when not reachable (body then holds the reason)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": UA, "Accept": "*/*"})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    handlers = [urllib.request.HTTPSHandler(context=ssl.create_default_context())]
    if not follow:
        handlers.append(_NoRedirect())
    try:
        with urllib.request.build_opener(*handlers).open(req, timeout=20) as res:
            return res.status, res.geturl(), res.read(), res.headers.get("Location", "")
    except urllib.error.HTTPError as err:
        return err.code, err.geturl(), err.read(), err.headers.get("Location", "")
    except (urllib.error.URLError, OSError) as err:
        return 0, url, str(getattr(err, "reason", err)).encode(), ""


def api(base, path, body):
    status, _, data, _ = http("POST", base + path, body)
    try:
        answer = json.loads(data or b"{}")
    except ValueError:
        answer = {}
    return status, answer


def origin(url):
    parts = urllib.parse.urlsplit(url)
    return "%s://%s" % (parts.scheme, parts.netloc)


# -- steps --------------------------------------------------------------------------------
def step_entry(entry):
    """Redirect of the entry and the push API behind it; returns ``(api base, redirect target origin)``."""
    print("1. Eingang %s" % entry)
    status, _, data, location = http("GET", entry.rstrip("/") + "/_pn/hello", follow=False)
    if status == 0:
        check("Eingang erreichbar", False, data.decode())
        return None, ""
    target = ""
    if status in (301, 302, 303, 307, 308):
        target = origin(location)
        check("Weiterleitung", True, "%d -> %s" % (status, target))
    else:
        check("Weiterleitung", status == 200, "keine Weiterleitung (HTTP %d), Eingang ist direkt das Ziel" % status)
    status, final, data, _ = http("GET", entry.rstrip("/") + "/_pn/hello")
    try:
        ok = status == 200 and json.loads(data).get("ok") is True
    except ValueError:
        ok = False
    if not check("Push-API unter /_pn/", ok, "HTTP %d bei %s" % (status, final) if status else data.decode()):
        print("   Tipp: Proxy-Pfad /_pn/ auf portnook Port 8099? Push-Ping eingeschaltet?")
        return None, target
    return final.rsplit("hello", 1)[0], target or origin(final)


def step_sign_in(base, use_password):
    dev = {"client": "pn-test-device", "device": "Test-Geraet", "device_id": "pn-test-device", "version": "1"}
    print("2. Anmeldung (%s)" % ("Benutzer und Passwort" if use_password else "Code"))
    if use_password:
        try:
            user = os.environ.get("PN_USER") or input("   Benutzer: ").strip()
            password = os.environ.get("PN_PASSWORD") or getpass.getpass("   Passwort: ")
        except (EOFError, KeyboardInterrupt):
            check("Anmeldung", False, "keine Eingabe (oder PN_USER/PN_PASSWORD setzen)")
            return None
        status, answer = api(base, "login", dict(dev, user=user, password=password))
        check("Anmeldung", status == 200, "Benutzer %s" % answer.get("user_name") if status == 200 else "HTTP %d" % status)
        return answer if status == 200 else None
    status, start = api(base, "code/start", dev)
    if status == 409:
        check("Code anfordern", False, "Quick Connect ist aus (einschalten oder --password)")
        return None
    if not check("Code anfordern", status == 200, "HTTP %d" % status):
        return None
    print("   Code: %s  - in einem angemeldeten Client bestätigen (Quick Connect), warte bis 10 Minuten ..."
          % start["code"])
    for _ in range(195):
        time.sleep(3)
        status, answer = api(base, "code/check", dict(dev, secret=start["secret"]))
        if status != 200:
            check("Code bestätigt", False, "abgelaufen oder abgelehnt (HTTP %d)" % status)
            return None
        if not answer.get("pending"):
            check("Code bestätigt", True, "Benutzer %s" % answer.get("user_name"))
            return answer
    check("Code bestätigt", False, "nicht innert 10 Minuten bestätigt")
    return None


def step_register(base, login, state_dir):
    print("3. Gerät registrieren")
    key = os.path.join(state_dir, "device.pem")
    old = os.umask(0o077)
    try:
        ossl(["genpkey", "-algorithm", "X25519", "-out", key])
    finally:
        os.umask(old)
    status, answer = api(base, "register", {"token": login["token"], "device_pub": public_raw(key).hex(),
                                            "platform": "other", "name": "Test-Gerät"})
    if not check("Registrieren", status == 200, "Gerät %s" % answer.get("device_id") if status == 200
                 else "HTTP %d %s" % (status, answer.get("error", ""))):
        return None
    state = {"device_id": answer["device_id"], "drop_url": answer["drop_url"], "sign_pub": answer["sign_pub"],
             "user": login.get("user_name", "")}
    with open(os.path.join(state_dir, "state.json"), "w") as fh:
        json.dump(state, fh, indent=2)
    check("Abruf-Adresse erhalten", bool(state["drop_url"]), state["drop_url"] or "leer: Ablage in portnook einrichten")
    return state if state["drop_url"] else None


def get_drop(state, state_dir):
    status, _, data, _ = http("GET", state["drop_url"])
    if status != 200:
        return None, "HTTP %d" % status if status else data.decode()
    try:
        return open_drop(data, os.path.join(state_dir, "device.pem"), bytes.fromhex(state["sign_pub"])), ""
    except ValueError as err:
        return None, str(err)


def step_fetch(state, state_dir, wait, target):
    print("4. Datei abholen: %s" % state["drop_url"])
    deadline = time.time() + wait
    while True:
        plain, err = get_drop(state, state_dir)
        if plain is not None or time.time() >= deadline or "Signatur" in err or "Prüfsumme" in err:
            break
        print("   noch nicht da (%s), neuer Versuch in 15 s ..." % err)
        time.sleep(15)
    if not check("Datei abrufbar, Signatur und Entschlüsselung", plain is not None, err):
        print("   Tipp: Upload in portnook ok (Weiterleitung -> Push-Ping -> Stand)? Ablage öffentlich lesbar?")
        return None
    show(plain)
    if target:
        check("Adresse = Ziel der Weiterleitung", origin(plain["url"]) == target,
              "%s / %s" % (origin(plain["url"]), target))
    status, _, data, _ = http("GET", plain["url"].rstrip("/") + "/_pn/hello")
    check("Adresse aus der Datei erreichbar", status == 200, "HTTP %d" % status if status else data.decode())
    return plain


def show(plain):
    print("   Adresse: %s   Nummer: %s   Zeit: %s" % (plain.get("url"), plain.get("seq"), time.strftime(
        "%d.%m.%Y %H:%M:%S", time.localtime(plain.get("ts", 0)))))
    if plain.get("cert"):
        print("   Zertifikat: %s" % plain["cert"])


def watch(state, state_dir, entry, every):
    """Fetch every ``every`` seconds and report each change of the file and of the redirect (Ctrl+C ends)."""
    print("Beobachte %s alle %d s (Ctrl+C beendet) ..." % (state["drop_url"], every))
    last, last_target = None, None
    try:
        while True:
            plain, err = get_drop(state, state_dir)
            target = ""
            if entry:
                status, _, _, location = http("GET", entry.rstrip("/") + "/", follow=False)
                target = origin(location) if location else ""
            now = time.strftime("%H:%M:%S")
            if plain is None:
                print("%s  Datei nicht lesbar: %s" % (now, err))
            elif last is None or plain.get("seq") != last.get("seq"):
                note = "" if not target else (" = Weiterleitung" if origin(plain["url"]) == target
                                              else " != Weiterleitung %s" % target)
                print("%s  Nummer %s: %s%s" % (now, plain.get("seq"), plain.get("url"), note))
                last = plain
            elif target and target != last_target and last_target is not None:
                print("%s  Weiterleitung jetzt %s, Datei noch %s" % (now, target, plain.get("url")))
            last_target = target or last_target
            time.sleep(every)
    except KeyboardInterrupt:
        print()


def load_state(state_dir):
    try:
        with open(os.path.join(state_dir, "state.json")) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        die("kein gespeichertes Gerät in %s, zuerst ohne --fetch/--watch starten" % state_dir)


def main():
    global OPENSSL
    ap = argparse.ArgumentParser(description="Test device for portnook push ping")
    ap.add_argument("entry", nargs="?", help="entry address, e.g. https://start.example.ch")
    ap.add_argument("--password", action="store_true", help="sign in with user and password instead of a code")
    ap.add_argument("--fetch", action="store_true", help="only fetch and open the file of the saved device")
    ap.add_argument("--watch", type=int, nargs="?", const=30, metavar="S",
                    help="fetch every S seconds (default 30) and report changes; Ctrl+C ends")
    ap.add_argument("--state", default="pn-test-device", help="folder for key and state (default ./pn-test-device)")
    ap.add_argument("--wait", type=int, default=300, help="seconds to wait for the file (default 300)")
    args = ap.parse_args()
    OPENSSL = find_openssl()
    os.makedirs(args.state, mode=0o700, exist_ok=True)
    if args.fetch or args.watch:
        state = load_state(args.state)
        if args.watch:
            return watch(state, args.state, args.entry, max(5, args.watch))
        target = ""
        if args.entry:
            _, target = step_entry(args.entry)
        step_fetch(state, args.state, args.wait, target)
        return summary()
    if not args.entry:
        ap.error("entry address missing")
    base, target = step_entry(args.entry)
    login = step_sign_in(base, args.password) if base else None
    state = step_register(base, login, args.state) if login else None
    if state:
        step_fetch(state, args.state, args.wait, target)
    return summary()


if __name__ == "__main__":
    sys.exit(main() or 0)
