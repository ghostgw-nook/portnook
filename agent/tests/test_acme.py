"""ACME helpers with the real openssl CLI (the full flow runs against pebble in .github/scripts/e2e.sh)."""

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from app import acme

HAVE_OPENSSL = shutil.which("openssl") is not None


@unittest.skipUnless(HAVE_OPENSSL, "openssl CLI missing")
class AcmeCryptoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.key = os.path.join(self.tmp, "account.key")
        acme.generate_key(self.key)

    def test_key_600_and_point(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.key).st_mode), 0o600)
        x, y = acme.public_point(self.key)
        self.assertEqual((len(x), len(y)), (32, 32))

    def test_signature_verifies(self):
        data = b"eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0Ijp0cnVlfQ"
        raw = acme.sign(self.key, data)
        self.assertEqual(len(raw), 64)
        der = acme.raw_to_der(raw)
        self.assertEqual(acme.der_to_raw(der), raw)
        sig = os.path.join(self.tmp, "sig")
        pub = os.path.join(self.tmp, "pub.pem")
        with open(sig, "wb") as fh:
            fh.write(der)
        subprocess.run(["openssl", "pkey", "-in", self.key, "-pubout", "-out", pub], check=True)
        res = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig], input=data,
                             capture_output=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_der_padding(self):
        # r with leading zero byte and s with high bit set
        raw = b"\x00" + b"\x11" * 31 + b"\xff" * 32
        self.assertEqual(acme.der_to_raw(acme.raw_to_der(raw)), raw)
        with self.assertRaises(acme.AcmeError):
            acme.der_to_raw(b"\x31\x00")

    def test_thumbprint_and_dns01(self):
        x, y = acme.public_point(self.key)
        jwk = {"crv": "P-256", "kty": "EC", "x": acme.b64u(x), "y": acme.b64u(y)}
        canon = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (jwk["x"], jwk["y"])
        self.assertEqual(json.dumps(jwk, sort_keys=True, separators=(",", ":")), canon)
        value = acme.dns01_value("tok", "thumb")
        self.assertEqual(value, base64.urlsafe_b64encode(hashlib.sha256(b"tok.thumb").digest()).rstrip(b"=").decode())
        self.assertEqual(len(value), 43)  # what myaddr.tools accepts

    def test_csr_and_self_signed_info(self):
        doms = ["familie-muster.myaddr.tools", "*.familie-muster.myaddr.tools"]
        der = acme.csr_der(self.key, doms)
        res = subprocess.run(["openssl", "req", "-inform", "DER", "-noout", "-text"], input=der, capture_output=True)
        self.assertIn(b"DNS:*.familie-muster.myaddr.tools", res.stdout)
        cert = subprocess.run(["openssl", "req", "-x509", "-key", self.key, "-subj", "/CN=" + doms[0], "-days", "10",
                               "-addext", "subjectAltName=DNS:%s,DNS:%s" % tuple(doms)],
                              capture_output=True, check=True).stdout.decode()
        info = acme.cert_info(cert)
        self.assertEqual(info["names"], doms)
        self.assertGreater(info["not_after"], info["not_before"])
        self.assertAlmostEqual(info["not_after"] - info["not_before"], 10 * 86400, delta=120)
        self.assertTrue(acme.key_matches(cert, self.key))
        other = os.path.join(self.tmp, "other.key")
        acme.generate_key(other)
        self.assertFalse(acme.key_matches(cert, other))
        leaf, rest = acme.split_chain(cert + cert)
        self.assertEqual(leaf.strip(), cert.strip())
        self.assertEqual(rest.strip(), cert.strip())
        with self.assertRaises(acme.AcmeError):
            acme.split_chain("nothing")


class ProblemTest(unittest.TestCase):
    def test_problem_text(self):
        t = acme.problem_text({"type": "urn:ietf:params:acme:error:rateLimited", "detail": "too many\ncerts"}, 429)
        self.assertEqual(t, "ACME-Fehler (HTTP 429, rateLimited): too many certs")
        self.assertEqual(acme.object_error({"challenges": [{"error": {"type": "x:dns", "detail": "no TXT"}}]}, "invalid"),
                         "ACME-Fehler (dns): no TXT")


if __name__ == "__main__":
    unittest.main()
