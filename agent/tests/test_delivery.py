import json
import os
import shutil
import stat
import tempfile
import unittest

from app import delivery
from app.validate import ValidationError
from tests.fakes import FakeHttp

LEAF = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
INTER = "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n"
KEYPEM = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"


class FakeNpm:
    """Just enough of the NPM API (routes/tokens.js, routes/nginx/certificates.js)."""

    def __init__(self, two_fa=False):
        self.certs = [{"id": 3, "provider": "letsencrypt", "nice_name": "other.example"}]
        self.uploads = []
        self.two_fa = two_fa
        self.srv = FakeHttp(self.handle)
        self.url = self.srv.url

    def handle(self, method, path, headers, body):
        if path == "/api/tokens" and method == "POST":
            data = json.loads(body)
            if data != {"identity": "pf@example.ch", "secret": "npm-pass"}:
                return 401, {"error": {"code": 401, "message": "Invalid email or password"}}
            if self.two_fa:
                return 200, {"requires_2fa": True, "challenge_token": "x"}
            return 200, {"token": "JWT", "expires": "2030-01-01T00:00:00Z"}
        if headers.get("Authorization") != "Bearer JWT":
            return 401, {"error": {"message": "auth"}}
        if path == "/api/nginx/certificates" and method == "GET":
            return 200, self.certs
        if path == "/api/nginx/certificates" and method == "POST":
            data = json.loads(body)
            new = {"id": 10 + len(self.certs), "provider": data["provider"], "nice_name": data["nice_name"]}
            self.certs.append(new)
            return 201, new
        if path.endswith("/upload") and method == "POST":
            self.uploads.append((int(path.split("/")[4]), headers.get("Content-Type"), body))
            return 200, {"certificate": "x"}
        return 404, {"error": {"message": "not found"}}


class NpmTest(unittest.TestCase):
    def setUp(self):
        try:
            self.npm = FakeNpm()
        except OSError as err:
            self.skipTest("cannot bind local port: %s" % err)
        self.addCleanup(self.npm.srv.close)
        self.cfg = {"url": self.npm.url, "identity": "pf@example.ch", "secret": "npm-pass",
                    "nice_name": "portnook familie-muster.myaddr.tools"}

    def test_create_then_reuse_same_id(self):
        cid = delivery.npm_push(self.cfg, LEAF + INTER, KEYPEM)
        self.assertEqual(cid, 11)
        self.assertEqual(self.npm.certs[-1]["provider"], "other")
        cid2 = delivery.npm_push(dict(self.cfg, cert_id=cid), LEAF + INTER, KEYPEM)
        self.assertEqual(cid2, cid)
        self.assertEqual(len(self.npm.certs), 2)  # no second certificate
        self.assertEqual([u[0] for u in self.npm.uploads], [11, 11])
        cid_, ctype, body = self.npm.uploads[0]
        self.assertTrue(ctype.startswith("multipart/form-data; boundary="))
        text = body.decode()
        self.assertIn('name="certificate"; filename="cert.pem"', text)
        self.assertIn('name="certificate_key"; filename="privkey.pem"', text)
        self.assertIn('name="intermediate_certificate"; filename="chain.pem"', text)
        self.assertIn("LEAF", text)
        self.assertIn("INTER", text.split('name="intermediate_certificate"')[1])
        self.assertNotIn("INTER", text.split('name="certificate_key"')[0])

    def test_wrong_password_and_2fa(self):
        with self.assertRaises(delivery.DeliveryError) as ctx:
            delivery.npm_push(dict(self.cfg, secret="wrong"), LEAF, KEYPEM)
        self.assertIn("401", str(ctx.exception))
        self.assertNotIn("wrong", str(ctx.exception))
        self.npm.two_fa = True
        with self.assertRaises(delivery.DeliveryError) as ctx:
            delivery.npm_push(self.cfg, LEAF, KEYPEM)
        self.assertIn("2FA", str(ctx.exception))

    def test_url_validation(self):
        self.assertEqual(delivery.check_npm_url("http://192.168.1.10:81/"), "http://192.168.1.10:81")
        self.assertEqual(delivery.check_npm_url("http://npm.lan:81"), "http://npm.lan:81")
        for bad in ("ftp://192.168.1.10", "http://8.8.8.8:81", "http://192.168.1.10:81/api", "192.168.1.10:81"):
            with self.assertRaises(ValidationError, msg=bad):
                delivery.check_npm_url(bad)
        self.assertTrue(delivery.lan_host_ok("npm.lan", lambda h: ["192.168.1.10"]))
        self.assertFalse(delivery.lan_host_ok("npm.lan", lambda h: ["192.168.1.10", "203.0.113.5"]))
        self.assertFalse(delivery.lan_host_ok("npm.lan", lambda h: []))


class ZoraxyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_write_pair(self):
        names = delivery.zoraxy_write(self.tmp, "familie-muster.myaddr.tools", LEAF + INTER, KEYPEM)
        self.assertEqual(names, ["familie-muster.myaddr.tools.key", "familie-muster.myaddr.tools.pem"])
        key = os.path.join(self.tmp, "familie-muster.myaddr.tools.key")
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        with open(os.path.join(self.tmp, "familie-muster.myaddr.tools.pem")) as fh:
            self.assertEqual(fh.read(), LEAF + INTER)
        self.assertEqual(sorted(os.listdir(self.tmp)), sorted(names))  # no temp files left
        with self.assertRaises(delivery.DeliveryError):
            delivery.zoraxy_write(os.path.join(self.tmp, "missing"), "a.myaddr.tools", LEAF, KEYPEM)
        with self.assertRaises(delivery.DeliveryError):
            delivery.zoraxy_write(self.tmp, "../x", LEAF, KEYPEM)

    def test_dir_validation(self):
        self.assertEqual(delivery.check_zoraxy_dir("/zoraxy-certs/"), "/zoraxy-certs")
        for bad in ("relative", "/", "/data", "/data/certs", "/etc/ssl", "/proc/x"):
            with self.assertRaises(ValidationError, msg=bad):
                delivery.check_zoraxy_dir(bad)


if __name__ == "__main__":
    unittest.main()
