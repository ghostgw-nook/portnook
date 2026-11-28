"""Push ping device registry (app/pushdevices.py) and device API (app/pushapi.py)."""

import http.client
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest

from app import httpc
from app.pushapi import _Server
from app.auth import Sessions
from app.pushdevices import AuthError, Devices
from app.store import Store
from app.validate import ValidationError

PUB = "ab" * 32
GOOD = "good-token-123"


class FakeMedia:
    """Stands in for ``httpc.request`` against ``/Users/Me``."""

    def __init__(self):
        self.calls = []
        self.users = {GOOD: {"Id": "0123456789abcdef0123456789abcdef", "Name": "Anna"},
                      "other-token-1": {"Id": "fedcba9876543210fedcba9876543210", "Name": "Ben"}}
        self.down = False

    def __call__(self, method, url, body=None, headers=None, device=None, timeout=20, **kw):
        self.calls.append((method, url, headers))
        if self.down:
            raise httpc.HttpError("connection refused")
        token = headers.get("X-Emby-Token")
        user = self.users.get(token)
        if user is None:
            return httpc.Response(401, {}, b"")
        return httpc.Response(200, {}, json.dumps(user).encode())


class DevicesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.media = FakeMedia()
        self.devices = Devices(self.tmp, self.store, request=self.media, clock=lambda: 1000)
        self.store.update("pushping", {"enabled": True, "media_url": "http://192.168.1.10:8096",
                                       "drop_base": "https://drop.example.ch/pn"})

    def test_register_checks_token_and_stores_device(self):
        answer = self.devices.register(GOOD, {"device_pub": PUB, "push_token": "fcm:abc", "platform": "ios",
                                              "name": "  iPhone   Anna "})
        self.assertEqual(self.media.calls[0][1], "http://192.168.1.10:8096/Users/Me")
        device = self.devices.get(answer["device_id"])
        self.assertEqual(device["user_name"], "Anna")
        self.assertEqual(device["name"], "iPhone Anna")
        self.assertEqual(device["platform"], "ios")
        self.assertTrue(answer["drop_url"].startswith("https://drop.example.ch/pn/"))
        self.assertTrue(answer["drop_url"].endswith(device["path"] + ".bin"))
        self.assertEqual(len(device["path"]), 32)
        self.assertEqual(stat.S_IMODE(os.stat(self.devices.path).st_mode), 0o600)
        with open(self.devices.path) as fh:
            self.assertNotIn(GOOD, fh.read())

    def test_bad_token_is_refused(self):
        for token in ("wrong-token-9", "", "x"):
            with self.assertRaises(AuthError):
                self.devices.register(token, {"device_pub": PUB})
        self.assertEqual(self.devices.list(), [])

    def test_media_server_down_is_refused(self):
        self.media.down = True
        with self.assertRaises(AuthError):
            self.devices.register(GOOD, {"device_pub": PUB})

    def test_bad_key_is_refused(self):
        for pub in ("", "zz" * 32, "00" * 32, "ab" * 31):
            with self.assertRaises(ValidationError):
                self.devices.register(GOOD, {"device_pub": pub})

    def test_update_only_for_same_user(self):
        device_id = self.devices.register(GOOD, {"device_pub": PUB})["device_id"]
        with self.assertRaises(AuthError):
            self.devices.update("other-token-1", {"device_id": device_id, "device_pub": "cd" * 32})
        self.devices.update(GOOD, {"device_id": device_id, "device_pub": "cd" * 32, "push_token": "fcm:new"})
        device = self.devices.get(device_id)
        self.assertEqual((device["pub"], device["push_token"]), ("cd" * 32, "fcm:new"))

    def test_update_unknown_device_is_refused(self):
        with self.assertRaises(AuthError):
            self.devices.update(GOOD, {"device_id": "0" * 16})

    def test_remove_and_reload(self):
        a = self.devices.register(GOOD, {"device_pub": PUB})["device_id"]
        b = self.devices.register(GOOD, {"device_pub": "cd" * 32})["device_id"]
        self.devices.remove(a)
        again = Devices(self.tmp, self.store, request=self.media)
        self.assertEqual([d["id"] for d in again.list()], [b])
        with self.assertRaises(ValidationError):
            self.devices.remove(a)

    def test_overview_hides_push_tokens(self):
        self.devices.register(GOOD, {"device_pub": PUB, "push_token": "fcm:secret"})
        text = json.dumps(self.devices.overview())
        self.assertNotIn("fcm:secret", text)
        self.assertTrue(self.devices.overview()["devices"][0]["push"])

    def test_settings_validation(self):
        with self.assertRaises(ValidationError):
            self.devices.set_settings({"enabled": True, "media_url": ""})
        with self.assertRaises(ValidationError):
            self.devices.set_settings({"enabled": False, "media_url": "ftp://x"})
        with self.assertRaises(ValidationError):
            self.devices.set_settings({"enabled": False, "port": 80})


class DeviceApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        store = Store(os.path.join(self.tmp, "agent.json"))
        store.update("pushping", {"enabled": True, "media_url": "http://192.168.1.10:8096"})
        self.devices = Devices(self.tmp, store, request=FakeMedia())
        self.server = _Server(("127.0.0.1", 0), self.devices, Sessions())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def post(self, path, body):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
        res = conn.getresponse()
        data = json.loads(res.read() or b"{}")
        conn.close()
        return res.status, data

    def test_hello(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        conn.request("GET", "/_pn/hello")
        res = conn.getresponse()
        data = res.read()
        self.assertEqual((res.status, json.loads(data)["ok"]), (200, True))
        self.assertNotIn(b"portnook", data)
        conn.close()

    def test_register_and_update(self):
        status, data = self.post("/_pn/register", {"token": GOOD, "device_pub": PUB, "platform": "android"})
        self.assertEqual(status, 200)
        status, _ = self.post("/_pn/device", {"token": GOOD, "device_id": data["device_id"], "push_token": "t"})
        self.assertEqual(status, 200)

    def test_bad_token_is_401_and_rate_limited(self):
        statuses = [self.post("/_pn/register", {"token": "wrong-token-9", "device_pub": PUB})[0]
                    for _ in range(12)]
        self.assertEqual(statuses[0], 401)
        self.assertEqual(statuses[-1], 429)

    def test_proxy_may_strip_the_prefix(self):
        status, data = self.post("/register", {"token": GOOD, "device_pub": PUB, "platform": "android"})
        self.assertEqual((status, bool(data.get("device_id"))), (200, True))

    def test_other_paths_are_404(self):
        self.assertEqual(self.post("/api/login", {"password": "x"})[0], 404)
        self.assertEqual(self.post("/_pn/other", {})[0], 404)

    def test_bad_input_is_400(self):
        self.assertEqual(self.post("/_pn/register", {"token": GOOD, "device_pub": "nope"})[0], 400)


class FakeJellyfin(FakeMedia):
    """``FakeMedia`` plus password and Quick Connect sign-in."""

    SECRET = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

    def __init__(self):
        super().__init__()
        self.confirmed = False
        self.qc_on = True

    def __call__(self, method, url, body=None, headers=None, device=None, timeout=20, **kw):
        path = url.split("8096", 1)[1]
        self.calls.append((method, path, headers, body))
        user = {"User": {"Id": "0123456789abcdef0123456789abcdef", "Name": "Anna"}, "AccessToken": GOOD,
                "ServerId": "srv1"}
        if path == "/Users/AuthenticateByName":
            ok = body == {"Username": "anna", "Pw": "pw-123"}
            return httpc.Response(200 if ok else 401, {}, json.dumps(user).encode() if ok else b"")
        if path == "/QuickConnect/Initiate":
            if not self.qc_on:
                return httpc.Response(401, {}, b"")
            return httpc.Response(200, {}, json.dumps({"Code": "123456", "Secret": self.SECRET}).encode())
        if path.startswith("/QuickConnect/Connect?secret="):
            if path.endswith(self.SECRET):
                return httpc.Response(200, {}, json.dumps({"Authenticated": self.confirmed}).encode())
            return httpc.Response(404, {}, b"")
        if path == "/Users/AuthenticateWithQuickConnect" and self.confirmed and body == {"Secret": self.SECRET}:
            return httpc.Response(200, {}, json.dumps(user).encode())
        return super().__call__(method, url, body, headers, device, timeout)


class SignInTest(unittest.TestCase):
    DEV = {"client": "Moonfin", "device": "Shield", "device_id": "abc123", "version": "1.2.0"}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        store = Store(os.path.join(self.tmp, "agent.json"))
        store.update("pushping", {"enabled": True, "media_url": "http://192.168.1.10:8096"})
        self.media = FakeJellyfin()
        self.devices = Devices(self.tmp, store, request=self.media)
        self.server = _Server(("127.0.0.1", 0), self.devices, Sessions())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def post(self, path, body):
        return DeviceApiTest.post(self, path, body)

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        conn.request("GET", path)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res, data

    def test_password_login_returns_token_and_registers(self):
        status, data = self.post("/_pn/login", dict(self.DEV, user="anna", password="pw-123"))
        self.assertEqual((status, data["token"], data["user_name"], data["server_id"]), (200, GOOD, "Anna", "srv1"))
        auth = self.media.calls[0][2]["Authorization"]
        self.assertIn('Client="Moonfin"', auth)
        self.assertIn('DeviceId="abc123"', auth)
        status, _ = self.post("/_pn/register", {"token": data["token"], "device_pub": PUB})
        self.assertEqual(status, 200)

    def test_wrong_password_is_401(self):
        self.assertEqual(self.post("/_pn/login", {"user": "anna", "password": "nope"})[0], 401)

    def test_device_fields_cannot_break_the_header(self):
        self.post("/_pn/login", {"user": "anna", "password": "pw-123", "client": 'x", Token="evil'})
        self.assertNotIn('Token="evil', self.media.calls[0][2]["Authorization"])

    def test_code_flow(self):
        status, start = self.post("/_pn/code/start", self.DEV)
        self.assertEqual((status, start["code"]), (200, "123456"))
        status, data = self.post("/_pn/code/check", {"secret": start["secret"]})
        self.assertEqual((status, data), (200, {"pending": True}))
        self.media.confirmed = True
        status, data = self.post("/_pn/code/check", {"secret": start["secret"]})
        self.assertEqual((status, data["token"]), (200, GOOD))

    def test_code_off_is_409(self):
        self.media.qc_on = False
        self.assertEqual(self.post("/_pn/code/start", {})[0], 409)

    def test_unknown_secret_is_401(self):
        self.assertEqual(self.post("/_pn/code/check", {"secret": "f" * 32})[0], 401)

    def test_code_starts_are_limited(self):
        statuses = [self.post("/_pn/code/start", {})[0] for _ in range(12)]
        self.assertEqual((statuses[0], statuses[-1]), (200, 429))

    def test_page_is_neutral(self):
        res, data = self.get("/_pn/")
        page = data.decode().lower()
        self.assertEqual(res.status, 200)
        self.assertIn("default-src 'none'", res.getheader("Content-Security-Policy"))
        for word in ("jellyfin", "emby", "portnook", "mediaserver", "media server", "film", "server"):
            self.assertNotIn(word, page)
        self.assertNotIn("portnook", (res.getheader("Server") or "").lower())

    def test_bare_prefix_redirects(self):
        res, _ = self.get("/_pn?client=x")
        self.assertEqual((res.status, res.getheader("Location")), (301, "/_pn/?client=x"))


class FakeEgress:
    def route(self, kind):
        return kind


class FakeRedirect:
    def __init__(self, agent):
        self.agent = agent

    def target(self):
        if not self.agent.ip or not self.agent.port:
            return None
        return {"url": "https://jf.familie-muster.example.ch:%d" % self.agent.port, "port": self.agent.port,
                "ip": self.agent.ip}


class FakeAgent:
    def __init__(self, store):
        self.store = store
        self.egress = FakeEgress()
        self.redirect = FakeRedirect(self)
        self.ip, self.port = "203.0.113.7", 51234


class FakeHost:
    """Stands in for the WebDAV host."""

    def __init__(self):
        self.files, self.calls, self.status = {}, [], None

    def __call__(self, method, url, body=None, headers=None, device=None, timeout=20, **kw):
        self.calls.append((method, url, headers, device))
        if self.status:
            return httpc.Response(self.status, {}, b"")
        name = url.rsplit("/", 1)[1]
        if method == "PUT":
            self.files[name] = body
            return httpc.Response(201, {}, b"")
        if method == "DELETE":
            return httpc.Response(204 if self.files.pop(name, None) is not None else 404, {}, b"")
        return httpc.Response(405, {}, b"")


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI missing")
class PublisherTest(unittest.TestCase):
    def setUp(self):
        from app import pushcrypto
        from app.pushdrop import Publisher
        self.pc = pushcrypto
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.now = [1000.0]
        self.devices = Devices(self.tmp, self.store, request=FakeMedia())
        self.devices.set_settings({"enabled": True, "media_url": "http://192.168.1.10:8096",
                                   "upload_url": "https://dav.example.ch/pn", "upload_user": "u",
                                   "upload_pass": "secret-pass"})
        self.host = FakeHost()
        self.agent = FakeAgent(self.store)
        self.pub = Publisher(self.agent, self.devices, request=self.host, clock=lambda: self.now[0])
        self.pings = []
        self.pub.after_publish.append(lambda: self.pings.append(self.now[0]))
        self.devkey = os.path.join(self.tmp, "dev.pem")
        pushcrypto.generate_x25519_key(self.devkey)
        self.dev = self.devices.register(GOOD, {"device_pub": pushcrypto.public_raw(self.devkey).hex()})

    def opened(self):
        name = self.devices.get(self.dev["device_id"])["path"] + ".bin"
        plain = self.pc.open_drop(self.host.files[name], self.devkey, self.devices.sign_pub())
        return json.loads(plain)

    def test_publishes_target_once_and_pings(self):
        self.pub.tick()
        data = self.opened()
        self.assertEqual((data["url"], data["seq"]), ("https://jf.familie-muster.example.ch:51234", 1))
        self.assertEqual(self.host.calls[0][3], "internet")
        self.assertTrue(self.host.calls[0][2]["Authorization"].startswith("Basic "))
        self.pub.tick()
        self.assertEqual(len(self.host.calls), 1)
        self.assertEqual(len(self.pings), 1)

    def test_port_change_republishes_and_pings(self):
        self.pub.tick()
        self.agent.port = 40000
        self.pub.tick()
        self.assertEqual((self.opened()["url"], self.opened()["seq"]), ("https://jf.familie-muster.example.ch:40000", 2))
        self.assertEqual(len(self.pings), 2)

    def test_drop_url_falls_back_to_upload_url(self):
        self.assertEqual(self.dev["drop_url"], "https://dav.example.ch/pn/%s.bin"
                         % self.devices.get(self.dev["device_id"])["path"])

    def test_no_refresh_by_default(self):
        self.pub.tick()
        self.now[0] += 30 * 24 * 3600
        self.pub.tick()
        self.assertEqual((self.opened()["seq"], len(self.host.calls)), (1, 1))

    def test_refresh_when_set_without_ping(self):
        self.devices.set_settings({"enabled": True, "media_url": "http://192.168.1.10:8096",
                                   "upload_url": "https://dav.example.ch/pn", "refresh_hours": 12})
        self.pub.tick()
        self.now[0] += 11 * 3600
        self.pub.tick()
        self.assertEqual(self.opened()["seq"], 1)
        self.now[0] += 3600 + 1
        self.pub.tick()
        self.assertEqual((self.opened()["seq"], len(self.pings)), (2, 1))

    def test_refresh_hours_checked(self):
        with self.assertRaises(ValidationError):
            self.devices.set_settings({"enabled": True, "media_url": "http://192.168.1.10:8096", "refresh_hours": 500})

    def test_no_target_no_upload(self):
        self.agent.ip = ""
        self.pub.tick()
        self.assertEqual(self.host.calls, [])

    def test_failure_waits_and_retries(self):
        self.host.status = 500
        self.pub.tick()
        self.assertIn("500", self.pub.status()["last_error"])
        self.host.status = None
        self.pub.tick()
        self.assertEqual(len(self.host.calls), 1)
        self.now[0] += 301
        self.pub.tick()
        self.assertEqual(self.opened()["url"], "https://jf.familie-muster.example.ch:51234")

    def test_removed_device_file_is_deleted(self):
        self.pub.tick()
        self.devices.remove(self.dev["device_id"])
        self.pub.tick()
        self.assertEqual(self.host.files, {})
        self.assertEqual(self.devices.orphans(), [])

    def test_password_is_write_only(self):
        self.devices.set_settings({"enabled": True, "media_url": "http://192.168.1.10:8096",
                                   "upload_url": "https://dav.example.ch/pn", "upload_user": "u"})
        self.assertEqual(self.store.section("pushping")["upload_pass"], "secret-pass")
        status = json.dumps(self.pub.status()) + json.dumps(self.devices.overview())
        self.assertNotIn("secret-pass", status)
        self.assertTrue(self.pub.status()["upload_pass_set"])


class FakeCloudflare:
    """Cloudflare API for the drop Worker: zone, workers.dev subdomain, script upload."""

    ZONE = "0123456789abcdef0123456789abcdef"

    def __init__(self):
        self.calls, self.table, self.enabled, self.status = [], None, False, 200

    def __call__(self, method, url, body=None, headers=None, device=None, timeout=20, **kw):
        path = url.split("/client/v4", 1)[1]
        self.calls.append((method, path, device))
        ok = lambda res: httpc.Response(200, {}, json.dumps({"success": True, "result": res}).encode())
        if method == "GET" and path == "/zones/" + self.ZONE:
            return ok({"account": {"id": "acc1"}})
        if method == "GET" and path == "/accounts/acc1/workers/subdomain":
            return ok({"subdomain": "familie-muster"})
        if method == "PUT" and path == "/accounts/acc1/workers/scripts/portnook-drops":
            if self.status != 200:
                return httpc.Response(self.status, {}, b"{}")
            js = body.decode()
            self.table = json.loads(js.split("const D = ", 1)[1].split(";\n", 1)[0])
            return ok({})
        if method == "POST" and path == "/accounts/acc1/workers/scripts/portnook-drops/subdomain":
            self.enabled = body == {"enabled": True, "previews_enabled": False}
            return ok({})
        return httpc.Response(404, {}, b"{}")


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI missing")
class CloudflareStorageTest(unittest.TestCase):
    def setUp(self):
        from app import pushcrypto
        from app.pushdrop import Publisher
        self.pc = pushcrypto
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.store.update("redirect", {"provider": "cloudflare", "cf": {"token": "cf-token-1", "zone": FakeCloudflare.ZONE}})
        self.devices = Devices(self.tmp, self.store, request=FakeMedia())
        self.devices.set_settings({"enabled": True, "media_url": "http://192.168.1.10:8096", "storage": "cloudflare"})
        self.cf = FakeCloudflare()
        self.agent = FakeAgent(self.store)
        self.pub = Publisher(self.agent, self.devices, request=self.cf, clock=lambda: 1000.0)
        self.pub.resolve()
        self.devkey = os.path.join(self.tmp, "dev.pem")
        pushcrypto.generate_x25519_key(self.devkey)
        self.dev = self.devices.register(GOOD, {"device_pub": pushcrypto.public_raw(self.devkey).hex()})

    def test_worker_serves_the_drop(self):
        path = self.devices.get(self.dev["device_id"])["path"]
        self.assertEqual(self.dev["drop_url"], "https://portnook-drops.familie-muster.workers.dev/%s.bin" % path)
        self.pub.tick()
        import base64
        plain = json.loads(self.pc.open_drop(base64.b64decode(self.cf.table[path]), self.devkey, self.devices.sign_pub()))
        self.assertEqual(plain["url"], "https://jf.familie-muster.example.ch:51234")
        self.assertTrue(self.cf.enabled)
        self.assertTrue(all(c[2] == "internet" for c in self.cf.calls))
        self.assertNotIn("published_drop", json.dumps(self.devices.overview()))

    def test_removed_device_leaves_the_worker(self):
        self.pub.tick()
        self.devices.remove(self.dev["device_id"])
        self.pub.tick()
        self.assertEqual((self.cf.table, self.devices.orphans()), ({}, []))

    def test_upload_error_is_retried(self):
        self.cf.status = 403
        self.pub.tick()
        self.assertIn("403", self.pub.status()["last_error"])
        self.assertFalse(self.devices.get(self.dev["device_id"]).get("published_at"))

    def test_without_cloudflare_token_nothing_happens(self):
        self.store.update("redirect", {"provider": "script", "cf": {}})
        self.cf.calls = []
        self.pub.tick()
        self.assertEqual(self.cf.calls, [])


class FakeSshRedirect:
    """Redirect with an SSH key; ``_p`` paths and the target as the real one has them."""

    def __init__(self, agent, tmp):
        self.agent, self.tmp = agent, tmp

    def _p(self, name):
        return os.path.join(self.tmp, name)

    def ssh_public(self):
        return "ssh-ed25519 AAAA portnook"

    def target(self):
        return {"url": "https://jf.familie-muster.example.ch:51234", "host": "jf.familie-muster.example.ch",
                "port": 51234, "ip": "203.0.113.7"}


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI missing")
class ScriptStorageTest(unittest.TestCase):
    """The remote command runs for real in a local shell (the web space is a temp folder)."""

    def setUp(self):
        from app import pushcrypto, pushstore
        from app.pushdrop import Publisher
        self.pc, self.ps = pushcrypto, pushstore
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.web = os.path.join(self.tmp, "web")
        os.makedirs(os.path.join(self.web, "httpdocs"))
        self.store = Store(os.path.join(self.tmp, "agent.json"))
        self.store.update("redirect", {"provider": "script", "entry_host": "start.example.ch",
                                       "gen": {"kind": "htaccess", "user": "web1", "host": "server.example.ch",
                                               "port": 2222, "root": "httpdocs"}})
        self.devices = Devices(self.tmp, self.store, request=FakeMedia())
        self.devices.set_settings({"enabled": True, "media_url": "http://192.168.1.10:8096", "storage": "script"})
        self.agent = FakeAgent(self.store)
        self.agent.redirect = FakeSshRedirect(self.agent, self.tmp)
        self.calls = []
        real = subprocess.run

        def fake_run(args, input=b"", **kw):
            self.calls.append(args)
            return real(["sh", "-c", args[-1]], input=input, cwd=self.web, **kw)
        self.ps._run = fake_run
        self.addCleanup(setattr, self.ps, "_run", real)
        self.pub = Publisher(self.agent, self.devices, request=None, clock=lambda: 1000.0)
        self.pub.resolve()
        self.devkey = os.path.join(self.tmp, "dev.pem")
        pushcrypto.generate_x25519_key(self.devkey)
        self.dev = self.devices.register(GOOD, {"device_pub": pushcrypto.public_raw(self.devkey).hex()})

    def test_file_lands_in_the_web_space(self):
        path = self.devices.get(self.dev["device_id"])["path"]
        self.assertEqual(self.dev["drop_url"], "https://start.example.ch/_pnd/%s.bin" % path)
        self.pub.tick()
        folder = os.path.join(self.web, "httpdocs", "_pnd")
        with open(os.path.join(folder, path + ".bin"), "rb") as fh:
            plain = json.loads(self.pc.open_drop(fh.read(), self.devkey, self.devices.sign_pub()))
        self.assertEqual(plain["url"], "https://jf.familie-muster.example.ch:51234")
        with open(os.path.join(folder, ".htaccess")) as fh:
            self.assertEqual(fh.read(), self.ps.DIR_HTACCESS)
        self.assertTrue(os.path.exists(os.path.join(folder, "index.html")))
        args = self.calls[0]
        self.assertIn("web1@server.example.ch", args)
        self.assertEqual(args[args.index("-p") + 1], "2222")

    def test_removed_device_file_is_deleted(self):
        self.pub.tick()
        path = self.devices.get(self.dev["device_id"])["path"]
        self.devices.remove(self.dev["device_id"])
        self.pub.tick()
        self.assertFalse(os.path.exists(os.path.join(self.web, "httpdocs", "_pnd", path + ".bin")))
        self.assertEqual(self.devices.orphans(), [])

    def test_htaccess_leaves_drop_folder_alone(self):
        from app.redirect import htaccess
        self.assertIn("RewriteCond %{REQUEST_URI} !^/_pnd/", htaccess([("start.example.ch", "https://a:1")], 302))

    def test_not_ready_without_generator(self):
        self.store.update("redirect", {"gen": {"kind": ""}})
        self.calls = []
        self.pub.tick()
        self.assertEqual(self.calls, [])


class FakeGoogle:
    def __init__(self):
        self.calls = []
        self.send_status, self.send_body = 200, b"{}"

    def __call__(self, method, url, body=None, headers=None, device=None, timeout=20, **kw):
        self.calls.append((url, body, headers, device))
        if "oauth2" in url:
            return httpc.Response(200, {}, json.dumps({"access_token": "ya29.test", "expires_in": 3600}).encode())
        return httpc.Response(self.send_status, {}, self.send_body)


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI missing")
class FcmTest(unittest.TestCase):
    def setUp(self):
        import subprocess
        from app.pushfcm import Fcm
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        store = Store(os.path.join(self.tmp, "agent.json"))
        store.update("pushping", {"enabled": True, "media_url": "http://192.168.1.10:8096"})
        self.devices = Devices(self.tmp, store, request=FakeMedia())
        self.google = FakeGoogle()
        self.fcm = Fcm(FakeAgent(store), self.devices, request=self.google, clock=lambda: 1000)
        key = subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
                             universal_newlines=True).stdout
        self.account = json.dumps({"type": "service_account", "project_id": "demo-project",
                                   "client_email": "pn@demo-project.iam.gserviceaccount.com", "private_key": key})
        self.android = self.devices.register(GOOD, {"device_pub": PUB, "push_token": "tok-a", "platform": "android"})
        self.devices.register(GOOD, {"device_pub": "cd" * 32, "push_token": "tok-i", "platform": "ios"})

    def test_account_is_write_only(self):
        status = self.fcm.set_account({"service_account": self.account})
        self.assertEqual((status["project_id"], status["account_set"]), ("demo-project", True))
        self.assertNotIn("PRIVATE KEY", json.dumps(status))
        with open(self.fcm.meta_path) as fh:
            self.assertNotIn("PRIVATE KEY", fh.read())
        self.assertEqual(stat.S_IMODE(os.stat(self.fcm.key_path).st_mode), 0o600)

    GS = {"project_info": {"project_number": "123456789012", "project_id": "demo-project"},
          "client": [{"client_info": {"mobilesdk_app_id": "1:123456789012:android:abc",
                                      "android_client_info": {"package_name": "org.moonfin.androidtv.test"}},
                      "api_key": [{"current_key": "AIzaDemoKey"}]}]}

    def test_app_config_goes_to_android_devices(self):
        self.fcm.set_client({"google_services": json.dumps(self.GS)})
        self.devices.fcm_options = self.fcm.client_options
        android = self.devices.register(GOOD, {"device_pub": "ef" * 32, "platform": "android"})
        ios = self.devices.register(GOOD, {"device_pub": "fe" * 32, "platform": "ios"})
        self.assertEqual(android["fcm"], {"api_key": "AIzaDemoKey", "app_id": "1:123456789012:android:abc",
                                          "project_id": "demo-project", "sender_id": "123456789012"})
        self.assertNotIn("fcm", ios)
        self.assertEqual(self.fcm.status()["client_apps"], ["org.moonfin.androidtv.test"])

    def test_bad_app_config_is_refused(self):
        for value in ("nope", json.dumps({"client": []}), json.dumps({"project_info": {"project_id": "x",
                                                                                     "project_number": "1"}})):
            with self.assertRaises(ValidationError):
                self.fcm.set_client({"google_services": value})

    def test_bad_account_is_refused(self):
        for value in ("nope", json.dumps({"type": "user"}), json.dumps({"type": "service_account"})):
            with self.assertRaises(ValidationError):
                self.fcm.set_account({"service_account": value})

    def test_ping_only_android_with_empty_data(self):
        self.fcm.set_account({"service_account": self.account})
        self.assertEqual(self.fcm.ping_all(), 1)
        token_call, send_call = self.google.calls
        assertion = dict(x.split("=", 1) for x in token_call[1].split("&"))["assertion"]
        self.assertEqual(len(assertion.split(".")), 3)
        self.assertEqual(send_call[0], "https://fcm.googleapis.com/v1/projects/demo-project/messages:send")
        msg = send_call[1]["message"]
        self.assertEqual((msg["token"], msg["data"]), ("tok-a", {"t": "refresh"}))
        self.assertEqual(send_call[2]["Authorization"], "Bearer ya29.test")
        self.assertEqual(send_call[3], "internet")
        self.fcm.ping_all()
        self.assertEqual(sum("oauth2" in c[0] for c in self.google.calls), 1)  # token cached

    def test_unregistered_token_is_dropped(self):
        self.fcm.set_account({"service_account": self.account})
        self.google.send_status, self.google.send_body = 404, b'{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}'
        self.assertEqual(self.fcm.ping_all(), 0)
        self.assertEqual(self.devices.get(self.android["device_id"])["push_token"], "")

    def test_without_account_nothing_is_sent(self):
        self.assertEqual(self.fcm.ping_all(), 0)
        self.assertEqual(self.google.calls, [])


if __name__ == "__main__":
    unittest.main()
