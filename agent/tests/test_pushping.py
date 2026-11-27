"""Push ping device registry (app/pushdevices.py) and device API (app/pushapi.py)."""

import http.client
import json
import os
import shutil
import stat
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
        self.assertEqual((res.status, json.loads(res.read())["ok"]), (200, True))
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

    def test_other_paths_are_404(self):
        self.assertEqual(self.post("/api/login", {"password": "x"})[0], 404)
        self.assertEqual(self.post("/_pn/other", {})[0], 404)

    def test_bad_input_is_400(self):
        self.assertEqual(self.post("/_pn/register", {"token": GOOD, "device_pub": "nope"})[0], 400)


if __name__ == "__main__":
    unittest.main()
