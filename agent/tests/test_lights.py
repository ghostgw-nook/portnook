import unittest

from app import lights

NOW = 1763300000


def status(**kw):
    s = {"time": NOW,
         "proton": {"enabled": True, "up": True, "handshake": NOW - 30, "port": 51234,
                    "natpmp": {"active": True, "ok": True, "last_ok": NOW - 10, "fails": 0}},
         "backend": {"checked": NOW - 5, "ok": True, "latency_ms": 4},
         "ddns": {"configured": True, "last_ok": NOW - 60, "last_try": NOW - 60, "error": ""},
         "cert": {"present": True, "days_left": 80.0, "last_error": ""},
         "delivery": {"npm": {"configured": True, "last_ok": NOW - 100, "error": ""},
                      "zoraxy": {"configured": False}},
         "redirect": {"provider": "script", "target": "https://a:1", "last_target": "https://a:1",
                      "last_ok": NOW - 10, "last_error": ""}}
    for k, v in kw.items():
        s[k] = dict(s[k], **v)
    return s


class AgentLightsTest(unittest.TestCase):
    def test_all_ok(self):
        r = lights.evaluate(status())
        self.assertEqual(r["overall"], "ok")
        self.assertEqual(set(r["checks"]), {"proton", "natpmp", "backend", "ddns", "cert", "delivery", "redirect"})

    def test_proton(self):
        self.assertEqual(lights.proton({"enabled": False}, NOW), "unknown")
        self.assertEqual(lights.proton({"enabled": True, "up": False}, NOW), "error")
        self.assertEqual(lights.proton({"enabled": True, "up": True, "handshake": NOW - 179}, NOW), "ok")
        self.assertEqual(lights.proton({"enabled": True, "up": True, "handshake": NOW - 180}, NOW), "error")
        self.assertEqual(lights.proton({"enabled": True, "up": True, "handshake": 0}, NOW), "error")

    def test_natpmp(self):
        self.assertEqual(lights.natpmp({"enabled": False}), "unknown")
        self.assertEqual(lights.natpmp({"enabled": True, "port": 1, "natpmp": {"fails": 0}}), "ok")
        self.assertEqual(lights.natpmp({"enabled": True, "port": 1, "natpmp": {"fails": 2}}), "warn")
        self.assertEqual(lights.natpmp({"enabled": True, "port": 0, "natpmp": {"active": True, "fails": 1}}), "error")
        self.assertEqual(lights.natpmp({"enabled": True, "port": 0, "natpmp": {}}), "unknown")

    def test_backend(self):
        self.assertEqual(lights.backend({}), "unknown")
        self.assertEqual(lights.backend({"checked": 1, "ok": True, "latency_ms": 300}), "ok")
        self.assertEqual(lights.backend({"checked": 1, "ok": True, "latency_ms": 301}), "warn")
        self.assertEqual(lights.backend({"checked": 1, "ok": False}), "error")

    def test_ddns(self):
        d = status()["ddns"]
        self.assertEqual(lights.ddns({"configured": False}, NOW), "unknown")
        self.assertEqual(lights.ddns(d, NOW), "ok")
        self.assertEqual(lights.ddns(dict(d, error="x"), NOW), "warn")
        self.assertEqual(lights.ddns(dict(d, error="x", last_ok=NOW - 90000), NOW), "error")
        self.assertEqual(lights.ddns(dict(d, last_ok=0, last_try=0), NOW), "unknown")

    def test_cert(self):
        self.assertEqual(lights.cert({}), "unknown")
        self.assertEqual(lights.cert({"present": True, "days_left": 30}), "ok")
        self.assertEqual(lights.cert({"present": True, "days_left": 20}), "warn")
        self.assertEqual(lights.cert({"present": True, "days_left": 3}), "error")
        self.assertEqual(lights.cert({"present": False, "last_error": "boom"}), "error")

    def test_delivery_and_redirect(self):
        self.assertEqual(lights.delivery({"npm": {"configured": False}}), "unknown")
        self.assertEqual(lights.delivery({"npm": {"configured": True, "error": "x"}}), "error")
        r = status()["redirect"]
        self.assertEqual(lights.redirect(r), "ok")
        self.assertEqual(lights.redirect(dict(r, target="https://a:2")), "warn")
        self.assertEqual(lights.redirect(dict(r, last_error="x")), "error")
        self.assertEqual(lights.redirect({"provider": ""}), "unknown")

    def test_overall_worst_known(self):
        self.assertEqual(lights.evaluate(status(cert={"days_left": 20}))["overall"], "warn")
        self.assertEqual(lights.evaluate(status(backend={"ok": False}))["overall"], "error")
        # without Proton and without DDNS only the known checks count
        r = lights.evaluate(status(proton={"enabled": False}, ddns={"configured": False}))
        self.assertEqual(r["checks"]["proton"], "unknown")
        self.assertEqual(r["checks"]["ddns"], "unknown")
        self.assertEqual(r["overall"], "ok")
        self.assertEqual(lights.overall(["unknown"]), "unknown")


if __name__ == "__main__":
    unittest.main()
