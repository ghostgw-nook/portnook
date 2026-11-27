"""Sealed address drops (app/pushcrypto.py) with the real openssl CLI and fixed test vectors."""

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from app import pushcrypto as pc

VECTORS = os.path.join(os.path.dirname(__file__), "data", "push_drop_vectors.json")


def _openssl_has_ed25519():
    if shutil.which("openssl") is None:
        return False
    res = subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, check=False)
    return res.returncode == 0


HAVE_OPENSSL = _openssl_has_ed25519()


class PrimitiveTest(unittest.TestCase):
    def test_hkdf_rfc5869_case_1(self):
        okm = pc.hkdf(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                      bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                    "34007208d5b887185865")

    def test_keystream_roundtrip_and_length(self):
        data = bytes(range(70))
        enc = pc.keystream_xor(b"k" * 32, b"n" * 16, data)
        self.assertEqual(len(enc), 70)
        self.assertNotEqual(enc, data)
        self.assertEqual(pc.keystream_xor(b"k" * 32, b"n" * 16, enc), data)


@unittest.skipUnless(HAVE_OPENSSL, "openssl CLI with Ed25519/X25519 missing")
class DropTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        with open(VECTORS) as fh:
            self.vec = json.load(fh)
        self.paths = {}
        for name in ("sign_key_pem", "device_key_pem", "ephemeral_key_pem"):
            path = os.path.join(self.tmp, name)
            with open(path, "w") as fh:
                fh.write(self.vec[name])
            self.paths[name] = path

    def test_vector_is_reproduced(self):
        drop = pc.seal(self.vec["plaintext"].encode(), bytes.fromhex(self.vec["device_pub"]),
                       self.paths["sign_key_pem"], _eph_key_path=self.paths["ephemeral_key_pem"],
                       _nonce=bytes.fromhex(self.vec["nonce"]))
        self.assertEqual(drop.hex(), self.vec["drop"])

    def test_vector_opens(self):
        plain = pc.open_drop(bytes.fromhex(self.vec["drop"]), self.paths["device_key_pem"],
                             bytes.fromhex(self.vec["sign_pub"]))
        self.assertEqual(plain.decode(), self.vec["plaintext"])

    def test_public_keys_match_vector(self):
        self.assertEqual(pc.public_raw(self.paths["sign_key_pem"]).hex(), self.vec["sign_pub"])
        self.assertEqual(pc.public_raw(self.paths["device_key_pem"]).hex(), self.vec["device_pub"])

    def test_fresh_drops_differ_and_open(self):
        args = (b"hello", bytes.fromhex(self.vec["device_pub"]), self.paths["sign_key_pem"])
        a, b = pc.seal(*args), pc.seal(*args)
        self.assertNotEqual(a, b)
        sign_pub = bytes.fromhex(self.vec["sign_pub"])
        self.assertEqual(pc.open_drop(a, self.paths["device_key_pem"], sign_pub), b"hello")
        self.assertEqual(pc.open_drop(b, self.paths["device_key_pem"], sign_pub), b"hello")

    def test_tampered_drop_is_rejected(self):
        drop = bytearray(bytes.fromhex(self.vec["drop"]))
        sign_pub = bytes.fromhex(self.vec["sign_pub"])
        for i in (5, pc.HEADER_LEN + 1, len(drop) - pc.SIG_LEN - 1, len(drop) - 1):
            bad = bytearray(drop)
            bad[i] ^= 1
            with self.assertRaises(pc.DropError):
                pc.open_drop(bytes(bad), self.paths["device_key_pem"], sign_pub)

    def test_other_signer_is_rejected(self):
        other = os.path.join(self.tmp, "other.pem")
        pc.generate_signing_key(other)
        with self.assertRaises(pc.DropError):
            pc.open_drop(bytes.fromhex(self.vec["drop"]), self.paths["device_key_pem"], pc.public_raw(other))

    def test_other_device_cannot_open(self):
        other = os.path.join(self.tmp, "otherdev.pem")
        pc.generate_x25519_key(other)
        with self.assertRaises(pc.DropError):
            pc.open_drop(bytes.fromhex(self.vec["drop"]), other, bytes.fromhex(self.vec["sign_pub"]))

    def test_new_keys_are_600(self):
        path = os.path.join(self.tmp, "k.pem")
        pc.generate_signing_key(path)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(len(pc.public_raw(path)), 32)

    def test_short_or_foreign_data_is_rejected(self):
        sign_pub = bytes.fromhex(self.vec["sign_pub"])
        for data in (b"", b"PNP1", b"XXXX" + bytes(200)):
            with self.assertRaises(pc.DropError):
                pc.open_drop(data, self.paths["device_key_pem"], sign_pub)


if __name__ == "__main__":
    unittest.main()
