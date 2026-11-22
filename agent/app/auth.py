"""UI password (PBKDF2-SHA256), in-memory sessions and login rate limit."""

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

ITERATIONS = 600000  # new hashes; stored hashes keep their own count
MIN_PASSWORD = 8
SESSION_TTL = 4 * 3600  # idle timeout
SESSION_MAX_AGE = 12 * 3600  # absolute lifetime
COOKIE = "portnook_session"
LOGIN_FAILS = 5
LOGIN_WINDOW = 600
LOGIN_FAILS_GLOBAL = 30  # ceiling over all source IPs per window


def hash_password(password, iterations=None, salt=None):
    iterations = iterations or ITERATIONS
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password, stored):
    try:
        algo, iters, salt_b64, dk_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
    except (ValueError, AttributeError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def check_new_password(password):
    """Return a German error message or ``None``."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        return "Passwort muss mindestens %d Zeichen lang sein." % MIN_PASSWORD
    if len(password) > 256:
        return "Passwort ist zu lang (max. 256 Zeichen)."
    return None


class Sessions:
    def __init__(self, ttl=SESSION_TTL, max_age=SESSION_MAX_AGE, clock=time.time):
        self.ttl = ttl
        self.max_age = max_age
        self.clock = clock
        self._lock = threading.Lock()
        self._sessions = {}  # sha256(token) -> [idle expiry, absolute expiry]
        self._fails = {}  # ip -> [timestamps]
        self._all_fails = []  # timestamps over all IPs

    @staticmethod
    def _key(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self):
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            now = self.clock()
            self._sessions[self._key(token)] = [now + self.ttl, now + self.max_age]
        return token

    def valid(self, token):
        if not token:
            return False
        key = self._key(token)
        with self._lock:
            entry = self._sessions.get(key)
            if entry is None:
                return False
            now = self.clock()
            if entry[0] < now or entry[1] < now:
                del self._sessions[key]
                return False
            entry[0] = min(now + self.ttl, entry[1])  # sliding idle expiry, capped
            return True

    def drop(self, token):
        if token:
            with self._lock:
                self._sessions.pop(self._key(token), None)

    def drop_all(self):
        with self._lock:
            self._sessions.clear()

    def _purge(self):
        now = self.clock()
        for key in [k for k, e in self._sessions.items() if min(e) < now]:
            del self._sessions[key]

    # login rate limit -------------------------------------------------
    def blocked(self, ip):
        now = self.clock()
        with self._lock:
            recent = [t for t in self._fails.get(ip, []) if now - t < LOGIN_WINDOW]
            if recent:
                self._fails[ip] = recent
            else:
                self._fails.pop(ip, None)
            self._all_fails = [t for t in self._all_fails if now - t < LOGIN_WINDOW]
            return len(recent) >= LOGIN_FAILS or len(self._all_fails) >= LOGIN_FAILS_GLOBAL

    def fail(self, ip):
        with self._lock:
            now = self.clock()
            self._fails.setdefault(ip, []).append(now)
            self._all_fails.append(now)

    def reset(self, ip):
        with self._lock:
            self._fails.pop(ip, None)
