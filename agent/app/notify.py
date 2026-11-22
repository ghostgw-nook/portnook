"""Push notifications to Gotify and/or ntfy (owner decision 2026-11-18, 0.10.1).

Events: VPN profile switch (failover), back to the preferred profile, all VPNs down (with a reminder every
``reminder`` minutes while it lasts), recovered, DDNS / certificate / redirect / NPM / Zoraxy errors,
certificate renewed.

* Sending goes through the egress policy (``app.egress``, route ``push``): push messages need not hide the
  home IP (owner decision 2026-11-19, 0.18.0), so every push server is reached directly through ``eth0``, the
  internet ones (e.g. ntfy.sh) too, with or without a VPN tunnel. A message that fails to send waits (latest
  message per event) and is retried.
* Repeats are suppressed: the same event with the same text at most once per ``DEDUPE`` seconds, and at most
  ``RATE`` messages per hour in total.
* Tokens (Gotify app token, ntfy access token) are write-only: stored in ``agent.json`` (mode 600), never
  returned by the API and never logged.
"""

import collections
import re
import threading
import time
import urllib.parse

from . import httpc
from .log import log
from .validate import ValidationError

TARGETS = ("gotify", "ntfy")
# event -> (Gotify priority 0-10, ntfy priority 1-5)
EVENTS = {
    "vpn_switch": (6, 4), "vpn_back": (4, 3), "vpn_down": (8, 5), "vpn_up": (6, 4),
    "vpn_rotate": (3, 3), "vpn_verify": (6, 4),
    "ddns_error": (6, 4), "cert_error": (6, 4), "redirect_error": (6, 4), "npm_error": (6, 4),
    "zoraxy_error": (6, 4), "cert_renewed": (3, 3), "test": (4, 3),
}
DEDUPE = 3600
RATE = 20
MAX_QUEUE = 20
REMINDER_DEFAULT = 30  # minutes
REMINDER_RANGE = (1, 1440)
URL_MAX = 200
_TOPIC = re.compile(r"[A-Za-z0-9_-]{1,64}")
_TOKEN = re.compile(r"[\x21-\x7e]{1,200}")


class PushError(Exception):
    """The push server refused the message (HTTP status); message without tokens."""


def check_url(value, what):
    url = str(value or "").strip().rstrip("/")
    if len(url) > URL_MAX:
        raise ValidationError("%s ist zu lang." % what)
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port  # noqa: B018 - raises on an invalid port
    except ValueError:
        raise ValidationError("%s ist keine gültige URL." % what)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValidationError("%s muss mit http:// oder https:// beginnen." % what)
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValidationError("%s ohne Benutzer, Passwort, ? oder # angeben (Token separat)." % what)
    return url


def check_token(value, what):
    token = str(value or "").strip()
    if not _TOKEN.fullmatch(token):
        raise ValidationError("%s: 1 bis 200 Zeichen ohne Leerzeichen." % what)
    return token


class Notifier:
    def __init__(self, agent, clock=time.time, request=httpc.request):
        self.agent = agent
        self.clock = clock
        self.request = request
        self.lock = threading.RLock()
        self.outbox = {t: collections.OrderedDict() for t in TARGETS}
        self.recent = {}  # (event, text) -> last time
        self.sent_times = collections.deque()
        self.rt = {t: {"last_ok": 0, "last_try": 0, "error": ""} for t in TARGETS}
        self.down_since = 0
        self.last_reminder = 0
        self._wake = threading.Event()
        self.thread = None

    # -- settings ------------------------------------------------------------
    def cfg(self):
        return self.agent.store.section("push")

    def reminder(self, cfg=None):
        cfg = cfg if cfg is not None else self.cfg()
        try:
            return int(cfg.get("reminder") or REMINDER_DEFAULT)
        except (TypeError, ValueError):
            return REMINDER_DEFAULT

    def configured(self, cfg=None):
        cfg = cfg if cfg is not None else self.cfg()
        out = []
        g, n = cfg.get("gotify") or {}, cfg.get("ntfy") or {}
        if g.get("url") and g.get("token"):
            out.append("gotify")
        if n.get("url") and n.get("topic"):
            out.append("ntfy")
        return out

    def set_config(self, body):
        cur = self.cfg()
        new = {"reminder": self.reminder(cur)}
        if "reminder" in body:
            try:
                rem = int(body.get("reminder"))
            except (TypeError, ValueError):
                raise ValidationError("Erinnerung: Minuten als Zahl.")
            if not REMINDER_RANGE[0] <= rem <= REMINDER_RANGE[1]:
                raise ValidationError("Erinnerung: %d bis %d Minuten." % REMINDER_RANGE)
            new["reminder"] = rem
        g_in, g_cur = body.get("gotify"), cur.get("gotify") or {}
        if isinstance(g_in, dict):
            g = {}
            if g_in.get("url"):
                g["url"] = check_url(g_in["url"], "Gotify-Adresse")
                if g_in.get("token"):
                    g["token"] = check_token(g_in["token"], "Gotify-App-Token")
                elif g_cur.get("token") and g_cur.get("url") == g["url"]:  # a new URL needs the token again
                    g["token"] = g_cur["token"]
                else:
                    raise ValidationError("Gotify-App-Token fehlt.")
            new["gotify"] = g
        else:
            new["gotify"] = g_cur
        n_in, n_cur = body.get("ntfy"), cur.get("ntfy") or {}
        if isinstance(n_in, dict):
            n = {}
            if n_in.get("url") or n_in.get("topic"):
                n["url"] = check_url(n_in.get("url") or "", "ntfy-Server")
                topic = str(n_in.get("topic") or "").strip()
                if not _TOPIC.fullmatch(topic):
                    raise ValidationError("ntfy-Thema: 1 bis 64 Zeichen (Buchstaben, Ziffern, '-' und '_').")
                n["topic"] = topic
                if n_in.get("token"):
                    n["token"] = check_token(n_in["token"], "ntfy-Token")
                elif n_cur.get("token") and n_cur.get("url") == n["url"]:
                    n["token"] = n_cur["token"]
            new["ntfy"] = n
        else:
            new["ntfy"] = n_cur
        for t in TARGETS:
            if new[t].get("url"):
                new[t]["lan"] = self.agent.egress.host_is_lan(new[t]["url"])
        self.agent.store.update("push", new, replace=True)
        with self.lock:
            for t in TARGETS:
                if not new[t]:
                    self.outbox[t].clear()
                    self.rt[t] = {"last_ok": 0, "last_try": 0, "error": ""}
        log("push: gotify %s, ntfy %s, reminder every %d min", "on" if new["gotify"] else "off",
            "on" if new["ntfy"] else "off", new["reminder"])
        return {"ok": True, "push": self.status()}

    # -- events --------------------------------------------------------------
    def event(self, kind, title, text, force=False):
        """Queue a message for every configured target. Returns True if queued."""
        cfg = self.cfg()
        targets = self.configured(cfg)
        if not targets:
            return False
        now = self.clock()
        with self.lock:
            key = (kind, text)
            if not force and now - self.recent.get(key, -DEDUPE) < DEDUPE:
                return False
            while self.sent_times and now - self.sent_times[0] >= 3600:
                self.sent_times.popleft()
            if len(self.sent_times) >= RATE:
                log("push: rate limit reached, '%s' not sent", kind)
                return False
            self.sent_times.append(now)
            self.recent[key] = now
            if len(self.recent) > 200:
                for k in sorted(self.recent, key=self.recent.get)[:100]:
                    del self.recent[k]
            msg = {"kind": kind, "title": title, "text": text, "time": int(now)}
            for t in targets:
                box = self.outbox[t]
                box.pop(kind, None)  # latest message per event
                box[kind] = msg
                while len(box) > MAX_QUEUE:
                    box.popitem(last=False)
        self._wake.set()
        return True

    def vpn_down(self, text):
        if not self.down_since:
            self.down_since = self.last_reminder = int(self.clock())
            self.event("vpn_down", "Alle VPNs ausgefallen", text, force=True)

    def vpn_up(self, name):
        if self.down_since:
            minutes = max(0, int(self.clock()) - self.down_since) // 60
            self.down_since = self.last_reminder = 0
            self.event("vpn_up", "VPN wieder verfügbar",
                       "Profil '%s' läuft wieder (Ausfall %d min). Vorgemerkte Updates werden gesendet." % (name, minutes),
                       force=True)

    def tick(self):
        """Monitor loop: reminder while all VPNs are down, then send what is queued."""
        if not self.agent._proton_on():
            self.down_since = self.last_reminder = 0
        now = int(self.clock())
        if self.down_since and now - self.last_reminder >= self.reminder() * 60:
            self.last_reminder = now
            self.event("vpn_down", "Alle VPNs weiterhin ausgefallen",
                       "Seit %d min kein VPN-Tunnel. Kein Verkehr über die Heimleitung, Updates sind vorgemerkt."
                       % ((now - self.down_since) // 60), force=True)
        return self.flush()

    # -- sending ---------------------------------------------------------------
    def _send(self, target, cfg, msg):
        g_prio, n_prio = EVENTS.get(msg["kind"], (5, 3))
        title = "portnook: " + msg["title"]
        device = self.agent.egress.route("push")
        if target == "gotify":
            c = cfg["gotify"]
            resp = self.request("POST", c["url"] + "/message", device=device, timeout=15,
                                body={"title": title, "message": msg["text"], "priority": g_prio},
                                headers={"X-Gotify-Key": c["token"]})
        else:
            c = cfg["ntfy"]
            headers = {"Authorization": "Bearer " + c["token"]} if c.get("token") else {}
            # JSON publishing to the server root: UTF-8 title without header encoding
            resp = self.request("POST", c["url"] + "/", device=device, timeout=15, headers=headers,
                                body={"topic": c["topic"], "title": title, "message": msg["text"],
                                      "priority": n_prio})
        if resp.status >= 300:
            raise PushError("%s antwortete HTTP %d" % ("Gotify" if target == "gotify" else "ntfy", resp.status))

    def flush(self):
        """Send queued messages (directly, also without a tunnel). Returns the number sent."""
        cfg = self.cfg()
        sent = 0
        for t in TARGETS:
            with self.lock:
                pending = list(self.outbox[t].items())
            if not pending:
                continue
            if t not in self.configured(cfg):
                with self.lock:
                    self.outbox[t].clear()
                continue
            for kind, msg in pending:
                self.rt[t]["last_try"] = int(self.clock())
                try:
                    self._send(t, cfg, msg)
                except httpc.HttpError as err:  # transport (EgressBlocked included): keep, retry later
                    self._failed(t, str(err))
                    break
                except PushError as err:  # refused (token, topic): drop
                    self._failed(t, str(err))
                    with self.lock:
                        if self.outbox[t].get(kind) is msg:
                            del self.outbox[t][kind]
                    continue
                with self.lock:
                    if self.outbox[t].get(kind) is msg:
                        del self.outbox[t][kind]
                if self.rt[t]["error"]:
                    log("push %s ok again", t)
                self.rt[t].update({"last_ok": int(self.clock()), "error": ""})
                sent += 1
        return sent

    def _failed(self, target, text):
        text = text[:200]
        if self.rt[target]["error"] != text:
            log("push %s failed: %s", target, text)
        self.rt[target]["error"] = text

    def test(self):
        """UI "Test senden": one message to every configured target, now. Returns {target: result}."""
        cfg = self.cfg()
        targets = self.configured(cfg)
        if not targets:
            raise ValidationError("Kein Ziel eingerichtet (Gotify oder ntfy).")
        msg = {"kind": "test", "title": "Test", "time": int(self.clock()),
               "text": "Testnachricht von portnook %s." % (self.agent.fqdn() or "")}
        out = {}
        for t in targets:
            self.rt[t]["last_try"] = int(self.clock())
            try:
                self._send(t, cfg, msg)
                self.rt[t].update({"last_ok": int(self.clock()), "error": ""})
                out[t] = {"ok": True}
            except (httpc.HttpError, PushError) as err:
                self._failed(t, str(err))
                out[t] = {"ok": False, "error": self.rt[t]["error"]}
        log("push test: %s", ", ".join("%s %s" % (t, "ok" if r["ok"] else "failed") for t, r in out.items()))
        return {"ok": all(r["ok"] for r in out.values()), "results": out}

    # -- worker ------------------------------------------------------------------
    def start(self):
        if self.thread is None:
            self.thread = threading.Thread(target=self._loop, name="push", daemon=True)
            self.thread.start()

    def _loop(self):
        while True:
            self._wake.wait(60)
            self._wake.clear()
            try:
                self.flush()
            except Exception as err:  # keep the worker alive
                log("push: flush failed: %s", err)

    # -- status ------------------------------------------------------------------
    def status(self):
        cfg = self.cfg()
        g, n = cfg.get("gotify") or {}, cfg.get("ntfy") or {}
        with self.lock:
            queued = {t: len(self.outbox[t]) for t in TARGETS}
        return {"reminder": self.reminder(cfg), "down_since": self.down_since,
                "gotify": dict({"url": g.get("url", ""), "token_set": bool(g.get("token")), "lan": bool(g.get("lan")),
                                "queued": queued["gotify"]}, **self.rt["gotify"]),
                "ntfy": dict({"url": n.get("url", ""), "topic": n.get("topic", ""), "token_set": bool(n.get("token")),
                              "lan": bool(n.get("lan")), "queued": queued["ntfy"]}, **self.rt["ntfy"])}
