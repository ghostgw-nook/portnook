"""Traffic light of the agent dashboard.

States: ok, warn, error, unknown. The overall state is the worst *known* state; checks that do not apply
(no Proton, nothing configured, not checked yet) are "unknown" and do not influence the result.
"""
OK, WARN, ERROR, UNKNOWN = "ok", "warn", "error", "unknown"
_RANK = {OK: 0, WARN: 1, ERROR: 2}
BACKEND_WARN_MS = 300


def overall(states):
    known = [s for s in states if s in _RANK]
    if not known:
        return UNKNOWN
    return max(known, key=lambda s: _RANK[s])


def proton(p, now):
    """wg0 handshake < 3 min ok, otherwise (or wg0 down) error. Without Proton unknown."""
    if not p or not p.get("enabled"):
        return UNKNOWN
    if (p.get("failover") or {}).get("all_down"):
        return ERROR  # every VPN profile failed
    if not p.get("up") or not p.get("handshake"):
        return ERROR
    return OK if now - p["handshake"] < 180 else ERROR


def natpmp(p):
    """Port forwarding: mapped port ok, NAT-PMP failing with a still known port warn, no port error."""
    if not p or not p.get("enabled"):
        return UNKNOWN
    if p.get("provider") == "fixed":
        return OK if p.get("ports") else ERROR
    nat = p.get("natpmp") or {}
    if p.get("port"):
        return WARN if nat.get("fails") else OK
    if not nat.get("active") and not nat.get("last_ok") and not nat.get("fails"):
        return UNKNOWN  # loop not run yet
    return ERROR


def backend(b):
    """TLS ok (> 300 ms warn), failure error, not checked yet unknown."""
    if not b or not b.get("checked"):
        return UNKNOWN
    if not b.get("ok"):
        return ERROR
    return WARN if (b.get("latency_ms") or 0) > BACKEND_WARN_MS else OK


def ddns(d, now):
    """Last update ok (no error) ok; failing but an update within 1 day warn; failing longer error."""
    if not d or not d.get("configured"):
        return UNKNOWN
    if d.get("error"):
        return WARN if d.get("last_ok") and now - d["last_ok"] < 86400 else ERROR
    if not d.get("last_ok"):
        return UNKNOWN if not d.get("last_try") else ERROR
    return OK


def cert(c):
    """>= 30 days left ok, 14-30 warn (renewal overdue), < 14 days, expired or failing without cert error."""
    if not c or not (c.get("present") or c.get("last_error")):
        return UNKNOWN
    if not c.get("present"):
        return ERROR
    left = c.get("days_left")
    if left is None or left < 14:
        return ERROR
    return OK if left >= 30 else WARN


def delivery(d):
    """All configured targets ok -> ok; any failing -> error; none configured unknown."""
    targets = [t for t in (d or {}).values() if isinstance(t, dict) and t.get("configured")]
    if not targets:
        return UNKNOWN
    if any(t.get("error") for t in targets):
        return ERROR
    return OK if all(t.get("last_ok") for t in targets) else UNKNOWN


def redirect(r):
    """Provider set: last run ok and target current -> ok; target changed but not applied yet warn; error."""
    if not r or not r.get("provider"):
        return UNKNOWN
    if r.get("last_error"):
        return ERROR
    if not r.get("last_ok"):
        return UNKNOWN
    return OK if not r.get("target") or r.get("target") == r.get("last_target") else WARN


def evaluate(status):
    """`status` is Agent.status() without "light". Returns {"overall", "checks": {name: state}}."""
    now = status.get("time") or 0
    checks = {
        "proton": proton(status.get("proton"), now),
        "natpmp": natpmp(status.get("proton")),
        "backend": backend(status.get("backend")),
        "ddns": ddns(status.get("ddns"), now),
        "cert": cert(status.get("cert")),
        "delivery": delivery(status.get("delivery")),
        "redirect": redirect(status.get("redirect")),
    }
    return {"overall": overall(checks.values()), "checks": checks}
