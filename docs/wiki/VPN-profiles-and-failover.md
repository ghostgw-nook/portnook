# VPN profiles and failover

> **Applies to:** portnook 0.27 (rc1) · [Versions](Versions)

Page **Connection** → **VPN profiles**. The profile from the wizard is profile 1. **New profile** adds more
(name, type Proton or fixed port, WireGuard file). Disabled profiles are skipped; **Activate** switches by hand.

## Fixed priority

The list order is the priority (1 = most important). You set it with the arrows; it does **not** change when
portnook switches. There is **no automatic switch back**:

- The **standby** (and first failover candidate) is the topmost enabled profile that is not active.
- Example: profile 2 runs, profile 1 recovers → profile 1 is prepared as standby and takes over only when
  profile 2 fails.

## Standby tunnel

On by default. The standby runs all the time as a second tunnel, with its own port and exit IP; connections on
its port also reach the reverse proxy. Internet requests (DDNS, certificate, Cloudflare) use only the active
tunnel. With Proton the standby needs a second device slot (one WireGuard file per profile).

## Failover

- The active tunnel is checked every 30 s: tunnel up, handshake younger than 3 minutes, NAT-PMP answers (Proton)
  or the exit IP can be read through the tunnel (fixed port).
- After **2 failed checks in a row** (adjustable; after the first failure every 5 s) the standby takes over at
  once: no rebuild, port and exit IP are known, DDNS and redirect follow right away.
- The failed profile is then rebuilt as the new standby.
- If all profiles fail, traffic stays blocked (kill switch, never over your home line) and the status is red.
  Push messages are the one exception: they always go directly over the home line, so the "all VPNs down"
  alarm still reaches you (also on an internet server such as ntfy.sh).
- After each switch portnook checks every 5 s that DNS and the redirect point to the new target; if not within
  5 minutes, you get a push message.

## Rotation

**When to switch?** Default "only on failure". Optional daily at a time (container time zone `TZ`) or every N
hours: then portnook moves to the next enabled profile below the active one (after the last, back to the first).

## One name per profile

On the **Names** page add a name with use **Connection / endpoint** and choose the profile (or several). It
always points to that profile's exit IP, even while it is standby, and the redirect uses it as soon as the
profile is active. No DNS wait on a switch. Add these names to your proxy hosts, see
[Nginx Proxy Manager](Nginx-Proxy-Manager) or [Zoraxy](Zoraxy).

## MTU

Per profile (**Edit** → **Advanced** → **Tunnel MTU**): 1420 for a single WireGuard, 1340 (default) when
WireGuard runs inside another WireGuard, 1280 if videos stall or large pages do not finish loading.
