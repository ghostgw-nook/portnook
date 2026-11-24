# VPN profiles and failover

> **Applies to:** portnook 0.37 (rc1) · [Versions](Versions)

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

## Up to 4 tunnels at once (0.37)

**Failover** → **Tunnels open at once**: 2 (default), 3 or 4. With 3 or 4 the next profiles of the list run as
**Reserve 2** and **Reserve 3** on `wg2`/`wg3`, each with its own port, exit IP and (if it has one) its own
name.

- A failover takes the ready reserve with the highest priority. The other reserves keep running untouched (same
  exit IP, same port); the old active profile comes back as a reserve.
- **Activate** on a profile that already runs as a reserve switches to it at once, without a rebuild.
- Fewer tunnels: the reserves with the lowest priority go down, the others stay where they run.
- **Round robin** in the redirect shares the visitors among all tunnels that have a name of their own
  (see [Redirect host](Redirect-host)).
- Every tunnel needs a device slot at Proton, and WireGuard costs CPU on the host.

## Load per tunnel and CPU (0.37)

Every tunnel tile shows **Connections**: new connections in the last 15 minutes and since the start, and with
the [PROXY protocol](PROXY-protocol) also the connections open right now. Below the tiles: the CPU load of the
host (WireGuard encrypts in the host's kernel, so this is where it shows) and what portnook itself uses. The CPU
cannot be split per tunnel; the traffic and the connections per tunnel show which one causes it.

## Failover

- The active tunnel is checked every 30 s: tunnel up, handshake younger than 3 minutes, NAT-PMP answers (Proton)
  or the exit IP can be read through the tunnel (fixed port).
- After **2 failed checks in a row** (adjustable; after the first failure every 5 s) the standby takes over at
  once: no rebuild, port and exit IP are known, DDNS and redirect follow right away. For a switch without DNS
  wait give each profile its own name (see [One name per profile](#one-name-per-profile)); a name shared by
  several profiles is updated on the switch, and clients may keep the old IP for a few minutes (DNS cache).
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
