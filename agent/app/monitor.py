"""Background loop every 30 s: VPN exit IP and failover, tunnel state, backend check, DDNS update (myaddr.tools),
certificate renewal check, redirect host, push notifications."""

import os
import threading

from .log import log

INTERVAL = int(os.environ.get("PF_MONITOR_INTERVAL") or 30)


class Monitor(threading.Thread):
    def __init__(self, agent, interval=INTERVAL):
        super().__init__(name="monitor", daemon=True)
        self.agent = agent
        self.interval = interval
        self._wake = threading.Event()
        self._halt = threading.Event()
        self.tunnel = None  # last tunnel state (egress policy)

    def trigger(self):
        self._wake.set()

    def stop(self):
        self._halt.set()
        self._wake.set()

    def run(self):
        log("monitor started")
        while not self._halt.is_set():
            self.cycle()
            self._wake.wait(self._next_wait())
            self._wake.clear()

    def _next_wait(self):
        """Faster checks while a VPN profile is failing or a switch is being verified (failover.wait_hint)."""
        try:
            hint = self.agent.failover.wait_hint()
        except Exception:  # never stop the loop over a hint
            hint = None
        return min(self.interval, hint) if hint else self.interval

    def cycle(self):
        agent = self.agent
        for name, fn in (("vpn exit ip", agent.refresh_exit_ip), ("vpn failover", agent.failover.tick),
                         ("tunnel state", self._tunnel), ("backend check", self._backend),
                         ("ddns", agent.ddns.tick), ("myaddr names", agent.names.tick), ("certificate", agent.certs.tick),
                         ("redirect", agent.redirect.tick), ("push", agent.notify.tick)):
            try:
                fn()
            except Exception as err:  # keep the loop alive
                log("monitor: %s failed: %s", name, err)

    def _tunnel(self):
        """Tunnel came back: send queued updates (DDNS, redirect, certificate, push) in this cycle."""
        up = self.agent.egress.tunnel_up()
        if up and self.tunnel is False:
            log("vpn tunnel up: sending queued updates")
            self.agent.ddns.retry_now()
            self.agent.redirect.rt.update({"next_try": 0, "next_try2": 0})
        elif not up and self.tunnel and self.agent._proton_on():
            log("vpn tunnel down: internet requests are held back")
        self.tunnel = up

    def _backend(self):
        if self.agent.store.section("backend").get("addr"):
            self.agent.backend_test()
