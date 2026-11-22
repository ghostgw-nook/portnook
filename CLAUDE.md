# Instructions for AI assistants

Read `README.md`, section "Notes for AI assistants", before changing anything and follow it.
If a requested change contradicts a note there, say so and ask whether the note should be updated.

---

# CLAUDE.md – Projekt portnook

Diese Datei ist die Arbeitsgrundlage für Claude Code. Sie beschreibt Ziel, Architektur, Regeln und Meilensteine. Lies sie vollständig, bevor du Code schreibst. Bei Widerspruch zwischen dieser Datei und einer Anweisung im Chat gilt der Chat. Bei Unklarheit fragen, nicht annehmen.

---

## 1. Ziel (Stand 0.9.0, Entscheid Owner 2026-11-18)

portnook ist ein eigenständiges Produkt im Heimnetz (der VPS-Teil "pf-edge" ist seit 0.9.0 entfernt, alte
Releases bleiben in der Historie):

- **Proton VPN** (`wg0`, optional) mit **NAT-PMP**-Portfreigabe; DNAT des gemappten TCP-Ports auf den Reverse Proxy (BACKEND). Zuhause ist kein Port offen.
- **DDNS über myaddr.tools:** `<name>.<domain>` zeigt auf die VPN-Exit-IP (bei Änderung, mindestens alle 30 Tage), sonst Ersatz-IP oder kein Update, oder eine manuelle IP. Die Heim-IP wird nie gemeldet (kein `ip=self`, Entscheid Owner 2026-11-18, 0.9.1).
- **VPN-Anbieter:** Proton (NAT-PMP) oder ein Anbieter mit festen Ports (z. B. AirVPN, Ports im UI), seit 0.9.1.
- **Mehrere VPN-Profile mit Failover** (0.10.0; seit 0.19.0 mit Reserve-Tunnel: aktiver Tunnel + Reserve auf `wg0`/`wg1`, eigene Routing-Tabellen, Failover = Umschalten ohne Neuaufbau, aktives Profil immer zuoberst, kein Rückwechsel); nie über die Heimleitung.
- **Let's-Encrypt-Wildcard-Zertifikat** (`<name>.<domain>` und `*.<name>.<domain>`) per ACME DNS-01 über myaddr.tools, eigener RFC-8555-Client.
- **Übergabe des Zertifikats:** Download im UI, Pull-API mit Token, Push an Nginx Proxy Manager (API), Zoraxy (Ordner).
- **Redirect-Host:** feste Eingangs-URL mit 302 auf das aktuelle Ziel `https://<sub>.<name>.myaddr.tools:<Port>` (Cloudflare oder Skript, optional zweiter myaddr-Name).
- **WebUI mit Login**, Assistent (Passwort, Proton, Backend) und Ampel.
- **TLS endet zuhause** beim Reverse Proxy des Benutzers. Kein integrierter Reverse Proxy.

Details, Schnittstellen und Entscheide: `docs/concept.md`.

## 2. Netz im Container

- `wg0` (optional): Proton-Config aus dem UI, `DNS=`/IPv6/Skript-Einträge entfernt, Default-Route über `wg0`.
- LAN-Routen: Netze aus dem UI über `eth0` (vor `wg-quick up`).
- DNAT: `wg0 tcp/<NAT-PMP-Port>` → BACKEND, Masquerade Richtung `eth0`; sonst ist von `wg0` nichts erreichbar.
- Anfragen ins Internet (myaddr, ACME, Cloudflare, Push) nur über einen funktionierenden `wg0`-Tunnel; ohne Tunnel (auch ganz ohne VPN) gar keine, Updates werden vorgemerkt (0.10.1, `app/egress.py`, Firewall-Kette `PF_OUT`). Anfragen ins LAN (private Adressen: NPM, LAN-Push) nur über `eth0`.
- LAN-Eingang (0.10.2): dieselben weitergeleiteten Ports auch auf der eigenen `eth0`-IP, seit 0.18.1 per TCP-Proxy (`app/lanproxy.py`, an `eth0` gebunden) statt DNAT, auf BACKEND (nur eingehend aus dem LAN, folgt Port und Failover, abschaltbar); NAT-PMP fragt nach dem zuletzt gehaltenen Port pro Profil (`/data/natpmp.json`).
- MTU (0.10.3): pro Profil 1280–1500 oder aus der wg.conf (Standard 1340), auf `wg0` bei Start und jedem Wechsel; MSS-Clamping (MTU − 40) für `wg+` (`PF_MSS`).
- WebUI `:8090` im LAN (`PF_BIND`).

## 3. Technik-Vorgaben

- **Sprache:** Python 3 nur mit **Standardbibliothek** (`http.server`, `ssl`, `json`, `subprocess`, `ipaddress`, `hmac`, `hashlib`, `threading`). Kein Flask/FastAPI, keine pip-Abhängigkeiten.
- **Frontend:** eine statische HTML-Datei mit Vanilla-JS und CSS, ohne Build-Schritt und ohne CDN. Polling `GET /api/status` alle 5 s.
- **Image portnook:** `alpine:3.24` + `python3 libnatpmp wireguard-tools iproute2 iptables openssl ca-certificates openssh-client`
- **System-Tools** werden über `subprocess` mit Argumentlisten aufgerufen, nie mit `shell=True` und nie mit unvalidierten Eingaben: `wg-quick`, `ip`, `iptables`, `natpmpc`, `openssl`, `ssh-keygen`. Einzige Ausnahme: das vom Benutzer im UI hinterlegte Redirect-Skript (`/bin/sh`, eigener Entscheid E).
- **Zustand** als JSON unter `/data`, atomar schreiben (tmp + `os.replace`), Dateirechte 600 für Geheimnisse.

### 3.1 Konventionen

- **Repo-Regeln aus `README.md` → „Notes for AI assistants“ gelten zuerst:** nur auf `claude/**`-Branches arbeiten (Auto-Merge nach grünen Tests), jede Änderung erhöht `VERSION` (Fix: Patch, Feature: Minor), optionale Notes in `.github/release-notes/X.Y.Z.md`.
- **Code, Kommentare, Docstrings, Doku (`docs/`, README), Commits und Logs:** Englisch. Ausnahme (Entscheid Owner, 0.7.1): `README.md` und `docs/installation.md` auf Deutsch.
- **WebUI-Texte:** Deutsch (Schweiz, kein ß).
- **Logs:** einzeilig mit Zeitstempel, ohne Geheimnisse (keine Keys, Tokens oder Passwörter, auch nicht gekürzt).
- **Tests:** `.github/workflows/tests.yml` mit den echten Unit-Tests ersetzen (M0), `build.yml` mit dem Docker-Build.
- **Kleine, nachvollziehbare Commits** pro Meilenstein-Schritt.

## 4. Repository-Struktur

```
portnook/
├── CLAUDE.md, README.md (Deutsch), VERSION, .github/
├── docs/            concept.md, installation.md (Deutsch), pull-cert.sh, images/
├── agent/           Dockerfile, compose, app/, web/index.html, examples/, tests/
└── reference/v1/    früher Prototyp, nur lesen
```

**Nie committen:** WG-Private-Keys, Proton-Configs, myaddr-Schlüssel, Tokens, Passwörter, Zertifikatsschlüssel, `agent.json`.

## 9. Tests

- **Unit-Tests** mit `unittest`, ohne Root: Validierung, Store, Ampel, Parser, NAT-PMP, myaddr/DDNS, ACME-Helfer (echtes openssl), NPM/Cloudflare gegen lokale Fake-Server, Redirect-Skript. System-Tools über `sysrun.run`, in Tests gemockt.
- **E2E** (`.github/scripts/e2e.sh`): Agent + TLS-Backend + pebble/challtestsrv + Fake myaddr/NPM, ohne Proton.
- **Manuelle Abnahme:** Befehle in `docs/concept.md`.

## 10. Nicht tun

- Keine Geheimnisse ins Repo, in Logs, ins API/UI (Schlüssel, Tokens, Passwörter sind write-only) oder in Fehlermeldungen.
- Keine externen Python-Pakete, keine CDN-Abhängigkeiten im Frontend.
- Kein integrierter Reverse Proxy; TLS endet beim Reverse Proxy des Benutzers.
- Nie Anfragen ins Internet über `eth0` (Heim-IP), auch nicht ohne VPN; nie LAN-Anfragen durch den Tunnel.
- Keine Annahmen über Hardware oder Netz der Benutzer: Werte kommen aus dem UI.
