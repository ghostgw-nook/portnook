#!/bin/sh
# Pulls the current Let's Encrypt certificate from portnook (LAN) with the pull token and installs it when it
# changed. Token: portnook UI -> Zertifikat -> "Neuen Token erzeugen" (shown once), store it in a file (mode 600).
# Usage:  PF_AGENT=http://192.168.1.20:8090 PF_TOKEN_FILE=/root/.pf-token DEST=/etc/ssl/pf ./pull-cert.sh
#         optional RELOAD="systemctl reload nginx" (run only when the certificate changed)
# Cron, e.g. daily:  17 4 * * *  PF_AGENT=... PF_TOKEN_FILE=... DEST=... /usr/local/bin/pull-cert.sh
set -eu

: "${PF_AGENT:?PF_AGENT=http://<agent>:8090}"
: "${PF_TOKEN_FILE:?PF_TOKEN_FILE=<file with the token>}"
: "${DEST:?DEST=<target directory>}"
RELOAD="${RELOAD:-}"

umask 077
mkdir -p "$DEST"
tmp=$(mktemp -d "$DEST/.pull.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
# the token goes in a header file, never on the command line (visible in ps)
printf 'Authorization: Bearer %s\n' "$(cat "$PF_TOKEN_FILE")" > "$tmp/hdr"

for f in fullchain.pem privkey.pem; do
  curl -fsS --max-time 30 -H @"$tmp/hdr" -o "$tmp/$f" "$PF_AGENT/api/cert/download/$f"
done
grep -q "BEGIN CERTIFICATE" "$tmp/fullchain.pem"
grep -q "PRIVATE KEY" "$tmp/privkey.pem"

if [ -f "$DEST/fullchain.pem" ] && cmp -s "$tmp/fullchain.pem" "$DEST/fullchain.pem"; then
  echo "unchanged"
  exit 0
fi
chmod 644 "$tmp/fullchain.pem"
chmod 600 "$tmp/privkey.pem"
mv "$tmp/privkey.pem" "$DEST/privkey.pem"
mv "$tmp/fullchain.pem" "$DEST/fullchain.pem"
echo "certificate updated in $DEST"
if [ -n "$RELOAD" ]; then
  sh -c "$RELOAD"
fi
