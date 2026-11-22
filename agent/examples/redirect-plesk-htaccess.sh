#!/bin/sh
# portnook redirect script (example): writes a .htaccess with a 302 redirect into a web space via SSH
# (e.g. Plesk with SSH access). portnook runs it after every change of the VPN port/exit IP with:
#   PF_TARGET_URL   https://app.<name>.myaddr.tools:<port>   (no trailing slash)
#   PF_TARGET_HOST  app.<name>.myaddr.tools
#   PF_PORT / PF_IP current Proton port / exit IP
#   PF_STATUS_CODE  302 (or what is set in the UI)
#   PF_ENTRY_HOST   the stable entry host, e.g. start.example.ch
#   PF_RULES        all rules, one "<entry host> <target URL>" per line
#   PF_HTACCESS     ready .htaccess for all rules (written below)
#   PF_SSH_KEY      private key made/uploaded in the UI (public key: copy into Plesk -> SSH keys)
#   PF_KNOWN_HOSTS  known_hosts file of portnook (host key is stored on the first connection)
# Exit code 0 = ok; the last 50 output lines are shown in the UI. Never print passwords or keys.
set -eu

# ---- placeholders: adapt ------------------------------------------------------------------------
SSH_USER="CHANGE_ME_user"                 # SSH user of the web space
SSH_HOST="CHANGE_ME_server.example.ch"    # SSH host of the hoster
SSH_PORT="22"
WEB_ROOT="httpdocs"                       # web root of the entry host, relative to the SSH home
# -------------------------------------------------------------------------------------------------

case "$SSH_USER$SSH_HOST" in *CHANGE_ME*) echo "Bitte SSH_USER, SSH_HOST und WEB_ROOT im Skript anpassen."; exit 2 ;; esac

# PF_HTACCESS is the complete file made by portnook: one block per rule (main entry, further hosts, *.host to
# *.<name>.myaddr.tools), every path redirected, query string kept, /.well-known/ stays local (Plesk can renew
# the certificate of the entry host), no caching (also on 3xx answers). All entry hosts must reach this web
# space (Plesk: domain aliases).
HTACCESS="$PF_HTACCESS"

printf '%s' "$HTACCESS" | ssh -i "$PF_SSH_KEY" -p "$SSH_PORT" \
  -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$PF_KNOWN_HOSTS" \
  "$SSH_USER@$SSH_HOST" "cat > '$WEB_ROOT/.htaccess.pf-tmp' && mv '$WEB_ROOT/.htaccess.pf-tmp' '$WEB_ROOT/.htaccess'"

echo "Redirect gesetzt ($PF_STATUS_CODE):"
printf '%s\n' "$PF_RULES" | sed 's/ / -> /'
