#!/bin/sh
# portnook redirect script (example): writes an index.php that redirects (for web spaces without .htaccess).
# Same environment as redirect-plesk-htaccess.sh (PF_PHP, PF_RULES, PF_SSH_KEY, ...).
# Only requests that reach index.php are redirected (the root URL; other paths only if the hoster routes
# them to index.php). The path and query string of the request are kept.
set -eu

# ---- placeholders: adapt ------------------------------------------------------------------------
SSH_USER="CHANGE_ME_user"
SSH_HOST="CHANGE_ME_server.example.ch"
SSH_PORT="22"
WEB_ROOT="httpdocs"
# -------------------------------------------------------------------------------------------------

case "$SSH_USER$SSH_HOST" in *CHANGE_ME*) echo "Bitte SSH_USER, SSH_HOST und WEB_ROOT im Skript anpassen."; exit 2 ;; esac

PHP="$PF_PHP"  # complete index.php made by portnook: all rules, no caching

printf '%s' "$PHP" | ssh -i "$PF_SSH_KEY" -p "$SSH_PORT" \
  -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$PF_KNOWN_HOSTS" \
  "$SSH_USER@$SSH_HOST" "cat > '$WEB_ROOT/index.php.pf-tmp' && mv '$WEB_ROOT/index.php.pf-tmp' '$WEB_ROOT/index.php'"

echo "Redirect gesetzt ($PF_STATUS_CODE):"
printf '%s\n' "$PF_RULES" | sed 's/ / -> /'
