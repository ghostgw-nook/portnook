#!/usr/bin/env bash
# Renders the PNG exports of the logos in docs/images/logo/ from their SVG sources (not run in CI).
# Uses the same headless Chromium container and driver as screenshots.sh, without network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHROME_IMAGE="${CHROME_IMAGE:-zenika/alpine-chrome:124-with-node}"
OPT_IMAGE="${OPT_IMAGE:-alpine:3.24}"
LOGO="$ROOT/docs/images/logo"
WORK="$(mktemp -d "${SHOT_TMP:-${TMPDIR:-/tmp}}/pf-logos.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
chmod 777 "$WORK"

render() { # $1 = svg name, $2 = png name, $3 = width, $4 = height
  docker run --rm --network none --shm-size=256m -v "$ROOT/.github/scripts/screenshots:/s:ro" \
    -v "$LOGO:/logo:ro" -v "$WORK:/out" --entrypoint node "$CHROME_IMAGE" --experimental-websocket --no-warnings \
    /s/shot.mjs svg "/logo/$1.svg" "$2" "$3" "$4"
}
render portnook portnook 512 512
render portnook-wordmark portnook-wordmark 1280 320
render portnook-icon portnook-icon 256 256
docker run --rm -v "$WORK:/out" "$OPT_IMAGE" sh -c \
  'apk add -q --no-cache pngquant >/dev/null && cd /out && for f in *.png; do pngquant --force --skip-if-larger --quality 80-98 --strip --output "$f" "$f" || true; done'
cp "$WORK"/*.png "$LOGO"/
ls -l "$LOGO"
