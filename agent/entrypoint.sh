#!/bin/sh
set -e
cd /app
exec python3 -m app serve "$@"
