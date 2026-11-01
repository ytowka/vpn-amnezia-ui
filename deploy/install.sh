#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker compose version >/dev/null
if [ ! -f data/template.conf ]; then
    echo 'Copy a working client config to data/template.conf first. See README.md.' >&2
    exit 1
fi
docker compose up -d --build --wait --wait-timeout 120
echo 'Console started. Password: data/state/admin-password.txt'
