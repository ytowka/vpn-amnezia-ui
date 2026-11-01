#!/bin/sh
# Run once as root from this repository; builds before stopping the old console.
set -eu
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 1; }
docker compose version >/dev/null
[ ! -e data ] || { echo 'data already exists; refusing to overwrite. Inspect it before retrying.'; exit 1; }
[ -f /root/template.conf ] && [ -d /root/awg-clients ] && [ -f /var/lib/amnezia-ui/credentials.json ]
[ -f .env ] || cp .env.example .env
docker compose build
systemctl stop amnezia-ui
client_backup=
state_backup=
rollback() {
    docker compose down || true
    if [ -n "$client_backup" ] && [ -d "$client_backup" ]; then
        [ ! -L /root/awg-clients ] || rm /root/awg-clients
        mv "$client_backup" /root/awg-clients
    fi
    if [ -n "$state_backup" ] && [ -d "$state_backup" ]; then
        [ ! -L /var/lib/amnezia-ui ] || rm /var/lib/amnezia-ui
        mv "$state_backup" /var/lib/amnezia-ui
    fi
    systemctl start amnezia-ui
    echo 'Migration interrupted; previous systemd console restored. Inspect data before retrying.' >&2
}
trap rollback EXIT
umask 077
mkdir -m 700 data
cp -a /var/lib/amnezia-ui data/state
cp -a /root/awg-clients data/clients
cp -p /root/template.conf data/template.conf
if [ -f /root/amnezia-ui-password.txt ]; then
    cp -p /root/amnezia-ui-password.txt data/state/admin-password.txt
fi
docker compose up -d --wait --wait-timeout 120
# Keep old CLI paths pointing to the same state and clients as the console.
stamp=$(date +%Y%m%d%H%M%S)
project=$(pwd)
client_backup="/root/awg-clients.pre-compose-$stamp"
mv /root/awg-clients "$client_backup"
ln -s "$project/data/clients" /root/awg-clients
state_backup="/var/lib/amnezia-ui.pre-compose-$stamp"
mv /var/lib/amnezia-ui "$state_backup"
ln -s "$project/data/state" /var/lib/amnezia-ui
systemctl disable amnezia-ui
trap - EXIT
echo 'Migration complete. Password unchanged. Data: ./data'
