#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 1; }
cd /opt/amnezia-ui
python3 -m unittest discover -s tests
install -d -m 700 /var/lib/amnezia-ui
python3 - <<'PY'
import hashlib,json,os,secrets
from pathlib import Path
os.umask(0o077)
state=Path('/var/lib/amnezia-ui')
if not (state/'credentials.json').exists():
    password=secrets.token_urlsafe(24)
    salt=secrets.token_bytes(16)
    digest=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1).hex()
    (state/'credentials.json').write_text(json.dumps({'salt':salt.hex(),'hash':digest}))
    Path('/root/amnezia-ui-password.txt').write_text(password+'\n')
PY
if [ ! -f /var/lib/amnezia-ui/cert.pem ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 365 -keyout /var/lib/amnezia-ui/key.pem -out /var/lib/amnezia-ui/cert.pem -subj '/CN=amnezia-console' -addext 'subjectAltName=IP:147.45.77.8' 2>/dev/null
fi
chmod 600 /var/lib/amnezia-ui/*
install -m 644 deploy/amnezia-ui.service /etc/systemd/system/amnezia-ui.service
systemctl daemon-reload
systemctl enable --now amnezia-ui
systemctl restart amnezia-ui
systemctl is-active amnezia-ui
printf 'Console: https://147.45.77.8:80\nPassword file: /root/amnezia-ui-password.txt\n'
