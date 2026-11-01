"""Initialize only missing console credentials/certificate, then exec the server."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys


def initialize():
    os.umask(0o077)
    state = Path(os.environ.get('STATE_DIR', '/data/state'))
    clients = Path(os.environ.get('CLIENT_DIR', '/data/clients'))
    template = Path(os.environ.get('CLIENT_TEMPLATE', '/data/template.conf'))
    if not template.is_file():
        raise RuntimeError('Missing client template: copy the working .conf to data/template.conf before starting')
    for directory in (state, clients):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    credentials = state/'credentials.json'
    if not credentials.exists():
        password = secrets.token_urlsafe(24)
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=16384,r=8,p=1).hex()
        # Write recovery password first; never put it in image, env or logs.
        (state/'admin-password.txt').write_text(password+'\n')
        credentials.write_text(json.dumps({'salt':salt.hex(),'hash':digest}))
    cert, key = state/'cert.pem', state/'key.pem'
    if cert.exists() != key.exists():
        raise RuntimeError('Incomplete TLS certificate/key pair; restore the missing file')
    if not cert.exists():
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','365',
                        '-keyout',str(key),'-out',str(cert),'-subj','/CN=amnezia-console',
                        '-addext','subjectAltName='+os.getenv('TLS_SAN','DNS:localhost,IP:127.0.0.1')],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    print('Console initialized; credentials and TLS files preserved in persistent state.', flush=True)

if __name__ == '__main__':
    initialize()
    os.execv(sys.executable,[sys.executable,str(Path(__file__).with_name('server.py'))])
