#!/usr/bin/env python3
"""Small single-server AmneziaWG console. No third-party runtime dependencies."""
import contextlib
import fcntl
import hashlib
import hmac
import http.cookies
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import awg_core as core

ROOT = Path(__file__).parent
STATE = Path(os.getenv('STATE_DIR', '/var/lib/amnezia-ui'))
CLIENTS = Path(os.getenv('CLIENT_DIR', '/root/awg-clients'))
CONF = os.getenv('SERVER_CONF', '/opt/amnezia/awg/awg0.conf')
CONTAINER = os.getenv('AWG_CONTAINER', 'amnezia-awg2')
INTERFACE = os.getenv('AWG_INTERFACE', 'awg0')
S = core.Server(CONTAINER)
LOCK = threading.RLock()
SESSIONS = {}
ATTEMPTS = {}

def atomic(path, value):
    tmp = path.with_suffix('.tmp')
    with tmp.open('w') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(value)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)

def state():
    return json.loads((STATE / 'disabled.json').read_text()) if (STATE / 'disabled.json').exists() else {}

@contextlib.contextmanager
def locked():
    with LOCK, open('/run/lock/add-awg-client.lock', 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield

def blocks(text):
    # Retain comments and all unknown AWG fields in each block.
    starts = [m.start() for m in re.finditer(r'^(?:# Client: [^\n]*\n)?\[Peer\]\s*$', text, re.M)]
    points = [0] + starts + [len(text)]
    return [text[a:b] for a,b in zip(points, points[1:]) if a != b]

def peer_key(block):
    parsed = core.parse(block)
    return core.one(parsed[0][1], 'PublicKey') if parsed and parsed[0][0] == 'peer' else None

def remove_peer(text, key):
    return ''.join(b for b in blocks(text) if peer_key(b) != key)

def backup_write(text):
    suffix = secrets.token_hex(8)
    S.call('cp', '-p', CONF, CONF + '.backup-ui-' + suffix)
    staged = CONF + '.ui-' + suffix
    S.call('sh', '-c', 'umask 077; cat > "$1"', 'sh', staged, data=text)
    S.call('mv', staged, CONF)

def add_runtime(block):
    path = '/tmp/awg-ui-' + secrets.token_hex(8)
    try:
        S.call('sh', '-c', 'umask 077; cat > "$1"', 'sh', path, data=block)
        S.call('awg', 'addconf', INTERFACE, path)
    finally:
        S.call('rm', '-f', path, check=False)

def files_by_key():
    result = {}
    for p in CLIENTS.glob('*.conf'):
        sections = core.parse(p.read_text())
        private = core.one(next(v for k,v in sections if k == 'interface'), 'PrivateKey')
        key = S.call('awg', 'pubkey', data=private + '\n').stdout.strip()
        result[key] = p
    return result

def listing():
    original = S.read(CONF)
    disabled = state()
    files = files_by_key()
    registry = json.loads(S.read('/opt/amnezia/awg/clientsTable'))
    names = {r['clientId']: r.get('userData', {}).get('clientName') for r in registry}
    live = {}
    for line in S.call('awg', 'show', INTERFACE, 'dump').stdout.splitlines()[1:]:
        p = line.split('\t')
        live[p[0]] = {'handshake': int(p[4]), 'rx': int(p[5]), 'tx': int(p[6])}
    active = {peer_key(b): b for b in blocks(original) if peer_key(b)}
    rows = []
    for key in sorted(set(active) | set(disabled) | set(live)):
        block = active.get(key) or disabled.get(key, {}).get('block')
        section = core.parse(block)[0][1] if block else {}
        stats = live.get(key, {'handshake': 0, 'rx': 0, 'tx': 0})
        rows.append(dict(key=key, name=(files[key].stem if key in files else names.get(key) or 'Клиент ' + key[:8]),
                         address=', '.join(section.get('allowedips', [])), disabled=key in disabled,
                         downloadable=key in files, online=key not in disabled and time.time()-stats['handshake'] < 180,
                         **stats))
    return {'clients': rows, 'container': CONTAINER, 'interface': INTERFACE,
            'endpoint': os.getenv('VPN_ENDPOINT', '178.236.242.31:4956'), 'time': int(time.time())}

def mutate(key, action):
    if not re.fullmatch(r'[A-Za-z0-9+/]{43}=', key):
        raise ValueError('Неверный ключ клиента')
    original = S.read(CONF)
    disabled = state()
    block = next((b for b in blocks(original) if peer_key(b) == key), None)
    saved = disabled.get(key, {}).get('block')
    if not block and not saved:
        # Runtime-only peers are deliberately not modified without a durable config.
        raise ValueError('Клиент отсутствует в сохранённом конфиге')
    if action == 'enable':
        if not saved:
            raise ValueError('Клиент уже включён')
        backup_write(original.rstrip() + '\n\n' + saved)
        try:
            add_runtime(saved)
        except Exception:
            backup_write(original)
            raise
        del disabled[key]
    elif action in ('disable', 'delete'):
        # Persist a recovery record before touching live or durable state.
        disabled[key] = {'block': block or saved, 'deleting': action == 'delete'}
        atomic(STATE / 'disabled.json', json.dumps(disabled))
        backup_write(remove_peer(original, key))
        S.call('awg', 'set', INTERFACE, 'peer', key, 'remove')
        if action == 'delete':
            for pub, p in files_by_key().items():
                if pub == key:
                    p.unlink()
            registry_path = '/opt/amnezia/awg/clientsTable'
            registry = json.loads(S.read(registry_path))
            registry = [r for r in registry if r.get('clientId') != key]
            S.call('sh', '-c', 'cat > "$1"', 'sh', registry_path, data=json.dumps(registry))
            del disabled[key]
    else:
        raise ValueError('Неизвестное действие')
    atomic(STATE / 'disabled.json', json.dumps(disabled))
    with (STATE / 'audit.log').open('a') as f:
        f.write(json.dumps({'time': int(time.time()), 'action': action, 'key': key}) + '\n')

def recover():
    # Finish interrupted revocations and keep disabled peers absent after reboot.
    for key, item in list(state().items()):
        mutate(key, 'delete' if item.get('deleting') else 'disable')

class Handler(BaseHTTPRequestHandler):
    server_version = 'AmneziaConsole'
    def log_message(self, fmt, *args):
        pass  # Never log download URLs, secrets, cookies or request bodies.
    def send(self, code, value, content_type='application/json; charset=utf-8', headers=None):
        body = json.dumps(value, ensure_ascii=False).encode() if content_type.startswith('application/json') else value
        self.send_response(code)
        for k,v in {'Content-Type':content_type, 'Content-Length': str(len(body)), 'Cache-Control':'no-store',
                    'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY',
                    'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'", **(headers or {})}.items():
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(body)
    def session(self):
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            token = cookie['session'].value
        except (KeyError, http.cookies.CookieError):
            return None
        with LOCK:
            item = SESSIONS.get(token)
            return item if item and item['expires'] > time.time() else None
    def do_GET(self):
        try:
            if self.path in ('/', '/app.js', '/style.css'):
                name = {'/':'index.html', '/app.js':'app.js', '/style.css':'style.css'}[self.path]
                mime = {'html':'text/html', 'js':'application/javascript', 'css':'text/css'}[name.split('.')[-1]]
                return self.send(200, (ROOT/'static'/name).read_bytes(), mime + '; charset=utf-8')
            session = self.session()
            if not session:
                return self.send(401, {'error':'Войдите в консоль'})
            if self.path == '/api/session':
                return self.send(200, {'csrf':session['csrf']})
            with locked():
                if self.path == '/api/clients':
                    return self.send(200, listing())
                if self.path.startswith('/api/config/'):
                    name = self.path.removeprefix('/api/config/')
                    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name):
                        raise ValueError('Неверное имя')
                    path = CLIENTS/(name+'.conf')
                    if not path.exists():
                        return self.send(404, {'error':'Конфиг не сохранён'})
                    return self.send(200, path.read_bytes(), 'application/octet-stream',
                                     {'Content-Disposition': f'attachment; filename="{name}.conf"'})
            self.send(404, {'error':'Не найдено'})
        except Exception:
            self.send(500, {'error':'Не удалось прочитать данные сервера'})
    def do_POST(self):
        try:
            # Require JSON + CSRF for mutations; login also rejects cross-origin requests.
            if self.headers.get('Sec-Fetch-Site') == 'cross-site' or self.headers.get('Content-Type') != 'application/json':
                return self.send(403, {'error':'Недопустимый запрос'})
            size = int(self.headers.get('Content-Length','0'))
            if not 0 < size <= 4096:
                return self.send(400, {'error':'Неверный размер запроса'})
            data = json.loads(self.rfile.read(size))
            if self.path == '/api/login':
                with LOCK:
                    now = time.time()
                    for ip in list(ATTEMPTS):
                        ATTEMPTS[ip] = [t for t in ATTEMPTS[ip] if now-t < 900]
                        if not ATTEMPTS[ip]: del ATTEMPTS[ip]
                    for token in list(SESSIONS):
                        if SESSIONS[token]['expires'] <= now: del SESSIONS[token]
                    attempts = ATTEMPTS.setdefault(self.client_address[0], [])
                    if len(attempts) >= 10:
                        return self.send(429, {'error':'Слишком много попыток. Подождите 15 минут.'})
                    credential = json.loads((STATE/'credentials.json').read_text())
                    candidate = hashlib.scrypt(str(data.get('password','')).encode(), salt=bytes.fromhex(credential['salt']), n=16384,r=8,p=1).hex()
                    if not hmac.compare_digest(candidate, credential['hash']):
                        attempts.append(now)
                        return self.send(401, {'error':'Неверный пароль'})
                    ATTEMPTS.pop(self.client_address[0], None)
                    token = secrets.token_urlsafe(32)
                    item = {'csrf': secrets.token_urlsafe(32), 'expires': now+28800}
                    SESSIONS[token] = item
                    return self.send(200, {'csrf':item['csrf']}, headers={'Set-Cookie':f'session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800'})
            session = self.session()
            if not session:
                return self.send(401, {'error':'Войдите в консоль'})
            if not hmac.compare_digest(self.headers.get('X-CSRF-Token',''), session['csrf']):
                return self.send(403, {'error':'Обновите страницу'})
            if self.path == '/api/logout':
                with LOCK:
                    for token in list(SESSIONS):
                        if SESSIONS[token] is session: del SESSIONS[token]
                return self.send(200, {}, headers={'Set-Cookie':'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'})
            if self.path == '/api/create':
                name = data.get('name', '')
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name):
                    raise ValueError('Имя: латинские буквы, цифры, _ и -, до 64 символов')
                with LOCK:
                    endpoint = os.getenv('VPN_ENDPOINT', '178.236.242.31:4956').split(':')
                    result = subprocess.run(['python3', str(ROOT/'awg_core.py'), name, '--template', os.getenv('CLIENT_TEMPLATE','/root/template.conf'), '--out-dir', str(CLIENTS), '--container',CONTAINER, '--server-conf', CONF, '--ru-ip', endpoint[0], '--ru-port',endpoint[1]], capture_output=True, text=True, timeout=90)
                    if result.returncode:
                        raise ValueError('Не удалось создать клиента: проверьте уникальность имени и серверный шаблон')
                return self.send(201, {'name':name})
            if self.path == '/api/action':
                with locked():
                    mutate(data.get('key',''), data.get('action',''))
                return self.send(200, {})
            self.send(404, {'error':'Не найдено'})
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            self.send(400, {'error':str(e)})
        except Exception:
            self.send(500, {'error':'Операция не завершена. Обновите список; повторите действие при необходимости.'})

if __name__ == '__main__':
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with locked(): recover()
    server = ThreadingHTTPServer((os.getenv('BIND','0.0.0.0'), int(os.getenv('PORT','80'))), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(STATE/'cert.pem', STATE/'key.pem')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
