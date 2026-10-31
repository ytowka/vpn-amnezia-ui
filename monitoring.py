"""Read-only sampling of AWG byte counters and tunnel packet counters."""
import contextlib
import ipaddress
import json
from pathlib import Path
import sqlite3
import subprocess
import threading
import time

RETENTION = 86400
INTERVAL = 10

def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=12)
    if p.returncode:
        raise RuntimeError('Диагностическая команда недоступна')
    return p.stdout

def docker(container, *args):
    return run(['docker', 'exec', container, *args])

def snapshot(container, interface):
    peers = {}
    for line in docker(container, 'awg', 'show', interface, 'dump').splitlines()[1:]:
        p = line.split('\t')
        peers[p[0]] = dict(rx=int(p[5]), tx=int(p[6]), handshake=int(p[4]))
    # Only aggregate interface counters provide packet counts, not AWG peers.
    totals = docker(container, 'sh', '-c',
        'for n in rx_bytes tx_bytes rx_packets tx_packets; do cat "/sys/class/net/$1/statistics/$n"; done',
        'sh', interface).splitlines()
    return {'total': dict(zip(('rx','tx','rx_packets','tx_packets'), map(int, totals))), 'peers': peers}

def rates(previous, current, seconds):
    if not previous or seconds <= 0 or seconds > INTERVAL * 3:
        return None
    # A decrease denotes a reset, not negative traffic or a giant spike.
    if any(current[k] < previous.get(k, current[k]) for k in current):
        return None
    return {k: (v-previous[k])/seconds for k,v in current.items() if k in previous}

class Monitor:
    def __init__(self, directory, container, interface):
        self.path = Path(directory)/'metrics.sqlite3'
        self.container, self.interface = container, interface
        self.error = None
    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute('CREATE TABLE IF NOT EXISTS samples (time REAL PRIMARY KEY, payload TEXT NOT NULL)')
        try:
            with db:
                yield db
        finally:
            db.close()
    def sample(self):
        data = snapshot(self.container, self.interface)
        now = time.time()
        with self.connect() as db:
            db.execute('INSERT INTO samples VALUES (?, ?)', (now, json.dumps(data)))
            db.execute('DELETE FROM samples WHERE time < ?', (now-RETENTION,))
        self.error = None
    def loop(self):
        while True:
            try: self.sample()
            except Exception: self.error = 'Нет свежих данных: не удалось опросить туннель'
            time.sleep(INTERVAL)
    def start(self):
        threading.Thread(target=self.loop, daemon=True, name='metrics').start()
    def history(self, key, hours):
        since = time.time()-hours*3600
        with self.connect() as db:
            rows = db.execute('SELECT time,payload FROM samples WHERE time >= ? ORDER BY time', (since-INTERVAL*3,)).fetchall()
        buckets = {}
        previous = None
        width = max(INTERVAL, hours*3600/300)
        for stamp, payload in rows:
            data = json.loads(payload)
            current = data['peers'].get(key) if key else data['total']
            if current and key:
                current = {k:current[k] for k in ('rx','tx')}
            value = rates(previous[1], current, stamp-previous[0]) if previous and current else None
            if stamp >= since:
                bucket = int(stamp/width)*width
                buckets.setdefault(bucket, []).append(value)
            previous = (stamp,current) if current else None
        points = []
        for stamp, values in buckets.items():
            good = [v for v in values if v is not None]
            value = {k:sum(v[k] for v in good)/len(good) for k in good[0]} if good else None
            points.append({'time':stamp, 'value':value})
        return {'points':points, 'interval':INTERVAL, 'error':self.error,
                'last_sample':rows[-1][0] if rows else None, 'packet_counts':not bool(key)}

def diagnostics(container, interface, key=None):
    checks = []
    def check(label, fn, interpret):
        try:
            text = fn().strip()
            status, detail = interpret(text)
            checks.append({'label':label, 'status':status, 'detail':detail})
            return text
        except Exception:
            checks.append({'label':label, 'status':'warning', 'detail':'Проверка недоступна или истекло время ожидания'})
            return None
    check('Контейнер VPN', lambda:run(['docker','inspect','-f','{{.State.Running}}',container]), lambda t:('ok' if t=='true' else 'error','Запущен' if t=='true' else 'Остановлен'))
    check('Интерфейс туннеля', lambda:docker(container,'ip','link','show','dev',interface), lambda t:('ok' if 'UP' in t else 'warning', 'Интерфейс поднят' if 'UP' in t else 'Интерфейс не поднят'))
    for label,fn in [('IP forwarding сервера',lambda:run(['cat','/proc/sys/net/ipv4/ip_forward'])),('IP forwarding контейнера',lambda:docker(container,'cat','/proc/sys/net/ipv4/ip_forward'))]:
        check(label,fn,lambda t:('ok' if t=='1' else 'error','Включён' if t=='1' else 'Выключен: транзит пакетов невозможен'))
    check('Маршрут в интернет',lambda:docker(container,'ip','-4','route','get','1.1.1.1'),lambda t:('ok',t))
    check('Правило NAT',lambda:docker(container,'iptables','-t','nat','-S','POSTROUTING'),lambda t:('ok' if 'MASQUERADE' in t or 'SNAT' in t else 'warning','Правило NAT найдено' if 'MASQUERADE' in t or 'SNAT' in t else 'NAT в контейнере не найден; возможна настройка на хосте'))
    check('Интернет из VPN-контейнера',lambda:docker(container,'ping','-n','-c','3','-W','2','1.1.1.1'),lambda t:('ok',t))
    if key:
        data = snapshot(container, interface)
        peer = data['peers'].get(key)
        if not peer:
            checks.append({'label':'Клиент в туннеле','status':'warning','detail':'Peer отсутствует: клиент заблокирован, удалён или конфиг не применён'})
        else:
            age = int(time.time()-peer['handshake']) if peer['handshake'] else None
            checks.append({'label':'Handshake клиента','status':'ok' if age is not None and age<180 else 'warning',
                           'detail':f'{age} сек. назад' if age is not None else 'Handshake ещё не было. Проверьте включение VPN, Endpoint, UDP-порт и ключи клиента.'})
            checks.append({'label':'Обмен данными (со стороны сервера)','status':'ok' if peer['rx'] and peer['tx'] else 'warning',
                           'detail':f"Принято {peer['rx']} байт; отправлено {peer['tx']} байт. Это счётчики с момента добавления peer, а не проверка текущей скорости."})
            allowed = docker(container,'awg','show',interface,'allowed-ips')
            addresses = next((line.split(maxsplit=1)[1] for line in allowed.splitlines() if line.split()[0]==key),'')
            targets = [ipaddress.ip_network(a.strip(),strict=False) for a in addresses.replace(',', ' ').split()]
            subnet_routes = docker(container,'ip','-4','route','show','dev',interface)
            subnets=[]
            for route in subnet_routes.splitlines():
                try: subnets.append(ipaddress.ip_network(route.split()[0],strict=False))
                except ValueError: pass
            target = next((n.network_address for n in targets if n.version==4 and n.prefixlen==32 and any(n.subnet_of(s) for s in subnets if s.version==4)),None)
            if target:
                check('Ping VPN-адреса клиента',lambda:docker(container,'ping','-n','-c','3','-W','2',str(target)),lambda t:('ok',t))
                checks.append({'label':'Как понимать ping','status':'info','detail':'Устройство может блокировать ICMP или спать. Неответивший ping сам по себе не означает неисправность VPN.'})
    return {'time':int(time.time()),'checks':checks,'note':'Проверки выполняются на SWE. Успешный ping не проверяет проброс UDP через RU и доступ в интернет с самого клиентского устройства.'}
