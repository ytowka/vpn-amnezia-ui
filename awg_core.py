#!/usr/bin/env python3
"""Add a distinct IPv4 client to an existing Docker AmneziaWG server.

Run on the EXIT server (SWE), not on the RU transit server.
Requires Python >= 3.8, Docker, and an existing working client .conf template.
The app's clientsTable is deliberately not modified; manage these peers here.
Do not run Amnezia client-management operations concurrently with this script.
"""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


def run(argv, data=None, check=True):
    p = subprocess.run(argv, input=data, text=True, capture_output=True)
    if check and p.returncode:
        # Never echo subprocess input, configuration contents or secret keys.
        raise RuntimeError('Command failed: ' + ' '.join(argv[:3]))
    return p


def parse(text):
    result = []
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('[') and line.endswith(']'):
            result.append((line[1:-1].lower(), {}))
        elif '=' in line and result:
            k, v = line.split('=', 1)
            result[-1][1].setdefault(k.strip().lower(), []).append(v.strip())
        else:
            raise ValueError('Invalid .conf syntax')
    return result


def one(section, key):
    values = section.get(key.lower(), [])
    if len(values) != 1:
        raise ValueError('Expected one field: ' + key)
    return values[0]


def rewrite(text, changes):
    """Preserve unknown AWG fields verbatim, modifying only named fields."""
    lines, section, seen = [], None, set()
    for line in text.splitlines():
        stripped = line.split('#', 1)[0].strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1].lower()
        elif '=' in stripped:
            key = stripped.split('=', 1)[0].strip().lower()
            pair = (section, key)
            if pair in changes:
                if pair in seen:
                    raise ValueError('Duplicate field: ' + key)
                seen.add(pair)
                label, value = changes[pair]
                line = label + ' = ' + value
        lines.append(line)
    if set(changes) != seen:
        raise ValueError('Template is missing required fields')
    return '\n'.join(lines).rstrip() + '\n'


class Server:
    def __init__(self, container):
        self.container = container

    def call(self, *args, data=None, check=True):
        return run(['docker', 'exec', '-i', self.container, *args], data, check)

    def read(self, path):
        return self.call('cat', path).stdout


def allocate(server_sections, live_allowed, template_address):
    interfaces = [v for k, v in server_sections if k == 'interface']
    if len(interfaces) != 1:
        raise ValueError('Expected one server [Interface]')
    addresses = [ipaddress.ip_interface(v.strip())
                 for value in interfaces[0].get('address', [])
                 for v in value.split(',')]
    ipv4 = [a for a in addresses if a.version == 4]
    if len(ipv4) != 1 or ipv4[0].network.prefixlen >= 31:
        raise ValueError('Expected one server IPv4 subnet with prefix <= 30')
    subnet = ipv4[0].network
    if subnet.num_addresses > 65536:
        raise ValueError('Automatic allocation supports /16 or smaller subnets')
    template_ip = ipaddress.ip_interface(template_address)
    if template_ip.version != 4 or template_ip.ip not in subnet:
        raise ValueError('Template must use one IPv4 address in the server subnet')
    occupied = [ipaddress.ip_network(str(a.ip) + '/32') for a in ipv4]
    occupied.append(ipaddress.ip_network(str(template_ip.ip) + '/32'))
    for name, section in server_sections:
        if name == 'peer':
            for value in section.get('allowedips', []):
                occupied.extend(ipaddress.ip_network(x.strip(), strict=False)
                                for x in value.split(','))
    for line in live_allowed.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[1] != '(none)':
            occupied.extend(ipaddress.ip_network(x.strip(), strict=False)
                            for x in parts[1].replace(',', ' ').split())
    for ip in subnet.hosts():
        if not any(n.version == 4 and ip in n for n in occupied):
            return str(ip) + '/32'
    raise ValueError('No available client IPv4 address')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('name', help='Client name: letters, digits, underscore or hyphen')
    p.add_argument('--template', required=True, type=Path, help='Working client .conf')
    p.add_argument('--ru-ip', default='178.236.242.31')
    p.add_argument('--ru-port', type=int, default=4956)
    p.add_argument('--container', help='Auto-detects one running amnezia-awg* container')
    p.add_argument('--server-conf', help='Config path INSIDE the container')
    p.add_argument('--out-dir', type=Path, default=Path('/root/awg-clients'))
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error('Run with sudo on the SWE exit server')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', a.name):
        p.error('Invalid client name; example: danil-phone')
    ipaddress.IPv4Address(a.ru_ip)
    if not 1 <= a.ru_port <= 65535:
        p.error('Invalid RU UDP port')
    os.umask(0o077)
    lock = open('/run/lock/add-awg-client.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX)
    if not a.container:
        names = run(['docker', 'ps', '--format', '{{.Names}}']).stdout.splitlines()
        names = [n for n in names if n.startswith('amnezia-awg')]
        if len(names) != 1:
            raise ValueError('Use --container NAME; expected exactly one running amnezia-awg*')
        a.container = names[0]
    s = Server(a.container)
    tool = s.call('sh', '-c', 'command -v awg || command -v wg').stdout.strip()
    if not tool or '\n' in tool:
        raise ValueError('No awg/wg tool inside container')
    devices = s.call(tool, 'show', 'interfaces').stdout.split()
    if len(devices) != 1:
        raise ValueError('Expected exactly one active AWG interface in this container')
    interface = devices[0]
    if not a.server_conf:
        candidates = ['/opt/amnezia/awg/' + interface + '.conf',
                      '/etc/amnezia/amneziawg/' + interface + '.conf',
                      '/etc/wireguard/' + interface + '.conf']
        found = [path for path in candidates
                 if s.call('test', '-f', path, check=False).returncode == 0]
        if len(found) != 1:
            raise ValueError('Use --server-conf /path/inside/container.conf')
        a.server_conf = found[0]
    if not a.server_conf.startswith('/') or '\n' in a.server_conf:
        raise ValueError('Server config path must be absolute')
    original = s.read(a.server_conf)
    sections = parse(original)
    if re.search(r'^# Client: ' + re.escape(a.name) + r'$', original, re.M):
        raise ValueError('Client name already exists on this server')
    template = a.template.read_text(encoding='utf-8-sig')
    template_sections = parse(template)
    if [k for k, _ in template_sections] != ['interface', 'peer']:
        raise ValueError('Template must contain exactly [Interface] and one [Peer]')
    ti, tp = [v for _, v in template_sections]
    if any(k in ti for k in ('preup', 'postup', 'predown', 'postdown', 'saveconfig')):
        raise ValueError('Use an exported client template without hooks or SaveConfig')
    server_public = s.call(tool, 'show', interface, 'public-key').stdout.strip()
    if one(tp, 'PublicKey') != server_public:
        raise ValueError('Template belongs to a different server')
    # Includes runtime-only peers so their addresses are not reused.
    live = s.call(tool, 'show', interface, 'allowed-ips').stdout
    disabled_file = Path(os.getenv('STATE_DIR', '/var/lib/amnezia-ui')) / 'disabled.json'
    reserved = []
    if disabled_file.exists():
        for item in json.loads(disabled_file.read_text()).values():
            reserved.extend(parse(item['block']))
    address = allocate(sections + reserved, live, one(ti, 'Address'))
    private = s.call(tool, 'genkey').stdout.strip()
    public = s.call(tool, 'pubkey', data=private + '\n').stdout.strip()
    changes = {('interface', 'privatekey'): ('PrivateKey', private),
               ('interface', 'address'): ('Address', address),
               ('peer', 'endpoint'): ('Endpoint', f'{a.ru_ip}:{a.ru_port}')}
    peer_text = '\n# Client: ' + a.name + '\n[Peer]\nPublicKey = ' + public + '\n'
    # Preserve whether this installation uses PSK, issuing a distinct PSK if so.
    if 'presharedkey' in tp:
        psk = s.call(tool, 'genpsk').stdout.strip()
        changes[('peer', 'presharedkey')] = ('PresharedKey', psk)
        peer_text += 'PresharedKey = ' + psk + '\n'
    peer_text += 'AllowedIPs = ' + address + '\n'
    client = '# Client: ' + a.name + '\n' + rewrite(template, changes)
    a.out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = a.out_dir / (a.name + '.conf')
    # Exclusive creation: repeated names never overwrite existing client secrets.
    with output.open('x', encoding='utf-8') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(client)
    token = uuid.uuid4().hex
    stage = a.server_conf + '.new-' + token
    peer_path = '/tmp/awg-peer-' + token + '.conf'
    backup = a.server_conf + '.backup-' + token
    updated = original.rstrip() + '\n' + peer_text
    runtime_added = False
    committed = False
    try:
        # Validate the existing server file against the running server identity.
        si = [v for k, v in sections if k == 'interface']
        if len(si) != 1 or s.call(tool, 'pubkey', data=one(si[0], 'PrivateKey') + '\n').stdout.strip() != server_public:
            raise ValueError('Server file and running interface have different keys')
        s.call('sh', '-c', 'umask 077; cat > "$1"', 'sh', stage, data=updated)
        s.call('sh', '-c', 'umask 077; cat > "$1"', 'sh', peer_path, data=peer_text)
        if s.read(a.server_conf) != original:
            raise ValueError('Server config changed concurrently; retry')
        s.call('cp', '-p', a.server_conf, backup)
        # Adds only the new peer; does not restart or replace existing peers.
        s.call(tool, 'addconf', interface, peer_path)
        runtime_added = True
        if s.read(a.server_conf) != original:
            raise ValueError('Server config changed concurrently; retry')
        s.call('mv', '-f', stage, a.server_conf)
        committed = True
    except Exception:
        rollback_ok = True
        if runtime_added and not committed:
            rollback_ok = s.call(tool, 'set', interface, 'peer', public, 'remove', check=False).returncode == 0
        if not committed and rollback_ok:
            output.unlink()
        elif not committed:
            print('WARNING: runtime peer cleanup failed; client config retained: ' + str(output), file=sys.stderr)
        raise
    finally:
        s.call('rm', '-f', stage, peer_path, check=False)
    print('Client: ' + a.name)
    print('VPN address: ' + address)
    print('Endpoint: ' + f'{a.ru_ip}:{a.ru_port}')
    print('Config: ' + str(output))
    print('Server backup (inside container): ' + backup)
    print('Client is active. clientsTable/app client list was not modified.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as e:
        print('ERROR: ' + str(e), file=sys.stderr)
        sys.exit(1)
