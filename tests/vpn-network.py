#!/usr/bin/env python3
"""Real WireGuard/nftables tests in disposable Docker network namespaces.
No host networking, privileged mode, Docker socket mounts, or host sysctl commands.
Build waypoint-gateway:local and waypoint-vpn-test:local first.
"""
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import socketserver
import subprocess
import tempfile
import threading
import time

prefix = 'waypoint-vpn-test-' + secrets.token_hex(4)
containers, networks, volumes = [], [], []
policy = {'revision': '', 'peers': []}
applied = ''
online = True
mutex = threading.Lock()
control_token = secrets.token_hex(32)


def docker(*args, data=None, check=True):
    p = subprocess.run(['docker', *args], input=data, text=True, capture_output=True)
    if check and p.returncode:
        # Never print commands or stdin: test key material is intentionally private.
        raise RuntimeError('Docker operation failed: ' + p.stderr.strip())
    return p.stdout.strip() if check else p


def ip(name, network):
    return json.loads(docker('inspect', name))[0]['NetworkSettings']['Networks'][network]['IPAddress']


def run_container(suffix, network, *extra):
    name = prefix + '-' + suffix
    docker('run', '-d', '--name', name, '--network', network,
           '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--security-opt=no-new-privileges',
           *extra, 'waypoint-vpn-test:local')
    containers.append(name)
    return name


class Control(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        with mutex:
            authorized = self.headers.get('Authorization') == 'Bearer ' + control_token
            self.send_response(200 if online and authorized else 503)
            self.end_headers()
            if online and authorized:
                self.wfile.write(json.dumps(policy).encode())

    def do_POST(self):
        global applied
        if self.headers.get('Authorization') != 'Bearer ' + control_token:
            self.send_response(401)
            self.end_headers()
            return
        value = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        with mutex:
            applied = value['revision']
        self.send_response(204)
        self.end_headers()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def install(peers):
    global policy
    body = {'revision': '', 'peers': peers}
    body['revision'] = hashlib.sha256(json.dumps(body, separators=(',', ':')).encode()).hexdigest()
    with mutex:
        policy = body
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        with mutex:
            if applied == body['revision']:
                return
        time.sleep(.15)
    raise AssertionError('Gateway did not confirm the new policy')


def deadline(seconds):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


server_code = '''import socket,threading,time

def tcp(port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen()
 def echo(c):
  try:
   while True:
    b=c.recv(4096)
    if not b:break
    c.sendall(b)
  except OSError:pass
  finally:c.close()
 while True:
  c,_=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()

def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',54321))
 while True:
  b,a=s.recvfrom(4096);s.sendto(b,a)
for p in (12345,12346):threading.Thread(target=tcp,args=(p,),daemon=True).start()
threading.Thread(target=udp,daemon=True).start()
while True:time.sleep(60)
'''


def connect(client, dest, port=12345, expected=True, udp=False):
    code = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if sys.argv[3]=='udp' else socket.SOCK_STREAM)
s.settimeout(1.5)
try:
 s.connect((sys.argv[1],int(sys.argv[2])));s.send(b'waypoint');ok=s.recv(8)==b'waypoint'
except OSError:ok=False
sys.exit(0 if ok else 1)
'''
    result = docker('exec', client, 'python3', '-c', code, dest, str(port), 'udp' if udp else 'tcp', check=False)
    assert (result.returncode == 0) == expected, f'Unexpected connectivity result for port {port}, expected {expected}'


def peer(client, ident, public, dest, expires):
    return {'id': ident, 'public_key': public, 'address': f'10.77.0.{ident+1}/32',
            'rules': [{'id': ident, 'cidr': dest + '/32', 'protocol': 'tcp', 'ports': '12345', 'expires': expires}]}


def main():
    global online
    server = None
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        control = Path(temporary) / 'control'
        control.mkdir(mode=0o755)
        (control / 'token').write_text(control_token)
        os.chmod(control / 'token', 0o644)  # disposable fixture token; production uses 0640
        server = Server(str(control / 'control.sock'), Control)
        os.chmod(control / 'control.sock', 0o666)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            for suffix in ('backend', 'outside'):
                name = prefix + '-' + suffix
                docker('network', 'create', '--internal', name)
                networks.append(name)
            backend, outside = networks
            target = run_container('target', backend)
            other = run_container('other', backend)
            for name in (target, other):
                docker('exec', '-d', name, 'python3', '-c', server_code)
            data = prefix + '-data'
            docker('volume', 'create', data)
            volumes.append(data)
            gateway = prefix + '-gateway'
            docker('run', '-d', '--name', gateway, '--network', backend,
                   '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--security-opt=no-new-privileges',
                   '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv6.conf.all.disable_ipv6=1',
                   '--read-only', '--tmpfs', '/tmp', '-v', str(control) + ':/control:ro',
                   '-v', data + ':/gateway', '--entrypoint', '/gateway-agent', 'waypoint-vpn-test:local')
            containers.append(gateway)
            docker('network', 'connect', outside, gateway)
            clients = [run_container('alice', outside), run_container('bob', outside)]
            # Management listener on the gateway to prove INPUT policy, not absence of a server.
            docker('exec', '-d', gateway, 'python3', '-c', server_code)
            gateway_ip = ip(gateway, outside)
            target_ip, other_ip = ip(target, backend), ip(other, backend)
            install([])
            for _ in range(80):
                result = docker('exec', gateway, 'wg', 'show', 'wg0', 'public-key', check=False)
                if result.returncode == 0 and result.stdout.strip():
                    gateway_pub = result.stdout.strip()
                    break
                time.sleep(.1)
            else:
                raise AssertionError('Gateway failed to start: ' + docker('logs', gateway))
            publics = []
            for ident, client in enumerate(clients, 1):
                private = docker('exec', client, 'wg', 'genkey')
                public = docker('exec', '-i', client, 'wg', 'pubkey', data=private)
                publics.append(public)
                conf = f'[Interface]\nPrivateKey = {private}\n[Peer]\nPublicKey = {gateway_pub}\nEndpoint = {gateway_ip}:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 1\n'
                docker('exec', client, 'ip', 'link', 'add', 'wg0', 'type', 'wireguard')
                docker('exec', '-i', client, 'python3', '-c', "import sys;open('/tmp/wg.conf','w').write(sys.stdin.read())", data=conf)
                docker('exec', client, 'wg', 'setconf', 'wg0', '/tmp/wg.conf')
                docker('exec', client, 'ip', 'addr', 'add', f'10.77.0.{ident+1}/32', 'dev', 'wg0')
                docker('exec', client, 'ip', 'link', 'set', 'wg0', 'mtu', '1280', 'up')
                for dest in (target_ip + '/32', other_ip + '/32', '10.77.0.0/24'):
                    docker('exec', client, 'ip', 'route', 'add', dest, 'dev', 'wg0')
            alice, bob = clients
            peers = [peer(alice, 1, publics[0], target_ip, deadline(300)), peer(bob, 2, publics[1], other_ip, deadline(300))]
            install(peers)
            connect(alice, target_ip)
            connect(bob, other_ip)
            connect(alice, target_ip, 12346, False)
            connect(alice, other_ip, expected=False)
            connect(bob, target_ip, expected=False)
            connect(alice, target_ip, 54321, False, udp=True)
            print('PASS per-peer destination and port ACLs with client AllowedIPs=0.0.0.0/0', flush=True)
            peers[0]['rules'].append({'id': 3, 'cidr': target_ip + '/32', 'protocol': 'udp', 'ports': '54321', 'expires': deadline(300)})
            install(peers)
            connect(alice, target_ip, 54321, True, udp=True)
            connect(bob, target_ip, 54321, False, udp=True)
            print('PASS explicit UDP approval', flush=True)
            connect(alice, gateway_ip)  # control server exists on external interface
            connect(alice, '10.77.0.1', expected=False)
            docker('exec', '-d', bob, 'python3', '-c', server_code)
            connect(alice, '10.77.0.3', expected=False)
            print('PASS gateway INPUT and peer isolation', flush=True)
            docker('exec', alice, 'ip', 'addr', 'del', '10.77.0.2/32', 'dev', 'wg0')
            docker('exec', alice, 'ip', 'addr', 'add', '10.77.0.3/32', 'dev', 'wg0')
            for dest in (target_ip + '/32', other_ip + '/32', '10.77.0.0/24'):
                docker('exec', alice, 'ip', 'route', 'replace', dest, 'dev', 'wg0', 'src', '10.77.0.3')
            connect(alice, other_ip, expected=False)
            docker('exec', alice, 'ip', 'addr', 'del', '10.77.0.3/32', 'dev', 'wg0')
            docker('exec', alice, 'ip', 'addr', 'add', '10.77.0.2/32', 'dev', 'wg0')
            for dest in (target_ip + '/32', other_ip + '/32', '10.77.0.0/24'):
                docker('exec', alice, 'ip', 'route', 'replace', dest, 'dev', 'wg0', 'src', '10.77.0.2')
            connect(alice, target_ip)
            print('PASS spoofed tunnel source rejected by WireGuard', flush=True)
            # Keep a connection alive across policy removal, then try the SAME socket.
            persistent = subprocess.Popen(['docker', 'exec', '-i', alice, 'python3', '-u', '-c',
                "import socket,sys;s=socket.create_connection((sys.argv[1],12345),3);s.settimeout(2);s.sendall(b'before');print(s.recv(6).decode(),flush=True);input();\ntry:s.sendall(b'after');print(s.recv(5).decode(),flush=True)\nexcept OSError:print('blocked',flush=True)", target_ip], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            first = persistent.stdout.readline().strip()
            assert first == 'before', 'Persistent socket setup failed: ' + persistent.stderr.read() if not first else first
            install([peers[1]])
            out, err = persistent.communicate('\n', timeout=8)
            assert out.strip() == 'blocked', 'Established flow survived revocation: ' + out + err
            connect(alice, target_ip, expected=False)
            print('PASS revocation removes established flows', flush=True)
            install(peers)
            docker('restart', gateway)
            for _ in range(80):
                if docker('exec', gateway, 'wg', 'show', 'wg0', 'peers', check=False).stdout.count('\n') >= 2:
                    break
                time.sleep(.15)
            # A restarted server has lost ephemeral handshake sessions; allow client re-handshake.
            for attempt in range(25):
                try:
                    connect(alice, target_ip)
                    break
                except AssertionError:
                    if attempt == 24:
                        raise
                    time.sleep(1)
            print('PASS gateway restart restores approved peers and firewall', flush=True)
            peers[0]['rules'] = [peers[0]['rules'][0]]
            peers[0]['rules'][0]['expires'] = deadline(12)
            peers[1]['rules'][0]['expires'] = deadline(12)
            install(peers)
            with mutex:
                online = False
            connect(alice, target_ip)
            # Stop the agent itself: kernel set timeouts must still stop traffic.
            docker('kill', '--signal=STOP', gateway)
            time.sleep(13)
            connect(alice, target_ip, expected=False)
            connect(bob, other_ip, expected=False)
            print('PASS expiry enforced while portal unavailable and gateway agent suspended', flush=True)
            docker('kill', '--signal=CONT', gateway)
            time.sleep(6)
            assert not docker('exec', gateway, 'wg', 'show', 'wg0', 'peers')
            print('PASS expired WireGuard peers removed while portal remains unavailable', flush=True)
        finally:
            for name in reversed(containers):
                docker('rm', '-f', name, check=False)
            for name in volumes:
                docker('volume', 'rm', name, check=False)
            for name in reversed(networks):
                docker('network', 'rm', name, check=False)
            if server:
                server.shutdown()
                server.server_close()


if __name__ == '__main__':
    main()
