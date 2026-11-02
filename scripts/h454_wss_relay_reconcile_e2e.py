"""Exercise sidecar reconciliation in disposable Docker resources only."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time

docker = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
nonce = secrets.token_hex(16)
label = 'com.hermes.h454.fixture=' + nonce
prefix = 'h454-reconcile-fixture-' + nonce
directory = tempfile.mkdtemp(prefix=prefix + '-', dir='/tmp')
containers = []
network = None
uncertain = False
passed = False
image = None
phase = 'PREPARE'

def run(args, timeout=20, expected=0):
    global uncertain
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        uncertain = True
        raise ValueError('TIMEOUT')
    if result.returncode != expected:
        if args[:1] == ['/usr/bin/python3']:
            for line in result.stdout.splitlines():
                if re.fullmatch(r'H454_WSS_RECONCILE(?:_REASON)?=[A-Z_]+', line):
                    print(line)
        else:
            error = result.stderr.lower()
            reason = ('STATIC_IPAM' if 'user specified ip address' in error else
                      'NETWORK_OVERLAP' if 'overlaps with other one' in error else
                      'ADDRESS_IN_USE' if 'address already in use' in error else
                      'NO_IP_POOL' if 'could not find an available' in error else 'OTHER')
            print('H454_FIXTURE_COMMAND_REASON=' + reason)
        raise ValueError('COMMAND')
    return result.stdout.strip()

def inspect(kind, identity):
    value = json.loads(run(docker + [kind, 'inspect', identity]))
    if len(value) != 1:
        raise ValueError('INSPECT')
    return value[0]

def new_container(name, args):
    result = run(docker + ['run', '-d', '--pull=never', '--name', prefix + '-' + name,
                           '--label', label, '--read-only', '--user', '65534:65534',
                           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                           '--pids-limit', '32', '--memory', '128m'] + args)
    if len(result) != 64 or any(c not in '0123456789abcdef' for c in result):
        raise ValueError('CONTAINER_ID')
    containers.append(result)
    return result

def digest(path):
    with open(path, 'rb') as file:
        return hashlib.sha256(file.read()).hexdigest()

def make_file(path, data, mode):
    with open(path, 'xb') as file:
        file.write(data)
    os.chmod(path, mode)

def profile_changes(before, after, prefix_name):
    for section in ('Config', 'HostConfig'):
        old, new = before[section], after[section]
        changed = sorted(k.upper() for k in set(old) | set(new)
                         if re.fullmatch(r'[A-Za-z0-9_]+', k) and old.get(k) != new.get(k))
        print('H454_FIXTURE_' + prefix_name + '_' + section.upper() + '=' + (','.join(changed) if changed else 'NONE'))
    print('H454_FIXTURE_' + prefix_name + '_MOUNTS=' + ('CHANGED' if before['Mounts'] != after['Mounts'] else 'SAME'))
    old_mounts = sorted(before['Mounts'], key=lambda mount: mount['Destination'])
    new_mounts = sorted(after['Mounts'], key=lambda mount: mount['Destination'])
    print('H454_FIXTURE_' + prefix_name + '_MOUNT_SET=' + ('SAME' if old_mounts == new_mounts else 'CHANGED'))

try:
    if os.geteuid() != 0:
        raise ValueError('ROOT')
    phase = 'INSPECT_IMAGE'
    if len(sys.argv) != 2:
        raise ValueError('IMAGE')
    image = inspect('image', sys.argv[1])['Id']
    if re.fullmatch(r'sha256:[a-f0-9]{64}', image) is None:
        raise ValueError('IMAGE')
    source = Path(__file__).resolve().parent
    proxy = (source / 'h454_wss_relay_proxy.mjs').read_bytes()
    reconciler = (source / 'h454_wss_relay_reconcile.py').read_bytes()
    operator = directory + '/operator'
    tls = directory + '/tls'
    os.mkdir(operator, 0o700)
    os.mkdir(tls, 0o700)
    make_file(operator + '/proxy.mjs', proxy, 0o444)
    make_file(operator + '/reconcile.py', reconciler, 0o444)
    phase = 'CERTIFICATE'
    run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-subj', '/CN=brc-agent.internal', '-addext', 'subjectAltName=DNS:brc-agent.internal',
         '-keyout', tls + '/relay.key', '-out', tls + '/relay.crt'], timeout=30)
    with open(tls + '/relay.crt', 'rb') as file:
        make_file(tls + '/ca.crt', file.read(), 0o444)
    os.chown(tls + '/relay.key', 0, 65534)
    os.chmod(tls + '/relay.key', 0o440)
    os.chmod(tls + '/relay.crt', 0o444)
    phase = 'CREATE_NETWORK'
    network = run(docker + ['network', 'create', '--internal', '--label', label, prefix])
    phase = 'INSPECT_NETWORK'
    network_data = inspect('network', network)
    if network_data['Labels'].get('com.hermes.h454.fixture') != nonce or not network_data['Internal']:
        raise ValueError('NETWORK')
    ipam = network_data['IPAM']['Config']
    if len(ipam) != 1:
        raise ValueError('NETWORK')
    subnet = ipaddress.IPv4Network(ipam[0]['Subnet'])
    gateway = ipaddress.IPv4Address(ipam[0]['Gateway'])
    relay_ip = str(next(ip for ip in subnet.hosts() if ip != gateway))
    relay_code = "require('node:http').createServer((q,s)=>{s.writeHead(q.url==='/health'?200:404);s.end()}).listen(3000,'127.0.0.1')"
    phase = 'CREATE_RELAY'
    relay = new_container('relay', ['--network', network, '--ip', relay_ip, '--entrypoint', 'node', image, '-e', relay_code])
    phase = 'CREATE_SIDECAR'
    sidecar = new_container('sidecar', ['--network', 'container:' + relay, '--restart', 'unless-stopped',
                            '-e', 'H454_SSH_SOURCE_IPV4=' + str(gateway),
                            '--mount', 'type=bind,src=' + operator + '/proxy.mjs,dst=/run/h454-wss/proxy.mjs,readonly',
                            '--mount', 'type=bind,src=' + tls + '/relay.key,dst=/run/h454-wss/relay.key,readonly',
                            '--mount', 'type=bind,src=' + tls + '/relay.crt,dst=/run/h454-wss/relay.crt,readonly',
                            '--entrypoint', 'node', image, '/run/h454-wss/proxy.mjs'])
    sidecar_data = inspect('container', sidecar)
    profile = {key: sidecar_data[key] for key in ('Config', 'HostConfig', 'Mounts')}
    profile['Mounts'] = sorted(profile['Mounts'], key=lambda mount: mount['Destination'])
    profile_raw = json.dumps(profile, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    pins = {'version': 1, 'relay_id': relay, 'relay_name': prefix + '-relay', 'relay_image': image,
            'network_id': network, 'network_name': prefix, 'relay_ipv4': relay_ip,
            'gateway_ipv4': str(gateway), 'sidecar_id': sidecar, 'sidecar_name': prefix + '-sidecar',
            'sidecar_image': image, 'profile_sha256': hashlib.sha256(profile_raw).hexdigest(),
            'proxy_sha256': digest(operator + '/proxy.mjs'), 'ca_sha256': digest(tls + '/ca.crt'),
            'certificate_sha256': digest(tls + '/relay.crt'), 'key_sha256': digest(tls + '/relay.key'),
            'tls_directory': tls}
    make_file(operator + '/pins.json', json.dumps(pins).encode('ascii'), 0o600)
    command = ['/usr/bin/python3', operator + '/reconcile.py', '--config', operator + '/pins.json']
    phase = 'INITIAL_READY'
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if result.returncode == 0 and result.stdout.strip() == 'H454_WSS_RECONCILE=READY':
            break
        time.sleep(0.5)
    else:
        profile_changes(sidecar_data, inspect('container', sidecar), 'INITIAL_REFUSED_PROFILE')
        namespace = {'__name__': 'fixture_reconciler'}
        exec(compile(reconciler, 'fixture_reconciler', 'exec'), namespace)
        try:
            namespace['reconcile'](operator + '/pins.json')
        except Exception as error:
            reason = str(error)
            allowed = {'PINS','FILE','FILE_DRIFT','RELAY','RELAY_NETWORK','NETWORK','NAMESPACE','TLS_PROBE'}
            print('H454_FIXTURE_RECONCILE_REASON=' + (reason if reason in allowed or
                  re.fullmatch(r'SIDECAR_[A-Z_]+', reason) else 'OTHER'))
        raise ValueError('INITIAL_READY')
    print('H454_FIXTURE_RECONCILE_READY=PASS')
    phase = 'STOP_RELAY'
    run(docker + ['stop', '--time', '2', relay], timeout=15)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        obj = inspect('container', sidecar)
        if obj['RestartCount'] >= 1:
            break
        time.sleep(1)
    else:
        raise ValueError('WATCHDOG')
    if obj['Id'] != sidecar or obj['Image'] != image or obj['Config']['Labels'].get('com.hermes.h454.fixture') != nonce:
        raise ValueError('CONTAINER_ID')
    # Docker versions differ in whether they keep retrying a missing namespace.
    run(docker + ['stop', '--time', '2', sidecar], timeout=15)
    if inspect('container', sidecar)['State']['Status'] != 'exited':
        raise ValueError('WATCHDOG')
    phase = 'START_RELAY'
    run(docker + ['start', relay], timeout=15)
    phase = 'RECONCILE'
    try:
        output = run(command, timeout=45)
    except ValueError:
        try:
            current = inspect('container', sidecar)
            profile_changes(sidecar_data, current, 'REFUSED_PROFILE')
            print('H454_FIXTURE_SIDECAR_IDENTITY=' + ('SAME' if current['Id'] == sidecar and
                  current['Image'] == image and current['Name'] == '/' + prefix + '-sidecar' else 'CHANGED'))
        except ValueError:
            print('H454_FIXTURE_PROFILE_INSPECT=HOLD')
        raise
    if output != 'H454_WSS_RECONCILE=RESTARTED':
        raise ValueError('RECOVERY')
    if run(command, timeout=15) != 'H454_WSS_RECONCILE=READY':
        raise ValueError('REPEAT')
    print('H454_FIXTURE_RECONCILE_LONG_OUTAGE=PASS')
    make_file(operator + '/reconcile.pending', b'synthetic pending\n', 0o600)
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    if result.returncode != 2 or result.stdout.splitlines() != [
            'H454_WSS_RECONCILE=HOLD', 'H454_WSS_RECONCILE_REASON=PENDING']:
        raise ValueError('PENDING')
    os.unlink(operator + '/reconcile.pending')
    print('H454_FIXTURE_RECONCILE_PENDING=REFUSED')
    passed = True
except Exception as error:
    reason = str(error)
    print('H454_RECONCILE_FIXTURE_PHASE=' + phase)
    print('H454_RECONCILE_FIXTURE=HOLD_' + (reason if reason in
          {'ROOT','IMAGE','NETWORK','COMMAND','TIMEOUT','CONTAINER_ID','INSPECT','INITIAL_READY','WATCHDOG','RECOVERY','REPEAT','PENDING'} else 'INTERNAL'))
finally:
    if not uncertain:
        try:
            for identity in reversed(containers):
                obj = inspect('container', identity)
                if obj['Id'] != identity or obj['Image'] != image or obj['Config']['Labels'].get('com.hermes.h454.fixture') != nonce:
                    raise ValueError('CLEANUP_PIN')
                run(docker + ['rm', '-f', identity], timeout=20)
            if network:
                obj = inspect('network', network)
                if obj['Id'] != network or obj['Labels'].get('com.hermes.h454.fixture') != nonce or obj['Containers']:
                    raise ValueError('CLEANUP_PIN')
                run(docker + ['network', 'rm', network], timeout=15)
            if os.path.realpath(directory) != directory or os.path.dirname(directory) != '/tmp' or not os.path.basename(directory).startswith(prefix + '-'):
                raise ValueError('CLEANUP_PATH')
            for subdir, allowed in [('operator', {'proxy.mjs','reconcile.py','pins.json','reconcile.pending'}),
                                    ('tls', {'relay.key','relay.crt','ca.crt'})]:
                path = os.path.join(directory, subdir)
                if not os.path.isdir(path) or os.path.islink(path) or not set(os.listdir(path)) <= allowed:
                    raise ValueError('CLEANUP_FILES')
                for name in os.listdir(path):
                    target = os.path.join(path, name)
                    if not stat.S_ISREG(os.lstat(target).st_mode):
                        raise ValueError('CLEANUP_FILES')
                    os.unlink(target)
                os.rmdir(path)
            os.rmdir(directory)
            print('H454_RECONCILE_FIXTURE_CLEANUP=PASS')
        except Exception:
            print('H454_RECONCILE_FIXTURE_CLEANUP=HOLD')
            passed = False
    else:
        print('H454_RECONCILE_FIXTURE_CLEANUP=HOLD')
        passed = False

sys.exit(0 if passed else 2)
