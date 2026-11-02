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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts import h454_wss_relay_prepare as prepare

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
prepared_id = None
prepared_name = prefix + '-prepared'
request_pin = hashlib.sha256(('synthetic-' + nonce).encode('ascii')).hexdigest()

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
    old = {mount['Destination']: mount for mount in old_mounts}
    new = {mount['Destination']: mount for mount in new_mounts}
    for suffix, destination in (('PROXY', '/run/h454-wss/proxy.mjs'), ('KEY', '/run/h454-wss/relay.key'),
                                ('CERT', '/run/h454-wss/relay.crt')):
        if destination not in old or destination not in new:
            print('H454_FIXTURE_' + prefix_name + '_' + suffix + '=MISSING')
        else:
            changed = sorted(k.upper() for k in set(old[destination]) | set(new[destination])
                             if re.fullmatch(r'[A-Za-z0-9_]+', k) and old[destination].get(k) != new[destination].get(k))
            print('H454_FIXTURE_' + prefix_name + '_' + suffix + '=' + (','.join(changed) if changed else 'NONE'))

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
    if (network_data['Id'] != network or network_data['Name'] != prefix or
            network_data['Labels'].get('com.hermes.h454.fixture') != nonce or not network_data['Internal']):
        raise ValueError('NETWORK')
    ipam = network_data['IPAM']['Config']
    if len(ipam) != 1:
        raise ValueError('NETWORK')
    subnet = ipaddress.IPv4Network(ipam[0]['Subnet'])
    gateway = ipaddress.IPv4Address(ipam[0]['Gateway'])
    if network_data.get('Containers'):
        raise ValueError('NETWORK')
    # Reserve Docker's chosen range again with explicit IPAM for static addresses.
    phase = 'EXPLICIT_NETWORK'
    run(docker + ['network', 'rm', network], timeout=15)
    network = None
    network = run(docker + ['network', 'create', '--internal', '--subnet', str(subnet),
                            '--gateway', str(gateway), '--label', label, prefix])
    network_data = inspect('network', network)
    if (network_data['Id'] != network or network_data['Name'] != prefix or
            network_data['Labels'].get('com.hermes.h454.fixture') != nonce or
            network_data['Internal'] is not True or network_data.get('Containers') or
            len(network_data['IPAM']['Config']) != 1 or
            network_data['IPAM']['Config'][0]['Subnet'] != str(subnet) or
            network_data['IPAM']['Config'][0]['Gateway'] != str(gateway)):
        raise ValueError('NETWORK')
    relay_ip = str(next(ip for ip in subnet.hosts() if ip != gateway))
    relay_code = "require('node:http').createServer((q,s)=>{s.writeHead(q.url==='/health'?200:404);s.end()}).listen(3000,'127.0.0.1')"
    phase = 'CREATE_RELAY'
    relay = new_container('relay', ['--network', network, '--ip', relay_ip, '--entrypoint', 'node', image, '-e', relay_code])
    phase = 'PREPARE_SIDECAR'
    request = {'account': 'fixture', 'public_key': 'synthetic', 'relay_id': relay, 'relay_image': image,
               'network_id': network, 'relay_ip': relay_ip}
    manifest = {'ca_sha256': digest(tls + '/ca.crt'), 'certificate_sha256': digest(tls + '/relay.crt')}
    with mock.patch.object(prepare, 'PARENT', Path(directory)), \
         mock.patch.object(prepare, 'NAME', 'prepared'), mock.patch.object(prepare, 'CONTAINER', prepared_name), \
         mock.patch.object(prepare.authorization, 'RELAY_NAME', prefix + '-relay'), \
         mock.patch.object(prepare.authorization, 'NETWORK_NAME', prefix), \
         mock.patch.object(prepare.authorization, '_registry', side_effect=lambda _create: os.open(directory, os.O_RDONLY)), \
         mock.patch.object(prepare.authorization, '_locked', side_effect=lambda _fd: os.open('/dev/null', os.O_RDONLY)), \
         mock.patch.object(prepare.authorization, '_request', return_value=request), \
         mock.patch.object(prepare.authorization, 'snapshot', return_value=request), \
         mock.patch.object(prepare.identity, 'PARENT', Path(directory)), \
         mock.patch.object(prepare.identity, 'NAME', 'tls'), \
         mock.patch.object(prepare.identity, 'verify', return_value=manifest):
        try:
            pin = prepare.prepare(request_pin, manifest['ca_sha256'], hashlib.sha256(proxy).hexdigest(),
                                  hashlib.sha256(reconciler).hexdigest(), proxy, reconciler)
        except subprocess.TimeoutExpired:
            uncertain = True
            raise ValueError('TIMEOUT')
        prepared = inspect('container', prepared_name)
        prepared_id = prepared['Id']
        containers.append(prepared_id)
        prepared_directory = directory + '/prepared'
        pins_raw = Path(prepared_directory + '/pins.json').read_bytes()
        if (hashlib.sha256(pins_raw).hexdigest() != pin or prepared['State']['Status'] != 'created' or
                json.loads(pins_raw)['sidecar_id'] != prepared_id or
                os.path.lexists(prepared_directory + '/prepare.pending')):
            raise ValueError('PREPARED')
        try:
            if prepare.reconcile.reconcile(prepared_directory + '/pins.json') != 'RESTARTED' or \
                    prepare.reconcile.reconcile(prepared_directory + '/pins.json') != 'READY':
                raise ValueError('PREPARED')
        except (prepare.reconcile.Hold, OSError):
            current = inspect('container', prepared_id)
            profile_changes(prepared, current, 'PREPARED_PROFILE')
            def hostname_kind(value):
                if value == '':
                    return 'EMPTY'
                if value == prepared_id[:12]:
                    return 'SIDECAR_ID'
                if value == relay[:12]:
                    return 'RELAY_ID'
                return 'OTHER'
            def bool_kind(value):
                return 'NULL' if value is None else 'TRUE' if value is True else 'FALSE' if value is False else 'OTHER'
            print('H454_FIXTURE_HOSTNAME_BEFORE=' + hostname_kind(prepared['Config']['Hostname']))
            print('H454_FIXTURE_HOSTNAME_AFTER=' + hostname_kind(current['Config']['Hostname']))
            print('H454_FIXTURE_OOM_BEFORE=' + bool_kind(prepared['HostConfig']['OomKillDisable']))
            print('H454_FIXTURE_OOM_AFTER=' + bool_kind(current['HostConfig']['OomKillDisable']))
            print('H454_FIXTURE_PREPARED_STATE=' + ('RUNNING' if current['State']['Running'] else 'NOT_RUNNING'))
            try:
                current_relay, current_sidecar = prepare.reconcile._snapshot(json.loads(pins_raw), Path(prepared_directory), Path(tls))
                prepare.reconcile._namespace(current_relay, current_sidecar)
                prepare.reconcile._tls(json.loads(pins_raw), Path(tls + '/ca.crt').read_bytes())
                print('H454_FIXTURE_PREPARED_PROBE=PASS')
            except Exception as error:
                reason = str(error)
                print('H454_FIXTURE_PREPARED_PROBE=' + (reason if re.fullmatch(r'[A-Z_]{1,60}', reason) else 'OTHER'))
            raise
        try:
            prepare._port_free(inspect('container', relay)['State']['Pid'])
        except prepare.reconcile.Hold as error:
            if str(error) != 'PORT_OCCUPIED':
                raise
        else:
            raise ValueError('PORT_CHECK')
        obj = inspect('container', prepared_id)
        if (obj['Id'] != prepared_id or obj['Name'] != '/' + prepared_name or obj['Image'] != image or
                obj['Config']['Labels'].get('com.hermes.h454.role') != 'wss-proxy' or
                obj['Config']['Labels'].get('com.hermes.h454.request') != request_pin):
            raise ValueError('CONTAINER_ID')
        run(docker + ['rm', '-f', prepared_id], timeout=20)
        containers.remove(prepared_id)
        prepared_id = None
        print('H454_FIXTURE_PREPARE_AND_START=PASS')
        print('H454_FIXTURE_OCCUPIED_PORT=REFUSED')
    phase = 'CREATE_SIDECAR'
    sidecar = new_container('sidecar', ['--network', 'container:' + relay, '--restart', 'unless-stopped',
                            '-e', 'H454_SSH_SOURCE_IPV4=' + str(gateway),
                            '--mount', 'type=bind,src=' + operator + '/proxy.mjs,dst=/run/h454-wss/proxy.mjs,readonly',
                            '--mount', 'type=bind,src=' + tls + '/relay.key,dst=/run/h454-wss/relay.key,readonly',
                            '--mount', 'type=bind,src=' + tls + '/relay.crt,dst=/run/h454-wss/relay.crt,readonly',
                            '--entrypoint', 'node', image, '/run/h454-wss/proxy.mjs'])
    sidecar_data = inspect('container', sidecar)
    profile = {key: sidecar_data[key] for key in ('Config', 'HostConfig', 'Mounts')}
    profile['Config'] = dict(profile['Config'])
    profile['HostConfig'] = dict(profile['HostConfig'])
    oom = profile['HostConfig']['OomKillDisable']
    if (profile['Config']['Hostname'] not in (sidecar[:12], relay[:12]) or
            (oom is not None and oom is not False)):
        raise ValueError('PROFILE')
    profile['Config']['Hostname'] = '<docker-container-network>'
    profile['HostConfig']['OomKillDisable'] = False
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
    if isinstance(error, subprocess.TimeoutExpired):
        uncertain = True
    reason = str(error)
    if re.fullmatch(r'[A-Z_]{1,60}', reason):
        print('H454_RECONCILE_FIXTURE_REASON=' + reason)
    print('H454_RECONCILE_FIXTURE_PHASE=' + phase)
    print('H454_RECONCILE_FIXTURE=HOLD_' + (reason if reason in
          {'ROOT','IMAGE','NETWORK','COMMAND','TIMEOUT','CONTAINER_ID','INSPECT','INITIAL_READY','WATCHDOG','RECOVERY','REPEAT','PENDING','PREPARED','PORT_CHECK'} else 'INTERNAL'))
finally:
    if not uncertain:
        try:
            if prepared_id is None:
                found = run(docker + ['container', 'ls', '--all', '--filter', 'name=^/' + prepared_name + '$',
                                      '--format', '{{.Names}}'])
                if found:
                    if found != prepared_name:
                        raise ValueError('CLEANUP_PIN')
                    obj = inspect('container', prepared_name)
                    if (obj['Name'] != '/' + prepared_name or obj['Image'] != image or
                            obj['Config']['Labels'].get('com.hermes.h454.role') != 'wss-proxy' or
                            obj['Config']['Labels'].get('com.hermes.h454.request') != request_pin):
                        raise ValueError('CLEANUP_PIN')
                    containers.append(obj['Id'])
            for identity in reversed(containers):
                obj = inspect('container', identity)
                fixture_owned = obj['Config']['Labels'].get('com.hermes.h454.fixture') == nonce
                prepared_owned = (obj['Name'] == '/' + prepared_name and
                                  obj['Config']['Labels'].get('com.hermes.h454.role') == 'wss-proxy' and
                                  obj['Config']['Labels'].get('com.hermes.h454.request') == request_pin)
                if obj['Id'] != identity or obj['Image'] != image or not (fixture_owned or prepared_owned):
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
                                    ('prepared', {'proxy.mjs','reconcile.py','pins.json','prepare.pending','reconcile.pending'}),
                                    ('tls', {'relay.key','relay.crt','ca.crt'})]:
                path = os.path.join(directory, subdir)
                if subdir == 'prepared' and not os.path.lexists(path):
                    continue
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
