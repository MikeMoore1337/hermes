"""Apply a pre-reviewed YFC-only sshd rule without authorizing any key."""
from __future__ import annotations

import argparse
try:
    import fcntl
except ImportError:
    fcntl = None
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import ssl
import stat
import subprocess
import tempfile

STAGE = Path('/root/h454-yfc-forward-policy-804a221')
CONFIG = Path('/etc/ssh/sshd_config')
INCLUDES = Path('/etc/ssh/sshd_config.d')
NAME = 'zz-h454-yfc-forward.conf'
ACCOUNT = 'hermes-yfc-forward'
CA = Path('/opt/hermes-commander-native/trust/ca.crt')
CA_SHA = '014868af3edc97e04c58099746964bde1d65d2f38c931360e27a8f309b8c0f7c'
FIELDS = frozenset({'version','target','policy_sha256','base_config_sha256','include_sha256',
                    'relay_id','sidecar_id','network_id','existing_accounts_checked','installation'})
HEX = re.compile(r'[a-f0-9]{64}\Z')


class Hold(ValueError):
    pass


class Unsettled(Hold):
    pass


def require(value):
    if not value:
        raise Hold('YFC_SSH_POLICY_HOLD')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path, *, mode=None, maximum=131072):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and (mode is None or stat.S_IMODE(before.st_mode) == mode)
                and 0 <= before.st_size <= maximum)
        data = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        require(len(data) == before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                == (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
        return data
    finally:
        os.close(fd)


def run(args, timeout=15):
    p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=timeout, check=True,
                       env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(len(p.stdout) <= 1048576)
    return p.stdout


def policy(address):
    ip = ipaddress.IPv4Address(address)
    require(str(ip) == address and any(ip in ipaddress.IPv4Network(c) for c in
            ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')))
    return '\n'.join((
        'Match User '+ACCOUNT, '    AuthenticationMethods publickey',
        '    AllowTcpForwarding local', '    AllowStreamLocalForwarding no',
        '    PermitOpen '+address+':3001', '    PermitListen none',
        '    PasswordAuthentication no', '    KbdInteractiveAuthentication no',
        '    PermitTTY no', '    X11Forwarding no', '    AllowAgentForwarding no',
        '    PermitTunnel no', '    PermitUserRC no', '    ForceCommand /usr/sbin/nologin', '')).encode('ascii')


def read_plan(pin):
    require(type(pin) is str and HEX.fullmatch(pin) is not None)
    directory = STAGE.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and stat.S_IMODE(directory.st_mode) == 0o700)
    raw = read_file(STAGE/'plan.json', mode=0o600, maximum=16384)
    require(sha(raw) == pin)
    data = json.loads(raw)
    require(type(data) is dict and set(data) == FIELDS and type(data['version']) is int and data['version'] == 1
            and data['target'] == 'yfc-vps' and data['installation'] is False
            and type(data['existing_accounts_checked']) is int
            and all(type(data[x]) is str and HEX.fullmatch(data[x]) for x in
                    ('policy_sha256','base_config_sha256','relay_id','sidecar_id','network_id'))
            and type(data['include_sha256']) is dict
            and all(type(k) is str and re.fullmatch(r'[A-Za-z0-9_.-]+\.conf',k)
                    and type(v) is str and HEX.fullmatch(v) for k,v in data['include_sha256'].items())
            and json.dumps(data,sort_keys=True,separators=(',',':')).encode('ascii') == raw)
    return data


def _users():
    accounts = pwd.getpwall()
    users = sorted(p.pw_name for p in accounts if re.fullmatch(r'[a-z_][a-z0-9_-]*',p.pw_name))
    require(len(users)==len(accounts) and len(set(users))==len(users) and 'root' in users and ACCOUNT not in users)
    try:
        pwd.getpwnam(ACCOUNT)
    except KeyError:
        pass
    else:
        raise Hold('YFC_SSH_POLICY_HOLD')
    return users


def _trusted_directory(path):
    for item in (path,*path.parents):
        s=item.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode & 0o022)


def _running_sshd():
    raw=run(['/usr/bin/systemctl','show','ssh.service','-p','MainPID','--value']).strip()
    require(re.fullmatch(rb'[1-9][0-9]*',raw) is not None)
    pid=int(raw)
    require(pid>1)
    title=Path('/proc').joinpath(str(pid),'cmdline').read_bytes()
    require(re.fullmatch(rb'sshd: /usr/sbin/sshd -D \[listener\] [0-9]+ of [0-9]+-[0-9]+ startups\x00*',title) is not None)
    listeners=run(['/usr/bin/ss','-lntp']).decode('utf-8').splitlines()
    require(any(':25566 ' in line and ('pid='+str(pid)+',') in line for line in listeners))
    return pid


def _safe_prior_matches(source, includes):
    for data in (source, *includes):
        for raw in data.decode('utf-8').splitlines():
            parts=raw.strip().split()
            if not parts or parts[0].startswith('#') or parts[0].lower()!='match':
                continue
            if len(parts)==2 and parts[1].lower()=='all':
                continue
            require(len(parts)==3 and parts[1].lower()=='user' and
                    re.fullmatch(r'[a-z_][a-z0-9_-]*',parts[2]) is not None and
                    parts[2].lower()!=ACCOUNT)
    for data in includes:
        for raw in data.decode('utf-8').splitlines():
            parts=raw.strip().split()
            require(not parts or parts[0].startswith('#') or parts[0].lower()!='include')


def _settings(config, user, address='127.0.0.1'):
    return run(['/usr/sbin/sshd','-T','-f',str(config),'-C',
                'user='+user+',addr='+address+',host=localhost'])


def _validate_target(settings, address):
    options={}
    for line in settings.decode('ascii').splitlines():
        name,sep,value=line.partition(' ')
        require(bool(sep))
        options.setdefault(name,[]).append(value)
    required = {'authenticationmethods':'publickey','allowtcpforwarding':'local',
                'allowstreamlocalforwarding':'no','permitopen':address+':3001','permitlisten':'none',
                'passwordauthentication':'no','kbdinteractiveauthentication':'no','permittty':'no',
                'x11forwarding':'no','allowagentforwarding':'no','permittunnel':'no','permituserrc':'no',
                'forcecommand':'/usr/sbin/nologin','pubkeyauthentication':'yes',
                'authorizedkeyscommand':'none','authorizedkeysfile':'.ssh/authorized_keys .ssh/authorized_keys2',
                'strictmodes':'yes'}
    require(all(options.get(name)==[value] for name,value in required.items()))


def _relay_address(plan, relay, sidecar):
    network=relay['NetworkSettings']['Networks']['hermes-brc-internal']
    require(relay['Id'] == plan['relay_id'] and sidecar['Id'] == plan['sidecar_id']
            and network['NetworkID'] == plan['network_id'] and relay['State']['Running'] is True
            and sidecar['State']['Running'] is True and sidecar['HostConfig']['NetworkMode'] == 'container:'+relay['Id']
            and type(network.get('IPAMConfig')) is dict
            and network['IPAMConfig'].get('IPv4Address') == network['IPAddress'])
    address=network['IPAddress']
    policy(address)
    return address


def preflight(plan):
    require(os.geteuid() == 0 and socket.gethostname() == 'vps1777112993')
    for path in (CONFIG.parent, INCLUDES, STAGE):
        _trusted_directory(path)
    sshd_pid=_running_sshd()
    source = read_file(CONFIG)
    require(sha(source) == plan['base_config_sha256'])
    includes = sorted(INCLUDES.glob('*.conf'))
    require(all(x.name < NAME for x in includes) and
            {p.name:sha(read_file(p)) for p in includes} == plan['include_sha256'])
    _safe_prior_matches(source, [read_file(p) for p in includes])
    require(not (INCLUDES/NAME).exists() and not (INCLUDES/NAME).is_symlink())
    relay, sidecar = json.loads(run(['/usr/bin/docker','--host','unix:///var/run/docker.sock',
                                     'inspect','hermes-brc-relay','hermes-h454-wss-proxy']))
    address = _relay_address(plan,relay,sidecar)
    raw = read_file(STAGE/NAME, mode=0o600, maximum=8192)
    require(sha(raw) == plan['policy_sha256'] and raw == policy(address))
    ca = read_file(CA, mode=0o444, maximum=8192)
    require(sha(ca) == CA_SHA)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=ca.decode('ascii'))
    with context.wrap_socket(socket.create_connection((address,3001),timeout=5), server_hostname='brc-agent.internal') as s:
        s.settimeout(5)
        s.sendall(b'GET /not-ws HTTP/1.1\r\nHost: brc-agent.internal\r\nConnection: close\r\n\r\n')
        require(s.recv(128).startswith(b'HTTP/1.1 404 '))
    users = _users()
    require(len(users) == plan['existing_accounts_checked'])
    baseline = {name:_settings(CONFIG,name) for name in users}
    lines = source.decode('utf-8').splitlines(keepends=True)
    indexes = [i for i,line in enumerate(lines) if line.strip().lower().startswith('include ')]
    require(len(indexes)==1 and lines[indexes[0]].strip()=='Include /etc/ssh/sshd_config.d/*.conf')
    with tempfile.TemporaryDirectory(prefix='h454-yfc-policy-',dir='/run') as td:
        folder = Path(td)
        staged = folder/NAME
        staged.write_bytes(raw)
        os.chmod(staged,0o600)
        lines.insert(indexes[0]+1,'Include '+str(staged)+'\n')
        candidate = folder/'sshd_config'
        candidate.write_text(''.join(lines))
        os.chmod(candidate,0o600)
        run(['/usr/sbin/sshd','-t','-f',str(candidate)])
        for user in users:
            require(_settings(candidate,user)==baseline[user])
        for client in ('127.0.0.1','192.0.2.1','8.8.8.8'):
            _validate_target(_settings(candidate,ACCOUNT,client),address)
    require(read_file(CONFIG)==source and {p.name:sha(read_file(p)) for p in sorted(INCLUDES.glob('*.conf'))}
            == plan['include_sha256'] and _users()==users)
    require(_running_sshd()==sshd_pid)
    return raw,address,baseline,sshd_pid


def _create(path, data, mode):
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    created=os.fstat(fd)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fsync(fd)
        st=os.fstat(fd)
        return st.st_dev,st.st_ino
    except Exception:
        try:
            current=path.lstat()
            require((current.st_dev,current.st_ino)==(created.st_dev,created.st_ino))
            path.unlink()
            _sync_dir(path.parent)
        except Exception:
            raise Unsettled('YFC_SSH_POLICY_UNSETTLED') from None
        raise
    finally:
        os.close(fd)


def _sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def apply(pin):
    plan=read_plan(pin)
    require(fcntl is not None)
    lock=os.open(STAGE/'apply.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(lock)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600)
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(all(not p.exists() and not p.is_symlink() for p in
                    (STAGE/'pending.json',STAGE/'receipt.json')))
        raw,address,baseline,sshd_pid=preflight(plan)
        marker=json.dumps({'plan_sha256':pin,'policy_sha256':sha(raw)},sort_keys=True,separators=(',',':')).encode('ascii')
        marker_id=_create(STAGE/'pending.json',marker,0o600)
        _sync_dir(STAGE)
        written=None
        reload_attempted=False
        try:
            written=_create(INCLUDES/NAME,raw,0o644)
            _sync_dir(INCLUDES)
            run(['/usr/sbin/sshd','-t','-f',str(CONFIG)])
            require(_users()==list(baseline))
            for user in baseline:
                require(_settings(CONFIG,user)==baseline[user])
            for client in ('127.0.0.1','192.0.2.1','8.8.8.8'):
                _validate_target(_settings(CONFIG,ACCOUNT,client),address)
            require(sha(read_file(CONFIG))==plan['base_config_sha256'])
            require({p.name:sha(read_file(p)) for p in sorted(INCLUDES.glob('*.conf')) if p.name!=NAME}
                    ==plan['include_sha256'])
            reload_attempted=True
            run(['/usr/bin/systemctl','reload','ssh.service'])
            require(run(['/usr/bin/systemctl','is-active','ssh.service']).strip()==b'active')
            require(_running_sshd()==sshd_pid)
            require(read_file(INCLUDES/NAME,mode=0o644)==raw)
            require(sha(read_file(CONFIG))==plan['base_config_sha256'] and _users()==list(baseline))
            require({p.name:sha(read_file(p)) for p in sorted(INCLUDES.glob('*.conf')) if p.name!=NAME}
                    ==plan['include_sha256'])
            for user in baseline:
                require(_settings(CONFIG,user)==baseline[user])
            for client in ('127.0.0.1','192.0.2.1','8.8.8.8'):
                _validate_target(_settings(CONFIG,ACCOUNT,client),address)
            receipt=json.dumps({'plan_sha256':pin,'policy_sha256':sha(raw),'device':written[0],
                                'inode':written[1],'account_created':False,'key_authorized':False},
                               sort_keys=True,separators=(',',':')).encode('ascii')
            _create(STAGE/'receipt.json',receipt,0o600)
            _sync_dir(STAGE)
            current=(STAGE/'pending.json').lstat()
            require((current.st_dev,current.st_ino)==marker_id and read_file(STAGE/'pending.json',mode=0o600)==marker)
            (STAGE/'pending.json').unlink()
            _sync_dir(STAGE)
            return 'YFC_SSH_POLICY_INSTALLED_ACCOUNT_ABSENT'
        except Exception as error:
            if not reload_attempted and not isinstance(error,Unsettled):
                if written is not None:
                    current=(INCLUDES/NAME).lstat()
                    require((current.st_dev,current.st_ino)==written and read_file(INCLUDES/NAME,mode=0o644)==raw)
                    (INCLUDES/NAME).unlink()
                    _sync_dir(INCLUDES)
                current=(STAGE/'pending.json').lstat()
                require((current.st_dev,current.st_ino)==marker_id and read_file(STAGE/'pending.json',mode=0o600)==marker)
                (STAGE/'pending.json').unlink()
                _sync_dir(STAGE)
            raise
    finally:
        os.close(lock)


def rollback(pin):
    """Remove only the receipted policy while the forwarding account is absent."""
    plan=read_plan(pin)
    require(fcntl is not None and os.geteuid()==0 and socket.gethostname()=='vps1777112993')
    for path in (CONFIG.parent,INCLUDES,STAGE):
        _trusted_directory(path)
    lock=os.open(STAGE/'apply.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(lock)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600)
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(all(not p.exists() and not p.is_symlink() for p in
                    (STAGE/'pending.json',STAGE/'rollback.json')))
        raw_receipt=read_file(STAGE/'receipt.json',mode=0o600,maximum=4096)
        receipt=json.loads(raw_receipt)
        require(type(receipt) is dict and set(receipt)=={'plan_sha256','policy_sha256','device','inode',
                'account_created','key_authorized'} and receipt['plan_sha256']==pin and
                receipt['policy_sha256']==plan['policy_sha256'] and
                type(receipt['device']) is int and type(receipt['inode']) is int and
                receipt['account_created'] is False and receipt['key_authorized'] is False and
                json.dumps(receipt,sort_keys=True,separators=(',',':')).encode('ascii')==raw_receipt)
        target=INCLUDES/NAME
        node=target.lstat()
        require((node.st_dev,node.st_ino)==(receipt['device'],receipt['inode']) and
                sha(read_file(target,mode=0o644,maximum=8192))==receipt['policy_sha256'])
        require(sha(read_file(CONFIG))==plan['base_config_sha256'] and
                {p.name:sha(read_file(p)) for p in sorted(INCLUDES.glob('*.conf')) if p.name!=NAME}
                ==plan['include_sha256'])
        users=_users()
        require(ACCOUNT not in users and len(users)==plan['existing_accounts_checked'])
        baseline={user:_settings(CONFIG,user) for user in users}
        sshd_pid=_running_sshd()
        marker=json.dumps({'plan_sha256':pin,'operation':'rollback'},sort_keys=True,separators=(',',':')).encode('ascii')
        marker_id=_create(STAGE/'pending.json',marker,0o600)
        _sync_dir(STAGE)
        current=target.lstat()
        require((current.st_dev,current.st_ino)==(receipt['device'],receipt['inode']) and
                sha(read_file(target,mode=0o644,maximum=8192))==receipt['policy_sha256'] and _users()==users)
        target.unlink()
        _sync_dir(INCLUDES)
        run(['/usr/sbin/sshd','-t','-f',str(CONFIG)])
        require(_users()==users and sha(read_file(CONFIG))==plan['base_config_sha256'] and
                {p.name:sha(read_file(p)) for p in sorted(INCLUDES.glob('*.conf'))}==plan['include_sha256'])
        for user in users:
            require(_settings(CONFIG,user)==baseline[user])
        run(['/usr/bin/systemctl','reload','ssh.service'])
        require(run(['/usr/bin/systemctl','is-active','ssh.service']).strip()==b'active' and _running_sshd()==sshd_pid)
        require(not target.exists() and not target.is_symlink() and _users()==users and
                sha(read_file(CONFIG))==plan['base_config_sha256'] and
                {p.name:sha(read_file(p)) for p in sorted(INCLUDES.glob('*.conf'))}==plan['include_sha256'])
        for user in users:
            require(_settings(CONFIG,user)==baseline[user])
        _create(STAGE/'rollback.json',marker,0o600)
        _sync_dir(STAGE)
        current=(STAGE/'pending.json').lstat()
        require((current.st_dev,current.st_ino)==marker_id and read_file(STAGE/'pending.json',mode=0o600)==marker)
        (STAGE/'pending.json').unlink()
        _sync_dir(STAGE)
        return 'YFC_SSH_POLICY_ROLLED_BACK_RECEIPT_PRESERVED'
    finally:
        os.close(lock)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--plan-sha256',required=True)
    actions=p.add_mutually_exclusive_group()
    actions.add_argument('--apply',action='store_true')
    actions.add_argument('--rollback',action='store_true')
    args=p.parse_args()
    try:
        if args.apply:
            print(apply(args.plan_sha256))
        elif args.rollback:
            print(rollback(args.plan_sha256))
        else:
            preflight(read_plan(args.plan_sha256))
            print('YFC_SSH_POLICY_PLAN_PASS_NO_CHANGES')
        return 0
    except Exception:
        print('YFC_SSH_POLICY_HOLD_INSPECT_BEFORE_RETRY')
        return 2


if __name__=='__main__':
    raise SystemExit(main())
