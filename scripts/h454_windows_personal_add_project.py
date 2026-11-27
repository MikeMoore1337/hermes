"""Add one owner-selected original Windows project without changing the task action.

Run locally in the interactive owner's account; no remote request supplies a
credential, executable, task identity or state location. The CLI retains a
protected config backup and reports only that task/grant checks passed, not
that a remote end-to-end invocation has succeeded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from device_fabric import native_private_tls as tls
from device_fabric import windows_personal_commander_bundle as bundle
from device_fabric import windows_personal_commander_config as config
from device_fabric import windows_personal_commander_status as status
from device_fabric import windows_personal_project_registration as transaction
from device_fabric.windows_personal_yfc_psec import APP_NAME, GIT_ROOT, YfcDevPsecTerminal, _real_directory
from scripts.h454_windows_personal_state import _create_private_directory
from scripts.h454_windows_personal_worker import current_sid, load_ca
from scripts.h454_windows_personal_yfc_action import build_action
from scripts.h454_windows_personal_yfc_bootstrap import _read
from scripts.h454_windows_personal_yfc_entry import _read_private


def main() -> int:
    parser = argparse.ArgumentParser()
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--project')
    operation.add_argument('--rollback', help='backup name from a completed registration')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    lock = None
    try:
        if os.name != 'nt' or not os.path.isabs(os.environ.get('LOCALAPPDATA', '')):
            raise ValueError()
        root = Path(os.environ['LOCALAPPDATA']) / APP_NAME
        private, release = root / 'worker-private', root / 'release'
        for directory in (root, private, release):
            _real_directory(directory)
        raw = _read_private(private, 'device.json', config.MAX_CONFIG_BYTES)
        current = config.parse_config(raw)
        owner = current_sid()
        ca = load_ca(current.ca_sha256)
        manifest = _read_private(private, 'release-manifest.json', bundle.MAX_MANIFEST)
        bundle.verify(release, manifest, current.bundle_sha256)
        if args.rollback:
            if not re.fullmatch(r'project-registration-[a-f0-9]{32}', args.rollback):
                raise ValueError()
            previous = private / args.rollback
            _real_directory(previous)
            old = _read(previous / 'old-device.json', config.MAX_CONFIG_BYTES)
            new = _read(previous / 'new-device.json', config.MAX_CONFIG_BYTES)
            if raw != new:
                raise ValueError()
            previous_config = config.parse_config(old)
            if (previous_config.device_id, previous_config.owner_sid, previous_config.release_sha,
                previous_config.ca_sha256, previous_config.bundle_sha256) != (
                current.device_id, current.owner_sid, current.release_sha,
                current.ca_sha256, current.bundle_sha256):
                raise ValueError()
            updated = old
        else:
            updated = config.add_project(raw, args.project, owner_sid=owner, ca=ca,
                                         bundle_sha256=current.bundle_sha256)
            if updated == raw:
                print(json.dumps({'status': 'ALREADY_CONFIGURED', 'changed': False,
                                  'remote_access': 'NOT_VERIFIED'}))
                return 0
        next_config = config.parse_config(updated)
        config.unseal(next_config, owner_sid=owner, ca=ca, bundle_sha256=current.bundle_sha256)
        roots = config.roots_for(next_config.profile, roots=next_config.roots)
        # The existing owner grant must be current before stopping anything.
        bearer = config.unseal(current, owner_sid=owner, ca=ca, bundle_sha256=current.bundle_sha256)
        relay = tls.PrivateRelay('windows', current.release_sha, tls.WINDOWS_LOOPBACK, ca)
        if status.bearer_state(relay, device_id=current.device_id, bearer=bearer) is not True:
            raise ValueError()
        verifier = release / 'code' / 'device_fabric' / 'windows_personal_commander_bundle.py'
        bootstrap = root / 'bootstrap' / 'h454_windows_personal_yfc_bootstrap.py'
        pythonw = Path(sys.executable).with_name('pythonw.exe')
        digest = lambda path, limit: hashlib.sha256(_read(path, limit)).hexdigest()
        boot_sha = digest(bootstrap, 128 * 1024)
        action = build_action(pythonw, pythonw_sha256=digest(pythonw, 16 * 1024 * 1024),
            bootstrap_sha256=boot_sha, manifest_sha256=current.bundle_sha256,
            verifier_sha256=digest(verifier, 128 * 1024))
        control_script = Path(__file__).with_name('h454_windows_personal_registration_task.ps1')
        if control_script.is_symlink() or not control_script.is_file():
            raise ValueError()
        def control(mode: str) -> None:
            command = ['pwsh', '-NoProfile', '-NonInteractive', '-File', str(control_script),
                '-Mode', mode, '-ExpectedExecutable:' + action.executable,
                '-ExpectedArguments:' + action.windows_arguments, '-ExpectedSid:' + owner,
                '-BootstrapDigest:' + boot_sha]
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode != 0 or ('TASK_CONTROL_' + mode + '=PASS').encode() not in result.stdout:
                raise ValueError()
        control('Check')
        # Exercise the actual PSEC boundary and project metadata scan before stop.
        options = {'project_roots': roots} if next_config.profile == 'owner-projects' else {}
        process = YfcDevPsecTerminal(roots[0], command='exit /b 0',
            writable=(str(root / 'adapter-state'), *roots[1:]), readonly=(str(release), str(GIT_ROOT)), **options)
        try:
            deadline = time.monotonic() + 10
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(.05)
            if process.poll() != 0:
                raise ValueError()
        finally:
            process.close()
        if not args.execute:
            print(json.dumps({'status': 'REGISTRATION_PLAN_PASS', 'changed': False,
                              'operation': 'rollback' if args.rollback else 'add'}))
            return 0
        lock = private / 'project-registration.lock'
        _create_private_directory(lock, owner)
        lock_info = lock.lstat()
        if _read_private(private, 'device.json', config.MAX_CONFIG_BYTES) != raw:
            raise ValueError()
        backup = private / ('project-registration-' + uuid.uuid4().hex)
        _create_private_directory(backup, owner)
        def verify() -> bool:
            try:
                # A scheduler "Running" state immediately after Start is not
                # evidence that the worker survived its initial project scans.
                # This is still not an end-to-end device invocation.
                for _ in range(10):
                    control('Check')
                    time.sleep(3)
                control('Check')
                return status.bearer_state(relay, device_id=current.device_id, bearer=bearer) is True
            except Exception:
                return False
        transaction.apply(private / 'device.json', backup, raw, updated,
                          stop=lambda: control('Stop'), start=lambda: control('Start'), verify=verify)
        print(json.dumps({'status': 'REGISTRATION_TASK_STARTED',
                          'remote_access': 'NOT_VERIFIED', 'backup': backup.name}))
        return 0
    except transaction.RegistrationRollbackFailed:
        print(json.dumps({'status': 'REGISTRATION_HOLD', 'rollback': 'FAILED'}), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps({'status': 'REGISTRATION_HOLD', 'rollback': 'IF_CHANGED'}), file=sys.stderr)
        return 2
    finally:
        if lock is not None:
            try:
                actual = lock.lstat()
                if (actual.st_dev, actual.st_ino) == (lock_info.st_dev, lock_info.st_ino):
                    lock.rmdir()
            except Exception:
                pass


if __name__ == '__main__':
    raise SystemExit(main())
