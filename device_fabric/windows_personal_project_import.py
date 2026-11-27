"""Single-flight public-project import broker for a personal Windows worker.

The worker supplies a verified release path. The only child is the fixed
offline import helper; callers cannot select an executable or host path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
from typing import Any, Callable

from scripts.h15_offline_project_import import repository_parts, workspace_name

NAME = 'import_public_project'
MAX_SECONDS = 300
SCHEMA = {
    'name': NAME,
    'description': 'Start or check an import of one public GitHub repository into the Windows sandbox.',
    'inputSchema': {'type': 'object', 'properties': {
        'action': {'type': 'string', 'enum': ['start', 'status']},
        'repository': {'type': 'string', 'maxLength': 140},
        'workspace': {'type': 'string', 'maxLength': 80},
        'job_id': {'type': 'string', 'maxLength': 32},
    }, 'required': ['action'], 'additionalProperties': False},
}


def _terminate_tree(process: Any) -> None:
    if os.name == 'nt':
        root = os.environ.get('SystemRoot', '')
        if not os.path.isabs(root) or type(process.pid) is not int or process.pid <= 0:
            raise ValueError('import_cancel_denied')
        command = [str(Path(root) / 'System32' / 'taskkill.exe'), '/PID', str(process.pid), '/T', '/F']
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=10, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
        if result.returncode != 0 and process.poll() is None:
            process.terminate()
            raise ValueError('import_cancel_failed')
    if process.poll() is None:
        process.terminate()
    process.wait(timeout=10)


class PublicProjectImport:
    def __init__(self, helper: Path, *, launch: Callable[..., Any] = subprocess.Popen,
                 terminate: Callable[[Any], None] = _terminate_tree):
        if (not isinstance(helper, Path) or not helper.is_absolute() or not helper.is_file()
            or helper.name != 'h15_offline_project_import.py' or not callable(launch) or not callable(terminate)):
            raise ValueError('import_broker_invalid')
        self._helper = helper
        self._launch = launch
        self._terminate = terminate
        self._lock = threading.Lock()
        self._process = None
        self._id = None
        self._result = None
        self._workspace = None
        self._timer = None

    def dispatch(self, args: dict) -> dict:
        try:
            if type(args) is not dict or args.get('action') not in ('start', 'status'):
                raise ValueError()
            with self._lock:
                if args['action'] == 'start':
                    if set(args) not in ({'action', 'repository'}, {'action', 'repository', 'workspace'}):
                        raise ValueError()
                    owner, repository = repository_parts(args['repository'])
                    name = workspace_name(repository, args.get('workspace'))
                    if self._process is not None and self._process.poll() is None:
                        return self._reply({'status': 'busy'}, error=True)
                    if self._timer is not None:
                        self._timer.cancel()
                    command = [os.path.abspath(os.sys.executable), '-I', '-B', str(self._helper),
                               owner + '/' + repository, '--workspace', name]
                    self._process = self._launch(command, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                    self._id = secrets.token_hex(16)
                    self._result = None
                    self._workspace = name
                    self._timer = threading.Timer(MAX_SECONDS, self._expire, args=(self._id,))
                    self._timer.daemon = True
                    self._timer.start()
                    return self._reply({'status': 'started', 'job_id': self._id, 'workspace': name})
                if set(args) != {'action', 'job_id'} or args['job_id'] != self._id or self._process is None:
                    raise ValueError()
                if self._result is not None:
                    return self._reply(self._result, error=self._result['status'] == 'failed')
                if self._process.poll() is None:
                    return self._reply({'status': 'running', 'job_id': self._id})
                if self._timer is not None:
                    self._timer.cancel()
                if self._result is None:
                    stdout, _ = self._process.communicate(timeout=1)
                    if self._process.returncode != 0 or type(stdout) is not bytes or len(stdout) > 4096:
                        self._result = {'status': 'failed', 'job_id': self._id}
                    else:
                        try:
                            value = json.loads(stdout)
                            if (type(value) is not dict or value.get('status') != 'INSTALLED'
                                or value.get('name') != self._workspace or type(value.get('head')) is not str
                                or re.fullmatch(r'[a-f0-9]{40}', value['head']) is None
                                or type(value.get('branch')) is not str or not 1 <= len(value['branch']) <= 200
                                or value.get('clean') is not True):
                                raise ValueError()
                            self._result = {'status': 'installed', 'job_id': self._id,
                                            'workspace': value['name'], 'head': value['head'], 'branch': value['branch']}
                        except (ValueError, TypeError):
                            self._result = {'status': 'failed', 'job_id': self._id}
                return self._reply(self._result, error=self._result['status'] == 'failed')
        except Exception:
            return self._reply({'status': 'refused'}, error=True)

    @staticmethod
    def _reply(value: dict, error: bool = False) -> dict:
        return {'content': [{'type': 'text', 'text': json.dumps(value, separators=(',', ':'))}],
                'isError': error}

    def _expire(self, job_id: str) -> None:
        with self._lock:
            if job_id == self._id and self._process is not None and self._process.poll() is None:
                try:
                    self._terminate(self._process)
                finally:
                    self._result = {'status': 'failed', 'job_id': job_id}

    def close(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            if self._process is not None and self._process.poll() is None:
                self._terminate(self._process)
