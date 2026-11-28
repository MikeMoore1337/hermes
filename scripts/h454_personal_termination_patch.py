"""Attach the existing Linux process-tree supervisor to the pinned bundle."""
from __future__ import annotations

import hashlib

SOURCE_SHA256 = '20ef592e52de7b6f7d96c5286a4d49387467fdf9f12dace78d1e2a0474bb4e84'
SPAWN = b'        const childProcess = spawn(spawnConfig.executable, spawnConfig.args, spawnOptions);'
SUPERVISED_SPAWN = b'''        // Every personal Linux terminal gets a private subreaper. Never pass
        // the wrapper through Node's shell option: it owns the actual shell.
        let executable = spawnConfig.executable;
        let args = spawnConfig.args;
        if (spawnOptions.shell) {
            args = ['-c', [executable, ...args].join(' ')];
            executable = typeof spawnOptions.shell === 'string' ? spawnOptions.shell : '/bin/sh';
        }
        delete spawnOptions.shell;
        const childProcess = spawn('/usr/bin/python3',
            ['-I', '-B', '/opt/commander/scripts/h454_terminal_supervisor.py', String(process.pid), executable, ...args],
            spawnOptions);'''
TERMINATE = b'''            if (!session.process.kill('SIGINT')) {
                return false;
            }
            setTimeout(() => {
                if (this.sessions.get(pid) === session &&
                    session.process.exitCode == null && session.process.signalCode == null) {
                    try {
                        if (!session.process.kill('SIGKILL'))
                            console.error('HERMES_TERMINATION_ESCALATION_FAILED');
                    }
                    catch {
                        console.error('HERMES_TERMINATION_ESCALATION_FAILED');
                    }
                }
            }, 1000);'''
SUPERVISED_TERMINATE = b'''            if (!session.process.kill('SIGTERM')) {
                return false;
            }
            // A SIGKILL here would orphan the descendants that the subreaper
            // must terminate. Resume and signal it again if still active.
            setTimeout(() => {
                if (this.sessions.get(pid) === session &&
                    session.process.exitCode == null && session.process.signalCode == null) {
                    try {
                        if (!session.process.kill('SIGCONT') || !session.process.kill('SIGTERM'))
                            console.error('HERMES_TERMINATION_ESCALATION_FAILED');
                    }
                    catch {
                        console.error('HERMES_TERMINATION_ESCALATION_FAILED');
                    }
                }
            }, 1000);'''


def patch(source: bytes) -> bytes:
    """Fail closed if the reviewed upstream bundle has changed."""
    if (type(source) is not bytes or hashlib.sha256(source).hexdigest() != SOURCE_SHA256
            or source.count(SPAWN) != 1 or source.count(TERMINATE) != 1):
        raise ValueError('personal_termination_patch_denied')
    return source.replace(SPAWN, SUPERVISED_SPAWN, 1).replace(TERMINATE, SUPERVISED_TERMINATE, 1)
