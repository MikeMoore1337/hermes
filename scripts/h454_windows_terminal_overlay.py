"""Prepare an offline, pinned terminal overlay for the owner Windows sandbox.

This source-only tool does not install an image, update a task, or start a
container. Inputs are copies of the two current agent JS files and the
terminal-manager JS from the verified CI relay image. No credentials are read.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import sys

PROCESS_SHA256 = '7e35b46818937d323e69685e3a018d426061c8dc1d18af8900e46961b2e1ed50'
MANAGER_SHA256 = '20ef592e52de7b6f7d96c5286a4d49387467fdf9f12dace78d1e2a0474bb4e84'
REFERENCE_SHA256 = '1954fe65576521a957ff9abb43e209a7e38b31dd14b3da606594402a50a10e2d'


class OverlayDenied(ValueError):
    pass


def once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise OverlayDenied('source_drift')
    return text.replace(before, after, 1)


def section(text: str, begin: str, end: str) -> str:
    if text.count(begin) != 1:
        raise OverlayDenied('source_drift')
    start = text.index(begin)
    finish = text.find(end, start)
    if finish < 0:
        raise OverlayDenied('source_drift')
    return text[start:finish]


def build(process: bytes, manager: bytes, reference: bytes) -> tuple[bytes, bytes]:
    if any(type(data) is not bytes for data in (process, manager, reference)):
        raise OverlayDenied('invalid_source')
    if tuple(sha256(data).hexdigest() for data in (process, manager, reference)) != (
            PROCESS_SHA256, MANAGER_SHA256, REFERENCE_SHA256):
        raise OverlayDenied('source_hash_mismatch')
    try:
        tools, old, ref = (data.decode('utf-8') for data in (process, manager, reference))
        tools = once(tools,
            'processStateMessage = `\\n✅ Process completed with exit code ${result.exitCode}${runtimeStr}`;',
            'processStateMessage = result.exitCode === 0\n'
            '            ? `\\n✅ Process completed with exit code 0${runtimeStr}`\n'
            '            : `\\n❌ Process failed or was terminated (exit code ${result.exitCode})${runtimeStr}`;')
        if tools.count('isError: result.isComplete && result.exitCode !== 0') != 1:
            raise OverlayDenied('source_drift')
        old = once(old, "import { spawn } from 'child_process';\n",
                   "import { spawn } from 'child_process';\nimport { existsSync } from 'node:fs';\n")
        constants = section(ref, 'const h454LinuxSessions = new WeakMap();',
                            'export const MAX_HERMES_TIMING_EVENTS')
        marker = 'export const MAX_HERMES_TIMING_EVENTS = 128;'
        old = once(old, marker, constants + marker)
        spawn = section(ref, '        let h454Mode = null;', "        let output = '';")
        old = once(old,
                   '        const childProcess = spawn(spawnConfig.executable, spawnConfig.args, spawnOptions);\n',
                   spawn)
        force_source = section(ref, '    forceTerminate(pid) {', '    listActiveSessions() {')
        linux_force = section(force_source, "            if (process.platform === 'linux') {",
                              "            if (!session.process.kill('SIGINT')) {")
        marker = "        try {\n            if (!session.process.kill('SIGINT')) {"
        old = once(old, marker, "        try {\n" + linux_force + "            if (!session.process.kill('SIGINT')) {")
        if ("childProcess.on('close', (code) => {" not in old
                or 'if (!resolved)\n                waitTimer = setTimeout' not in old):
            raise OverlayDenied('existing_fixes_missing')
        return tools.encode('utf-8'), old.encode('utf-8')
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, OverlayDenied):
            raise
        raise OverlayDenied('source_drift') from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--process', type=Path, required=True)
    parser.add_argument('--manager', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        sources = (args.process, args.manager, args.reference)
        if any(path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024 for path in sources):
            raise OverlayDenied('invalid_source')
        tools, manager = build(*(path.read_bytes() for path in sources))
        args.output_dir.mkdir(mode=0o700)
        for name, data in (('improved-process-tools.js', tools), ('terminal-manager.js', manager)):
            with (args.output_dir / name).open('xb') as output:
                output.write(data)
        print('TERMINAL_OVERLAY_PREPARED tools_sha256=' + sha256(tools).hexdigest()
              + ' manager_sha256=' + sha256(manager).hexdigest())
        return 0
    except (OSError, OverlayDenied):
        print('TERMINAL_OVERLAY=HOLD', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
