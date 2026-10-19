#!/usr/bin/env python3
"""H-15 #371: source-pinned, fail-closed BRC DeviceHub reconnect hardening.

Prevent an old/different WebSocket from completing a newly routed call, keep
old sockets from affecting live heartbeat, and immediately fail pending
calls when the owning connection is replaced or closed.

No network access, no owner machine modifications and no service deployment.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import (
    AuditError, UPSTREAM_SHA, evaluate,
)

HUB = Path("packages/relay/src/device-hub.ts")

REPLACEMENTS = (
    (
        """interface Pending {
  resolve: (r: ToolResult) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}""",
        """interface Pending {
  resolve: (r: ToolResult) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
  deviceId: string;
  socket: WebSocket;
}""",
    ),
    (
        """      if (msg.type === 'hello') {
        if (msg.protocol !== BRC_PROTOCOL_VERSION) {""",
        """      if (msg.type === 'hello') {
        if (deviceId !== null) {
          return socket.close(1002, 'duplicate hello');
        }
        if (msg.protocol !== BRC_PROTOCOL_VERSION) {""",
    ),
    (
        """        if (prev && prev.socket !== socket) {
          this.log('info', `device ${deviceId} reconnected; closing stale socket`);
          prev.socket.terminate();
        }""",
        """        if (prev && prev.socket !== socket) {
          this.log('info', `device ${deviceId} reconnected; closing stale socket`);
          this.rejectPending(deviceId, prev.socket, 'DEVICE_REPLACED');
          prev.socket.terminate();
        }""",
    ),
    (
        """      const dev = this.devices.get(deviceId);
      if (dev) dev.lastSeen = Date.now();

      if (msg.type === 'pong') return;
      if (msg.type === 'result') {
        const p = this.pending.get(msg.id);
        if (!p) return;""",
        """      const dev = this.devices.get(deviceId);
      // No superseded/foreign socket can update activity or complete a
      // pending command, even when it knows a previously issued call ID.
      if (!dev || dev.socket !== socket) return;
      dev.lastSeen = Date.now();

      if (msg.type === 'pong') return;
      if (msg.type === 'result') {
        const p = this.pending.get(msg.id);
        if (!p || p.socket !== socket || p.deviceId !== deviceId) return;""",
    ),
    (
        """      if (deviceId && this.devices.get(deviceId)?.socket === socket) {
        this.devices.delete(deviceId);
        this.log('info', `device offline: ${deviceId}`);
      }""",
        """      if (deviceId && this.devices.get(deviceId)?.socket === socket) {
        this.rejectPending(deviceId, socket, 'DEVICE_DISCONNECTED');
        this.devices.delete(deviceId);
        this.log('info', `device offline: ${deviceId}`);
      }""",
    ),
    (
        """      this.pending.set(id, { resolve, reject, timer });""",
        """      this.pending.set(id, { resolve, reject, timer, deviceId, socket: dev.socket });""",
    ),
    (
        """  private tick(): void {
    const now = Date.now();""",
        """  private rejectPending(deviceId: string, socket: WebSocket, reason: string): void {
    for (const [id, p] of this.pending) {
      if (p.deviceId !== deviceId || p.socket !== socket) continue;
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.reject(new Error(reason));
    }
  }

  private tick(): void {
    const now = Date.now();""",
    ),
    (
        """        dev.socket.terminate();
        this.devices.delete(id);
        continue;""",
        """        this.rejectPending(id, dev.socket, 'DEVICE_HEARTBEAT_EXPIRED');
        dev.socket.terminate();
        this.devices.delete(id);
        continue;""",
    ),
)


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    target = root / HUB
    if (root.is_symlink() or target.is_symlink() or not target.is_file()):
        raise AuditError("unsafe_hub_source")
    if target.stat().st_size > 150_000:
        raise AuditError("oversize_hub_source")
    original = target.read_text(encoding="utf-8")
    updated = original
    for old, new in REPLACEMENTS:
        if updated.count(old) != 1 or new in updated:
            raise AuditError("unreviewed_hub_source_change")
        updated = updated.replace(old, new)
    if updated == original:
        raise AuditError("no_change")
    # Fail closed and only write after all source contracts were verified.
    target.write_text(updated, encoding="utf-8")
    return {
        "status": "RECONNECT_CALL_BINDING_PATCHED",
        "source_sha": sha,
        "pending_calls": "BOUND_TO_DEVICE_AND_SOCKET",
        "old_socket_results": "IGNORED",
        "pending_on_reconnect": "REJECTED",
        "pending_on_disconnect": "REJECTED",
        "production_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        result = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, ValueError) as exc:
        reason = str(exc) if type(exc) is AuditError else type(exc).__name__
        print(json.dumps({"status": "REJECTED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
