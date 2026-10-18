#!/bin/sh
# Install as root-owned 0755 /usr/local/libexec/hermes-yfc-metrics-emit,
# only as an authorized_keys forced command for a dedicated unprivileged user.
# The YFC collector must be pinned to a reviewed immutable release.
set -eu
[ "$#" -eq 0 ] || exit 2
unset PYTHONPATH PYTHONSTARTUP
cd /opt/hermes-yfc-metrics/current
exec /usr/bin/python3 -m control_center.infrastructure --host yfc --stdout
