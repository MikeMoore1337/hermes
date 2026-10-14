#!/usr/bin/env bash
# Prepare private host storage for a separate non-login Hermes identity.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root on the approved Hermes host" >&2
  exit 1
fi
if ! getent passwd hermes-agent >/dev/null; then
  useradd --system --no-create-home --home-dir /var/lib/hermes-agent --shell /usr/sbin/nologin --user-group hermes-agent
fi
if [ -L /var/lib/hermes-agent ]; then
  echo "Symlinked agent home is forbidden" >&2
  exit 1
fi
install -d -m 0700 -o hermes-agent -g hermes-agent /var/lib/hermes-agent
test "$(stat -c %U:%G /var/lib/hermes-agent)" = "hermes-agent:hermes-agent"
test "$(stat -c %a /var/lib/hermes-agent)" = 700
echo "Prepared independent agent home without starting any services"
