#!/usr/bin/env bash
# Reviewed replacement for /usr/local/sbin/docker-gc.sh.
# Install only in an expressly owner-approved production maintenance window.
set -euo pipefail
cd /opt/hermes-agent-owner
exec /usr/bin/python3 -B -m scripts.h01_docker_gc_safe --apply
