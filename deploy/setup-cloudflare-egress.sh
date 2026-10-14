#!/usr/bin/env bash
# Create only the independent agent internal network and interface-scoped nft rules.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo 'root required' >&2; exit 1; fi
if docker network inspect hermes-agent-isolated >/dev/null 2>&1; then
  echo 'Existing dedicated network: verify manually; refusing overwrite' >&2
  exit 2
fi
if nft list table inet hermes_agent_isolation >/dev/null 2>&1; then
  echo 'Existing dedicated firewall: verify manually; refusing overwrite' >&2
  exit 2
fi
if ip route show 172.29.250.0/28 | grep -q .; then
  echo 'Subnet collision' >&2
  exit 2
fi
if ss -Hlnt sport = :18573 | grep -q .; then
  echo 'Proxy port occupied' >&2
  exit 2
fi
docker network create --driver bridge --internal \
  --subnet 172.29.250.0/28 --gateway 172.29.250.1 \
  --opt com.docker.network.bridge.name=br-hcf-agent \
  hermes-agent-isolated >/dev/null
if ! nft -f - <<'EOF'
add table inet hermes_agent_isolation
add chain inet hermes_agent_isolation input { type filter hook input priority -110; policy accept; }
add rule inet hermes_agent_isolation input iifname "br-hcf-agent" ip saddr 172.29.250.2 ip daddr 172.29.250.1 tcp dport 18573 accept
add rule inet hermes_agent_isolation input iifname "br-hcf-agent" drop
add chain inet hermes_agent_isolation forward { type filter hook forward priority -110; policy accept; }
add rule inet hermes_agent_isolation forward iifname "br-hcf-agent" drop
EOF
then
  nft delete table inet hermes_agent_isolation 2>/dev/null || true
  docker network rm hermes-agent-isolated >/dev/null 2>&1 || true
  echo 'Isolation firewall setup failed closed and rolled back' >&2
  exit 3
fi
echo 'ISOLATED_NETWORK_AND_DENY_FIREWALL_READY'
