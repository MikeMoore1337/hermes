#!/usr/bin/env bash
# #295 owner-only opt-in collection. Always run as:
#   bash /opt/hermes-agent-owner/releases/main-$SHA/deploy/h15-provider-source-setup.sh status github
# NEVER: source this file from an interactive SSH login shell.
set -euo pipefail

action="${1:-status}"
provider="${2:-github}"
case "$action" in status|install|smoke|enable|disable) ;; *) echo 'UNKNOWN_ACTION'; exit 2;; esac
case "$provider" in
  github) unit="hermes-github-rate-limit";;
  cloudflare) unit="hermes-cloudflare-billing-read";;
  *) echo 'UNKNOWN_PROVIDER'; exit 2;;
esac
if [[ "$(id -u)" != "0" ]]; then
  echo "ROOT_CONSOLE_REQUIRED"
  exit 2
fi
active="$(readlink -f /opt/hermes-control-center/current)"
if [[ ! "$active" =~ ^/opt/hermes-control-center/releases/main-([0-9a-f]{40})$ ]]; then
  echo "UNTRUSTED_ACTIVE_RELEASE"
  exit 2
fi
sha="${BASH_REMATCH[1]}"
release="/opt/hermes-agent-owner/releases/main-$sha"
if [[ ! -d "$release" || -L "$release" || "$(stat -c %u "$release")" != "0" ]]; then
  echo "UNTRUSTED_OWNER_RELEASE"
  exit 2
fi
gate=(/usr/bin/python3 -m scripts.h15_provider_collector_gate --provider "$provider")
source_service="$release/deploy/$unit.service"
source_timer="$release/deploy/$unit.timer"
service="/etc/systemd/system/$unit.service"
timer="/etc/systemd/system/$unit.timer"

trusted_source() {
  local f
  for f in "$source_service" "$source_timer"; do
    if [[ ! -f "$f" || -L "$f" ||
          "$(stat -c %u "$f")" != "0" ||
          -n "$(find "$f" -maxdepth 0 -perm /022 -print)" ]]; then
      echo "UNTRUSTED_SOURCE_UNIT"
      return 2
    fi
  done
}
same_installed_units() {
  if [[ ! -f "$service" || -L "$service" ||
        ! -f "$timer" || -L "$timer" ]] ||
        ! cmp -s "$source_service" "$service" ||
        ! cmp -s "$source_timer" "$timer"; then
    echo "UNINSTALLED_OR_DRIFTED_UNIT"
    return 2
  fi
}

if [[ "$action" == "status" ]]; then
  (cd "$release" && "${gate[@]}")
  systemctl show "$unit.timer" \
    -p LoadState -p ActiveState -p UnitFileState --no-pager
  exit 0
fi

if [[ "$action" == "disable" ]]; then
  # Disabling collection must remain possible even after token revocation.
  systemctl disable --now "$unit.timer"
  echo "COLLECTOR_TIMER_DISABLED=$provider"
  exit 0
fi

trusted_source
(cd "$release" && "${gate[@]}" --gate credentials)

if [[ "$action" == "install" ]]; then
  systemd-analyze verify "$source_service" "$source_timer"
  for spec in "$source_service:$service" "$source_timer:$timer"; do
    src="${spec%%:*}"
    dst="${spec#*:}"
    if [[ -L "$dst" ]]; then
      echo "UNSAFE_INSTALLED_UNIT"
      exit 2
    fi
    if [[ -e "$dst" ]]; then
      backup="$(mktemp "/root/$unit.backup-XXXXXXXX")"
      cp -a "$dst" "$backup"
      echo "BACKUP_CREATED=$unit"
    fi
    install -o root -g root -m 0644 "$src" "$dst"
  done
  systemctl daemon-reload
  echo "COLLECTOR_UNITS_INSTALLED=$provider"
  echo "COLLECTOR_NOT_STARTED=true"
  exit 0
fi

same_installed_units

if [[ "$action" == "smoke" ]]; then
  # Explicitly authorized single GET (no inference, no paid API call).
  systemctl start "$unit.service"
  systemctl show "$unit.service" \
    -p Result -p ExecMainStatus --no-pager
  (cd "$release" && "${gate[@]}" --gate observed)
  echo "OFFICIAL_SOURCE_SMOKE_PASSED=$provider"
  exit 0
fi

# enable: only after a separate approved one-shot real source observation.
(cd "$release" && "${gate[@]}" --gate observed)
systemctl enable --now "$unit.timer"
systemctl is-active --quiet "$unit.timer"
echo "COLLECTOR_TIMER_ENABLED=$provider"
