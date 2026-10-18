#!/usr/bin/env bash
# H-15 #295: owner-authorized opt-in advisory Cloudflare analytics timer.
# Execute ONLY as "bash /.../h15-cloudflare-analytics-setup.sh <action>"
# NEVER source this script inside a login/SSH shell.
set -euo pipefail

action="${1:-status}"
case "$action" in
  status|install|smoke|enable|disable) ;;
  *) echo "UNKNOWN_ACTION"; exit 2 ;;
esac
[[ "$(id -u)" == 0 ]] || { echo "ROOT_CONSOLE_REQUIRED"; exit 2; }

unit="hermes-cloudflare-analytics-advisory"
active="$(readlink -f /opt/hermes-control-center/current)"
if [[ ! "$active" =~ ^/opt/hermes-control-center/releases/main-([0-9a-f]{40})$ ]]; then
  echo "UNTRUSTED_ACTIVE_RELEASE"
  exit 2
fi
sha="${BASH_REMATCH[1]}"
release="/opt/hermes-agent-owner/releases/main-$sha"
if [[ ! -d "$release" || -L "$release" || "$(stat -c %u "$release")" != 0 ]]; then
  echo "UNTRUSTED_OWNER_RELEASE"
  exit 2
fi
source_service="$release/deploy/$unit.service"
source_timer="$release/deploy/$unit.timer"
installed_service="/etc/systemd/system/$unit.service"
installed_timer="/etc/systemd/system/$unit.timer"
gate=(/usr/bin/python3 -m scripts.h15_cloudflare_analytics_gate)

trusted_sources() {
  local file
  for file in "$source_service" "$source_timer"; do
    if [[ ! -f "$file" || -L "$file" || "$(stat -c %u "$file")" != 0 ||
          -n "$(find "$file" -maxdepth 0 -perm /022 -print)" ]]; then
      echo "UNTRUSTED_SOURCE_UNIT"
      return 2
    fi
  done
}

same_installed_units() {
  if [[ ! -f "$installed_service" || -L "$installed_service" ||
        ! -f "$installed_timer" || -L "$installed_timer" ||
        "$(stat -c %u "$installed_service")" != 0 ||
        "$(stat -c %u "$installed_timer")" != 0 ]] ||
        ! cmp -s "$source_service" "$installed_service" ||
        ! cmp -s "$source_timer" "$installed_timer"; then
    echo "UNINSTALLED_OR_DRIFTED_UNIT"
    return 2
  fi
}

run_gate() {
  (cd "$release" && "${gate[@]}" --gate "$1")
}

if [[ "$action" == "status" ]]; then
  run_gate status
  systemctl show "$unit.timer" -p LoadState -p ActiveState -p UnitFileState --no-pager
  systemctl show "$unit.service" -p Result -p ExecMainStatus --no-pager
  exit 0
fi

if [[ "$action" == "disable" ]]; then
  systemctl disable --now "$unit.timer"
  echo "CLOUDFLARE_ADVISORY_TIMER_DISABLED=true"
  exit 0
fi

trusted_sources
run_gate credentials

if [[ "$action" == "install" ]]; then
  systemd-analyze verify "$source_service" "$source_timer"
  # Stop rather than silently overwrite an unrelated pre-existing service.
  for item in "$source_service:$installed_service" "$source_timer:$installed_timer"; do
    source_file="${item%%:*}"
    target_file="${item#*:}"
    if [[ -L "$target_file" ]]; then
      echo "UNSAFE_INSTALLED_UNIT"
      exit 2
    fi
    if [[ -e "$target_file" ]]; then
      if [[ ! -f "$target_file" || "$(stat -c %u "$target_file")" != 0 ]]; then
        echo "UNSAFE_INSTALLED_UNIT"
        exit 2
      fi
      saved="$(mktemp "/root/$unit.backup-XXXXXXXX")"
      cp -a "$target_file" "$saved"
      echo "BACKUP_CREATED=$unit"
    fi
    install -o root -g root -m 0644 "$source_file" "$target_file"
  done
  systemctl daemon-reload
  echo "CLOUDFLARE_ADVISORY_UNITS_INSTALLED=true"
  echo "CLOUDFLARE_ADVISORY_NOT_STARTED=true"
  exit 0
fi

same_installed_units

if [[ "$action" == "smoke" ]]; then
  # One oneshot invocation; may skip HTTP if previous complete UTC day is already collected.
  systemctl start "$unit.service"
  systemctl show "$unit.service" -p Result -p ExecMainStatus --no-pager
  run_gate observed
  echo "CLOUDFLARE_ADVISORY_SMOKE_PASSED=true"
  exit 0
fi

# Enable only after real owner-provisioned credentials + a fresh archive.
run_gate observed
systemctl enable --now "$unit.timer"
systemctl is-active --quiet "$unit.timer"
echo "CLOUDFLARE_ADVISORY_TIMER_ENABLED=true"
