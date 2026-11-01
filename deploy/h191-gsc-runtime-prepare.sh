#!/usr/bin/env bash
# H-24/#191: owner-approved PRE-ACTIVATION only. No credentials, OAuth or timer.
set -euo pipefail
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/bin
umask 077

fail() { printf 'H191_PREPARE=HOLD REASON=%s\n' "$1" >&2; exit 2; }

if [[ "$#" -ne 1 || ( "$1" != "--plan" && "$1" != "--prepare" ) ]]; then
  fail "action_must_be_plan_or_prepare"
fi
if [[ "$1" == "--plan" ]]; then
  echo "H191_PLAN=OWNER_HOST_PREPARATION_ONLY"
  echo "H191_ACTIONS=DEDICATED_IDENTITY,PRIVATE_DIRECTORIES,ISOLATED_VENV,PINNED_WHEELS,DORMANT_DENY_ALL_UNITS,OFFLINE_DRY_RUN"
  echo "H191_EXCLUSIONS=NO_SECRET_CONTENT,NO_GOOGLE_API,NO_SERVICE_START,NO_TIMER_ENABLE,NO_YFC_CHANGES"
  exit 0
fi

[[ "$EUID" -eq 0 ]] || fail "root_required"
[[ "$(hostname -s)" == "vps1777112993" ]] || fail "wrong_host"
state=/var/lib/hermes-main-deploy/last-success.sha
[[ -f "$state" && ! -L "$state" ]] || fail "release_marker_missing"
sha="$(cat "$state")"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail "release_sha_invalid"
app=/opt/hermes-agent-owner
release="$app/releases/main-$sha"
[[ -d "$release" && ! -L "$release" ]] || fail "release_missing"
[[ "$(stat -c %u "$release")" == "0" ]] || fail "release_owner_invalid"
[[ "$(realpath -e -- "$0")" == "$release/deploy/h191-gsc-runtime-prepare.sh" ]] ||
  fail "untrusted_installer_location"
[[ ! -L "$0" ]] || fail "installer_symlink_denied"
grep -Fxq "SHA=$sha" "$release/.deployment-receipt.txt" ||
  fail "release_receipt_mismatch"

for path in \
  marketing/gsc_direct.py marketing/gsc_analytics.py \
  scripts/hermes_gsc_collect.py deploy/requirements-gsc-readonly.txt \
  deploy/hermes-gsc-readonly.service deploy/hermes-gsc-readonly.timer; do
  [[ -f "$release/$path" && ! -L "$release/$path" ]] ||
    fail "release_source_missing"
done
for path in marketing/gsc_direct.py marketing/gsc_analytics.py scripts/hermes_gsc_collect.py; do
  cmp -s "$release/$path" "$app/$path" || fail "active_source_drift"
done

requirements="$release/deploy/requirements-gsc-readonly.txt"
grep -Fxq 'google-auth==2.62.0' "$requirements" || fail "google_auth_pin_invalid"
grep -Fxq 'requests==2.32.5' "$requirements" || fail "requests_pin_invalid"
[[ "$(grep -Ev '^(#|[[:space:]]*$)' "$requirements")" == $'google-auth==2.62.0\nrequests==2.32.5' ]] ||
  fail "requirements_scope_invalid"
/usr/bin/python3 -c 'import sys; assert sys.version_info >= (3, 10)' ||
  fail "unsupported_python"

for unit in hermes-gsc-readonly.service hermes-gsc-readonly.timer; do
  if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit"; then
    fail "gsc_unit_already_active_or_enabled"
  fi
  dest="/etc/systemd/system/$unit"
  if [[ -e "$dest" || -L "$dest" ]]; then
    [[ -f "$dest" && ! -L "$dest" ]] || fail "unit_destination_unsafe"
    cmp -s "$release/deploy/$unit" "$dest" || fail "unit_destination_conflict"
    [[ "$(stat -c '%a:%U:%G' "$dest")" == "644:root:root" ]] ||
      fail "unit_permissions_unsafe"
  fi
done

service="$release/deploy/hermes-gsc-readonly.service"
for line in 'User=hermes-gsc' 'Group=hermes-gsc' \
  'PrivateNetwork=yes' 'IPAddressDeny=any' \
  'RestrictAddressFamilies=AF_UNIX' 'CapabilityBoundingSet=' \
  'AmbientCapabilities=' 'NoNewPrivileges=yes'; do
  grep -Fxq "$line" "$service" || fail "network_or_identity_gate_missing"
done
[[ ! -e /etc/hermes-gsc/service-account.json &&
   ! -L /etc/hermes-gsc/service-account.json ]] ||
  fail "existing_credentials_require_separate_metadata_review"

if ! getent passwd hermes-gsc >/dev/null; then
  getent group hermes-gsc >/dev/null && fail "existing_group_without_user"
  /usr/sbin/useradd --system --user-group --no-create-home \
    --home-dir /var/lib/hermes-gsc --shell /usr/sbin/nologin hermes-gsc ||
    fail "user_creation_failed"
fi
getent passwd hermes-gsc | awk -F: \
  '$1=="hermes-gsc" && $3!=0 && $6=="/var/lib/hermes-gsc" && $7=="/usr/sbin/nologin" {ok=1} END {exit !ok}' ||
  fail "identity_mismatch"
[[ "$(id -nG hermes-gsc)" == "hermes-gsc" ]] || fail "identity_extra_groups"

ensure_directory() {
  local path="$1" owner="$2" group="$3" mode="$4"
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || fail "directory_not_trusted"
    [[ "$(stat -c '%a:%U:%G' "$path")" == "$mode:$owner:$group" ]] ||
      fail "directory_permissions_mismatch"
  else
    install -d -m "0$mode" -o "$owner" -g "$group" "$path" ||
      fail "directory_creation_failed"
  fi
}

ensure_directory /etc/hermes-gsc root hermes-gsc 750
ensure_directory /var/lib/hermes-gsc hermes-gsc hermes-gsc 700
ensure_directory /opt/hermes-gsc root root 755

venv=/opt/hermes-gsc/venv
if [[ -e "$venv" || -L "$venv" ]]; then
  [[ -d "$venv" && ! -L "$venv" &&
     "$(stat -c '%a:%U:%G' "$venv")" == "755:root:root" ]] ||
    fail "venv_path_unsafe"
else
  (umask 022; /usr/bin/python3 -m venv "$venv") ||
    fail "python_venv_unavailable"
fi
[[ -x "$venv/bin/python" && -f "$venv/pyvenv.cfg" ]] ||
  fail "venv_invalid"

marker=/opt/hermes-gsc/.deps-ready
[[ ! -L "$marker" ]] || fail "dependency_marker_symlink"
[[ ! -e "$marker" || -f "$marker" ]] || fail "dependency_marker_unsafe"
if [[ ! -f "$marker" ]]; then
  "$venv/bin/python" -m pip --isolated --disable-pip-version-check install \
    --no-input --no-cache-dir --only-binary=:all: \
    --index-url https://pypi.org/simple --timeout 8 --retries 0 \
    -r "$requirements" >/dev/null 2>&1 ||
    fail "pinned_wheel_install_failed"
fi
"$venv/bin/python" -m pip --isolated --disable-pip-version-check check \
  >/dev/null 2>&1 || fail "dependency_conflict"
"$venv/bin/python" -c \
  'from importlib.metadata import version; assert version("google-auth")=="2.62.0"; assert version("requests")=="2.32.5"' ||
  fail "dependency_version_mismatch"
if [[ ! -f "$marker" ]]; then
  printf 'GOOGLE_AUTH=2.62.0\nREQUESTS=2.32.5\n' > "$marker"
  chmod 0400 "$marker"
else
  [[ "$(stat -c '%a:%U:%G' "$marker")" == "400:root:root" ]] ||
    fail "dependency_marker_permissions"
fi

# This is the offline-only CLI path. Never pass credentials or output paths.
cd "$app"
dry_run="$(runuser -u hermes-gsc -- env -i PATH=/usr/bin:/bin \
  HOME=/var/lib/hermes-gsc PYTHONDONTWRITEBYTECODE=1 \
  "$venv/bin/python" -B -m scripts.hermes_gsc_collect --dry-run)" ||
  fail "unprivileged_dry_run_failed"
printf '%s\n' "$dry_run" | "$venv/bin/python" -c \
  'import json,sys; o=json.load(sys.stdin); assert o["status"]=="DRY_RUN_NO_NETWORK"; assert o["credentials_accessed"] is False; assert o["publication_allowed"] is False; assert o["requests_per_run"]==7; assert o["property"]=="sc-domain:your-fitness-coach.ru"; assert o["scope"]=="webmasters.readonly"' ||
  fail "offline_contract_invalid"

systemd-analyze verify "$service" "$release/deploy/hermes-gsc-readonly.timer" \
  >/dev/null 2>&1 || fail "systemd_template_invalid"
for unit in hermes-gsc-readonly.service hermes-gsc-readonly.timer; do
  dest="/etc/systemd/system/$unit"
  if [[ ! -e "$dest" ]]; then
    install -o root -g root -m 0644 "$release/deploy/$unit" "$dest" ||
      fail "dormant_unit_stage_failed"
  fi
done
systemctl daemon-reload || fail "systemd_reload_failed"
for unit in hermes-gsc-readonly.service hermes-gsc-readonly.timer; do
  [[ "$(systemctl show "$unit" --property=LoadState --value)" == "loaded" ]] ||
    fail "unit_not_loaded"
  if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit"; then
    fail "unit_unexpectedly_activated"
  fi
done
[[ "$(cat "$state")" == "$sha" ]] || fail "release_changed_during_prepare"
echo "H191_INSTALLED_SHA=$sha"
echo "H191_OS_IDENTITY=PASS"
echo "H191_DIRECTORIES=PASS"
echo "H191_VENV_PINNED_DIRECT_DEPS=PASS"
echo "H191_OFFLINE_DRY_RUN=PASS"
echo "H191_DORMANT_SYSTEMD_UNITS=PASS"
echo "H191_NETWORK_POLICY=PREACTIVATION_DENY_ALL_NOT_LIVE_TESTED"
echo "H191_GOOGLE_OAUTH=NOT_RUN"
echo "H191_TIMER=NOT_ENABLED"
echo "H191_PREPARE=PASS"
