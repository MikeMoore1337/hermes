#!/usr/bin/env bash
# Manual, owner-gated YFC VPS bootstrap for #294: NO SSHD/firewall edits,
# network probing, service restarts, or resident processes.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/bin
umask 077

die() { printf 'YFC_EMITTER_INSTALL=refused reason=%s\n' "$1" >&2; exit 1; }
if [[ $# -ne 3 ]]; then
  echo 'Usage: sudo bash deploy/install-yfc-infrastructure-emitter.sh CHECKOUT_DIR EXPECTED_40_HEX_SHA PUBLIC_KEY_FILE' >&2
  exit 2
fi
[[ "$EUID" == 0 ]] || die root_required
checkout=$(realpath -e -- "$1") || die invalid_checkout
sha=$2
[[ "$sha" =~ ^[a-f0-9]{40}$ ]] || die invalid_revision
pub=$(realpath -e -- "$3") || die missing_public_key
[[ -f "$pub" && ! -L "$3" && "$(wc -c < "$pub")" -le 300 ]] || die bad_public_key
public_key=$(cat "$pub")
public_key_pattern='^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9_.@:-]+)?$'
[[ "$public_key" =~ $public_key_pattern ]] || die unsupported_key
/usr/bin/ssh-keygen -lf "$pub" >/dev/null 2>&1 || die malformed_public_key

for name in control_center/infrastructure.py control_center/yfc_polling.py control_center/__init__.py deploy/hermes-yfc-metrics-emit.sh; do
  [[ -f "$checkout/$name" && ! -L "$checkout/$name" ]] || die missing_or_symlink_source
done
[[ "$(git -C "$checkout" rev-parse --verify HEAD)" == "$sha" ]] || die revision_mismatch
[[ -z "$(git -C "$checkout" status --porcelain --untracked-files=no)" ]] ||
  die dirty_checkout

user=hermes-infra-read
home=/var/lib/hermes-infra-read
release="/opt/hermes-yfc-metrics/releases/main-$sha"
[[ ! -e "$release" && ! -L "$release" ]] || die release_already_exists
[[ ! -L /opt/hermes-yfc-metrics && ! -L /opt/hermes-yfc-metrics/releases ]] ||
  die release_symlink
if id "$user" >/dev/null 2>&1; then
  [[ "$(getent passwd "$user" | cut -d: -f6)" == "$home" &&
     "$(getent passwd "$user" | cut -d: -f7)" == /bin/sh ]] ||
    die incompatible_existing_user
else
  /usr/sbin/useradd --system --create-home --home-dir "$home" \
    --shell /bin/sh --user-group "$user" || die useradd_failed
fi
[[ "$(id -u "$user")" != 0 ]] || die invalid_user_id
[[ ! -L "$home" && ! -L "$home/.ssh" && ! -L "$home/.ssh/authorized_keys" ]] ||
  die ssh_home_symlink

forced="restrict,command=\"/usr/local/libexec/hermes-yfc-metrics-emit\" $public_key"
if [[ -e "$home/.ssh/authorized_keys" ]]; then
  [[ "$(cat "$home/.ssh/authorized_keys")" == "$forced" ]] ||
    die existing_authorized_keys_conflict
fi

install -d -o root -g root -m 0755 /opt/hermes-yfc-metrics /opt/hermes-yfc-metrics/releases
install -d -o root -g root -m 0755 "$release" "$release/control_center"
install -o root -g root -m 0644 \
  "$checkout/control_center/__init__.py" "$release/control_center/__init__.py"
install -o root -g root -m 0644 \
  "$checkout/control_center/infrastructure.py" "$release/control_center/infrastructure.py"
install -o root -g root -m 0644 \
  "$checkout/control_center/yfc_polling.py" "$release/control_center/yfc_polling.py"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$checkout/deploy/hermes-yfc-metrics-emit.sh" \
  /usr/local/libexec/hermes-yfc-metrics-emit

# No network: validate the immutable release as a dedicated non-root user.
(
  cd "$release"
  env -u PYTHONPATH -u PYTHONSTARTUP /usr/sbin/runuser -u "$user" -- \
    /usr/bin/python3 -m control_center.infrastructure --host yfc --stdout |
    /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert data["schema"] == 1 and data["host"] == "yfc"
assert data["source"] == "linux_procfs_local"
assert 0 <= data["metrics"]["ram_used_percent"] <= 100
assert 0 <= data["metrics"]["disk_used_percent"] <= 100
'
) || die unprivileged_collector_smoke_failed

install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
if [[ ! -e "$home/.ssh/authorized_keys" ]]; then
  printf '%s\n' "$forced" | install -o "$user" -g "$user" -m 0600 \
    /dev/stdin "$home/.ssh/authorized_keys"
fi

# Only switch the symlink after unprivileged smoke succeeds.
tmp="/opt/hermes-yfc-metrics/.current-$sha-$$"
trap 'rm -f -- "$tmp"' EXIT
ln -s "$release" "$tmp"
mv -Tf -- "$tmp" /opt/hermes-yfc-metrics/current
echo 'YFC_EMITTER_INSTALL=ready'
echo "PINNED_REVISION=$sha"
echo "REMOTE_USER=$user"
echo 'SSH_MODE=forced_read_only'
echo 'NEXT=pin_YFC_host_key_and_install_Hermes_pull'
