#!/usr/bin/env bash
# Manual, operator-gated YFC VPS bootstrap for the existing #294 SSH pull.
# NO remote connection, agent, daemon, network access or SSHD modification.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/bin
umask 077

usage() {
  echo "Usage: sudo bash deploy/install-yfc-infrastructure-emitter.sh CHECKOUT_DIR EXPECTED_40_HEX_SHA PUBLIC_KEY_FILE" >&2
  exit 2
}
die() { printf 'YFC_EMITTER_INSTALL=refused reason=%s\n' "$1" >&2; exit 1; }

[[ $# == 3 ]] || usage
[[ "$EUID" == 0 ]] || die root_required
checkout=$(realpath -e -- "$1") || die invalid_checkout
sha=$2
pub=$(realpath -e -- "$3") || die missing_public_key
[[ "$sha" =~ ^[a-f0-9]{40}$ ]] || die invalid_revision
[[ -f "$checkout/control_center/infrastructure.py" &&
   -f "$checkout/control_center/__init__.py" &&
   -f "$checkout/deploy/hermes-yfc-metrics-emit.sh" ]] || die missing_files
for name in control_center/infrastructure.py control_center/__init__.py deploy/hermes-yfc-metrics-emit.sh; do
  [[ ! -L "$checkout/$name" ]] || die source_symlink
done
[[ "$(git -C "$checkout" rev-parse HEAD)" == "$sha" ]] || die revision_mismatch
[[ -f "$pub" && ! -L "$3" ]] || die bad_public_key
[[ "$(wc -c < "$pub")" -le 300 ]] || die key_oversize
public_key=$(cat "$pub")
# Use a quoted regular expression variable to avoid Bash condition parsing of ().
pubkey_pattern='^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9_.@:-]+)?$'
[[ "$public_key" =~ $pubkey_pattern ]] || die unsupported_key
/usr/bin/ssh-keygen -lf "$pub" >/dev/null || die malformed_key

user=hermes-infra-read
home=/var/lib/hermes-infra-read
if id "$user" >/dev/null 2>&1; then
  [[ "$(getent passwd "$user" | cut -d: -f6)" == "$home" ]] || die incompatible_existing_user
else
  /usr/sbin/useradd --system --create-home --home-dir "$home" \
    --shell /bin/sh --user-group "$user" || die useradd_failed
fi
[[ "$(id -u "$user")" != 0 ]] || die invalid_user_id
[[ "$(getent passwd "$user" | cut -d: -f7)" == /bin/sh ]] ||
  die incompatible_existing_shell

[[ ! -L /opt/hermes-yfc-metrics && ! -L /opt/hermes-yfc-metrics/releases ]] ||
  die release_symlink
install -d -o root -g root -m 0755 /opt/hermes-yfc-metrics
install -d -o root -g root -m 0755 /opt/hermes-yfc-metrics/releases
release="/opt/hermes-yfc-metrics/releases/main-$sha"
[[ ! -e "$release" && ! -L "$release" ]] || die release_already_exists
install -d -o root -g root -m 0755 "$release"
install -d -o root -g root -m 0755 "$release/control_center"
install -o root -g root -m 0644 "$checkout/control_center/__init__.py" "$release/control_center/__init__.py"
install -o root -g root -m 0644 "$checkout/control_center/infrastructure.py" "$release/control_center/infrastructure.py"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$checkout/deploy/hermes-yfc-metrics-emit.sh" \
  /usr/local/libexec/hermes-yfc-metrics-emit

# An old authorized_keys file with unrelated access must never be overwritten.
install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
forced="restrict,command=\"/usr/local/libexec/hermes-yfc-metrics-emit\" $public_key"
if [[ -e "$home/.ssh/authorized_keys" ]]; then
  [[ ! -L "$home/.ssh/authorized_keys" ]] || die existing_authorized_keys_symlink
  [[ "$(cat "$home/.ssh/authorized_keys")" == "$forced" ]] ||
    die existing_authorized_keys_conflict
else
  printf '%s\n' "$forced" | install -o "$user" -g "$user" -m 0600 /dev/stdin "$home/.ssh/authorized_keys"
fi

# Validate the unprivileged command BEFORE switching the pinned release.
# -m with the release directory as CWD is the only Python import path allowed.
(
  cd "$release"
  env -u PYTHONPATH -u PYTHONSTARTUP /usr/sbin/runuser -u "$user" -- \
    /usr/bin/python3 -m control_center.infrastructure --host yfc --stdout |
    /usr/bin/python3 -c '
import json, sys
obj=json.load(sys.stdin)
assert obj["schema"] == 1
assert obj["host"] == "yfc"
assert obj["source"] == "linux_procfs_local"
assert 0 <= obj["metrics"]["ram_used_percent"] <= 100
assert 0 <= obj["metrics"]["disk_used_percent"] <= 100
'
) || die collector_smoke_failed

# Keep previous immutable target for normal operator rollback.
tmp="/opt/hermes-yfc-metrics/.current-$sha-$$"
ln -s "$release" "$tmp"
mv -Tf -- "$tmp" /opt/hermes-yfc-metrics/current
echo "YFC_EMITTER_INSTALL=ready"
echo "PINNED_REVISION=$sha"
echo "REMOTE_USER=$user"
echo "KEY_MODE=forced_read_only"
echo "NEXT=configure_pinned_ssh_pull_on_hermes"
\n'* ]] || die key_multiple
[[ "$public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9_.@:-]+)?$ ]] ||
  die unsupported_key
/usr/bin/ssh-keygen -lf "$pub" >/dev/null || die malformed_key

user=hermes-infra-read
home=/var/lib/hermes-infra-read
if id "$user" >/dev/null 2>&1; then
  [[ "$(getent passwd "$user" | cut -d: -f6)" == "$home" ]] || die incompatible_existing_user
else
  /usr/sbin/useradd --system --create-home --home-dir "$home" \
    --shell /bin/sh --user-group "$user" || die useradd_failed
fi
[[ "$(id -u "$user")" != 0 ]] || die invalid_user_id
[[ "$(getent passwd "$user" | cut -d: -f7)" == /bin/sh ]] ||
  die incompatible_existing_shell

install -d -o root -g root -m 0755 /opt/hermes-yfc-metrics
install -d -o root -g root -m 0755 /opt/hermes-yfc-metrics/releases
release="/opt/hermes-yfc-metrics/releases/main-$sha"
install -d -o root -g root -m 0755 "$release"
install -d -o root -g root -m 0755 "$release/control_center"
install -o root -g root -m 0644 "$checkout/control_center/__init__.py" "$release/control_center/__init__.py"
install -o root -g root -m 0644 "$checkout/control_center/infrastructure.py" "$release/control_center/infrastructure.py"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$checkout/deploy/hermes-yfc-metrics-emit.sh" \
  /usr/local/libexec/hermes-yfc-metrics-emit

# An old authorized_keys file with unrelated access must never be overwritten.
install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
forced="restrict,command=\"/usr/local/libexec/hermes-yfc-metrics-emit\" $public_key"
if [[ -e "$home/.ssh/authorized_keys" ]]; then
  [[ ! -L "$home/.ssh/authorized_keys" ]] || die existing_authorized_keys_symlink
  [[ "$(cat "$home/.ssh/authorized_keys")" == "$forced" ]] ||
    die existing_authorized_keys_conflict
else
  printf '%s\n' "$forced" | install -o "$user" -g "$user" -m 0600 /dev/stdin "$home/.ssh/authorized_keys"
fi

# Validate the unprivileged command BEFORE switching the pinned release.
# -m with the release directory as CWD is the only Python import path allowed.
(
  cd "$release"
  env -u PYTHONPATH -u PYTHONSTARTUP /usr/sbin/runuser -u "$user" -- \
    /usr/bin/python3 -m control_center.infrastructure --host yfc --stdout |
    /usr/bin/python3 -c '
import json, sys
obj=json.load(sys.stdin)
assert obj["schema"] == 1
assert obj["host"] == "yfc"
assert obj["source"] == "linux_procfs_local"
assert 0 <= obj["metrics"]["ram_used_percent"] <= 100
assert 0 <= obj["metrics"]["disk_used_percent"] <= 100
'
) || die collector_smoke_failed

# Keep previous immutable target for normal operator rollback.
tmp="/opt/hermes-yfc-metrics/.current-$sha-$$"
ln -s "$release" "$tmp"
mv -Tf -- "$tmp" /opt/hermes-yfc-metrics/current
echo "YFC_EMITTER_INSTALL=ready"
echo "PINNED_REVISION=$sha"
echo "REMOTE_USER=$user"
echo "KEY_MODE=forced_read_only"
echo "NEXT=configure_pinned_ssh_pull_on_hermes"
