#!/usr/bin/env bash
# OWNER-OPERATED ONLY. Never invoked by GitHub Actions or forced-command SSH.
# Initial: bash deploy/provision-main-deploy.sh --initial-setup <reviewed-sha256> < key.pub
# Update:  bash deploy/provision-main-deploy.sh --install-handler <reviewed-sha256>
# Restore: bash deploy/provision-main-deploy.sh --rollback-handler <current-sha256> <previous-sha256>
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/bin
umask 077
die() { echo "HERMES_HANDLER_INSTALL_FAILED: $*" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || die "root only"
script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
source_handler="$script_dir/hermes-main-deploy.sh"
target=/usr/local/sbin/hermes-main-deploy
history=/usr/local/lib/hermes-main-deploy-versions
sha_valid() { [[ "${1:-}" =~ ^[a-f0-9]{64}$ ]]; }
file_sha() { sha256sum -- "$1" | cut -d' ' -f1; }
safe_handler() {
  [[ -f "$1" && ! -L "$1" ]] || die "handler is missing or a symlink"
  bash -n "$1" || die "handler shell syntax invalid"
}
safe_target() {
  if [[ -e "$target" || -L "$target" ]]; then
    safe_handler "$target"
    [[ "$(stat -c %u "$target")" == 0 ]] || die "installed handler not root-owned"
  fi
}
prepare_history() {
  if [[ -e "$history" || -L "$history" ]]; then
    [[ -d "$history" && ! -L "$history" &&
       "$(stat -c %u "$history")" == 0 &&
       "$(stat -c %a "$history")" == 700 ]] ||
      die "handler history directory is unsafe"
  else
    install -d -m 0700 -o root -g root "$history"
  fi
}
install_handler() {
  local expected="$1" current candidate
  sha_valid "$expected" || die "expected reviewed SHA-256 required"
  safe_handler "$source_handler"
  safe_target
  prepare_history
  candidate=$(mktemp "${target}.incoming.XXXXXXXX")
  trap 'rm -f -- "${candidate:-}"' RETURN
  install -m 0750 -o root -g root "$source_handler" "$candidate"
  [[ "$(file_sha "$candidate")" == "$expected" ]] ||
    die "candidate differs from independently reviewed SHA-256"
  if [[ -f "$target" ]]; then
    current=$(file_sha "$target")
    if [[ "$current" == "$expected" ]]; then
      echo "HERMES_HANDLER_ALREADY_INSTALLED=$expected"
      return 0
    fi
    # This directory is root-only; backups cannot be altered by the restricted SSH user.
    if [[ ! -e "$history/$current" ]]; then
      install -m 0700 -o root -g root "$target" "$history/$current"
    fi
    [[ "$(file_sha "$history/$current")" == "$current" ]] ||
      die "existing handler backup invalid"
  fi
  mv -Tf -- "$candidate" "$target"
  [[ "$(file_sha "$target")" == "$expected" ]] || die "installed hash mismatch"
  echo "HERMES_HANDLER_INSTALLED=$expected"
}
rollback_handler() {
  local current="$1" previous="$2" candidate
  sha_valid "$current" && sha_valid "$previous" || die "two reviewed digests required"
  safe_target
  [[ -f "$target" && "$(file_sha "$target")" == "$current" ]] ||
    die "installed handler differs from expected version"
  prepare_history
  safe_handler "$history/$previous"
  [[ "$(file_sha "$history/$previous")" == "$previous" ]] ||
    die "backup digest mismatch"
  candidate=$(mktemp "${target}.restore.XXXXXXXX")
  trap 'rm -f -- "${candidate:-}"' RETURN
  install -m 0750 -o root -g root "$history/$previous" "$candidate"
  [[ "$(file_sha "$candidate")" == "$previous" ]] ||
    die "restored handler digest mismatch"
  mv -Tf -- "$candidate" "$target"
  echo "HERMES_HANDLER_ROLLED_BACK=$previous"
}
case "${1:-}" in
  --install-handler)
    [[ "$#" -eq 2 ]] || die "usage: --install-handler <reviewed-sha256>"
    install_handler "$2"
    exit 0 ;;
  --rollback-handler)
    [[ "$#" -eq 3 ]] || die "usage: --rollback-handler <current-sha256> <previous-sha256>"
    rollback_handler "$2" "$3"
    exit 0 ;;
  --initial-setup)
    [[ "$#" -eq 2 ]] || die "usage: --initial-setup <reviewed-sha256>"
    # Validate the key before any privileged write.
    read -r pubkey || die "public key required on stdin"
    [[ "$pubkey" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9_.@+-]+)?$ ]] ||
      die "expected one ED25519 public key"
    ssh-keygen -lf <(printf '%s\n' "$pubkey") >/dev/null || die "invalid public key"
    install_handler "$2" ;;
  *) die "explicit owner operation required" ;;
esac
user=hermes-deploy
home=/var/lib/hermes-main-deploy
if ! id "$user" >/dev/null 2>&1; then
  useradd --system --home-dir "$home" --create-home --shell /bin/sh "$user"
fi
[[ "$(getent passwd "$user" | cut -d: -f6)" == "$home" ]] ||
  die "unexpected deploy user home"
install -d -m 0700 -o "$user" -g "$user" "$home/.ssh"
cat >/etc/sudoers.d/hermes-main-deploy <<'SUDOERS'
Defaults:hermes-deploy env_keep += "SSH_ORIGINAL_COMMAND"
hermes-deploy ALL=(root) NOPASSWD: /usr/local/sbin/hermes-main-deploy
SUDOERS
chmod 0440 /etc/sudoers.d/hermes-main-deploy
visudo -cf /etc/sudoers.d/hermes-main-deploy >/dev/null
auth="$home/.ssh/authorized_keys"
touch "$auth"
chmod 0600 "$auth"
chown "$user:$user" "$auth"
entry='restrict,command="sudo -n /usr/local/sbin/hermes-main-deploy" '
if ! grep -Fqx "$entry$pubkey" "$auth"; then
  printf '%s%s\n' "$entry" "$pubkey" >> "$auth"
fi
if result="$(runuser -u "$user" -- env SSH_ORIGINAL_COMMAND='not-an-approved-deploy' sudo -n /usr/local/sbin/hermes-main-deploy 2>&1)"; then
  die "unexpectedly accepted an invalid deploy command"
fi
[[ "$result" == *'HERMES_DEPLOY_FAILED: invalid command'* ]] ||
  die "restricted SSH refusal check failed"
echo "HERMES_RESTRICTED_DEPLOY_ACCOUNT_CONFIGURED=yes"
