#!/usr/bin/env bash
# ONE-TIME OWNER-OPERATED SETUP. Not invoked from untrusted CI.
# Usage as root on the approved Hermes VPS:
#   bash deploy/provision-main-deploy.sh < restricted-deploy-key.pub
set -Eeuo pipefail
umask 077
[[ "$EUID" -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }
read -r pubkey || { echo "Public key required on stdin" >&2; exit 1; }
[[ "$pubkey" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9_.@+-]+)?$ ]] || {
  echo "Expected one ED25519 public key" >&2; exit 1;
}
script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
source_handler="$script_dir/hermes-main-deploy.sh"
[[ -f "$source_handler" && ! -L "$source_handler" ]] || { echo "Missing audited handler" >&2; exit 1; }
bash -n "$source_handler"
ssh-keygen -lf <(printf '%s\n' "$pubkey") >/dev/null
user=hermes-deploy
home=/var/lib/hermes-main-deploy
if ! id "$user" >/dev/null 2>&1; then
  useradd --system --home-dir "$home" --create-home --shell /bin/sh "$user"
fi
[[ "$(getent passwd "$user" | cut -d: -f6)" == "$home" ]] || { echo "Unexpected user home" >&2; exit 1; }
install -d -m 0700 -o "$user" -g "$user" "$home/.ssh"
install -m 0750 -o root -g root "$source_handler" /usr/local/sbin/hermes-main-deploy
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
if runuser -u "$user" -- env SSH_ORIGINAL_COMMAND='not-an-approved-deploy' sudo -n /usr/local/sbin/hermes-main-deploy >/dev/null 2>&1; then
  echo "Unexpectedly accepted an invalid deploy command" >&2
  exit 1
fi
echo "HERMES_RESTRICTED_DEPLOY_ACCOUNT_CONFIGURED=yes"
echo "GitHub Secrets and live SSH refusal test are still required before merge."
