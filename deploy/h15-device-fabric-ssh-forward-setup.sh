#!/usr/bin/env bash
# Owner-only #276 SSH local-forward identity. No sshd edits/restart or shell access.
set -Eeuo pipefail
umask 077

[[ $# -ge 1 ]] || { echo "SSH_TUNNEL_SETUP_ERROR=missing_mode" >&2; exit 3; }
MODE="$1"
USER_NAME=hermes-presence-tunnel
HOME_DIR=/var/lib/hermes-presence-tunnel
AUTH="$HOME_DIR/.ssh/authorized_keys"
DEST=127.0.0.1:38177
SERVER_PUB=/etc/ssh/ssh_host_ed25519_key.pub
KEY_OPTIONS='command="/usr/sbin/nologin",restrict,port-forwarding,permitopen="127.0.0.1:38177"'

die() { echo "SSH_TUNNEL_SETUP_ERROR=$1" >&2; exit 3; }
[[ "$(id -u)" == 0 ]] || die "root_required"
[[ "$MODE" =~ ^(prepare|status|rollback)$ ]] || die "mode_must_be_prepare_status_or_rollback"

key_line() {
  local path="$1" comment="$2" line count
  [[ -f "$path" && ! -L "$path" ]] || die "missing_or_symlink_public_key"
  count=$(wc -l < "$path")
  [[ "$count" == 1 ]] || die "public_key_must_be_single_line"
  IFS= read -r line < "$path"
  [[ "$line" =~ ^ssh-ed25519[[:space:]]+[A-Za-z0-9+/=]+[[:space:]]+$comment$ ]] ||
    die "invalid_public_key_format_or_comment"
  ssh-keygen -l -f "$path" -E sha256 >/dev/null || die "invalid_ed25519_public_key"
  printf '%s' "$line"
}

account_check() {
  local entry uid home shell groups
  entry=$(getent passwd "$USER_NAME") || return 1
  IFS=: read -r _ _ uid _ _ home shell <<< "$entry"
  [[ "$home" == "$HOME_DIR" && "$shell" == /usr/sbin/nologin ]] ||
    die "unexpected_existing_tunnel_account"
  groups=$(id -Gn "$USER_NAME")
  [[ "$groups" == "$USER_NAME" ]] || die "unexpected_tunnel_group_membership"
  [[ "$uid" =~ ^[0-9]+$ && "$uid" -lt 1000 ]] || die "unexpected_tunnel_uid"
}

verify_identity() {
  local windows linux count
  [[ -f "$AUTH" && ! -L "$AUTH" ]] || die "authorized_keys_not_found"
  [[ "$(stat -c %a "$HOME_DIR")" == 700 ]] || die "home_permissions"
  [[ "$(stat -c %a "$HOME_DIR/.ssh")" == 700 ]] || die "ssh_permissions"
  [[ "$(stat -c %a "$AUTH")" == 600 ]] || die "authorized_keys_permissions"
  [[ "$(stat -c %U "$AUTH")" == "$USER_NAME" ]] || die "authorized_keys_owner"
  count=$(wc -l < "$AUTH")
  [[ "$count" == 2 ]] || die "authorized_keys_unexpected_count"
  windows=$(sed -n '1p' "$AUTH")
  linux=$(sed -n '2p' "$AUTH")
  [[ "$windows" == "$KEY_OPTIONS ssh-ed25519 "*' hermes-presence-windows' ]] ||
    die "authorized_keys_windows_policy"
  [[ "$linux" == "$KEY_OPTIONS ssh-ed25519 "*' hermes-presence-linux' ]] ||
    die "authorized_keys_linux_policy"
  [[ "$windows" != "$linux" ]] || die "duplicate_device_keys"
}

case "$MODE" in
  prepare)
    [[ "$#" == 6 ]] || die "usage_prepare_windows_pub_linux_pub_host_fingerprint_windows_fingerprint_linux_fingerprint"
    command -v ssh-keygen >/dev/null || die "ssh_keygen_missing"
    [[ -f "$SERVER_PUB" && ! -L "$SERVER_PUB" ]] || die "host_key_missing"
    host_fingerprint=$(ssh-keygen -l -f "$SERVER_PUB" -E sha256 | awk '{print $2}')
    [[ "$host_fingerprint" == "$4" ]] || die "host_key_fingerprint_mismatch"
    windows=$(key_line "$2" "hermes-presence-windows")
    linux=$(key_line "$3" "hermes-presence-linux")
    win_fingerprint=$(ssh-keygen -l -f "$2" -E sha256 | awk '{print $2}')
    linux_fingerprint=$(ssh-keygen -l -f "$3" -E sha256 | awk '{print $2}')
    [[ "$win_fingerprint" == "$5" && "$linux_fingerprint" == "$6" ]] || die "device_key_fingerprint_mismatch"
    [[ "$windows" != "$linux" ]] || die "device_keys_not_distinct"
    [[ -x /usr/sbin/nologin ]] || die "nologin_unavailable"
    [[ -x /usr/sbin/sshd ]] || die "sshd_unavailable"
    /usr/sbin/sshd -t || die "existing_sshd_config_invalid"
    if id "$USER_NAME" >/dev/null 2>&1; then
      account_check || die "account_not_found"
    else
      # Invalid password hash '*'; SSH key auth still allowed.
      useradd --system --user-group --create-home \
        --home-dir "$HOME_DIR" --shell /usr/sbin/nologin \
        --password '*' "$USER_NAME" || die "account_create_failed"
      account_check || die "account_invalid"
    fi
    [[ ! -L "$HOME_DIR" && ! -L "$HOME_DIR/.ssh" && ! -L "$AUTH" ]] ||
      die "unexpected_symlink_in_account"
    install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR" "$HOME_DIR/.ssh"
    staged=$(mktemp "$HOME_DIR/.ssh/.authorized_keys.XXXXXXXX")
    trap 'rm -f -- "$staged"' EXIT
    printf '%s %s\n%s %s\n' "$KEY_OPTIONS" "$windows" "$KEY_OPTIONS" "$linux" > "$staged"
    chmod 0600 "$staged"
    chown "$USER_NAME:$USER_NAME" "$staged"
    if [[ -e "$AUTH" ]]; then
      [[ -f "$AUTH" && ! -L "$AUTH" ]] || die "unexpected_existing_authorized_keys"
      cmp -s "$staged" "$AUTH" || die "existing_keys_differ_manual_review_required"
      echo "SSH_TUNNEL_KEYS=ALREADY_PRESENT"
    else
      mv -T -- "$staged" "$AUTH"
      echo "SSH_TUNNEL_KEYS=INSTALLED"
    fi
    verify_identity
    echo "SSH_HOST_FINGERPRINT=VERIFIED"
    echo "SSH_TUNNEL_ACCOUNT=ISOLATED"
    echo "SSH_ALLOWED_DESTINATION=$DEST"
    echo "SSH_REMOTE_SHELL=DENIED"
    echo "SSHD_CONFIG=UNCHANGED"
    echo "SSHD_RESTART=NOT_REQUIRED"
    ;;
  status)
    [[ "$#" == 1 ]] || die "unexpected_arguments"
    account_check || die "account_missing"
    verify_identity
    echo "SSH_TUNNEL_ACCOUNT=READY"
    echo "SSH_TUNNEL_DEVICE_KEYS=2"
    echo "SSH_ALLOWED_DESTINATION=$DEST"
    echo "SSH_REMOTE_SHELL=DENIED"
    echo "SSHD_CONFIG=UNCHANGED"
    ;;
  rollback)
    [[ "$#" == 1 ]] || die "unexpected_arguments"
    account_check || die "account_missing"
    verify_identity
    rm -f -- "$AUTH"
    echo "SSH_TUNNEL_KEYS=REVOKED"
    echo "TUNNEL_ACCOUNT_PRESERVED=YES"
    echo "SSHD_RESTART=NOT_REQUIRED"
    ;;
esac
