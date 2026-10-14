#!/usr/bin/env bash
# Offline, idempotent bootstrap. Does not enable any Hermes service or add keys.
set -euo pipefail

ROOT='/opt/hermes-agent-owner'
STATE='/var/lib/hermes-agent'
NAME='cloudflare-workers-ai-free'
SOURCE="$ROOT/plugins/$NAME"
DEST="$STATE/plugins/$NAME"

if [ "$(id -u)" -ne 0 ]; then
  echo "Administrator context required" >&2
  exit 1
fi
if [ ! -d "$STATE" ] || [ -L "$STATE" ]; then
  echo "Private agent data root missing/unsafe" >&2
  exit 1
fi
uid="$(id -u hermes-agent)"
gid="$(id -g hermes-agent)"
if [ "$(stat -c %u "$STATE")" != "$uid" ] || [ "$(stat -c %g "$STATE")" != "$gid" ] || [ "$(stat -c %a "$STATE")" != 700 ]; then
  echo "Private agent directory permissions differ from audited baseline" >&2
  exit 1
fi
for file in __init__.py plugin.yaml LICENSE; do
  if [ ! -s "$SOURCE/$file" ] || [ -L "$SOURCE/$file" ]; then
    echo "Missing or unsafe reviewed provider file" >&2
    exit 1
  fi
done
if [ -e "$DEST" ]; then
  echo "Provider already staged; refusing to overwrite an existing installation" >&2
  exit 2
fi
if [ -e "$STATE/config.yaml" ]; then
  echo "Existing config.yaml detected; refusing to overwrite" >&2
  exit 2
fi

install -d -m 0700 -o "$uid" -g "$gid" "$STATE/plugins"
install -d -m 0700 -o "$uid" -g "$gid" "$DEST"
for file in __init__.py plugin.yaml LICENSE; do
  install -m 0600 -o "$uid" -g "$gid" "$SOURCE/$file" "$DEST/$file"
done
umask 077
config="$(mktemp "$STATE/.config.yaml.staged.XXXXXX")"
trap 'rm -f "$config"' EXIT
printf '%s\n' 'model:' '  provider: workers-ai' '  default: "@cf/openai/gpt-oss-20b"' 'agent:' '  reasoning_effort: low' > "$config"
chown "$uid:$gid" "$config"
chmod 0600 "$config"
mv -T "$config" "$STATE/config.yaml"
echo 'Free-only provider and model selection staged (no token, network or service activation).'
