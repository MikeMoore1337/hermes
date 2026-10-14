#!/usr/bin/env bash
# Interactive, zero-network secret provisioning for the isolated Workers Free agent.
set -euo pipefail
umask 077

STATE=/var/lib/hermes-agent
if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите локально на Hermes VPS с правами администратора." >&2
  exit 1
fi
if [ ! -t 0 ] || [ ! -t 1 ]; then
  echo "Нужен настоящий интерактивный терминал, не CI и не чат." >&2
  exit 1
fi
if [ ! -d "$STATE" ] || [ -L "$STATE" ] || [ "$(stat -c %a "$STATE")" != 700 ]; then
  echo "Не обнаружен защищённый каталог Hermes Agent." >&2
  exit 1
fi
if [ -e "$STATE/.env" ] || [ -L "$STATE/.env" ]; then
  echo "Файл .env уже существует. Не перезаписываю секреты." >&2
  exit 1
fi

printf '%s\n' 'Cloudflare Dashboard -> Workers AI -> Use REST API.'
read -r -p 'Account ID (32 символа hex): ' account_id
if [[ ! "$account_id" =~ ^[0-9a-fA-F]{32}$ ]]; then
  echo "Недопустимый формат Account ID." >&2
  exit 1
fi
read -r -s -p 'Отдельный Workers AI API Token (ввод скрыт): ' token
printf '\n'
if [[ ! "$token" =~ ^[A-Za-z0-9._-]{20,256}$ ]]; then
  unset token
  echo "Недопустимый формат токена." >&2
  exit 1
fi
printf '%s\n' 'Важно: Workers Paid и платный AI Gateway здесь ЗАПРЕЩЕНЫ.'
read -r -p 'Подтвердите, что аккаунт использует Workers Free (напишите FREE): ' confirmation
if [ "$confirmation" != FREE ]; then
  unset token
  echo "План не подтверждён, сохранение отменено." >&2
  exit 1
fi

uid="$(id -u hermes-agent)"
gid="$(id -g hermes-agent)"
tmp="$(mktemp "$STATE/.env.pending.XXXXXXXX")"
trap 'rm -f "$tmp"' EXIT
printf 'CLOUDFLARE_WORKERS_AI_API_TOKEN=%s\n' "$token" > "$tmp"
printf 'CLOUDFLARE_WORKERS_AI_BASE_URL=https://api.cloudflare.com/client/v4/accounts/%s/ai/v1\n' "$account_id" >> "$tmp"
unset token
chown "$uid:$gid" "$tmp"
chmod 0600 "$tmp"
# Atomic hard-link creation: will fail rather than overwrite on a race.
ln -T "$tmp" "$STATE/.env"
rm -f "$tmp"
trap - EXIT
printf '%s\n' 'Cloudflare Workers Free credentials saved securely. No services were started.'
