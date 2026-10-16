#!/usr/bin/env bash
# Hermes production deploy endpoint, invoked ONLY via a restricted SSH key.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/bin
umask 077
die() { echo "HERMES_DEPLOY_FAILED: $*" >&2; exit 1; }
read -r verb sha digest extra <<< "$SSH_ORIGINAL_COMMAND"
[[ "$verb" == deploy && -z "$extra" && "$sha" =~ ^[a-f0-9]{40}$ && "$digest" =~ ^[a-f0-9]{64}$ ]] || die "invalid command"
[[ "$EUID" == 0 ]] || die "root only"
base=/opt/hermes-agent-owner
ui=/opt/hermes-control-center
short=$(printf %.12s "$sha")
state=/var/lib/hermes-main-deploy/last-success.sha
mkdir -p /var/lib/hermes-main-deploy "$base/releases" "$ui/releases"
exec 9>/run/lock/hermes-main-deploy.lock
flock -n 9 || die "another deploy is running"
if [[ -r "$state" && "$(cat "$state")" == "$sha" ]] && systemctl is-active --quiet hermes-control-center.service && curl -fsS --max-time 5 http://127.0.0.1:9133/healthz >/dev/null; then
  echo "ALREADY_DEPLOYED=$sha"
  exit 0
fi
work=$(mktemp -d "$base/releases/.incoming-$short-XXXXXXXX")
backup="$base/releases/.backup-$short-$(date -u +%Y%m%dT%H%M%SZ)"
release="$base/releases/main-$sha"
ui_release="$ui/releases/main-$sha"
updated=""
ui_old=""
ui_switched=no
release_created=no
ui_created=no
committed=no
cleanup() {
  result=$?
  if [[ "$committed" != yes ]]; then
    for m in $updated; do
      rm -rf -- "$base/$m"
      if [[ -d "$backup/$m" ]]; then mv -T -- "$backup/$m" "$base/$m"; fi
    done
    if [[ "$ui_switched" == yes ]]; then
      ln -s -- "$ui_old" "$ui/.rollback-$short"
      mv -Tf -- "$ui/.rollback-$short" "$ui/current"
      systemctl restart hermes-control-center.service || true
    fi
    if [[ "$ui_created" == yes ]]; then rm -rf -- "$ui_release"; fi
    if [[ "$release_created" == yes ]]; then rm -rf -- "$release"; fi
  fi
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT
head -c 30000001 > "$work/source.tar.gz"
[[ "$(stat -c %s "$work/source.tar.gz")" -le 30000000 ]] || die "archive too large"
printf '%s  %s\n' "$digest" "$work/source.tar.gz" | sha256sum -c - >/dev/null || die "checksum mismatch"
gzip -t "$work/source.tar.gz" || die "invalid gzip"
set +o pipefail
actual=$(gzip -dc "$work/source.tar.gz" | git get-tar-commit-id 2>/dev/null)
set -o pipefail
[[ "$actual" == "$sha" ]] || die "Git archive SHA mismatch"
python3 - "$work/source.tar.gz" <<'PY'
import sys, tarfile
from pathlib import PurePosixPath
with tarfile.open(sys.argv[1], "r:gz") as tf:
    entries = tf.getmembers()
    if not entries or sum(e.size for e in entries) > 200_000_000:
        raise SystemExit("invalid archive size")
    for e in entries:
        p = PurePosixPath(e.name)
        if p.is_absolute() or ".." in p.parts or not (e.isfile() or e.isdir()):
            raise SystemExit("unsafe archive member")
PY
mkdir "$work/src"
tar -xzf "$work/source.tar.gz" -C "$work/src" --no-same-owner --no-same-permissions
cd "$work/src"
for m in ops_watch qa_advisor research_scout scripts agent_budget editorial_review knowledge_quality content_research marketing plugins control_center; do
  [[ -d "$m" ]] || die "missing module $m"
done
# The uploaded source is untrusted until validated. NEVER execute its Python as root.
# systemd-run creates an ephemeral non-root user with a separate network namespace,
# no privilege escalation, read-only host filesystem, and explicit resource limits.
# Git tar paths inherit the root process umask 077 on extraction. Without
# normalizing file/dir *read* bits, DynamicUser cannot open validation scripts.
# Source remains root-owned and non-writable by the transient sandbox user.
chmod 0755 "$work" "$work/src"
chmod -R a+rX,go-w "$work/src"
isolated_python() {
  systemd-run --wait --collect --pipe --quiet \
    -p DynamicUser=yes -p "WorkingDirectory=$work/src" \
    -p PrivateNetwork=yes -p NoNewPrivileges=yes \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes \
    -p PrivateDevices=yes -p MemoryMax=1G -p TasksMax=128 \
    -p RuntimeMaxSec=180 -E PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/python3 "$@"
}
isolated_python scripts/validate_repo.py || die "repo validation failed"
isolated_python scripts/check_policy_index.py || die "policy check failed"
isolated_python scripts/check_markdown_links.py || die "markdown links failed"
isolated_python -m unittest discover -s tests -q > "$work/tests.log" 2>&1 || { tail -25 "$work/tests.log" >&2; die "non-root offline tests failed"; }
grep -q '^OK$' "$work/tests.log" || die "unit test status missing"
grep '^Ran [0-9]* tests' "$work/tests.log" | tail -1
systemctl is-active --quiet hermes-agent-sandbox.service && die "resident agent unexpectedly active"
systemctl is-active --quiet hermes-cloudflare-proxy.service && die "proxy unexpectedly active"
for u in hermes-ops-watch.service hermes-ops-alerts.service hermes-qa-watch.service hermes-research-scout.service; do
  for attempt in 1 2 3 4 5; do
    systemctl is-active --quiet "$u" || break
    sleep 3
  done
  systemctl is-active --quiet "$u" && die "service busy: $u"
done
[[ ! -e "$release" && ! -e "$ui_release" ]] || die "release path already exists"
mv -T -- "$work/src" "$release"
release_created=yes
mkdir -m 0700 "$backup"
for m in ops_watch qa_advisor research_scout scripts agent_budget editorial_review knowledge_quality content_research marketing plugins; do
  cp -a -- "$release/$m" "$base/.incoming-$short-$m"
  if [[ -d "$base/$m" ]]; then mv -T -- "$base/$m" "$backup/$m"; fi
  updated="$m $updated"
  mv -T -- "$base/.incoming-$short-$m" "$base/$m"
done
mkdir -m 0755 "$ui_release"
ui_created=yes
cp -a -- "$release/control_center" "$ui_release/"
chown -R root:root "$ui_release"
chmod -R a+rX,go-w "$ui_release"
runuser -u hermes-control -- env PYTHONPATH="$ui_release" python3 -c 'import control_center.server'
ui_old=$(readlink -f "$ui/current")
ln -s -- "$ui_release" "$ui/.incoming-$short"
mv -Tf -- "$ui/.incoming-$short" "$ui/current"
ui_switched=yes
systemctl restart hermes-control-center.service
sleep 2
systemctl is-active --quiet hermes-control-center.service || die "UI service not active"
curl -fsS --max-time 8 http://127.0.0.1:9133/healthz >/dev/null || die "health check failed"
for u in hermes-discovery.timer hermes-ops-watch.timer hermes-ops-alerts.timer hermes-qa-watch.timer hermes-research-scout.timer hermes-control-center-snapshot.timer; do
  systemctl is-active --quiet "$u" || die "timer unhealthy: $u"
done
systemctl is-active --quiet hermes-agent-sandbox.service && die "resident agent unexpectedly enabled"
systemctl is-active --quiet hermes-cloudflare-proxy.service && die "proxy unexpectedly enabled"
printf '%s\n' "$sha" > "$work/last-success.sha"
install -m 0600 "$work/last-success.sha" "$state"
printf 'SHA=%s\nARCHIVE_SHA256=%s\nPREVIOUS_UI=%s\nBACKUP=%s\nRESIDENT_ACTIVATED=no\n' "$sha" "$digest" "$ui_old" "$backup" > "$release/.deployment-receipt.txt"
chmod -R a-w "$release"
committed=yes
echo "PRODUCTION_DEPLOYED=$sha"
