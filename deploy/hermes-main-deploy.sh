#!/usr/bin/env bash
# Hermes production deploy endpoint, invoked ONLY via a restricted SSH key.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/bin
umask 077
die() { echo "HERMES_DEPLOY_FAILED: $*" >&2; exit 1; }
# Observe the kernel's monotonic uptime; curl attempts and sleeps share one deadline.
# Never extend the readiness budget by starting another full timeout near its end.
health_monotonic_ms() {
  local uptime whole fraction
  IFS=' ' read -r uptime _ < /proc/uptime || die "monotonic clock unavailable"
  [[ "$uptime" =~ ^[0-9]+\.[0-9]+$ ]] || die "invalid monotonic clock"
  whole="${uptime%%.*}"
  fraction="${uptime#*.}000"
  echo "$((10#$whole * 1000 + 10#${fraction:0:3}))"
}
wait_for_control_center_health() {
  local deadline remaining budget wait_ms max_time http_code reason=not_ready
  local response_file="$work/health-response"
  deadline=$(( $(health_monotonic_ms) + 20000 ))
  while :; do
    systemctl is-active --quiet hermes-control-center.service ||
      die "UI service stopped during readiness"
    remaining=$(( deadline - $(health_monotonic_ms) ))
    (( remaining > 0 )) || die "health readiness timed out: $reason"
    budget=$(( remaining < 3000 ? remaining : 3000 ))
    printf -v max_time '%d.%03d' "$((budget / 1000))" "$((budget % 1000))"
    : > "$response_file"
    if http_code=$(curl -sS --noproxy '*' --max-time "$max_time" \
      --connect-timeout "$max_time" --max-redirs 0 \
      --output "$response_file" --write-out '%{http_code}' \
      http://127.0.0.1:9133/healthz 2>/dev/null); then
      if [[ "$http_code" == 200 ]] && grep -q '[^[:space:]]' "$response_file"; then
        systemctl is-active --quiet hermes-control-center.service ||
          die "UI service stopped during readiness"
        return 0
      fi
      if [[ "$http_code" == 200 ]]; then
        reason=empty_health_response
      else
        reason="HTTP_${http_code:-unknown}"
      fi
    else
      reason=transport_error
    fi
    systemctl is-active --quiet hermes-control-center.service ||
      die "UI service stopped during readiness"
    remaining=$(( deadline - $(health_monotonic_ms) ))
    (( remaining > 0 )) || die "health readiness timed out: $reason"
    wait_ms=$(( remaining < 250 ? remaining : 250 ))
    printf -v max_time '%d.%03d' "$((wait_ms / 1000))" "$((wait_ms % 1000))"
    sleep "$max_time"
  done
}
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
if [[ -r "$state" && "$(cat "$state")" == "$sha" && \
      -r "$base/releases/main-$sha/.deployment-receipt.txt" && \
      "$(readlink -f "$ui/current")" == "$ui/releases/main-$sha" ]] && \
      grep -Fxq "SHA=$sha" "$base/releases/main-$sha/.deployment-receipt.txt" && \
      systemctl is-active --quiet hermes-control-center.service && \
      [[ "$(curl -fsS --max-time 5 --noproxy '*' --max-redirs 0 --write-out '%{http_code}' http://127.0.0.1:9133/healthz 2>/dev/null)" == ok200 ]]; then
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
# Optional WSS integration tests run in their own pinned CI venv; isolated host
# stdlib unittest may legitimately finish as OK (skipped=N).
grep -Eq '^OK( \(skipped=[0-9]+\))?
grep '^Ran [0-9]* tests' "$work/tests.log" | tail -1
systemctl is-active --quiet hermes-agent-sandbox.service && die "unscoped gateway unexpectedly active"
# The approved H-01 read-only one-shot needs the dedicated CONNECT proxy.
# Allow an already-running proxy only when the dedicated OS egress guard passes.
if systemctl is-active --quiet hermes-cloudflare-proxy.service; then
  systemctl is-active --quiet hermes-cloudflare-network-guard.service || die "agent guard inactive"
  /usr/bin/python3 "$base/scripts/ensure_cloudflare_egress.py" --check >/dev/null ||
    die "active agent proxy has unverified egress boundary"
fi
for u in hermes-ops-watch.service hermes-ops-alerts.service hermes-qa-watch.service hermes-research-scout.service hermes-h01-ops-agent.service; do
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
# H-03 owner review consumes the existing read-only Research Scout packet.
cp -a -- "$release/research_scout" "$ui_release/"
chown -R root:root "$ui_release"
chmod -R a+rX,go-w "$ui_release"
# Verify imports exactly as the UI service starts: cwd-based python -m,
# without the PYTHONPATH override which previously concealed missing siblings.
runuser -u hermes-control -- sh -c 'cd "$1" && /usr/bin/python3 -c "import control_center.server; import research_scout.report_view"' sh "$ui_release"
ui_old=$(readlink -f "$ui/current")
ln -s -- "$ui_release" "$ui/.incoming-$short"
mv -Tf -- "$ui/.incoming-$short" "$ui/current"
ui_switched=yes
systemctl restart hermes-control-center.service
wait_for_control_center_health
for u in hermes-discovery.timer hermes-ops-watch.timer hermes-ops-alerts.timer hermes-qa-watch.timer hermes-research-scout.timer hermes-control-center-snapshot.timer; do
  systemctl is-active --quiet "$u" || die "timer unhealthy: $u"
done
systemctl is-active --quiet hermes-agent-sandbox.service && die "unscoped gateway unexpectedly enabled"
if systemctl is-active --quiet hermes-cloudflare-proxy.service; then
  systemctl is-active --quiet hermes-cloudflare-network-guard.service || die "agent guard lost"
  /usr/bin/python3 "$base/scripts/ensure_cloudflare_egress.py" --check >/dev/null ||
    die "active agent proxy drifted during deploy"
fi
printf 'SHA=%s\nARCHIVE_SHA256=%s\nPREVIOUS_UI=%s\nBACKUP=%s\nRESIDENT_ACTIVATED=no\n' "$sha" "$digest" "$ui_old" "$backup" > "$release/.deployment-receipt.txt"
chmod -R a-w "$release"
printf '%s\n' "$sha" > "$work/last-success.sha"
install -m 0600 "$work/last-success.sha" "$state"
committed=yes
echo "PRODUCTION_DEPLOYED=$sha"
 "$work/tests.log" || die "unit test status missing"
grep '^Ran [0-9]* tests' "$work/tests.log" | tail -1
systemctl is-active --quiet hermes-agent-sandbox.service && die "unscoped gateway unexpectedly active"
# The approved H-01 read-only one-shot needs the dedicated CONNECT proxy.
# Allow an already-running proxy only when the dedicated OS egress guard passes.
if systemctl is-active --quiet hermes-cloudflare-proxy.service; then
  systemctl is-active --quiet hermes-cloudflare-network-guard.service || die "agent guard inactive"
  /usr/bin/python3 "$base/scripts/ensure_cloudflare_egress.py" --check >/dev/null ||
    die "active agent proxy has unverified egress boundary"
fi
for u in hermes-ops-watch.service hermes-ops-alerts.service hermes-qa-watch.service hermes-research-scout.service hermes-h01-ops-agent.service; do
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
# H-03 owner review consumes the existing read-only Research Scout packet.
cp -a -- "$release/research_scout" "$ui_release/"
chown -R root:root "$ui_release"
chmod -R a+rX,go-w "$ui_release"
# Verify imports exactly as the UI service starts: cwd-based python -m,
# without the PYTHONPATH override which previously concealed missing siblings.
runuser -u hermes-control -- sh -c 'cd "$1" && /usr/bin/python3 -c "import control_center.server; import research_scout.report_view"' sh "$ui_release"
ui_old=$(readlink -f "$ui/current")
ln -s -- "$ui_release" "$ui/.incoming-$short"
mv -Tf -- "$ui/.incoming-$short" "$ui/current"
ui_switched=yes
systemctl restart hermes-control-center.service
wait_for_control_center_health
for u in hermes-discovery.timer hermes-ops-watch.timer hermes-ops-alerts.timer hermes-qa-watch.timer hermes-research-scout.timer hermes-control-center-snapshot.timer; do
  systemctl is-active --quiet "$u" || die "timer unhealthy: $u"
done
systemctl is-active --quiet hermes-agent-sandbox.service && die "unscoped gateway unexpectedly enabled"
if systemctl is-active --quiet hermes-cloudflare-proxy.service; then
  systemctl is-active --quiet hermes-cloudflare-network-guard.service || die "agent guard lost"
  /usr/bin/python3 "$base/scripts/ensure_cloudflare_egress.py" --check >/dev/null ||
    die "active agent proxy drifted during deploy"
fi
printf 'SHA=%s\nARCHIVE_SHA256=%s\nPREVIOUS_UI=%s\nBACKUP=%s\nRESIDENT_ACTIVATED=no\n' "$sha" "$digest" "$ui_old" "$backup" > "$release/.deployment-receipt.txt"
chmod -R a-w "$release"
printf '%s\n' "$sha" > "$work/last-success.sha"
install -m 0600 "$work/last-success.sha" "$state"
committed=yes
echo "PRODUCTION_DEPLOYED=$sha"
