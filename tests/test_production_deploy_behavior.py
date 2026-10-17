"""Offline behavior of the REAL deploy shell (production paths substituted in a temp copy).

Synthetic git archive, fake systemd and HTTP adapter; no VPS, production credentials
or privileged operations. CI runs this test on Linux.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ("ops_watch", "qa_advisor", "research_scout", "scripts", "agent_budget",
           "editorial_review", "knowledge_quality", "content_research", "marketing",
           "plugins", "control_center")
DEPS = ("bash", "git", "tar", "gzip", "python3")


def executable(path, source):
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


@unittest.skipUnless(os.name == "posix" and Path("/proc/uptime").exists()
                     and all(shutil.which(cmd) for cmd in DEPS), "Linux utilities required")
class ProductionDeployBehavior(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hermes-cd-offline-")
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.base = self.dir / "base"
        self.ui = self.dir / "ui"
        (self.base / "releases").mkdir(parents=True)
        (self.base / "ops_watch").mkdir()
        (self.base / "ops_watch" / "old").write_text("old")
        (self.ui / "releases" / "old").mkdir(parents=True)
        (self.ui / "current").symlink_to(self.ui / "releases" / "old")
        self.state = self.dir / "last-success.sha"
        self.clock = self.dir / "clock"
        self.clock.write_text("0")
        self._prepare_mocks()
        self.sha, self.data = self._make_archive()
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.script = self.dir / "deploy.sh"
        source = (ROOT / "deploy/hermes-main-deploy.sh").read_text()
        for before, after in (
            ("export PATH=/usr/sbin:/usr/bin:/bin",
             'export PATH="' + str(self.bin) + ':/usr/sbin:/usr/bin:/bin"'),
            ('[[ "$EUID" == 0 ]]', '[[ "$EUID" -ge 0 ]]'),
            ("base=/opt/hermes-agent-owner", 'base="' + str(self.base) + '"'),
            ("ui=/opt/hermes-control-center", 'ui="' + str(self.ui) + '"'),
            ("state=/var/lib/hermes-main-deploy/last-success.sha", 'state="' + str(self.state) + '"'),
            ("mkdir -p /var/lib/hermes-main-deploy ", "mkdir -p " + str(self.dir / "state") + " "),
            ("exec 9>/run/lock/hermes-main-deploy.lock", 'exec 9>"' + str(self.dir / "lock") + '"'),
        ):
            self.assertIn(before, source)
            source = source.replace(before, after, 1)
        # Every clock call advances by 500ms, including curl network budget accounting.
        clock_function = ('health_monotonic_ms() {\n'
                          '  local n\n'
                          '  n=$(cat "$MOCK_CLOCK")\n'
                          '  n=$((n + 500))\n'
                          '  echo "$n" > "$MOCK_CLOCK"\n'
                          '  echo "$n"\n'
                          '}')
        source, count = re.subn(r'health_monotonic_ms\(\) \{.*?^\}',
                                clock_function, source, count=1,
                                flags=re.MULTILINE | re.DOTALL)
        self.assertEqual(count, 1)
        self.script.write_text(source)
        subprocess.run(["bash", "-n", str(self.script)], check=True)

    def _prepare_mocks(self):
        # The fake endpoints are processes (not text assertions): every invocation records state.
        executable(self.bin / "curl", """#!/usr/bin/env python3
import os, pathlib, sys
p = pathlib.Path(os.environ["MOCK_HTTP_COUNT"])
n = int(p.read_text()) + 1 if p.exists() else 1
p.write_text(str(n))
entries = os.environ["MOCK_HTTP"].split(",")
item = entries[min(n - 1, len(entries) - 1)]
if item == "ERR":
    sys.exit(7)
args = sys.argv
out = pathlib.Path(args[args.index("--output") + 1]) if "--output" in args else None
if item == "200:ok":
    if out: out.write_text("ok")
    else: print("ok", end="")
    code = "200"
elif item == "200:empty":
    code = "200"
elif item == "200:space":
    if out: out.write_text("  \\n")
    code = "200"
else:
    if out: out.write_text("error")
    code = item
if "--write-out" in args:
    print(code, end="")
""")
        executable(self.bin / "systemctl", """#!/usr/bin/env python3
import os, pathlib, sys
a = sys.argv[1:]
if a[:2] == ["is-active", "--quiet"]:
    name = a[2]
    if name == "hermes-control-center.service":
        p = pathlib.Path(os.environ["MOCK_SYSTEM_COUNT"])
        n = int(p.read_text()) + 1 if p.exists() else 1
        p.write_text(str(n))
        sys.exit(3 if int(os.environ["MOCK_STOP_AT"]) and n >= int(os.environ["MOCK_STOP_AT"]) else 0)
    sys.exit(3 if name in ("hermes-agent-sandbox.service", "hermes-cloudflare-proxy.service") else 0)
if a == ["restart", "hermes-control-center.service"]:
    p = pathlib.Path(os.environ["MOCK_RESTART_COUNT"])
    n = int(p.read_text()) + 1 if p.exists() else 1
    p.write_text(str(n))
    sys.exit(0)
sys.exit(9)
""")
        executable(self.bin / "systemd-run", """#!/usr/bin/env python3
import sys
if "unittest" in sys.argv:
    print("Ran 1 tests in 0.001s\\n\\nOK", file=sys.stderr)
""")
        for cmd in ("runuser", "chown", "sleep"):
            executable(self.bin / cmd, "#!/bin/sh\nexit 0\n")

    def _make_archive(self):
        repo = self.dir / "fixture"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for key, value in (("user.email", "test@example.invalid"), ("user.name", "Fixture")):
            subprocess.run(["git", "-C", str(repo), "config", key, value], check=True)
        for name in MODULES:
            folder = repo / name
            folder.mkdir()
            (folder / "fixture.txt").write_text(name)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        data = subprocess.check_output(["git", "-C", str(repo), "archive", "--format=tar.gz", sha])
        return sha, data

    def deploy(self, http="200:ok", sha=None, digest=None, data=None, stop_at=0, command=None):
        env = dict(os.environ, SSH_ORIGINAL_COMMAND=command or
                   ("deploy " + (sha or self.sha) + " " + (digest or self.digest)),
                   MOCK_HTTP=http, MOCK_HTTP_COUNT=str(self.dir / "curl-count"),
                   MOCK_SYSTEM_COUNT=str(self.dir / "system-count"),
                   MOCK_RESTART_COUNT=str(self.dir / "restart-count"),
                   MOCK_STOP_AT=str(stop_at), MOCK_CLOCK=str(self.clock))
        return subprocess.run(["bash", str(self.script)], input=self.data if data is None else data,
                              capture_output=True, env=env, timeout=30)

    def assert_rollback(self, result):
        self.assertNotEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.ui / "current").resolve(), self.ui / "releases" / "old")
        self.assertEqual((self.base / "ops_watch" / "old").read_text(), "old")
        self.assertFalse(self.state.exists(), "false successful state after rollback")
        self.assertFalse((self.base / "releases" / ("main-" + self.sha)).exists())

    def test_immediate_ready_and_exact_receipt(self):
        r = self.deploy()
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertIn(("PRODUCTION_DEPLOYED=" + self.sha).encode(), r.stdout)
        self.assertEqual(self.state.read_text().strip(), self.sha)
        receipt = (self.base / "releases" / ("main-" + self.sha) / ".deployment-receipt.txt").read_text()
        self.assertIn("SHA=" + self.sha + "\n", receipt)
        self.assertIn("ARCHIVE_SHA256=" + self.digest + "\n", receipt)

    def test_delayed_web_start_succeeds(self):
        r = self.deploy(http="ERR,ERR,200:ok")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertEqual((self.dir / "curl-count").read_text(), "3")

    def test_persistent_unavailable_and_deadline(self):
        r = self.deploy(http="ERR")
        self.assert_rollback(r)
        self.assertIn(b"readiness timed out", r.stderr)
        self.assertLessEqual(int(self.clock.read_text()), 21500)
        self.assertLess(int((self.dir / "curl-count").read_text()), 80)

    def test_401_403_500_and_empty_responses(self):
        for result_code in ("401", "403", "500", "200:empty", "200:space"):
            with self.subTest(code=result_code):
                self.assert_rollback(self.deploy(http=result_code))

    def test_stopped_service_fails(self):
        r = self.deploy(http="ERR,200:ok", stop_at=3)
        self.assert_rollback(r)
        self.assertIn(b"stopped during readiness", r.stderr)

    def test_duplicate_exact_sha_is_idempotent(self):
        self.assertEqual(self.deploy().returncode, 0)
        r = self.deploy(data=b"")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertIn(("ALREADY_DEPLOYED=" + self.sha).encode(), r.stdout)
        self.assertEqual((self.dir / "restart-count").read_text(), "1")

    def test_bad_sha_digest_archive(self):
        for case in ({"sha": "invalid"}, {"digest": "nothex"},
                     {"digest": "0" * 64}, {"data": b"badgzip",
                       "digest": hashlib.sha256(b"badgzip").hexdigest()}):
            with self.subTest(case=str(case)[:40]):
                self.assertNotEqual(self.deploy(**case).returncode, 0)
                self.assertFalse(self.state.exists())

    def test_unapproved_ssh_command_refused(self):
        r = self.deploy(command="id")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"invalid command", r.stderr)
        self.assertFalse(self.state.exists())

    def test_missing_credentials_fail_without_leak(self):
        # Mirrors the actual workflow credential gate. No production secrets used.
        workflow = (ROOT / ".github/workflows/production-deploy.yml").read_text()
        self.assertIn("Production SSH configuration missing", workflow)
        gate = """set -euo pipefail
[[ -n "$HERMES_DEPLOY_KEY" && -n "$HERMES_DEPLOY_TARGET" &&
   -n "$HERMES_DEPLOY_PORT" && -n "$HERMES_DEPLOY_KNOWN_HOSTS" ]] ||
   { echo "Production SSH configuration missing" >&2; exit 1; }
"""
        names = ("HERMES_DEPLOY_KEY", "HERMES_DEPLOY_TARGET",
                 "HERMES_DEPLOY_PORT", "HERMES_DEPLOY_KNOWN_HOSTS")
        for missing in names:
            env = dict(os.environ, **dict.fromkeys(names, "SECRET_NOT_FOR_LOGS"))
            env[missing] = ""
            r = subprocess.run(["bash", "-c", gate], capture_output=True, env=env)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn(b"SECRET_NOT_FOR_LOGS", r.stdout + r.stderr)
