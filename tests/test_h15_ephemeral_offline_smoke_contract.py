"""Static guard: #349 smoke must never use YFC VPS or provider credentials."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "h15-evals-offline-smoke.yml"
PROFILE = ROOT / "tests" / "fixtures" / "h15-eval-probe-seccomp.json"


class EphemeralOfflineSmokeContract(unittest.TestCase):
    def test_default_deny_syscalls_include_no_network_or_process_spawning(self):
        cfg = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.assertEqual("SCMP_ACT_ERRNO", cfg["defaultAction"])
        self.assertEqual(1, cfg["defaultErrnoRet"])
        names = set()
        for entry in cfg["syscalls"]:
            self.assertEqual("SCMP_ACT_ALLOW", entry["action"])
            names.update(entry["names"])
        self.assertNotIn("socketcall", names)
        self.assertIn("execve", names)
        self.assertIn("fstatfs", names)  # Docker init needs this.
        inet_families = (2, 10)  # AF_INET, AF_INET6
        inet_allowed = []
        for rule in cfg["syscalls"]:
            if "socket" not in rule["names"]:
                continue
            self.assertEqual(1, len(rule.get("args", [])))
            arg = rule["args"][0]
            for family in inet_families:
                if (arg["op"] == "SCMP_CMP_EQ" and family == arg["value"] or
                        arg["op"] == "SCMP_CMP_LT" and family < arg["value"]):
                    inet_allowed.append(family)
        self.assertEqual([], inet_allowed)

    def test_github_hosted_only_and_no_prod_or_model_auth(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        for expected in (
            "runs-on: ubuntu-24.04", 'test "$EXEC_ENV" = "github-hosted"',
            "persist-credentials: false", "--network none",
            "--cap-drop ALL", "--read-only", "--user 10001:10001",
            "--memory 768m", "--cpus 0.45", "--pids-limit 32",
            "eval_lane.isolation_probe", "NO_MODEL_REQUESTS=TRUE",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)
        for unsafe in ("secrets.", "self-hosted", "ssh ", "kubectl",
                       "codex exec", "claude -p", "docker.sock",
                       "hermes-main-deploy", "deploy_production",
                       "vps1789630393", "vps1777112993"):
            if unsafe == "self-hosted":
                self.assertNotIn("runs-on: self-hosted", text)
            else:
                self.assertNotIn(unsafe, text)
        self.assertNotIn("pull_request_target:", text)
        self.assertNotIn("push:", text)


if __name__ == "__main__":
    unittest.main()
