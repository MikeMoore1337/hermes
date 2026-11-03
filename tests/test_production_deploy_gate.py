"""Real production gate shell under offline simulated GitHub Actions events.

No real GitHub calls, SSH, secrets or VPS operations. The exact YAML run
block is executed in bash with a mocked gh executable and normal jq.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=ROOT/".github/workflows/production-deploy.yml"
SHA="a"*40
OTHER="b"*40

def gate_shell():
    text=WORKFLOW.read_text(encoding="utf-8")
    marker="      - name: Verify current main and both required SHA-scoped checks"
    first=text.index(marker)
    begin=text.index("        run: |\n",first)+len("        run: |\n")
    end=text.index("\n      - name: Check out the exact approved main SHA",begin)
    body=text[begin:end].splitlines()
    if not body or any(not line.startswith("          ") for line in body if line):
        raise ValueError("Gate structure changed; refuse to mock wrong action")
    return "\n".join(line[10:] if line else "" for line in body)+"\n"

MOCK_GH=r"""#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
url=args[1] if len(args)>1 else ""
if args[0]!="api":
    sys.exit(2)
if "/branches/main" in url:
    print(os.environ["MOCK_MAIN_SHA"])
elif "/actions/runs?" in url:
    print(json.dumps({"workflow_runs":[
        {"name":"Hermes repository checks","conclusion":os.environ["MOCK_QUALITY"]},
        {"name":"Hermes Control Center UI","conclusion":os.environ["MOCK_UI"]}
    ]}))
else:
    sys.exit(3)
"""


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"),
                     "bash and jq must be available")
class SourceDeployGateTests(unittest.TestCase):
    def run_gate(self, *, event="workflow_dispatch", main=SHA, quality="success",
                 ui="pending"):
        with TemporaryDirectory(prefix="h454-source-gate-") as dirname:
            base=Path(dirname)
            binpath=base/"bin"
            binpath.mkdir()
            gh=binpath/"gh"
            gh.write_text(MOCK_GH)
            gh.chmod(0o755)
            sleeper=binpath/"sleep"
            sleeper.write_text("#!/bin/sh\nexit 0\n")
            sleeper.chmod(0o755)
            output=base/"output"
            output.touch()
            env=dict(os.environ,PATH=str(binpath)+os.pathsep+os.environ["PATH"],
                     GITHUB_REPOSITORY="MikeMoore1337/hermes",
                     TARGET_SHA=SHA,
                     GITHUB_EVENT_NAME=event,
                     GITHUB_OUTPUT=str(output),
                     MOCK_MAIN_SHA=main,
                     MOCK_QUALITY=quality,
                     MOCK_UI=ui)
            p=subprocess.run(["bash","-e","-o","pipefail","-c",gate_shell()],
                             capture_output=True,text=True,timeout=15,env=env)
            return p.returncode,p.stdout,p.stderr,output.read_text()

    def test_bash_syntax_of_real_gate(self):
        p=subprocess.run(["bash","-n"],input=gate_shell(),
                         capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)

    def test_pending_ui_refuses_manual_release(self):
        code,stdout,stderr,out=self.run_gate()
        self.assertNotEqual(code,0)
        self.assertNotIn("deploy=true",out)
        self.assertIn("not green",stderr)

    def test_completed_ui_enables_exact_sha_deploy(self):
        code,stdout,stderr,out=self.run_gate(ui="success")
        self.assertEqual(code,0,stderr)
        self.assertIn("deploy=true",out)
        self.assertIn("Exact SHA CI green",stdout)

    def test_manual_dispatch_cannot_bypass_pending_ui(self):
        code,stdout,stderr,out=self.run_gate(event="workflow_dispatch")
        self.assertNotEqual(code,0)
        self.assertNotIn("deploy=true",out)
        self.assertIn("not green",stderr)

    def test_failed_quality_cannot_deploy(self):
        code,stdout,stderr,out=self.run_gate(quality="failure",ui="success")
        self.assertNotEqual(code,0)
        self.assertNotIn("deploy=true",out)

    def test_failed_ui_cannot_deploy(self):
        code,stdout,stderr,out=self.run_gate(ui="failure")
        self.assertNotEqual(code,0)
        self.assertNotIn("deploy=true",out)

    def test_superseded_main_does_not_deploy(self):
        code,stdout,stderr,out=self.run_gate(main=OTHER,ui="success")
        self.assertEqual(code,0,stderr)
        self.assertIn("deploy=false",out)
        self.assertNotIn("deploy=true",out)

    def test_manual_only_and_main_always_runs_ui_checks(self):
        workflow=WORKFLOW.read_text()
        self.assertIn("if: github.event_name == 'workflow_dispatch'",workflow)
        self.assertNotIn('workflow_run:',workflow)
        ui=(ROOT/".github/workflows/control-center-ui.yml").read_text()
        main_push=ui.split('  push:\n',1)[1].split('\npermissions:',1)[0]
        self.assertIn('branches: [main]',main_push)
        self.assertNotIn('paths:',main_push)
        self.assertIn('StrictHostKeyChecking=yes',workflow)
        self.assertNotIn('StrictHostKeyChecking=no',workflow)
        self.assertNotIn('actions: write',workflow)
        self.assertNotIn('cancel-in-progress: true',workflow)


if __name__=="__main__":
    unittest.main()
