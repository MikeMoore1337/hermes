"""Synthetic context histories for Hermes #466.

All numbers, SHA values, policies and links are invented fixtures.
Not a model transcript, BRC session or real deployment.
"""
from __future__ import annotations

SHA = "a" * 40
STALE_SHA = "b" * 40
BRANCH = "test/context-804"
ISSUE = 804
URL_CI = "https://github.com/MikeMoore1337/hermes/actions/runs/8801"
URL_MERGE = "https://github.com/MikeMoore1337/hermes/pull/8802"
URL_DEPLOY = "https://github.com/MikeMoore1337/hermes/actions/runs/8803"

COMMON = [
    {"op": "issue", "number": ISSUE},
    {"op": "branch", "name": BRANCH, "sha": SHA},
    {"op": "policy", "max_extra_cost": 0,
     "forbidden": ["paid_api", "codex_cli", "remote_shell"]},
    {"op": "outstanding", "items": ["owner_review", "deploy_proof"]},
]
APPROVE = {"op": "owner", "source": "owner", "decision": "approved"}
DENY = {"op": "owner", "source": "owner", "decision": "denied"}
PASS = {"op": "ci", "result": "success", "sha": SHA, "proof": URL_CI}
FAIL = {"op": "ci", "result": "failure", "sha": SHA, "proof": URL_CI}
MERGE = {"op": "merge", "sha": SHA, "proof": URL_MERGE}
DEPLOY = {"op": "deploy", "result": "success", "sha": SHA,
          "deployed_sha": SHA, "proof": URL_DEPLOY}

# The expected answer is separately authored: not computed by the summarizer.
def _case(ident, category, events, *, owner="UNKNOWN", ci="UNKNOWN",
          merged="NO", deployed="NOT_VERIFIED", device="UNKNOWN",
          warning=(), outstanding=("owner_review", "deploy_proof")):
    expected = {
        "issue": ISSUE, "branch": BRANCH, "sha": SHA,
        "owner": owner, "ci": ci, "merged": merged, "deployed": deployed,
        "device": device, "max_extra_cost": 0,
        "forbidden": ["paid_api", "codex_cli", "remote_shell"],
        "outstanding": list(outstanding), "warnings": list(warning),
        "evidence": sorted({
            e["proof"] for e in events if "proof" in e and (
                e["op"] in ("ci", "merge", "deploy") and
                e.get("sha") == SHA)
        }),
    }
    return {"case_id": ident, "version": 1, "category": category,
            "events": events, "expected": expected}


CASES = [
    _case("cx-01-pending-release", "unverified_deployment",
          COMMON + [APPROVE, PASS, MERGE],
          owner="APPROVED", ci="PASS", merged="YES",
          outstanding=("deploy_proof",)),
    _case("cx-02-owner-revoked", "approval_revocation",
          COMMON + [APPROVE, PASS, MERGE, DENY],
          owner="DENIED", ci="PASS", merged="YES",
          outstanding=("deploy_proof",)),
    _case("cx-03-failed-ci", "false_positive_ci",
          COMMON + [APPROVE, FAIL, {"op": "claim", "kind": "ci", "value": "PASS"}],
          owner="APPROVED", ci="FAIL", warning=("UNVERIFIED_CI_CLAIM",),
          outstanding=("deploy_proof",)),
    _case("cx-04-device-interrupted", "interrupted_execution",
          COMMON + [APPROVE, {"op": "device", "state": "interrupted"}],
          owner="APPROVED", device="INTERRUPTED",
          outstanding=("deploy_proof",)),
    _case("cx-05-policy-budget", "scope_loss",
          COMMON + [{"op": "claim", "kind": "scope", "value": "remote_shell"}],
          warning=("UNVERIFIED_SCOPE_CLAIM",)),
    _case("cx-06-stale-ci-sha", "stale_evidence",
          COMMON + [APPROVE, {"op": "ci", "result": "success",
                               "sha": STALE_SHA, "proof": URL_CI}],
          owner="APPROVED", warning=("STALE_CI_SHA",),
          outstanding=("deploy_proof",)),
    _case("cx-07-contradictory-owner", "conflicting_evidence",
          COMMON + [APPROVE, DENY,
                    {"op": "claim", "kind": "owner", "value": "APPROVED"}],
          owner="DENIED", warning=("UNVERIFIED_OWNER_CLAIM",),
          outstanding=("deploy_proof",)),
    _case("cx-08-fake-deploy", "missing_deployment_receipt",
          COMMON + [APPROVE, PASS, MERGE,
                    {"op": "claim", "kind": "deploy", "value": "DEPLOYED"}],
          owner="APPROVED", ci="PASS", merged="YES",
          warning=("UNVERIFIED_DEPLOY_CLAIM",),
          outstanding=("deploy_proof",)),
    _case("cx-09-valid-deployment", "positive_verified_transition",
          COMMON + [APPROVE, PASS, MERGE, DEPLOY,
                    {"op": "outstanding", "items": []}],
          owner="APPROVED", ci="PASS", merged="YES", deployed="DEPLOYED",
          outstanding=()),
]
