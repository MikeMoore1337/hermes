"""Integration I2: no-vault, no-network, manual-review handoff checks."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from integrations.knowledge_handoff import DraftRefused, prepare_review_draft

REPO = "MikeMoore1337/hermes"


def handoff() -> dict:
    return {
        "schema_version": 1,
        "task": {"repository": REPO, "issue": 556},
        "workspace": {"alias": "hermes", "scope": "sandbox", "git_verified": False},
        "toolkit": {"profile": None, "selection": "NOT_VERIFIED"},
        "evidence": {
            "pr": None,
            "tests": {"state": "NOT_RUN", "ref": None},
            "ci": {"state": "NOT_VERIFIED", "ref": None, "sha": None},
            "production": {"state": "NOT_VERIFIED", "ref": None, "sha": None},
            "owner_acceptance": "PENDING",
        },
    }


def facts() -> dict:
    return {
        "problem": "При передаче задачи между чатами терялся контекст.",
        "decision": "Добавить ограниченный формат передачи статусов.",
        "rationale": "Независимая проверка GitHub остаётся обязательной.",
        "reviewed_on": "2026-10-24",
    }


class KnowledgeDraftTests(unittest.TestCase):
    def test_stays_draft_no_vault_or_network(self):
        result = prepare_review_draft(handoff(), facts())
        self.assertEqual(result["status"], "DRAFT_REVIEW_REQUIRED")
        self.assertFalse(result["canonical_vault_written"])
        self.assertFalse(result["remote_api_called"])
        self.assertFalse(result["source_claims_verified"])
        self.assertFalse(result["privacy_review_complete"])
        self.assertIn("Second Brain Web GUI", result["markdown"])
        self.assertIn("https://github.com/MikeMoore1337/hermes/issues/556", result["markdown"])

    def test_reference_is_self_reported_not_accepted_as_fact(self):
        data = handoff()
        data["evidence"]["pr"] = {
            "number": 559, "head_sha": "a" * 40,
            "ref": "https://github.com/MikeMoore1337/hermes/pull/559",
        }
        data["evidence"]["ci"] = {
            "state": "REPORTED_SUCCESS",
            "sha": "a" * 40,
            "ref": "https://github.com/MikeMoore1337/hermes/actions/runs/40092077776",
        }
        output = prepare_review_draft(data, facts())["markdown"]
        self.assertIn("REPORTED_SUCCESS (не проверено этим инструментом)", output)
        self.assertIn("ЧЕРНОВИК", output)
        self.assertIn("PR (заявленная ссылка)", output)

    def test_rejects_private_paths_markup_secrets_and_raw_data(self):
        for key, value in (
            ("problem", "ghp_" + "A" * 35),
            ("decision", "Bearer TOP_SECRET"),
            ("rationale", "password=VerySecret"),
            ("problem", "/root/private/vault"),
            ("decision", "C:\\Users\\Private"),
            ("rationale", "[phishing](https://evil.invalid)"),
            ("problem", "<script>hello</script>"),
            ("decision", "foo\nbar"),
            ("problem", "x" * 241),
        ):
            with self.subTest(key=key, value=value[:20]):
                item = facts()
                item[key] = value
                with self.assertRaises(DraftRefused):
                    prepare_review_draft(handoff(), item)

    def test_rejects_unknown_fields_invalid_date_and_untrusted_handoff(self):
        invalid = facts()
        invalid["another_field"] = "silent payload"
        with self.assertRaisesRegex(DraftRefused, "facts_fields_invalid"):
            prepare_review_draft(handoff(), invalid)
        for value in ("2026-02-30", "24.10.2026", "2026-10-24T15:00:00", True):
            invalid = facts()
            invalid["reviewed_on"] = value
            with self.assertRaisesRegex(DraftRefused, "review_date_invalid"):
                prepare_review_draft(handoff(), invalid)
        packet = handoff()
        packet["workspace"]["scope"] = "native-host"
        with self.assertRaisesRegex(DraftRefused, "handoff_invalid"):
            prepare_review_draft(packet, facts())

    def test_escaping_does_not_create_markdown_heading_or_link(self):
        obj = facts()
        obj["problem"] = "Ошибка *важная* (сравнить)."
        obj["decision"] = "# Исправлено."
        md = prepare_review_draft(handoff(), obj)["markdown"]
        self.assertIn("Ошибка \\*важная\\* \\(сравнить\\)", md)
        self.assertIn("\\# Исправлено.", md)

    def test_cli_returns_review_only_and_redacts_invalid_payload(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "prepare_knowledge_handoff.py"
        correct = json.dumps({"handoff": handoff(), "facts": facts()}, ensure_ascii=False).encode()
        result = subprocess.run(
            [sys.executable, str(script)], input=correct, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "DRAFT_REVIEW_REQUIRED")
        wrong = json.dumps({
            "handoff": handoff(),
            "facts": {**facts(), "decision": "token=VERY_PRIVATE_DATA"},
        }).encode()
        refused = subprocess.run(
            [sys.executable, str(script)], input=wrong, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False,
        )
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(json.loads(refused.stdout)["status"], "REFUSED")
        self.assertNotIn(b"VERY_PRIVATE_DATA", refused.stdout)


if __name__ == "__main__":
    unittest.main()
