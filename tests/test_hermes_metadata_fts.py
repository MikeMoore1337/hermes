"""H-30 synthetic metadata FTS5 positive, negative and lifecycle tests."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hermes_metadata_fts.core import (
    IndexDenied, SyntheticIndex, sample, MAX_RECORDS,
    MAX_RESULTS, RETENTION_DAYS, DAY,
)

NOW = 1792680000


class MetadataFTSContractTests(unittest.TestCase):
    def setUp(self):
        self.index = SyntheticIndex(now=NOW)

    def tearDown(self):
        self.index.close()

    def test_bilingual_search_and_cited_metadata(self):
        self.index.upsert(sample("H-demo-0001", "Проверка состояния агента", now=NOW))
        self.index.upsert(sample("H-demo-0002", "Agent recovery verified", now=NOW))
        ru = self.index.search("Проверка агента", project_id="hermes")
        en = self.index.search("agent recovery", project_id="hermes")
        self.assertEqual([x["task_id"] for x in ru], ["H-demo-0001"])
        self.assertEqual([x["task_id"] for x in en], ["H-demo-0002"])
        self.assertTrue(all(x["source_uri"].startswith(
            "https://github.com/MikeMoore1337/hermes/issues/")
            for x in ru + en))
        self.assertTrue(all(x["status"] == "verified" and
                            x["source_authenticated"] is False
                            for x in ru + en))

    def test_search_filters_project_kind_time_and_status(self):
        a = sample("H-demo-0003", "План релиза", now=NOW-10, kind="issue")
        b = sample("H-demo-0004", "План тестов", now=NOW-100, kind="pr")
        c = sample("H-demo-0005", "План статус неизвестен", now=NOW,
                   status="unknown", source_uri=None)
        for row in (a, b, c):
            self.index.upsert(row)
        self.assertEqual(len(self.index.search("План", project_id="hermes")), 2)
        self.assertEqual([x["kind"] for x in self.index.search(
            "План", project_id="hermes", kind="pr")], ["pr"])
        self.assertEqual(len(self.index.search("План", project_id="hermes",
                                              since=NOW-50)), 1)
        self.assertEqual(len(self.index.search("План", project_id="hermes",
                                              until=NOW-50)), 1)
        unknown = self.index.search("План", project_id="hermes", status="unknown")
        self.assertEqual([x["status"] for x in unknown], ["unknown"])
        self.assertIsNone(unknown[0]["source_uri"])
        with self.assertRaisesRegex(IndexDenied, "PROJECT_SCOPE_DENIED"):
            self.index.search("План", project_id="second-brain")

    def test_update_status_and_title_refresh_fts_dedup(self):
        a = sample("H-demo-0006", "Черновик задачи", now=NOW)
        self.assertEqual(self.index.upsert(a), "INSERTED")
        self.assertEqual(self.index.upsert(a), "UNCHANGED")
        self.assertEqual(self.index.count(), 1)
        newer = {**a, "revision": 2, "status": "stale", "title": "Архив задачи"}
        self.assertEqual(self.index.upsert(newer), "UPDATED")
        self.assertEqual(self.index.count(), 1)
        self.assertEqual(self.index.search("Черновик", project_id="hermes"), [])
        self.assertEqual(self.index.search("Архив", project_id="hermes"), [])
        res = self.index.search("Архив", project_id="hermes", status="stale")
        self.assertEqual(res[0]["revision"], 2)
        self.assertEqual(res[0]["status"], "stale")
        with self.assertRaisesRegex(IndexDenied, "REVISION_CONFLICT"):
            self.index.upsert({**a, "title": "Подмена"})
        with self.assertRaisesRegex(IndexDenied, "STALE_REVISION"):
            self.index.upsert(a)

    def test_remove_physically_deletes_fts_and_denies_replay(self):
        a = sample("H-demo-0007", "Удалённая задача", now=NOW)
        self.index.upsert(a)
        self.assertTrue(self.index.remove("H-demo-0007"))
        self.assertFalse(self.index.remove("H-demo-0007"))
        self.assertEqual(self.index.count(), 0)
        self.assertEqual(self.index.search("Удалённая", project_id="hermes"), [])
        with self.assertRaisesRegex(IndexDenied, "REVOKED_OR_DELETED"):
            self.index.upsert({**a, "revision": 999})

    def test_absent_or_revoked_source_cannot_prove_verified(self):
        a = sample("H-demo-0008", "Источник не найден", now=NOW, status="unknown")
        self.assertIsNone(a["source_uri"])
        with self.assertRaisesRegex(IndexDenied, "VERIFIED_WITHOUT_SOURCE"):
            self.index.upsert({**a, "status": "verified"})
        with self.assertRaisesRegex(IndexDenied, "REVOKED_INPUT"):
            self.index.upsert({**a, "revoked": True})
        self.index.upsert(a)
        self.assertEqual(self.index.search("Источник", project_id="hermes"), [])
        self.assertEqual(len(self.index.search(
            "Источник", project_id="hermes", status="unknown")), 1)

    def test_denies_secret_vault_paths_and_untrusted_fields(self):
        good = sample("H-demo-0009", "Проверка задачи", now=NOW)
        candidates = [
            {"title": "Bearer abcd"}, {"title": "ghp_abc"},
            {"title": "password=123"}, {"title": "vault contents"},
            {"title": "/home/operator/private"}, {"title": "C:\\Users\\one"},
            {"title": "sk-proj-secret"}, {"title": "../private/path"},
            {"scope": "second-brain:vault"}, {"project_id": "yfc"},
            {"source_uri": "file:///home/operator/.ssh/id_rsa"},
            {"source_uri": "https://evil.example/issues/9900001"},
            {"source_uri": "https://github.com/MikeMoore1337/hermes/issues/9900001?token=a"},
            {"kind": "vault"},
            {"private_body": "should never be indexed"},
        ]
        for changed in candidates:
            with self.subTest(changed=changed):
                with self.assertRaises(IndexDenied):
                    self.index.upsert({**good, **changed})
        self.assertEqual(self.index.count(), 0)

    def test_query_sql_fts_injection_path_traversal_and_caps(self):
        self.index.upsert(sample("H-demo-0010", "Сводка результатов", now=NOW))
        for q in ('"Сводка" OR *', "'; DROP TABLE tasks; --", "../vault",
                  "sk-proj-xyz", "  ", "*", "Сводка\nDROP"):
            with self.subTest(q=q):
                with self.assertRaises(IndexDenied):
                    self.index.search(q, project_id="hermes")
        self.assertEqual(len(self.index.search("Сводка", project_id="hermes")), 1)
        for cap in (0, MAX_RESULTS+1, True):
            with self.assertRaisesRegex(IndexDenied, "RESULT_CAP"):
                self.index.search("Сводка", project_id="hermes", limit=cap)

    def test_retention_and_no_future_rows(self):
        old = sample("H-demo-0011", "Очень старая задача", now=NOW)
        old["timestamp"] = NOW-(RETENTION_DAYS+1)*DAY
        with self.assertRaisesRegex(IndexDenied, "OUT_OF_RETENTION"):
            self.index.upsert(old)
        future = sample("H-demo-0012", "Ещё не произошло", now=NOW)
        future["timestamp"] = NOW+121
        with self.assertRaisesRegex(IndexDenied, "OUT_OF_RETENTION"):
            self.index.upsert(future)
        self.index.upsert(sample("H-demo-0013", "Запись вчера", now=NOW-1))
        self.assertEqual(self.index.count(), 1)

    def test_fixed_record_cap_and_no_disk_persistence(self):
        for i in range(MAX_RECORDS):
            self.index.upsert(sample(f"H-demo-{1000+i:04}", f"Task synthetic {i}",
                                     now=NOW))
        self.assertEqual(self.index.count(), MAX_RECORDS)
        with self.assertRaisesRegex(IndexDenied, "RECORD_CAP"):
            self.index.upsert(sample("H-demo-2000", "Overflow synthetic", now=NOW))
        info = self.index.limits()
        self.assertEqual(info["backend"], ":memory:")
        self.assertEqual(info["persistent_disk_bytes"], 0)
        self.assertGreater(info["sqlite_main_bytes"], 0)

    def test_source_kind_strict_and_untrusted_metadata_unverified(self):
        good = sample("H-demo-0014", "Pull request completion", now=NOW, kind="pr")
        good["source_uri"] = "https://github.com/MikeMoore1337/hermes/issues/9900014"
        with self.assertRaisesRegex(IndexDenied, "SOURCE_TYPE_DENIED"):
            self.index.upsert(good)
        good["source_uri"] = "https://github.com/MikeMoore1337/hermes/pull/9900014"
        self.index.upsert(good)
        self.assertFalse(self.index.search("Pull", project_id="hermes")[0][
            "source_authenticated"])

    def test_reject_corrupt_schema_types_and_bad_windows(self):
        record = sample("H-demo-0015", "Проверка отчёта", now=NOW)
        for patch_ in ({"revision": True}, {"timestamp": "today"},
                       {"revoked": 0}, {"schema_version": 2},
                       {"task_id": "../x"}, {"source_uri": []}):
            with self.subTest(patch=patch_):
                with self.assertRaises(IndexDenied):
                    self.index.upsert({**record, **patch_})
        with self.assertRaisesRegex(IndexDenied, "TIME_WINDOW_INVALID"):
            self.index.search("Проверка", project_id="hermes",
                              since=NOW, until=NOW-1)
        with self.assertRaisesRegex(IndexDenied, "STATUS_INVALID"):
            self.index.search("Проверка", project_id="hermes", status="success")

    def test_no_network_subprocess_or_real_files(self):
        with patch.object(socket.socket, "connect",
                          side_effect=AssertionError("network used")), \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("process used")):
            self.index.upsert(sample("H-demo-0016", "Локальный синтетический", now=NOW))
            actual = self.index.search("Локальный", project_id="hermes")
        self.assertEqual(len(actual), 1)
        self.assertTrue(all(x["scope"] == "synthetic:hermes" for x in actual))


if __name__ == "__main__":
    unittest.main()
