"""Synthetic JATS snapshot tests. Never contact Europe PMC or YFC."""
from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest.mock import patch

from research_scout import yfc_primary_snapshot as snapshot


def xml(pmcid="12345678", doi="10.1234/example"):
    return ('<article><front><article-meta>'
             '<article-id pub-id-type="pmc">' + pmcid + '</article-id>'
             '<article-id pub-id-type="doi">' + doi + '</article-id>'
             '<permissions><license>CC BY</license></permissions>'
             '</article-meta></front><body><sec>'
             '<p>A full text paragraph for verifying protected snapshot identity.</p>'
             '<p>Second paragraph with methodological limitations and study context.</p>'
             '</sec></body></article>').encode()


class ProtectedSnapshotTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.folder = Path(d.name) / "private"
        self.folder.mkdir(mode=0o700)

    def test_snapshot_is_immutable_hash_bound_and_never_ready_to_publish(self):
        with patch.object(snapshot.gate, "fetch") as fetch:
            receipt = snapshot.stage("PMC12345678", "paperone", xml(),
                                     expected_doi="10.1234/example",
                                     directory=self.folder)
            fetch.assert_not_called()
        path = self.folder / "paperone.txt"
        self.assertEqual(receipt["status"], "STAGED_NEEDS_EDITORIAL_REVIEW")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         receipt["full_text_sha256"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(receipt["license_reuse_verified"])
        self.assertFalse(receipt["primary_claims_verified"])
        self.assertFalse(receipt["automatic_publication"])
        with self.assertRaisesRegex(snapshot.SnapshotHold, "SOURCE_ALREADY_STAGED"):
            snapshot.stage("PMC12345678", "paperone", xml(),
                           directory=self.folder)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         receipt["full_text_sha256"])

    def test_bad_doi_xml_or_source_id_cannot_stage(self):
        for label, pmcid, source_id, raw, doi in (
            ("doi", "PMC12345678", "p1", xml(), "10.1234/other"),
            ("body", "PMC12345678", "p2", xml().replace(b"<body>", b"<empty>").replace(b"</body>", b"</empty>"), None),
            ("id", "PMC12345678", "../escape", xml(), None),
            ("entity", "PMC12345678", "p3", b"<!DOCTYPE a [<!ENTITY e 'evil'>]>" + xml(), None),
        ):
            with self.subTest(label=label):
                with self.assertRaises(snapshot.SnapshotHold):
                    snapshot.stage(pmcid, source_id, raw,
                                   expected_doi=doi, directory=self.folder)
        self.assertEqual(list(self.folder.iterdir()), [])


    def test_standard_jats_public_dtd_snapshots_identical_body_only(self):
        public = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<!DOCTYPE article PUBLIC '
            b'"-//NLM//DTD JATS (Z39.96) Journal Publishing DTD v1.0 20120330//EN" '
            b'"JATS-journalpublishing1.dtd">'
        )
        original = xml()
        receipt = snapshot.stage("PMC12345678", "standardjats",
                                 public + original,
                                 expected_doi="10.1234/example",
                                 directory=self.folder)
        source = (self.folder / "standardjats.txt").read_bytes()
        self.assertNotIn(b"DOCTYPE", source)
        self.assertNotIn(b"JATS-journalpublishing", source)
        self.assertEqual(hashlib.sha256(source).hexdigest(), receipt["full_text_sha256"])
        self.assertEqual(receipt["status"], "STAGED_NEEDS_EDITORIAL_REVIEW")

    def test_internal_subset_without_entity_still_not_staged(self):
        header = (
            b'<!DOCTYPE article PUBLIC '
            b'"-//NLM//DTD JATS (Z39.96) Journal Publishing DTD v1.0 20120330//EN" '
            b'"JATS-journalpublishing1.dtd" [ ]>'
        )
        with self.assertRaisesRegex(snapshot.SnapshotHold, "FULLTEXT_IDENTITY_OR_STRUCTURE_HOLD"):
            snapshot.stage("PMC12345678", "unsafeheader",
                           header + xml(), directory=self.folder)
        self.assertFalse((self.folder / "unsafeheader.txt").exists())

    def test_untrusted_folder_and_existing_symlink_refused(self):
        self.folder.chmod(0o755)
        with self.assertRaisesRegex(snapshot.SnapshotHold, "SOURCE_DIRECTORY_UNTRUSTED"):
            snapshot.stage("PMC12345678", "paperone", xml(),
                           directory=self.folder)
        self.folder.chmod(0o700)
        (self.folder / "paperone.txt").symlink_to(self.folder / "target")
        with self.assertRaisesRegex(snapshot.SnapshotHold, "SOURCE_ALREADY_STAGED"):
            snapshot.stage("PMC12345678", "paperone", xml(),
                           directory=self.folder)

    def test_empty_body_and_oversized_paragraphs_fail(self):
        bad = xml().replace(b"A full text paragraph for verifying protected snapshot identity.", b"short").replace(
            b"Second paragraph with methodological limitations and study context.", b"short")
        with self.assertRaisesRegex(snapshot.SnapshotHold, "JATS_BODY_EMPTY"):
            snapshot.stage("PMC12345678", "paperone", bad,
                           directory=self.folder)


if __name__ == "__main__":
    unittest.main()
