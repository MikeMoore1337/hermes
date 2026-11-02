"""#732: root-only public project feed contract survives split release installs."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from control_center import github_projects_view as view
from qa_advisor import public_project_observe as source

NOW = datetime(2026, 11, 2, 10, 30, tzinfo=UTC)


class PublicProjectsViewTests(unittest.TestCase):
    def setUp(self):
        self.source = dict(source.PROJECTS)
        self.view = dict(view.PROJECTS)
        updated={key: (repo, 8111+n) for n,(key,(repo,_)) in enumerate(self.source.items())}
        source.PROJECTS.update(updated)
        view.PROJECTS.update(updated)
        self.addCleanup(lambda: (source.PROJECTS.clear(),source.PROJECTS.update(self.source),
                                 view.PROJECTS.clear(),view.PROJECTS.update(self.view)))

    def sample(self):
        def reader(path, *, token, timeout):
            for key,(repo,wid) in source.PROJECTS.items():
                if f"/repos/{repo}/" in path:
                    ident=1201+list(source.PROJECTS).index(key)
                    return {"workflow_runs":[{
                        "repository":{"full_name":repo},
                        "workflow_id":wid,"id":ident,
                        "event":"issues","status":"completed","conclusion":"success",
                        "name":f"observe:issues:opened:{ident}:none:{ident}",
                        "display_title":f"observe:issues:opened:{ident}:none:{ident}",
                        "created_at":(NOW-timedelta(minutes=2)).isoformat(),
                        "body":"EXCLUDED_TEXT_EXAMPLE",
                    }]}
            raise AssertionError("unallowlisted GitHub route")
        return source.poll(now=NOW,reader=reader)

    def test_cross_package_safe_contract_and_expiry(self):
        report=self.sample()
        self.assertEqual(view.validate(report),report)
        self.assertTrue(view.fresh(report,now=NOW))
        self.assertFalse(view.fresh(report,now=NOW+timedelta(minutes=46)))
        self.assertFalse(view.fresh(report,now=NOW-timedelta(minutes=3)))
        self.assertNotIn("EXCLUDED_TEXT_EXAMPLE",json.dumps(report))

    def test_wrong_repo_source_id_approval_or_event_refused(self):
        report=self.sample()
        original=report["sources"]["toolkit"]
        for other in (
            {**report,"owner_approval":"GRANTED"},
            {**report,"execution_authorized":True},
            {**report,"sources":{**report["sources"],"toolkit":{**original,"repo":"other/foreign"}}},
            {**report,"sources":{**report["sources"],"toolkit":{**original,"workflow_id":True}}},
            {**report,"sources":{**report["sources"],"toolkit":{**original,
                    "events":[{**original["events"][0],"candidate":"EXECUTE_AGENT"}]}}},
            {**report,"sources":{**report["sources"],"toolkit":{**original,
                    "events":[original["events"][0],original["events"][0]]}}},
        ):
            with self.subTest(changed=list(other)),self.assertRaises(view.ProjectFeedRefused):
                view.validate(other)

    def test_root_file_permissions_reject_symlink_and_mode(self):
        report=self.sample()
        with tempfile.TemporaryDirectory() as root:
            directory=Path(root)
            directory.chmod(0o700)
            path=directory/"public-feed.json"
            self.assertIsNone(view.load(path))
            path.write_text(json.dumps(report),encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(view.load(path),report)
            path.chmod(0o644)
            with self.assertRaises(view.ProjectFeedRefused):
                view.load(path)
            path.unlink()
            target=directory/"target.json"
            target.write_text(json.dumps(report),encoding="utf-8")
            path.symlink_to(target)
            with self.assertRaises(view.ProjectFeedRefused):
                view.load(path)
            path.unlink()
            directory.chmod(0o755)
            with self.assertRaises(view.ProjectFeedRefused):
                view.load(path)

    def test_control_center_does_not_import_public_network_reader(self):
        import inspect
        from control_center import operator_inbox, snapshot
        for src in (view,operator_inbox,snapshot):
            code=inspect.getsource(src)
            self.assertNotRegex(code, r"(?m)^\s*(?:from|import)\s+qa_advisor\b")


if __name__=="__main__":
    unittest.main()
