"""#732: existing Operator Inbox consumes project observations without UI changes."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import unittest

from control_center import github_projects_view as view
from control_center.operator_inbox import assemble
from control_center.snapshot import UNITS
from qa_advisor import public_project_observe as poller

NOW=datetime(2026,11,2,10,30,tzinfo=UTC)


def overview():
    return {"schema":1,"mode":"read_only","generated_at":NOW.isoformat(),
            "services":[{"id":key,"name":label,"unit":unit,"kind":kind,
                         "state":"blocked" if key=="agent" else "active"}
                        for key,label,unit,kind in UNITS]}


class PublicProjectInboxTests(unittest.TestCase):
    def setUp(self):
        old_poll=dict(poller.PROJECTS)
        old_view=dict(view.PROJECTS)
        new={key:(repo,8878+n if key!="second_brain" else 0)
             for n,(key,(repo,_)) in enumerate(old_poll.items())}
        poller.PROJECTS.update(new)
        view.PROJECTS.update(new)
        self.addCleanup(lambda: (poller.PROJECTS.clear(),poller.PROJECTS.update(old_poll),
                                 view.PROJECTS.clear(),view.PROJECTS.update(old_view)))

    def sample(self):
        def reader(path, *, token, timeout):
            for key,(repo,wf) in poller.PROJECTS.items():
                if wf and f"/repos/{repo}/" in path:
                    number=521 if key=="toolkit" else 1366
                    run_id=1000 if key=="toolkit" else 1001
                    return {"workflow_runs":[{
                        "id":run_id,"workflow_id":wf,
                        "repository":{"full_name":repo},
                        "name":f"observe:issues:opened:{number}:none:{run_id}",
                        "display_title":f"observe:issues:opened:{number}:none:{run_id}",
                        "event":"issues","status":"completed","conclusion":"success",
                        "created_at":(NOW-timedelta(minutes=2)).isoformat(),
                        "title":"SECRET_CONTENT_DO_NOT_EXPOSE",
                    }]}
            raise AssertionError("Unexpected API")
        return poller.poll(now=NOW,reader=reader)

    def test_enabled_projects_and_disabled_second_brain(self):
        data=overview()
        data["github_project_feed"]=self.sample()
        report=assemble(data,None,now=NOW)
        self.assertFalse(report["actions_enabled"])
        self.assertEqual(report["sources"]["gh_toolkit"]["status"],"PARTIAL")
        self.assertEqual(report["sources"]["gh_yfc"]["status"],"PARTIAL")
        self.assertEqual(report["sources"]["gh_second_brain"]["status"],"NOT_AVAILABLE")
        self.assertEqual(report["summary"]["source_count"],10)
        selected=[e for e in report["events"] if e["source"].startswith("gh_")]
        self.assertEqual(len(selected),2)
        self.assertEqual({e["source"] for e in selected},{"gh_toolkit","gh_yfc"})
        self.assertTrue(all(e["scope"]=="owner_read_only" and
                            e["evidence_link"] is None for e in selected))
        self.assertNotIn("SECRET_CONTENT_DO_NOT_EXPOSE",json.dumps(report))
        self.assertNotIn("run arbitrary",json.dumps(report))

    def test_stale_snapshot_hides_old_actions(self):
        data=overview()
        data["github_project_feed"]=self.sample()
        after=assemble(data,None,now=NOW+timedelta(minutes=50))
        self.assertEqual(after["sources"]["gh_toolkit"]["status"],"STALE")
        self.assertEqual(after["sources"]["gh_yfc"]["status"],"STALE")
        self.assertEqual(after["sources"]["gh_second_brain"]["status"],"NOT_AVAILABLE")
        self.assertFalse(any(e["event_id"]=="gh_toolkit:issues:521" for e in after["events"]))
        self.assertTrue(any(e["event_id"]=="gh_toolkit:stale" for e in after["events"]))
        self.assertFalse(after["actions_enabled"])

    def test_tampered_scope_is_not_project_execution_permission(self):
        data=overview()
        modified=self.sample()
        modified["owner_approval"]="GRANTED"
        data["github_project_feed"]=modified
        reply=assemble(data,None,now=NOW)
        self.assertEqual(reply["sources"]["gh_toolkit"]["status"],"NOT_AVAILABLE")
        self.assertEqual(reply["sources"]["gh_yfc"]["status"],"NOT_AVAILABLE")
        self.assertFalse(any(e["source"]=="gh_toolkit" for e in reply["events"]))


if __name__=="__main__":
    unittest.main()
