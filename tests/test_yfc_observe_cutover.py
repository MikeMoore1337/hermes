"""Old YFC native snapshots must not be accepted after exporter cutover."""
from datetime import UTC, datetime
import unittest

from control_center import github_projects_view as view
from qa_advisor import public_project_observe as source


class YfcObserveCutoverTests(unittest.TestCase):
    def test_old_source_id_is_refused_by_both_validators(self):
        feed = source.poll(now=datetime(2026, 11, 26, tzinfo=UTC),
                           reader=lambda path, token, timeout: {"workflow_runs": []})
        feed["sources"]["yfc"]["workflow_id"] = 259698256
        with self.assertRaises(source.PublicObserveError):
            source.validate(feed)
        with self.assertRaises(view.ProjectFeedRefused):
            view.validate(feed)


if __name__ == "__main__":
    unittest.main()
