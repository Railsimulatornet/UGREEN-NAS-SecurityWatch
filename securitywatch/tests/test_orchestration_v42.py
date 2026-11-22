"""Regressionen aus dem ersten echten NAS-Bericht, ohne Produktionszugriff."""
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import securitywatch as sw
from securitywatch_common import ConfigurationError
import test_orchestration as original_tests
from test_lifecycle import CID, OLD, NEW


class ReportDirectoryTests(unittest.TestCase):
    def test_collision_waits_for_real_next_second_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            now = datetime.fromisoformat("2026-11-22T17:12:20+01:00")
            previous = root / "2026-11-22_17-12-20"
            previous.mkdir()
            (previous / "mail.txt").write_text("Vorheriger Bericht")
            with patch.object(sw, "berlin_now", side_effect=[now, now + timedelta(seconds=1)]), \
                 patch.object(sw.time, "sleep"):
                result = sw.create_report_directory(root)
            self.assertEqual(result.name, "2026-11-22_17-12-21")
            self.assertEqual((previous / "mail.txt").read_text(), "Vorheriger Bericht")
            self.assertRegex(result.name, r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")

    def test_clock_collision_has_bounded_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "2026-11-22_17-12-20").mkdir()
            with patch.object(sw, "berlin_now", return_value=datetime(2026, 11, 22, 17, 12, 20)), \
                 patch.object(sw.time, "sleep") as wait:
                with self.assertRaises(ConfigurationError):
                    sw.create_report_directory(root)
            self.assertEqual(wait.call_count, 100)
            self.assertEqual(len(list(root.iterdir())), 1)


class CoverageAndRetryTests(unittest.TestCase):
    setUp = original_tests.OrchestrationTests.setUp
    app = original_tests.OrchestrationTests.app

    def disable_baseline_health(self):
        self.docker.containers[CID]["Config"].pop("Healthcheck")
        self.docker.containers[CID]["State"].pop("Health")

    def build_count(self):
        return sum(args[0] == "compose" and "build" in args for args, _, _ in self.docker.calls)

    def test_report_only_explains_missing_health_without_building(self):
        self.disable_baseline_health()
        app = self.app(["--report-only"])
        self.assertEqual(app.run(), 0)
        item = app.status["maintenance"]["items"][0]
        self.assertEqual(item["kind"], "local")
        self.assertTrue(item["build_allowed"])
        self.assertFalse(item["eligible"])
        self.assertIn("Zustandsprüfung", item["reason"])
        self.assertEqual(self.build_count(), 0)

    def test_preparation_reports_running_old_image_and_candidate_separately(self):
        self.disable_baseline_health()
        app = self.app()
        self.assertEqual(app.run(), 0)
        item = app.status["image_outcomes"][0]
        self.assertEqual(item["status"], "prepared_only")
        self.assertEqual(item["actual_image_id"], OLD)
        self.assertEqual(item["candidate_image_id"], NEW)
        self.assertEqual(item["candidate"]["total"], 0)
        self.assertEqual(item["after"]["total"], 1)
        self.assertEqual(item["resolved"], 0)
        self.assertEqual(item["verification_status"], "not_run")
        self.assertFalse(any(event.get("status") == "source_fix_needed" for event in app.status["events"]))
        self.assertFalse(self.docker.up_calls)

    def test_successful_replacement_does_not_immediately_rebuild_again(self):
        first = self.app()
        self.assertEqual(first.run(), 0)
        count = self.build_count()
        second = self.app()
        self.assertEqual(second.run(), 0)
        self.assertEqual(self.build_count(), count)
        self.assertEqual(second.status["image_outcomes"], [])

    def test_repaired_build_retries_after_one_day_instead_of_waiting_six(self):
        self.docker.build_failure = True
        first = self.app()
        with patch.object(sw.time, "time", return_value=2000000000):
            self.assertEqual(first.run(), 2)
        self.docker.build_failure = False
        second = self.app()
        with patch.object(sw.time, "time", return_value=2000000000 + 25 * 3600):
            self.assertEqual(second.run(), 0)
        self.assertEqual(self.build_count(), 2)
        self.assertEqual(second.status["image_outcomes"][0]["deployment_status"], "applied")

    def test_changed_build_inputs_bypass_preparation_cooldown(self):
        self.disable_baseline_health()
        (self.project / "Dockerfile").write_text("FROM example:old\n")
        first = self.app()
        self.assertEqual(first.run(), 0)
        (self.project / "Dockerfile").write_text("FROM example:patched\n")
        second = self.app()
        self.assertEqual(second.run(), 0)
        self.assertEqual(self.build_count(), 2)
        self.assertFalse(self.docker.up_calls)

    def test_report_only_applies_report_retention_but_respects_disable_switch(self):
        result = {"days": 30, "keep_last": 10, "removed": 2, "errors": 0}
        app = self.app(["--report-only"])
        with patch("securitywatch_housekeeping.cleanup_reports", return_value=result) as cleanup:
            self.assertEqual(app.run(), 0)
        cleanup.assert_called_once()
        self.assertEqual(app.status["report_retention"]["removed"], 2)
        second = self.app(["--report-only"])
        second.env["REPORT_CLEANUP_ENABLED"] = "0"
        with patch("securitywatch_housekeeping.cleanup_reports") as cleanup:
            self.assertEqual(second.run(), 0)
        cleanup.assert_not_called()
        self.assertEqual(second.status["report_retention"]["status"], "disabled")


if __name__ == "__main__":
    unittest.main()
