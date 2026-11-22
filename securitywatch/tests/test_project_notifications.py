"""Completed one-time updates reach mail once; security counts use the active scan."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import securitywatch as sw
import securitywatch_notifications as notices
from securitywatch_lifecycle import LifecycleEngine
from securitywatch_project_updates import ProjectUpdater
from test_lifecycle import Clock, OLD, NEW, OTHER, scan
from test_orchestration import SimulatedScanner
from test_project_updates import MigrationDocker


class ReceiptScanner(SimulatedScanner):
    def __init__(self, run_dir, documents):
        super().__init__(run_dir, documents)
        self.calls = []

    def scan_image(self, iid):
        self.calls.append(iid)
        return super().scan_image(iid)


class ProjectNotificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sw_project_mail_")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        project = self.root / "project"
        project.mkdir()
        self.docker = MigrationDocker(project)
        self.clock = Clock()
        self.state = self.root / "state"
        # Produce the receipt through the real migration code, not a hand-written schema.
        engine = LifecycleEngine(self.state, self.docker, lambda iid: scan(iid),
                                 options={"health_timeout": 10, "health_interval": 1, "stable_seconds": 0},
                                 clock=self.clock, sleep=self.clock.sleep)
        updater = ProjectUpdater(engine, lambda ref: ref.rsplit(":", 1)[0] + "@sha256:" + "c" * 64)
        result = updater.apply("schulmanager")
        self.assertEqual(result["status"], "updated")
        self.transaction_id = result["transaction_id"]
        self.journal = self.state / "transactions" / (self.transaction_id + ".json")
        self.env_path = self.root / ".env"
        self.env_path.write_text("TRIVY_SCAN_FILESYSTEM=0\nSTATE_DIR=" + str(self.state) +
                                 "\nREPORT_DIR=" + str(self.root / "reports") + "\nCACHE_DIR=" + str(self.root / "cache") +
                                 "\nIMAGE_UPDATE_VERIFY_STABLE_SECONDS=0\nREPORT_RETENTION_DAYS=0\n")
        self.sources = {
            OLD: scan(OLD, [("CVE-now-known", "old-package", "HIGH", "1")]),
            NEW: scan(NEW), OTHER: scan(OTHER, [("CVE-other", "other", "CRITICAL", "1")]),
        }

    def app(self, flags=()):
        args = sw.arguments(["--no-mail", "--report-only", *flags])
        env = sw.config(ROOT, self.env_path, args)
        def runner(arguments, **kwargs):
            if arguments[:2] == ["container", "inspect"]:
                arguments = ["inspect", "--type", "container", *arguments[2:]]
            return self.docker(arguments, **kwargs)
        def factory(state, runner, scanner, *, options, emit):
            return LifecycleEngine(state, runner, scanner, options=options, emit=emit,
                                   clock=self.clock, sleep=self.clock.sleep)
        app = sw.SecurityWatch(ROOT, self.env_path, env, args, runner, factory)
        app.scanner = ReceiptScanner(app.run_dir, copy.deepcopy(self.sources))
        app.say = lambda _line: None
        app.github = lambda: None
        app.render_and_mail = lambda: app.status.update(delivery={"status": "disabled"})
        return app

    def delivered(self, app, result, returncode=0):
        app.args.no_mail = False
        real_run = subprocess.run
        def process(command, **kwargs):
            if "--result-json" in command:
                Path(command[command.index("--result-json") + 1]).write_text(json.dumps({"status": result}))
                return subprocess.CompletedProcess(command, returncode, "", "")
            return real_run(command, **kwargs)
        with patch.object(sw.subprocess, "run", side_effect=process):
            sw.SecurityWatch.render_and_mail(app)

    def test_report_only_rescans_old_image_using_current_database_and_reports_real_after(self):
        app = self.app()
        self.assertEqual(app.run(), 0)
        row, = app.status["image_outcomes"]
        self.assertTrue(row["historical_update"])
        self.assertEqual(row["status"], "update_applied")
        self.assertEqual(row["origin"], "registry")
        self.assertEqual(row["build_status"], "not_attempted")
        self.assertEqual(row["old_image_id"], OLD)
        self.assertEqual(row["actual_image_id"], NEW)
        self.assertEqual(row["before"]["high"], 1)  # migration itself saw zero; current database sees one
        self.assertEqual(row["after"]["total"], 0)
        self.assertEqual(row["resolved"], 1)
        self.assertEqual(app.scanner.calls, [NEW, OLD])
        self.assertEqual(len(app.status["scans"]["images"]["items"]), 1)
        self.assertEqual(len(list(app.run_dir.glob("image_*.json"))), 1)  # old findings never inflate current totals
        self.assertIn("Bereits am", row["message"])
        self.assertNotIn("private-test-value", json.dumps(app.status))
        self.assertFalse((self.state / "project-notifications.json").exists())

    def test_missing_old_image_is_unknown_not_zero_and_current_counts_remain_available(self):
        self.sources.pop(OLD)
        app = self.app()
        app.run()
        row, = app.status["image_outcomes"]
        self.assertNotIn("before", row)
        self.assertNotIn("resolved", row)
        self.assertEqual(row["after"]["total"], 0)
        self.assertIn("Vergleich bleibt unbekannt", row["message"])

    def test_another_live_image_is_historical_notice_without_false_regression(self):
        current = next(iter(self.docker.containers.values()))
        current["Image"] = OTHER
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [], "RepoDigests": []}
        app = self.app()
        app.run()
        row, = app.status["image_outcomes"]
        self.assertTrue(row["historical_only"])
        self.assertIsNone(row["actual_image_id"])
        self.assertNotIn("after", row)
        self.assertNotIn("before", row)
        self.assertFalse(any(event["status"] == "final_state_changed" for event in app.status["events"]))
        self.assertEqual(app.scanner.calls, [OTHER])

    def test_disabled_image_scan_keeps_only_historical_fact_without_comparison(self):
        app = self.app(["--no-images"])
        app.run()
        row, = app.status["image_outcomes"]
        self.assertTrue(row["historical_only"])
        self.assertNotIn("after", row)
        self.assertEqual(row["actual_image_id"], NEW)
        self.assertEqual(app.scanner.calls, [])

    def test_failed_current_scan_does_not_turn_old_success_into_current_safe_result(self):
        app = self.app()
        app.scanner.fail.add(NEW)
        app.run()
        row, = app.status["image_outcomes"]
        self.assertTrue(row["historical_only"])
        self.assertNotIn("after", row)
        self.assertNotIn(OLD, app.scanner.calls)

    def test_existing_current_run_update_keeps_one_outcome_and_mentions_earlier_change(self):
        app = self.app()
        target = self.docker.target
        app.status["image_outcomes"].append({
            "image": target.new_ref, "targets": [{"project": target.project, "service": target.service}],
            "services": [target.name], "build_status": "not_attempted", "deployment_status": "applied",
            "verification_status": "ok", "old_image_id": OLD, "actual_image_id": NEW})
        app.run()
        self.assertEqual(len(app.status["image_outcomes"]), 1)
        self.assertIn("Bereits am", app.status["image_outcomes"][0]["earlier_updates"][0])
        self.assertEqual(len(app.status["project_updates"]), 1)

    def test_deferred_current_attempt_does_not_hide_attached_earlier_update(self):
        app = self.app()
        target = self.docker.target
        app.status["image_outcomes"].append({
            "image": target.new_ref, "targets": [{"project": target.project, "service": target.service}],
            "services": [target.name], "build_status": "not_attempted", "deployment_status": "kept_previous",
            "verification_status": "not_run", "old_image_id": NEW, "actual_image_id": NEW})
        app.run()
        app.import_project_notifications(list(self.docker.containers.values()))
        self.assertEqual(len(app.status["project_updates"]), 1)
        self.delivered(app, "skipped")
        model = notices.build_model(json.loads((app.run_dir / "summary.json").read_text()))
        self.assertEqual(len(model["mail_outcomes"]), 1)
        self.assertEqual(model["update_count"], 0)
        self.assertIn("Bereits am", notices.render_text(model))

    def test_same_image_channel_switch_does_not_claim_repairs(self):
        record = json.loads(self.journal.read_text())
        record["old_image_id"] = NEW
        record["services"][0]["image_id"] = NEW
        self.journal.write_text(json.dumps(record))
        app = self.app()
        app.run()
        row, = app.status["image_outcomes"]
        self.assertEqual(row["actual_image_id"], NEW)
        self.assertEqual(row["before"], row["after"])
        self.assertEqual(row["resolved"], 0)
        self.assertTrue(row["historical_update"])

    def test_sent_delivery_acknowledges_receipt_and_next_run_does_not_repeat(self):
        app = self.app()
        app.run()
        self.delivered(app, "sent")
        ledger = json.loads((self.state / "project-notifications.json").read_text())
        self.assertIn(self.transaction_id, ledger["sent"])
        next_app = self.app()
        next_app.run()
        self.assertEqual(next_app.status["image_outcomes"], [])
        self.assertEqual(next_app.scanner.calls, [NEW])

    def test_failed_skipped_and_inconsistent_delivery_do_not_acknowledge(self):
        app = self.app()
        app.run()
        for result, returncode in (("failed", 1), ("skipped", 0), ("sent", 1)):
            with self.subTest(status=result, returncode=returncode):
                self.delivered(app, result, returncode)
                self.assertFalse((self.state / "project-notifications.json").exists())
                self.assertIn(self.transaction_id, app._project_receipts_to_ack)
        self.delivered(app, "sent")
        self.assertTrue((self.state / "project-notifications.json").exists())

    def test_unfinished_or_non_allowlisted_receipt_never_claims_update(self):
        record = json.loads(self.journal.read_text())
        for change in ({"phase": "candidate_ready"}, {"migration": {**record["migration"], "to": "unrelated:latest"}}):
            with self.subTest(change=change):
                self.journal.write_text(json.dumps({**record, **change}))
                app = self.app()
                app.prepare_project_notifications()
                app.import_project_notifications(list(self.docker.containers.values()))
                self.assertEqual(app.status["image_outcomes"], [])
                self.assertEqual(app._project_receipts_to_ack, {})

    def test_symlink_receipt_and_symlink_ledger_are_not_followed(self):
        original = self.journal.read_bytes()
        foreign = self.root / "outside.json"
        foreign.write_bytes(original)
        self.journal.unlink()
        self.journal.symlink_to(foreign)
        app = self.app()
        app.prepare_project_notifications()
        self.assertEqual(app._project_receipts, [])
        self.journal.unlink()
        self.journal.write_bytes(original)
        ledger = self.state / "project-notifications.json"
        ledger.symlink_to(foreign)
        app = self.app()
        app.prepare_project_notifications()
        self.assertEqual(app._project_receipts, [])
        self.assertEqual(foreign.read_bytes(), original)

    def test_imported_receipt_mail_is_not_counted_as_new_build_or_current_update(self):
        app = self.app()
        app.run()
        self.delivered(app, "skipped")
        summary = json.loads((app.run_dir / "summary.json").read_text())
        decision = notices.mail_decision(summary)
        model = decision["model"]
        self.assertEqual(model["update_count"], 0)
        self.assertEqual(model["built_count"], 0)
        self.assertEqual(model["historical_update_count"], 1)
        self.assertTrue(decision["send"])
        self.assertIn("nachgemeldet", decision["subject"])
        for rendered in (notices.render_text(model), notices.render_html(model)):
            self.assertIn("Bereits am", rendered)
            self.assertIn("1 behoben", rendered)
            self.assertIn("keine Anwendungsimages neu gebaut oder ausgetauscht", rendered)
            self.assertNotIn("private-test-value", rendered)


if __name__ == "__main__":
    unittest.main()
