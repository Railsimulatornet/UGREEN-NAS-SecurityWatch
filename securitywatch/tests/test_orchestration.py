"""Prüft Betriebsfehler und Image-Zuordnung ohne NAS, Registry oder E-Mailversand."""
import copy
import csv
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
from securitywatch_common import ConfigurationError, RunLock, load_env
from securitywatch_lifecycle import LifecycleEngine
from securitywatch_scanner import ScanError, validate_scan, findings
from test_lifecycle import FakeDocker, Clock, OLD, NEW, OTHER, CID, scan


class LocalDocker(FakeDocker):
    def __call__(self, args, **kwargs):
        if args[:2] == ["container", "inspect"]:
            args = ["inspect", "--type", "container", *args[2:]]
        return super().__call__(args, **kwargs)


class SimulatedScanner:
    def __init__(self, run_dir, documents):
        self.run_dir, self.source = run_dir, documents
        self.documents, self.paths = {}, {}
        self.fail = set()

    def prepare(self):
        return {"test": True}

    def scan_image(self, iid):
        if iid in self.fail:
            raise ScanError("Simulierter Prüffehler")
        doc = copy.deepcopy(self.source[iid])
        doc["ArtifactType"] = "container_image"
        validate_scan(doc, iid)
        self.documents[iid] = doc
        path = self.run_dir / ("simuliert_" + iid.split(":")[1] + ".json")
        path.write_text(json.dumps(doc), encoding="utf-8")
        self.paths[iid] = path
        return doc

    def close(self):
        pass


class ConfigurationTests(unittest.TestCase):
    def test_credentials_are_data_and_embedded_hash_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings"
            path.write_text("A=abc#def\nB='abc # def' # Kommentar\nC=#prefix\nD= # Kommentar\nE=\"$(touch test);$HOME\"\nF=foo\\ bar\n")
            values = load_env(path)
            self.assertEqual(values, {"A": "abc#def", "B": "abc # def", "C": "#prefix", "D": "",
                                      "E": "$(touch test);$HOME", "F": "foo bar"})
            self.assertFalse((Path(temp) / "test").exists())

    def test_same_process_cannot_start_overlapping_run(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "run.lock"
            with RunLock(path):
                with self.assertRaises(ConfigurationError):
                    with RunLock(path):
                        self.fail("Lock missing")

    def test_unfinished_installer_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            (state / "securitywatch-install.json").write_text('{"phase":"installing"}')
            with self.assertRaises(ConfigurationError):
                sw.installation_complete(state)


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sw_root_test_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "compose.yaml").write_text("services: {app: {image: example/app:1}}\n")
        self.docker = LocalDocker(self.project)
        self.clock = Clock()
        self.env_path = self.root / ".env"
        self.env_path.write_text("TRIVY_SCAN_FILESYSTEM=0\nSTATE_DIR=" + str(self.root / "state") +
                                 "\nREPORT_DIR=" + str(self.root / "reports") + "\nCACHE_DIR=" + str(self.root / "cache") +
                                 "\nIMAGE_UPDATE_VERIFY_STABLE_SECONDS=0\nREPORT_RETENTION_DAYS=0\n")

    def app(self, flags=()):
        args = sw.arguments(["--no-mail", *flags])
        env = sw.config(ROOT, self.env_path, args)
        def engine(state, runner, scan_image, *, options, emit):
            return LifecycleEngine(state, runner, scan_image, options=options, emit=emit,
                                   clock=self.clock, sleep=self.clock.sleep)
        app = sw.SecurityWatch(ROOT, self.env_path, env, args, self.docker, engine)
        app.scanner = SimulatedScanner(app.run_dir, {
            OLD: scan(OLD, [("CVE-old", "paket", "HIGH", "1")]),
            NEW: scan(NEW), OTHER: scan(OTHER, [("CVE-new", "anders", "CRITICAL", "1")])})
        app.say = lambda _text: None
        app.github = lambda: None
        app.render_and_mail = lambda: app.status.update(delivery={"status": "disabled"})
        return app

    def test_real_orchestration_links_newbuild_to_running_image_and_findings(self):
        app = self.app()
        self.assertEqual(app.run(), 0)
        item = app.status["image_outcomes"][0]
        self.assertEqual(item["build_status"], "succeeded")
        self.assertEqual(item["deployment_status"], "applied")
        self.assertTrue(item["runtime_confirmed"])
        self.assertEqual(item["actual_image_id"], NEW)
        self.assertEqual(item["before"]["high"], 1)
        self.assertEqual(item["after"]["total"], 0)
        self.assertEqual(item["resolved"], 1)
        report_files = list(app.run_dir.glob("image_*.json"))
        self.assertEqual(len(report_files), 1)
        self.assertEqual(json.loads(report_files[0].read_text())["Metadata"]["ImageID"], NEW)

    def test_rollback_reports_old_findings_despite_clean_candidate(self):
        self.docker.candidate_mode = "unhealthy"
        app = self.app()
        self.assertEqual(app.run(), 0)  # the controlled rollback completed successfully
        item = app.status["image_outcomes"][0]
        self.assertEqual(item["candidate"]["total"], 0)
        self.assertEqual(item["after"]["total"], 1)
        self.assertEqual(item["actual_image_id"], OLD)
        self.assertEqual(item["resolved"], 0)
        self.assertEqual(item["deployment_status"], "rolled_back")

    def test_missing_scan_blocks_all_application_changes(self):
        app = self.app()
        app.scanner.fail.add(OLD)
        self.assertEqual(app.run(), 2)
        self.assertEqual(app.status["scans"]["images"]["failed"], 1)
        self.assertEqual(self.docker.up_calls, [])
        self.assertFalse(any("build" in args for args, _, _ in self.docker.calls))

    def test_report_only_never_builds_or_deletes_application_images(self):
        app = self.app(["--report-only"])
        self.assertEqual(app.run(), 0)
        self.assertEqual(self.docker.up_calls, [])
        self.assertFalse(any("build" in args or args[:2] == ["image", "rm"] for args, _, _ in self.docker.calls))
        self.assertTrue(app.status["retention"]["preview"])

    def test_existing_local_target_filter_is_respected(self):
        app = self.app()
        app.env["LOCAL_IMAGE_AUTO_REBUILD_TARGET_PATTERNS"] = "different/*"
        self.assertEqual(app.run(), 0)
        self.assertEqual(self.docker.up_calls, [])

    def test_external_change_invalidates_previous_after_result(self):
        app = self.app()
        self.assertEqual(app.run(), 0)
        current = next(iter(self.docker.containers.values()))
        current["Image"] = OTHER
        app.reconcile_outcomes([current])
        item = app.status["image_outcomes"][0]
        self.assertEqual(item["actual_image_id"], OTHER)
        self.assertNotIn("after", item)
        self.assertEqual(item["verification_status"], "failed")

    def test_missing_final_inventory_does_not_leave_false_after_counts(self):
        app = self.app()
        self.assertEqual(app.run(), 0)
        app.reconcile_outcomes(None)
        item = app.status["image_outcomes"][0]
        self.assertNotIn("after", item)
        self.assertIsNone(item["actual_image_id"])

    def test_run_observes_change_after_final_scan_and_does_not_count_old_image(self):
        app = self.app()
        def external_deployment():
            current = next(iter(self.docker.containers.values()))
            current["Image"] = OTHER
            current["State"]["Health"]["Status"] = "unhealthy"
        app.github = external_deployment
        app.render_and_mail = lambda: sw.SecurityWatch.render_and_mail(app)
        self.assertEqual(app.run(), 2)
        item = app.status["image_outcomes"][0]
        self.assertEqual(app.status["run"]["status"], "partial")
        self.assertEqual(item["actual_image_id"], OTHER)
        self.assertEqual(item["verification_status"], "failed")
        self.assertNotIn("after", item)
        images = app.status["scans"]["images"]
        self.assertEqual(images["expected"], 1)
        self.assertEqual(images["succeeded"], 0)
        self.assertEqual(images["failed"], 1)
        self.assertEqual([entry["image_id"] for entry in images["items"]], [OTHER])
        self.assertNotIn(OTHER, app.scanner.documents)
        summary = json.loads((app.run_dir / "summary.json").read_text())
        self.assertFalse(summary["scan"]["complete"])
        self.assertEqual(summary["findings"], [])
        final = json.loads((app.run_dir / "container-nachher.json").read_text())
        self.assertEqual(final[0]["image_id"], OTHER)
        with (app.run_dir / "local-image-rebuild-results.tsv").open(newline="") as handle:
            legacy = list(csv.DictReader(handle, delimiter="\t"))[0]
        self.assertEqual(legacy["fixable"], "nicht ermittelt")

    def test_missing_final_inventory_in_run_invalidates_previously_successful_scan(self):
        app = self.app()
        inventory = sw.container_inventory
        calls = 0
        def failing_final_inventory(runner):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeError("Simulierter fehlender Abschlussbestand")
            return inventory(runner)
        with patch.object(sw, "container_inventory", side_effect=failing_final_inventory):
            self.assertEqual(app.run(), 2)
        self.assertEqual(app.status["scans"]["images"]["status"], "failed")
        self.assertEqual(app.status["scans"]["images"]["succeeded"], 0)
        self.assertNotIn("after", app.status["image_outcomes"][0])
        self.assertFalse(app.status["image_outcomes"][0]["runtime_confirmed"])

    def test_report_validation_failure_changes_exit_and_persisted_run_status(self):
        app = self.app()
        def remove_result_before_report():
            for path in app.run_dir.glob("image_*.json"):
                path.unlink()
        app.github = remove_result_before_report
        app.render_and_mail = lambda: sw.SecurityWatch.render_and_mail(app)
        self.assertEqual(app.run(), 2)
        status = json.loads((app.run_dir / "run-status.json").read_text())
        last = json.loads((app.state_dir / "last-run.json").read_text())
        summary = json.loads((app.run_dir / "summary.json").read_text())
        self.assertEqual(status["run"]["status"], "partial")
        self.assertEqual(last["run"]["status"], "partial")
        self.assertEqual(status["scans"]["images"]["succeeded"], 0)
        self.assertEqual(status["scans"]["images"]["failed"], 1)
        self.assertTrue(status["report_validation_errors"])
        self.assertFalse(summary["scan"]["complete"])
        self.assertTrue(any(event["status"] == "rebuilt" for event in status["events"]))

    def test_detail_table_uses_confirmed_after_counts_and_no_pending_scan_claim(self):
        app = self.app()
        app.render_and_mail = lambda: sw.SecurityWatch.render_and_mail(app)
        self.assertEqual(app.run(), 0)
        summary = json.loads((app.run_dir / "summary.json").read_text())
        row = summary["local_built_image_rebuild_results"][0]
        self.assertEqual(row["result"], "fixed")
        self.assertEqual(row["fixable"], "0")
        self.assertNotIn("Neu gebaut, erneute Prüfung ausstehend", (app.run_dir / "bericht.html").read_text())

    def test_github_publication_mismatch_reaches_run_events_and_rendered_mail(self):
        app = self.app()
        configuration = {"enabled": True, "repositories": [{"repository": "example/source",
                         "workflow": "weekly.yml", "image_patterns": ["example/app:*"],
                         "published_image_patterns": ["example/app:latest"]}]}
        configured = self.root / "github.json"
        configured.write_text(json.dumps(configuration))
        app.env["GITHUB_CONFIG_FILE"] = str(configured)
        app.github = lambda: sw.SecurityWatch.github(app)
        app.render_and_mail = lambda: sw.SecurityWatch.render_and_mail(app)
        with patch("securitywatch_github.monitor_github", return_value={"status": "ok", "events": []}) as monitor:
            self.assertEqual(app.run(), 0)
        monitor.assert_called_once_with(configuration, token_file=None)
        self.assertTrue(any(event["status"] == "published_tag_mismatch" for event in app.status["events"]))
        self.assertTrue(any(event["status"] == "published_tag_mismatch" for event in app.status["github"]["events"]))
        mail = (app.run_dir / "mail.txt").read_text()
        self.assertIn("Der Wochenneubau erreicht die verwendete Image-Version nicht: example/app:1", mail)

    def test_report_timeout_still_creates_failure_mail_and_preserves_failed_status(self):
        app = self.app()
        app.status["run"]["status"] = "failed"
        app.args.no_mail = False
        def failing_process(command, **_):
            if "securitywatch_report.py" in command[1]:
                raise subprocess.TimeoutExpired(command, 180)
            result = Path(command[command.index("--result-json") + 1])
            result.write_text('{"status":"failed"}')
            return subprocess.CompletedProcess(command, 1, "", "")
        with patch.object(sw.subprocess, "run", side_effect=failing_process):
            sw.SecurityWatch.render_and_mail(app)
        self.assertTrue((app.run_dir / "mail.html").is_file())
        self.assertIn("keine vollständige Prüfung", (app.run_dir / "mail.txt").read_text())
        self.assertEqual(app.status["run"]["status"], "failed")
        self.assertEqual(app.status["delivery"]["status"], "failed")

    def test_skipped_email_is_not_reported_as_sent(self):
        app = self.app()
        app.args.no_mail = False
        def process(command, **_):
            if "--result-json" in command:
                Path(command[command.index("--result-json") + 1]).write_text('{"status":"skipped"}')
            return subprocess.CompletedProcess(command, 0, "", "")
        with patch.object(sw.subprocess, "run", side_effect=process):
            sw.SecurityWatch.render_and_mail(app)
        self.assertEqual(app.status["delivery"]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
