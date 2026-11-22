"""Einmalige Quellenumstellung mit nachgebildetem Docker, ohne NAS-Zugriff."""
import copy
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from securitywatch_lifecycle import LifecycleEngine, LifecycleError
from securitywatch_project_updates import ProjectUpdater, TARGETS, replace_image_line
from test_lifecycle import FakeDocker, Clock, container, scan, CID, OLD, NEW, OTHER


class MigrationDocker(FakeDocker):
    def __init__(self, directory, key="schulmanager", baseline_health=False):
        super().__init__(directory, registry=True)
        self.target = TARGETS[key]
        self.ref = self.target.old_ref
        self.containers = {CID: container(CID, OLD, self.ref, directory, service=self.target.service, project=self.target.project)}
        self.containers[CID]["Name"] = "/" + self.target.name
        if not baseline_health:
            self.containers[CID]["Config"].pop("Healthcheck")
            self.containers[CID]["State"].pop("Health")
        self.images = {OLD: {"Id": OLD, "RepoTags": [self.ref], "RepoDigests": [self.target.old_ref.rsplit(":", 1)[0] + "@" + OLD]}}
        self.config = {"name": self.target.project, "services": {
            self.target.service: {"image": self.ref, "environment": {"TOKEN": "private-test-value"}},
            "unrelated": {"image": "busybox:1.36.1"}}}
        self.original = ("# preserved header\nservices:\n  " + self.target.service + ":\n"
                         "    image: '" + self.ref + "' # keep this comment\n"
                         "    environment:\n      TOKEN: private-test-value\n"
                         "  unrelated:\n    image: busybox:1.36.1\n")
        self.compose = directory / "compose.yaml"
        self.compose.write_text(self.original)
        self.native_health = True
        self.input_changes_other_setting = False
        self.custom_up_hook = None
        self.baseline_health = baseline_health
        self.up_hook = self._native_container

    def _native_container(self, iid, service):
        current = next(c for c in self.containers.values() if c["Config"]["Labels"]["com.docker.compose.service"] == service)
        current["Name"] = "/" + self.target.name
        current["Config"]["Labels"]["com.docker.compose.project"] = self.target.project
        if iid == NEW:
            current["Config"]["Healthcheck"]["Test"] = list(self.target.health_test)
        elif not self.baseline_health:
            current["Config"].pop("Healthcheck", None)
            current["State"].pop("Health", None)
        if self.custom_up_hook:
            self.custom_up_hook(iid, service, current)

    def __call__(self, args, *, cwd=None, timeout=60, input_text=None):
        if args[0] == "compose" and "config" in args:
            self.calls.append((list(args), cwd, timeout))
            text = self.compose.read_text() if input_text is None else input_text
            match = re.search(r"(?m)^\s+image:\s+['\"]?([^\s'\"]+)", text)
            result = copy.deepcopy(self.config)
            result["services"][self.target.service]["image"] = match[1]
            if "EXTERNAL_CHANGE" in text or (input_text is not None and self.input_changes_other_setting):
                result["services"]["unrelated"]["image"] = "unexpected:other"
            return self.reply(args, json.dumps(result))
        result = super().__call__(args, cwd=cwd, timeout=timeout)
        if args[0] == "pull" and self.native_health:
            self.images[NEW]["Config"] = {"Healthcheck": {
                "Test": list(self.target.health_test), "Interval": 1_000_000_000,
                "Timeout": 1_000_000_000, "Retries": 1, "StartPeriod": 0}}
        return result


class ProjectUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sw_project_update_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.state = self.root / "state"
        self.clock = Clock()
        self.docker = MigrationDocker(self.project)
        self.scans = {OLD: scan(OLD, [("CVE-existing", "package", "HIGH", "1")]), NEW: scan(NEW)}
        self.scanned = []
        self.make_updater()

    def make_updater(self):
        def scanner(iid):
            self.scanned.append(iid)
            return copy.deepcopy(self.scans[iid])
        self.engine = LifecycleEngine(self.state, self.docker, scanner,
                                      options={"health_timeout": 10, "health_interval": 1, "stable_seconds": 2},
                                      clock=self.clock, sleep=self.clock.sleep)
        self.updater = ProjectUpdater(self.engine, lambda reference: reference.rsplit(":", 1)[0] + "@sha256:" + "c" * 64)

    def test_check_reads_exact_plan_without_writes_or_image_changes(self):
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        plan = self.updater.plan("schulmanager")
        shown = self.updater.public_plan(plan)
        self.assertEqual(shown["bisherige_quelle"], self.docker.target.old_ref)
        self.assertEqual(shown["neue_quelle"], self.docker.target.new_ref)
        self.assertNotIn("private-test-value", json.dumps(shown))
        after = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(self.state.exists())
        self.assertFalse(any(args[0] == "pull" or args[:2] == ["image", "tag"] or "up" in args for args, _, _ in self.docker.calls))

    def test_known_projects_migrate_without_retagging_fixed_versions(self):
        for key in TARGETS:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp)
                docker = MigrationDocker(project, key)
                clock = Clock()
                engine = LifecycleEngine(project / "state", docker, lambda iid: scan(iid),
                                         options={"health_timeout": 10, "health_interval": 1, "stable_seconds": 1},
                                         clock=clock, sleep=clock.sleep)
                updater = ProjectUpdater(engine, lambda reference: reference.rsplit(":", 1)[0] + "@sha256:" + "c" * 64)
                result = updater.apply(key)
                self.assertEqual(result["status"], "updated", result)
                if docker.target.old_ref != docker.target.new_ref:
                    self.assertEqual(docker.find_image(docker.target.old_ref)["Id"], OLD)
                self.assertEqual(docker.find_image(docker.target.new_ref)["Id"], NEW)
                self.assertEqual(docker.compose.read_text(), docker.original.replace(docker.target.old_ref, docker.target.new_ref))
                current = next(iter(docker.containers.values()))
                self.assertEqual(current["Image"], NEW)
                self.assertTrue(engine.describe(current)["automatic_allowed"])
                self.assertEqual(engine.describe(current)["image_ref"], docker.target.new_ref)
                self.assertEqual(engine.open_transactions(), [])
                record = json.loads(engine.retention_file.read_text())["images"][OLD]
                self.assertGreaterEqual(record["retain_until"] - record["successful_replacement_at"], 7 * 86400)
                self.assertIn(docker.target.old_ref, record["allowed_tags"])
                self.assertEqual(updater.apply(key)["status"], "already_current")

    def test_easyepg_adoption_preserves_original_compose_bytes_and_mount_settings(self):
        self.docker = MigrationDocker(self.project, "easyepg")
        self.docker.config["services"]["easyepg"]["volumes"] = [{"type": "bind", "source": "/mnt/existing", "target": "/easyepg"}]
        original_bytes = self.docker.compose.read_bytes()
        inode = self.docker.compose.stat().st_ino
        self.make_updater()
        result = self.updater.apply("easyepg")
        self.assertEqual(result["status"], "updated")
        self.assertEqual(self.docker.compose.read_bytes(), original_bytes)
        self.assertEqual(self.docker.compose.stat().st_ino, inode)
        self.assertEqual(self.docker.config["services"]["easyepg"]["volumes"][0]["source"], "/mnt/existing")
        self.assertEqual(self.docker.find_image(self.docker.target.new_ref)["Id"], NEW)

    def test_easyepg_failed_health_restores_old_runtime_and_tag_without_false_verification(self):
        self.docker = MigrationDocker(self.project, "easyepg")
        self.docker.candidate_mode = "unhealthy"
        self.make_updater()
        result = self.updater.apply("easyepg")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertTrue(result["runtime_restored"])
        self.assertEqual(self.docker.find_image(self.docker.target.old_ref)["Id"], OLD)
        self.assertEqual(next(iter(self.docker.containers.values()))["Image"], OLD)
        self.assertEqual(self.docker.compose.read_text(), self.docker.original)

    def test_native_healthcheck_missing_waits_without_restart_or_source_change(self):
        self.docker.native_health = False
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "rejected")
        self.assertIn("Zustandsprüfung", result["message"])
        self.assertEqual(self.docker.up_calls, [])
        self.assertEqual(self.docker.compose.read_text(), self.docker.original)
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OLD)
        self.assertEqual(self.engine.open_transactions(), [])

    def test_additional_high_finding_rejects_candidate_before_restart(self):
        self.scans[NEW] = scan(NEW, [("CVE-new", "other", "HIGH", "1")])
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(self.docker.up_calls, [])
        self.assertEqual(self.docker.compose.read_text(), self.docker.original)
        self.assertEqual(self.scanned, [OLD, NEW])

    def test_invalid_before_after_scan_identity_rejects_candidate(self):
        self.scans[NEW]["Metadata"]["ImageID"] = OTHER
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(self.docker.up_calls, [])

    def test_scanner_failure_rejects_without_leaving_false_recovery_work(self):
        def unavailable(iid):
            raise RuntimeError("private-tool-diagnostic")
        self.engine.scan_image = unavailable
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "rejected")
        self.assertNotIn("private-tool-diagnostic", json.dumps(result))
        self.assertEqual(self.docker.up_calls, [])
        self.assertEqual(self.engine.open_transactions(), [])
        self.assertEqual(self.docker.images[OLD]["RepoTags"], [self.docker.ref])

    def test_failed_candidate_returns_exact_old_image_but_keeps_unverified_recovery_open(self):
        self.docker.candidate_mode = "unhealthy"
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertTrue(result["runtime_restored"])
        self.assertFalse(result["functional_restore_verified"])
        self.assertEqual(next(iter(self.docker.containers.values()))["Image"], OLD)
        self.assertEqual(self.docker.compose.read_text(), self.docker.original)
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OLD)
        self.assertEqual(len(self.engine.open_transactions()), 1)
        self.assertFalse(self.engine.describe(next(iter(self.docker.containers.values())))["automatic_allowed"])

    def test_healthy_baseline_rollback_can_be_fully_verified(self):
        self.docker = MigrationDocker(self.project, baseline_health=True)
        self.docker.candidate_mode = "unhealthy"
        self.make_updater()
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(self.engine.open_transactions(), [])
        self.assertEqual(next(iter(self.docker.containers.values()))["Image"], OLD)

    def test_other_compose_change_is_rejected_by_resolved_configuration_check(self):
        self.docker.input_changes_other_setting = True
        with self.assertRaises(LifecycleError):
            self.updater.plan("schulmanager")
        self.assertEqual(self.docker.up_calls, [])
        self.assertFalse(any(args[0] == "pull" for args, _, _ in self.docker.calls))

    def test_foreign_source_change_after_start_is_preserved_and_recovery_stays_open(self):
        def change(iid, service, current):
            if iid == NEW:
                self.docker.compose.write_text(self.docker.original + "# EXTERNAL_CHANGE\n")
        self.docker.custom_up_hook = change
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertIn("EXTERNAL_CHANGE", self.docker.compose.read_text())
        self.assertEqual(len(self.engine.open_transactions()), 1)

    def test_existing_latest_tag_can_move_without_changing_fixed_tag(self):
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [self.docker.target.new_ref], "RepoDigests": []}
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "updated")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OLD)
        self.assertEqual(self.docker.find_image(self.docker.target.new_ref)["Id"], NEW)
        self.assertIn(OTHER, self.docker.images)

    def test_foreign_fixed_old_tag_mapping_is_not_silently_accepted(self):
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [], "RepoDigests": []}
        self.docker.move_tag(self.docker.ref, OTHER)
        with self.assertRaises(LifecycleError):
            self.updater.plan("schulmanager")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OTHER)
        self.assertEqual(self.docker.up_calls, [])

    def test_concurrent_latest_tag_change_is_preserved(self):
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [], "RepoDigests": []}
        def change(source, target):
            if target == self.docker.target.new_ref:
                self.docker.move_tag(target, OTHER)
        self.docker.tag_hook = change
        result = self.updater.apply("schulmanager")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertEqual(self.docker.find_image(self.docker.target.new_ref)["Id"], OTHER)
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OLD)
        self.assertEqual(self.docker.compose.read_text(), self.docker.original)

    def test_interruption_stays_in_common_journal_and_blocks_next_apply(self):
        self.docker.interrupt_up = True
        with self.assertRaises(KeyboardInterrupt):
            self.updater.apply("schulmanager")
        self.assertEqual(len(self.engine.open_transactions()), 1)
        self.assertEqual(self.engine.open_transactions()[0]["phase"], "deploying")
        with self.assertRaises(LifecycleError):
            self.updater.apply("schulmanager")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OLD)

    def test_journal_has_hashes_not_resolved_environment_secrets(self):
        result = self.updater.apply("schulmanager")
        journal = (self.engine.tx_dir / (result["transaction_id"] + ".json")).read_text()
        self.assertNotIn("private-test-value", journal)
        backup = Path(result["backup"])
        self.assertEqual(backup.read_text(), self.docker.original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)

    def test_compose_health_override_is_not_implicitly_bypassed(self):
        self.docker.config["services"][self.docker.target.service]["healthcheck"] = {"disable": True}
        with self.assertRaises(LifecycleError):
            self.updater.plan("schulmanager")

    def test_ambiguous_literal_and_environment_image_references_are_not_rewritten(self):
        with self.assertRaises(LifecycleError):
            replace_image_line("image: '${IMAGE_NAME}'\n", self.docker.ref, self.docker.target.new_ref)
        with self.assertRaises(LifecycleError):
            replace_image_line("image: " + self.docker.ref + "\nimage: " + self.docker.ref + "\n", self.docker.ref, self.docker.target.new_ref)


if __name__ == "__main__":
    unittest.main()
