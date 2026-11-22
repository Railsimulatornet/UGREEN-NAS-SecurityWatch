"""Lebenszyklusprüfungen mit simuliertem Docker, ohne Produktionsverbindung."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from securitywatch_lifecycle import (LifecycleEngine, LifecycleError, atomic_json,
                                     compare_scans, DockerRunner)


OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
OTHER = "sha256:" + "f" * 64
CID = "1" * 64


def scan(iid, vulnerabilities=()):
    return {"SchemaVersion": 2, "Metadata": {"ImageID": iid}, "Results": [{
        "Type": "python-pkg", "Target": "python3.13/site-packages", "Vulnerabilities": [
            {"VulnerabilityID": cve, "PkgName": package, "Severity": severity,
             "InstalledVersion": version, "FixedVersion": "2.0"}
            for cve, package, severity, version in vulnerabilities]}]}


def container(cid, iid, ref, directory, *, service="app", project="sample", health="healthy", running=True):
    return {"Id": cid, "Image": iid, "Name": "/sample-" + service + "-1", "RestartCount": 0,
            "Config": {"Image": ref, "Healthcheck": {"Test": ["CMD", "true"],
                       "StartPeriod": 0, "Interval": 1_000_000_000, "Timeout": 1_000_000_000, "Retries": 1},
                       "Labels": {"com.docker.compose.project": project, "com.docker.compose.service": service,
                                  "com.docker.compose.project.working_dir": str(directory),
                                  "com.docker.compose.project.config_files": str(directory / "compose.yaml")}},
            "State": {"Running": running, "Status": "running" if running else "exited",
                      "Restarting": False, "Health": {"Status": health}}, "Mounts": []}


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeDocker:
    def __init__(self, directory, *, registry=False):
        self.directory = directory
        self.ref = "example/app:1"
        self.containers = {CID: container(CID, OLD, self.ref, directory)}
        self.images = {OLD: {"Id": OLD, "RepoTags": [self.ref],
                             "RepoDigests": ["example/app@sha256:" + "a" * 64] if registry else []}}
        self.config = {"services": {"app": {"image": self.ref}}}
        if not registry:
            self.config["services"]["app"]["build"] = {"context": str(directory), "dockerfile": "Dockerfile"}
        self.calls = []
        self.up_calls = []
        self.candidate_mode = "healthy"
        self.candidate_service_modes = {}
        self.rollback_mode = "healthy"
        self.build_id = NEW
        self.build_failure = False
        self.fail_ps = False
        self.interrupt_up = False
        self.up_hook = None
        self.tag_hook = None
        self.sequence = 2

    def move_tag(self, reference, iid):
        for image in self.images.values():
            if reference in image.get("RepoTags", []):
                image["RepoTags"].remove(reference)
        self.images[iid].setdefault("RepoTags", []).append(reference)

    def find_image(self, ref):
        if ref in self.images:
            return self.images[ref]
        for image in self.images.values():
            if ref in image.get("RepoTags", []) or ref in image.get("RepoDigests", []):
                return image
        return None

    def reply(self, args, out="", rc=0):
        return subprocess.CompletedProcess(args, rc, out, "simulated failure" if rc else "")

    def __call__(self, args, *, cwd=None, timeout=60):
        args = list(args)
        self.calls.append((args, cwd, timeout))
        if args[0] == "ps":
            if self.fail_ps:
                return self.reply(args, rc=1)
            filters = [args[i + 1] for i, word in enumerate(args[:-1]) if word == "--filter"]
            values = list(self.containers.values())
            for value in filters:
                label, expected = value.removeprefix("label=").split("=", 1)
                values = [c for c in values if c["Config"]["Labels"].get(label) == expected]
            return self.reply(args, "\n".join(c["Id"] for c in values))
        if args[:3] == ["inspect", "--type", "container"]:
            values = [self.containers[cid] for cid in args[3:] if cid in self.containers]
            if len(values) != len(args[3:]):
                return self.reply(args, rc=1)
            return self.reply(args, json.dumps(values))
        if args[:2] == ["image", "ls"]:
            return self.reply(args, "\n".join(self.images))
        if args[:2] == ["image", "inspect"]:
            image = self.find_image(args[2])
            return (self.reply(args, json.dumps([image])) if image else
                    subprocess.CompletedProcess(args, 1, "", "Error response from daemon: No such image: " + args[2]))
        if args[:2] == ["image", "tag"]:
            image = self.find_image(args[2])
            if image is None:
                return self.reply(args, rc=1)
            target = args[3]
            for other in self.images.values():
                if target in other.get("RepoTags", []):
                    other["RepoTags"].remove(target)
            image.setdefault("RepoTags", []).append(target)
            if self.tag_hook:
                self.tag_hook(args[2], target)
            return self.reply(args)
        if args[:2] == ["image", "rm"]:
            self.assert_not_forced(args)
            ref = args[-1]
            image = self.find_image(ref)
            if image is None:
                return self.reply(args, rc=1)
            iid = image["Id"]
            used = any(c["Image"] == iid for c in self.containers.values())
            tags = image.get("RepoTags", [])
            if ref == iid:
                if used or len(tags) > 1:
                    return self.reply(args, rc=1)
                del self.images[iid]
            else:
                if used and len(tags) <= 1:
                    return self.reply(args, rc=1)
                image["RepoTags"].remove(ref)
                if not image["RepoTags"] and not used:
                    del self.images[iid]
            return self.reply(args)
        if args[0] == "pull":
            self.images.setdefault(NEW, {"Id": NEW, "RepoTags": [], "RepoDigests": []})
            self.images[NEW]["RepoDigests"].append(args[1])
            return self.reply(args)
        if args[0] == "compose":
            if "config" in args:
                return self.reply(args, json.dumps(self.config))
            files = [args[i + 1] for i, word in enumerate(args[:-1]) if word == "-f"]
            if "build" in args:
                if self.build_failure:
                    return self.reply(args, rc=1)
                override = json.loads(Path(files[-1]).read_text())
                tag = override["services"][args[-1]]["image"]
                self.images.setdefault(self.build_id, {"Id": self.build_id, "RepoTags": [], "RepoDigests": []})
                self.images[self.build_id]["RepoTags"].append(tag)
                return self.reply(args)
            if "up" in args:
                self.up_calls.append(args)
                override = json.loads(Path(files[-1]).read_text())
                service = args[-1]
                ref = override["services"][service]["image"]
                image = self.find_image(ref)
                if not image:
                    return self.reply(args, rc=1)
                iid = image["Id"]
                current = next((c for c in self.containers.values()
                                if c["Config"]["Labels"]["com.docker.compose.service"] == service), None)
                if current:
                    del self.containers[current["Id"]]
                cid = str(self.sequence) * 64
                self.sequence += 1
                state = self.rollback_mode if iid == OLD else self.candidate_service_modes.get(service, self.candidate_mode)
                actual_id = OTHER if state == "wrong_id" else iid
                new = container(cid, actual_id, ref, self.directory, service=service,
                                health="healthy" if state in {"healthy", "wrong_id"} else state)
                new["Config"]["Labels"]["com.docker.compose.project.config_files"] = ",".join(files)
                self.containers[cid] = new
                if self.up_hook:
                    self.up_hook(iid, service)
                if self.interrupt_up:
                    raise KeyboardInterrupt()
                return self.reply(args)
        raise AssertionError("Unexpected fake Docker call: " + repr(args))

    @staticmethod
    def assert_not_forced(args):
        if "-f" in args or "--force" in args:
            raise AssertionError("Forced image deletion is forbidden")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sw_lifecycle_test_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "compose.yaml").write_text("services: {app: {image: example/app:1}}\n")
        self.state = self.root / "state"
        self.docker = FakeDocker(self.project)
        self.clock = Clock()
        self.events = []
        self.scans = {OLD: scan(OLD, [("CVE-old", "example", "HIGH", "1.0")]), NEW: scan(NEW)}
        self.engine = self.make_engine()

    def make_engine(self, scanner=None):
        return LifecycleEngine(self.state, self.docker, scanner or (lambda iid: copy.deepcopy(self.scans[iid])),
                               options={"health_timeout": 10, "health_max_wait": 2400,
                                        "stable_seconds": 2, "health_interval": 1},
                               emit=self.events.append, clock=self.clock, sleep=self.clock.sleep)

    def initial(self):
        return [copy.deepcopy(self.docker.containers[CID])]

    def test_success_protects_seven_days_from_verified_completion(self):
        before = self.clock()
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rebuilt")
        self.assertEqual(result["actual_image_id"], NEW)
        self.assertEqual(result["build_status"], "succeeded")
        self.assertEqual(result["deployment_status"], "applied")
        data = json.loads((self.state / "image-retention.json").read_text())
        item = data["images"][OLD]
        self.assertGreater(item["successful_replacement_at"], before)
        self.assertEqual(item["retain_until"], item["successful_replacement_at"] + 7 * 86400)
        self.assertTrue(any(tag.startswith("securitywatch-previous:") for tag in self.docker.images[OLD]["RepoTags"]))
        self.assertEqual(self.engine.open_transactions(), [])
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], NEW)
        self.assertEqual(result["source_tag_status"], "updated")
        args = self.docker.up_calls[0]
        self.assertIn("--no-build", args)
        self.assertEqual(args[args.index("--pull") + 1], "never")
        self.assertIn("--force-recreate", args)
        self.assertFalse(any(a[0] in {"stop", "rm"} for a, _, _ in self.docker.calls))
        current = next(iter(self.docker.containers.values()))
        descriptor = self.engine.describe(current)
        self.assertEqual(descriptor["image_ref"], "example/app:1")
        for p in current["Config"]["Labels"]["com.docker.compose.project.config_files"].split(","):
            self.assertTrue(Path(p).exists(), p)

    def test_retention_boundary_and_stopped_shared_image(self):
        self.engine.update_group(self.initial(), source="local")
        deadline = json.loads((self.state / "image-retention.json").read_text())["images"][OLD]["retain_until"]
        self.clock.now = deadline - 1
        self.assertEqual(self.engine.cleanup_retention()["removed"], 0)
        stopped = container("9" * 64, OLD, "another-alias:1", self.project, service="stopped", running=False)
        self.docker.containers[stopped["Id"]] = stopped
        self.clock.now = deadline + 1
        self.assertEqual(self.engine.cleanup_retention()["removed"], 0)
        del self.docker.containers[stopped["Id"]]
        self.assertEqual(self.engine.cleanup_retention()["removed"], 1)
        self.assertNotIn(OLD, self.docker.images)

    def test_new_unknown_alias_prevents_deletion(self):
        self.engine.update_group(self.initial(), source="local")
        self.clock.now += 8 * 86400
        self.docker.images[OLD]["RepoTags"].append("manual-backup:keep")
        result = self.engine.cleanup_retention()
        self.assertEqual(result["removed"], 0)
        self.assertEqual(result["entries"][0]["status"], "weitere_image_namen")

    def test_preexisting_manual_alias_is_not_claimed_by_retention(self):
        self.docker.images[OLD]["RepoTags"].append("manual-backup:keep")
        self.engine.update_group(self.initial(), source="local")
        self.clock.now += 8 * 86400
        result = self.engine.cleanup_retention()
        self.assertEqual(result["removed"], 0)
        self.assertEqual(result["entries"][0]["status"], "weitere_image_namen")

    def test_unhealthy_successor_keeps_expired_previous_version(self):
        self.engine.update_group(self.initial(), source="local")
        self.clock.now += 8 * 86400
        next(iter(self.docker.containers.values()))["State"]["Health"]["Status"] = "unhealthy"
        result = self.engine.cleanup_retention()
        self.assertEqual(result["removed"], 0)
        self.assertEqual(result["entries"][0]["status"], "nachfolger_nicht_geprueft")

    def test_failed_candidate_restores_exact_old_image(self):
        self.docker.candidate_mode = "unhealthy"
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(result["actual_image_id"], OLD)
        self.assertEqual(next(iter(self.docker.containers.values()))["Image"], OLD)
        self.assertEqual(len(self.docker.up_calls), 2)
        self.assertEqual(self.engine.open_transactions(), [])
        current_ref = next(iter(self.docker.containers.values()))["Config"]["Image"]
        self.assertTrue(current_ref.startswith("securitywatch-previous:"))
        self.assertIsNotNone(self.docker.find_image(current_ref))

    def test_wrong_started_image_is_detected(self):
        self.docker.candidate_mode = "wrong_id"
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(result["actual_image_id"], OLD)

    def test_failed_rollback_stays_open_and_protected(self):
        self.docker.candidate_mode = "unhealthy"
        self.docker.rollback_mode = "unhealthy"
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertIsNone(result["actual_image_id"])
        pending = self.engine.open_transactions()
        self.assertEqual(len(pending), 1)
        self.assertTrue(self.docker.find_image(pending[0]["backup_tag"]))
        self.clock.now += 30 * 86400
        self.engine.cleanup_retention()
        self.assertIn(OLD, self.docker.images)

    def test_interruption_leaves_journal_and_next_update_blocked(self):
        self.docker.interrupt_up = True
        with self.assertRaises(KeyboardInterrupt):
            self.engine.update_group(self.initial(), source="local")
        pending = self.engine.open_transactions()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["phase"], "deploying")
        self.assertTrue(self.docker.find_image(pending[0]["backup_tag"]))
        current = next(iter(self.docker.containers.values()))
        descriptor = self.make_engine().describe(current)
        self.assertFalse(descriptor["automatic_allowed"])
        self.assertIn("ungeklärt", descriptor["reason"])

    def test_scan_error_never_becomes_zero_findings(self):
        def broken(iid):
            if iid == NEW:
                raise ValueError("bad JSON")
            return self.scans[iid]
        result = self.make_engine(broken).update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "scan_failed")
        self.assertEqual(result["new_image_id"], NEW)
        self.assertEqual(result["build_status"], "succeeded")
        self.assertEqual(result["actual_image_id"], OLD)
        self.assertEqual(self.docker.up_calls, [])

    def test_wrong_scan_identity_blocks_deployment(self):
        self.scans[NEW]["Metadata"]["ImageID"] = OTHER
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "scan_failed")
        self.assertEqual(self.docker.up_calls, [])

    def test_config_changed_during_build_prevents_switch(self):
        def change(iid):
            if iid == NEW:
                (self.project / "compose.yaml").write_text("changed while building\n")
            return self.scans[iid]
        result = self.make_engine(change).update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "skipped")
        self.assertIn("Konfiguration", result["message"])
        self.assertEqual(self.docker.up_calls, [])

    def test_stopped_service_is_not_started(self):
        self.docker.containers[CID]["State"]["Running"] = False
        self.docker.containers[CID]["State"]["Status"] = "created"
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.docker.up_calls, [])
        self.assertFalse(any("build" in args for args, _, _ in self.docker.calls))

    def test_disabled_healthcheck_blocks_before_build(self):
        self.docker.containers[CID]["Config"]["Healthcheck"]["Test"] = ["NONE"]
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "skipped")
        self.assertIn("Zustandsprüfung", result["message"])
        self.assertEqual(self.docker.up_calls, [])

    def test_missing_healthcheck_allows_isolated_local_preparation_only(self):
        self.docker.containers[CID]["Config"].pop("Healthcheck")
        self.docker.containers[CID]["State"].pop("Health")
        original = self.initial()
        descriptor = self.engine.describe(original[0])
        self.assertTrue(descriptor["build_allowed"])
        self.assertFalse(descriptor["automatic_allowed"])
        result = self.engine.update_group(original, source="local", prepare_only=True)
        self.assertEqual(result["status"], "prepared_only")
        self.assertEqual(result["build_status"], "succeeded")
        self.assertEqual(result["deployment_status"], "kept_previous")
        self.assertEqual(result["verification_status"], "not_run")
        self.assertEqual(result["actual_image_id"], OLD)
        self.assertEqual(result["new_image_id"], NEW)
        self.assertEqual(result["comparison"]["fixed_count"], 1)
        self.assertEqual(self.initial(), original)
        self.assertEqual(self.docker.up_calls, [])
        self.assertEqual(self.docker.images[OLD]["RepoTags"], [self.docker.ref])
        self.assertNotIn(NEW, self.docker.images)
        self.assertFalse(self.engine.deploy_dir.exists())
        self.assertFalse(self.engine.retention_file.exists())
        self.assertEqual(self.engine.open_transactions(), [])

    def test_preparation_only_still_rejects_new_vulnerabilities(self):
        self.docker.containers[CID]["Config"].pop("Healthcheck")
        self.scans[NEW] = scan(NEW, [("CVE-new", "new-package", "CRITICAL", "1")])
        result = self.engine.update_group(self.initial(), source="local", prepare_only=True)
        self.assertEqual(result["status"], "candidate_rejected")
        self.assertEqual(result["actual_image_id"], OLD)
        self.assertEqual(self.docker.up_calls, [])
        self.assertEqual(self.docker.images[OLD]["RepoTags"], [self.docker.ref])

    def test_preparation_only_does_not_bypass_project_ownership(self):
        self.engine.options["excluded_projects"] = ["sample"]
        descriptor = self.engine.describe(self.initial()[0])
        self.assertFalse(descriptor["build_allowed"])
        result = self.engine.update_group(self.initial(), source="local", prepare_only=True)
        self.assertEqual(result["status"], "skipped")
        self.assertFalse(any("build" in args for args, _, _ in self.docker.calls))

    def test_preparation_only_does_not_restart_or_build_stopped_service(self):
        self.docker.containers[CID]["State"].update(Running=False, Status="exited")
        self.assertFalse(self.engine.describe(self.initial()[0])["build_allowed"])
        result = self.engine.update_group(self.initial(), source="local", prepare_only=True)
        self.assertEqual(result["status"], "skipped")
        self.assertFalse(any("build" in args or "up" in args for args, _, _ in self.docker.calls))

    def test_preparation_only_does_not_ignore_pending_transaction(self):
        self.state.mkdir()
        atomic_json(self.engine.tx_dir / "incomplete.json", {
            "schema": 1, "phase": "deploying", "old_image_id": OLD, "services": []})
        self.assertFalse(self.engine.describe(self.initial()[0])["build_allowed"])
        result = self.engine.update_group(self.initial(), source="local", prepare_only=True)
        self.assertEqual(result["status"], "skipped")
        self.assertFalse(any("build" in args for args, _, _ in self.docker.calls))

    def test_preparation_only_is_not_a_registry_health_bypass(self):
        self.docker = FakeDocker(self.project, registry=True)
        self.engine = self.make_engine()
        with self.assertRaises(LifecycleError):
            self.engine.update_group(self.initial(), source="registry", prepare_only=True)
        self.assertFalse(any("pull" in args or "up" in args for args, _, _ in self.docker.calls))

    def test_dependency_change_updates_build_retry_fingerprint_without_exposing_content(self):
        requirement = self.project / "requirements.txt"
        requirement.write_text("private-package @ https://private-token@example.invalid/package-1.whl\n")
        first = self.engine.describe(self.initial()[0])
        requirement.write_text("private-package @ https://private-token@example.invalid/package-2.whl\n")
        second = self.engine.describe(self.initial()[0])
        self.assertNotEqual(first["build_fingerprint"], second["build_fingerprint"])
        self.assertNotIn("private-token", json.dumps(second))

    def test_dockerfile_changed_during_build_prevents_deployment(self):
        dockerfile = self.project / "Dockerfile"
        dockerfile.write_text("FROM example/base:1\n")
        def changed(iid):
            if iid == NEW:
                dockerfile.write_text("FROM example/base:2\n")
            return self.scans[iid]
        result = self.make_engine(changed).update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "skipped")
        self.assertIn("Baugrundlage", result["message"])
        self.assertEqual(self.docker.up_calls, [])

    def test_long_start_period_and_camera_interval(self):
        value = self.initial()[0]
        value["Config"]["Healthcheck"].update(StartPeriod=600_000_000_000, Interval=60_000_000_000,
                                             Timeout=15_000_000_000, Retries=3)
        self.assertEqual(self.engine.health_budget(value), 827)
        value["Config"]["Healthcheck"].update(Interval=1800_000_000_000)
        with self.assertRaises(LifecycleError):
            self.engine.health_budget(value)

    def test_corrupt_retention_fails_before_mutation(self):
        self.state.mkdir()
        (self.state / "image-retention.json").write_text("not json")
        with self.assertRaises(LifecycleError):
            self.engine.update_group(self.initial(), source="local")
        self.assertFalse(any(args[0] in {"pull"} or args[:2] == ["image", "tag"]
                             or "build" in args for args, _, _ in self.docker.calls))

    def test_failed_container_inventory_prevents_cleanup(self):
        self.engine.update_group(self.initial(), source="local")
        self.clock.now += 8 * 86400
        self.docker.fail_ps = True
        count = len(self.docker.calls)
        with self.assertRaises(LifecycleError):
            self.engine.cleanup_retention()
        self.assertFalse(any(args[:2] == ["image", "rm"] for args, _, _ in self.docker.calls[count:]))

    def test_registry_candidate_uses_immutable_digest(self):
        self.docker = FakeDocker(self.project, registry=True)
        self.engine = self.make_engine()
        remote = "example/app@sha256:" + "c" * 64
        result = self.engine.update_group(self.initial(), source="registry", remote_ref=remote)
        self.assertEqual(result["status"], "update_applied")
        self.assertEqual([a for a, _, _ in self.docker.calls if a[0] == "pull"], [["pull", remote]])
        self.assertEqual(result["build_status"], "not_attempted")

    def test_normal_rebuild_can_keep_same_vulnerabilities(self):
        self.scans[NEW] = scan(NEW, [("CVE-old", "example", "HIGH", "1.1")])
        result = self.engine.update_group(self.initial(), source="local", require_improvement=False)
        self.assertEqual(result["status"], "rebuilt")
        self.assertEqual(result["comparison"]["fixed_count"], 0)
        self.assertEqual(result["comparison"]["remaining_fixable_count"], 1)
        self.assertIn("Bauanleitung", result["action"])

    def test_targeted_repair_requires_actual_removal(self):
        self.scans[NEW] = scan(NEW, [("CVE-old", "example", "HIGH", "1.1")])
        result = self.engine.update_group(self.initial(), source="local", require_improvement=True)
        self.assertEqual(result["status"], "candidate_rejected")
        self.assertEqual(self.docker.up_calls, [])

    def test_dry_run_has_no_docker_mutations(self):
        self.engine.options["dry_run"] = True
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "planned")
        self.assertFalse(any(args[0] == "pull" or args[:2] == ["image", "tag"]
                             or "build" in args or "up" in args for args, _, _ in self.docker.calls))

    def test_unmanaged_images_are_never_pruned(self):
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [], "RepoDigests": []}
        self.engine.cleanup_retention()
        self.assertIn(OTHER, self.docker.images)
        self.assertFalse(any("prune" in args for args, _, _ in self.docker.calls))

    def test_unchanged_build_does_not_leak_candidate_alias(self):
        self.docker.build_id = OLD
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(self.docker.images[OLD]["RepoTags"], [self.docker.ref])
        self.assertEqual(self.docker.up_calls, [])

    def test_preexisting_rejected_candidate_keeps_owner_tag(self):
        self.docker.images[NEW] = {"Id": NEW, "RepoTags": ["manual-prepared:keep"], "RepoDigests": []}
        self.scans[NEW] = scan(NEW, [("new", "different", "CRITICAL", "1")])
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "candidate_rejected")
        self.assertEqual(self.docker.images[NEW]["RepoTags"], ["manual-prepared:keep"])

    def test_shared_group_is_updated_together_and_rolled_back_together(self):
        second = container("8" * 64, OLD, self.docker.ref, self.project, service="api")
        self.docker.containers[second["Id"]] = second
        self.docker.config["services"]["api"] = copy.deepcopy(self.docker.config["services"]["app"])
        self.docker.candidate_service_modes["api"] = "unhealthy"
        originals = [copy.deepcopy(v) for v in self.docker.containers.values()]
        result = self.engine.update_group(originals, source="local")
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(len(self.docker.up_calls), 4)
        self.assertEqual({c["Image"] for c in self.docker.containers.values()}, {OLD})
        self.assertEqual(self.engine.open_transactions(), [])

    def test_omitted_shared_consumer_blocks_group(self):
        second = container("8" * 64, OLD, self.docker.ref, self.project, service="api")
        self.docker.containers[second["Id"]] = second
        with self.assertRaises(LifecycleError):
            self.engine.update_group(self.initial(), source="local")
        self.assertEqual(self.docker.up_calls, [])

    def test_cleanup_preview_respects_manual_alias(self):
        self.engine.update_group(self.initial(), source="local")
        self.clock.now += 8 * 86400
        self.docker.images[OLD]["RepoTags"].append("manual-backup:keep")
        result = self.engine.cleanup_retention(preview=True)
        self.assertEqual(result["eligible"], 0)
        self.assertEqual(result["protected"], 1)

    def test_reporting_callback_failure_does_not_roll_back_commit(self):
        def callback(_event):
            raise OSError("report disk full")
        self.engine.emit = callback
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rebuilt")
        self.assertIn("reporting_warning", result)
        self.assertEqual(self.engine.open_transactions(), [])
        self.assertEqual(len(self.docker.up_calls), 1)

    def test_project_exclusion_globs_are_observed(self):
        self.engine.options["excluded_projects"] = ["sam*"]
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.docker.up_calls, [])

    def test_tag_already_changed_before_preparation_blocks_update(self):
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [], "RepoDigests": []}
        self.docker.move_tag(self.docker.ref, OTHER)
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OTHER)
        self.assertFalse(any("build" in args or "up" in args for args, _, _ in self.docker.calls))

    def test_external_tag_change_while_building_blocks_switch(self):
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [], "RepoDigests": []}
        def scanner(iid):
            if iid == NEW:
                self.docker.move_tag(self.docker.ref, OTHER)
            return self.scans[iid]
        result = self.make_engine(scanner).update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OTHER)
        self.assertEqual(self.docker.up_calls, [])

    def test_external_tag_change_during_health_is_preserved(self):
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [], "RepoDigests": []}
        def after_up(iid, service):
            if iid == NEW:
                self.docker.move_tag(self.docker.ref, OTHER)
        self.docker.up_hook = after_up
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(result["actual_image_id"], OLD)
        self.assertEqual(result["source_tag_status"], "external_change_preserved")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OTHER)
        self.assertFalse(any(args[:2] == ["image", "tag"] and args[-1] == self.docker.ref
                             for args, _, _ in self.docker.calls))

    def test_failure_after_tag_commit_restores_original_tag(self):
        def broken_retention(*_args):
            raise LifecycleError("simulated state failure")
        self.engine._retain = broken_retention
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OLD)
        self.assertEqual(result["source_tag_status"], "restored")
        tag_changes = [args[2] for args, _, _ in self.docker.calls
                       if args[:2] == ["image", "tag"] and args[-1] == self.docker.ref]
        self.assertEqual(tag_changes, [NEW, OLD])
        self.assertEqual(self.engine.open_transactions(), [])

    def test_external_tag_change_after_commit_is_not_overwritten_by_restore(self):
        self.docker.images[OTHER] = {"Id": OTHER, "RepoTags": [], "RepoDigests": []}
        def after_tag(iid, reference):
            if iid == NEW and reference == self.docker.ref:
                self.docker.move_tag(self.docker.ref, OTHER)
        self.docker.tag_hook = after_tag
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertEqual(result["actual_image_id"], OLD)
        self.assertEqual(result["verification_status"], "ok")
        self.assertEqual(result["source_tag_status"], "conflict")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OTHER)
        tag_changes = [args[2] for args, _, _ in self.docker.calls
                       if args[:2] == ["image", "tag"] and args[-1] == self.docker.ref]
        self.assertEqual(tag_changes, [NEW])
        self.assertEqual(len(self.engine.open_transactions()), 1)

    def test_absent_original_tag_is_restored_to_absence_on_failure(self):
        self.docker.images[OLD]["RepoTags"] = ["manual-original:keep"]
        def broken_retention(*_args):
            raise LifecycleError("simulated state failure")
        self.engine._retain = broken_retention
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rolled_back")
        self.assertIsNone(self.docker.find_image(self.docker.ref))
        self.assertEqual(result["source_tag_status"], "restored")
        self.assertEqual(result["actual_image_id"], OLD)

    def test_base_file_change_after_first_service_blocks_next_start_and_restore(self):
        second = container("8" * 64, OLD, self.docker.ref, self.project, service="api")
        self.docker.containers[second["Id"]] = second
        self.docker.config["services"]["api"] = copy.deepcopy(self.docker.config["services"]["app"])
        def after_up(iid, service):
            if iid == NEW and service == "app":
                (self.project / "compose.yaml").write_text("external change after first start\n")
        self.docker.up_hook = after_up
        originals = [copy.deepcopy(c) for c in self.docker.containers.values()]
        result = self.engine.update_group(originals, source="local")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertEqual(len(self.docker.up_calls), 1)
        self.assertEqual(self.docker.up_calls[0][-1], "app")
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OLD)
        self.assertEqual(len(self.engine.open_transactions()), 1)

    def test_resolved_environment_change_blocks_commit_and_restore(self):
        marker = "PRIVATE_ENV_CHANGED_DURING_HEALTH"
        def after_up(iid, service):
            if iid == NEW:
                self.docker.config["services"]["app"]["environment"] = {"PRIVATE": marker}
        self.docker.up_hook = after_up
        result = self.engine.update_group(self.initial(), source="local")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertEqual(len(self.docker.up_calls), 1)
        self.assertEqual(self.docker.find_image(self.docker.ref)["Id"], OLD)
        self.assertNotIn(marker, json.dumps(result))
        self.assertFalse(any(marker in p.read_text() for p in self.state.rglob("*.json")))


class ComparisonTests(unittest.TestCase):
    def test_lower_count_with_new_critical_is_rejected(self):
        before = scan(OLD, [("A", "one", "HIGH", "1"), ("B", "two", "HIGH", "1")])
        after = scan(NEW, [("C", "three", "CRITICAL", "1")])
        result = compare_scans(before, after, before_id=OLD, after_id=NEW)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["new_count"], 1)

    def test_version_and_path_change_does_not_claim_fix(self):
        before = scan(OLD, [("A", "one", "HIGH", "1")])
        after = scan(NEW, [("A", "one", "HIGH", "2")])
        after["Results"][0]["Target"] = "renamed/path"
        result = compare_scans(before, after, before_id=OLD, after_id=NEW, require_improvement=True)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["fixed_count"], 0)

    def test_severity_escalation_is_rejected(self):
        result = compare_scans(scan(OLD, [("A", "one", "HIGH", "1")]),
                               scan(NEW, [("A", "one", "CRITICAL", "1")]))
        self.assertFalse(result["allowed"])
        self.assertEqual(result["escalated_count"], 1)

    def test_missing_or_invalid_severity_is_not_a_fix(self):
        for invalid in (None, "", "high", "unexpected", 0):
            with self.subTest(invalid=invalid):
                before = scan(OLD, [("A", "one", "HIGH", "1")])
                after = scan(NEW, [("A", "one", "HIGH", "2")])
                if invalid is None:
                    del after["Results"][0]["Vulnerabilities"][0]["Severity"]
                else:
                    after["Results"][0]["Vulnerabilities"][0]["Severity"] = invalid
                with self.assertRaises(LifecycleError):
                    compare_scans(before, after)


if __name__ == "__main__":
    unittest.main()
