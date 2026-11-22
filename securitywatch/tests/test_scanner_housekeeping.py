import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from securitywatch_scanner import ScanError, TrivyScanner, validate_scan, findings
from securitywatch_housekeeping import cleanup_reports, host_package_inventory

IID = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def image_document():
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": IID},
            "Results": [{"Type": "pip", "Target": "application", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2026-12345", "PkgName": "sample", "Severity": "HIGH",
                 "InstalledVersion": "1", "FixedVersion": "2"}]}]}


class ScanTests(unittest.TestCase):
    def test_wrong_image_or_incomplete_finding_never_becomes_zero(self):
        with self.assertRaises(ScanError):
            validate_scan(image_document(), OTHER)
        for field, value in (("Severity", None), ("Severity", "incorrect"), ("PkgName", 8),
                             ("FixedVersion", {}), ("InstalledVersion", [])):
            doc = image_document()
            doc["Results"][0]["Vulnerabilities"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ScanError):
                validate_scan(doc, IID)

    def test_versions_and_paths_do_not_disguise_remaining_vulnerability(self):
        before, after = image_document(), image_document()
        after["Results"][0]["Target"] = "another/path"
        after["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "1.1"
        self.assertEqual(findings(before), findings(after))

    def test_same_id_is_scanned_once_and_only_scanner_container_is_cleaned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            calls = []
            def runner(args, **_):
                calls.append(args)
                if args[0] == "run":
                    output = args[args.index("--output") + 1]
                    path = root / output.removeprefix("/reports/")
                    path.write_text(json.dumps(image_document()), encoding="utf-8")
                return subprocess.CompletedProcess(args, 0, "", "")
            scanner = TrivyScanner(runner, {"CACHE_DIR": str(root / "cache")}, root, root, lambda _: None)
            scanner.scanner_id, scanner.scratch = OTHER, root / "database"
            scanner.scan_image(IID)
            scanner.scan_image(IID)
            run_calls = [args for args in calls if args[0] == "run"]
            self.assertEqual(len(run_calls), 1)
            self.assertIn("--offline-scan", run_calls[0])
            self.assertIn("--skip-db-update", run_calls[0])
            self.assertIn(f"{scanner.scratch}:/root/.cache/trivy:ro", run_calls[0])
            self.assertEqual(run_calls[0][-1], IID)
            rm = [args for args in calls if args[:2] == ["container", "rm"]]
            self.assertEqual(len(rm), 1)
            self.assertTrue(rm[0][-1].startswith("securitywatch-pruefung-"))

    def test_failed_command_does_not_adopt_a_stale_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "einzelpruefungen"
            folder.mkdir()
            (folder / ("a" * 64 + ".json")).write_text(json.dumps(image_document()))
            def runner(args, **_):
                return subprocess.CompletedProcess(args, 1, "", "failed")
            scanner = TrivyScanner(runner, {"CACHE_DIR": str(root / "cache")}, root, root, lambda _: None)
            scanner.scanner_id, scanner.scratch = OTHER, root / "database"
            with self.assertRaises(ScanError):
                scanner.scan_image(IID)
            self.assertEqual(scanner.documents, {})


class HousekeepingTests(unittest.TestCase):
    def test_only_marked_finished_old_reports_are_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            now = 2_000_000_000
            current = root / "2026-11-22_06-00-00_abcdef"
            current.mkdir()
            owned = root / "2026-01-01_06-00-00_abcdef"
            owned.mkdir()
            (owned / ".securitywatch-report").write_text("1\n")
            (owned / "run-status.json").write_text(json.dumps({"version": 1, "run": {
                "id": owned.name, "finished_at": datetime.fromtimestamp(now - 31 * 86400, timezone.utc).isoformat()}}))
            legacy = root / "2026-01-01_06-00-00"
            legacy.mkdir()
            unmarked = root / "2026-01-02_06-00-00_abcdef"
            unmarked.mkdir()
            result = cleanup_reports(root, current, days=30, keep_last=1, now=now)
            self.assertEqual(result["removed"], 1)
            self.assertFalse(owned.exists())
            self.assertTrue(legacy.exists())
            self.assertTrue(unmarked.exists())
            self.assertTrue(current.exists())

    def test_minimum_number_of_recent_reports_is_kept(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            current = root / "current"
            current.mkdir()
            for i in range(3):
                report = root / f"2026-01-0{i+1}_06-00-00_abcdef"
                report.mkdir()
                (report / ".securitywatch-report").write_text("1\n")
                (report / "run-status.json").write_text(json.dumps({"version": 1, "run": {
                    "id": report.name, "finished_at": f"2026-01-0{i+1}T06:00:00+00:00"}}))
            self.assertEqual(cleanup_reports(root, current, days=1, keep_last=3, now=2_000_000_000)["removed"], 1)
            self.assertEqual(len(list(root.iterdir())), 3)

    def test_package_inventory_is_read_only_and_respects_watchlist(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            def run(args, **_):
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, "openssl\t3.0.1\tamd64\tii \topenssl\nother\t1\tall\trc \tother\n", "")
            root = Path(temp)
            host_package_inventory(root, {"HOST_PACKAGE_WATCHLIST": "openssl"}, run)
            self.assertEqual(calls[0][0], "dpkg-query")
            self.assertEqual(len(calls), 1)
            self.assertIn("installed", (root / "host_package_watchlist.tsv").read_text())
            self.assertNotIn("other", (root / "host_package_watchlist.tsv").read_text())


if __name__ == "__main__":
    unittest.main()
