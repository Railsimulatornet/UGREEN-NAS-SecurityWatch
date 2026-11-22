"""Berichtsaufbewahrung über alte und neue SecurityWatch-Fassungen hinweg."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from securitywatch_housekeeping import cleanup_reports


class ReportRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sw_report_retention_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self.current = self.reports / "2026-11-22_17-12-20"
        self.current.mkdir()
        self.now = datetime(2026, 11, 22, 18, tzinfo=ZoneInfo("Europe/Berlin")).timestamp()

    def legacy(self, stamp="2026-09-20_06-00-01", *, complete=True):
        folder = self.reports / stamp
        folder.mkdir()
        counts = {"total": 2, "critical": 1, "high": 1}
        summary = {"language": "de", **counts, "host": counts, "docker": counts,
                   "script_version": "4.0-rc19b", "scan": {"filesystem_scanned": True, "images_scanned": True},
                   "findings": []}
        (folder / "summary.json").write_text(json.dumps(summary))
        (folder / "mail.txt").write_text("UGREEN SecurityWatch Bericht\n\nKritisch gesamt: 1\n")
        date = stamp[:10]
        log = f"[{date} 06:00:01] SecurityWatch-Scan gestartet\nVersion: 4.0-rc19b\n"
        if complete:
            log += f"[{date} 06:08:21] SecurityWatch-Scan beendet\n"
        (folder / "scan.log").write_text(log)
        return folder

    def marked(self, stamp):
        folder = self.reports / stamp
        folder.mkdir()
        (folder / ".securitywatch-report").write_text("1\n")
        (folder / "run-status.json").write_text(json.dumps({"version": 1, "run": {
            "id": stamp, "status": "completed", "mode": "check",
            "finished_at": stamp[:10] + "T06:01:00+02:00"}}))
        return folder

    def test_original_and_marked_plain_and_hash_reports_expire(self):
        legacy = self.legacy()
        plain = self.marked("2026-09-21_06-00-00")
        hashed = self.marked("2026-09-22_06-00-00_abcdef")
        result = cleanup_reports(self.reports, self.current, days=30, keep_last=1, now=self.now)
        self.assertEqual(result["removed"], 3)
        self.assertTrue(self.current.exists())
        self.assertTrue(all(not path.exists() for path in (legacy, plain, hashed)))

    def test_minimum_count_uses_combined_original_and_current_formats(self):
        first = self.legacy()
        middle = self.marked("2026-09-21_06-00-00")
        newest = self.marked("2026-09-22_06-00-00_abcdef")
        result = cleanup_reports(self.reports, self.current, days=30, keep_last=3, now=self.now)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(first.exists())
        self.assertTrue(middle.exists())
        self.assertTrue(newest.exists())

    def test_unfinished_and_wrongly_identified_legacy_reports_remain(self):
        incomplete = self.legacy(complete=False)
        wrong_mail = self.legacy("2026-09-21_06-00-01")
        (wrong_mail / "mail.txt").write_text("Unrelated report\n")
        wrong_summary = self.legacy("2026-09-22_06-00-01")
        (wrong_summary / "summary.json").write_text('{"script_version":"4.1.1"}')
        unknown = self.reports / "2026-09-23_06-00-01"
        unknown.mkdir()
        (unknown / "precious.txt").write_text("keep")
        result = cleanup_reports(self.reports, self.current, days=30, keep_last=1, now=self.now)
        self.assertEqual(result["removed"], 0)
        self.assertTrue(all(path.exists() for path in (incomplete, wrong_mail, wrong_summary, unknown)))

    def test_expiry_uses_verified_completion_time_at_full_day_boundary(self):
        legacy = self.legacy()
        completion = datetime(2026, 9, 20, 6, 8, 21, tzinfo=ZoneInfo("Europe/Berlin")).timestamp()
        self.assertEqual(cleanup_reports(self.reports, self.current, days=30, keep_last=1,
                                        now=completion + 30 * 86400 - 1)["removed"], 0)
        self.assertEqual(cleanup_reports(self.reports, self.current, days=30, keep_last=1,
                                        now=completion + 30 * 86400)["removed"], 1)
        self.assertFalse(legacy.exists())

    def test_symlinks_never_adopt_or_delete_external_report_contents(self):
        external = self.root / "external"
        external.mkdir()
        (external / "keep.txt").write_text("keep")
        (self.reports / "2026-09-01_06-00-00").symlink_to(external, target_is_directory=True)
        legacy = self.legacy()
        (legacy / "nested-link").symlink_to(external, target_is_directory=True)
        with_linked_summary = self.legacy("2026-09-21_06-00-01")
        actual_summary = self.root / "summary.json"
        (with_linked_summary / "summary.json").replace(actual_summary)
        (with_linked_summary / "summary.json").symlink_to(actual_summary)
        result = cleanup_reports(self.reports, self.current, days=30, keep_last=1, now=self.now)
        self.assertEqual(result["removed"], 1)
        self.assertTrue((external / "keep.txt").exists())
        self.assertTrue(with_linked_summary.exists())
        self.assertTrue(actual_summary.exists())

    def test_zero_days_disables_automatic_expiry(self):
        old = self.legacy()
        self.assertEqual(cleanup_reports(self.reports, self.current, days=0, keep_last=1,
                                        now=self.now)["removed"], 0)
        self.assertTrue(old.exists())


if __name__ == "__main__":
    unittest.main()
