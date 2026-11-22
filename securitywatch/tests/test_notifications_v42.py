"""Regressionen: Berichtsläufe müssen den laufenden Sicherheitsstand zeigen."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import securitywatch_notifications as notices
import securitywatch_report as report


def fixture():
    return {
        "total": 2, "critical": 1, "high": 1, "script_version": "4.2.0",
        "host": {"total": 1, "critical": 1, "high": 0},
        "docker": {"total": 1, "critical": 0, "high": 1},
        "sources": [
            {"group": "docker", "source": "Docker-Image: local/watcher:1", "file": "image_a.json", "unique_findings": 1},
            {"group": "docker", "source": "Docker-Image: clean:1", "file": "image_b.json", "unique_findings": 0},
        ],
        "findings": [
            {"group": "docker", "source": "Docker-Image: local/watcher:1", "source_file": "image_a.json", "cve": "CVE-2026-11111", "pkg": "example", "severity": "HIGH", "fixed": "2.0"},
            {"group": "host", "source": "NAS-Dateisystem", "source_file": "host_rootfs.json", "cve": "CVE-2026-22222", "pkg": "host-package", "installed": "1.0", "severity": "CRITICAL", "fixed": "1.1", "primary_url": "https://example.invalid/advisory"},
        ],
        "run_status": {
            "version": 1,
            "run": {"id": "2026-11-22_06-00-00", "mode": "report_only", "status": "completed", "finished_at": "2026-11-22T05:00:00+00:00"},
            "scans": {
                "host": {"status": "ok", "file": "host_rootfs.json"},
                "images": {"status": "ok", "expected": 2, "succeeded": 2, "failed": 0, "items": [
                    {"image_id": "sha256:" + "a" * 64, "file": "image_a.json", "status": "ok", "references": ["local/watcher:1"], "containers": ["watcher-one", "watcher-two"]},
                    {"image_id": "sha256:" + "b" * 64, "file": "image_b.json", "status": "ok", "references": ["clean:1"], "containers": ["clean"]},
                ]},
            },
            "events": [{"kind": "github", "status": "published_tag_mismatch", "severity": "warning", "project": "example/repo", "message": "Die veröffentlichte Version ist nicht zugeordnet."}],
            "image_outcomes": [], "github": {"status": "ok"},
            "maintenance": {"status": "ok", "items": [
                {"container": "watcher-one", "image_id": "sha256:" + "a" * 64, "image": "local/watcher:1", "eligible": True, "kind": "local", "reason": ""},
                {"container": "watcher-two", "image_id": "sha256:" + "a" * 64, "image": "local/watcher:1", "eligible": False, "kind": "local", "reason": "Eine Zustandsprüfung fehlt."},
                {"container": "clean", "image_id": "sha256:" + "b" * 64, "image": "clean:1", "eligible": True, "kind": "registry", "reason": ""},
            ]},
        },
    }


class CurrentSecurityTests(unittest.TestCase):
    def test_report_only_displays_container_counts_and_host_excerpt_without_outcomes(self):
        decision = notices.mail_decision(fixture())
        model = decision["model"]
        self.assertEqual(model["image_outcomes"], [])
        self.assertEqual(len(model["affected_images"]), 1)
        self.assertEqual(model["clean_images"], 1)
        self.assertEqual(model["affected_images"][0]["counts"], {"critical": 0, "high": 1, "total": 1, "fixable": 1})
        self.assertIn("1 kritische, 1 hohe Paketfunde", decision["subject"])
        for rendered in (notices.render_text(model), notices.render_html(model)):
            self.assertIn("watcher-one, watcher-two", rendered)
            self.assertIn("0 kritisch · 1 hoch · 1 mit bekannter Korrektur", rendered)
            self.assertIn("CVE-2026-22222", rendered)
            self.assertIn("keine Anwendungsimages neu gebaut oder ausgetauscht", rendered)
            self.assertIn("Eine Zustandsprüfung fehlt.", rendered)

    def test_shared_image_is_counted_once_and_blocker_is_visible(self):
        model = notices.build_model(fixture())
        self.assertEqual(len(model["image_security"]), 2)
        self.assertEqual(model["maintenance"]["local_eligible"], 1)
        self.assertEqual(model["maintenance"]["local_blocked"], 1)
        self.assertTrue(model["affected_images"][0]["blocked"])
        self.assertTrue(model["affected_images"][0]["local"])

    def test_separate_update_owner_has_its_own_label(self):
        summary = fixture()
        summary["run_status"]["maintenance"]["items"][1]["separate_update_path"] = True
        row = notices.build_model(summary)["affected_images"][0]
        lines = " ".join(notices.image_security_lines(row))
        self.assertIn("eigener Aktualisierungsweg", lines)
        self.assertNotIn("Austausch zurückgestellt", lines)

    def test_failed_scan_never_uses_stale_findings_as_success(self):
        summary = fixture()
        summary["run_status"]["scans"]["images"]["items"][0]["status"] = "failed"
        model = notices.build_model(summary)
        self.assertFalse(model["complete"])
        self.assertEqual(model["affected_images"][0]["counts"]["high"], None)
        self.assertIn("Sicherheitsstand unbekannt", notices.render_text(model))

    def test_missing_source_does_not_become_zero(self):
        summary = fixture()
        summary["sources"] = summary["sources"][:1]
        model = notices.build_model(summary)
        self.assertEqual(model["clean_images"], 0)
        self.assertEqual(len(model["affected_images"]), 2)
        self.assertEqual(model["affected_images"][0]["image"], "clean:1")

    def test_old_summary_uses_only_unambiguous_source_name(self):
        summary = fixture()
        del summary["findings"][0]["source_file"]
        self.assertEqual(notices.build_model(summary)["affected_images"][0]["counts"]["high"], 1)
        summary["sources"][1]["source"] = summary["sources"][0]["source"]
        self.assertEqual(notices.build_model(summary)["clean_images"], 0)

    def test_two_image_ids_with_one_display_tag_do_not_merge(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "images_map.tsv").write_text("a\tsame:latest\nb\tsame:latest\n")
            doc = {"SchemaVersion": 2, "ArtifactName": "same:latest", "Results": [{"Target": "deps", "Type": "pip", "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-11111", "PkgName": "example", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"}]}]}
            paths = [root / "image_a.json", root / "image_b.json"]
            for path in paths:
                path.write_text(json.dumps(doc))
            findings, sources, total = report.collect_findings(root, paths)
            self.assertEqual(total, 2)
            self.assertEqual(len(findings), 2)
            self.assertEqual({item["source_file"] for item in findings}, {"image_a.json", "image_b.json"})
            self.assertEqual([item["unique_findings"] for item in sources], [1, 1])

    def test_host_excerpt_groups_cve_packages_and_keeps_limit(self):
        summary = fixture()
        base = summary["findings"][1]
        summary["findings"].extend([dict(base, pkg="other-package"), *[dict(base, cve=f"CVE-2026-{30000+i}", pkg=f"package-{i}") for i in range(5)]])
        excerpt = notices.host_excerpt(summary)
        self.assertEqual(len(excerpt), 3)
        self.assertEqual(len({item["id"] for item in excerpt}), 3)
        self.assertIn("other-package", excerpt[0]["packages"])

    def test_host_excerpt_does_not_assign_one_packages_fix_to_another(self):
        summary = fixture()
        summary["findings"].append(dict(summary["findings"][1], pkg="unfixed-package", installed="9.0", fixed="-"))
        excerpt = notices.host_excerpt(summary)
        self.assertNotIn("unfixed-package", excerpt[0]["packages"])
        self.assertNotIn("9.0", excerpt[0]["versions"])
        self.assertTrue(excerpt[0]["additional_packages"])
        self.assertIn("Weitere betroffene Paketstände", " ".join(notices.host_excerpt_lines(excerpt[0])))

    def test_missing_maintenance_and_disabled_host_are_explicit(self):
        summary = fixture()
        summary["run_status"].pop("maintenance")
        summary["run_status"]["scans"]["host"]["status"] = "disabled"
        plain = notices.render_text(notices.build_model(summary))
        self.assertIn("nicht vollständig erfasst", plain)
        self.assertIn("Die NAS-Prüfung ist deaktiviert", plain)
        self.assertNotIn("CVE-2026-22222", plain)

    def test_buildable_local_image_is_not_counted_as_deployable(self):
        summary = fixture()
        for item in summary["run_status"]["maintenance"]["items"]:
            item["build_allowed"] = item["kind"] == "local"
        model = notices.build_model(summary)
        self.assertEqual(model["maintenance"]["local_buildable"], 2)
        self.assertEqual(model["maintenance"]["local_eligible"], 1)
        plain = notices.render_text(model)
        self.assertIn("2 Dienste neu baubar · 1 automatisch übernehmbar", plain)
        self.assertIn("repariert den laufenden Dienst noch nicht", plain)

    def test_report_retention_counts_and_deferral_are_distinct(self):
        for state, expected in [
            ({"status": "ok", "days": 30, "keep_last": 10, "removed": 2}, "mindestens die letzten 10 Läufe. Bei diesem Lauf entfernt: 2"),
            ({"status": "deferred", "removed": 0}, "wegen einer noch offenen Wiederherstellung zurückgestellt"),
            ({"status": "partial", "removed": 1, "errors": 2}, "Berichtsbereinigung unvollständig: 1 entfernt; 2 Vorgänge"),
        ]:
            with self.subTest(state=state):
                summary = fixture()
                summary["run_status"]["report_retention"] = state
                plain = notices.render_text(notices.build_model(summary))
                self.assertIn(expected, plain)

    def test_name_metacharacters_are_escaped(self):
        summary = fixture()
        summary["run_status"]["scans"]["images"]["items"][0]["containers"] = ["<script>example</script>"]
        content = notices.render_html(notices.build_model(summary))
        self.assertNotIn("<script>", content)
        self.assertIn("&lt;script&gt;example&lt;/script&gt;", content)


if __name__ == "__main__":
    unittest.main()
