import copy
import json
import ssl
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import securitywatch_mail as mail
import securitywatch_notifications as notices
import securitywatch_report as report


def complete_status():
    return {
        "version": 1,
        "run": {"id": "2026-11-22_06-00-00_test", "started_at": "2026-11-22T05:00:00+00:00", "finished_at": "2026-11-22T05:30:00+00:00", "status": "completed"},
        "scans": {
            "host": {"status": "disabled"},
            "images": {"status": "ok", "expected": 1, "succeeded": 1, "failed": 0, "items": [{"image_id": "sha256:" + "a" * 64, "status": "ok", "file": "image_example.json"}]},
        },
        "events": [],
        "retention": {"days": 7, "protected": 2, "removed": 0, "errors": []},
        "github": {"status": "disabled"},
    }


def empty_summary(status=None):
    return {"total": 0, "critical": 0, "high": 0, "findings": [], "host": {"total": 0}, "docker": {"total": 0}, "script_version": "4.1.0", "run_status": status if status is not None else complete_status()}


def scan_doc(cve=None):
    result = {"Target": "requirements.txt", "Type": "pip", "Vulnerabilities": []}
    if cve:
        result["Vulnerabilities"] = [{"VulnerabilityID": cve, "PkgName": "example", "InstalledVersion": "1.0", "FixedVersion": "1.1", "Severity": "HIGH"}]
    return {"SchemaVersion": 2, "ArtifactName": "example:1", "ArtifactType": "container_image", "Results": [result]}


class DocumentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []
        self.external = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "iframe", "link", "img"}:
            self.external.append(tag)
        if tag not in {"meta", "br", "hr", "img", "link", "input"}:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(tag)
        else:
            self.stack.pop()


class NotificationTests(unittest.TestCase):
    def test_local_error_without_findings_forces_mail(self):
        summary = empty_summary()
        summary["run_status"]["events"] = [{"kind": "local", "status": "build_failed", "service": "ticket-desk", "message": "Die Bauanleitung konnte nicht ausgeführt werden."}]
        decision = notices.mail_decision(summary, {"MAIL_ONLY_ON_FINDINGS": "1", "MAIL_SEND_OK": "0", "MAIL_SEND_ON_IMAGE_UPDATES": "0"})
        self.assertTrue(decision["send"])
        self.assertTrue(decision["required"])
        self.assertIn("Handlung erforderlich", decision["subject"])
        self.assertIn("ticket-desk", notices.render_text(decision["model"]))

    def test_legacy_local_failure_included(self):
        summary = empty_summary({})
        summary["local_built_image_rebuild_results"] = [{"result": "rollback_failed", "service": "example", "detail": "SECRET_RAW_ERROR"}]
        model = notices.build_model(summary)
        self.assertEqual(model["error_count"], 1)
        rendered = notices.render_html(model)
        self.assertIn("nicht vollständig wiederhergestellt", rendered)
        self.assertNotIn("SECRET_RAW_ERROR", rendered)

    def test_legacy_zero_findings_is_not_green(self):
        decision = notices.mail_decision(empty_summary({}))
        self.assertTrue(decision["required"])
        self.assertFalse(decision["model"]["complete"])
        self.assertIn("unvollständig", decision["subject"])

    def test_success_without_events_obeys_mail_policy(self):
        decision = notices.mail_decision(empty_summary(), {"MAIL_ONLY_ON_FINDINGS": "1", "MAIL_SEND_OK": "0"})
        self.assertTrue(decision["model"]["complete"])
        self.assertFalse(decision["send"])
        summary = empty_summary()
        summary["run_status"]["run"]["weekly_summary"] = True
        self.assertTrue(notices.mail_decision(summary)["send"])

    def test_retention_error_and_early_run_failure_are_reported(self):
        summary = empty_summary()
        summary["run_status"]["retention"]["errors"] = ["PRIVATE_RAW_EXCEPTION"]
        summary["run_status"]["run"].update(status="failed", error="PRIVATE_RAW_EXCEPTION")
        decision = notices.mail_decision(summary)
        self.assertTrue(decision["required"])
        self.assertEqual(decision["model"]["error_count"], 2)
        content = notices.render_html(decision["model"])
        self.assertIn("Aufbewahrung", content)
        self.assertNotIn("PRIVATE_RAW_EXCEPTION", content)

    def test_wrong_coverage_counts_are_not_green(self):
        summary = empty_summary()
        summary["run_status"]["scans"]["images"]["expected"] = 2
        self.assertFalse(notices.build_model(summary)["complete"])

    def test_active_github_failure_and_missing_manifest_are_incomplete(self):
        summary = empty_summary()
        summary["run_status"]["github"]["status"] = "partial"
        self.assertFalse(notices.build_model(summary)["complete"])
        summary = empty_summary()
        del summary["run_status"]["scans"]["images"]["items"]
        self.assertFalse(notices.build_model(summary)["complete"])

    def test_available_update_stays_visible_when_event_calls_it_info(self):
        summary = empty_summary()
        summary["run_status"]["events"] = [{"kind": "registry", "status": "update_available", "severity": "info", "image": "example:1", "message": "Eine neue Version ist verfügbar.", "action": "Die freigegebene Versionslinie prüfen."}]
        decision = notices.mail_decision(summary)
        self.assertTrue(decision["send"])
        self.assertEqual(decision["model"]["notice_count"], 1)

    def test_missing_and_disabled_checks_not_success(self):
        summary = empty_summary()
        summary["run_status"]["scans"]["images"] = {"status": "disabled"}
        model = notices.build_model(summary)
        self.assertFalse(model["complete"])
        self.assertTrue(any("keine Sicherheitsprüfung" in line for line in model["coverage"]))

    def test_escaping_size_and_safe_links(self):
        summary = empty_summary()
        for index in range(60):
            summary["run_status"]["events"].append({"kind": "local", "status": "update_applied" if index % 2 else "build_failed", "severity": "warning", "service": f"{index}-" + "<&\"" * 1000, "message": "<&\"" * 1000, "action": "<&\"" * 1000, "url": "javascript:alert(1)"})
        document = notices.render_html(notices.build_model(summary))
        parser = DocumentParser()
        parser.feed(document)
        self.assertEqual(parser.errors, [])
        self.assertEqual(parser.stack, [])
        self.assertEqual(parser.external, [])
        self.assertNotIn("javascript:", document)
        self.assertIn("&lt;&amp;&quot;", document)
        self.assertLess(len(document.encode("utf-8")), 60_000)
        self.assertEqual(notices.safe_url("https://user:password@example.org/path"), "")
        self.assertEqual(notices.safe_url("https://github.com/org/repo/actions/runs/1?token=secret"), "https://github.com/org/repo/actions/runs/1")

    def test_same_vulnerability_is_not_two_distinct_identifiers(self):
        summary = empty_summary()
        summary.update(total=2, high=2, findings=[{"cve": "CVE-2026-12345", "source": "one"}, {"cve": "CVE-2026-12345", "source": "two"}])
        model = notices.build_model(summary)
        self.assertEqual(model["total"], 2)
        self.assertEqual(model["distinct"], 1)
        self.assertEqual(model["distinct_cves"], 1)

    def test_duplicate_package_keeps_highest_reported_severity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            doc = scan_doc("CVE-2026-12345")
            second = copy.deepcopy(doc["Results"][0])
            second["Vulnerabilities"][0]["Severity"] = "CRITICAL"
            doc["Results"].append(second)
            path = root / "image_example.json"
            path.write_text(json.dumps(doc))
            findings, _, raw_total = report.collect_findings(root, [path])
            self.assertEqual(raw_total, 2)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_rebuilt_candidate_does_not_replace_running_finding_counts(self):
        summary = empty_summary()
        summary["run_status"]["image_outcomes"] = [{
            "image": "local/example:1", "services": ["watcher"],
            "build_status": "succeeded", "deployment_status": "kept_previous", "verification_status": "not_run",
            "before": {"critical": 1, "high": 2, "total": 3, "fixable": 2},
            "candidate": {"critical": 0, "high": 0, "total": 0, "fixable": 0},
            "after": {"critical": 1, "high": 2, "total": 3, "fixable": 2},
            "comparison_scope": "candidate", "resolved": 3, "new": 0, "remaining": 0,
            "message": "Die erforderliche Startprüfung fehlt.",
        }]
        decision = notices.mail_decision(summary)
        plain = notices.render_text(decision["model"])
        document = notices.render_html(decision["model"])
        self.assertTrue(decision["send"])
        self.assertIn("Neubau: erfolgreich", plain)
        self.assertIn("bisherige Version beibehalten", plain)
        self.assertIn("Geprüfter Kandidat: 0 kritisch", plain)
        self.assertIn("Tatsächlich laufende Version: 1 kritisch", plain)
        self.assertIn("weiterhin Sicherheitsbefunde", document)
        self.assertNotIn("Im geprüften laufenden Image wurden keine", plain)

    def test_updated_image_reports_remaining_unfixed_findings(self):
        summary = empty_summary()
        summary["run_status"]["image_outcomes"] = [{
            "image": "local/example:1", "services": ["watcher"],
            "build_status": "succeeded", "deployment_status": "applied", "verification_status": "ok",
            "before": {"critical": 1, "high": 2, "total": 3, "fixable": 2},
            "candidate": {"critical": 0, "high": 1, "total": 1, "fixable": 0},
            "after": {"critical": 0, "high": 1, "total": 1, "fixable": 0},
            "resolved": 2, "new": 0, "remaining": 1,
        }]
        decision = notices.mail_decision(summary)
        plain = notices.render_text(decision["model"])
        self.assertIn("1 Image aktualisiert", decision["subject"])
        self.assertIn("keine korrigierte Paketversion", plain)
        self.assertIn("2 behoben · 0 neu · 1 weiterhin vorhanden", plain)
        self.assertNotIn("Geprüfter Kandidat:", plain)

    def test_image_outcome_failure_alone_forces_mail(self):
        summary = empty_summary()
        summary["run_status"]["image_outcomes"] = [{"image": "local/example:1", "build_status": "failed", "deployment_status": "kept_previous", "verification_status": "not_run"}]
        self.assertTrue(notices.mail_decision(summary, {"MAIL_SEND_ON_IMAGE_UPDATES": "0"})["required"])

    def test_many_long_image_outcomes_stay_bounded(self):
        summary = empty_summary()
        summary["run_status"]["image_outcomes"] = [{"image": str(index) + "<&" * 200, "services": ["<&" * 200], "build_status": "succeeded", "deployment_status": "kept_previous", "verification_status": "not_run", "message": "<&" * 200, "action": "<&" * 200} for index in range(80)]
        document = notices.render_html(notices.build_model(summary))
        self.assertLess(len(document.encode("utf-8")), 60_000)
        self.assertIn("Weitere", document)
        self.assertIn("vollständigen Liste", document)

    def test_missing_or_invalid_scan_file_changes_report_status(self):
        for value in (None, "not json", "{}", "[]", '{"SchemaVersion":2,"Results":"invalid"}'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                status = complete_status()
                if value is not None:
                    (root / "image_example.json").write_text(value)
                paths, errors = report.validated_scan_paths(root, status)
                self.assertEqual(paths, [])
                self.assertEqual(len(errors), 1)
                self.assertEqual(status["run"]["status"], "partial")
                self.assertEqual(status["scans"]["images"]["failed"], 1)
                summary = empty_summary(status)
                summary["report_validation_errors"] = errors
                self.assertTrue(notices.mail_decision(summary)["required"])

    def test_manifest_prevents_stale_results_and_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "image_example.json").write_text(json.dumps(scan_doc()))
            (root / "image_stale.json").write_text(json.dumps(scan_doc("CVE-2026-11111")))
            paths, errors = report.validated_scan_paths(root, complete_status())
            findings, _, _ = report.collect_findings(root, paths)
            self.assertEqual(errors, [])
            self.assertEqual(findings, [])
            status = complete_status()
            status["scans"]["images"]["items"][0]["file"] = "../outside.json"
            paths, errors = report.validated_scan_paths(root, status)
            self.assertEqual(paths, [])
            self.assertEqual(len(errors), 1)

    def test_report_cli_produces_consistent_short_and_full_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = complete_status()
            status["scans"]["images"].update(expected=2, succeeded=2)
            status["scans"]["images"]["items"].append({"image_id": "sha256:" + "b" * 64, "status": "ok", "file": "image_second.json"})
            (root / "run-status.json").write_text(json.dumps(status))
            (root / "images_map.tsv").write_text("example\texample:1\nsecond\tsecond:1\n")
            for filename in ("image_example.json", "image_second.json"):
                (root / filename).write_text(json.dumps(scan_doc("CVE-2026-12345")))
            result = subprocess.run([sys.executable, str(ROOT / "securitywatch_report.py"), "--run-dir", str(root), "--summary-json", str(root / "summary.json"), "--mail-txt", str(root / "mail.txt"), "--mail-html", str(root / "mail.html"), "--script-version", "4.1.0"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["distinct_vulnerability_ids"], 1)
            self.assertTrue(summary["scan"]["complete"])
            self.assertTrue((root / "bericht.html").is_file())
            self.assertTrue((root / "bericht.txt").is_file())
            self.assertLess((root / "mail.html").stat().st_size, 60_000)
            self.assertIn("Paketfunde", (root / "mail.txt").read_text())
            self.assertIn("1 verschiedene Schwachstellenkennungen", (root / "mail.txt").read_text())

    def test_render_only_does_not_open_smtp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "env").write_text("MAIL_ONLY_ON_FINDINGS=1\n")
            (root / "summary.json").write_text(json.dumps(empty_summary({})))
            argv = ["mail", "--env-file", str(root / "env"), "--summary-json", str(root / "summary.json"), "--mail-txt", str(root / "absent.txt"), "--mail-html", str(root / "absent.html"), "--render-only"]
            with patch.object(sys, "argv", argv), patch.object(mail.smtplib, "SMTP") as smtp, patch.object(mail.smtplib, "SMTP_SSL") as smtp_ssl, patch("builtins.print") as output:
                mail.main()
            smtp.assert_not_called()
            smtp_ssl.assert_not_called()
            self.assertTrue(json.loads(output.call_args[0][0])["required"])

    def test_suppressed_mail_records_skipped_without_smtp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "env").write_text("MAIL_ONLY_ON_FINDINGS=1\nMAIL_SEND_OK=0\n")
            (root / "summary.json").write_text(json.dumps(empty_summary()))
            delivery = root / "mail-delivery.json"
            argv = ["mail", "--env-file", str(root / "env"), "--summary-json", str(root / "summary.json"), "--mail-txt", str(root / "absent.txt"), "--mail-html", str(root / "absent.html"), "--result-json", str(delivery)]
            with patch.object(sys, "argv", argv), patch.object(mail.smtplib, "SMTP") as smtp, patch("builtins.print"):
                mail.main()
            smtp.assert_not_called()
            self.assertEqual(json.loads(delivery.read_text())["status"], "skipped")

    def test_smtp_tls_validates_certificates_and_preserves_text_alternative(self):
        env = {"SMTP_SERVER": "mail.example.invalid", "SMTP_FROM": "a@example.invalid", "SMTP_TO": "b@example.invalid", "SMTP_STARTTLS": "1"}
        message = mail.create_message(env, "Prüfung", "Klartext", "<p>HTML</p>")
        self.assertEqual(message.get_content_type(), "multipart/alternative")
        self.assertEqual([p.get_content_type() for p in message.iter_parts()], ["text/plain", "text/html"])
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with patch.object(mail.smtplib, "SMTP", return_value=smtp):
            mail.send_message(env, message)
        context = smtp.starttls.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        smtp.send_message.assert_called_once_with(message)

    def test_smtp_implicit_tls_uses_verified_context(self):
        env = {"SMTP_SERVER": "mail.example.invalid", "SMTP_FROM": "a@example.invalid", "SMTP_TO": "b@example.invalid", "SMTP_PORT": "465"}
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with patch.object(mail.smtplib, "SMTP_SSL", return_value=smtp) as factory, patch.object(mail.smtplib, "SMTP") as plaintext:
            mail.send_message(env, mail.create_message(env, "Test", "Text", "<p>Text</p>"))
        plaintext.assert_not_called()
        smtp.starttls.assert_not_called()
        self.assertTrue(factory.call_args.kwargs["context"].check_hostname)


if __name__ == "__main__":
    unittest.main()
