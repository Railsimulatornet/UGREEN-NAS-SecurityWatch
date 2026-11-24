"""Exercise mail configuration and TLS without an SMTP connection."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("securitywatch_mail", ROOT / "securitywatch/securitywatch_mail.py")
mail = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mail)


class MailTlsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.config = self.directory / "mail.env"
        self.summary = self.directory / "summary.json"
        self.summary.write_text(json.dumps({"total": 1, "high": 1}))
        (self.directory / "mail.txt").write_text("Test report")
        (self.directory / "mail.html").write_text("<p>Test report</p>")
        self.server = MagicMock()
        self.server.__enter__.return_value = self.server
        smtp = patch.object(mail.smtplib, "SMTP", return_value=self.server)
        self.smtp = smtp.start()
        self.addCleanup(smtp.stop)
        network = patch.object(socket, "create_connection", side_effect=AssertionError("No network in tests"))
        network.start()
        self.addCleanup(network.stop)

    def run_mail(self, *, tls="1", user="test-user"):
        self.config.write_text(
            f"SMTP_SERVER=smtp.example.test\nSMTP_FROM=from@example.test\nSMTP_TO=to@example.test\n"
            f"SMTP_USER={user}\nSMTP_PASS=test-password\nSMTP_STARTTLS={tls}\n")
        arguments = ["mail", "--env-file", str(self.config), "--summary-json", str(self.summary),
                     "--mail-txt", str(self.directory / "mail.txt"),
                     "--mail-html", str(self.directory / "mail.html")]
        with patch("sys.argv", arguments), contextlib.redirect_stdout(io.StringIO()):
            mail.main()

    def test_starttls_verifies_certificate_and_hostname_before_authentication(self):
        self.run_mail()
        context = self.server.starttls.call_args.kwargs.get("context")
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        calls = [call[0] for call in self.server.method_calls]
        self.assertLess(calls.index("starttls"), calls.index("login"))
        self.assertLess(calls.index("login"), calls.index("send_message"))

    def test_untrusted_or_wrong_hostname_certificate_stops_delivery(self):
        for reason in ("untrusted certificate", "hostname mismatch"):
            with self.subTest(reason=reason):
                self.server.reset_mock()
                self.server.starttls.side_effect = ssl.SSLCertVerificationError(reason)
                with self.assertRaises(ssl.SSLCertVerificationError):
                    self.run_mail()
                self.server.login.assert_not_called()
                self.server.send_message.assert_not_called()

    def test_explicit_plain_mode_is_preserved(self):
        self.run_mail(tls="0")
        self.server.starttls.assert_not_called()
        self.server.send_message.assert_called_once()

    def test_anonymous_mail_is_preserved(self):
        self.run_mail(user="")
        self.server.login.assert_not_called()
        self.server.send_message.assert_called_once()

    def test_no_findings_still_skips_mail(self):
        self.summary.write_text(json.dumps({"total": 0}))
        self.run_mail()
        self.smtp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
