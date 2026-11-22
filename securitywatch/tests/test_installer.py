import fcntl
import hashlib
import json
import os
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install_securitywatch as installer


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="securitywatch_installer_test_")
        self.root = Path(self.temp.name)
        self.package = self.root / "package"
        self.target = self.root / "securitywatch"
        self.package.mkdir()
        self.target.mkdir()
        self.old_program = b"VALUE = 'old'\n"
        self.new_program = b"VALUE = 'new'\n"
        (self.target / "securitywatch.py").write_bytes(self.old_program)
        (self.target / ".env").write_text("SMTP_PASS=DO_NOT_CHANGE_SECRET\n")
        (self.target / "securitywatch.local-images").write_text("my-custom-image:*\n")
        state = self.target / "state"
        state.mkdir()
        (state / "deployments").mkdir()
        (state / "deployments" / "pins.json").write_text('{"keep":"current-images"}')
        self.package_files = {
            "securitywatch.py": self.new_program,
            "securitywatch_extra.py": b"EXTRA = True\n",
            "securitywatch.local-images": b"package-default:*\n",
        }
        self.write_package()
        self.running_patch = patch.object(installer, "_legacy_running", return_value=[])
        self.running_patch.start()

    def tearDown(self):
        self.running_patch.stop()
        self.temp.cleanup()

    def write_package(self):
        for name, data in self.package_files.items():
            (self.package / name).write_bytes(data)
        self.manifest = {"version": "4.1.0", "files": {k: hashlib.sha256(v).hexdigest() for k, v in self.package_files.items()},
                         "install_files": list(self.package_files)}
        (self.package / "manifest.json").write_text(json.dumps(self.manifest))

    def install(self):
        return installer.install(self.package, self.target, check_dependencies=False)

    def assert_preserved(self):
        self.assertEqual("SMTP_PASS=DO_NOT_CHANGE_SECRET\n", (self.target / ".env").read_text())
        self.assertEqual("my-custom-image:*\n", (self.target / "securitywatch.local-images").read_text())
        self.assertEqual('{"keep":"current-images"}', (self.target / "state" / "deployments" / "pins.json").read_text())

    def test_check_is_read_only(self):
        before = sorted(str(p.relative_to(self.target)) for p in self.target.rglob("*"))
        result = installer.check_installation(self.package, self.target, check_dependencies=False)
        self.assertFalse(result["installed"])
        self.assertEqual(before, sorted(str(p.relative_to(self.target)) for p in self.target.rglob("*")))
        self.assertFalse((self.target.parent / "securitywatch-backups").exists())

    def test_dependency_check_requires_buildx_inspection(self):
        outputs = ["29.6.2", "5.1.3", "--no-build --pull --no-deps --force-recreate", "--format", "buildx v0.30", "--format", "--builder"]
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout=outputs[len(calls) - 1])

        with patch.object(installer.shutil, "which", return_value="/usr/bin/docker"), patch.object(installer.subprocess, "run", side_effect=run):
            self.assertEqual(4, len(installer._dependencies()))
        self.assertEqual(["buildx", "imagetools", "inspect", "--help"], calls[-2][3:])
        self.assertEqual(["compose", "build", "--help"], calls[-1][3:])

        outputs[-1] = "inspect without structured format support"
        calls.clear()
        with patch.object(installer.shutil, "which", return_value="/usr/bin/docker"), patch.object(installer.subprocess, "run", side_effect=run):
            with self.assertRaises(installer.InstallError):
                installer._dependencies()

    def test_install_backup_restore_preserve_configuration_and_pins(self):
        result = self.install()
        self.assertEqual(self.new_program, (self.target / "securitywatch.py").read_bytes())
        self.assert_preserved()
        backup = Path(result["backup"])
        self.assertEqual(self.target.parent / "securitywatch-backups", backup.parent)
        self.assertEqual(0o700, stat.S_IMODE(backup.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((backup / "files" / ".env").stat().st_mode))
        (self.target / ".env").write_text("SMTP_PASS=NEW_CURRENT_SECRET\n")
        restored = installer.restore(backup, self.target)
        self.assertTrue(restored["restored"])
        self.assertEqual(self.old_program, (self.target / "securitywatch.py").read_bytes())
        self.assertFalse((self.target / "securitywatch_extra.py").exists())
        self.assertEqual("SMTP_PASS=NEW_CURRENT_SECRET\n", (self.target / ".env").read_text())
        self.assertEqual('{"keep":"current-images"}', (self.target / "state" / "deployments" / "pins.json").read_text())
        self.assertEqual("restored", json.loads((self.target / "state" / "securitywatch-install.json").read_text())["phase"])

    def test_corrupt_package_rejected_before_backup_or_code_change(self):
        (self.package / "securitywatch.py").write_text("VALUE='tampered'\n")
        with self.assertRaises(installer.InstallError):
            self.install()
        self.assertEqual(self.old_program, (self.target / "securitywatch.py").read_bytes())
        self.assertFalse((self.target.parent / "securitywatch-backups").exists())
        self.assert_preserved()

    def test_syntax_error_names_line_and_runtime_before_any_installation_change(self):
        self.package_files["securitywatch.py"] = b"VALUE = 1\nif\n"
        self.write_package()
        with self.assertRaises(installer.InstallError) as failure:
            self.install()
        message = str(failure.exception)
        self.assertIn("securitywatch.py, Zeile 2", message)
        self.assertIn("Python " + ".".join(str(n) for n in sys.version_info[:3]), message)
        self.assertIn("nicht verändert", message)
        self.assertNotIn("VALUE = 1", message)
        self.assertFalse((self.target.parent / "securitywatch-backups").exists())
        self.assertFalse((self.target / "state" / "securitywatch-install.json").exists())
        self.assertEqual(self.old_program, (self.target / "securitywatch.py").read_bytes())
        self.assert_preserved()

    def test_replace_failure_rolls_back_program_set(self):
        real_replace = installer.os.replace
        failed = False
        def replace(source, dest):
            nonlocal failed
            if Path(dest) == self.target / "securitywatch_extra.py" and not failed:
                failed = True
                raise OSError("simulated write error")
            return real_replace(source, dest)
        with patch.object(installer.os, "replace", side_effect=replace):
            with self.assertRaises(installer.InstallError):
                self.install()
        self.assertEqual(self.old_program, (self.target / "securitywatch.py").read_bytes())
        self.assertFalse((self.target / "securitywatch_extra.py").exists())
        self.assertEqual("rolled_back", json.loads((self.target / "state" / "securitywatch-install.json").read_text())["phase"])
        self.assert_preserved()

    def test_running_process_and_lock_prevent_install(self):
        with patch.object(installer, "_legacy_running", return_value=[123]):
            with self.assertRaises(installer.InstallError):
                self.install()
        lock = self.target / "state" / "securitywatch.lock"
        with lock.open("w") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(installer.InstallError):
                self.install()
        self.assertEqual(self.old_program, (self.target / "securitywatch.py").read_bytes())

    def test_pending_or_corrupt_journal_prevents_install(self):
        journal = self.target / "state" / "securitywatch-install.json"
        for text in ('{"schema_version":1,"phase":"installing"}', '{broken'):
            journal.write_text(text)
            with self.assertRaises(installer.InstallError):
                self.install()
            with self.assertRaises(installer.InstallError):
                installer.check_installation(self.package, self.target, check_dependencies=False)
        self.assertEqual(self.old_program, (self.target / "securitywatch.py").read_bytes())

    def test_restore_refuses_unrelated_later_edit(self):
        result = self.install()
        (self.target / "securitywatch.py").write_text("VALUE='user-change'\n")
        with self.assertRaises(installer.InstallError):
            installer.restore(Path(result["backup"]), self.target)
        self.assertEqual("VALUE='user-change'\n", (self.target / "securitywatch.py").read_text())

    def test_backup_checksum_mismatch_refuses_restore(self):
        result = self.install()
        backup = Path(result["backup"])
        (backup / "files" / "securitywatch.py").write_text("VALUE='corrupt'\n")
        with self.assertRaises(installer.InstallError):
            installer.restore(backup, self.target)
        self.assertEqual(self.new_program, (self.target / "securitywatch.py").read_bytes())

    def test_path_traversal_and_symlink_rejected(self):
        self.manifest["files"]["../outside"] = "0" * 64
        (self.package / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaises(installer.InstallError):
            self.install()
        self.write_package()
        (self.target / "securitywatch.py").unlink()
        outside = self.root / "outside.py"
        outside.write_text("KEEP=True\n")
        (self.target / "securitywatch.py").symlink_to(outside)
        with self.assertRaises(installer.InstallError):
            self.install()
        self.assertEqual("KEEP=True\n", outside.read_text())

    def test_state_dir_known_variable_only(self):
        (self.target / ".env").write_text('STATE_DIR="${SCRIPT_DIR}/state"\n')
        self.assertEqual(self.target / "state", installer.state_directory(self.target))
        (self.target / ".env").write_text('STATE_DIR="$(touch /tmp/should-never-exist)"\n')
        with self.assertRaises(installer.InstallError):
            installer.state_directory(self.target)

    def test_entrypoint_first_and_racing_legacy_process_aborts(self):
        original_entry = b"#!/bin/bash\necho old\n"
        (self.target / "securitywatch_scan.sh").write_bytes(original_entry)
        # Im Paket absichtlich zuletzt, der Installer muss den Einstieg vorziehen.
        self.package_files["securitywatch_scan.sh"] = b"#!/bin/bash\necho new\n"
        self.write_package()
        observed = []
        real_replace = installer.os.replace
        def replace(source, dest):
            if Path(dest).parent == self.target:
                observed.append(Path(dest).name)
            return real_replace(source, dest)
        with patch.object(installer.os, "replace", side_effect=replace):
            with patch.object(installer, "_legacy_running", side_effect=[[], [], [123]]):
                with self.assertRaises(installer.InstallError):
                    self.install()
        self.assertEqual(["securitywatch_scan.sh", "securitywatch_scan.sh"], observed)
        self.assertEqual(original_entry, (self.target / "securitywatch_scan.sh").read_bytes())
        self.assertEqual(self.old_program, (self.target / "securitywatch.py").read_bytes())

    def test_legacy_detection_matches_exact_paths_not_substrings(self):
        proc = self.root / "proc"
        proc.mkdir()
        for pid, args in (("123", ["bash", str(self.target / "securitywatch_scan.sh")]),
                          ("124", ["bash", str(self.target / "securitywatch_scan.sh.old")]),
                          ("125", ["sh", "-c", str(self.target / "securitywatch_scan.sh") + " --no-mail"]),
                          ("126", ["bash", "./securitywatch_scan.sh"])):
            process = proc / pid
            process.mkdir()
            (process / "cmdline").write_bytes(b"\0".join(s.encode() for s in args) + b"\0")
            (process / "cwd").symlink_to(self.target)
        self.running_patch.stop()
        try:
            self.assertEqual([123, 125, 126], sorted(installer._legacy_running(self.target, proc)))
        finally:
            self.running_patch.start()


if __name__ == "__main__":
    unittest.main()
