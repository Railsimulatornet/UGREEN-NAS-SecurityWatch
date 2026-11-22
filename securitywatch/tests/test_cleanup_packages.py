"""Nur bekannte alte Pakete entfernen, aktive oder fremde Daten erhalten."""
import hashlib
import json
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import securitywatch_cleanup as cleanup
from securitywatch_common import RunLock, ConfigurationError


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PackageCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sw_package_cleanup_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.live = self.root / "securitywatch"
        self.live.mkdir()
        self.package = self.root / "securitywatch-update-4.2.0"
        self.package.mkdir()
        self.state = self.live / "state"
        self.state.mkdir()
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self.backups = self.root / "securitywatch-backups"
        self.backups.mkdir()
        (self.reports / "keep.txt").write_text("report")
        (self.backups / "keep.txt").write_text("backup")
        (self.state / "keep.txt").write_text("state")
        self.env = f"STATE_DIR={self.state}\nREPORT_DIR={self.reports}\nSMTP_PASSWORD=private-value\n"
        (self.live / ".env").write_text(self.env)
        files = {}
        for name in cleanup.CORE_PROGRAMS:
            data = b"#!/usr/bin/env bash\nexit 0\n" if name.endswith(".sh") else b"# verified current fixture\n"
            (self.package / name).write_bytes(data)
            (self.live / name).write_bytes(data)
            files[name] = digest(data)
        data = b'{"default":true}\n'
        (self.package / "securitywatch.github.json").write_bytes(data)
        files["securitywatch.github.json"] = digest(data)
        (self.live / "securitywatch.github.json").write_text('{"custom":true}\n')
        (self.package / "manifest.json").write_text(json.dumps({
            "version": "4.2.0", "files": files, "install_files": sorted(files)}))
        self.known = dict(cleanup.KNOWN_OLD_MANIFESTS)
        self.patch = patch.dict(cleanup.KNOWN_OLD_MANIFESTS, {}, clear=True)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.cleaner = cleanup.PackageCleaner(self.package, root=self.root)

    def old(self, version="4.1.1"):
        folder = self.root / ("securitywatch-update-" + version)
        folder.mkdir()
        (folder / "tests").mkdir()
        content = {"securitywatch_common.py": (f"VERSION = '{version}'\n").encode(),
                   "README_DE.md": b"Old package fixture\n", "tests/test_old.py": b"# old test\n"}
        for name, data in content.items():
            (folder / name).write_bytes(data)
        manifest = json.dumps({"version": version, "files": {name: digest(data) for name, data in content.items()},
                               "install_files": ["securitywatch_common.py"]}).encode()
        (folder / "manifest.json").write_bytes(manifest)
        cleanup.KNOWN_OLD_MANIFESTS[version] = digest(manifest)
        return folder

    def test_readonly_plan_lists_known_package_and_size_without_writes(self):
        old = self.old()
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        result = self.cleaner.check()[0]
        after = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertTrue(result["loeschbar"])
        self.assertEqual(result["bytes"], sum(p.stat().st_size for p in old.rglob("*") if p.is_file()))
        self.assertNotIn("private-value", json.dumps(self.cleaner.public(result)))

    def test_cli_imports_do_not_create_bytecode_in_package(self):
        program = self.root / "actual-program"
        program.mkdir()
        source = Path(__file__).resolve().parents[1]
        for name in ("securitywatch_cleanup.py", "install_securitywatch.py", "securitywatch_common.py", "securitywatch_lifecycle.py"):
            shutil.copyfile(source / name, program / name)
        before = {p.name for p in program.iterdir()}
        result = subprocess.run([sys.executable, str(program / "securitywatch_cleanup.py"), "--help"],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in program.iterdir()}, before)

    def test_removes_both_old_packages_and_preserves_live_configuration_data_and_current_package(self):
        first, second = self.old("4.1.0"), self.old("4.1.1")
        result = self.cleaner.apply()
        self.assertEqual([r["entfernt"] for r in result], [True, True])
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())
        self.assertTrue((self.package / "manifest.json").exists())
        self.assertEqual((self.live / ".env").read_text(), self.env)
        self.assertEqual((self.live / "securitywatch.github.json").read_text(), '{"custom":true}\n')
        self.assertEqual((self.reports / "keep.txt").read_text(), "report")
        self.assertEqual((self.backups / "keep.txt").read_text(), "backup")
        self.assertEqual((self.state / "keep.txt").read_text(), "state")

    def test_current_version_or_program_mismatch_blocks_deletion(self):
        old = self.old()
        (self.live / "securitywatch_common.py").write_text("VERSION = '4.1.1'\n")
        with self.assertRaises(cleanup.CleanupError):
            self.cleaner.apply()
        self.assertTrue((old / "manifest.json").exists())

    def test_modified_old_program_and_unknown_env_file_are_preserved(self):
        first, second = self.old("4.1.0"), self.old("4.1.1")
        (first / "securitywatch_common.py").write_text("# user edit\n")
        (second / ".env").write_text("SECRET=keep-me\n")
        result = self.cleaner.apply()
        self.assertFalse(any(r["entfernt"] for r in result))
        self.assertEqual((first / "securitywatch_common.py").read_text(), "# user edit\n")
        self.assertEqual((second / ".env").read_text(), "SECRET=keep-me\n")
        self.assertTrue(all((p / "manifest.json").exists() for p in (first, second)))

    def test_forged_but_self_consistent_old_manifest_is_not_accepted(self):
        old = self.old()
        path = old / "README_DE.md"
        path.write_text("changed\n")
        manifest_path = old / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"]["README_DE.md"] = digest(path.read_bytes())
        manifest_path.write_text(json.dumps(manifest))
        result = self.cleaner.apply()[0]
        self.assertFalse(result["entfernt"])
        self.assertTrue(path.exists())

    def test_known_python_bytecode_cache_is_recognized(self):
        old = self.old()
        py_compile.compile(str(old / "securitywatch_common.py"), doraise=True)
        py_compile.compile(str(old / "tests/test_old.py"), doraise=True)
        self.assertTrue(self.cleaner.check()[0]["loeschbar"])
        self.assertTrue(self.cleaner.apply()[0]["entfernt"])
        self.assertFalse(old.exists())

    def test_unknown_bytecode_or_other_empty_directory_blocks_deletion(self):
        first, second = self.old("4.1.0"), self.old("4.1.1")
        (first / "__pycache__").mkdir()
        (first / "__pycache__" / ("other." + sys.implementation.cache_tag + ".pyc")).write_bytes(b"not a known cache")
        (second / "personal-data").mkdir()
        result = self.cleaner.apply()
        self.assertFalse(any(r["entfernt"] for r in result))
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_nested_and_top_level_symlinks_preserve_external_files(self):
        first, second = self.old("4.1.0"), self.old("4.1.1")
        external = self.root / "external"
        external.mkdir()
        (external / "test_old.py").write_text("# old test\n")
        shutil.rmtree(first / "tests")
        (first / "tests").symlink_to(external, target_is_directory=True)
        shutil.rmtree(second)
        second.symlink_to(external, target_is_directory=True)
        result = self.cleaner.apply()
        self.assertFalse(any(r["entfernt"] for r in result))
        self.assertEqual((external / "test_old.py").read_text(), "# old test\n")

    def test_active_report_path_and_mount_are_never_cleaned(self):
        first, second = self.old("4.1.0"), self.old("4.1.1")
        (self.live / ".env").write_text(f"STATE_DIR={self.state}\nREPORT_DIR={first}\n")
        with patch.object(cleanup, "_mounts", return_value={second / "tests"}):
            result = self.cleaner.apply()
        self.assertFalse(any(r["entfernt"] for r in result))
        self.assertTrue((first / "manifest.json").exists())
        self.assertTrue((second / "manifest.json").exists())

    def test_open_image_or_installation_journal_prevents_deletion(self):
        old = self.old()
        transactions = self.state / "transactions"
        transactions.mkdir()
        pending = transactions / "pending.json"
        pending.write_text(json.dumps({"schema": 1, "phase": "deploying", "old_image_id": "sha256:" + "a" * 64}))
        with self.assertRaises(cleanup.CleanupError):
            self.cleaner.apply()
        pending.unlink()
        (self.state / "securitywatch-install.json").write_text(json.dumps({"schema_version": 1, "phase": "installing"}))
        with self.assertRaises(cleanup.CleanupError):
            self.cleaner.apply()
        self.assertTrue((old / "manifest.json").exists())

    def test_global_run_lock_prevents_deletion(self):
        old = self.old()
        with RunLock(self.state / "securitywatch.lock"):
            with self.assertRaises(ConfigurationError):
                self.cleaner.apply()
        self.assertTrue(old.exists())

    def test_unknown_file_added_after_plan_is_not_removed(self):
        old = self.old()
        candidate = self.cleaner.check()[0]
        (old / "personal.txt").write_text("keep")
        result = self.cleaner._remove(candidate)
        self.assertFalse(result["entfernt"])
        self.assertEqual(result["entfernte_dateien"], 0)
        self.assertEqual((old / "personal.txt").read_text(), "keep")
        self.assertTrue((old / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
