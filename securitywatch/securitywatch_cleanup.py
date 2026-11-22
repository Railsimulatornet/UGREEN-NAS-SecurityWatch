#!/usr/bin/env python3
"""Gezielt die zwei unveränderten alten SecurityWatch-Installationspakete entfernen.

Keine allgemeine Verzeichnis- oder Docker-Bereinigung. Fremde/geänderte Dateien
bleiben erhalten. Die produktive Installation, ihre Einstellungen, Zustandsdaten,
Berichte, Sicherungen und das aktuelle Installationspaket sind ausgeschlossen.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

from install_securitywatch import (ACTIVE_PHASES, InstallError, MAX_FILE_BYTES,
                                   MAX_MANIFEST_BYTES, _journal, _regular_bytes,
                                   _safe_name, state_directory, verify_package)
from securitywatch_common import ConfigurationError, RunLock, VERSION, parse_env_text
from securitywatch_lifecycle import LifecycleEngine


ROOT = Path("/volume2/docker")
EXPECTED_VERSION = "4.2.0"
# These are the manifests of the exact ZIP files previously delivered to Roman.
# A self-consistent but foreign/edited manifest is not sufficient for deletion.
KNOWN_OLD_MANIFESTS = {
    "4.1.0": "e769c62b7f97be29018fff4347380c177f46e7267c8b18310e50ec08bf0152d7",
    "4.1.1": "6c2367f0d2cab0346453bf78dd455320444238da2bb9af7451ac76ae46e755f4",
}
CORE_PROGRAMS = frozenset({
    "install_securitywatch.py", "securitywatch.py", "securitywatch_common.py",
    "securitywatch_github.py", "securitywatch_housekeeping.py", "securitywatch_image_origin.py",
    "securitywatch_lifecycle.py", "securitywatch_mail.py", "securitywatch_minecraft_java.py",
    "securitywatch_notifications.py", "securitywatch_project_updates.py", "securitywatch_report.py",
    "securitywatch_scan.sh", "securitywatch_scanner.py", "securitywatch_cleanup.py",
})


class CleanupError(RuntimeError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mounts() -> set[Path]:
    """Also recognize same-filesystem bind mounts, which ismount can miss."""
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
        return {Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), row.split()[4]))
                for row in lines if len(row.split()) >= 6}
    except (OSError, ValueError) as exc:
        raise CleanupError("Die eingebundenen Dateisysteme konnten nicht geprüft werden; keine Paketlöschung.") from exc


def _cache_source(name: str, files: dict[str, str]) -> str | None:
    path = PurePosixPath(name)
    if path.parent.name != "__pycache__":
        return None
    tag = re.escape(sys.implementation.cache_tag or "unsupported")
    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\." + tag + r"(?:\.opt-[12])?\.pyc", path.name)
    if not match:
        return None
    source = str(path.parent.parent / (match[1] + ".py"))
    return source if source in files else None


def _valid_cache(raw: bytes, source: bytes) -> bool:
    if len(raw) < 17 or raw[:4] != importlib.util.MAGIC_NUMBER:
        return False
    flags = int.from_bytes(raw[4:8], "little")
    if flags == 0:
        return int.from_bytes(raw[12:16], "little") == len(source)
    if flags in {1, 3}:
        return raw[8:16] == importlib.util.source_hash(source)
    return False


def _open_parent(root_fd: int, relative: str) -> tuple[int, str]:
    parts = PurePosixPath(_safe_name(relative)).parts
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def _bytes_at(parent_fd: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise CleanupError("Eine Paketdatei ist nicht mehr eindeutig regulär.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            result = stream.read(MAX_FILE_BYTES + 1)
        if len(result) > MAX_FILE_BYTES:
            raise CleanupError("Eine Paketdatei hat sich während der Prüfung verändert.")
        return result
    finally:
        os.close(fd)


class PackageCleaner:
    def __init__(self, package: Path, *, root: Path = ROOT):
        # The CLI offers no root/target argument. An alternate root exists only
        # for isolated tests; the allowed two child names remain fixed.
        self.root = root.absolute()
        self.live = self.root / "securitywatch"
        self.package = package.absolute()
        self.state: Path | None = None
        self.protected: set[Path] = set()

    def verify_live(self) -> None:
        if self.root.resolve() != self.root or not self.root.is_dir() or self.live.resolve() != self.live:
            raise CleanupError("Der Docker- oder Installationsordner ist nicht eindeutig oder eine Verknüpfung.")
        manifest, selected = verify_package(self.package)
        if VERSION != EXPECTED_VERSION or manifest["version"] != EXPECTED_VERSION:
            raise CleanupError("Die Bereinigung benötigt das geprüfte SecurityWatch-Paket 4.2.0.")
        programs = {name for name in selected if name.endswith((".py", ".sh"))}
        if not CORE_PROGRAMS.issubset(programs):
            raise CleanupError("Das aktuelle Paket enthält nicht alle benötigten Programmdateien.")
        for name in programs:
            if _sha(_regular_bytes(self.live / name)) != manifest["files"][name]:
                raise CleanupError(f"Die installierte Programmdatei stimmt nicht mit 4.2.0 überein: {name}")
        self.state = state_directory(self.live)
        self.protected = {self.live, self.package, self.state, self.root / "securitywatch-backups"}
        env = parse_env_text(_regular_bytes(self.live / ".env", MAX_MANIFEST_BYTES).decode("utf-8-sig"))
        for key, fallback in (("REPORT_DIR", self.live / "reports"), ("CACHE_DIR", self.live / "trivy-cache")):
            value = env.get(key, str(fallback)).replace("${SCRIPT_DIR}", str(self.live)).replace("$SCRIPT_DIR", str(self.live))
            if "$" in value or "`" in value or any(c in value for c in ("\n", "\r", "\x00")):
                raise CleanupError("Ein aktiver Datenpfad konnte nicht zuverlässig zugeordnet werden.")
            path = Path(value)
            self.protected.add((path if path.is_absolute() else self.live / path).resolve())
        self._no_pending()

    def _no_pending(self) -> None:
        if self.state is None:
            raise CleanupError("Die installierte Version wurde noch nicht geprüft.")
        installation = _journal(self.state)
        if installation and installation.get("phase") in ACTIVE_PHASES:
            raise CleanupError("Eine Installation oder Wiederherstellung ist offen; keine Paketlöschung.")
        engine = LifecycleEngine(self.state, None, lambda _: None)
        if engine.open_transactions():
            raise CleanupError("Eine Image-Aktualisierung ist ungeklärt; keine Paketlöschung.")

    def _candidate(self, version: str) -> dict:
        name = "securitywatch-update-" + version
        path = self.root / name
        result = {"ordner": str(path), "version": version, "bytes": 0, "loeschbar": False}
        if not path.exists() and not path.is_symlink():
            return {**result, "grund": "Nicht vorhanden."}
        try:
            if path.resolve() != path or not path.is_dir():
                raise CleanupError("Der Paketordner ist eine Verknüpfung oder kein regulärer Ordner.")
            if any(path == protected or path in protected.parents for protected in self.protected):
                raise CleanupError("Der Ordner enthält einen aktiven Programm-, Daten- oder Sicherungspfad.")
            if any(mount == path or path in mount.parents for mount in _mounts()):
                raise CleanupError("Im Paketordner ist ein Dateisystem eingebunden.")
            raw_manifest = _regular_bytes(path / "manifest.json", MAX_MANIFEST_BYTES)
            if _sha(raw_manifest) != KNOWN_OLD_MANIFESTS[version]:
                raise CleanupError("Das Manifest entspricht nicht dem unveränderten früher gelieferten Paket.")
            manifest = json.loads(raw_manifest)
            if manifest.get("version") != version or not isinstance(manifest.get("files"), dict):
                raise CleanupError("Die frühere Paketkennung ist ungültig.")
            tracked = manifest["files"]
            contents = {}
            hashes = {"manifest.json": _sha(raw_manifest)}
            allowed_dirs = set()
            for relative, expected in tracked.items():
                _safe_name(relative)
                raw = _regular_bytes(path / relative)
                if _sha(raw) != expected:
                    raise CleanupError(f"Eine frühere Paketdatei wurde geändert: {relative}")
                contents[relative] = raw
                hashes[relative] = expected
                for parent in PurePosixPath(relative).parents:
                    if str(parent) != ".":
                        allowed_dirs.add(str(parent))
                if relative.endswith(".py"):
                    allowed_dirs.add(str(PurePosixPath(relative).parent / "__pycache__"))
            total = len(raw_manifest) + sum(len(raw) for raw in contents.values())
            directories = []
            for directory, subdirectories, filenames in os.walk(path, followlinks=False):
                base = Path(directory)
                for entry in subdirectories:
                    child = base / entry
                    relative = child.relative_to(path).as_posix()
                    if child.is_symlink() or relative not in allowed_dirs:
                        raise CleanupError(f"Zusätzlicher oder verlinkter Ordner vorhanden: {relative}")
                    directories.append(relative)
                for filename in filenames:
                    child = base / filename
                    relative = child.relative_to(path).as_posix()
                    if relative in hashes:
                        # Re-read tracked files to catch changes during discovery.
                        if _sha(_regular_bytes(child)) != hashes[relative]:
                            raise CleanupError(f"Eine Paketdatei wurde während der Prüfung geändert: {relative}")
                        continue
                    source = _cache_source(relative, tracked)
                    raw = _regular_bytes(child)
                    if not source or not _valid_cache(raw, contents[source]):
                        raise CleanupError(f"Zusätzliche oder unbekannte Datei vorhanden: {relative}")
                    hashes[relative] = _sha(raw)
                    total += len(raw)
            info = path.stat()
            return {**result, "bytes": total, "loeschbar": True,
                    "grund": "Unverändertes altes Installationspaket; keine aktiven Daten enthalten.",
                    "_hashes": hashes, "_directories": directories, "_identity": (info.st_dev, info.st_ino)}
        except (CleanupError, InstallError, OSError, ValueError, KeyError, TypeError) as exc:
            message = str(exc) if isinstance(exc, (CleanupError, InstallError)) else "Der Paketinhalt konnte nicht vollständig geprüft werden."
            return {**result, "grund": message}

    @staticmethod
    def public(result: dict) -> dict:
        return {key: value for key, value in result.items() if not key.startswith("_")}

    def check(self) -> list[dict]:
        self.verify_live()
        return [self._candidate(version) for version in KNOWN_OLD_MANIFESTS]

    def _remove(self, candidate: dict) -> dict:
        fresh = self._candidate(candidate["version"])
        if (not fresh["loeschbar"] or fresh.get("_identity") != candidate["_identity"]
                or fresh.get("_hashes") != candidate["_hashes"]):
            return {**self.public(candidate), "entfernt": False, "entfernte_dateien": 0,
                    "grund": fresh.get("grund") if not fresh["loeschbar"] else "Der Paketinhalt wurde zwischenzeitlich geändert."}
        path = Path(candidate["ordner"])
        removed_files = 0
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        package_fd = None
        try:
            package_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            info = os.fstat(package_fd)
            if (info.st_dev, info.st_ino) != candidate["_identity"]:
                raise CleanupError("Der frühere Paketordner wurde zwischenzeitlich ausgetauscht.")
            # Remove only the exact files verified above. No recursive deletion
            # can accidentally sweep up a new unrelated file or follow a link.
            names = sorted(candidate["_hashes"], key=lambda name: (name == "manifest.json", name))
            for relative in names:
                parent_fd, basename = _open_parent(package_fd, relative)
                try:
                    if _sha(_bytes_at(parent_fd, basename)) != candidate["_hashes"][relative]:
                        raise CleanupError("Eine Paketdatei wurde während der Bereinigung geändert; weitere Löschungen angehalten.")
                    os.unlink(basename, dir_fd=parent_fd)
                    removed_files += 1
                finally:
                    os.close(parent_fd)
            for relative in sorted(candidate["_directories"], key=lambda value: (value.count("/"), value), reverse=True):
                parent_fd, basename = _open_parent(package_fd, relative)
                try:
                    os.rmdir(basename, dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
            current = os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != candidate["_identity"]:
                raise CleanupError("Der Paketpfad wurde zwischenzeitlich ausgetauscht; der neue Pfad bleibt erhalten.")
            os.rmdir(path.name, dir_fd=root_fd)
            return {**self.public(candidate), "entfernt": True, "entfernte_dateien": removed_files}
        except (OSError, CleanupError, InstallError) as exc:
            message = str(exc) if isinstance(exc, (CleanupError, InstallError)) else "Ein verbleibender oder inzwischen geänderter Inhalt wurde nicht gelöscht."
            return {**self.public(candidate), "entfernt": False, "entfernte_dateien": removed_files, "grund": message}
        finally:
            if package_fd is not None:
                os.close(package_fd)
            os.close(root_fd)

    def apply(self) -> list[dict]:
        self.verify_live()
        with RunLock(self.state / "securitywatch.lock"):
            # The installed version and journals are checked again under the
            # same lock used by scans, installation and project adoption.
            self.verify_live()
            results = []
            for version in KNOWN_OLD_MANIFESTS:
                self._no_pending()
                candidate = self._candidate(version)
                if not candidate["loeschbar"]:
                    results.append({**self.public(candidate), "entfernt": False})
                    continue
                results.append(self._remove(candidate))
            return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Nur die unveränderten alten Installationspakete 4.1.0 und 4.1.1 bereinigen")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Nur Kandidaten und Gründe anzeigen; keine Dateiänderung")
    mode.add_argument("--apply", action="store_true", help="Ausschließlich vollständig erkannte alte Paketdateien entfernen")
    parser.add_argument("--package", type=Path, default=ROOT / "securitywatch-update-4.2.0",
                        help="Unverändertes aktuelles Paket zur Prüfung der installierten Programmdateien")
    args = parser.parse_args(argv)
    try:
        cleaner = PackageCleaner(args.package)
        results = cleaner.check() if args.check else cleaner.apply()
        for result in results:
            print(json.dumps(cleaner.public(result), ensure_ascii=False, indent=2))
        if args.check:
            print("Prüfung beendet. Es wurden keine Dateien, Images oder Container verändert.")
        else:
            print("Paketbereinigung beendet. Produktive Installation, Einstellungen, Zustandsdaten, Berichte und Sicherungen bleiben erhalten.")
        return 2 if args.apply and any(result.get("loeschbar") and not result.get("entfernt") for result in results) else 0
    except (CleanupError, InstallError, ConfigurationError, OSError, ValueError, RuntimeError) as exc:
        print("ABBRUCH: " + (str(exc) if isinstance(exc, (CleanupError, InstallError, ConfigurationError)) else "Die sichere Paketbereinigung konnte nicht vorbereitet werden."), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
