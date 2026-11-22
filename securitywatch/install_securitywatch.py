#!/usr/bin/env python3
"""Geprüfte Installation von SecurityWatch-Programmdateien, ohne Dienststart.

Programme werden unter gemeinsamer Sperre einzeln atomar ausgetauscht.
Ein dauerhaftes Installationsjournal blockiert einen unvollständigen Stand.
Konfiguration, Anwendungsdaten, Container und Image-Zuordnungen bleiben erhalten.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from securitywatch_common import ConfigurationError, parse_env_text

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
DEFAULT_TARGET = Path("/volume2/docker/securitywatch")
ACTIVE_PHASES = frozenset({"installing", "restoring", "rollback_failed"})
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")


class InstallError(Exception):
    pass


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: Any) -> str:
    if not isinstance(name, str) or not name or "\\" in name or any(ord(c) < 32 for c in name):
        raise InstallError("Das Paket enthält einen ungültigen Dateipfad.")
    p = PurePosixPath(name)
    if p.is_absolute() or any(c in {".", ".."} for c in name.split("/")) or str(p) != name:
        raise InstallError("Das Paket enthält einen nicht zulässigen Dateipfad.")
    return name


def _regular_bytes(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    try:
        if path.resolve() != path.absolute():
            raise InstallError(f"Verknüpfungen sind hier nicht zulässig: {path.name}")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
                raise InstallError(f"Keine zulässige reguläre Datei: {path.name}")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise InstallError(f"Datei überschreitet die zulässige Größe: {path.name}")
            return data
        finally:
            os.close(fd)
    except OSError as exc:
        raise InstallError(f"Datei konnte nicht sicher gelesen werden: {path.name}") from exc


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    temp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        _write_file(temp, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        os.replace(temp, path)
        _sync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def _load_json(path: Path, limit: int = MAX_MANIFEST_BYTES) -> dict[str, Any]:
    try:
        result = json.loads(_regular_bytes(path, limit))
    except (ValueError, UnicodeError) as exc:
        raise InstallError(f"JSON-Datei ist beschädigt: {path.name}") from exc
    if not isinstance(result, dict):
        raise InstallError(f"JSON-Datei enthält kein Objekt: {path.name}")
    return result


def _allowed_install_name(name: str) -> bool:
    # Nur flache, nachvollziehbare Programm-/Konfigurationsdateien.
    if "/" in name or name.startswith(".") or name in {"state", "reports", "trivy-cache", "manifest.json"}:
        return False
    if name == "install_securitywatch.py":
        return True
    return name.startswith("securitywatch") and (
        name.endswith((".py", ".sh", ".json")) or name == "securitywatch.local-images"
    )


def _preserve_existing(name: str) -> bool:
    return name == "securitywatch.local-images" or name.endswith(".json")


def verify_package(package: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    package = package.absolute()
    if package.resolve() != package:
        raise InstallError("Der Paketordner darf keine Verknüpfung sein.")
    manifest = _load_json(package / "manifest.json")
    files = manifest.get("files")
    selected = manifest.get("install_files")
    if not isinstance(manifest.get("version"), str) or not manifest["version"]:
        raise InstallError("Die Paketversion fehlt.")
    if not isinstance(files, dict) or not files or len(files) > 300:
        raise InstallError("Die Paketprüfsummen fehlen oder sind ungültig.")
    if not isinstance(selected, list) or not selected or any(not isinstance(n, str) for n in selected) or len(selected) != len(set(selected)):
        raise InstallError("Die Liste der zu installierenden Dateien ist ungültig.")
    for name in selected:
        if not isinstance(name, str) or name not in files or not _allowed_install_name(_safe_name(name)):
            raise InstallError("Die Installationsliste enthält eine nicht zulässige Datei.")
    contents: dict[str, bytes] = {}
    total = 0
    for name, expected in files.items():
        _safe_name(name)
        if not isinstance(expected, str) or not HASH_RE.fullmatch(expected):
            raise InstallError("Eine Paketprüfsumme ist ungültig.")
        raw = _regular_bytes(package / name)
        total += len(raw)
        if total > 100 * 1024 * 1024:
            raise InstallError("Das Programmpaket ist unerwartet groß.")
        if _digest(raw) != expected:
            raise InstallError(f"Paketprüfsumme stimmt nicht: {name}")
        if name in selected:
            contents[name] = raw
    for name, raw in contents.items():
        if name.endswith(".py"):
            try:
                compile(raw, name, "exec", dont_inherit=True)
            except SyntaxError as exc:
                runtime = ".".join(str(part) for part in sys.version_info[:3])
                location = f", Zeile {exc.lineno}" if exc.lineno else ""
                raise InstallError(
                    f"Python-Datei ist syntaktisch ungültig: {name}{location} (Python {runtime}). "
                    "Die vorhandene Installation wurde nicht verändert."
                ) from exc
            except (ValueError, UnicodeError) as exc:
                raise InstallError(
                    f"Python-Datei konnte nicht übersetzt werden: {name}. "
                    "Die vorhandene Installation wurde nicht verändert."
                ) from exc
        elif name.endswith(".sh"):
            checked = subprocess.run(["bash", "-n"], input=raw, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
            if checked.returncode:
                raise InstallError(f"Shell-Datei ist syntaktisch ungültig: {name}")
    return manifest, contents


def _read_env_settings(target: Path) -> dict[str, str]:
    path = target / ".env"
    if not path.exists():
        raise InstallError("Vorhandene .env fehlt. Die Installation benötigt die bestehende SecurityWatch-Konfiguration.")
    try:
        text = _regular_bytes(path, MAX_MANIFEST_BYTES).decode("utf-8-sig")
    except UnicodeError as exc:
        raise InstallError("Die vorhandene .env ist nicht als UTF-8 lesbar.") from exc
    try:
        settings = parse_env_text(text)
    except ConfigurationError as exc:
        raise InstallError(f"Die vorhandene Einstellungsdatei kann nicht sicher gelesen werden: {exc}") from exc
    return {"STATE_DIR": settings["STATE_DIR"]} if "STATE_DIR" in settings else {}


def state_directory(target: Path) -> Path:
    settings = _read_env_settings(target)
    value = settings.get("STATE_DIR") or str(target / "state")
    # Ausschließlich bekannte Pfadvariable; niemals .env als Shell ausführen.
    for marker in ("${SCRIPT_DIR}", "$SCRIPT_DIR"):
        value = value.replace(marker, str(target))
    if "$" in value or "`" in value:
        raise InstallError("STATE_DIR enthält eine nicht unterstützte Variable oder Shell-Anweisung.")
    state_path = Path(value)
    if not state_path.is_absolute() or len(state_path.parts) < 3:
        raise InstallError("STATE_DIR muss ein eindeutiger absoluter Unterordner sein.")
    if state_path.resolve() != state_path:
        raise InstallError("STATE_DIR darf keine Verknüpfungen oder relativen Pfadanteile enthalten.")
    return state_path


def _validate_target(target: Path) -> Path:
    target = target.absolute()
    if len(target.parts) < 3 or target.resolve() != target or not target.is_dir():
        raise InstallError("Der vorhandene Installationsordner ist ungültig oder eine Verknüpfung.")
    _read_env_settings(target)
    return target


def _legacy_running(target: Path, proc_root: Path = Path("/proc")) -> list[int]:
    expected = str(target / "securitywatch_scan.sh")
    found = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            arguments = (entry / "cmdline").read_bytes().split(b"\0")
            args = [a.decode("utf-8", "replace") for a in arguments if a]
            match = expected in args
            if not match and any(a in {"securitywatch_scan.sh", "./securitywatch_scan.sh"} for a in args):
                match = (entry / "cwd").resolve() == target
            # Auch ein von cron über sh -c gestarteter, noch aktiver Altaufruf.
            if not match and "-c" in args:
                index = args.index("-c")
                if index + 1 < len(args):
                    try:
                        match = expected in shlex.split(args[index + 1])
                    except ValueError:
                        pass
            if match:
                found.append(int(entry.name))
        except (OSError, ValueError):
            continue
    return found


@contextlib.contextmanager
def _lock(state: Path):
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    path = state / "securitywatch.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InstallError("Die SecurityWatch-Sperre ist keine reguläre Datei.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallError("SecurityWatch oder eine Installation läuft bereits. Diesen Lauf erst beenden lassen.") from exc
        yield
    finally:
        os.close(fd)


def _journal(state: Path) -> dict[str, Any] | None:
    path = state / "securitywatch-install.json"
    if not (path.exists() or path.is_symlink()):
        return None
    result = _load_json(path)
    if result.get("schema_version") != 1 or result.get("phase") not in ACTIVE_PHASES | {"committed", "rolled_back", "restored"}:
        raise InstallError("Das Installationsjournal ist beschädigt oder nicht kompatibel.")
    return result


def _dependencies() -> list[str]:
    if sys.version_info < (3, 11):
        raise InstallError("Python 3.11 oder neuer wird benötigt.")
    executable = shutil.which("docker")
    if not executable:
        raise InstallError("Docker wurde nicht gefunden.")
    env = dict(os.environ)
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_TLS", "DOCKER_API_VERSION"):
        env.pop(name, None)
    commands = [
        [executable, "--host", "unix:///var/run/docker.sock", "version", "--format", "{{.Server.Version}}"],
        [executable, "--host", "unix:///var/run/docker.sock", "compose", "version", "--short"],
        [executable, "--host", "unix:///var/run/docker.sock", "compose", "up", "--help"],
        [executable, "--host", "unix:///var/run/docker.sock", "compose", "config", "--help"],
        [executable, "--host", "unix:///var/run/docker.sock", "buildx", "version"],
        [executable, "--host", "unix:///var/run/docker.sock", "buildx", "imagetools", "inspect", "--help"],
        [executable, "--host", "unix:///var/run/docker.sock", "compose", "build", "--help"],
    ]
    outputs = []
    for command in commands:
        try:
            result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallError("Docker/Compose/Buildx konnte nicht innerhalb des Zeitlimits geprüft werden.") from exc
        if result.returncode:
            raise InstallError("Docker, Docker Compose oder Docker Buildx ist nicht lesbar. Installation abgebrochen.")
        outputs.append(result.stdout)
    if not all(flag in outputs[2] for flag in ("--no-build", "--pull", "--no-deps", "--force-recreate")) or "--format" not in outputs[3]:
        raise InstallError("Die benötigten Docker-Compose-Funktionen fehlen.")
    if "--format" not in outputs[5]:
        raise InstallError("Docker Buildx unterstützt den benötigten Registry-Abgleich nicht.")
    if "--builder" not in outputs[6]:
        raise InstallError("Docker Compose unterstützt die benötigte Auswahl des lokalen Bauwerkzeugs nicht.")
    return ["Python-Version geeignet", "Lokaler Docker-Dienst erreichbar", "Docker Compose unterstützt die benötigten Funktionen", "Docker Buildx unterstützt den benötigten Registry-Abgleich"]


def check_installation(package: Path, target: Path, *, check_dependencies: bool = True) -> dict[str, Any]:
    manifest, contents = verify_package(package)
    target = _validate_target(target)
    state = state_directory(target)
    journal = _journal(state)
    if journal and journal.get("phase") in ACTIVE_PHASES:
        raise InstallError("Eine frühere Programminstallation ist unvollständig. Zuerst die zugehörige Programmsicherung wiederherstellen.")
    if _legacy_running(target):
        raise InstallError("Das bisherige SecurityWatch-Skript läuft noch. Den Lauf erst beenden lassen.")
    for name in contents:
        destination = target / name
        if destination.exists() or destination.is_symlink():
            _regular_bytes(destination)
    checks = _dependencies() if check_dependencies else []
    return {"version": manifest["version"], "target": str(target), "state_directory": str(state),
            "files": len(contents), "checks": checks, "installed": False}


def _backup(target: Path, selected: dict[str, bytes], version: str, manifest_hash: str) -> tuple[Path, dict[str, Any]]:
    root = target.parent / (target.name + "-backups")
    if root.exists() and (root.resolve() != root or not root.is_dir()):
        raise InstallError("Der Sicherungsordner ist keine zulässige Verzeichnisstruktur.")
    root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    name = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    directory = root / name
    directory.mkdir(mode=0o700)
    saved = directory / "files"
    saved.mkdir(mode=0o700)
    backup: dict[str, Any] = {"schema_version": 1, "target": str(target), "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                              "version_installed": version, "package_manifest_sha256": manifest_hash, "files": {},
                              "installed_files": {key: _digest(value) for key, value in selected.items()}}
    try:
        for relative in [*selected.keys(), ".env"]:
            path = target / relative
            if path.exists() or path.is_symlink():
                data = _regular_bytes(path)
                mode = stat.S_IMODE(path.stat().st_mode)
                _write_file(saved / relative, data, 0o600)
                backup["files"][relative] = {"existed": True, "sha256": _digest(data), "mode": mode}
            else:
                backup["files"][relative] = {"existed": False}
        _atomic_json(directory / "backup.json", backup)
        _sync_dir(saved)
        _sync_dir(directory)
        _sync_dir(root)
    except Exception:
        # Ein unvollständiges Verzeichnis bleibt nachvollziehbar; keine Programme wurden geändert.
        raise
    return directory, backup


def _restore_bytes(target: Path, stage: Path, backup_dir: Path, backup: dict[str, Any], names: list[str]) -> None:
    # Den alten Einstieg zuletzt zurücklegen: Er kennt die neue Sperre nicht.
    ordered = [name for name in names if name != "securitywatch_scan.sh"]
    if "securitywatch_scan.sh" in names:
        ordered.append("securitywatch_scan.sh")
    for name in ordered:
        original = backup["files"][name]
        destination = target / name
        if original["existed"]:
            data = _regular_bytes(backup_dir / "files" / name)
            if _digest(data) != original["sha256"]:
                raise InstallError(f"Programmsicherung ist beschädigt: {name}")
            temporary = stage / (name + ".restore-" + uuid.uuid4().hex)
            _write_file(temporary, data, original["mode"] & 0o777)
            os.replace(temporary, destination)
        else:
            destination.unlink(missing_ok=True)
    _sync_dir(target)


def install(package: Path, target: Path, *, check_dependencies: bool = True) -> dict[str, Any]:
    # Einmal vor jeder Änderung vollständig lesen, prüfen und im Speicher halten.
    manifest, contents = verify_package(package)
    target = _validate_target(target)
    state = state_directory(target)
    if check_dependencies:
        _dependencies()
    if _legacy_running(target):
        raise InstallError("Das bisherige SecurityWatch-Skript läuft noch. Installation abgebrochen.")
    with _lock(state):
        old_journal = _journal(state)
        if old_journal and old_journal.get("phase") in ACTIVE_PHASES:
            raise InstallError("Eine frühere Programminstallation ist unvollständig. Zuerst die Programmsicherung wiederherstellen.")
        if _legacy_running(target):
            raise InstallError("Das bisherige SecurityWatch-Skript wurde inzwischen gestartet. Installation abgebrochen.")
        selected = {}
        preserved = []
        for name, data in contents.items():
            destination = target / name
            if destination.exists() or destination.is_symlink():
                _regular_bytes(destination)
                if _preserve_existing(name):
                    preserved.append(name)
                    continue
            selected[name] = data
        if not selected:
            raise InstallError("Das Paket enthält keine auszutauschenden Programmdateien.")
        stage = Path(tempfile.mkdtemp(prefix=".securitywatch-install-", dir=target))
        os.chmod(stage, 0o700)
        backup_dir = None
        journal: dict[str, Any] = {}
        replaced: list[str] = []
        try:
            for name, data in selected.items():
                _write_file(stage / name, data, 0o755 if name.endswith(".sh") else 0o644)
            _sync_dir(stage)
            backup_dir, backup = _backup(target, selected, manifest["version"], _digest(_regular_bytes(package / "manifest.json", MAX_MANIFEST_BYTES)))
            journal = {"schema_version": 1, "phase": "installing", "version": manifest["version"], "backup": str(backup_dir),
                       "target": str(target), "started_at": dt.datetime.now(dt.timezone.utc).isoformat()}
            _atomic_json(state / "securitywatch-install.json", journal)
            # Der neue Einstieg beachtet Sperre und Installationsjournal. Ein
            # früherer, noch nicht sperrender Einstieg wird deshalb zuerst
            # ersetzt; ein bereits geöffneter Altaufruf danach erneut erkannt.
            ordered = list(selected)
            if "securitywatch_scan.sh" in selected:
                ordered.remove("securitywatch_scan.sh")
                ordered.insert(0, "securitywatch_scan.sh")
            for name in ordered:
                os.replace(stage / name, target / name)
                replaced.append(name)
                if name == "securitywatch_scan.sh" and _legacy_running(target):
                    raise InstallError("Ein früherer SecurityWatch-Aufruf wurde während der Vorbereitung gestartet. Die Programmdateien werden zurückgesetzt.")
            _sync_dir(target)
            journal["phase"] = "committed"
            journal["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            _atomic_json(state / "securitywatch-install.json", journal)
            return {"version": manifest["version"], "target": str(target), "backup": str(backup_dir),
                    "installed_files": list(selected), "preserved_files": preserved, "installed": True}
        except BaseException as original_error:
            if backup_dir is not None and journal:
                try:
                    _restore_bytes(target, stage, backup_dir, backup, replaced)
                    journal["phase"] = "rolled_back"
                    _atomic_json(state / "securitywatch-install.json", journal)
                except BaseException:
                    journal["phase"] = "rollback_failed"
                    try:
                        _atomic_json(state / "securitywatch-install.json", journal)
                    except BaseException:
                        pass
                    raise InstallError(f"Die Installation und ihre Wiederherstellung wurden unterbrochen. Programmsicherung: {backup_dir}") from original_error
            if isinstance(original_error, (KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(original_error, InstallError):
                raise
            raise InstallError("Die Installation ist fehlgeschlagen; bereits ausgetauschte Programmdateien wurden zurückgesetzt.") from original_error
        finally:
            shutil.rmtree(stage, ignore_errors=True)


def _verify_backup(directory: Path, target: Path) -> dict[str, Any]:
    directory = directory.absolute()
    expected_root = target.parent / (target.name + "-backups")
    if directory.resolve() != directory or directory.parent != expected_root:
        raise InstallError("Die Sicherung gehört nicht zum vorgesehenen Sicherungsordner dieser Installation.")
    backup = _load_json(directory / "backup.json")
    if backup.get("schema_version") != 1 or backup.get("target") != str(target):
        raise InstallError("Die Programmsicherung gehört nicht zu diesem Zielordner.")
    files, installed = backup.get("files"), backup.get("installed_files")
    if not isinstance(files, dict) or not isinstance(installed, dict) or not installed or len(files) > 100:
        raise InstallError("Die Programmsicherung hat eine ungültige Dateiliste.")
    for name, new_hash in installed.items():
        if not _allowed_install_name(_safe_name(name)) or name not in files or not isinstance(new_hash, str) or not HASH_RE.fullmatch(new_hash):
            raise InstallError("Die Programmsicherung enthält eine ungültige Dateizuordnung.")
        item = files[name]
        if not isinstance(item, dict) or not isinstance(item.get("existed"), bool):
            raise InstallError("Die Programmsicherung enthält einen ungültigen Dateizustand.")
        permitted_hashes = {new_hash}
        if item["existed"]:
            old_hash = item.get("sha256")
            mode = item.get("mode")
            if not isinstance(old_hash, str) or not HASH_RE.fullmatch(old_hash) or not isinstance(mode, int) or not 0 <= mode <= 0o7777:
                raise InstallError("Die Programmsicherung enthält ungültige Dateimetadaten.")
            if _digest(_regular_bytes(directory / "files" / name)) != old_hash:
                raise InstallError(f"Die Programmsicherung ist beschädigt: {name}")
            permitted_hashes.add(old_hash)
        current = target / name
        if current.exists() or current.is_symlink():
            if _digest(_regular_bytes(current)) not in permitted_hashes:
                raise InstallError(f"Programmdatei wurde seit der Installation anderweitig verändert: {name}. Keine automatische Überschreibung.")
    return backup


def restore(directory: Path, target: Path) -> dict[str, Any]:
    target = _validate_target(target)
    directory = directory.absolute()
    state = state_directory(target)
    if _legacy_running(target):
        raise InstallError("SecurityWatch läuft noch. Wiederherstellung abgebrochen.")
    with _lock(state):
        if _legacy_running(target):
            raise InstallError("SecurityWatch wurde inzwischen gestartet. Wiederherstellung abgebrochen.")
        backup = _verify_backup(directory, target)
        stage = Path(tempfile.mkdtemp(prefix=".securitywatch-restore-", dir=target))
        journal = {"schema_version": 1, "phase": "restoring", "backup": str(directory), "target": str(target),
                   "started_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        try:
            _atomic_json(state / "securitywatch-install.json", journal)
            _restore_bytes(target, stage, directory, backup, list(backup["installed_files"]))
            journal["phase"] = "restored"
            journal["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            _atomic_json(state / "securitywatch-install.json", journal)
        except BaseException:
            journal["phase"] = "rollback_failed"
            try:
                _atomic_json(state / "securitywatch-install.json", journal)
            except BaseException:
                pass
            raise
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        return {"restored": True, "target": str(target), "backup": str(directory), "configuration_restored": False}


def main() -> int:
    parser = argparse.ArgumentParser(description="SecurityWatch-Programmdateien prüfen, gesichert installieren oder wiederherstellen.")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="Paket und Voraussetzungen ausschließlich prüfen")
    action.add_argument("--install", action="store_true", help="Programmdateien gesichert austauschen; keinen Lauf starten")
    action.add_argument("--restore", type=Path, metavar="SICHERUNGSORDNER", help="Nur Programmdateien wiederherstellen")
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--package-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.check:
            result = check_installation(args.package_dir.absolute(), args.target.absolute())
            print(f"Prüfung erfolgreich: SecurityWatch {result['version']}; {result['files']} Paketdateien geprüft.")
            print("Es wurden keine Dateien, Container oder Zeitpläne geändert.")
        elif args.install:
            result = install(args.package_dir.absolute(), args.target.absolute())
            print(f"SecurityWatch {result['version']} wurde installiert.")
            print(f"Programmsicherung: {result['backup']}")
            print("Vorhandene Konfiguration und Zustandsdaten wurden beibehalten. Es wurde kein Wartungslauf gestartet.")
        else:
            result = restore(args.restore.absolute(), args.target.absolute())
            print("Die Programmdateien wurden wiederhergestellt. Konfiguration, Container und Zustandsdaten wurden beibehalten.")
            print("Vor dem nächsten automatischen Lauf die gespeicherten Image-Zuordnungen prüfen: Ein älterer Programmstand kennt deren Schutzregeln möglicherweise nicht.")
        return 0
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        text = str(exc) if isinstance(exc, InstallError) else "Die Dateioperation konnte nicht abgeschlossen werden. Das Installationsjournal und die Programmsicherung prüfen."
        print("ABBRUCH: " + text, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
