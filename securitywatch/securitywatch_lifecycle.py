#!/usr/bin/env python3
"""Nachvollziehbare Docker-Aktualisierungen und geschützte Vorversionen.

Python 3.11+, nur Standardbibliothek. Der Aufrufer hält zusätzlich die gemeinsame
SecurityWatch-Laufsperre. Diese Klasse schützt ihre eigenen Schreibvorgänge mit
einer zweiten Sperre. DockerRunner führt ausschließlich Argumentlisten aus und
verwendet immer den lokalen Docker-Socket.

Ein eingesetzter runner hat die Signatur
    runner(args: list[str], *, cwd: str | None = None, timeout: float = 60)
und liefert subprocess.CompletedProcess[str]. Die Argumentliste enthält die
Docker-Unterbefehle, nicht das Programm oder globale Verbindungsoptionen.

scan_image(image_id) liefert einen erfolgreichen Trivy-Bericht. Alle Aufrufe
eines Laufs müssen dieselbe Datenbank und dasselbe Prüfwerkzeug verwenden.
Compose-Konfigurationen können Geheimnisse enthalten und bleiben im Speicher.
Gespeichert werden nur Prüfsummen, Pfade und eigene Image-Zuordnungen.

Die Sperre koordiniert SecurityWatch, nicht andere Docker-Programme. Während
eines Austauschs darf kein weiterer Aktualisierer dieselben Dienste, Image-Namen
oder Compose-Dateien verändern. Docker bietet für Image-Namen kein atomisches
Vergleichen-und-Ersetzen; Prüfungen erkennen Änderungen vor/nach den Schritten,
ersetzen aber keine gemeinsame Zuständigkeit für diese Ressourcen.
"""
from __future__ import annotations

import copy
import fcntl
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable


IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
OWN_IMAGE_TAG = re.compile(r"securitywatch-(?:candidate|previous):[0-9a-f]{32}\Z")
TERMINAL_PHASES = {"complete", "rejected", "unchanged", "rolled_back", "prepared_only"}
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SCHEMA = 1


class LifecycleError(RuntimeError):
    """Eine Änderung ist nicht sicher durchführbar; keine rohen Fehlertexte."""


class PendingTransactionError(LifecycleError):
    pass


class DockerRunner:
    """Lokaler Docker-Aufruf; kein Shell-Aufruf und keine fremden Kontexte."""

    def __init__(self, binary: str = "docker") -> None:
        self.binary = binary

    def __call__(self, args: list[str], *, cwd: str | None = None,
                 timeout: float = 60, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS",
                    "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION", "BUILDX_BUILDER"):
            env.pop(key, None)
        return subprocess.run(
            [self.binary, "--host", "unix:///var/run/docker.sock", *args],
            cwd=cwd, env=env, stdin=subprocess.DEVNULL if input_text is None else None,
            input=input_text, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=timeout,
            check=False,
        )


def _image_id(value: Any) -> str:
    if not isinstance(value, str) or not IMAGE_ID.fullmatch(value):
        raise LifecycleError("Docker hat keine eindeutige Image-ID geliefert.")
    return value


def _container_id(value: Any) -> str:
    if not isinstance(value, str) or not CONTAINER_ID.fullmatch(value):
        raise LifecycleError("Docker hat keine eindeutige Container-ID geliefert.")
    return value


def _image_ref(value: Any) -> str:
    # References are passed as distinct arguments, but flags/control characters
    # are still rejected. Registry credentials never belong in an image name.
    if (not isinstance(value, str) or not value or len(value) > 512
            or value.startswith("-") or "://" in value
            or any(ord(c) < 33 or ord(c) == 127 for c in value)):
        raise LifecycleError("Die Image-Referenz ist ungültig.")
    if "@" in value:
        parts = value.split("@")
        if len(parts) != 2 or not IMAGE_ID.fullmatch(parts[1]):
            raise LifecycleError("Die feste Image-Referenz ist ungültig.")
    return value


def image_repository(reference: str) -> str:
    value = _image_ref(reference).split("@", 1)[0]
    slash, colon = value.rfind("/"), value.rfind(":")
    return value[:colon] if colon > slash else value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    """Atomarer, synchronisierter Schreibvorgang mit privaten Dateirechten."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise LifecycleError("Eine Zustandsdatei ist unerwartet ein symbolischer Verweis.")
    data = _canonical(value) + b"\n"
    fd, name = tempfile.mkstemp(prefix=".sw-", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def read_json(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, ValueError) as exc:
        raise LifecycleError(f"Zustandsdatei nicht lesbar: {path.name}") from exc
    if not isinstance(data, dict):
        raise LifecycleError(f"Zustandsdatei hat ein ungültiges Format: {path.name}")
    return data


def vulnerability_set(document: dict[str, Any], expected_image_id: str | None = None
                      ) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Stabile Identität: Typ, Paket und Schwachstelle, niemals Versionsnummern.

    Mehrfachvorkommen bleiben so lange offen, wie mindestens ein Vorkommen der
    Schwachstelle vorhanden ist. Ein umbenannter Pfad ist keine Behebung.
    """
    if not isinstance(document, dict) or document.get("SchemaVersion") != 2:
        raise LifecycleError("Der Sicherheitsbericht ist ungültig oder nicht unterstützt.")
    if expected_image_id is not None:
        expected_image_id = _image_id(expected_image_id)
        metadata = document.get("Metadata") or {}
        actual = metadata.get("ImageID") if isinstance(metadata, dict) else None
        if actual != expected_image_id:
            raise LifecycleError("Der Sicherheitsbericht gehört nicht zum erwarteten Image.")
    results = document.get("Results", [])
    if results is None:
        results = []
    if not isinstance(results, list):
        raise LifecycleError("Der Sicherheitsbericht enthält keine gültige Ergebnisliste.")
    found: dict[tuple[str, str, str], dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            raise LifecycleError("Ein Ergebnis im Sicherheitsbericht ist ungültig.")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise LifecycleError("Die Schwachstellenliste ist ungültig.")
        for item in vulnerabilities:
            if not isinstance(item, dict):
                raise LifecycleError("Eine Schwachstelle hat ein ungültiges Format.")
            cve, package = item.get("VulnerabilityID"), item.get("PkgName")
            if not isinstance(cve, str) or not cve or not isinstance(package, str) or not package:
                raise LifecycleError("Eine Schwachstelle enthält keine gültige Kennung oder Paketbezeichnung.")
            severity = item.get("Severity")
            if not isinstance(severity, str) or severity not in SEVERITY_RANK:
                raise LifecycleError("Eine Schwachstelle enthält keinen gültigen Schweregrad.")
            if severity not in {"HIGH", "CRITICAL"}:
                continue
            key = (str(result.get("Type") or result.get("Class") or "unknown"), package, cve)
            old = found.get(key)
            if old is None or SEVERITY_RANK[severity] > SEVERITY_RANK[old["severity"]]:
                found[key] = {"type": key[0], "package": package, "id": cve,
                              "severity": severity, "fix_available": bool(item.get("FixedVersion"))}
            elif item.get("FixedVersion"):
                found[key]["fix_available"] = True
    return found


def compare_scans(before: dict[str, Any], after: dict[str, Any], *,
                  before_id: str | None = None, after_id: str | None = None,
                  require_improvement: bool = False) -> dict[str, Any]:
    old = vulnerability_set(before, before_id)
    new = vulnerability_set(after, after_id)
    introduced = set(new) - set(old)
    escalated = {key for key in set(old) & set(new)
                 if SEVERITY_RANK[new[key]["severity"]] > SEVERITY_RANK[old[key]["severity"]]}
    removed = set(old) - set(new)
    allowed = not introduced and not escalated and (bool(removed) or not require_improvement)
    return {"allowed": allowed, "before_count": len(old), "after_count": len(new),
            "fixed_count": len(removed), "new_count": len(introduced),
            "escalated_count": len(escalated),
            "remaining_fixable_count": sum(bool(v["fix_available"]) for v in new.values()),
            "fixed": [old[k] for k in sorted(removed)],
            "new": [new[k] for k in sorted(introduced)],
            "escalated": [new[k] for k in sorted(escalated)]}


class LifecycleEngine:
    def __init__(self, state_dir: str | Path, runner: Callable | None,
                 scan_image: Callable[[str], dict[str, Any]], *,
                 options: dict[str, Any] | None = None,
                 emit: Callable[[dict[str, Any]], None] | None = None,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] | None = None) -> None:
        self.state_dir = Path(state_dir).absolute()
        self.runner = runner or DockerRunner()
        self.scan_image = scan_image
        self.options = {"retention_days": 7, "health_timeout": 120,
                        "health_max_wait": 2400, "health_interval": 5,
                        "stable_seconds": 10, "build_pull": True,
                        "build_no_cache": True, "build_timeout": 3600,
                        "excluded_projects": ["wazuh", "ugreen_minecraft_java"],
                        "dry_run": False, **(options or {})}
        for key in ("health_timeout", "health_max_wait", "health_interval", "stable_seconds", "build_timeout"):
            try:
                value = float(self.options[key])
            except (TypeError, ValueError) as exc:
                raise LifecycleError(f"Ungültige Zeiteinstellung: {key}") from exc
            if not math.isfinite(value) or value < 0:
                raise LifecycleError(f"Ungültige Zeiteinstellung: {key}")
        try:
            self.options["retention_days"] = max(7, int(self.options["retention_days"]))
        except (TypeError, ValueError) as exc:
            raise LifecycleError("Die Aufbewahrungsdauer ist ungültig.") from exc
        if isinstance(self.options["excluded_projects"], str):
            self.options["excluded_projects"] = [p.strip() for p in self.options["excluded_projects"].split(",") if p.strip()]
        self.emit = emit or (lambda event: None)
        self.clock, self.sleep = clock, sleep
        self.monotonic = monotonic or (time.monotonic if clock is time.time else clock)
        self.tx_dir = self.state_dir / "transactions"
        self.deploy_dir = self.state_dir / "deployments"
        self.candidate_dir = self.state_dir / "candidate-configs"
        self.retention_file = self.state_dir / "image-retention.json"
        self._describe_cache: dict[str, dict[str, Any]] = {}
        self._context_cache: dict[str, dict[str, Any]] = {}

    def _call(self, args: list[str], *, cwd: str | None = None,
              timeout: float = 60, allow_failure: bool = False):
        try:
            result = self.runner(args, cwd=cwd, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LifecycleError(f"Docker-Aufruf fehlgeschlagen oder Zeitlimit erreicht: {args[0]}") from exc
        if result.returncode and not allow_failure:
            raise LifecycleError(f"Docker-Aufruf fehlgeschlagen: {args[0]} (Rückgabewert {result.returncode}).")
        return result

    def _json_call(self, args: list[str], *, cwd: str | None = None,
                   timeout: float = 60) -> Any:
        result = self._call(args, cwd=cwd, timeout=timeout)
        try:
            return json.loads(result.stdout)
        except (TypeError, ValueError) as exc:
            raise LifecycleError("Docker hat ungültige JSON-Daten geliefert.") from exc

    def _inspect_container(self, container_id: str) -> dict[str, Any]:
        value = self._json_call(["inspect", "--type", "container", _container_id(container_id)])
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise LifecycleError("Ein Container konnte nicht eindeutig gelesen werden.")
        if value[0].get("Id") != container_id:
            raise LifecycleError("Die gelesene Container-ID stimmt nicht überein.")
        return value[0]

    def _inspect_image(self, reference: str) -> dict[str, Any]:
        value = self._json_call(["image", "inspect", _image_ref(reference)])
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise LifecycleError("Ein Image konnte nicht eindeutig gelesen werden.")
        _image_id(value[0].get("Id"))
        return value[0]

    def _tag_image_id(self, reference: str) -> str | None:
        """Den aktuellen Namen lesen; ein Docker-Fehler ist keine Abwesenheit."""
        reference = _image_ref(reference)
        result = self._call(["image", "inspect", reference], allow_failure=True)
        if result.returncode:
            if "no such image" not in str(result.stderr).lower():
                raise LifecycleError("Die Zuordnung des ursprünglichen Image-Namens konnte nicht gelesen werden.")
            # Confirm that the daemon itself is still reachable; only the
            # explicit missing-image response is treated as an absent tag.
            self._all_image_ids()
            return None
        try:
            values = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise LifecycleError("Die Image-Namenszuordnung ist ungültig.") from exc
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise LifecycleError("Die Image-Namenszuordnung ist nicht eindeutig.")
        return _image_id(values[0].get("Id"))

    def _source_tag_snapshot(self, reference: str, old_image_id: str) -> dict[str, Any]:
        if "@" in reference or IMAGE_ID.fullmatch(reference):
            raise LifecycleError("Für die automatische Übernahme ist ein eindeutiger veränderbarer Image-Name erforderlich.")
        before = self._tag_image_id(reference)
        if before not in {None, old_image_id}:
            raise LifecycleError("Der ursprüngliche Image-Name zeigt bereits auf eine andere Version; diese Änderung wird nicht überschrieben.")
        return {"reference": reference, "before_image_id": before, "phase": "prepared"}

    def _check_source_tag(self, transaction: dict[str, Any]) -> None:
        source = transaction["source_tag"]
        if self._tag_image_id(source["reference"]) != source["before_image_id"]:
            raise LifecycleError("Der ursprüngliche Image-Name wurde zwischenzeitlich geändert; die fremde Zuordnung bleibt erhalten.")

    def _commit_source_tag(self, transaction: dict[str, Any]) -> None:
        self._check_source_tag(transaction)
        source = transaction["source_tag"]
        source["phase"] = "setting"
        source["after_image_id"] = transaction["candidate_image_id"]
        self._journal(transaction, "tag_committing")
        self._call(["image", "tag", source["after_image_id"], source["reference"]])
        source["phase"] = "applied"
        self._journal(transaction, "tag_committed")
        if self._tag_image_id(source["reference"]) != source["after_image_id"]:
            raise LifecycleError("Die Übernahme des ursprünglichen Image-Namens konnte nicht bestätigt werden.")

    def _restore_source_tag(self, transaction: dict[str, Any]) -> str:
        source = transaction["source_tag"]
        current = self._tag_image_id(source["reference"])
        before = source["before_image_id"]
        if current == before:
            source["phase"] = "restored"
            self._journal(transaction)
            return "restored"
        if source["phase"] == "prepared":
            # We never changed this tag. It belongs to the intervening actor.
            source["phase"] = "external_change_preserved"
            self._journal(transaction)
            return "external_change_preserved"
        if current != source.get("after_image_id"):
            source["phase"] = "conflict"
            self._journal(transaction)
            raise LifecycleError("Der Image-Name wurde nach der Übernahme fremd geändert; er wurde nicht zurückgesetzt.")
        source["phase"] = "restoring"
        self._journal(transaction)
        if before is None:
            # The candidate also has its own durable name. Removing only the
            # newly-created logical alias must not remove unrelated content.
            self._call(["image", "rm", "--no-prune", source["reference"]])
        else:
            self._call(["image", "tag", before, source["reference"]])
        if self._tag_image_id(source["reference"]) != before:
            raise LifecycleError("Die Wiederherstellung des ursprünglichen Image-Namens konnte nicht bestätigt werden.")
        source["phase"] = "restored"
        self._journal(transaction)
        return "restored"

    def _all_containers(self) -> list[dict[str, Any]]:
        result = self._call(["ps", "-aq", "--no-trunc"])
        ids = list(dict.fromkeys(result.stdout.split()))
        for cid in ids:
            _container_id(cid)
        values: list[dict[str, Any]] = []
        for offset in range(0, len(ids), 20):
            batch = ids[offset:offset + 20]
            found = self._json_call(["inspect", "--type", "container", *batch])
            if (not isinstance(found, list) or len(found) != len(batch)
                    or {item.get("Id") for item in found if isinstance(item, dict)} != set(batch)):
                raise LifecycleError("Der Containerbestand konnte nicht vollständig gelesen werden.")
            for item in found:
                _image_id(item.get("Image"))
            values.extend(found)
        # A disappearing or newly-created container makes deletion unsafe.
        again = self._call(["ps", "-aq", "--no-trunc"]).stdout.split()
        if set(ids) != set(again):
            raise LifecycleError("Der Containerbestand hat sich während der Prüfung verändert.")
        return values

    def _all_image_ids(self) -> set[str]:
        values = set(self._call(["image", "ls", "-aq", "--no-trunc"]).stdout.split())
        for value in values:
            _image_id(value)
        return values

    @contextmanager
    def _lock(self):
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.state_dir / "lifecycle.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LifecycleError("Eine weitere Aktualisierung oder Bereinigung läuft bereits.") from exc
            yield
        finally:
            os.close(fd)

    def _journal(self, transaction: dict[str, Any], phase: str | None = None) -> None:
        if phase:
            transaction["phase"] = phase
        transaction["updated_at"] = self.clock()
        atomic_json(self.tx_dir / f"{transaction['id']}.json", transaction)

    def open_transactions(self) -> list[dict[str, Any]]:
        if not self.tx_dir.exists():
            return []
        result = []
        for path in sorted(self.tx_dir.glob("*.json")):
            data = read_json(path)
            if data.get("schema") != SCHEMA or not isinstance(data.get("phase"), str):
                raise LifecycleError("Ein Aktualisierungsprotokoll ist beschädigt; Änderungen sind gesperrt.")
            _image_id(data.get("old_image_id"))
            if data.get("candidate_image_id"):
                _image_id(data["candidate_image_id"])
            if data["phase"] not in TERMINAL_PHASES:
                result.append(data)
        return result

    def _read_retention(self) -> dict[str, Any]:
        if not self.retention_file.exists():
            return {"schema": SCHEMA, "images": {}}
        data = read_json(self.retention_file)
        if data.get("schema") != SCHEMA or not isinstance(data.get("images"), dict):
            raise LifecycleError("Das Aufbewahrungsregister ist ungültig; es wird nichts gelöscht.")
        for key, entry in data["images"].items():
            _image_id(key)
            if (not isinstance(entry, dict) or entry.get("image_id") != key
                    or not isinstance(entry.get("retain_until"), (int, float))
                    or not math.isfinite(entry["retain_until"])
                    or not isinstance(entry.get("successful_replacement_at"), (int, float))
                    or not math.isfinite(entry["successful_replacement_at"])
                    or entry["retain_until"] - entry["successful_replacement_at"] < 7 * 86400
                    or not isinstance(entry.get("allowed_tags"), list)):
                raise LifecycleError("Ein Aufbewahrungseintrag ist ungültig; es wird nichts gelöscht.")
            for tag in entry["allowed_tags"]:
                _image_ref(tag)
        return data

    def _retain(self, transaction: dict[str, Any], succeeded_at: float) -> None:
        data = self._read_retention()
        old_id = transaction["old_image_id"]
        existing = data["images"].get(old_id, {})
        days = max(7, int(self.options["retention_days"]))
        tags = set(existing.get("allowed_tags", []))
        # A shared image can have an unrelated manual alias even before this
        # transaction. Registration must not silently take ownership of it.
        tags.update(tag for tag in transaction.get("old_tags", [])
                    if tag == transaction["image_ref"] or OWN_IMAGE_TAG.fullmatch(tag))
        tags.add(transaction["backup_tag"])
        data["images"][old_id] = {
            "image_id": old_id,
            "successful_replacement_at": succeeded_at,
            "retain_until": max(succeeded_at + days * 86400, existing.get("retain_until", 0)),
            "allowed_tags": sorted(tags),
            "transaction_ids": list(dict.fromkeys([*existing.get("transaction_ids", []), transaction["id"]])),
            "services": list({(service["project"], service["service"]): {
                "project": service["project"], "service": service["service"]}
                for service in [*existing.get("services", []), *transaction["services"]]}.values()),
        }
        atomic_json(self.retention_file, data)

    def _managed_override(self, path: Path) -> dict[str, Any] | None:
        if path.parent.absolute() != self.deploy_dir.absolute():
            return None
        data = read_json(path)
        marker = data.get("x-securitywatch")
        if (not isinstance(marker, dict) or marker.get("schema") != SCHEMA
                or not isinstance(marker.get("sources"), dict)
                or set(data) != {"x-securitywatch", "services"}
                or not isinstance(data.get("services"), dict)):
            raise LifecycleError("Eine verwaltete Compose-Ergänzung ist ungültig.")
        for name, service in data["services"].items():
            if (not SERVICE_NAME.fullmatch(name) or not isinstance(service, dict)
                    or set(service) != {"image", "pull_policy"}
                    or service.get("pull_policy") != "never"):
                raise LifecycleError("Eine verwaltete Image-Zuordnung ist ungültig.")
            _image_ref(service.get("image"))
        return data

    def _context(self, container: dict[str, Any], *, fresh: bool = False) -> dict[str, Any]:
        labels = container.get("Config", {}).get("Labels") or {}
        project, service = labels.get("com.docker.compose.project"), labels.get("com.docker.compose.service")
        working_dir = labels.get("com.docker.compose.project.working_dir")
        config_csv = labels.get("com.docker.compose.project.config_files")
        if (not isinstance(project, str) or not SERVICE_NAME.fullmatch(project)
                or not isinstance(service, str) or not SERVICE_NAME.fullmatch(service)
                or not isinstance(working_dir, str) or not Path(working_dir).is_absolute()
                or not Path(working_dir).is_dir() or not isinstance(config_csv, str)):
            raise LifecycleError("Die Compose-Zuordnung des Dienstes ist unvollständig.")
        base_files, source_meta = [], {}
        for text in config_csv.split(","):
            path = Path(text.strip())
            if not path.is_absolute() or not path.is_file():
                raise LifecycleError("Eine zugehörige Compose-Datei fehlt.")
            own = self._managed_override(path)
            if own is not None:
                source_meta.update(own["x-securitywatch"]["sources"])
            else:
                if path.stat().st_size > 4 * 1024 * 1024:
                    raise LifecycleError("Eine Compose-Datei ist unerwartet groß.")
                base_files.append(str(path))
        if not base_files:
            raise LifecycleError("Die ursprüngliche Compose-Datei fehlt.")
        identity = {"project": project, "working_dir": working_dir, "config_files": base_files}
        key = hashlib.sha256(_canonical(identity)).hexdigest()[:32]
        if not fresh and key in self._context_cache:
            context = self._context_cache[key]
            if service not in context["config"].get("services", {}):
                raise LifecycleError("Der Dienst fehlt in seiner Compose-Datei.")
            return context
        args = ["compose", "--project-directory", working_dir, "-p", project]
        for file in base_files:
            args.extend(["-f", file])
        config = self._json_call([*args, "config", "--format", "json"], cwd=working_dir)
        if (not isinstance(config, dict) or not isinstance(config.get("services"), dict)
                or not isinstance(config["services"].get(service), dict)):
            raise LifecycleError("Der Dienst fehlt in der ausgewerteten Compose-Datei.")
        override_path = self.deploy_dir / f"{key}.json"
        override = self._managed_override(override_path) if override_path.exists() else None
        if override:
            if override["x-securitywatch"].get("context") != key:
                raise LifecycleError("Die verwaltete Compose-Zuordnung passt nicht zum Projekt.")
            source_meta.update(override["x-securitywatch"]["sources"])
        fingerprints = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in base_files}
        context = {**identity, "key": key, "args": args, "config": config,
                   "base_fingerprint": hashlib.sha256(_canonical({"files": fingerprints, "config": config})).hexdigest(),
                   "fingerprint": hashlib.sha256(_canonical({"files": fingerprints, "config": config,
                                                              "override": override})).hexdigest(),
                   "override_path": str(override_path), "override": override,
                   "source_meta": source_meta}
        self._context_cache[key] = context
        return context

    def _assert_base_unchanged(self, context: dict[str, Any]) -> None:
        # Re-read both direct files and the resolved basis. The latter also
        # catches changed .env/env_file/include content without exporting it.
        config = self._json_call([*context["args"], "config", "--format", "json"],
                                 cwd=context["working_dir"])
        fingerprints = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
                        for p in context["config_files"]}
        current = hashlib.sha256(_canonical({"files": fingerprints, "config": config})).hexdigest()
        if current != context["base_fingerprint"]:
            raise LifecycleError("Die ursprüngliche Compose-Konfiguration wurde geändert; dieser Start wird nicht ausgeführt.")

    def health_budget(self, container: dict[str, Any]) -> int:
        config = container.get("Config", {}).get("Healthcheck") or {}
        test = config.get("Test")
        if (not isinstance(test, list) or len(test) < 2
                or test[0] not in {"CMD", "CMD-SHELL"}):
            raise LifecycleError("Keine belastbare Zustandsprüfung eingerichtet.")
        def seconds(key: str, default: float) -> float:
            value = config.get(key)
            if value in (None, 0):
                return default
            if not isinstance(value, (float, int)) or value < 0:
                raise LifecycleError("Die Zeitangaben der Zustandsprüfung sind ungültig.")
            return value / 1_000_000_000
        retries = config.get("Retries") or 3
        if not isinstance(retries, int) or retries < 1:
            raise LifecycleError("Die Wiederholungszahl der Zustandsprüfung ist ungültig.")
        budget = max(float(self.options["health_timeout"]),
                     seconds("StartPeriod", 0) + retries * (seconds("Interval", 30) + seconds("Timeout", 30))
                     + float(self.options["stable_seconds"]))
        if budget > float(self.options["health_max_wait"]):
            raise LifecycleError("Die Zustandsprüfung benötigt mehr Zeit als freigegeben; eine passende Startprüfung ist erforderlich.")
        return math.ceil(budget)

    def _build_fingerprint(self, service: dict[str, Any], working_dir: str) -> str:
        """Fingerprint build configuration and common dependency inputs.

        This is a retry hint, not a claim to snapshot the complete Docker build
        context. Weekly rebuilds still run even without a changed fingerprint.
        Only hashes leave memory; dependency files can contain private URLs.
        """
        build = service.get("build")
        inputs: dict[str, Any] = {"build": build, "files": {}}
        if isinstance(build, str):
            build = {"context": build}
        if not isinstance(build, dict):
            return hashlib.sha256(_canonical(inputs)).hexdigest()
        context_text = build.get("context")
        if (not isinstance(context_text, str) or "://" in context_text
                or context_text.startswith("git@")):
            return hashlib.sha256(_canonical(inputs)).hexdigest()
        context = Path(context_text)
        if not context.is_absolute():
            context = Path(working_dir) / context
        dockerfile = Path(str(build.get("dockerfile") or "Dockerfile"))
        if not dockerfile.is_absolute():
            dockerfile = context / dockerfile
        candidates = {dockerfile, context / ".dockerignore"}
        names = ("pyproject.toml", "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock",
                 "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
                 "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock",
                 "composer.json", "composer.lock")
        candidates.update(context / name for name in names)
        if context.is_dir():
            candidates.update(context.glob("requirements*.txt"))
        for path in sorted(candidates, key=str):
            key = str(path)
            try:
                # Do not follow a dependency-file symlink into an unrelated tree.
                if path.is_symlink():
                    inputs["files"][key] = {"link": os.readlink(path)}
                elif path.is_file():
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
                    inputs["files"][key] = digest.hexdigest()
                else:
                    inputs["files"][key] = None
            except OSError as exc:
                raise LifecycleError("Eine lokale Baugrundlage konnte nicht zuverlässig gelesen werden.") from exc
        return hashlib.sha256(_canonical(inputs)).hexdigest()

    def describe(self, container: dict[str, Any]) -> dict[str, Any]:
        cid, iid = _container_id(container.get("Id")), _image_id(container.get("Image"))
        config = container.get("Config") or {}
        labels = config.get("Labels") or {}
        descriptor = {"container_id": cid, "name": str(container.get("Name", "")).lstrip("/"),
                      "image_id": iid, "image_ref": _image_ref(config.get("Image")),
                      "project": labels.get("com.docker.compose.project", ""),
                      "service": labels.get("com.docker.compose.service", ""),
                      "working_dir": labels.get("com.docker.compose.project.working_dir", ""),
                      "config_files": [], "origin": "unknown", "automatic_allowed": False,
                      "build_allowed": False, "build_fingerprint": "",
                      "reason": "", "health_budget_seconds": None, "compose_fingerprint": ""}
        try:
            context = self._context(container)
            service = context["config"]["services"][descriptor["service"]]
            source_meta = context["source_meta"].get(descriptor["service"], {})
            source_ref = service.get("image") or source_meta.get("image_ref") or descriptor["image_ref"]
            descriptor["image_ref"] = _image_ref(source_ref)
            descriptor["config_files"] = context["config_files"]
            descriptor["compose_fingerprint"] = context["fingerprint"]
            if service.get("build"):
                descriptor["origin"] = "local"
                descriptor["build_fingerprint"] = self._build_fingerprint(service, context["working_dir"])
            elif "@sha256:" in source_ref:
                descriptor["origin"] = "pinned"
            else:
                image = self._inspect_image(iid)
                if image.get("RepoDigests") or source_meta.get("origin") == "registry":
                    descriptor["origin"] = "registry"
            if any(fnmatch.fnmatchcase(descriptor["project"], pattern) for pattern in self.options["excluded_projects"]):
                raise LifecycleError("Dieses Projekt hat einen getrennten Aktualisierungsweg.")
            if descriptor["origin"] == "unknown":
                raise LifecycleError("Die Herkunft und Bauanleitung des Images sind noch nicht eindeutig zugeordnet.")
            if descriptor["origin"] == "pinned":
                raise LifecycleError("Die Compose-Datei ist auf eine feste Image-Version gebunden; die Quellenzuordnung muss aktualisiert werden.")
            state = container.get("State") or {}
            if not state.get("Running") or state.get("Status") != "running":
                raise LifecycleError("Der Dienst läuft nicht und wird nicht automatisch gestartet.")
            for transaction in self.open_transactions():
                if (iid in {transaction["old_image_id"], transaction.get("candidate_image_id")}
                        or any(s.get("project") == descriptor["project"] and s.get("service") == descriptor["service"]
                               for s in transaction.get("services", []))):
                    raise PendingTransactionError("Ein vorheriger Aktualisierungsvorgang ist noch ungeklärt.")
            # A missing healthcheck blocks deployment, but need not prevent a
            # separately tagged local build and security comparison. Excluded,
            # stopped or unresolved services remain blocked even for a build.
            descriptor["build_allowed"] = descriptor["origin"] == "local"
            descriptor["health_budget_seconds"] = self.health_budget(container)
            if state.get("Health", {}).get("Status") != "healthy":
                raise LifecycleError("Die Zustandsprüfung ist bereits vor der Aktualisierung nicht erfolgreich.")
            descriptor["automatic_allowed"] = True
        except LifecycleError as exc:
            descriptor["reason"] = str(exc)
        self._describe_cache[cid] = descriptor
        return descriptor

    def _emit(self, event: dict[str, Any]) -> None:
        try:
            self.emit(event)
        except Exception:
            # A reporting callback must not roll back an already committed
            # production change. The caller still receives the result object.
            event["reporting_warning"] = "Die unmittelbare Ereignismeldung ist fehlgeschlagen."

    def _event(self, status: str, descriptors: list[dict[str, Any]], message: str,
               *, severity: str = "info", **extra: Any) -> dict[str, Any]:
        old_id = descriptors[0]["image_id"] if descriptors else None
        new_id = extra.get("new_image_id")
        deployed = status in {"rebuilt", "update_applied"}
        verified = deployed or status == "rolled_back"
        attempted_build = bool(extra.get("attempted_build", False))
        event = {"kind": "update", "status": status, "severity": severity,
                 "project": ", ".join(sorted({d["project"] for d in descriptors})),
                 "service": ", ".join(d["service"] or d["name"] for d in descriptors),
                 "image": descriptors[0]["image_ref"] if descriptors else "",
                 "message": message, "changed": False,
                 "old_image_id": old_id, "new_image_id": new_id,
                 "actual_image_id": new_id if deployed else None if status == "rollback_failed" else old_id,
                 "attempted_build": attempted_build,
                 "build_status": "failed" if status == "build_failed" else "succeeded" if attempted_build else "not_attempted",
                 "deployment_status": "applied" if deployed else "rolled_back" if status == "rolled_back"
                                      else "failed" if status == "rollback_failed" else "kept_previous",
                 "verification_status": "ok" if verified else "failed" if status == "rollback_failed" else "not_run",
                 **extra}
        self._emit(event)
        return event

    def _fresh_group(self, originals: list[dict[str, Any]], descriptors: list[dict[str, Any]],
                     contexts: dict[str, dict[str, Any]], *, require_healthy: bool = True) -> None:
        expected_ids = {d["container_id"] for d in descriptors}
        live = self._all_containers()
        live_by_id = {c["Id"]: c for c in live}
        if not expected_ids.issubset(live_by_id):
            raise LifecycleError("Ein vorbereiteter Container wurde zwischenzeitlich verändert oder entfernt.")
        keys = {(d["project"], d["service"]) for d in descriptors}
        if len(keys) != len(descriptors):
            raise LifecycleError("Mehrere Instanzen desselben Dienstes benötigen eine eigene Aktualisierungsregel.")
        old_id, image_ref = descriptors[0]["image_id"], descriptors[0]["image_ref"]
        for original, descriptor in zip(originals, descriptors):
            now = live_by_id[descriptor["container_id"]]
            if (now.get("Image") != old_id or now.get("Config", {}).get("Image") != original.get("Config", {}).get("Image")
                    or not now.get("State", {}).get("Running")
                    or (require_healthy and now.get("State", {}).get("Health", {}).get("Status") != "healthy")):
                raise LifecycleError("Der Ausgangszustand hat sich während der Vorbereitung verändert.")
            current_context = self._context(now, fresh=True)
            old_context = contexts[current_context["key"]]
            if current_context["fingerprint"] != old_context["fingerprint"]:
                raise LifecycleError("Die Compose-Konfiguration wurde während der Vorbereitung verändert.")
            if descriptor.get("build_fingerprint"):
                service = current_context["config"]["services"][descriptor["service"]]
                if self._build_fingerprint(service, current_context["working_dir"]) != descriptor["build_fingerprint"]:
                    raise LifecycleError("Die lokale Baugrundlage wurde während der Vorbereitung verändert.")
        # An omitted running consumer of the same logical source may not be
        # silently left behind. Other aliases are protected by retention.
        for container in live:
            if container["Id"] in expected_ids or not container.get("State", {}).get("Running"):
                continue
            if container.get("Image") != old_id:
                continue
            config_ref = container.get("Config", {}).get("Image")
            if config_ref == originals[0].get("Config", {}).get("Image"):
                raise LifecycleError("Ein weiterer laufender Dienst verwendet diese Image-Zuordnung; die Gruppe ist unvollständig.")

    def _pin(self, context: dict[str, Any], descriptors: list[dict[str, Any]],
             tag: str, source: str) -> None:
        current = context["override"] or {"services": {}, "x-securitywatch": {
            "schema": SCHEMA, "context": context["key"], "sources": {}}}
        current = copy.deepcopy(current)
        for descriptor in descriptors:
            if descriptor["project"] != context["project"] or descriptor["working_dir"] != context["working_dir"]:
                continue
            current["services"][descriptor["service"]] = {"image": tag, "pull_policy": "never"}
            current["x-securitywatch"]["sources"][descriptor["service"]] = {
                "image_ref": descriptor["image_ref"], "origin": source}
        atomic_json(Path(context["override_path"]), current)

    def _service_container(self, descriptor: dict[str, Any]) -> dict[str, Any]:
        result = self._call(["ps", "-aq", "--no-trunc", "--filter",
                             f"label=com.docker.compose.project={descriptor['project']}", "--filter",
                             f"label=com.docker.compose.service={descriptor['service']}"])
        ids = result.stdout.split()
        if len(ids) != 1:
            raise LifecycleError("Der gestartete Dienst konnte nicht eindeutig zugeordnet werden.")
        return self._inspect_container(_container_id(ids[0]))

    def _wait_healthy(self, descriptor: dict[str, Any], expected_image: str) -> dict[str, Any]:
        started = self.monotonic()
        deadline = started + int(descriptor["health_budget_seconds"])
        stable_start: float | None = None
        seen_id: str | None = None
        while self.monotonic() < deadline:
            current = self._service_container(descriptor)
            if current.get("Image") != expected_image:
                raise LifecycleError("Nach dem Start läuft nicht die erwartete Image-Version.")
            cid = current.get("Id")
            if seen_id is not None and cid != seen_id:
                raise LifecycleError("Der Container wurde während der Zustandsprüfung ausgetauscht.")
            seen_id = cid
            state = current.get("State") or {}
            if not state.get("Running") or state.get("Status") != "running" or state.get("Restarting"):
                raise LifecycleError("Der gestartete Dienst läuft nicht stabil.")
            if int(current.get("RestartCount", 0)) != 0:
                raise LifecycleError("Der gestartete Dienst wurde unerwartet neu gestartet.")
            self.health_budget(current)  # NONE or an unknown changed check is never success.
            health = state.get("Health", {}).get("Status")
            if health == "unhealthy":
                raise LifecycleError("Die Zustandsprüfung nach dem Start ist fehlgeschlagen.")
            if health == "healthy":
                if stable_start is None:
                    stable_start = self.monotonic()
                if self.monotonic() - stable_start >= float(self.options["stable_seconds"]):
                    return current
            elif health == "starting":
                stable_start = None
            else:
                raise LifecycleError("Der gestartete Dienst liefert keinen eindeutigen Prüfstatus.")
            self.sleep(min(max(0.1, float(self.options["health_interval"])), max(0, deadline - self.monotonic())))
        raise LifecycleError("Die Zustandsprüfung hat das freigegebene Zeitlimit überschritten.")

    def _up(self, descriptor: dict[str, Any], context: dict[str, Any], expected_image: str) -> dict[str, Any]:
        self._assert_base_unchanged(context)
        args = [*context["args"], "-f", context["override_path"], "up", "-d", "--no-deps",
                "--no-build", "--pull", "never", "--force-recreate", descriptor["service"]]
        self._call(args, cwd=context["working_dir"], timeout=max(120, float(self.options["health_timeout"])))
        return self._wait_healthy(descriptor, expected_image)

    def _verify_group_snapshot(self, descriptors: list[dict[str, Any]], expected_image: str,
                               expected_containers: dict[tuple[str, str], str]) -> None:
        for descriptor in descriptors:
            current = self._service_container(descriptor)
            state = current.get("State") or {}
            if (current.get("Id") != expected_containers[(descriptor["project"], descriptor["service"])]
                    or current.get("Image") != expected_image or not state.get("Running")
                    or state.get("Status") != "running" or state.get("Restarting")
                    or int(current.get("RestartCount", 0)) != 0
                    or state.get("Health", {}).get("Status") != "healthy"):
                raise LifecycleError("Die gemeinsame Abschlussprüfung der betroffenen Dienste ist fehlgeschlagen.")
            self.health_budget(current)

    def _remove_hold_tag(self, transaction: dict[str, Any]) -> None:
        # Removing a temporary alias is optional. Any failure leaves protection
        # in place and must never turn a rejected update into an unsafe cleanup.
        result = self._call(["image", "rm", "--no-prune", transaction["backup_tag"]], allow_failure=True)
        if result.returncode:
            self._emit({"kind": "retention", "status": "tag_kept", "severity": "info",
                       "message": "Ein vorübergehender Schutzname bleibt erhalten.",
                       "image_id": transaction["old_image_id"], "changed": False})

    def _release_candidate_alias(self, transaction: dict[str, Any]) -> None:
        """Ein eigener Zusatzname darf kein fremdes, bereits vorhandenes Image löschen."""
        iid, tag = transaction.get("candidate_image_id"), transaction.get("candidate_tag")
        if not iid or not tag:
            return
        try:
            result = self._call(["image", "inspect", tag], allow_failure=True)
            if result.returncode:
                return
            images = json.loads(result.stdout)
            if not isinstance(images, list) or len(images) != 1 or images[0].get("Id") != iid:
                return
            if not (set(images[0].get("RepoTags") or []) - {tag}):
                return
            if any(c.get("Config", {}).get("Image") == tag for c in self._all_containers()):
                return
            self._call(["image", "rm", "--no-prune", tag])
        except (LifecycleError, ValueError, TypeError):
            # The image is left available. No force and no deletion of another
            # owner's pre-existing image to save a mere additional alias.
            return

    def _discard_candidate(self, transaction: dict[str, Any]) -> None:
        iid, tag = transaction.get("candidate_image_id"), transaction.get("candidate_tag")
        if not iid or not tag or not transaction.get("candidate_created_here"):
            return
        try:
            if any(c["Image"] == iid for c in self._all_containers()):
                return
            image = self._inspect_image(iid)
            tags = image.get("RepoTags") or []
            if set(tags) - {tag}:
                return
            if tag in tags:
                self._call(["image", "rm", "--no-prune", tag])
            if iid in self._all_image_ids():
                self._call(["image", "rm", "--no-prune", iid])
        except LifecycleError:
            self._emit({"kind": "retention", "status": "candidate_kept", "severity": "warning",
                       "message": "Ein verworfenes Kandidaten-Image konnte noch nicht entfernt werden.",
                       "image_id": iid, "changed": False})

    def update_group(self, containers: list[dict[str, Any]], *, source: str,
                     remote_ref: str | None = None, require_improvement: bool = False,
                     prepare_only: bool = False) -> dict[str, Any]:
        with self._lock():
            try:
                return self._update_group(containers, source=source, remote_ref=remote_ref,
                                          require_improvement=require_improvement, prepare_only=prepare_only)
            finally:
                self._context_cache.clear()

    def _update_group(self, containers: list[dict[str, Any]], *, source: str,
                      remote_ref: str | None, require_improvement: bool,
                      prepare_only: bool = False) -> dict[str, Any]:
        if not containers:
            raise LifecycleError("Die Aktualisierungsgruppe ist leer.")
        if source not in {"local", "registry"}:
            raise LifecycleError("Der Aktualisierungsweg ist nicht freigegeben.")
        if prepare_only and source != "local":
            raise LifecycleError("Ein getrennter Probebau ist nur für lokale Images vorgesehen.")
        self._context_cache.clear()
        descriptors = [self.describe(c) for c in containers]
        allowed_key = "build_allowed" if prepare_only else "automatic_allowed"
        blocked = [d for d in descriptors if not d[allowed_key] or d["origin"] != source]
        if blocked:
            return self._event("skipped", descriptors, blocked[0]["reason"] or "Der Aktualisierungsweg ist uneindeutig.",
                               severity="warning", action="Baugrundlage oder Zustandsprüfung dieses Dienstes ergänzen.")
        old_id, logical_ref = descriptors[0]["image_id"], descriptors[0]["image_ref"]
        if any(d["image_id"] != old_id or d["image_ref"] != logical_ref for d in descriptors):
            raise LifecycleError("Die Gruppe verwendet unterschiedliche Ausgangsversionen oder Quellen.")
        contexts = {self._context(c)["key"]: copy.deepcopy(self._context(c)) for c in containers}
        if source == "local":
            builds = {_canonical(self._context(c)["config"]["services"][d["service"]].get("build"))
                      for c, d in zip(containers, descriptors)}
            if len(builds) != 1:
                return self._event("skipped", descriptors, "Gemeinsam verwendete Images haben unterschiedliche Bauanleitungen.", severity="warning")
        if source == "registry":
            if (not remote_ref or "@sha256:" not in _image_ref(remote_ref)
                    or image_repository(remote_ref) != image_repository(logical_ref)):
                raise LifecycleError("Der Kandidat muss aus derselben Quelle mit festem Digest geladen werden.")
        self._fresh_group(containers, descriptors, contexts, require_healthy=not prepare_only)
        try:
            source_tag = self._source_tag_snapshot(logical_ref, old_id)
        except LifecycleError as exc:
            return self._event("skipped", descriptors, str(exc), severity="warning",
                               action="Die vorhandene Image-Zuordnung zuerst mit dem laufenden Dienst abgleichen.")
        if self.options["dry_run"]:
            return self._event("planned", descriptors, "Aktualisierung vorbereitet; im Probelauf wird nichts verändert.")
        # Read every safety document before the first mutation.
        self._read_retention()
        self.open_transactions()
        try:
            baseline = self.scan_image(old_id)
            vulnerability_set(baseline, old_id)
        except Exception as exc:
            return self._event("scan_failed", descriptors, "Die Ausgangsversion konnte nicht zuverlässig geprüft werden.",
                               severity="error", action="Prüfprotokoll kontrollieren; laufender Dienst wurde nicht verändert.")
        before_ids = self._all_image_ids()
        old_image = self._inspect_image(old_id)
        transaction_id = uuid.uuid4().hex
        backup_tag = f"securitywatch-previous:{transaction_id}"
        candidate_tag = f"securitywatch-candidate:{transaction_id}"
        transaction = {
            "schema": SCHEMA, "id": transaction_id, "phase": "prepared",
            "created_at": self.clock(), "old_image_id": old_id,
            "old_tags": list(old_image.get("RepoTags") or []),
            "backup_tag": backup_tag, "candidate_tag": candidate_tag,
            "image_ref": logical_ref, "source": source,
            "source_tag": source_tag,
            "services": descriptors, "touched_services": [],
            "overrides": {key: {"path": c["override_path"], "before": c["override"]} for key, c in contexts.items()},
        }
        self._journal(transaction)
        build_file: Path | None = None
        try:
            self._call(["image", "tag", old_id, backup_tag])
            self._journal(transaction, "candidate_preparation")
            if source == "local":
                first = descriptors[0]
                context = self._context(containers[0])
                build_file = self.candidate_dir / f"{transaction_id}.json"
                atomic_json(build_file, {"services": {first["service"]: {"image": candidate_tag}}})
                args = [*context["args"], "-f", str(build_file), "build", "--builder", "default"]
                if self.options["build_pull"]:
                    args.append("--pull")
                if self.options["build_no_cache"]:
                    args.append("--no-cache")
                self._call([*args, first["service"]], cwd=context["working_dir"],
                           timeout=float(self.options["build_timeout"]))
                candidate = self._inspect_image(candidate_tag)
            else:
                self._call(["pull", remote_ref], timeout=float(self.options["build_timeout"]))
                candidate = self._inspect_image(remote_ref)
                self._call(["image", "tag", candidate["Id"], candidate_tag])
            new_id = _image_id(candidate["Id"])
            transaction["candidate_image_id"] = new_id
            transaction["candidate_created_here"] = new_id not in before_ids
            self._journal(transaction, "candidate_ready")
        except LifecycleError as exc:
            if source == "local":
                try:
                    result = self._call(["image", "inspect", candidate_tag], allow_failure=True)
                    if not result.returncode:
                        maybe = json.loads(result.stdout)
                        if isinstance(maybe, list) and len(maybe) == 1:
                            transaction["candidate_image_id"] = _image_id(maybe[0].get("Id"))
                            transaction["candidate_created_here"] = maybe[0]["Id"] not in before_ids
                except (LifecycleError, ValueError, TypeError):
                    pass
            transaction["failure"] = str(exc)
            self._journal(transaction, "rejected")
            self._discard_candidate(transaction)
            self._release_candidate_alias(transaction)
            self._remove_hold_tag(transaction)
            return self._event("build_failed" if source == "local" else "pull_failed", descriptors,
                               "Der Kandidat konnte nicht vorbereitet werden; der laufende Dienst bleibt erhalten.",
                               severity="error", transaction_id=transaction_id, attempted_build=source == "local")
        finally:
            if build_file is not None:
                try:
                    build_file.unlink(missing_ok=True)
                except OSError:
                    pass
        if new_id == old_id:
            self._journal(transaction, "unchanged")
            self._release_candidate_alias(transaction)
            self._remove_hold_tag(transaction)
            return self._event("unchanged", descriptors, "Die vorbereitete Version enthält dasselbe Image.",
                               transaction_id=transaction_id, new_image_id=new_id, attempted_build=source == "local")
        try:
            comparison = compare_scans(baseline, self.scan_image(new_id), before_id=old_id, after_id=new_id,
                                       require_improvement=require_improvement)
        except Exception:
            self._journal(transaction, "rejected")
            self._discard_candidate(transaction)
            self._release_candidate_alias(transaction)
            self._remove_hold_tag(transaction)
            return self._event("scan_failed", descriptors, "Der Kandidat konnte nicht zuverlässig geprüft werden; kein Austausch erfolgt.",
                               severity="error", transaction_id=transaction_id, new_image_id=new_id,
                               attempted_build=source == "local")
        transaction["comparison"] = comparison
        if not comparison["allowed"]:
            self._journal(transaction, "rejected")
            self._discard_candidate(transaction)
            self._release_candidate_alias(transaction)
            self._remove_hold_tag(transaction)
            message = ("Der Kandidat enthält neue oder höher bewertete hohe/kritische Schwachstellen."
                       if comparison["new_count"] or comparison["escalated_count"] else
                       "Der Neubau behebt keinen der vorhandenen hohen/kritischen Befunde.")
            return self._event("candidate_rejected", descriptors, message, severity="warning",
                               action="Abhängigkeiten oder Basisimage in der Bauanleitung korrigieren.",
                               transaction_id=transaction_id, comparison=comparison, new_image_id=new_id,
                               attempted_build=source == "local")
        try:
            self._fresh_group(containers, descriptors, contexts, require_healthy=not prepare_only)
            self._check_source_tag(transaction)
        except LifecycleError as exc:
            transaction["failure"] = str(exc)
            self._journal(transaction, "rejected")
            self._discard_candidate(transaction)
            self._release_candidate_alias(transaction)
            self._remove_hold_tag(transaction)
            return self._event("skipped", descriptors, str(exc), severity="warning", transaction_id=transaction_id,
                               new_image_id=new_id, comparison=comparison, attempted_build=source == "local")
        if prepare_only:
            # A candidate without an approved deployment path is evidence, not
            # a running update. Retain its scan in the report; remove only our
            # unused temporary image/alias, without claiming its old findings
            # were fixed in production or adding a false retention success.
            self._journal(transaction, "prepared_only")
            self._discard_candidate(transaction)
            self._release_candidate_alias(transaction)
            self._remove_hold_tag(transaction)
            reasons = "; ".join(dict.fromkeys(d["reason"] for d in descriptors if d.get("reason")))
            return self._event("prepared_only", descriptors,
                               "Lokales Image neu gebaut und geprüft; die laufende Version bleibt unverändert. " + reasons,
                               severity="warning", transaction_id=transaction_id,
                               new_image_id=new_id, comparison=comparison, attempted_build=True,
                               action="Eine belastbare Zustandsprüfung ergänzen, damit die geprüfte neue Version automatisch übernommen werden kann.")
        # From this point an interruption deliberately leaves an open journal.
        self._journal(transaction, "deploying")
        changed = False
        try:
            for context in contexts.values():
                members = [d for c, d in zip(containers, descriptors) if self._context(c)["key"] == context["key"]]
                self._pin(context, members, candidate_tag, source)
            deployed_ids = {}
            for raw, descriptor in zip(containers, descriptors):
                context = contexts[self._context(raw)["key"]]
                transaction["touched_services"].append({"project": descriptor["project"], "service": descriptor["service"]})
                self._journal(transaction)
                changed = True
                actual = self._up(descriptor, context, new_id)
                deployed_ids[(descriptor["project"], descriptor["service"])] = actual["Id"]
            self._verify_group_snapshot(descriptors, new_id, deployed_ids)
            self._journal(transaction, "verified")
            for context in contexts.values():
                self._assert_base_unchanged(context)
            self._commit_source_tag(transaction)
            self._verify_group_snapshot(descriptors, new_id, deployed_ids)
            succeeded_at = self.clock()
            transaction["successful_replacement_at"] = succeeded_at
            self._retain(transaction, succeeded_at)
            self._journal(transaction, "complete")
            action = ("Verbleibende behebbare Befunde benötigen eine Änderung der Abhängigkeiten oder Bauanleitung."
                      if comparison["remaining_fixable_count"] else "")
            return self._event("rebuilt" if source == "local" else "update_applied", descriptors,
                               "Neue Version gestartet und geprüft; Vorversion mindestens sieben Tage geschützt.",
                               changed=True, old_image_id=old_id, new_image_id=new_id,
                               transaction_id=transaction_id, comparison=comparison, action=action,
                               source_tag_status="updated",
                               attempted_build=source == "local")
        except (LifecycleError, OSError, ValueError) as exc:
            transaction["failure"] = str(exc)
            self._journal(transaction, "rolling_back")
            rollback_error = None
            source_tag_error = None
            source_tag_status = "unknown"
            containers_restored = False
            try:
                # Roll back using a persistent pin, also when the initial
                # deployment did not previously have an override.
                for context in contexts.values():
                    members = [d for c, d in zip(containers, descriptors) if self._context(c)["key"] == context["key"]]
                    self._pin(context, members, backup_tag, source)
                restored_ids = {}
                for raw, descriptor in zip(containers, descriptors):
                    actual = self._up(descriptor, contexts[self._context(raw)["key"]], old_id)
                    restored_ids[(descriptor["project"], descriptor["service"])] = actual["Id"]
                self._verify_group_snapshot(descriptors, old_id, restored_ids)
                containers_restored = True
            except (LifecycleError, OSError, ValueError) as rollback_exc:
                rollback_error = str(rollback_exc)
            try:
                source_tag_status = self._restore_source_tag(transaction)
            except (LifecycleError, OSError, ValueError) as tag_exc:
                source_tag_error = str(tag_exc)
            if rollback_error or source_tag_error:
                transaction["rollback_failure"] = rollback_error or source_tag_error
                if source_tag_error:
                    transaction["source_tag_failure"] = source_tag_error
                self._journal(transaction, "rollback_failed")
                message = ("Die vorherige Container-Version läuft wieder; die Image-Namenszuordnung konnte nicht wiederhergestellt werden."
                           if containers_restored else
                           "Die neue Version ist fehlgeschlagen; die Wiederherstellung konnte nicht bestätigt werden.")
                return self._event("rollback_failed", descriptors,
                                   message,
                                   severity="error", changed=True, old_image_id=old_id, new_image_id=new_id,
                                   actual_image_id=old_id if containers_restored else None,
                                   verification_status="ok" if containers_restored else "failed",
                                   deployment_status="rolled_back" if containers_restored else "failed",
                                   source_tag_status="conflict" if source_tag_error else source_tag_status,
                                   transaction_id=transaction_id,
                                   comparison=comparison, attempted_build=source == "local",
                                   action="Dienst und offene Wiederherstellung prüfen. Die Vorversion bleibt geschützt.")
            self._journal(transaction, "rolled_back")
            self._discard_candidate(transaction)
            self._release_candidate_alias(transaction)
            # backup_tag is now the durable running image pin. Never remove it.
            return self._event("rolled_back", descriptors,
                               "Die neue Version ist fehlgeschlagen; die vorherige Image-ID läuft wieder und wurde geprüft.",
                               severity="warning", changed=True, old_image_id=old_id, new_image_id=new_id,
                               transaction_id=transaction_id, comparison=comparison, attempted_build=source == "local",
                               source_tag_status=source_tag_status,
                               action="Fehler des Kandidaten vor dem nächsten Versuch beheben.")

    def cleanup_retention(self, *, preview: bool = False) -> dict[str, Any]:
        with self._lock():
            data = self._read_retention()
            pending = self.open_transactions()
            containers = self._all_containers()
            used = {c["Image"] for c in containers}
            unresolved = {t["old_image_id"] for t in pending}
            unresolved.update(t["candidate_image_id"] for t in pending if t.get("candidate_image_id"))
            result: dict[str, Any] = {"protected": 0, "removed": 0, "eligible": 0,
                                      "errors": 0, "entries": [], "preview": bool(preview or self.options["dry_run"])}
            for iid in sorted(unresolved - set(data["images"])):
                result["protected"] += 1
                result["entries"].append({"image_id": iid, "retain_until": None,
                                           "status": "wiederherstellung_offen"})
            now = self.clock()
            for iid, entry in list(data["images"].items()):
                successor_problem = False
                for service in entry.get("services", []):
                    matching = [c for c in containers
                                if c.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") == service["project"]
                                and c.get("Config", {}).get("Labels", {}).get("com.docker.compose.service") == service["service"]]
                    if matching and (len(matching) != 1 or not matching[0].get("State", {}).get("Running")
                                     or matching[0].get("State", {}).get("Health", {}).get("Status") != "healthy"):
                        successor_problem = True
                reason = ("noch_verwendet" if iid in used else "wiederherstellung_offen" if iid in unresolved
                          else "aufbewahrungsfrist" if now < entry["retain_until"]
                          else "nachfolger_nicht_geprueft" if successor_problem else "")
                item = {"image_id": iid, "retain_until": entry["retain_until"]}
                if reason:
                    result["protected"] += 1
                    item["status"] = reason
                    result["entries"].append(item)
                    continue
                try:
                    if iid in self._all_image_ids():
                        image = self._inspect_image(iid)
                        tags = image.get("RepoTags") or []
                        if set(tags) - set(entry["allowed_tags"]):
                            result["protected"] += 1
                            item["status"] = "weitere_image_namen"
                            result["entries"].append(item)
                            continue
                        result["eligible"] += 1
                        if result["preview"]:
                            item["status"] = "loeschung_vorgesehen"
                            result["entries"].append(item)
                            continue
                        # Refresh immediately before deletion; Docker's own
                        # non-forced deletion adds another reference check.
                        if any(c["Image"] == iid for c in self._all_containers()):
                            result["protected"] += 1
                            item["status"] = "noch_verwendet"
                            result["entries"].append(item)
                            continue
                        for tag in tags:
                            if self._inspect_image(tag)["Id"] != iid:
                                raise LifecycleError("Ein Image-Name wurde während der Bereinigung verändert.")
                            self._call(["image", "rm", "--no-prune", tag])
                        if iid in self._all_image_ids():
                            self._call(["image", "rm", "--no-prune", iid])
                        if iid in self._all_image_ids():
                            raise LifecycleError("Das Image ist nach der Bereinigung noch vorhanden.")
                    elif result["preview"]:
                        item["status"] = "bereits_entfernt"
                        result["entries"].append(item)
                        continue
                    del data["images"][iid]
                    atomic_json(self.retention_file, data)
                    result["removed"] += 1
                    item["status"] = "entfernt"
                except LifecycleError:
                    result["errors"] += 1
                    item["status"] = "loeschung_fehlgeschlagen"
                result["entries"].append(item)
            self._emit({"kind": "retention", "status": "cleanup_failed" if result["errors"] else "cleanup_complete",
                       "severity": "warning" if result["errors"] else "info", "changed": bool(result["removed"]),
                       "message": f"Vorversionen: {result['protected']} geschützt, {result['removed']} entfernt.",
                       "summary": result})
            return result
