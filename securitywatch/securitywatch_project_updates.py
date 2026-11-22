#!/usr/bin/env python3
"""Einmalige, begrenzte Übernahme der freigegebenen GitHub-Images.

Der normale Aktualisierungslauf behält seine strenge Zustandsprüfung. Dieses
Werkzeug ist ausschließlich für die drei bekannten Ausgangsquellen vorgesehen,
deren bisherige Images noch keine Zustandsprüfung enthalten. Ein Abbruch bleibt
im gemeinsamen Aktualisierungsjournal sichtbar. Zugangsdaten und ausgewertete
Compose-Konfigurationen werden nicht in Berichte oder Terminalausgaben kopiert.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from securitywatch_common import ConfigurationError, RunLock, bounded_int, private_directory
from securitywatch_lifecycle import (DockerRunner, LifecycleEngine, LifecycleError,
                                     compare_scans, image_repository, _canonical)


@dataclass(frozen=True)
class Target:
    key: str
    name: str
    project: str
    service: str
    old_ref: str
    new_ref: str
    health_test: tuple[str, ...]


TARGETS = {
    "schulmanager": Target(
        "schulmanager", "schulmanager-homework-watcher", "schulmanager",
        "schulmanager-homework-watcher", "railsimulatornet/schulmanager-homework-watcher:3.0.1",
        "railsimulatornet/schulmanager-homework-watcher:latest",
        ("CMD", "node", "/app/src/healthcheck.js")),
    "minecraft-wartung": Target(
        "minecraft-wartung", "minecraftserver_maintenance", "minecraft_server",
        "minecraftserver_maintenance", "railsimulatornet/minecraft-maintenance:1.0.3",
        "railsimulatornet/minecraft-maintenance:latest",
        ("CMD", "python3", "/usr/local/libexec/maintenance_health.py")),
    "easyepg": Target(
        "easyepg", "emby_takealug_new-easyepg", "emby", "easyepg",
        "railsimulatornet/new-easyepg:latest", "railsimulatornet/new-easyepg:latest",
        ("CMD", "/opt/venv/bin/python", "/usr/local/bin/easyepg.healthcheck.py")),
}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replace_image_line(text: str, old: str, new: str) -> str:
    """Edit one literal image value; full Compose evaluation proves its scope."""
    pattern = re.compile(r"^([ \t]*image[ \t]*:[ \t]*)(['\"]?)(" + re.escape(old)
                         + r")\2([ \t]*(?:#[^\r\n]*)?)(\r?\n|$)", re.MULTILINE)
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise LifecycleError("Die alte Image-Zeile ist nicht eindeutig wörtlich eingetragen; keine automatische Textänderung.")
    return pattern.sub(lambda m: m[1] + m[2] + new + m[2] + m[4] + m[5], text, count=1)


def _replace_file(path: Path, expected: str, data: bytes, metadata: os.stat_result) -> None:
    """Atomically replace the checked regular file, preserving its ownership."""
    if path.is_symlink() or not path.is_file() or _digest(path.read_bytes()) != expected:
        raise LifecycleError("Die Compose-Datei wurde zwischenzeitlich geändert; fremde Änderungen bleiben erhalten.")
    fd, temporary = tempfile.mkstemp(prefix=".securitywatch-uebernahme-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchown(handle.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode))
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Recheck after writing our temporary file, before replacing the source.
        if path.is_symlink() or _digest(path.read_bytes()) != expected:
            raise LifecycleError("Die Compose-Datei wurde während der Vorbereitung geändert.")
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class ProjectUpdater:
    def __init__(self, engine: LifecycleEngine, resolve_remote):
        self.engine = engine
        self.resolve_remote = resolve_remote

    def _input_config(self, context: dict, text: str) -> dict:
        # One original file, located in working_dir, is an explicit prerequisite.
        # Feeding its modified content on stdin keeps --check read-only.
        args = [*context["args"][:-2], "-f", "-", "config", "--format", "json"]
        try:
            result = self.engine.runner(args, cwd=context["working_dir"], timeout=60, input_text=text)
        except (OSError, subprocess.SubprocessError) as exc:
            raise LifecycleError("Die geänderte Compose-Konfiguration konnte nicht geprüft werden.") from exc
        if result.returncode:
            raise LifecycleError("Die geänderte Compose-Konfiguration wurde von Docker abgelehnt.")
        try:
            value = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise LifecycleError("Docker lieferte keine lesbare geänderte Compose-Konfiguration.") from exc
        if not isinstance(value, dict):
            raise LifecycleError("Die geänderte Compose-Konfiguration ist nicht vollständig.")
        return value

    @staticmethod
    def _expected_config(original: dict, target: Target) -> dict:
        expected = copy.deepcopy(original)
        expected["services"][target.service]["image"] = target.new_ref
        return expected

    @staticmethod
    def _health_matches(image_or_container: dict, target: Target) -> bool:
        config = image_or_container.get("Config") or {}
        return (config.get("Healthcheck") or {}).get("Test") == list(target.health_test)

    def plan(self, key: str) -> dict:
        if key not in TARGETS:
            raise LifecycleError("Für dieses Projekt ist keine einmalige Übernahme freigegeben.")
        target = TARGETS[key]
        if self.engine.open_transactions():
            raise LifecycleError("Ein Aktualisierungsvorgang ist ungeklärt; zuerst die Wiederherstellung prüfen.")
        self.engine._context_cache.clear()
        containers = self.engine._all_containers()
        matching = []
        for container in containers:
            labels = (container.get("Config") or {}).get("Labels") or {}
            if (labels.get("com.docker.compose.project") == target.project
                    and labels.get("com.docker.compose.service") == target.service):
                matching.append(container)
        if len(matching) != 1 or str(matching[0].get("Name", "")).lstrip("/") != target.name:
            raise LifecycleError(f"{target.name}: Der bekannte Dienst ist nicht eindeutig vorhanden.")
        container = matching[0]
        state = container.get("State") or {}
        if not state.get("Running") or state.get("Status") != "running" or state.get("Restarting"):
            raise LifecycleError(f"{target.name}: Die Ausgangsversion läuft nicht stabil.")
        current_health = (state.get("Health") or {}).get("Status")
        if current_health not in {None, "healthy"}:
            raise LifecycleError(f"{target.name}: Eine bestehende fehlgeschlagene Zustandsprüfung wird nicht übergangen.")
        context = copy.deepcopy(self.engine._context(container, fresh=True))
        service = context["config"]["services"][target.service]
        reference = service.get("image")
        if reference == target.new_ref:
            if self._health_matches(container, target) and current_health == "healthy":
                return {"target": target, "already_current": True, "container": container}
            if target.old_ref != target.new_ref:
                raise LifecycleError(f"{target.name}: Die neue Quelle ist eingetragen, aber ihre Zustandsprüfung ist nicht bestätigt.")
        if reference != target.old_ref or container.get("Config", {}).get("Image") != target.old_ref:
            raise LifecycleError(f"{target.name}: Die laufende oder konfigurierte Quelle entspricht nicht der freigegebenen Altversion.")
        if service.get("build") or service.get("healthcheck"):
            raise LifecycleError(f"{target.name}: Eine eigene Bau- oder Zustandsdefinition benötigt eine gesonderte Prüfung.")
        if any((c.get("Config") or {}).get("Image") == target.new_ref for c in containers if c["Id"] != container["Id"]):
            raise LifecycleError(f"{target.name}: Ein weiterer Container verwendet bereits den neuen Image-Namen.")
        image = self.engine._inspect_image(container["Image"])
        repository = image_repository(target.old_ref)
        if not any(str(digest).startswith(repository + "@sha256:") for digest in image.get("RepoDigests") or []):
            raise LifecycleError(f"{target.name}: Die veröffentlichte Herkunft der Altversion ist nicht bestätigt.")
        old_tag_before = self.engine._tag_image_id(target.old_ref)
        if target.old_ref != target.new_ref and old_tag_before not in {None, container["Image"]}:
            raise LifecycleError(f"{target.name}: Der feste alte Image-Name zeigt bereits auf eine fremde Version.")
        if len(context["config_files"]) != 1:
            raise LifecycleError(f"{target.name}: Mehrere Compose-Dateien benötigen eine gesonderte Zuordnung.")
        path = Path(context["config_files"][0])
        if (path.is_symlink() or not path.is_file() or path.parent.resolve() != Path(context["working_dir"]).resolve()
                or path.stat().st_size > 4 * 1024 * 1024):
            raise LifecycleError(f"{target.name}: Die Compose-Datei liegt nicht eindeutig im zugeordneten Projektordner.")
        original = path.read_bytes()
        try:
            changed = (replace_image_line(original.decode("utf-8"), target.old_ref, target.new_ref).encode("utf-8")
                       if target.old_ref != target.new_ref else original)
        except UnicodeError as exc:
            raise LifecycleError("Die Compose-Datei ist nicht als UTF-8 lesbar.") from exc
        expected = self._expected_config(context["config"], target)
        if (changed != original and
                _canonical(self._input_config(context, changed.decode("utf-8"))) != _canonical(expected)):
            raise LifecycleError("Die Quellenänderung würde weitere Compose-Einstellungen verändern; Vorgang zurückgestellt.")
        descriptor = self.engine.describe(container)
        # Describe may reject only the old image's missing native healthcheck.
        if not descriptor["automatic_allowed"] and descriptor["reason"] != "Keine belastbare Zustandsprüfung eingerichtet.":
            raise LifecycleError(descriptor["reason"] or "Die Ausgangsversion wurde nicht freigegeben.")
        remote = self.resolve_remote(target.new_ref)
        if ("@sha256:" not in remote or image_repository(remote) != repository):
            raise LifecycleError("Die neue Veröffentlichung gehört nicht zur freigegebenen Quelle.")
        local_id = self.engine._tag_image_id(remote)
        readiness = "noch_nicht_lokal_geprueft"
        if local_id:
            readiness = "zustandspruefung_vorhanden" if self._health_matches(self.engine._inspect_image(local_id), target) else "zustandspruefung_fehlt"
        return {"target": target, "already_current": False, "container": container, "descriptor": descriptor,
                "context": context, "path": path, "original": original, "changed": changed,
                "metadata": path.stat(), "expected_config": expected, "remote": remote,
                "old_tag_before": old_tag_before,
                "target_tag_before": self.engine._tag_image_id(target.new_ref), "readiness": readiness}

    @staticmethod
    def public_plan(plan: dict) -> dict:
        target = plan["target"]
        result = {"dienst": target.name, "bisherige_quelle": target.old_ref, "neue_quelle": target.new_ref}
        if plan["already_current"]:
            return {**result, "zustand": "Bereits umgestellt; die Zustandsprüfung ist erfolgreich."}
        readiness = plan["readiness"]
        message = {"zustandspruefung_fehlt": "Wartet auf die neue Veröffentlichung mit passender Zustandsprüfung.",
                   "zustandspruefung_vorhanden": "Zustandsprüfung vorhanden; Sicherheits- und Startprüfung erfolgen beim Anwenden.",
                   "noch_nicht_lokal_geprueft": "Die neue Version wird beim Anwenden geladen und vor dem Austausch geprüft."}[readiness]
        return {**result, "compose_datei": str(plan["path"]), "veroeffentlichung": plan["remote"], "zustand": message}

    def _assert_original(self, plan: dict) -> None:
        self.engine._assert_base_unchanged(plan["context"])
        if plan["path"].is_symlink() or _digest(plan["path"].read_bytes()) != _digest(plan["original"]):
            raise LifecycleError("Die vorbereitete Compose-Datei wurde geändert.")
        current = self.engine._service_container(plan["descriptor"])
        baseline = plan["container"]
        state = current.get("State") or {}
        if (current.get("Id") != baseline["Id"] or current.get("Image") != baseline["Image"]
                or current.get("Config", {}).get("Image") != baseline["Config"]["Image"]
                or not state.get("Running") or state.get("Status") != "running" or state.get("Restarting")
                or current.get("RestartCount", 0) != baseline.get("RestartCount", 0)):
            raise LifecycleError("Der Ausgangsdienst wurde während der Vorbereitung verändert.")
        self._assert_fixed_tag(plan)

    def _assert_fixed_tag(self, plan: dict) -> None:
        target = plan["target"]
        if (target.old_ref != target.new_ref and
                self.engine._tag_image_id(target.old_ref) != plan["old_tag_before"]):
            raise LifecycleError("Die Zuordnung des festen alten Image-Namens wurde fremd geändert.")

    def _check_target_tag(self, transaction: dict) -> None:
        source = transaction["migration"]["target_tag"]
        if self.engine._tag_image_id(source["reference"]) != source["before_image_id"]:
            raise LifecycleError("Der neue Image-Name wurde zwischenzeitlich fremd geändert; er wird nicht überschrieben.")

    def _restore_target_tag(self, transaction: dict) -> None:
        source = transaction["migration"]["target_tag"]
        if source["phase"] == "prepared":
            return
        current = self.engine._tag_image_id(source["reference"])
        if current == source["before_image_id"]:
            return
        if current != transaction["candidate_image_id"]:
            raise LifecycleError("Eine fremde Änderung des neuen Image-Namens bleibt erhalten; Wiederherstellung offen.")
        if source["before_image_id"] is None:
            self.engine._call(["image", "rm", "--no-prune", source["reference"]])
        else:
            self.engine._call(["image", "tag", source["before_image_id"], source["reference"]])
        if self.engine._tag_image_id(source["reference"]) != source["before_image_id"]:
            raise LifecycleError("Die frühere Zuordnung des neuen Image-Namens konnte nicht bestätigt werden.")

    def _restore_runtime_without_health(self, descriptor: dict, context: dict, old_id: str) -> dict:
        self.engine._assert_base_unchanged(context)
        self.engine._call([*context["args"], "-f", context["override_path"], "up", "-d", "--no-deps",
                           "--no-build", "--pull", "never", "--force-recreate", descriptor["service"]],
                          cwd=context["working_dir"], timeout=120)
        started = self.engine.monotonic()
        seen = None
        while self.engine.monotonic() - started < 120:
            current = self.engine._service_container(descriptor)
            state = current.get("State") or {}
            if (current.get("Image") != old_id or not state.get("Running") or state.get("Status") != "running"
                    or state.get("Restarting") or int(current.get("RestartCount", 0)) != 0
                    or (seen is not None and seen != current["Id"])):
                raise LifecycleError("Die Rückkehr zum laufenden alten Container konnte nicht bestätigt werden.")
            seen = current["Id"]
            if self.engine.monotonic() - started >= float(self.engine.options["stable_seconds"]):
                return current
            self.engine.sleep(max(0.1, float(self.engine.options["health_interval"])))
        raise LifecycleError("Die Rückkehr zum alten Container hat das Zeitlimit überschritten.")

    def _rollback(self, plan: dict, transaction: dict) -> dict:
        engine, target = self.engine, plan["target"]
        engine._journal(transaction, "rolling_back")
        runtime_restored = False
        old_healthy = bool(plan["descriptor"]["automatic_allowed"])
        failures = []
        try:
            current = _digest(plan["path"].read_bytes()) if not plan["path"].is_symlink() else "changed"
            if current == _digest(plan["changed"]) and plan["changed"] != plan["original"]:
                _replace_file(plan["path"], current, plan["original"], plan["metadata"])
            elif current != _digest(plan["original"]):
                raise LifecycleError("Fremde Compose-Änderungen bleiben erhalten; automatische Rückkehr benötigt Prüfung.")
            engine._pin(plan["context"], [plan["descriptor"]], transaction["backup_tag"], "registry")
            if old_healthy:
                engine._up(plan["descriptor"], plan["context"], transaction["old_image_id"])
            else:
                self._restore_runtime_without_health(plan["descriptor"], plan["context"], transaction["old_image_id"])
            runtime_restored = True
        except (LifecycleError, OSError, ValueError) as exc:
            failures.append(str(exc) if isinstance(exc, LifecycleError) else "Die alte Konfiguration oder der alte Container konnte nicht wiederhergestellt werden.")
        try:
            # Restore our target-name write independently of the runtime result.
            # A foreign later mapping is still preserved by its compare check.
            self._restore_target_tag(transaction)
        except (LifecycleError, OSError, ValueError) as exc:
            failures.append(str(exc) if isinstance(exc, LifecycleError) else "Die frühere Image-Namenszuordnung konnte nicht wiederhergestellt werden.")
        if runtime_restored and not old_healthy:
            failures.append("Der alte Container läuft wieder. Ohne seine eigene Zustandsprüfung ist die funktionale Wiederherstellung nicht bestätigt.")
        if not failures:
            engine._journal(transaction, "rolled_back")
            engine._discard_candidate(transaction)
            engine._release_candidate_alias(transaction)
            return {"status": "rolled_back", "dienst": target.name, "changed": True,
                    "message": "Die alte Image-Version läuft wieder und ihre Zustandsprüfung ist erfolgreich.",
                    "transaction_id": transaction["id"]}
        transaction["rollback_failure"] = " ".join(failures)
        transaction["runtime_restored"] = runtime_restored
        engine._journal(transaction, "rollback_failed")
        return {"status": "rollback_failed", "dienst": target.name, "changed": True,
                "runtime_restored": runtime_restored, "functional_restore_verified": False,
                "message": transaction["rollback_failure"], "transaction_id": transaction["id"]}

    def apply(self, key: str) -> dict:
        with self.engine._lock():
            plan = self.plan(key)
            if plan["already_current"]:
                return {"status": "already_current", "dienst": plan["target"].name, "changed": False,
                        "message": "Bereits umgestellt; die Zustandsprüfung ist erfolgreich."}
            return self._apply(plan)

    def _apply(self, plan: dict) -> dict:
        engine, target = self.engine, plan["target"]
        self._assert_original(plan)
        self._check_target_tag({"migration": {"target_tag": {"reference": target.new_ref,
                               "before_image_id": plan["target_tag_before"]}}})
        engine._read_retention()
        before_ids = engine._all_image_ids()
        transaction_id = uuid.uuid4().hex
        backup_dir = private_directory(engine.state_dir / "project-update-backups" / transaction_id)
        backup = backup_dir / "compose-before.yaml"
        with backup.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(plan["original"])
            stream.flush()
            os.fsync(stream.fileno())
        old_id = plan["container"]["Image"]
        transaction = {"schema": 1, "id": transaction_id, "phase": "prepared", "source": "registry",
                       "created_at": engine.clock(), "old_image_id": old_id, "image_ref": target.old_ref,
                       "old_tags": engine._inspect_image(old_id).get("RepoTags") or [],
                       "backup_tag": f"securitywatch-previous:{transaction_id}",
                       "candidate_tag": f"securitywatch-candidate:{transaction_id}",
                       "services": [plan["descriptor"]], "touched_services": [],
                       "migration": {"target": target.key, "from": target.old_ref, "to": target.new_ref,
                                     "compose_path": str(plan["path"]), "backup_path": str(backup),
                                     "before_sha256": _digest(plan["original"]), "after_sha256": _digest(plan["changed"]),
                                     "target_tag": {"reference": target.new_ref, "before_image_id": plan["target_tag_before"],
                                                    "phase": "prepared"}}}
        engine._journal(transaction)
        deployed = False
        try:
            engine._call(["image", "tag", old_id, transaction["backup_tag"]])
            engine._journal(transaction, "candidate_preparation")
            engine._call(["pull", plan["remote"]], timeout=float(engine.options["build_timeout"]))
            candidate = engine._inspect_image(plan["remote"])
            new_id = candidate["Id"]
            transaction["candidate_image_id"] = new_id
            transaction["candidate_created_here"] = new_id not in before_ids
            engine._call(["image", "tag", new_id, transaction["candidate_tag"]])
            engine._journal(transaction, "candidate_ready")
            if not self._health_matches(candidate, target):
                raise LifecycleError("Die neue Veröffentlichung enthält noch nicht die freigegebene Zustandsprüfung. Zuerst den GitHub-Bau abschließen lassen.")
            candidate_descriptor = copy.deepcopy(plan["descriptor"])
            candidate_descriptor["image_ref"] = target.new_ref
            candidate_descriptor["health_budget_seconds"] = engine.health_budget(candidate)
            comparison = compare_scans(engine.scan_image(old_id), engine.scan_image(new_id),
                                       before_id=old_id, after_id=new_id)
            transaction["comparison"] = comparison
            if not comparison["allowed"]:
                raise LifecycleError("Die neue Veröffentlichung enthält zusätzliche oder höher bewertete hohe/kritische Sicherheitsfunde; keine Übernahme.")
            self._assert_original(plan)
            self._check_target_tag(transaction)
            # From here interruption must leave the common journal open.
            transaction["touched_services"] = [{"project": target.project, "service": target.service}]
            engine._journal(transaction, "deploying")
            deployed = True
            engine._pin(plan["context"], [candidate_descriptor], transaction["candidate_tag"], "registry")
            actual = engine._up(candidate_descriptor, plan["context"], new_id)
            if not self._health_matches(actual, target):
                raise LifecycleError("Der gestartete Dienst verwendet nicht die freigegebene Zustandsprüfung.")
            engine._journal(transaction, "verified")
            engine._assert_base_unchanged(plan["context"])
            self._assert_fixed_tag(plan)
            self._check_target_tag(transaction)
            engine._journal(transaction, "source_config_committing")
            if plan["changed"] != plan["original"]:
                _replace_file(plan["path"], _digest(plan["original"]), plan["changed"], plan["metadata"])
            observed = engine._json_call([*plan["context"]["args"], "config", "--format", "json"], cwd=plan["context"]["working_dir"])
            if _canonical(observed) != _canonical(plan["expected_config"]):
                raise LifecycleError("Die übernommene Compose-Konfiguration weicht vom geprüften Ergebnis ab.")
            source = transaction["migration"]["target_tag"]
            self._check_target_tag(transaction)
            source["phase"] = "setting"
            engine._journal(transaction, "source_tag_committing")
            engine._call(["image", "tag", new_id, target.new_ref])
            source["phase"] = "applied"
            engine._journal(transaction, "source_tag_committed")
            if engine._tag_image_id(target.new_ref) != new_id:
                raise LifecycleError("Die neue Image-Namenszuordnung konnte nicht bestätigt werden.")
            engine._verify_group_snapshot([candidate_descriptor], new_id, {(target.project, target.service): actual["Id"]})
            if _digest(plan["path"].read_bytes()) != _digest(plan["changed"]):
                raise LifecycleError("Die Compose-Datei wurde nach der Übernahme erneut verändert.")
            succeeded_at = engine.clock()
            transaction["successful_replacement_at"] = succeeded_at
            engine._retain(transaction, succeeded_at)
            engine._journal(transaction, "complete")
            return {"status": "updated", "dienst": target.name, "changed": True,
                    "message": ("Neue Veröffentlichung mit passender Zustandsprüfung übernommen; die Quelle bleibt latest."
                                if target.old_ref == target.new_ref else
                                "Neue Veröffentlichung übernommen, Zustandsprüfung erfolgreich und Quelle dauerhaft auf latest umgestellt."),
                    "old_image_id": old_id, "new_image_id": new_id, "comparison": comparison,
                    "transaction_id": transaction_id, "backup": str(backup)}
        except (LifecycleError, OSError, ValueError, RuntimeError) as exc:
            transaction["failure"] = str(exc) if isinstance(exc, LifecycleError) else "Die Übernahme konnte nicht abgeschlossen werden."
            if deployed:
                return self._rollback(plan, transaction)
            engine._journal(transaction, "rejected")
            engine._discard_candidate(transaction)
            engine._release_candidate_alias(transaction)
            engine._remove_hold_tag(transaction)
            return {"status": "rejected", "dienst": target.name, "changed": False,
                    "message": transaction["failure"], "transaction_id": transaction_id}
        finally:
            engine._context_cache.clear()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Einmalige geprüfte Übernahme: Schulmanager, Minecraft-Wartung und EasyEPG")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Plan nur lesen; keine Dateien, Images oder Container verändern")
    mode.add_argument("--apply", action="store_true", help="Die genau zugeordneten Projekte geprüft umstellen")
    parser.add_argument("--project", choices=tuple(TARGETS), help="Nur dieses Projekt bearbeiten")
    parser.add_argument("--env-file", type=Path, help="SecurityWatch-Einstellungen; Standard: .env daneben")
    args = parser.parse_args(argv)
    from securitywatch import arguments, config, remote_image
    from securitywatch_scanner import TrivyScanner
    base = Path(__file__).resolve().parent
    env_path = args.env_file or base / ".env"
    scanner = None
    try:
        env = config(base, env_path, arguments(["--check"]))
        state = Path(env["STATE_DIR"])
        runner = DockerRunner()
        options = {"health_timeout": bounded_int(env, "IMAGE_UPDATE_VERIFY_TIMEOUT_SECONDS", 120, 10, 7200),
                   "health_max_wait": bounded_int(env, "IMAGE_UPDATE_VERIFY_MAX_SECONDS", 2400, 60, 21600),
                   "health_interval": bounded_int(env, "IMAGE_UPDATE_VERIFY_INTERVAL_SECONDS", 5, 1, 60),
                   "stable_seconds": bounded_int(env, "IMAGE_UPDATE_VERIFY_STABLE_SECONDS", 10, 1, 300),
                   "retention_days": bounded_int(env, "IMAGE_RETENTION_DAYS", 7, 7, 365)}
        keys = [args.project] if args.project else list(TARGETS)
        if args.check:
            engine = LifecycleEngine(state, runner, lambda _: (_ for _ in ()).throw(LifecycleError("Im Prüflauf wird kein Sicherheitslauf gestartet.")), options=options)
            updater = ProjectUpdater(engine, lambda reference: remote_image(runner, reference))
            for key in keys:
                print(json.dumps(updater.public_plan(updater.plan(key)), ensure_ascii=False, indent=2))
            print("Prüfung beendet. Es wurden keine Dateien, Images, Container oder Zeitpläne verändert.")
            return 0
        with RunLock(state / "securitywatch.lock"):
            engine = LifecycleEngine(state, runner, lambda _: (_ for _ in ()).throw(LifecycleError("Die Sicherheitsprüfung ist noch nicht vorbereitet.")), options=options)
            updater = ProjectUpdater(engine, lambda reference: remote_image(runner, reference))
            # Resolve every requested plan before preparation or a first restart.
            plans = [updater.plan(key) for key in keys]
            if all(plan["already_current"] for plan in plans):
                print("Alle ausgewählten Projekte sind bereits umgestellt und erfolgreich geprüft.")
                return 0
            # These are private transaction evidence, not another mail/report tree.
            work = private_directory(state / "project-update-checks" / uuid.uuid4().hex)
            scanner = TrivyScanner(runner, env, work, state, lambda event: print(event.get("message", ""), flush=True))
            engine.scan_image = scanner.scan_image
            scanner.prepare()
            for key in keys:
                result = updater.apply(key)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                if result["status"] not in {"updated", "already_current"}:
                    print("Weitere Übernahmen wurden angehalten. Die Meldung und das Aktualisierungsjournal prüfen.")
                    return 2
            print("Übernahme abgeschlossen. Die regulären SecurityWatch-Läufe verfolgen jetzt die neue Quelle.")
            return 0
    except (LifecycleError, ConfigurationError, OSError, ValueError, RuntimeError) as exc:
        print("ABBRUCH: " + (str(exc) if isinstance(exc, (LifecycleError, ConfigurationError)) else "Die Projektdaten konnten nicht zuverlässig verarbeitet werden."), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ABBRUCH: Übernahme unterbrochen. Offene Aktualisierungsjournale bleiben zur Prüfung erhalten.", file=sys.stderr)
        return 130
    finally:
        if scanner is not None:
            scanner.close()


if __name__ == "__main__":
    raise SystemExit(main())
