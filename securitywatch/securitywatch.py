#!/usr/bin/env python3
"""SecurityWatch: nachvollziehbare Prüfungen und geschützte Image-Aktualisierungen.

Copyright Roman Glos 2026. Python 3.11+, ausschließlich Standardbibliothek.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from securitywatch_common import (VERSION, IMAGE_ID, ConfigurationError, RunLock, atomic_json,
                                  berlin_now, bounded_int, enabled, load_env, now_iso,
                                  patterns, private_directory, safe_field)
from securitywatch_scanner import ScanError, TrivyScanner, findings


def arguments(argv=None):
    parser = argparse.ArgumentParser(description="SecurityWatch – Sicherheitsprüfung und kontrollierte Aktualisierung")
    parser.add_argument("--env-file", type=Path, help="Einstellungsdatei; Standard: .env neben diesem Programm")
    parser.add_argument("--check", action="store_true", help="Voraussetzungen und Dienste prüfen; keine Images bauen oder Container verändern")
    parser.add_argument("--dry-run", action="store_true", help="Wie --check; keine Aktualisierung, Löschung oder E-Mail")
    parser.add_argument("--report-only", action="store_true", help="Sicherheitsbericht erstellen; keine Anwendungsimages oder Container verändern")
    parser.add_argument("--force-rebuild", action="store_true", help="Wartefrist für lokale Neubauten überspringen; Sicherheitsprüfungen bleiben aktiv")
    options = {
        "no-cleanup": "Aufbewahrte Images diesmal nicht bereinigen",
        "no-prune-unused-images": "Aufbewahrte Images diesmal nicht bereinigen",
        "no-prune-build-cache": "Kompatibilitätsoption: Bau-Zwischenspeicher wird ohnehin nicht pauschal geleert",
        "no-trivy-pull": "Vorhandenes Prüfwerkzeug verwenden",
        "no-mail": "Keine E-Mail versenden",
        "no-report-cleanup": "Ältere Berichte behalten",
        "no-local-image-report": "Zusätzliche Liste lokaler Images auslassen",
        "no-local-image-rebuild": "Lokale Images nicht neu bauen",
        "no-image-update-check": "Veröffentlichte Images nicht auf neue Versionen prüfen",
        "apply-image-updates": "Geprüfte Image-Aktualisierungen gemäß den Schutzregeln anwenden",
        "no-image-update-recreate": "Neue veröffentlichte Images melden, aber Dienste nicht austauschen",
        "host-only": "Nur das NAS-Dateisystem prüfen",
        "no-filesystem": "NAS-Dateisystem nicht prüfen",
        "no-images": "Anwendungsimages nicht prüfen",
    }
    for option, help_text in options.items():
        parser.add_argument("--" + option, action="store_true", help=help_text)
    return parser.parse_args(argv)


def config(base: Path, path: Path, args) -> dict:
    if not path.is_file():
        raise ConfigurationError(f"Einstellungsdatei fehlt: {path}")
    env = load_env(path)
    defaults = {"REPORT_DIR": str(base / "reports"), "CACHE_DIR": str(base / "trivy-cache"),
                "STATE_DIR": str(base / "state"), "TRIVY_IMAGE": "ghcr.io/aquasecurity/trivy:latest",
                "TRIVY_TIMEOUT": "60m", "TRIVY_AUTO_PULL_IMAGE": "1", "TRIVY_SCAN_FILESYSTEM": "1",
                "TRIVY_SCAN_IMAGES": "1", "LOCAL_IMAGE_AUTO_REBUILD_ENABLED": "1",
                "IMAGE_UPDATE_CHECK_ENABLED": "1", "IMAGE_UPDATE_AUTO_RECREATE_ENABLED": "1",
                "LOCAL_IMAGE_OVERRIDES_FILE": str(base / "securitywatch.local-images"),
                "GITHUB_CONFIG_FILE": str(base / "securitywatch.github.json")}
    for key, value in defaults.items():
        if not env.get(key):
            env[key] = value
    for key in ("REPORT_DIR", "CACHE_DIR", "STATE_DIR", "LOCAL_IMAGE_OVERRIDES_FILE", "GITHUB_CONFIG_FILE"):
        value = env[key].replace("${SCRIPT_DIR}", str(base)).replace("$SCRIPT_DIR", str(base))
        if any(c in value for c in ("\n", "\r", "\x00", ":")) or "$" in value:
            raise ConfigurationError(f"{key} benötigt einen eindeutigen lokalen Pfad.")
        p = Path(value).expanduser()
        env[key] = str((p if p.is_absolute() else base / p).resolve())
    if len({env["REPORT_DIR"], env["CACHE_DIR"], env["STATE_DIR"]}) != 3:
        raise ConfigurationError("Berichte, Prüfdaten und Zustandsdaten benötigen getrennte Ordner.")
    changes = {"no_trivy_pull": "TRIVY_AUTO_PULL_IMAGE", "no_local_image_rebuild": "LOCAL_IMAGE_AUTO_REBUILD_ENABLED",
               "no_image_update_check": "IMAGE_UPDATE_CHECK_ENABLED", "no_image_update_recreate": "IMAGE_UPDATE_AUTO_RECREATE_ENABLED",
               "no_filesystem": "TRIVY_SCAN_FILESYSTEM", "no_images": "TRIVY_SCAN_IMAGES"}
    for flag, key in changes.items():
        if getattr(args, flag, False):
            env[key] = "0"
    if args.apply_image_updates:
        env["IMAGE_UPDATE_CHECK_ENABLED"] = "1"
        env["IMAGE_UPDATE_AUTO_RECREATE_ENABLED"] = "1"
    if args.host_only:
        env["TRIVY_SCAN_FILESYSTEM"], env["TRIVY_SCAN_IMAGES"] = "1", "0"
    if not enabled(env.get("UGOS_HOST_SCAN_ENABLED"), True):
        env["TRIVY_SCAN_FILESYSTEM"] = "0"
    env["OUTPUT_LANG"] = "de"
    return env


def docker_json(runner, args: list[str], timeout=45):
    proc = runner(args, timeout=timeout)
    if proc.returncode:
        raise RuntimeError("Docker konnte die angeforderten Bestandsdaten nicht liefern.")
    try:
        return json.loads(proc.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Docker lieferte keine lesbaren Bestandsdaten.") from exc


def container_inventory(runner) -> list[dict]:
    proc = runner(["ps", "-aq", "--no-trunc"], timeout=30)
    if proc.returncode:
        raise RuntimeError("Der Containerbestand konnte nicht gelesen werden.")
    ids = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if any(not re.fullmatch(r"[0-9a-f]{64}", cid) for cid in ids):
        raise RuntimeError("Docker hat eine ungültige Containerkennung geliefert.")
    result = []
    for i in range(0, len(ids), 20):
        chunk = ids[i:i + 20]
        rows = docker_json(runner, ["container", "inspect", *chunk])
        if not isinstance(rows, list) or len(rows) != len(chunk):
            raise RuntimeError("Der Containerbestand hat sich während der Erfassung verändert.")
        if {item.get("Id") for item in rows if isinstance(item, dict)} != set(chunk):
            raise RuntimeError("Docker lieferte unvollständige Containerdetails.")
        result.extend(rows)
    return result


def minimal_container(item: dict) -> dict:
    labels = (item.get("Config") or {}).get("Labels") or {}
    health = (item.get("State") or {}).get("Health") or {}
    return {"container_id": item.get("Id"), "name": str(item.get("Name", "")).lstrip("/"),
            "image_id": item.get("Image"), "image_ref": (item.get("Config") or {}).get("Image"),
            "project": labels.get("com.docker.compose.project", ""),
            "service": labels.get("com.docker.compose.service", ""),
            "running": bool((item.get("State") or {}).get("Running")),
            "status": (item.get("State") or {}).get("Status"),
            "health": health.get("Status", "nicht eingerichtet"),
            "restarts": item.get("RestartCount", 0)}


def repository_without_tag(reference: str) -> str:
    reference = reference.split("@", 1)[0]
    slash, colon = reference.rfind("/"), reference.rfind(":")
    return reference[:colon] if colon > slash else reference


def remote_image(runner, reference: str) -> str:
    if not reference or reference.startswith("-") or any(c.isspace() for c in reference):
        raise RuntimeError("Die Image-Referenz ist ungültig.")
    doc = docker_json(runner, ["buildx", "imagetools", "inspect", reference, "--format", "{{json .Manifest}}"], 120)
    digest = doc.get("digest", "") if isinstance(doc, dict) else ""
    if not IMAGE_ID.fullmatch(digest):
        raise RuntimeError("Die Veröffentlichung enthält keine eindeutige Image-Prüfsumme.")
    return f"{repository_without_tag(reference)}@{digest}"


def write_tsv(path: Path, rows: list[list]):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerows([[safe_field(v) for v in row] for row in rows])


def package_counts(document: dict) -> dict:
    """Same per-source package-finding granularity as the detailed report."""
    packages = {}
    rank = {"CRITICAL": 4, "HIGH": 3}
    for result in document.get("Results", []):
        for item in result.get("Vulnerabilities") or []:
            severity = item.get("Severity")
            if severity not in rank:
                continue
            key = tuple(str(item.get(field) or "-") for field in
                        ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion"))
            if key not in packages or rank[severity] > rank[packages[key][0]]:
                packages[key] = (severity, bool(item.get("FixedVersion")))
    return {"critical": sum(s == "CRITICAL" for s, _ in packages.values()),
            "high": sum(s == "HIGH" for s, _ in packages.values()),
            "total": len(packages), "fixable": sum(f for _, f in packages.values())}


def create_report_directory(report_dir: Path) -> Path:
    """Use the actual local timestamp; never reuse or overwrite an earlier run.

    The process lock normally excludes a collision. An immediately following
    check, or another installation sharing the report directory, can still
    finish within the same second. Wait briefly for the next real second.
    """
    for _ in range(100):
        path = report_dir / berlin_now().strftime("%Y-%m-%d_%H-%M-%S")
        try:
            path.mkdir(mode=0o700)
            return path
        except FileExistsError:
            time.sleep(0.05)
    raise ConfigurationError("Für diesen Zeitpunkt besteht bereits ein Berichtsordner. Es wurde kein vorhandener Bericht überschrieben.")


class SecurityWatch:
    def __init__(self, base: Path, env_path: Path, env: dict, args, runner, engine_factory=None):
        self.base, self.env_path, self.env, self.args, self.runner = base, env_path, env, args, runner
        self.state_dir = private_directory(Path(env["STATE_DIR"]))
        self.report_dir = private_directory(Path(env["REPORT_DIR"]))
        self.run_dir = create_report_directory(self.report_dir)
        self.run_id = self.run_dir.name
        (self.run_dir / ".securitywatch-report").write_text("1\n", encoding="ascii")
        self.status = {"version": 1, "run": {"id": self.run_id, "version": VERSION,
                       "started_at": now_iso(), "finished_at": None, "status": "running",
                       "weekly_summary": not (args.report_only or args.check or args.dry_run),
                       "mode": "report_only" if args.report_only else "maintenance"},
                       "scans": {"host": {"status": "pending" if enabled(env["TRIVY_SCAN_FILESYSTEM"]) else "disabled", "file": "host_rootfs.json"},
                                 "images": {"status": "pending" if enabled(env["TRIVY_SCAN_IMAGES"]) else "disabled",
                                            "expected": 0, "succeeded": 0, "failed": 0, "items": []}},
                       "events": [], "image_outcomes": [], "retention": {"days": 7, "protected": 0, "removed": 0, "errors": []},
                       "github": {"status": "disabled"},
                       "maintenance": {"status": "pending", "items": []}}
        self.scanner = TrivyScanner(runner, env, self.run_dir, self.state_dir, self.emit)
        self._events_seen = set()
        self._descriptors = {}
        self.engine = None
        self.engine_factory = engine_factory
        self._project_receipts = None
        self._project_receipts_to_ack = {}
        self.save()

    def say(self, text: str):
        line = f"[{berlin_now().strftime('%H:%M:%S')}] {text}"
        print(line, flush=True)
        with (self.run_dir / "scan.log").open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def save(self):
        atomic_json(self.run_dir / "run-status.json", self.status)

    def emit(self, event: dict):
        event = dict(event)
        event.setdefault("kind", "run")
        event.setdefault("severity", "info")
        event.setdefault("service", "")
        event.setdefault("project", "")
        event.setdefault("image", "")
        event.setdefault("action", "")
        event.setdefault("message", "Ein Prüfschritt benötigt Aufmerksamkeit.")
        key = (event["kind"], event.get("status"), event["service"], event["image"], event["message"])
        if key in self._events_seen:
            return
        self._events_seen.add(key)
        self.status["events"].append(event)
        self.save()
        self.say(event["message"])

    def make_engine(self):
        if self.engine_factory is None:
            from securitywatch_lifecycle import LifecycleEngine
            self.engine_factory = LifecycleEngine
        excluded = sorted(set(patterns(self.env.get("UGOS_AUTO_UPDATE_EXCLUDE_PROJECTS", "wazuh"))) | {"wazuh", "ugreen_minecraft_java"})
        options = {"retention_days": bounded_int(self.env, "IMAGE_RETENTION_DAYS", 7, 7, 365),
                   "health_timeout": bounded_int(self.env, "IMAGE_UPDATE_VERIFY_TIMEOUT_SECONDS", 120, 10, 7200),
                   "health_max_wait": bounded_int(self.env, "IMAGE_UPDATE_VERIFY_MAX_SECONDS", 2400, 60, 21600),
                   "health_interval": bounded_int(self.env, "IMAGE_UPDATE_VERIFY_INTERVAL_SECONDS", 5, 1, 60),
                   "stable_seconds": bounded_int(self.env, "IMAGE_UPDATE_VERIFY_STABLE_SECONDS", 10, 0, 300),
                   "build_pull": enabled(self.env.get("LOCAL_IMAGE_AUTO_REBUILD_PULL"), True),
                   "build_no_cache": enabled(self.env.get("LOCAL_IMAGE_AUTO_REBUILD_NO_CACHE"), True),
                   "excluded_projects": excluded,
                   "dry_run": bool(self.args.report_only or self.args.check or self.args.dry_run)}
        self.status["retention"]["days"] = options["retention_days"]
        self.engine = self.engine_factory(self.state_dir, self.runner, self.scanner.scan_image,
                                         options=options, emit=self.emit)

    def describe(self, items: list[dict]) -> list[tuple[dict, dict]]:
        rows = []
        for item in items:
            if not (item.get("State") or {}).get("Running"):
                continue
            try:
                descriptor = self.engine.describe(item)
            except Exception:
                short = minimal_container(item)
                descriptor = {**short, "origin": "unknown", "automatic_allowed": False,
                              "reason": "Die Compose-Zuordnung konnte nicht vollständig gelesen werden."}
            self._descriptors[item["Id"]] = descriptor
            rows.append((item, descriptor))
        self.maintenance_coverage(rows)
        return rows

    def maintenance_coverage(self, described):
        """Explain the update path even when this run only creates a report."""
        rows = []
        for _, descriptor in described:
            origin = descriptor.get("origin", "unknown")
            reason = descriptor.get("reason", "")
            eligible = bool(descriptor.get("automatic_allowed"))
            build_allowed = bool(descriptor.get("build_allowed", eligible and origin == "local"))
            separate = "getrennten Aktualisierungsweg" in reason
            if separate:
                action = "Der zuständige Aktualisierungsweg bleibt erhalten."
            elif "Zustandsprüfung" in reason:
                action = "Eine passende Funktionsprüfung für diesen Dienst einrichten."
            elif origin == "pinned":
                action = "Die festgelegte Version über die maßgebliche Compose-Konfiguration aktualisieren."
            elif origin == "unknown":
                action = "Die tatsächliche Compose-Bauanleitung oder Registry-Quelle zuordnen."
            elif reason:
                action = "Die genannte Voraussetzung in der Compose-Konfiguration dieses Dienstes prüfen."
            else:
                action = ""
            rows.append({"container": descriptor.get("name", ""),
                         "image": descriptor.get("image_ref", ""),
                         "image_id": descriptor.get("image_id", ""),
                         "project": descriptor.get("project", ""),
                         "service": descriptor.get("service", ""),
                         "eligible": eligible, "build_allowed": build_allowed,
                         "kind": origin, "reason": reason, "action": action,
                         "separate_update_path": separate})
        self.status["maintenance"] = {"status": "ok", "items": rows,
                                      "eligible": sum(row["eligible"] for row in rows),
                                      "local_buildable": sum(row["build_allowed"] for row in rows)}
        self.save()

    def health_events(self, containers: list[dict]):
        for item in containers:
            short = minimal_container(item)
            if not short["running"]:
                continue
            if short["health"] == "unhealthy":
                self.emit({"kind": "health", "status": "unhealthy", "severity": "error",
                           "service": short["name"], "project": short["project"], "image": short["image_ref"],
                           "message": f"{short['name']}: Die Zustandsprüfung meldet einen bestehenden Fehler.",
                           "action": "Prüfdefinition und Diagnose des Dienstes ansehen; automatische Aktualisierung bleibt gesperrt."})

    def image_scans(self, containers: list[dict], *, phase: str):
        running = [item for item in containers if (item.get("State") or {}).get("Running")]
        grouped = defaultdict(list)
        for item in running:
            image_id = item.get("Image", "")
            if not IMAGE_ID.fullmatch(image_id):
                raise ScanError("Der laufende Containerbestand enthält eine ungültige Image-ID.")
            grouped[image_id].append(item)
        results = {"status": "running", "expected": len(grouped), "succeeded": 0, "failed": 0, "items": []}
        self.status["scans"]["images"] = results
        self.save()
        mapping, image_list, container_list = [], [], []
        for idx, (image_id, items) in enumerate(sorted(grouped.items()), 1):
            refs = sorted({self._descriptors.get(item["Id"], {}).get("image_ref") or item["Config"]["Image"] for item in items})
            name = image_id.split(":")[1]
            filename = f"image_{name}.json"
            entry = {"image_id": image_id, "references": refs,
                     "containers": [str(item["Name"]).lstrip("/") for item in items],
                     "status": "running", "file": filename}
            results["items"].append(entry)
            mapping.append([name, refs[0]])
            image_list.append(refs[0])
            container_list += [[str(item["Name"]).lstrip("/"), refs[0]] for item in items]
            self.say(f"Image-Prüfung {idx}/{len(grouped)}: {refs[0]}")
            try:
                self.scanner.scan_image(image_id)
                shutil.copyfile(self.scanner.paths[image_id], self.run_dir / filename)
                entry["status"] = "ok"
                results["succeeded"] += 1
            except Exception as exc:
                entry["status"] = "failed"
                entry["error"] = str(exc) if isinstance(exc, ScanError) else "Image-Prüfung konnte nicht abgeschlossen werden."
                results["failed"] += 1
                self.emit({"kind": "scan", "status": "image_scan_failed", "severity": "error", "image": refs[0],
                           "message": f"{refs[0]}: Die Sicherheitsprüfung ist unvollständig.",
                           "action": "Prüfprotokoll ansehen. Für dieses Image wird keine Aktualisierung freigegeben."})
            self.save()
        results["status"] = "partial" if results["failed"] else "ok"
        results["phase"] = phase
        # Only final/current entries are considered by the legacy detailed report.
        current = {item["file"] for item in results["items"]}
        for old in self.run_dir.glob("image_*.json"):
            if old.name not in current:
                old.unlink()
        write_tsv(self.run_dir / "images_map.tsv", mapping)
        (self.run_dir / "images_scanned.txt").write_text("\n".join(image_list) + "\n", encoding="utf-8")
        (self.run_dir / "containers_running.txt").write_text("\n".join("|".join(row) for row in container_list) + "\n", encoding="utf-8")
        self.status.setdefault("scan_phases", {})[phase] = json.loads(json.dumps(results))
        self.save()

    def local_metadata(self, described):
        rows = [["image", "container", "project", "service", "working_dir", "config_files"]]
        for item, d in described:
            if d.get("origin") == "local":
                files = d.get("config_files", [])
                rows.append([d["image_ref"], d.get("name", ""), d.get("project", ""), d.get("service", ""),
                             d.get("working_dir", ""), ",".join(files) if isinstance(files, list) else files])
        if not self.args.no_local_image_report:
            write_tsv(self.run_dir / "local-built-images.tsv", rows)
            (self.run_dir / "local-built-images.txt").write_text("\n".join(sorted({r[0] for r in rows[1:]})), encoding="utf-8")

    def check_only(self) -> int:
        self.make_engine()
        items = container_inventory(self.runner)
        described = self.describe(items)
        atomic_json(self.run_dir / "vorpruefung.json", {"version": VERSION,
                    "containers": [minimal_container(item) for item in items],
                    "services": [desc for _, desc in described]})
        self.say(f"Vorprüfung: {len(items)} Container, davon {len(described)} laufend.")
        for _, d in described:
            state = "grundsätzlich geeignet" if d.get("automatic_allowed") else "zurückgestellt"
            self.say(f"{d.get('name', '')}: {state}. {d.get('reason', '')}")
        pending = self.engine.open_transactions()
        if pending:
            self.say("Offene Aktualisierungsvorgänge gefunden. Ihre Vorversionen bleiben geschützt.")
        self.status["run"].update(status="completed", finished_at=now_iso(), mode="check")
        self.status["scans"]["host"]["status"] = "disabled"
        self.status["scans"]["images"]["status"] = "disabled"
        self.cleanup_report_history()
        self.save()
        self.say(f"Vorprüfung gespeichert: {self.run_dir}")
        return 2 if pending else 0

    def _load_schedule(self):
        path = self.state_dir / "rebuild-schedule.json"
        if not path.exists():
            return {"version": 1, "entries": {}}
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if doc.get("version") != 1 or not isinstance(doc.get("entries"), dict):
                raise ValueError
            return doc
        except (OSError, ValueError, AttributeError):
            raise RuntimeError("Die Zeitplanung lokaler Neubauten ist beschädigt; automatische Neubauten werden zurückgestellt.")

    def updates(self, described):
        groups = defaultdict(list)
        for item, descriptor in described:
            groups[(descriptor.get("image_id"), descriptor.get("image_ref"))].append((item, descriptor))
        schedule = self._load_schedule()
        # Six days lets a weekly 06:00 job rebuild every week even when its
        # preceding run reached this step a few minutes later.
        interval = bounded_int(self.env, "LOCAL_IMAGE_REBUILD_INTERVAL_HOURS", 144, 1, 8760) * 3600
        retry_interval = min(interval, bounded_int(self.env, "LOCAL_IMAGE_REBUILD_RETRY_HOURS", 24, 1, 168) * 3600)
        local_results = [["image", "container", "project", "service", "working_dir", "result", "fixable", "detail"]]
        registry_results = [["image", "container", "project", "service", "status", "current_image_id", "latest_image_id", "detail"]]
        excluded_images = patterns(self.env.get("IMAGE_UPDATE_AUTO_RECREATE_EXCLUDE_PATTERNS", ""))
        included_images = patterns(self.env.get("IMAGE_UPDATE_AUTO_RECREATE_INCLUDE_PATTERNS", ""))
        local_includes = patterns(self.env.get("LOCAL_IMAGE_INCLUDE_PATTERNS", ""))
        local_excludes = patterns(self.env.get("LOCAL_IMAGE_EXCLUDE_PATTERNS", ""))
        local_targets = patterns(self.env.get("LOCAL_IMAGE_AUTO_REBUILD_TARGET_PATTERNS", ""))
        for (old_id, reference), pairs in sorted(groups.items(), key=lambda x: str(x[0])):
            item, d = pairs[0]
            origins = {desc.get("origin") for _, desc in pairs}
            origin = next(iter(origins)) if len(origins) == 1 else "unknown"
            if origin == "local" and (not enabled(self.env["LOCAL_IMAGE_AUTO_REBUILD_ENABLED"]) or
               any(fnmatch.fnmatchcase(reference, p) for p in local_excludes) or
               (local_includes and not any(fnmatch.fnmatchcase(reference, p) for p in local_includes)) or
               (local_targets and not any(fnmatch.fnmatchcase(reference, p) for p in local_targets))):
                continue
            if origin in {"registry", "pinned"} and not enabled(self.env["IMAGE_UPDATE_CHECK_ENABLED"]):
                continue
            if origin == "unknown":
                self.emit({"kind": "source", "status": "unknown_source", "severity": "warning",
                           "service": d.get("name", ""), "image": reference,
                           "message": f"{reference}: Der Bau- oder Veröffentlichungsweg ist nicht eindeutig.",
                           "action": "Compose-Bauanleitung oder ursprüngliche Registry-Referenz zuordnen."})
                continue
            if "@sha256:" in reference or origin == "pinned":
                self.emit({"kind": "registry", "status": "digest_pinned", "severity": "warning",
                           "service": d.get("name", ""), "image": reference,
                           "message": f"{d.get('name', reference)}: Die Version ist über eine Prüfsumme festgelegt.",
                           "action": "Neue Version in der maßgeblichen Compose-Datei bzw. über deren Abhängigkeitsaktualisierung eintragen."})
                continue
            prepare_only = origin == "local" and any(not desc.get("automatic_allowed") for _, desc in pairs)
            allowed_key = "build_allowed" if prepare_only else "automatic_allowed"
            if any(not desc.get(allowed_key) for _, desc in pairs):
                reason = next((desc.get("reason") for _, desc in pairs if not desc.get("automatic_allowed")), "Vorprüfung nicht bestanden.")
                self.emit({"kind": origin, "status": "update_deferred", "severity": "warning",
                           "service": d.get("name", ""), "project": d.get("project", ""), "image": reference,
                           "message": f"{d.get('name', reference)}: Aktualisierung zurückgestellt. {reason}",
                           "action": "Die genannte Voraussetzung für diesen Dienst ergänzen."})
                continue
            if old_id not in self.scanner.documents:
                continue
            remote = None
            fingerprint = hashlib.sha256(json.dumps(sorted(findings(self.scanner.documents[old_id]))).encode()).hexdigest()
            build_fingerprint = hashlib.sha256(json.dumps({
                "image_id": old_id, "prepare_only": prepare_only,
                "builds": sorted(desc.get("build_fingerprint", "") for _, desc in pairs),
            }, sort_keys=True).encode()).hexdigest()
            key = hashlib.sha256(f"{reference}|{d.get('project')}|{d.get('service')}".encode()).hexdigest()
            if origin == "local":
                previous = schedule["entries"].get(key, {})
                previous_wait = interval if previous.get("status") in {
                    "rebuilt", "update_applied", "updated", "applied", "unchanged",
                    "prepared_only", "candidate_rejected"} else retry_interval
                if (not self.args.force_rebuild and previous.get("findings") == fingerprint and
                    previous.get("build_fingerprint") == build_fingerprint and
                    time.time() - float(previous.get("attempted_at", 0)) < previous_wait):
                    continue
                self.say(f"Lokales Image wird getrennt neu gebaut: {reference}")
            else:
                if any(fnmatch.fnmatchcase(reference, p) for p in excluded_images):
                    continue
                try:
                    remote = remote_image(self.runner, reference)
                    image_info = docker_json(self.runner, ["image", "inspect", old_id])[0]
                    digests = image_info.get("RepoDigests") or []
                    if any(str(ref).split("@")[-1] == remote.split("@")[-1] for ref in digests):
                        continue
                except Exception:
                    self.emit({"kind": "registry", "status": "registry_check_failed", "severity": "warning",
                               "image": reference, "message": f"{reference}: Die veröffentlichte Version konnte nicht geprüft werden.",
                               "action": "Registry-Zugriff, Anmeldung und Netzwerk prüfen."})
                    continue
                if (not enabled(self.env["IMAGE_UPDATE_AUTO_RECREATE_ENABLED"]) or
                    (included_images and not any(fnmatch.fnmatchcase(reference, p) for p in included_images))):
                    self.emit({"kind": "registry", "status": "update_available", "severity": "info", "image": reference,
                               "message": f"{reference}: Eine neue Veröffentlichung ist verfügbar.",
                               "action": "Die automatische Übernahme ist für dieses Image ausgeschaltet."})
                    continue
            result = self.engine.update_group([raw for raw, _ in pairs], source=origin,
                                              remote_ref=remote, require_improvement=False,
                                              prepare_only=prepare_only)
            status = result.get("status", "unknown")
            before = self.scanner.documents[old_id]
            candidate = self.scanner.documents.get(result.get("new_image_id"))
            actual_id = result.get("actual_image_id")
            after = self.scanner.documents.get(actual_id) if actual_id else None
            outcome = {"image": reference, "services": [desc.get("name", "") for _, desc in pairs],
                       "targets": [{"project": desc.get("project", ""), "service": desc.get("service", "")}
                                   for _, desc in pairs],
                       "origin": origin, "status": status, "build_status": result.get("build_status", "not_attempted"),
                       "deployment_status": result.get("deployment_status", "kept_previous"),
                       "verification_status": result.get("verification_status", "not_run"),
                       "preparation_only": prepare_only,
                       "old_image_id": old_id, "candidate_image_id": result.get("new_image_id"),
                       "actual_image_id": actual_id, "before": package_counts(before),
                       "message": result.get("message", ""), "action": result.get("action", "")}
            if candidate is not None:
                outcome["candidate"] = package_counts(candidate)
            if after is not None:
                outcome["after"] = package_counts(after)
                old_findings, new_findings = findings(before), findings(after)
                outcome.update(resolved=len(old_findings - new_findings), new=len(new_findings - old_findings),
                               remaining=len(new_findings), comparison_scope="running")
            self.status["image_outcomes"].append(outcome)
            self.save()
            if origin == "local":
                observed_id = result.get("actual_image_id") or old_id
                observed_document = self.scanner.documents.get(observed_id, before)
                next_findings = hashlib.sha256(json.dumps(sorted(findings(observed_document))).encode()).hexdigest()
                next_build = hashlib.sha256(json.dumps({
                    "image_id": observed_id, "prepare_only": prepare_only,
                    "builds": sorted(desc.get("build_fingerprint", "") for _, desc in pairs),
                }, sort_keys=True).encode()).hexdigest()
                schedule["entries"][key] = {"attempted_at": time.time(), "findings": next_findings,
                                             "build_fingerprint": next_build,
                                             "image_id": observed_id, "status": status}
                atomic_json(self.state_dir / "rebuild-schedule.json", schedule)
            for _, desc in pairs:
                if origin == "local":
                    legacy_status = {"rebuilt": "rebuilt_pending_rescan", "updated": "rebuilt_pending_rescan", "applied": "rebuilt_pending_rescan",
                                     "unchanged": "candidate_not_improved", "candidate_rejected": "candidate_not_improved"}.get(status, status)
                    local_results.append([reference, desc.get("name", ""), desc.get("project", ""), desc.get("service", ""),
                                          desc.get("working_dir", ""), legacy_status,
                                          len(findings(self.scanner.documents[old_id], fixable=True)), result.get("message", "")])
                else:
                    legacy_status = {"updated": "update_applied", "applied": "update_applied", "unchanged": "up_to_date"}.get(status, status)
                    registry_results.append([reference, desc.get("name", ""), desc.get("project", ""), desc.get("service", ""),
                                             legacy_status, old_id, result.get("new_image_id", ""), result.get("message", "")])
            write_tsv(self.run_dir / "local-image-rebuild-results.tsv", local_results)
            write_tsv(self.run_dir / "image-update-check-results.tsv", registry_results)
            after_id = result.get("actual_image_id")
            if (origin == "local" and result.get("deployment_status") == "applied"
                and after_id in self.scanner.documents):
                remaining = findings(self.scanner.documents[after_id], fixable=True)
                if remaining:
                    packages = ", ".join(sorted({row[1] for row in remaining})[:8])
                    self.emit({"kind": "local", "status": "source_fix_needed", "severity": "warning",
                               "image": reference, "service": d.get("name", ""), "project": d.get("project", ""),
                               "message": f"{reference}: Nach dem Neubau bleiben korrigierbare Paketfunde bestehen.",
                               "action": f"Baugrundlagen in {d.get('working_dir', '')} prüfen. Betroffene Pakete: {packages}."})
            if status in {"rollback_failed", "interrupted", "recovery_required"}:
                self.emit({"kind": "run", "status": "maintenance_stopped", "severity": "error",
                           "message": "Weitere Aktualisierungen wurden nach einer ungeklärten Wiederherstellung angehalten.",
                           "action": "Den betroffenen Dienst und das geschützte Aktualisierungsjournal prüfen."})
                break

    def _project_notification_ledger(self):
        from securitywatch_lifecycle import read_json
        path = self.state_dir / "project-notifications.json"
        if not path.exists() and not path.is_symlink():
            return {"schema": 1, "sent": {}}
        if path.is_symlink() or path.resolve() != self.state_dir.resolve() / path.name:
            raise ValueError("Unerwarteter Quittungspfad")
        data = read_json(path)
        if data.get("schema") != 1 or not isinstance(data.get("sent"), dict):
            raise ValueError("Ungültige Versandquittung")
        for key, value in data["sent"].items():
            if (not re.fullmatch(r"[0-9a-f]{32}", key) or not isinstance(value, dict)
                or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", "")))):
                raise ValueError("Ungültige Versandquittung")
        return data

    def prepare_project_notifications(self):
        """Read completed one-time changes; compare retained images before cleanup."""
        if self._project_receipts is not None:
            return
        self._project_receipts = []
        from securitywatch_lifecycle import read_json
        from securitywatch_project_updates import TARGETS
        try:
            ledger = self._project_notification_ledger()
            directory = self.state_dir / "transactions"
            if not directory.exists() and not directory.is_symlink():
                return
            if directory.is_symlink() or directory.resolve() != self.state_dir.resolve() / "transactions":
                raise ValueError("Unerwarteter Journalpfad")
            paths = sorted(directory.glob("*.json"))
        except Exception:
            self.emit({"kind": "run", "status": "project_notice_failed", "severity": "warning",
                       "message": "Die Nachmeldung früherer Projektumstellungen konnte nicht gelesen werden.",
                       "action": "Das private Aktualisierungsjournal und die Versandquittungen prüfen."})
            return
        confirmed = {item["image_id"] for item in self.status["scans"]["images"].get("items", [])
                     if item.get("status") == "ok"}
        for path in paths:
            try:
                if (path.is_symlink() or path.resolve() != directory.resolve() / path.name
                    or not re.fullmatch(r"[0-9a-f]{32}\.json", path.name)):
                    raise ValueError("Unerwarteter Journalpfad")
                record = read_json(path)
                if record.get("phase") != "complete" or "migration" not in record:
                    continue
                migration = record["migration"]
                target = TARGETS.get(migration.get("target")) if isinstance(migration, dict) else None
                old_id, new_id = record.get("old_image_id"), record.get("candidate_image_id")
                stamp = record.get("successful_replacement_at")
                if (record.get("schema") != 1 or record.get("id") != path.stem or record.get("source") != "registry"
                    or not target or migration.get("from") != target.old_ref or migration.get("to") != target.new_ref
                    or record.get("image_ref") != target.old_ref
                    or not isinstance(old_id, str) or not IMAGE_ID.fullmatch(old_id)
                    or not isinstance(new_id, str) or not IMAGE_ID.fullmatch(new_id)
                    or isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or not math.isfinite(stamp)
                    or stamp <= 0):
                    raise ValueError("Ungültige Projektumstellung")
                services = record.get("services")
                if (not isinstance(services, list) or len(services) != 1 or not isinstance(services[0], dict)
                    or services[0].get("project") != target.project or services[0].get("service") != target.service
                    or services[0].get("image_id") != old_id
                    or record.get("touched_services") != [{"project": target.project, "service": target.service}]):
                    raise ValueError("Ungültige Dienstzuordnung")
                source = migration.get("target_tag") or {}
                if source.get("reference") != target.new_ref or source.get("phase") != "applied":
                    raise ValueError("Nicht abgeschlossene Image-Zuordnung")
                for field in ("before_sha256", "after_sha256"):
                    if not re.fullmatch(r"[0-9a-f]{64}", str(migration.get(field, ""))):
                        raise ValueError("Ungültige Quellensicherung")
                source_path = Path(migration.get("compose_path", ""))
                backup_path = self.state_dir / "project-update-backups" / path.stem / "compose-before.yaml"
                if (not source_path.is_absolute() or source_path.resolve() != source_path
                    or migration.get("backup_path") != str(backup_path)
                    or backup_path.resolve() != self.state_dir.resolve() / "project-update-backups" / path.stem / "compose-before.yaml"):
                    raise ValueError("Unerwartete Quellenpfade")
                digest = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"),
                                                  ensure_ascii=False, allow_nan=False).encode()).hexdigest()
                if ledger["sent"].get(path.stem, {}).get("sha256") == digest:
                    continue
                completed_at = datetime.fromtimestamp(stamp, tz=timezone.utc)
                display_time = completed_at.astimezone(berlin_now().tzinfo).strftime("%d.%m.%Y, %H:%M Uhr")
                receipt = {"id": path.stem, "sha256": digest, "old_image_id": old_id,
                           "candidate_image_id": new_id, "from": target.old_ref, "to": target.new_ref,
                           "completed_at": completed_at.isoformat(), "project": target.project,
                           "service": target.service, "container": target.name,
                           "message": f"Bereits am {display_time} übernommen und geprüft: {target.old_ref} → {target.new_ref}."}
                if enabled(self.env["TRIVY_SCAN_IMAGES"]) and new_id in confirmed:
                    try:
                        # Uses this run's frozen database and immutable IDs, never an old comparison.
                        self.scanner.scan_image(old_id)
                    except Exception:
                        receipt["comparison_unavailable"] = True
                self._project_receipts.append(receipt)
            except Exception:
                self.emit({"kind": "run", "status": "project_notice_invalid", "severity": "warning",
                           "message": "Eine frühere Projektumstellung konnte nicht verlässlich nachgemeldet werden.",
                           "action": "Das private Aktualisierungsjournal prüfen; die Umstellung wurde nicht als gemeldet markiert."})

    def import_project_notifications(self, containers):
        """Report prior changes without claiming that this run deployed them."""
        self.prepare_project_notifications()
        confirmed = {item["image_id"] for item in self.status["scans"]["images"].get("items", [])
                     if item.get("status") == "ok"}
        existing = list(self.status["image_outcomes"])
        included = {item["id"] for item in self.status.get("project_updates", [])}
        for receipt in self._project_receipts:
            if receipt["id"] in included:
                continue
            target = {"project": receipt["project"], "service": receipt["service"]}
            current = next((item for item in existing if target in item.get("targets", [])), None)
            if current is not None:
                current.setdefault("earlier_updates", []).append(receipt["message"])
            else:
                members = [item for item in containers or [] if
                           all(((item.get("Config") or {}).get("Labels") or {}).get("com.docker.compose." + key) == value
                               for key, value in target.items())]
                same_image = (len(members) == 1 and (members[0].get("State") or {}).get("Running")
                              and members[0].get("Image") == receipt["candidate_image_id"])
                comparable = bool(same_image and receipt["candidate_image_id"] in confirmed
                                  and receipt["candidate_image_id"] in self.scanner.documents)
                message = receipt["message"]
                if not same_image:
                    message += " Diese frühere Übernahme entspricht nicht dem jetzt bestätigten laufenden Stand."
                elif not comparable:
                    message += " Für den aktuellen Sicherheitsstand liegt keine bestätigte Image-Prüfung vor."
                elif receipt["old_image_id"] not in self.scanner.documents:
                    message += " Die Vorversion ist nicht mehr prüfbar; der Vorher/Nachher-Vergleich bleibt unbekannt."
                outcome = {"image": receipt["to"], "services": [receipt["container"]], "targets": [target],
                           "origin": "registry", "status": "update_applied", "build_status": "not_attempted",
                           "deployment_status": "applied", "verification_status": "ok" if comparable else "not_run",
                           "historical_update": True, "historical_only": not comparable,
                           "migration_transaction_id": receipt["id"], "completed_at": receipt["completed_at"],
                           "old_image_id": receipt["old_image_id"], "candidate_image_id": receipt["candidate_image_id"],
                           "actual_image_id": receipt["candidate_image_id"] if same_image else None,
                           "runtime_confirmed": bool(same_image), "message": message, "action": ""}
                before = self.scanner.documents.get(receipt["old_image_id"])
                if comparable and before is not None:
                    outcome["before"] = package_counts(before)
                self.status["image_outcomes"].append(outcome)
            self.status.setdefault("project_updates", []).append({
                key: receipt[key] for key in ("id", "old_image_id", "candidate_image_id", "from", "to",
                                              "completed_at", "project", "service", "container")})
            self._project_receipts_to_ack[receipt["id"]] = receipt["sha256"]
        self.save()

    def acknowledge_project_notifications(self):
        """Only an actual SMTP delivery may acknowledge the included receipts."""
        if self.status.get("delivery", {}).get("status") != "sent" or not self._project_receipts_to_ack:
            return
        from securitywatch_lifecycle import atomic_json as private_json
        try:
            ledger = self._project_notification_ledger()
            for key, digest in self._project_receipts_to_ack.items():
                ledger["sent"][key] = {"sha256": digest, "sent_at": now_iso(), "run_id": self.run_id}
            private_json(self.state_dir / "project-notifications.json", ledger)
            self._project_receipts_to_ack.clear()
        except Exception:
            self.say("Die E-Mail wurde versendet, ihre Umstellungsquittung konnte jedoch nicht gespeichert werden. Die nächste Mail kann diese Meldung wiederholen.")

    def final_inventory(self) -> list[dict] | None:
        """Observe the final runtime again; never promote an unscanned image."""
        images = self.status["scans"]["images"]
        if images["status"] == "disabled" and not self.status["image_outcomes"] and not self._project_receipts:
            return None
        try:
            containers = container_inventory(self.runner)
            grouped = defaultdict(list)
            for item in containers:
                if not (item.get("State") or {}).get("Running"):
                    continue
                image_id = item.get("Image", "")
                if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
                    raise ScanError("Der abschließende Bestand enthält eine ungültige Image-ID.")
                grouped[image_id].append(item)
            atomic_json(self.run_dir / "container-nachher.json", [minimal_container(c) for c in containers])
        except Exception:
            if images["status"] != "disabled":
                images["status"] = "failed"
                images["succeeded"] = 0
                images["failed"] = images.get("expected", 0)
                for entry in images.get("items", []):
                    entry.update(status="failed", error="Der abschließende Containerbestand konnte nicht bestätigt werden.")
            self.emit({"kind": "scan", "status": "final_inventory_failed", "severity": "error",
                       "message": "Der abschließende Containerbestand konnte nicht bestätigt werden.",
                       "action": "Docker-Zugriff prüfen und die Sicherheitsprüfung wiederholen."})
            return None

        if images["status"] != "disabled":
            previous = {entry["image_id"]: entry for entry in images.get("items", [])}
            changed = set(previous) != set(grouped)
            entries = []
            for image_id, members in sorted(grouped.items()):
                entry = dict(previous.get(image_id) or {
                    "image_id": image_id, "status": "failed",
                    "file": "image_" + image_id.split(":")[1] + ".json",
                    "error": "Dieses Image war nicht Bestandteil der abgeschlossenen Image-Prüfung.",
                })
                entry["references"] = sorted({self._descriptors.get(item["Id"], {}).get("image_ref")
                                               or (item.get("Config") or {}).get("Image", image_id)
                                               for item in members})
                entry["containers"] = sorted(str(item.get("Name", "")).lstrip("/") for item in members)
                entries.append(entry)
            images.update(items=entries, expected=len(entries),
                          succeeded=sum(entry["status"] == "ok" for entry in entries),
                          failed=sum(entry["status"] != "ok" for entry in entries))
            if changed or images["failed"]:
                images["status"] = "partial"
            if changed:
                self.emit({"kind": "scan", "status": "final_images_changed", "severity": "error",
                           "message": "Der laufende Image-Bestand hat sich nach der Sicherheitsprüfung verändert.",
                           "action": "Die Sicherheitsprüfung wiederholen. Neu beobachtete Images gelten noch nicht als geprüft."})
        self.health_events(containers)
        return containers

    def reconcile_outcomes(self, containers: list[dict] | None):
        """Tie every final per-image statement to the observed running services."""
        confirmed = {entry["image_id"] for entry in self.status["scans"]["images"].get("items", [])
                     if entry.get("status") == "ok"}
        for outcome in self.status["image_outcomes"]:
            if outcome.get("historical_only"):
                continue
            outcome["runtime_confirmed"] = False
            for field in ("after", "resolved", "new", "remaining", "comparison_scope"):
                outcome.pop(field, None)
            targets = outcome.get("targets", [])
            matching = []
            if containers is not None and targets:
                for target in targets:
                    rows = []
                    for item in containers:
                        labels = (item.get("Config") or {}).get("Labels") or {}
                        if (labels.get("com.docker.compose.project") == target["project"] and
                            labels.get("com.docker.compose.service") == target["service"]):
                            rows.append(item)
                    if len(rows) != 1 or not (rows[0].get("State") or {}).get("Running"):
                        matching = []
                        break
                    matching.extend(rows)
            ids = {item.get("Image") for item in matching}
            if len(ids) != 1:
                outcome["actual_image_id"] = None
                outcome["verification_status"] = "failed"
                outcome["action"] = "Den tatsächlich laufenden Stand des Dienstes prüfen; kein bestätigtes Nachher-Ergebnis verfügbar."
                self.emit({"kind": "health", "status": "final_state_unknown", "severity": "error",
                           "image": outcome["image"], "message": f"{outcome['image']}: Der abschließende Betriebszustand ist nicht eindeutig.",
                           "action": outcome["action"]})
                continue
            actual_id = next(iter(ids))
            previous_actual = outcome.get("actual_image_id")
            outcome["actual_image_id"] = actual_id
            outcome["runtime_confirmed"] = True
            if previous_actual != actual_id:
                outcome["verification_status"] = "failed"
                outcome["deployment_status"] = "failed"
                outcome["action"] = "Der Image-Stand wurde während des Laufs verändert. Dienst und Aktualisierungsjournal prüfen."
                self.emit({"kind": "health", "status": "final_state_changed", "severity": "error",
                           "image": outcome["image"], "message": f"{outcome['image']}: Der laufende Stand weicht von der Übernahmeprüfung ab.",
                           "action": outcome["action"]})
            if (not outcome.get("preparation_only") and
                any(((item.get("State") or {}).get("Health") or {}).get("Status") != "healthy" for item in matching)):
                outcome["verification_status"] = "failed"
                self.emit({"kind": "health", "status": "final_health_failed", "severity": "error",
                           "image": outcome["image"], "message": f"{outcome['image']}: Die abschließende Zustandsprüfung ist nicht erfolgreich.",
                           "action": "Den aktuellen Dienstzustand und die Zustandsprüfung kontrollieren."})
            after = self.scanner.documents.get(actual_id) if actual_id in confirmed else None
            before = self.scanner.documents.get(outcome["old_image_id"])
            if after is not None:
                outcome["after"] = package_counts(after)
                if before is not None:
                    old_findings, new_findings = findings(before), findings(after)
                    outcome.update(resolved=len(old_findings - new_findings), new=len(new_findings - old_findings),
                                   remaining=len(new_findings), comparison_scope="running")
        self.save()

    def reconcile_legacy_results(self):
        """Keep the detailed legacy table consistent with the final image cards."""
        path = self.run_dir / "local-image-rebuild-results.tsv"
        if not path.is_file():
            return
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            fields = list(reader.fieldnames or [])
            rows = list(reader)
        for row in rows:
            outcome = next((item for item in self.status["image_outcomes"]
                            if item["origin"] == "local" and item["image"] == row.get("image")
                            and any(target["project"] == row.get("project") and target["service"] == row.get("service")
                                    for target in item.get("targets", []))), None)
            if outcome is None:
                continue
            after = outcome.get("after")
            row["fixable"] = str(after["fixable"]) if isinstance(after, dict) else "nicht ermittelt"
            deployment = outcome.get("deployment_status")
            if outcome.get("build_status") == "failed":
                result = "build_failed"
            elif deployment == "failed" or outcome.get("verification_status") == "failed":
                result = "rollback_failed" if outcome.get("status") in {"rolled_back", "rollback_failed"} else "up_failed"
            elif deployment == "rolled_back":
                result = "rolled_back"
            elif deployment == "applied":
                result = ("rebuilt_pending_rescan" if after is None else "still_vulnerable" if after["total"]
                          else "fixed" if outcome.get("before", {}).get("total") else "rebuilt")
            elif outcome.get("status") == "candidate_rejected":
                result = "candidate_not_improved"
            elif outcome.get("build_status") == "succeeded":
                result = "rebuilt"
            else:
                result = "skipped"
            row["result"] = result
            row["detail"] = outcome.get("message", "")
            if outcome.get("action"):
                row["detail"] += " " + outcome["action"]
        write_tsv(path, [fields] + [[row.get(field, "") for field in fields] for row in rows])

    def github(self):
        path = Path(self.env["GITHUB_CONFIG_FILE"])
        if not path.is_file():
            self.status["github"] = {"status": "disabled", "reason": "Keine geprüfte Repository-Zuordnung hinterlegt."}
            self.emit({"kind": "github", "status": "configuration_needed", "severity": "warning",
                       "message": "Die GitHub-Bauüberwachung ist noch nicht eingerichtet.",
                       "action": "Repository, Bauablauf und Image in securitywatch.github.json zuordnen; Beispiel und Anleitung liegen im Paket."})
            return
        try:
            from securitywatch_github import deployment_advice, load_config, monitor_github
            configured = load_config(path)
            result = monitor_github(configured, token_file=self.env.get("GITHUB_TOKEN_FILE") or None)
            references = sorted({descriptor["image_ref"] for descriptor in self._descriptors.values()
                                 if descriptor.get("image_ref")})
            result.setdefault("events", []).extend(deployment_advice(configured, references))
            self.status["github"] = result
            for event in result.get("events", []):
                self.emit(event)
        except Exception:
            self.status["github"] = {"status": "partial"}
            self.emit({"kind": "github", "status": "check_failed", "severity": "warning",
                       "message": "Die GitHub-Bauüberwachung konnte nicht vollständig ausgeführt werden.",
                       "action": "Zuordnungsdatei und lesenden Repository-Zugriff prüfen."})
        self.save()

    def render_and_mail(self):
        command = [sys.executable, str(self.base / "securitywatch_report.py"), "--run-dir", str(self.run_dir),
                   "--summary-json", str(self.run_dir / "summary.json"), "--mail-txt", str(self.run_dir / "mail.txt"),
                   "--mail-html", str(self.run_dir / "mail.html"), "--env-file", str(self.env_path),
                   "--lang", "de", "--script-version", VERSION,
                   "--filesystem-scanned", "1" if self.status["scans"]["host"]["status"] == "ok" else "0",
                   "--images-scanned", "1" if self.status["scans"]["images"]["status"] == "ok" else "0"]
        try:
            proc = subprocess.run(command, text=True, capture_output=True, timeout=180)
            report_failed = bool(proc.returncode)
            if not report_failed:
                summary = json.loads((self.run_dir / "summary.json").read_text(encoding="utf-8"))
                evaluated = summary.get("run_status")
                if (not isinstance(evaluated, dict) or evaluated.get("version") != 1 or
                    not isinstance(evaluated.get("run"), dict) or
                    evaluated["run"].get("id") != self.run_id or
                    not isinstance(evaluated.get("scans"), dict)):
                    raise ValueError("Die Berichtsauswertung gehört nicht zu diesem Lauf.")
                # The report may discover missing or invalid files after the
                # scanner returned. Import only its coverage downgrades; keep
                # the orchestrator's own events and other state intact.
                for name in ("host", "images"):
                    section = evaluated["scans"].get(name)
                    if not isinstance(section, dict):
                        raise ValueError("Die Berichtsauswertung enthält keinen vollständigen Prüfumfang.")
                    if section.get("status") not in {"ok", "disabled"}:
                        self.status["scans"][name] = section
                validation_errors = summary.get("report_validation_errors") or []
                self.status["report_validation_errors"] = validation_errors
                report_state = evaluated["run"].get("status")
                if report_state == "failed":
                    self.status["run"]["status"] = "failed"
                elif (validation_errors or report_state != "completed" or
                      not (summary.get("scan") or {}).get("complete")):
                    if self.status["run"]["status"] == "completed":
                        self.status["run"]["status"] = "partial"
                self.save()
        except (OSError, ValueError, AttributeError, TypeError, subprocess.SubprocessError):
            report_failed = True
        if report_failed:
            self.say("Der ausführliche Bericht konnte nicht erstellt werden. Ein kurzer Fehlerbericht wird erzeugt.")
            self.status["run"]["status"] = "failed"
            self.emit({"kind": "run", "status": "report_failed", "severity": "error",
                       "message": "Die Berichtserstellung ist fehlgeschlagen.", "action": "Programmdateien und Laufordner prüfen."})
            from securitywatch_notifications import build_model, render_html, render_text
            summary = {"total": 0, "critical": 0, "high": 0, "script_version": VERSION, "run_status": self.status}
            model = build_model(summary, self.status, self.env)
            atomic_json(self.run_dir / "summary.json", summary)
            (self.run_dir / "mail.txt").write_text(render_text(model), encoding="utf-8")
            (self.run_dir / "mail.html").write_text(render_html(model), encoding="utf-8")
        if not self.args.no_mail:
            delivery_path = self.run_dir / "mail-delivery.json"
            try:
                proc = subprocess.run([sys.executable, str(self.base / "securitywatch_mail.py"),
                                   "--env-file", str(self.env_path), "--summary-json", str(self.run_dir / "summary.json"),
                                   "--mail-txt", str(self.run_dir / "mail.txt"), "--mail-html", str(self.run_dir / "mail.html"),
                                   "--result-json", str(delivery_path)],
                                  text=True, capture_output=True, timeout=120)
                delivery = json.loads(delivery_path.read_text(encoding="utf-8"))
                delivery_status = delivery.get("status")
                if proc.returncode or delivery_status not in {"sent", "skipped"}:
                    delivery_status = "failed"
            except (OSError, ValueError, AttributeError, subprocess.SubprocessError):
                delivery_status = "failed"
            self.status["delivery"] = {"status": delivery_status}
            if delivery_status == "failed":
                self.status["delivery"] = {"status": "failed"}
                if self.status["run"]["status"] != "failed":
                    self.status["run"]["status"] = "partial"
                self.say("Die E-Mail konnte nicht versendet werden. Der Bericht liegt vollständig im Laufordner.")
        else:
            self.status["delivery"] = {"status": "disabled"}
        self.acknowledge_project_notifications()
        self.save()

    def cleanup_report_history(self):
        """Apply report retention to check, report-only and maintenance runs."""
        if (self.args.no_report_cleanup or self.args.no_cleanup or
            not enabled(self.env.get("REPORT_CLEANUP_ENABLED"), True)):
            self.status["report_retention"] = {"status": "disabled", "removed": 0}
            return
        if self.engine is None or self.engine.open_transactions():
            self.status["report_retention"] = {
                "status": "deferred", "removed": 0,
                "reason": "Berichte bleiben für die noch offene Wiederherstellung erhalten."}
            return
        from securitywatch_housekeeping import cleanup_reports
        result = cleanup_reports(self.report_dir, self.run_dir,
                                 days=bounded_int(self.env, "REPORT_RETENTION_DAYS", 30, 0, 3650),
                                 keep_last=bounded_int(self.env, "REPORT_KEEP_LAST", 10, 1, 1000))
        self.status["report_retention"] = {"status": "partial" if result["errors"] else "ok", **result}
        if result["errors"]:
            self.emit({"kind": "retention", "status": "report_cleanup_failed", "severity": "warning",
                       "message": "Einige abgelaufene Berichte konnten noch nicht entfernt werden.",
                       "action": "Schreibrechte und freien Speicherplatz im Berichtsordner prüfen."})
        elif result["removed"]:
            self.say(f"Berichtsaufbewahrung: {result['removed']} abgelaufene Berichte entfernt.")

    def run(self) -> int:
        self.say(f"SecurityWatch {VERSION} gestartet. Lauf: {self.run_id}")
        outcome = 0
        final_inventory = None
        try:
            self.make_engine()
            containers = container_inventory(self.runner)
            atomic_json(self.run_dir / "container-vorher.json", [minimal_container(c) for c in containers])
            described = self.describe(containers)
            self.local_metadata(described)
            self.health_events(containers)
            pending = self.engine.open_transactions()
            if pending:
                self.emit({"kind": "run", "status": "unfinished_update", "severity": "error",
                           "message": "Ein früherer Aktualisierungsvorgang ist noch nicht abgeschlossen.",
                           "action": "Geschütztes Journal prüfen. Betroffene Dienste werden nicht erneut automatisch verändert."})
            if enabled(self.env["TRIVY_SCAN_FILESYSTEM"]) or enabled(self.env["TRIVY_SCAN_IMAGES"]):
                self.say("Prüfwerkzeug und gemeinsame Schwachstellendaten werden vorbereitet.")
                self.status["scanner"] = self.scanner.prepare()
                self.save()
            if enabled(self.env["TRIVY_SCAN_FILESYSTEM"]):
                self.say("Das NAS-Dateisystem wird ausschließlich lesend geprüft.")
                try:
                    self.scanner.scan_host()
                    self.status["scans"]["host"]["status"] = "ok"
                    from securitywatch_housekeeping import host_package_inventory, host_backport_notes
                    host_backport_notes(self.run_dir)
                    if enabled(self.env.get("HOST_PACKAGE_INVENTORY_ENABLED"), True):
                        try:
                            host_package_inventory(self.run_dir, self.env)
                        except (OSError, subprocess.SubprocessError, RuntimeError):
                            self.emit({"kind": "scan", "status": "host_inventory_failed", "severity": "warning",
                                       "message": "Die ergänzende NAS-Paketliste konnte nicht vollständig erstellt werden.",
                                       "action": "dpkg-query und die Lesbarkeit der Paketdatenbank prüfen."})
                except ScanError as exc:
                    self.status["scans"]["host"].update(status="failed", error=str(exc))
                    self.emit({"kind": "scan", "status": "host_scan_failed", "severity": "error",
                               "message": "Die Sicherheitsprüfung des NAS-Dateisystems ist unvollständig.",
                               "action": "Prüfprotokoll im Laufordner ansehen."})
                self.save()
            if enabled(self.env["TRIVY_SCAN_IMAGES"]):
                self.image_scans(containers, phase="before")
                if not self.args.report_only and self.status["scans"]["images"]["status"] == "ok":
                    self.updates(described)
                    after = container_inventory(self.runner)
                    described_after = self.describe(after)
                    self.local_metadata(described_after)
                    self.health_events(after)
                    self.image_scans(after, phase="after")
                    atomic_json(self.run_dir / "container-nachher.json", [minimal_container(c) for c in after])
                    final_inventory = after
                elif not self.args.report_only:
                    self.emit({"kind": "run", "status": "updates_blocked", "severity": "warning",
                               "message": "Anwendungsaktualisierungen wurden wegen unvollständiger Image-Prüfungen zurückgestellt.",
                               "action": "Fehlgeschlagene Image-Prüfungen beheben und den Lauf wiederholen."})
            self.prepare_project_notifications()
            self.github()
            if not self.args.host_only and not self.args.report_only and not self.args.no_cleanup and not self.args.no_prune_unused_images:
                self.status["retention"].update(self.engine.cleanup_retention())
                self.save()
            elif self.engine is not None:
                self.status["retention"].update(self.engine.cleanup_retention(preview=True))
                self.save()
            self.cleanup_report_history()
            if (any(e.get("severity") == "error" for e in self.status["events"]) or
                self.status.get("github", {}).get("status") in {"partial", "failed"}):
                outcome = 2
            self.status["run"]["status"] = "partial" if outcome else "completed"
        except (KeyboardInterrupt, SystemExit):
            outcome = 130
            self.status["run"]["status"] = "failed"
            self.emit({"kind": "run", "status": "interrupted", "severity": "error",
                       "message": "Der Lauf wurde unterbrochen. Offene Aktualisierungen bleiben geschützt.",
                       "action": "Laufbericht und offene Journale vor einer erneuten Aktualisierung prüfen."})
        except Exception as exc:
            outcome = 1
            self.status["run"]["status"] = "failed"
            detail = str(exc) if isinstance(exc, (ConfigurationError, ScanError)) else "Ein notwendiger Prüfschritt konnte nicht abgeschlossen werden."
            self.emit({"kind": "run", "status": "run_failed", "severity": "error", "message": f"SecurityWatch wurde vorzeitig beendet. {detail}",
                       "action": "Laufbericht prüfen; bisherige Images und offene Wiederherstellungen bleiben geschützt."})
        finally:
            self.prepare_project_notifications()
            final_inventory = self.final_inventory()
            self.import_project_notifications(final_inventory)
            self.reconcile_outcomes(final_inventory)
            self.reconcile_legacy_results()
            if self.status["run"]["status"] == "completed" and any(e.get("severity") == "error" for e in self.status["events"]):
                self.status["run"]["status"] = "partial"
            self.status["run"]["finished_at"] = now_iso()
            for section in self.status["scans"].values():
                if section.get("status") in {"running", "pending"}:
                    section["status"] = "failed"
            self.save()
            try:
                self.scanner.close()
            except Exception:
                self.say("Temporäre Prüfdaten konnten noch nicht vollständig entfernt werden.")
            try:
                self.render_and_mail()
            except Exception:
                outcome = 1
                self.status["run"]["status"] = "failed"
                self.say("Bericht oder Versand konnte nicht abgeschlossen werden. run-status.json enthält den tatsächlichen Zustand.")
                self.save()
            if self.status.get("delivery", {}).get("status") == "failed":
                outcome = max(outcome, 2)
            if self.status["run"]["status"] in {"failed", "partial"} or any(e.get("severity") == "error" for e in self.status["events"]):
                outcome = max(outcome, 2)
                if self.status["run"]["status"] == "completed":
                    self.status["run"]["status"] = "partial"
                    self.save()
            atomic_json(self.state_dir / "last-run.json", {"version": VERSION, "run_dir": str(self.run_dir),
                        "run": self.status["run"], "delivery": self.status.get("delivery", {})})
            self.say(f"Lauf beendet. Bericht: {self.run_dir}")
        return outcome


def installation_complete(state_dir: Path):
    path = state_dir / "securitywatch-install.json"
    if not path.exists():
        return
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        phase = doc.get("phase", doc.get("status"))
    except (OSError, ValueError, AttributeError) as exc:
        raise ConfigurationError("Das Installationsjournal ist nicht lesbar. Programmdateien vor einem Wartungslauf wiederherstellen.") from exc
    if phase not in {"committed", "rolled_back", "restored"}:
        raise ConfigurationError("Die Programmaktualisierung ist nicht abgeschlossen. Erst die Installation wiederherstellen.")


def main(argv=None) -> int:
    args = arguments(argv)
    os.umask(0o077)
    base = Path(__file__).resolve().parent
    env_path = (args.env_file or base / ".env").resolve()
    try:
        env = config(base, env_path, args)
        from securitywatch_lifecycle import DockerRunner
        runner = DockerRunner()
        state = Path(env["STATE_DIR"])
        with RunLock(state / "securitywatch.lock"):
            installation_complete(state)
            app = SecurityWatch(base, env_path, env, args, runner)
            if args.check or args.dry_run:
                return app.check_only()
            previous_handler = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
            try:
                return app.run()
            finally:
                signal.signal(signal.SIGTERM, previous_handler)
    except (ConfigurationError, ScanError, OSError) as exc:
        print(f"SecurityWatch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
