#!/usr/bin/env python3
"""Scans actual image IDs using one isolated Trivy/database snapshot per run."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from securitywatch_common import IMAGE_ID, atomic_json, enabled, patterns, private_directory


class ScanError(RuntimeError):
    pass


def validate_scan(doc: object, image_id: str | None = None) -> dict:
    if not isinstance(doc, dict) or doc.get("SchemaVersion") != 2:
        raise ScanError("Das Prüfwerkzeug lieferte kein unterstütztes Ergebnisdokument.")
    if not isinstance(doc.get("Metadata"), dict) or not isinstance(doc.get("Results", []), list):
        raise ScanError("Das Ergebnis der Sicherheitsprüfung ist unvollständig.")
    if image_id is not None:
        if doc.get("ArtifactType") != "container_image" or doc["Metadata"].get("ImageID") != image_id:
            raise ScanError("Das Prüfergebnis gehört nicht zur erwarteten Image-ID.")
    elif doc.get("ArtifactType") not in {"rootfs", "filesystem"}:
        raise ScanError("Das Prüfergebnis gehört nicht zum Dateisystem des NAS.")
    for result in doc.get("Results", []):
        if not isinstance(result, dict):
            raise ScanError("Ein Prüfabschnitt ist nicht lesbar.")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise ScanError("Die Liste der Sicherheitsfunde ist nicht lesbar.")
        for item in vulnerabilities or []:
            if (not isinstance(item, dict) or
                any(not isinstance(item.get(key), str) or not item[key].strip()
                    for key in ("VulnerabilityID", "PkgName"))):
                raise ScanError("Ein Sicherheitsfund enthält keine eindeutige Paketzuordnung.")
            if item.get("Severity") not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ScanError("Ein Sicherheitsfund enthält keinen gültigen Schweregrad.")
            if any(key in item and not isinstance(item[key], str)
                   for key in ("InstalledVersion", "FixedVersion")):
                raise ScanError("Ein Sicherheitsfund enthält eine ungültige Paketversion.")
    return doc


def findings(doc: dict, *, fixable: bool = False) -> set[tuple[str, str, str]]:
    """Identity deliberately excludes installed/fixed version and varying target paths."""
    out = set()
    for result in doc.get("Results", []):
        for item in result.get("Vulnerabilities") or []:
            if item.get("Severity") not in {"HIGH", "CRITICAL"}:
                continue
            if fixable and not item.get("FixedVersion"):
                continue
            out.add((str(result.get("Type", "")), str(item["PkgName"]), str(item["VulnerabilityID"])))
    return out


class TrivyScanner:
    def __init__(self, runner, env: dict, run_dir: Path, state_dir: Path, emit):
        self.runner = runner
        self.env = env
        self.run_dir = run_dir
        self.state_dir = state_dir
        self.emit = emit
        self.cache_dir = Path(env["CACHE_DIR"])
        self.scratch: Path | None = None
        self.scanner_id = ""
        self.context: dict = {}
        self.documents: dict[str, dict] = {}
        self.paths: dict[str, Path] = {}
        self.timeout = self._timeout_seconds(env.get("TRIVY_TIMEOUT", "60m"))

    @staticmethod
    def _timeout_seconds(value: str) -> int:
        import re
        match = re.fullmatch(r"([0-9]+)(s|m|h)?", str(value))
        if not match:
            raise ScanError("TRIVY_TIMEOUT muss beispielsweise 60m, 1h oder 3600s sein.")
        seconds = int(match[1]) * {None: 1, "s": 1, "m": 60, "h": 3600}[match[2]]
        if not 30 <= seconds <= 86400:
            raise ScanError("TRIVY_TIMEOUT muss zwischen 30 Sekunden und 24 Stunden liegen.")
        return seconds

    def _command(self, args: list[str], *, timeout: int, operation: str):
        try:
            proc = self.runner(args, timeout=timeout)
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            raise ScanError(f"{operation} konnte nicht abgeschlossen werden.") from exc
        if proc.returncode:
            # Raw tool messages may contain build paths or credentials. Keep them only in
            # the private run directory, never in events, subjects or terminal messages.
            with (self.run_dir / "pruefwerkzeug.log").open("a", encoding="utf-8") as handle:
                handle.write(f"\n{operation}\n{proc.stderr or ''}\n")
            raise ScanError(f"{operation} ist fehlgeschlagen; Einzelheiten stehen im Prüfprotokoll.")
        return proc

    def _run_container(self, mounts: list[str], trivy_args: list[str], operation: str):
        name = "securitywatch-pruefung-" + uuid.uuid4().hex[:20]
        args = ["run", "--rm", "--pull", "never", "--name", name,
                "--label", "de.securitywatch.purpose=scanner"]
        for mount in mounts:
            args += ["-v", mount]
        args += [self.scanner_id] + trivy_args
        try:
            return self._command(args, timeout=self.timeout + 90, operation=operation)
        finally:
            # On client cancellation Docker can keep a scanner running. This name is
            # generated here and never belongs to an application container.
            try:
                self.runner(["container", "rm", "--force", name], timeout=20)
            except Exception:
                pass

    def prepare(self) -> dict:
        reference = self.env.get("TRIVY_IMAGE", "ghcr.io/aquasecurity/trivy:latest")
        if not reference or reference.startswith("-") or any(c.isspace() for c in reference):
            raise ScanError("Die Referenz des Prüfwerkzeugs ist ungültig.")
        if enabled(self.env.get("TRIVY_AUTO_PULL_IMAGE"), True):
            try:
                self._command(["pull", reference], timeout=self.timeout, operation="Aktualisierung des Prüfwerkzeugs")
            except ScanError:
                self.emit({"kind": "run", "status": "scanner_pull_failed", "severity": "warning",
                           "message": "Das Prüfwerkzeug konnte nicht aktualisiert werden. Die vorhandene Version wird geprüft.",
                           "action": "Netzwerkzugriff und Prüfprotokoll kontrollieren."})
        proc = self._command(["image", "inspect", reference], timeout=30, operation="Ermittlung des Prüfwerkzeugs")
        try:
            rows = json.loads(proc.stdout)
            self.scanner_id = rows[0]["Id"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ScanError("Die Image-ID des Prüfwerkzeugs fehlt.") from exc
        if not IMAGE_ID.fullmatch(self.scanner_id):
            raise ScanError("Die Image-ID des Prüfwerkzeugs ist ungültig.")
        private_directory(self.cache_dir)
        self.scratch = Path(tempfile.mkdtemp(prefix="scan-daten-", dir=private_directory(self.state_dir)))
        for folder in ("db", "java-db"):
            cached = self.cache_dir / folder
            if cached.is_dir() and not cached.is_symlink():
                shutil.copytree(cached, self.scratch / folder, symlinks=False)
        for option, caption in (("--download-db-only", "Aktualisierung der Schwachstellendaten"),
                                ("--download-java-db-only", "Aktualisierung der Java-Paketdaten")):
            self._run_container([f"{self.scratch}:/root/.cache/trivy"], ["image", option, "--no-progress"], caption)
        hashes = {}
        for folder, database in (("db", "trivy.db"), ("java-db", "trivy-java.db")):
            for name in (database, "metadata.json"):
                path = self.scratch / folder / name
                if not path.is_file() or path.is_symlink():
                    raise ScanError("Die benötigten Prüfdaten wurden nicht vollständig bereitgestellt.")
                h = hashlib.sha256()
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                        h.update(block)
                hashes[f"{folder}/{name}"] = h.hexdigest()
                destination = private_directory(self.cache_dir / folder) / name
                fd, tmp_name = tempfile.mkstemp(prefix=".daten-", dir=destination.parent)
                import os
                os.close(fd)
                try:
                    shutil.copy2(path, tmp_name)
                    Path(tmp_name).replace(destination)
                finally:
                    Path(tmp_name).unlink(missing_ok=True)
        self.context = {"scanner_image_id": self.scanner_id, "database_sha256": hashes,
                        "severities": ["HIGH", "CRITICAL"], "unfixed_included": True}
        atomic_json(self.run_dir / "pruefgrundlage.json", self.context)
        return self.context

    def _scan_args(self) -> list[str]:
        return ["--format", "json", "--scanners", "vuln", "--severity", "HIGH,CRITICAL",
                "--timeout", self.env.get("TRIVY_TIMEOUT", "60m"), "--no-progress",
                "--skip-db-update", "--skip-java-db-update", "--offline-scan",
                "--cache-backend", "memory"]

    def scan_image(self, image_id: str) -> dict:
        if not IMAGE_ID.fullmatch(image_id):
            raise ScanError("Eine ungültige Image-ID sollte geprüft werden.")
        if image_id in self.documents:
            return self.documents[image_id]
        if not self.scanner_id or not self.scratch:
            raise ScanError("Die gemeinsame Prüfgrundlage ist noch nicht bereit.")
        scan_dir = private_directory(self.run_dir / "einzelpruefungen")
        path = scan_dir / f"{image_id.split(':')[1]}.json"
        args = ["image", "--image-src", "docker"] + self._scan_args() + [
            "--output", f"/reports/einzelpruefungen/{path.name}", image_id]
        self._run_container(["/var/run/docker.sock:/var/run/docker.sock",
                             f"{self.scratch}:/root/.cache/trivy:ro", f"{self.run_dir}:/reports"],
                            args, "Image-Sicherheitsprüfung")
        try:
            doc = validate_scan(json.loads(path.read_text(encoding="utf-8")), image_id)
        except (OSError, ValueError) as exc:
            raise ScanError("Die Image-Prüfung hat keine lesbare Ergebnisdatei erzeugt.") from exc
        self.documents[image_id] = doc
        self.paths[image_id] = path
        return doc

    def scan_host(self) -> Path:
        if not self.scanner_id or not self.scratch:
            raise ScanError("Die gemeinsame Prüfgrundlage ist noch nicht bereit.")
        path = self.run_dir / "host_rootfs.json"
        args = ["rootfs"] + self._scan_args() + ["--output", "/reports/host_rootfs.json"]
        distro = self.env.get("TRIVY_HOST_FORCE_DISTRO", "debian/12")
        if distro:
            args += ["--distro", distro]
        pkg_types = self.env.get("TRIVY_PKG_TYPES", "os,library")
        args += ["--pkg-types", pkg_types]
        skips = []
        if enabled(self.env.get("TRIVY_HOST_SKIP_STANDARD_DIRS"), True):
            skips = [f"/host/{item}" for item in ("proc", "sys", "dev", "run", "tmp", "var/run", "var/tmp",
                     "var/lib/docker", "var/lib/containerd", "overlay", "rom", "rootfs", "mnt", "media",
                     "home", "root/.cache", "volume1", "volume2", "volume3", "volume4", "volume5", "volume6")]
        skips += patterns(self.env.get("TRIVY_SKIP_DIRS", ""))
        if skips:
            args += ["--skip-dirs", ",".join(skips)]
        args.append("/host")
        self._run_container([f"{self.scratch}:/root/.cache/trivy:ro", "/:/host:ro", f"{self.run_dir}:/reports"],
                            args, "Sicherheitsprüfung des NAS-Dateisystems")
        try:
            validate_scan(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            raise ScanError("Die NAS-Prüfung hat keine lesbare Ergebnisdatei erzeugt.") from exc
        return path

    def close(self):
        if self.scratch is not None:
            # Only the exact directory allocated by mkdtemp above is removed.
            shutil.rmtree(self.scratch)
            self.scratch = None
