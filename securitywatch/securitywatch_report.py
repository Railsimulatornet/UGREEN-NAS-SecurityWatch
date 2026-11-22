#!/usr/bin/env python3
# Copyright Roman Glos 2026
import argparse
import copy
import html
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from securitywatch_common import load_env
from securitywatch_notifications import build_model, collect_events, image_security_lines, mail_decision, maintenance_lines, number, outcome_lines, render_html, render_text


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


TRANSLATIONS = {
    "de": {
        "report_title": "UGREEN SecurityWatch Bericht",
        "host_filesystem": "NAS-Dateisystem",
        "docker_image_prefix": "Docker-Image: ",
        "unique_total": "Paketfunde über alle geprüften Quellen",
        "raw_total": "Roh-Treffer vor Deduplizierung",
        "duplicates_removed": "Entfernte Dubletten",
        "critical_total": "Kritisch gesamt",
        "high_total": "Hoch gesamt",
        "unique": "Paketfunde",
        "critical": "Kritisch",
        "high": "Hoch",
        "host_section": "NAS-Dateisystem",
        "docker_section": "Docker-Images",
        "docker_baselines": "Wichtigste Docker-Basisthemen",
        "images_affected": "Images betroffen",
        "top_host_findings": "Wichtigste Funde im NAS-Dateisystem",
        "top_docker_findings": "Wichtigste einzelne Image-Befunde",
        "sources_with_findings": "Quellen mit Treffern",
        "source": "Quelle",
        "sources_preview": "Quellen (Auszug)",
        "raw": "Roh",
        "cve": "CVE",
        "cvss": "CVSS",
        "severity": "Schweregrad",
        "package": "Paket",
        "packages": "Pakete",
        "affected_packages": "Betroffene Pakete",
        "installed": "Installiert",
        "installed_preview": "Installiert (Auszug)",
        "fix": "Korrigierte Version",
        "fix_preview": "Korrigierte Version (Auszug)",
        "occurrences": "Vorkommen",
        "targets_preview": "Ziele (Auszug)",
        "priority": "Priorität",
        "context_hint": "Kontext",
        "priority_p1": "P1: Kritisch, Korrektur verfügbar",
        "priority_p2": "P2: Hoch, Korrektur verfügbar",
        "priority_p3": "P3: Kritisch, Herstellerkorrektur prüfen",
        "priority_p4": "P4: Hoch, Herstellerkorrektur prüfen",
        "context_network_noauth": "CVSS: Netzwerk, keine Rechte, keine Nutzeraktion",
        "context_network": "CVSS: Netzwerkvektor",
        "context_local": "CVSS: lokaler Vektor",
        "context_user_interaction": "CVSS: Nutzerinteraktion erforderlich",
        "context_unknown": "Kontext nicht automatisch bestimmbar",
        "affected_images": "Betroffene Images",
        "no_findings": "Keine Treffer.",
        "no_docker_findings": "Keine Docker-Treffer.",
        "docker_scan_disabled": "Die Image-Prüfung war für diesen Lauf deaktiviert.",
        "scan_disabled": "Prüfung deaktiviert",
        "no_host_findings": "Keine Host-Funde.",
        "no_docker_single_findings": "Keine Docker-Funde.",
        "other_more": "weitere",
        "other_smaller_docker_sources": "Weitere {count} kleinere Docker-Quellen",
        "other_docker_sources_summary": "Weitere {count} Docker-Quellen mit zusammen {unique} Paketfunden",
        "mail_note": "Dieser Detailbericht enthält eine priorisierte Auswahl. Sämtliche erfassten Befunde stehen in summary.json. Paketfunde zählen Quelle, Paket und Versionsstand; sie sind keine Anzahl weltweit unterschiedlicher Schwachstellen.",
        "triage_note": "Priorität und Kontext sind eine automatische Einordnung nach Schweregrad, vorhandener Korrekturversion und CVSS-Bewertung. Sie bestätigen keine praktische Ausnutzbarkeit.",
        "host_inventory_hidden": "Die ausgewählten Paketstände sind in dieser Ansicht ausgeblendet. Sie stehen als host_package_watchlist.tsv im Berichtsordner.",
        "top_docker_heading_txt": "Wichtigste Docker-Basisthemen:",
        "top_host_heading_txt": "Wichtigste Funde im NAS-Dateisystem:",
        "top_docker_single_heading_txt": "Wichtigste einzelne Image-Befunde:",
        "sources_heading_txt": "Quellen mit Treffern:",
        "major_host_sources_html": "Quellen mit Treffern: NAS-Dateisystem",
        "major_docker_sources_html": "Quellen mit Treffern: Docker-Images",
        "count_line": "- {label}: {value}",
        "major_topic_line": "- {cve} - {pkg} - {severity} - {count} Images betroffen",
        "finding_line": "{cve} - CVSS {score} - {severity} - {pkg} - {source}{occ}",
        "source_line": "- {source}: {unique} Paketfunde",
        "source_line_other": "- Weitere {count} Docker-Quellen mit zusammen {unique} Paketfunden",
        "summary_box_total": "Paketfunde",
        "summary_box_critical": "Kritisch",
        "summary_box_high": "Hoch",
        "severity_critical": "Kritisch",
        "severity_high": "Hoch",
        "severity_medium": "Mittel",
        "severity_low": "Niedrig",
        "severity_unknown": "Unbekannt",
        "local_images_heading": "Lokale/selbst gebaute Docker-Images",
        "local_images_intro": "Automatisch erkannte lokale Compose-Build-Images. Die Erkennung ist generisch und kann bei Bedarf über .env-Muster ergänzt oder eingeschränkt werden.",
        "local_images_none": "Keine lokalen/selbst gebauten Docker-Images erkannt.",
        "local_image_fixable": "Behebbare Funde",
        "compose_project": "Compose-Projekt",
        "compose_service": "Compose-Dienst",
        "container": "Container",
        "top_local_image_findings": "Behebbare Paket-Funde in lokalen Images",
        "no_local_image_findings": "Keine behebbaren Paket-Funde in lokalen Images.",
        "local_image_rebuild_heading": "Automatischer Neubau lokaler Images",
        "local_image_rebuild_none": "Kein automatischer Neubau lokaler Images ausgeführt.",
        "local_image_rebuild_result": "Ergebnis",
        "local_image_rebuild_detail": "Details",
        "local_image_rebuild_rebuilt": "Neu gebaut",
        "local_image_rebuild_rebuilt_pending_rescan": "Neu gebaut, erneute Prüfung ausstehend",
        "local_image_rebuild_fixed": "Neu gebaut und behoben",
        "local_image_rebuild_still_vulnerable": "Neu gebaut, Fund weiterhin vorhanden",
        "local_image_rebuild_candidate_not_improved": "Kandidat nicht besser, nicht angewendet",
        "local_image_rebuild_skipped_cooldown": "Wartefrist vor erneutem Versuch",
        "local_image_rebuild_build_failed": "Neubau fehlgeschlagen",
        "local_image_rebuild_up_failed": "Neustart fehlgeschlagen",
        "local_image_rebuild_rolled_back": "Vorherige Version wiederhergestellt",
        "local_image_rebuild_rollback_failed": "Wiederherstellung fehlgeschlagen",
        "local_image_rebuild_skipped": "Übersprungen",
        "local_image_rebuild_compose_unavailable": "Compose nicht verfügbar",
        "image_update_heading": "Prüfung auf neue Image-Versionen",
        "image_update_none": "Keine Prüfung auf neue Image-Versionen ausgeführt.",
        "image_update_status": "Status",
        "image_update_detail": "Details",
        "image_update_up_to_date": "Aktuell",
        "image_update_update_available": "Aktualisierung verfügbar",
        "image_update_pull_failed": "Prüfung fehlgeschlagen",
        "image_update_update_applied": "Aktualisierung übernommen",
        "image_update_recreate_failed": "Anwendung fehlgeschlagen",
        "image_update_verification_failed": "Prüfung fehlgeschlagen",
        "image_update_rolled_back": "Vorherige Version wiederhergestellt",
        "image_update_rollback_failed": "Wiederherstellung fehlgeschlagen",
        "image_update_recreate_skipped": "Nicht angewendet",
        "image_update_local_image": "Lokal gebaut – Aktualisierung aus der eigenen Bauanleitung",
        "image_update_digest_pinned": "Auf einen bestimmten Image-Inhalt festgelegt",
        "image_update_skipped": "Übersprungen",
        "image_update_no_actionable": "Keine offenen oder fehlgeschlagenen Aktualisierungen veröffentlichter Images. Einzelheiten stehen im JSON-Bericht.",
        "host_inventory_heading": "Ausgewählte Paketstände des NAS-Betriebssystems",
        "host_inventory_note": "Diese Übersicht zeigt wichtige Paketstände des NAS-Betriebssystems unabhängig davon, ob Trivy dafür aktuell eine Schwachstelle meldet.",
        "host_inventory_none": "Keine Pakete aus der ausgewählten Liste gefunden.",
        "backport_notes_heading": "Debian-/Backport-Hinweise aus dem Host-Scan",
        "backport_notes_note": "Hinweis: Der Debian-erzwungene Trivy-Scan nutzt die Debian-Sicherheitsdatenbank und berücksichtigt dort gepflegte Fixed-Versionen/Backports. UGREEN-spezifische Backports ohne passende Versionskennung können damit nicht automatisch bestätigt werden.",
        "backport_notes_none": "Keine Debian-OS-Paketfunde mit Backport-Hinweisen vorhanden.",
        "backport_notes_fix_summary": "Kritische CVE-Gruppen zuerst; innerhalb des Schweregrads zuerst mit Trivy-Fix-Version. Mit Fix-Version: {fixed}, ohne Fix-Version: {unfixed}.",
        "architecture": "Architektur",
        "status": "Status",
        "backport_note": "Backport-Hinweis",
        "target": "Ziel",
        "script_version": "Script-Version",
        "footer_generated": "Erstellt mit UGREEN SecurityWatch",
        "copyright": "Copyright Roman Glos 2026",
    },
    "en": {
        "report_title": "UGREEN SecurityWatch Report",
        "host_filesystem": "Host filesystem",
        "docker_image_prefix": "Docker image: ",
        "unique_total": "Unique vulnerabilities total",
        "raw_total": "Raw findings before deduplication",
        "duplicates_removed": "Duplicates removed",
        "critical_total": "Critical total",
        "high_total": "High total",
        "unique": "Unique",
        "critical": "Critical",
        "high": "High",
        "host_section": "Host filesystem",
        "docker_section": "Docker images",
        "docker_baselines": "Top Docker base topics",
        "images_affected": "images affected",
        "top_host_findings": "Top host findings",
        "top_docker_findings": "Top Docker single findings",
        "sources_with_findings": "Sources with findings",
        "source": "Source",
        "sources_preview": "Sources (preview)",
        "raw": "Raw",
        "cve": "CVE",
        "cvss": "CVSS",
        "severity": "Severity",
        "package": "Package",
        "packages": "Packages",
        "affected_packages": "Affected packages",
        "installed": "Installed",
        "installed_preview": "Installed (preview)",
        "fix": "Fix",
        "fix_preview": "Fix (preview)",
        "occurrences": "Occurrences",
        "targets_preview": "Targets (preview)",
        "priority": "Priority",
        "context_hint": "Context",
        "priority_p1": "P1: Critical + fix available",
        "priority_p2": "P2: High + fix available",
        "priority_p3": "P3: Critical, vendor/backport review",
        "priority_p4": "P4: High, vendor/backport review",
        "context_network_noauth": "CVSS: network, no privileges, no user interaction",
        "context_network": "CVSS: network vector",
        "context_local": "CVSS: local vector",
        "context_user_interaction": "CVSS: user interaction required",
        "context_unknown": "Context cannot be determined automatically",
        "affected_images": "Affected images",
        "no_findings": "No findings.",
        "no_docker_findings": "No Docker findings.",
        "docker_scan_disabled": "Docker image scan was disabled for this run.",
        "scan_disabled": "Scan disabled",
        "no_host_findings": "No host findings.",
        "no_docker_single_findings": "No Docker findings.",
        "other_more": "more",
        "other_smaller_docker_sources": "{count} additional smaller Docker sources",
        "other_docker_sources_summary": "{count} additional Docker sources with {unique} unique findings combined",
        "mail_note": "Note: This email is intentionally shortened and prioritized. Full details are still available in the JSON report.",
        "triage_note": "Note: Priority and context are automatic triage hints based on severity, fix availability and CVSS metrics. They do not confirm practical exploitability.",
        "host_inventory_hidden": "Package watchlist hidden in the visible report. The complete watchlist remains available as host_package_watchlist.tsv in the report folder.",
        "top_docker_heading_txt": "Top Docker base topics:",
        "top_host_heading_txt": "Top host findings:",
        "top_docker_single_heading_txt": "Top Docker single findings:",
        "sources_heading_txt": "Sources with findings:",
        "major_host_sources_html": "Sources with findings: Host filesystem",
        "major_docker_sources_html": "Sources with findings: Docker images",
        "count_line": "- {label}: {value}",
        "major_topic_line": "- {cve} - {pkg} - {severity} - {count} images affected",
        "finding_line": "{cve} - CVSS {score} - {severity} - {pkg} - {source}{occ}",
        "source_line": "- {source}: {unique} unique vulnerabilities",
        "source_line_other": "- {count} additional Docker sources with {unique} unique findings combined",
        "summary_box_total": "Unique",
        "summary_box_critical": "Critical",
        "summary_box_high": "High",
        "severity_critical": "Critical",
        "severity_high": "High",
        "severity_medium": "Medium",
        "severity_low": "Low",
        "severity_unknown": "Unknown",
        "local_images_heading": "Local / self-built Docker images",
        "local_images_intro": "Automatically detected local Compose build images. Detection is generic and can be extended or restricted with .env patterns if needed.",
        "local_images_none": "No local / self-built Docker images detected.",
        "local_image_fixable": "Fixable findings",
        "compose_project": "Compose project",
        "compose_service": "Compose service",
        "container": "Container",
        "top_local_image_findings": "Fixable package findings in local images",
        "no_local_image_findings": "No fixable package findings in local images.",
        "local_image_rebuild_heading": "Automatic rebuild for local images",
        "local_image_rebuild_none": "No automatic rebuild for local images was performed.",
        "local_image_rebuild_result": "Result",
        "local_image_rebuild_detail": "Details",
        "local_image_rebuild_rebuilt": "Rebuilt",
        "local_image_rebuild_rebuilt_pending_rescan": "Rebuilt, verification pending",
        "local_image_rebuild_fixed": "Rebuilt and fixed",
        "local_image_rebuild_still_vulnerable": "Rebuilt, finding still present",
        "local_image_rebuild_candidate_not_improved": "Candidate not improved, not applied",
        "local_image_rebuild_skipped_cooldown": "Skipped (cooldown)",
        "local_image_rebuild_build_failed": "Build failed",
        "local_image_rebuild_up_failed": "Restart failed",
        "local_image_rebuild_rolled_back": "Rolled back",
        "local_image_rebuild_rollback_failed": "Rollback failed",
        "local_image_rebuild_skipped": "Skipped",
        "local_image_rebuild_compose_unavailable": "Compose unavailable",
        "image_update_heading": "Container image update check",
        "image_update_none": "No container image update check was performed.",
        "image_update_status": "Status",
        "image_update_detail": "Details",
        "image_update_up_to_date": "Up to date",
        "image_update_update_available": "Update available",
        "image_update_pull_failed": "Check failed",
        "image_update_update_applied": "Update applied",
        "image_update_recreate_failed": "Apply failed",
        "image_update_verification_failed": "Verification failed",
        "image_update_rolled_back": "Rolled back",
        "image_update_rollback_failed": "Rollback failed",
        "image_update_recreate_skipped": "Not applied",
        "image_update_local_image": "Locally built – no registry update intended",
        "image_update_digest_pinned": "Pinned by digest",
        "image_update_skipped": "Skipped",
        "image_update_no_actionable": "No pending or failed registry image updates. Full details remain available in the JSON report.",
        "host_inventory_heading": "UGOS/Debian package watchlist",
        "host_inventory_note": "Note: This watchlist shows important host package versions even if Trivy currently does not report a vulnerability for them.",
        "host_inventory_none": "No watchlist packages found.",
        "backport_notes_heading": "Debian/backport notes from the host scan",
        "backport_notes_note": "Note: The Debian-forced Trivy scan uses the Debian security database and its fixed package versions/backports. UGREEN-specific backports without a matching package version cannot be confirmed automatically.",
        "backport_notes_none": "No Debian OS package findings with backport notes found.",
        "backport_notes_fix_summary": "Critical CVE groups first; within each severity, groups with a Trivy fixed version first. With fixed version: {fixed}, without fixed version: {unfixed}.",
        "architecture": "Architecture",
        "status": "Status",
        "backport_note": "Backport note",
        "target": "Target",
        "script_version": "Script version",
        "footer_generated": "Generated by UGREEN SecurityWatch",
        "copyright": "Copyright Roman Glos 2026",
    },
}


def parse_env(path: Path) -> dict:
    return load_env(path)


def env_bool(env: Dict[str, str], key: str, default: bool = False) -> bool:
    raw = str(env.get(key, "")).strip().lower()
    if raw == "":
        return default
    return raw in {"1", "true", "yes", "on", "y"}


def option_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    raw = str(value).strip().lower()
    if raw == "":
        return default
    return raw in {"1", "true", "yes", "on", "y"}


def env_int(env: Dict[str, str], key: str, default: int, minimum: int = 0, maximum: int = 500) -> int:
    raw = str(env.get(key, "")).strip()
    if raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < minimum:
        return minimum
    if value > maximum:
        return maximum
    return value


def normalize_lang(value: Optional[str]) -> str:
    lang = (value or "de").strip().lower()
    return lang if lang in {"de", "en"} else "de"


def tr(lang: str, key: str, **kwargs: Any) -> str:
    text = TRANSLATIONS[lang].get(key, key)
    return text.format(**kwargs)


def display_severity(severity: str, lang: str) -> str:
    mapping = {
        "CRITICAL": "severity_critical",
        "HIGH": "severity_high",
        "MEDIUM": "severity_medium",
        "LOW": "severity_low",
        "UNKNOWN": "severity_unknown",
    }
    return tr(lang, mapping.get(severity, "severity_unknown"))


def display_backport_note(note: str, lang: str) -> str:
    value = (note or "").strip()
    if lang == "de":
        mapping = {
            "Debian fixed/backported package version is listed by Trivy": "Debian-Fix-/Backport-Version wird von Trivy gelistet",
            "No fixed package version listed by Trivy for this Debian advisory state": "Keine feste Paketversion von Trivy für diesen Debian-Advisory-Stand gelistet",
            "Language/library finding; fixed version shown by upstream metadata": "Sprach-/Bibliotheksfund; Fix-Version stammt aus Upstream-Metadaten",
        }
        return mapping.get(value, value or "-")
    return value or "-"


def display_source(source_label: str, lang: str) -> str:
    if source_label == "Host-Dateisystem":
        return tr(lang, "host_filesystem")
    if source_label.startswith("Docker-Image: "):
        return tr(lang, "docker_image_prefix") + source_label[len("Docker-Image: "):]
    return source_label


def load_json(path: Path) -> Optional[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, UnicodeError, ValueError):
        return None


def valid_scan_document(doc: Optional[dict]) -> bool:
    """Ein Parserfehler darf niemals als leeres Prüfergebnis gelten."""
    if not isinstance(doc, dict) or type(doc.get("SchemaVersion")) is not int:
        return False
    if doc["SchemaVersion"] < 1:
        return False
    results = doc.get("Results")
    if results is None:
        return bool(doc.get("ArtifactName") or doc.get("ArtifactType"))
    if not isinstance(results, list):
        return False
    for result in results:
        if not isinstance(result, dict):
            return False
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            return False
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("VulnerabilityID"), str) or not isinstance(vuln.get("PkgName"), str):
                return False
    return True


def load_run_status(run_dir: Path) -> Dict[str, Any]:
    doc = load_json(run_dir / "run-status.json")
    if not doc or doc.get("version") != 1:
        return {}
    return copy.deepcopy(doc)


def validated_scan_paths(run_dir: Path, status: Dict[str, Any]) -> Tuple[List[Path], List[Dict[str, str]]]:
    """Liest nur die im Abschlusszustand erwarteten Ergebnisse dieses Laufs.

    Ältere Läufe ohne Manifest bleiben auswertbar, werden in der Mail aber
    ausdrücklich ohne bestätigte Vollständigkeit dargestellt.
    """
    root = run_dir.resolve()
    errors: List[Dict[str, str]] = []
    expected: List[Tuple[str, str, Optional[dict]]] = []
    scans = status.get("scans") if isinstance(status.get("scans"), dict) else {}
    host = scans.get("host") if isinstance(scans.get("host"), dict) else {}
    images = scans.get("images") if isinstance(scans.get("images"), dict) else {}

    if status:
        if host.get("status") == "ok":
            expected.append(("host", str(host.get("file") or "host_rootfs.json"), host))
        items = images.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("status") == "ok":
                    expected.append(("image", str(item.get("file") or ""), item))
        elif images.get("status") == "ok" and number(images.get("expected")) > 0:
            # Ein unvollständiges neues Manifest darf nicht still auf alte
            # Zufallsdateien im Laufordner zurückfallen.
            errors.append({"source": "image", "file": "", "reason": "Die Liste der erwarteten Image-Ergebnisse fehlt."})
            images["status"] = "failed"
    else:
        mapping = load_image_name_map(run_dir)
        for host_name in ("host_rootfs.json", "host_fs.json"):
            if (run_dir / host_name).exists():
                expected.append(("host", host_name, None))
                break
        if mapping:
            expected.extend(("image", "image_" + name + ".json", None) for name in sorted(mapping))
        else:
            expected.extend(("image", p.name, None) for p in sorted(run_dir.glob("image_*.json")))

    paths: List[Path] = []
    seen: set[Path] = set()
    for source, filename, item in expected:
        path = run_dir / filename
        reason = ""
        try:
            resolved = path.resolve()
            if not filename or Path(filename).is_absolute() or root not in resolved.parents:
                reason = "Der Pfad des Prüfergebnisses ist ungültig."
            elif resolved in seen:
                reason = "Eine Ergebnisdatei wurde mehreren Prüfungen zugeordnet."
            elif not path.is_file() or path.is_symlink():
                reason = "Die erwartete Ergebnisdatei fehlt."
            elif not valid_scan_document(load_json(path)):
                reason = "Die Ergebnisdatei ist nicht als Sicherheitsprüfung auswertbar."
        except (OSError, ValueError, RuntimeError):
            reason = "Die Ergebnisdatei konnte nicht gelesen werden."
        if reason:
            errors.append({"source": source, "file": filename[:200], "reason": reason})
            if item is not None:
                item["status"] = "failed"
                item["error"] = reason
            if source == "host":
                host["status"] = "failed"
            elif status:
                images["status"] = "failed"
            continue
        seen.add(resolved)
        paths.append(path)

    if errors and status:
        run = status.get("run")
        if isinstance(run, dict) and run.get("status") == "completed":
            run["status"] = "partial"
        items = images.get("items")
        if isinstance(items, list):
            images["succeeded"] = sum(isinstance(i, dict) and i.get("status") == "ok" for i in items)
            images["failed"] = sum(isinstance(i, dict) and i.get("status") != "ok" for i in items)
    return paths, errors


def extract_score(vuln: Dict[str, Any]) -> Optional[float]:
    best: Optional[float] = None
    cvss = vuln.get("CVSS") or {}
    if isinstance(cvss, dict):
        for _, value in cvss.items():
            if not isinstance(value, dict):
                continue
            for key in ("V3Score", "V2Score"):
                raw = value.get(key)
                if isinstance(raw, (int, float)):
                    best = max(best, float(raw)) if best is not None else float(raw)

    for key in ("CVSSScore", "Score"):
        raw = vuln.get(key)
        if isinstance(raw, (int, float)):
            best = max(best, float(raw)) if best is not None else float(raw)

    return best


def score_to_text(score: Optional[float]) -> str:
    if score is None:
        return "-"
    return f"{score:.1f}"


def has_fixed_version(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and text not in {"-", "none", "None", "null"})


def extract_cvss_vector(vuln: Dict[str, Any]) -> str:
    cvss = vuln.get("CVSS") or {}
    if not isinstance(cvss, dict):
        return ""

    candidates: List[str] = []
    for value in cvss.values():
        if not isinstance(value, dict):
            continue
        for key in ("V4Vector", "V3Vector", "V2Vector"):
            raw = value.get(key)
            if isinstance(raw, str) and raw.strip():
                candidates.append(raw.strip())

    # Prefer CVSS v3/v4 vectors over legacy vectors where available.
    for prefix in ("CVSS:4", "CVSS:3", "CVSS:2"):
        for vector in candidates:
            if vector.startswith(prefix):
                return vector
    return candidates[0] if candidates else ""


def parse_cvss_metrics(vector: str) -> Dict[str, str]:
    metrics: Dict[str, str] = {}
    if not vector:
        return metrics
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        if key.startswith("CVSS"):
            continue
        metrics[key] = value
    return metrics


def remediation_priority(item: Dict[str, Any], lang: str) -> str:
    fixed = has_fixed_version(item.get("fixed"))
    sev = (item.get("severity") or "").upper()
    if fixed and sev == "CRITICAL":
        return tr(lang, "priority_p1")
    if fixed and sev == "HIGH":
        return tr(lang, "priority_p2")
    if sev == "CRITICAL":
        return tr(lang, "priority_p3")
    return tr(lang, "priority_p4")


def exposure_context(item: Dict[str, Any], lang: str) -> str:
    metrics = item.get("cvss_metrics") or {}
    av = metrics.get("AV")
    pr = metrics.get("PR")
    ui = metrics.get("UI")

    if av == "N" and pr == "N" and ui == "N":
        return tr(lang, "context_network_noauth")
    if av == "N":
        if ui and ui != "N":
            return tr(lang, "context_user_interaction")
        return tr(lang, "context_network")
    if av == "L":
        return tr(lang, "context_local")
    if ui and ui != "N":
        return tr(lang, "context_user_interaction")
    return tr(lang, "context_unknown")


def finding_sort_key(item: Dict[str, Any]) -> tuple:
    """Severity first, then a known fixed version, then CVSS. Stable tie-breaks."""
    score = item.get("score")
    score_value = float(score) if isinstance(score, (int, float)) else -1.0
    return (
        SEVERITY_ORDER.get(item.get("severity", "UNKNOWN"), 9),
        0 if has_fixed_version(item.get("fixed")) else 1,
        -score_value,
        str(item.get("cve", "")),
        str(item.get("pkg", "")),
        str(item.get("source", "")),
        str(item.get("installed", "")),
    )

def sanitize_image_ref(image_ref: str) -> str:
    return re.sub(r"[/:@]", "_", image_ref)


def load_image_name_map(run_dir: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}

    map_file = run_dir / "images_map.tsv"
    if map_file.exists():
        for raw_line in map_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or "	" not in line:
                continue
            safe_name, image_ref = line.split("	", 1)
            safe_name = safe_name.strip()
            image_ref = image_ref.strip()
            if safe_name and image_ref:
                mapping[safe_name] = image_ref
        if mapping:
            return mapping

    images_file = run_dir / "images_scanned.txt"
    if images_file.exists():
        buckets: Dict[str, List[str]] = {}
        for raw_line in images_file.read_text(encoding="utf-8").splitlines():
            image_ref = raw_line.strip()
            if not image_ref:
                continue
            buckets.setdefault(sanitize_image_ref(image_ref), []).append(image_ref)

        for safe_name, refs in buckets.items():
            if len(refs) == 1:
                mapping[safe_name] = refs[0]

    return mapping


def normalize_source_label(path: Path, image_name_map: Dict[str, str]) -> str:
    if path.name in ("host_fs.json", "host_rootfs.json"):
        return "Host-Dateisystem"

    safe_name = path.stem.replace("image_", "", 1)
    image_ref = image_name_map.get(safe_name, safe_name)
    return f"Docker-Image: {image_ref}"


def source_group(source_label: str) -> str:
    return "host" if source_label == "Host-Dateisystem" else "docker"


def normalize_display_target(target: str) -> str:
    if not target:
        return ""

    prefixes = [
        "overlay/upper/",
        "rootfs/base/",
        "rom/",
    ]

    out = target
    for prefix in prefixes:
        if out.startswith(prefix):
            out = out[len(prefix):]
            break

    if out.startswith("ugreen/@appstore/"):
        out = out[len("ugreen/@appstore/"):]

    return out


def target_to_short_text(target: str, source_label: str) -> str:
    if not target or target == source_label:
        return source_label
    return normalize_display_target(str(target))


def dedupe_key(source_label: str, vuln: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    return (
        source_label,
        str(vuln.get("VulnerabilityID", "-")),
        str(vuln.get("PkgName", "-")),
        str(vuln.get("InstalledVersion", "-")),
        str(vuln.get("FixedVersion") or "-"),
    )


def current_scan_json_paths(run_dir: Path, image_name_map: Dict[str, str]) -> List[Path]:
    paths: List[Path] = []

    for host_name in ("host_rootfs.json", "host_fs.json"):
        host_path = run_dir / host_name
        if host_path.exists():
            paths.append(host_path)
            break

    if image_name_map:
        for safe_name in sorted(image_name_map):
            image_path = run_dir / f"image_{safe_name}.json"
            if image_path.exists():
                paths.append(image_path)
    else:
        paths.extend(sorted(run_dir.glob("image_*.json")))

    return paths


def collect_findings(run_dir: Path, scan_paths: Optional[List[Path]] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    deduped: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}
    sources: List[Dict[str, Any]] = []
    raw_total = 0
    image_name_map = load_image_name_map(run_dir)

    for path in (scan_paths if scan_paths is not None else current_scan_json_paths(run_dir, image_name_map)):

        doc = load_json(path)
        if not valid_scan_document(doc):
            continue

        source_label = normalize_source_label(path, image_name_map)
        group = source_group(source_label)
        raw_count = 0

        for result in doc.get("Results") or []:
            target = target_to_short_text(result.get("Target") or source_label, source_label)
            vulns = result.get("Vulnerabilities") or []

            for vuln in vulns:
                raw_total += 1
                raw_count += 1
                score = extract_score(vuln)
                # A display tag can refer to two different running image IDs.
                # The validated result file, not that mutable name, owns counts.
                key = dedupe_key(path.name, vuln)

                if key not in deduped:
                    deduped[key] = {
                        "group": group,
                        "source": source_label,
                        "source_file": path.name,
                        "target": target,
                        "targets": [target] if target else [],
                        "occurrences": 1,
                        "cve": vuln.get("VulnerabilityID", "-"),
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "score": score,
                        "score_text": score_to_text(score),
                        "pkg": vuln.get("PkgName", "-"),
                        "installed": vuln.get("InstalledVersion", "-"),
                        "fixed": vuln.get("FixedVersion") or "-",
                        "title": vuln.get("Title") or "",
                        "primary_url": vuln.get("PrimaryURL") or "",
                        "trivy_status": vuln.get("Status") or "",
                        "cvss_vector": extract_cvss_vector(vuln),
                        "cvss_metrics": parse_cvss_metrics(extract_cvss_vector(vuln)),
                        "result_type": result.get("Type") or "",
                    }
                else:
                    entry = deduped[key]
                    entry["occurrences"] += 1
                    incoming_severity = vuln.get("Severity", "UNKNOWN")
                    if SEVERITY_ORDER.get(incoming_severity, 9) < SEVERITY_ORDER.get(entry.get("severity"), 9):
                        entry["severity"] = incoming_severity

                    if target and target not in entry["targets"]:
                        entry["targets"].append(target)

                    existing_score = entry.get("score")
                    if score is not None and (existing_score is None or score > existing_score):
                        entry["score"] = score
                        entry["score_text"] = score_to_text(score)

                    if not entry.get("title") and vuln.get("Title"):
                        entry["title"] = vuln.get("Title")

                    if not entry.get("primary_url") and vuln.get("PrimaryURL"):
                        entry["primary_url"] = vuln.get("PrimaryURL")

        unique_count = sum(1 for item in deduped.values() if item["source_file"] == path.name)
        sources.append(
            {
                "group": group,
                "source": source_label,
                "file": path.name,
                "raw_findings": raw_count,
                "unique_findings": unique_count,
                "duplicates_removed": max(raw_count - unique_count, 0),
            }
        )

    findings = list(deduped.values())
    findings.sort(key=finding_sort_key)

    sources.sort(
        key=lambda src: (
            0 if src["group"] == "host" else 1,
            -src["unique_findings"],
            src["source"],
        )
    )

    return findings, sources, raw_total


def summarize_group(findings: List[Dict[str, Any]], group: str) -> Dict[str, int]:
    selected = [f for f in findings if f["group"] == group]
    return {
        "total": len(selected),
        "critical": sum(1 for f in selected if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in selected if f["severity"] == "HIGH"),
    }


def aggregate_findings(findings: List[Dict[str, Any]], group: str) -> List[Dict[str, Any]]:
    aggregated: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for item in findings:
        if item["group"] != group:
            continue

        key = (
            item["cve"],
            item["pkg"],
            item["severity"],
        )

        if key not in aggregated:
            aggregated[key] = {
                "group": group,
                "cve": item["cve"],
                "pkg": item["pkg"],
                "severity": item["severity"],
                "score": item["score"],
                "score_text": item["score_text"],
                "primary_url": item["primary_url"],
                "sources": [item["source"]],
                "installed_versions": [item["installed"]] if item["installed"] != "-" else [],
                "fixed_versions": [item["fixed"]] if item["fixed"] != "-" else [],
                "source_count": 1,
                "occurrences": item.get("occurrences", 1),
            }
        else:
            entry = aggregated[key]
            entry["occurrences"] += item.get("occurrences", 1)

            if item["source"] not in entry["sources"]:
                entry["sources"].append(item["source"])
                entry["source_count"] = len(entry["sources"])

            if item["installed"] != "-" and item["installed"] not in entry["installed_versions"]:
                entry["installed_versions"].append(item["installed"])

            if item["fixed"] != "-" and item["fixed"] not in entry["fixed_versions"]:
                entry["fixed_versions"].append(item["fixed"])

            existing_score = entry.get("score")
            item_score = item.get("score")
            if item_score is not None and (existing_score is None or item_score > existing_score):
                entry["score"] = item_score
                entry["score_text"] = item["score_text"]

            if not entry.get("primary_url") and item.get("primary_url"):
                entry["primary_url"] = item["primary_url"]

    rows = list(aggregated.values())
    rows.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 5),
            0 if item.get("fixed_versions") else 1,
            -(item["score"] if item["score"] is not None else -1),
            item["cve"],
            item["pkg"],
            -item["source_count"],
            -item["occurrences"],
        )
    )
    return rows



def cve_link_url(cve: str, primary_url: str = "") -> str:
    url = (primary_url or "").strip()
    if url.startswith("http://") or url.startswith("https://"):
        return url
    cve = (cve or "").strip()
    if cve.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{cve}"
    return ""


def cve_link_html(cve: str, primary_url: str = "") -> str:
    cve_text = html.escape(cve or "-")
    url = cve_link_url(cve or "", primary_url)
    return f'<a href="{html.escape(url)}">{cve_text}</a>' if url else cve_text


def unique_sorted(values: List[str]) -> List[str]:
    cleaned = []
    seen = set()
    for value in values:
        v = str(value or "").strip()
        if not v or v == "-" or v in seen:
            continue
        seen.add(v)
        cleaned.append(v)
    return sorted(cleaned, key=lambda x: x.lower())


def preview_values(values: List[str], lang: str, limit: int = 4) -> str:
    vals = unique_sorted(values)
    if not vals:
        return "-"
    text = ", ".join(vals[:limit])
    if len(vals) > limit:
        text += f" (+{len(vals) - limit} {tr(lang, 'other_more')})"
    return text


def grouped_findings_by_cve(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for item in findings:
        cve = str(item.get("cve") or "-")
        entry = grouped.setdefault(
            cve,
            {
                "cve": cve,
                "severity": item.get("severity") or "UNKNOWN",
                "score": item.get("score"),
                "score_text": item.get("score_text") or "-",
                "packages": [],
                "installed_versions": [],
                "fixed_versions": [],
                "sources": [],
                "targets": [],
                "occurrences": 0,
                "primary_url": item.get("primary_url") or "",
                "cvss_metrics": item.get("cvss_metrics") or {},
                "cvss_vector": item.get("cvss_vector") or "",
            },
        )

        old_sev = SEVERITY_ORDER.get(entry.get("severity", "UNKNOWN"), 9)
        new_sev = SEVERITY_ORDER.get(item.get("severity", "UNKNOWN"), 9)
        if new_sev < old_sev:
            entry["severity"] = item.get("severity") or "UNKNOWN"

        score = item.get("score")
        if score is not None and (entry.get("score") is None or score > entry.get("score")):
            entry["score"] = score
            entry["score_text"] = item.get("score_text") or str(score)
            entry["cvss_metrics"] = item.get("cvss_metrics") or entry.get("cvss_metrics") or {}
            entry["cvss_vector"] = item.get("cvss_vector") or entry.get("cvss_vector") or ""

        if not entry.get("primary_url") and item.get("primary_url"):
            entry["primary_url"] = item.get("primary_url")

        entry["packages"].append(item.get("pkg") or "-")
        entry["installed_versions"].append(item.get("installed") or "-")
        entry["fixed_versions"].append(item.get("fixed") or "-")
        entry["sources"].append(item.get("source") or "-")
        entry["targets"].extend(item.get("targets") or [])
        entry["occurrences"] += int(item.get("occurrences") or 1)

    rows = []
    for entry in grouped.values():
        entry["packages"] = unique_sorted(entry["packages"])
        entry["installed_versions"] = unique_sorted(entry["installed_versions"])
        entry["fixed_versions"] = unique_sorted(entry["fixed_versions"])
        entry["sources"] = unique_sorted(entry["sources"])
        entry["targets"] = unique_sorted(entry["targets"])
        entry["package_count"] = len(entry["packages"])
        entry["fixed"] = ", ".join(entry["fixed_versions"]) if entry["fixed_versions"] else "-"
        entry["pkg"] = preview_values(entry["packages"], "de", 4)
        entry["installed"] = preview_values(entry["installed_versions"], "de", 3)
        rows.append(entry)

    rows.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity", "UNKNOWN"), 9),
            0 if item.get("fixed_versions") else 1,
            -(item.get("score") if item.get("score") is not None else -1),
            item.get("cve", ""),
            -item.get("package_count", 0),
            -item.get("occurrences", 0),
        )
    )
    return rows


def build_grouped_top_lines(findings: List[Dict[str, Any]], lang: str, limit: int = 15) -> List[str]:
    lines: List[str] = []
    for item in grouped_findings_by_cve(findings)[:limit]:
        fixed = preview_values(item.get("fixed_versions", []), lang, limit=3)
        pkgs = preview_values(item.get("packages", []), lang, limit=4)
        url = cve_link_url(item.get("cve", ""), item.get("primary_url", ""))
        url_suffix = f" - URL: {url}" if url else ""
        lines.append(
            f"- {item['cve']} - CVSS {item['score_text']} - {display_severity(item['severity'], lang)} - "
            f"{tr(lang, 'affected_packages')}: {item.get('package_count', 0)} ({pkgs}) - "
            f"{tr(lang, 'fix')}: {fixed} - {remediation_priority(item, lang)}{url_suffix}"
        )
    return lines

def build_top_lines(findings: List[Dict[str, Any]], lang: str, limit: int = 15) -> List[str]:
    lines: List[str] = []
    for item in findings[:limit]:
        occ = f" ({item['occurrences']}x)" if item.get("occurrences", 1) > 1 else ""
        fixed = item.get("fixed") or "-"
        lines.append(
            tr(
                lang,
                "finding_line",
                cve=item["cve"],
                score=item["score_text"],
                severity=display_severity(item["severity"], lang),
                pkg=item["pkg"],
                source=display_source(item["source"], lang),
                occ=occ,
            ) + f" - {tr(lang, 'fix')}: {fixed} - {remediation_priority(item, lang)}"
        )
    return lines


def severity_badge(severity: str, lang: str) -> str:
    colors = {
        "CRITICAL": "#b91c1c",
        "HIGH": "#c2410c",
        "MEDIUM": "#a16207",
        "LOW": "#1d4ed8",
        "UNKNOWN": "#4b5563",
    }
    color = colors.get(severity, "#4b5563")
    return (
        f"<span style='display:inline-block;padding:2px 8px;border-radius:999px;"
        f"background:{color};color:#fff;font-weight:600;font-size:12px;'>{html.escape(display_severity(severity, lang))}</span>"
    )


def summarize_sources_for_mail(sources: List[Dict[str, Any]], group: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    selected = [s for s in sources if s["group"] == group and s["unique_findings"] > 0]

    if group == "docker":
        major = [s for s in selected if s["unique_findings"] >= 3]
        minor = [s for s in selected if s["unique_findings"] < 3]
        minor_summary = {
            "count": len(minor),
            "unique_findings": sum(s["unique_findings"] for s in minor),
            "raw_findings": sum(s["raw_findings"] for s in minor),
            "duplicates_removed": sum(s["duplicates_removed"] for s in minor),
        }
        return major, minor_summary

    return selected, {"count": 0, "unique_findings": 0, "raw_findings": 0, "duplicates_removed": 0}


def localized_target(value: str, internal_source: str, lang: str) -> str:
    return display_source(internal_source, lang) if value == internal_source else value


def localize_finding(item: Dict[str, Any], lang: str) -> Dict[str, Any]:
    out = dict(item)
    out["source_internal"] = item["source"]
    out["source"] = display_source(item["source"], lang)
    out["severity_display"] = display_severity(item["severity"], lang)
    out["priority"] = remediation_priority(item, lang)
    out["context_hint"] = exposure_context(item, lang)
    if "target" in out:
        out["target"] = localized_target(str(out["target"]), item["source"], lang)
    out["targets"] = [localized_target(str(target), item["source"], lang) for target in item.get("targets", [])]
    return out


def localize_source(item: Dict[str, Any], lang: str) -> Dict[str, Any]:
    out = dict(item)
    out["source_internal"] = item["source"]
    out["source"] = display_source(item["source"], lang)
    return out


def localize_aggregate(item: Dict[str, Any], lang: str) -> Dict[str, Any]:
    out = dict(item)
    out["severity_display"] = display_severity(item["severity"], lang)
    out["sources_internal"] = list(item["sources"])
    out["sources"] = [display_source(source, lang) for source in item["sources"]]
    return out



def load_local_built_images(run_dir: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    tsv = run_dir / "local-built-images.tsv"
    if not tsv.exists():
        return rows

    seen = set()
    for raw_line in tsv.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if parts and parts[0].strip().lower() == "image":
            continue

        image = parts[0].strip() if len(parts) > 0 else ""
        container = parts[1].strip() if len(parts) > 1 else ""
        project = parts[2].strip() if len(parts) > 2 else ""
        service = parts[3].strip() if len(parts) > 3 else ""

        if not image or image in seen:
            continue

        seen.add(image)
        rows.append(
            {
                "image": image,
                "container": container,
                "project": project,
                "service": service,
            }
        )

    rows.sort(key=lambda item: item["image"])
    return rows


def load_local_image_rebuild_results(run_dir: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    tsv = run_dir / "local-image-rebuild-results.tsv"
    if not tsv.exists():
        return rows

    for raw_line in tsv.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("	")
        if parts and parts[0].strip().lower() == "image":
            continue

        rows.append(
            {
                "image": parts[0].strip() if len(parts) > 0 else "",
                "container": parts[1].strip() if len(parts) > 1 else "",
                "project": parts[2].strip() if len(parts) > 2 else "",
                "service": parts[3].strip() if len(parts) > 3 else "",
                "working_dir": parts[4].strip() if len(parts) > 4 else "",
                "result": parts[5].strip() if len(parts) > 5 else "",
                "fixable": parts[6].strip() if len(parts) > 6 else "",
                "detail": parts[7].strip() if len(parts) > 7 else "",
            }
        )

    return rows


def display_local_image_rebuild_result(value: str, lang: str) -> str:
    mapping = {
        "rebuilt": "local_image_rebuild_rebuilt",
        "rebuilt_pending_rescan": "local_image_rebuild_rebuilt_pending_rescan",
        "fixed": "local_image_rebuild_fixed",
        "still_vulnerable": "local_image_rebuild_still_vulnerable",
        "candidate_not_improved": "local_image_rebuild_candidate_not_improved",
        "skipped_cooldown": "local_image_rebuild_skipped_cooldown",
        "build_failed": "local_image_rebuild_build_failed",
        "up_failed": "local_image_rebuild_up_failed",
        "rolled_back": "local_image_rebuild_rolled_back",
        "rollback_failed": "local_image_rebuild_rollback_failed",
        "skipped": "local_image_rebuild_skipped",
        "compose_unavailable": "local_image_rebuild_compose_unavailable",
    }
    return tr(lang, mapping.get(value, "local_image_rebuild_result")) if value else "-"


def display_operation_detail(detail: str, lang: str) -> str:
    translations = {
        "remote digest check failed; no image was pulled":
            "Registry-Abfrage fehlgeschlagen. Es wurde kein Image heruntergeladen.",
        "local build; registry update not applicable":
            "Lokal gebaut – Registry-Update nicht vorgesehen.",
        "image origin could not be determined; registry update not attempted":
            "Image-Herkunft nicht bestimmbar. Registry-Update wurde nicht gestartet.",
        "shared image also belongs to a local or unclassified service; no update applied":
            "Dasselbe Image gehört auch zu einem lokalen oder nicht zugeordneten Dienst. Kein Update installiert.",
    }
    if lang != "de":
        return detail
    if detail in translations:
        return translations[detail]
    match = re.fullmatch(r"candidate not deployed: fixable High/Critical (\d+) -> (\d+); no safely attributable direct Python package remediation available", detail)
    if match:
        before, after = match.groups()
        return (f"Nicht übernommen: Behebbare kritische/hohe Funde {before} → {after}. "
                "Keine sicher zuordenbare direkte Python-Paketkorrektur verfügbar.")
    return detail


def build_local_image_rebuild_text(run_dir: Path, lang: str) -> List[str]:
    rows = load_local_image_rebuild_results(run_dir)
    lines: List[str] = []
    lines.append(tr(lang, "local_image_rebuild_heading") + ":")
    if not rows:
        lines.append(tr(lang, "local_image_rebuild_none"))
        lines.append("")
        return lines

    for row in rows:
        details = []
        if row.get("project"):
            details.append(f"{tr(lang, 'compose_project')}: {row['project']}")
        if row.get("service"):
            details.append(f"{tr(lang, 'compose_service')}: {row['service']}")
        if row.get("fixable"):
            details.append(f"{tr(lang, 'local_image_fixable')}: {row['fixable']}")
        detail_text = f" ({', '.join(details)})" if details else ""
        suffix = f" - {display_operation_detail(row['detail'], lang)}" if row.get("detail") else ""
        lines.append(f"- {row.get('image') or '-'}: {display_local_image_rebuild_result(row.get('result', ''), lang)}{detail_text}{suffix}")

    lines.append("")
    return lines


def build_local_image_rebuild_table(run_dir: Path, lang: str) -> str:
    rows = load_local_image_rebuild_results(run_dir)
    if not rows:
        return f"<p>{html.escape(tr(lang, 'local_image_rebuild_none'))}</p>"

    columns = [
        ("image", "source"), ("result", "local_image_rebuild_result"),
        ("fixable", "local_image_fixable"), ("detail", "local_image_rebuild_detail"),
        ("container", "container"), ("project", "compose_project"), ("service", "compose_service"),
    ]
    body = []
    for row in rows:
        cells = []
        for key, _ in columns:
            value = row.get(key) or "-"
            if key == "result":
                value = display_local_image_rebuild_result(row.get(key, ""), lang)
            elif key == "detail":
                value = display_operation_detail(value, lang)
            cells.append(f"<td>{html.escape(value)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    headings = "".join(f"<th>{html.escape(tr(lang, label))}</th>" for _, label in columns)
    return ("<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>"
            + "<tr>" + headings + "</tr>" + "".join(body) + "</table>")

def load_image_update_results(run_dir: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    tsv = run_dir / "image-update-check-results.tsv"
    if not tsv.exists():
        return rows

    for raw_line in tsv.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("	")
        if parts and parts[0].strip().lower() == "image":
            continue

        rows.append(
            {
                "image": parts[0].strip() if len(parts) > 0 else "",
                "container": parts[1].strip() if len(parts) > 1 else "",
                "project": parts[2].strip() if len(parts) > 2 else "",
                "service": parts[3].strip() if len(parts) > 3 else "",
                "status": parts[4].strip() if len(parts) > 4 else "",
                "current_image_id": parts[5].strip() if len(parts) > 5 else "",
                "latest_image_id": parts[6].strip() if len(parts) > 6 else "",
                "detail": parts[7].strip() if len(parts) > 7 else "",
            }
        )

    priority = {
        "rollback_failed": 0,
        "verification_failed": 1,
        "recreate_failed": 2,
        "rolled_back": 3,
        "recreate_skipped": 4,
        "update_available": 5,
        "update_applied": 6,
        "pull_failed": 4,
        "up_to_date": 8,
        "digest_pinned": 9,
        "local_image": 10,
        "skipped": 11,
    }
    rows.sort(key=lambda item: (priority.get(item.get("status", ""), 99), item.get("image", ""), item.get("container", "")))
    return rows


def display_image_update_status(value: str, lang: str) -> str:
    mapping = {
        "up_to_date": "image_update_up_to_date",
        "update_available": "image_update_update_available",
        "update_applied": "image_update_update_applied",
        "recreate_failed": "image_update_recreate_failed",
        "verification_failed": "image_update_verification_failed",
        "rolled_back": "image_update_rolled_back",
        "rollback_failed": "image_update_rollback_failed",
        "recreate_skipped": "image_update_recreate_skipped",
        "pull_failed": "image_update_pull_failed",
        "local_image": "image_update_local_image",
        "digest_pinned": "image_update_digest_pinned",
        "skipped": "image_update_skipped",
    }
    return tr(lang, mapping.get(value, "image_update_status")) if value else "-"


def build_image_update_text(run_dir: Path, lang: str) -> List[str]:
    rows = load_image_update_results(run_dir)
    lines: List[str] = []
    lines.append(tr(lang, "image_update_heading") + ":")
    if not rows:
        lines.append(tr(lang, "image_update_none"))
        lines.append("")
        return lines

    benign = {"up_to_date", "local_image", "digest_pinned", "skipped"}
    visible_rows = [row for row in rows if row.get("status", "") not in benign]
    checked = sum(1 for row in rows if row.get("status") not in {"local_image", "digest_pinned", "skipped"})
    available = sum(1 for row in rows if row.get("status") == "update_available")
    applied = sum(1 for row in rows if row.get("status") == "update_applied")
    problems = sum(1 for row in rows if row.get("status") in {"pull_failed", "recreate_failed", "verification_failed", "rolled_back", "rollback_failed", "recreate_skipped"})
    if lang == "en":
        lines.append(f"Checked registry containers: {checked}; pending updates: {available}; applied: {applied}; warnings/errors: {problems}")
    else:
        lines.append(f"Geprüfte Registry-Container: {checked}; offene Updates: {available}; angewendet: {applied}; Warnungen/Fehler: {problems}")

    local_count = sum(1 for row in rows if row.get("status") == "local_image")
    if local_count:
        lines.append(f"Lokal gebaute Container ohne Registry-Abfrage: {local_count}." if lang == "de"
                     else f"Locally built containers without registry requests: {local_count}.")

    if not visible_rows:
        lines.append(tr(lang, "image_update_no_actionable"))
        lines.append("")
        return lines

    for row in visible_rows:
        details = []
        if row.get("project"):
            details.append(f"{tr(lang, 'compose_project')}: {row['project']}")
        if row.get("service"):
            details.append(f"{tr(lang, 'compose_service')}: {row['service']}")
        detail_text = f" ({', '.join(details)})" if details else ""
        suffix = f" - {display_operation_detail(row['detail'], lang)}" if row.get("detail") else ""
        lines.append(f"- {row.get('image') or '-'}: {display_image_update_status(row.get('status', ''), lang)}{detail_text}{suffix}")

    lines.append("")
    return lines

def build_image_update_table(run_dir: Path, lang: str) -> str:
    rows = load_image_update_results(run_dir)
    if not rows:
        return f"<p>{html.escape(tr(lang, 'image_update_none'))}</p>"

    benign = {"up_to_date", "local_image", "digest_pinned", "skipped"}
    visible_rows = [row for row in rows if row.get("status", "") not in benign]
    checked = sum(1 for row in rows if row.get("status") not in {"local_image", "digest_pinned", "skipped"})
    available = sum(1 for row in rows if row.get("status") == "update_available")
    applied = sum(1 for row in rows if row.get("status") == "update_applied")
    problems = sum(1 for row in rows if row.get("status") in {"pull_failed", "recreate_failed", "verification_failed", "rolled_back", "rollback_failed", "recreate_skipped"})
    summary = (
        f"Checked registry containers: {checked}; pending updates: {available}; applied: {applied}; warnings/errors: {problems}"
        if lang == "en"
        else f"Geprüfte Registry-Container: {checked}; offene Updates: {available}; angewendet: {applied}; Warnungen/Fehler: {problems}"
    )
    local_count = sum(1 for row in rows if row.get("status") == "local_image")
    local_summary = (f"Lokal gebaute Container ohne Registry-Abfrage: {local_count}."
                     if lang == "de" else f"Locally built containers without registry requests: {local_count}.")
    summary_html = html.escape(summary) + ("<br>" + html.escape(local_summary) if local_count else "")
    if not visible_rows:
        return f"<p>{summary_html}<br>{html.escape(tr(lang, 'image_update_no_actionable'))}</p>"

    columns = [
        ("image", "source"), ("status", "image_update_status"), ("detail", "image_update_detail"),
        ("container", "container"), ("project", "compose_project"), ("service", "compose_service"),
    ]
    body = []
    for row in visible_rows:
        cells = []
        for key, _ in columns:
            value = row.get(key) or "-"
            if key == "status":
                value = display_image_update_status(row.get(key, ""), lang)
            elif key == "detail":
                value = display_operation_detail(value, lang)
            cells.append(f"<td>{html.escape(value)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    headings = "".join(f"<th>{html.escape(tr(lang, label))}</th>" for _, label in columns)
    return (f"<p>{summary_html}</p>"
            "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>"
            + "<tr>" + headings + "</tr>" + "".join(body) + "</table>")

def local_image_finding_rows(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    local_image_set = {item["image"] for item in local_images if item.get("image")}
    selected = [
        item
        for item in findings
        if item.get("group") == "docker"
        and item.get("source", "").startswith("Docker-Image: ")
        and item.get("source", "")[len("Docker-Image: "):] in local_image_set
        and item.get("fixed")
        and item.get("fixed") != "-"
    ]

    selected.sort(
        key=lambda item: (
            item.get("source", ""),
            SEVERITY_ORDER.get(item.get("severity", "UNKNOWN"), 5),
            -(item.get("score") if item.get("score") is not None else -1),
            item.get("pkg", ""),
            item.get("cve", ""),
        )
    )
    return selected


def local_image_summary(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    selected = local_image_finding_rows(findings, local_images)
    by_image: Dict[str, List[Dict[str, Any]]] = {}
    for item in selected:
        image = item["source"][len("Docker-Image: "):]
        by_image.setdefault(image, []).append(item)

    rows: List[Dict[str, Any]] = []
    for image_info in local_images:
        image = image_info["image"]
        items = by_image.get(image, [])
        rows.append(
            {
                **image_info,
                "fixable": len(items),
                "critical": sum(1 for item in items if item.get("severity") == "CRITICAL"),
                "high": sum(1 for item in items if item.get("severity") == "HIGH"),
            }
        )

    rows.sort(key=lambda item: (-item["fixable"], item["image"]))
    return rows


def build_local_image_text(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]], lang: str, limit: int = 12) -> List[str]:
    lines: List[str] = []
    lines.append(tr(lang, "local_images_heading") + ":")
    if not local_images:
        lines.append(tr(lang, "local_images_none"))
        lines.append("")
        return lines

    for row in local_image_summary(findings, local_images):
        details = []
        if row.get("project"):
            details.append(f"{tr(lang, 'compose_project')}: {row['project']}")
        if row.get("service"):
            details.append(f"{tr(lang, 'compose_service')}: {row['service']}")
        detail_text = f" ({', '.join(details)})" if details else ""
        lines.append(
            f"- {row['image']}: {row['fixable']} {tr(lang, 'local_image_fixable')}, "
            f"{row['critical']} {tr(lang, 'critical')}, {row['high']} {tr(lang, 'high')}{detail_text}"
        )

    local_findings = local_image_finding_rows(findings, local_images)
    lines.append("")
    lines.append(tr(lang, "top_local_image_findings") + ":")
    if not local_findings:
        lines.append(tr(lang, "no_local_image_findings"))
    else:
        for item in local_findings[:limit]:
            image = item["source"][len("Docker-Image: "):]
            lines.append(
                f"- {image} - {item['cve']} - CVSS {item['score_text']} - "
                f"{display_severity(item['severity'], lang)} - {item['pkg']} - "
                f"{item['installed']} -> {item['fixed']}"
            )
        if len(local_findings) > limit:
            lines.append(f"- ... +{len(local_findings) - limit} {tr(lang, 'other_more')}")

    lines.append("")
    return lines


def build_local_image_summary_table(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]], lang: str) -> str:
    if not local_images:
        return f"<p>{html.escape(tr(lang, 'local_images_none'))}</p>"

    rows = []
    for item in local_image_summary(findings, local_images):
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['image'])}</td>"
            f"<td>{html.escape(item.get('container') or '-')}</td>"
            f"<td>{html.escape(item.get('project') or '-')}</td>"
            f"<td>{html.escape(item.get('service') or '-')}</td>"
            f"<td>{item['fixable']}</td>"
            f"<td>{item['critical']}</td>"
            f"<td>{item['high']}</td>"
            "</tr>"
        )

    return (
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>"
        f"<tr><th>{html.escape(tr(lang, 'source'))}</th>"
        f"<th>{html.escape(tr(lang, 'container'))}</th>"
        f"<th>{html.escape(tr(lang, 'compose_project'))}</th>"
        f"<th>{html.escape(tr(lang, 'compose_service'))}</th>"
        f"<th>{html.escape(tr(lang, 'local_image_fixable'))}</th>"
        f"<th>{html.escape(('Kritisch mit Fix' if lang == 'de' else 'Critical with fix'))}</th>"
        f"<th>{html.escape(('Hoch mit Fix' if lang == 'de' else 'High with fix'))}</th></tr>"
        + "".join(rows)
        + "</table>"
    )

def build_local_image_finding_table(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]], lang: str, limit: int = 15) -> str:
    selected = local_image_finding_rows(findings, local_images)
    if not selected:
        return f"<p>{html.escape(tr(lang, 'no_local_image_findings'))}</p>"

    rows = []
    for item in selected[:limit]:
        image = item["source"][len("Docker-Image: "):]
        url = html.escape(item["primary_url"]) if item["primary_url"] else ""
        cve = html.escape(item["cve"])
        cve_html = f'<a href="{url}">{cve}</a>' if url else cve

        target_preview = ", ".join(item.get("targets", [])[:2])
        if len(item.get("targets", [])) > 2:
            target_preview += f" (+{len(item['targets']) - 2} {tr(lang, 'other_more')})"

        rows.append(
            "<tr>"
            f"<td>{html.escape(image)}</td>"
            f"<td>{cve_html}</td>"
            f"<td>{html.escape(item['score_text'])}</td>"
            f"<td>{severity_badge(item['severity'], lang)}</td>"
            f"<td>{html.escape(item['pkg'])}</td>"
            f"<td>{html.escape(item['installed'])}</td>"
            f"<td>{html.escape(item['fixed'])}</td>"
            f"<td>{html.escape(target_preview)}</td>"
            "</tr>"
        )

    if len(selected) > limit:
        rows.append(
            "<tr>"
            f"<td colspan='8'>{html.escape('+' + str(len(selected) - limit) + ' ' + tr(lang, 'other_more'))}</td>"
            "</tr>"
        )

    return (
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>"
        f"<tr><th>{html.escape(tr(lang, 'source'))}</th>"
        f"<th>{html.escape(tr(lang, 'cve'))}</th>"
        f"<th>{html.escape(tr(lang, 'cvss'))}</th>"
        f"<th>{html.escape(tr(lang, 'severity'))}</th>"
        f"<th>{html.escape(tr(lang, 'package'))}</th>"
        f"<th>{html.escape(tr(lang, 'installed'))}</th>"
        f"<th>{html.escape(tr(lang, 'fix'))}</th>"
        f"<th>{html.escape(tr(lang, 'targets_preview'))}</th></tr>"
        + "".join(rows)
        + "</table>"
    )



def read_tsv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return []
    headers = lines[0].split("\t")
    rows: List[Dict[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        row = {headers[i]: parts[i] if i < len(parts) else "" for i in range(len(headers))}
        rows.append(row)
    return rows


def load_host_package_watchlist(run_dir: Path) -> List[Dict[str, str]]:
    return read_tsv(run_dir / "host_package_watchlist.tsv")


def load_host_debian_backport_notes(run_dir: Path) -> List[Dict[str, str]]:
    return read_tsv(run_dir / "host_debian_backport_notes.tsv")




def backport_note_sort_key(row: Dict[str, str]) -> Tuple[int, int, str, str]:
    fixed = (row.get("Fixed") or "").strip()
    sev = (row.get("Severity") or "UNKNOWN").upper()
    return (SEVERITY_ORDER.get(sev, 9), 0 if fixed and fixed != "-" else 1, row.get("CVE", ""), row.get("Package", ""))


def group_backport_notes(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        cve = (row.get("CVE") or "-").strip()
        entry = grouped.setdefault(
            cve,
            {
                "CVE": cve,
                "Packages": [],
                "Installed": [],
                "Fixed": [],
                "Severity": (row.get("Severity") or "UNKNOWN").upper(),
                "Types": [],
                "Targets": [],
                "BackportNotes": [],
            },
        )
        if SEVERITY_ORDER.get((row.get("Severity") or "UNKNOWN").upper(), 9) < SEVERITY_ORDER.get(entry["Severity"], 9):
            entry["Severity"] = (row.get("Severity") or "UNKNOWN").upper()
        entry["Packages"].append(row.get("Package") or "-")
        entry["Installed"].append(row.get("Installed") or "-")
        entry["Fixed"].append(row.get("Fixed") or "-")
        entry["Types"].append(row.get("Type") or "-")
        entry["Targets"].append(row.get("Target") or "-")
        entry["BackportNotes"].append(row.get("BackportNote") or "-")

    result: List[Dict[str, Any]] = []
    for entry in grouped.values():
        entry["Packages"] = unique_sorted(entry["Packages"])
        entry["Installed"] = unique_sorted(entry["Installed"])
        entry["Fixed"] = unique_sorted(entry["Fixed"])
        entry["Types"] = unique_sorted(entry["Types"])
        entry["Targets"] = unique_sorted(entry["Targets"])
        entry["BackportNotes"] = unique_sorted(entry["BackportNotes"])
        entry["PackageCount"] = len(entry["Packages"])
        result.append(entry)

    result.sort(
        key=lambda row: (
            SEVERITY_ORDER.get(row.get("Severity", "UNKNOWN"), 9),
            0 if row.get("Fixed") else 1,
            -row.get("PackageCount", 0),
            row.get("CVE", ""),
        )
    )
    return result


def summarize_backport_notes(rows: List[Dict[str, str]]) -> Tuple[int, int]:
    grouped = group_backport_notes(rows)
    fixed = sum(1 for row in grouped if row.get("Fixed"))
    return fixed, len(grouped) - fixed


def display_package_status(value: str) -> str:
    v = (value or "").strip()
    mapping = {
        "ii": "installed",
        "rc": "removed-config-files",
        "un": "not-installed",
        "iF": "install-failed",
        "iU": "unpacked",
        "iH": "half-installed",
        "iW": "triggers-awaited",
        "iT": "triggers-pending",
        "hi": "hold-installed",
        "install ok installed": "installed",
    }
    return mapping.get(v, v or "-")


def build_host_inventory_text(run_dir: Path, lang: str, limit: int = 30) -> List[str]:
    rows = load_host_package_watchlist(run_dir)
    lines: List[str] = []
    lines.append(tr(lang, "host_inventory_heading") + ":")
    lines.append(tr(lang, "host_inventory_note"))
    if not rows:
        lines.append(tr(lang, "host_inventory_none"))
        lines.append("")
        return lines
    for row in rows[:limit]:
        lines.append(
            f"- {row.get('Package','-')}: {row.get('Version','-')} ({row.get('Architecture','-')}, {display_package_status(row.get('Status','-'))})"
        )
    if len(rows) > limit:
        lines.append(f"- +{len(rows) - limit} {tr(lang, 'other_more')}")
    lines.append("")
    return lines


def build_backport_notes_text(run_dir: Path, lang: str, limit: int = 20) -> List[str]:
    raw_rows = load_host_debian_backport_notes(run_dir)
    rows = group_backport_notes(raw_rows)
    lines: List[str] = []
    lines.append(tr(lang, "backport_notes_heading") + ":")
    lines.append(tr(lang, "backport_notes_note"))
    if not rows:
        lines.append(tr(lang, "backport_notes_none"))
        lines.append("")
        return lines
    fixed_count, unfixed_count = summarize_backport_notes(raw_rows)
    lines.append(tr(lang, "backport_notes_fix_summary", fixed=fixed_count, unfixed=unfixed_count))
    for row in rows[:limit]:
        lines.append(
            f"- {row.get('CVE','-')} - {display_severity(row.get('Severity','UNKNOWN'), lang)} - "
            f"{tr(lang, 'affected_packages')}: {row.get('PackageCount', 0)} ({preview_values(row.get('Packages', []), lang, 5)}) - "
            f"{tr(lang, 'installed')}: {preview_values(row.get('Installed', []), lang, 3)} -> "
            f"{tr(lang, 'fix')}: {preview_values(row.get('Fixed', []), lang, 3)} - "
            f"{'; '.join(display_backport_note(n, lang) for n in row.get('BackportNotes', [])[:2])} - URL: {cve_link_url(row.get('CVE',''))}"
        )
    if len(rows) > limit:
        lines.append(f"- +{len(rows) - limit} {tr(lang, 'other_more')}")
    lines.append("")
    return lines


def build_host_inventory_html(run_dir: Path, lang: str, limit: int = 30) -> str:
    rows = load_host_package_watchlist(run_dir)
    if not rows:
        return f"<p>{html.escape(tr(lang, 'host_inventory_none'))}</p>"
    out: List[str] = [
        f"<p style='color:#4b5563;'>{html.escape(tr(lang, 'host_inventory_note'))}</p>",
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>",
        f"<tr><th>{html.escape(tr(lang, 'package'))}</th><th>{html.escape(tr(lang, 'installed'))}</th><th>{html.escape(tr(lang, 'architecture'))}</th><th>{html.escape(tr(lang, 'status'))}</th></tr>",
    ]
    for row in rows[:limit]:
        out.append(
            "<tr>"
            f"<td>{html.escape(row.get('Package','-'))}</td>"
            f"<td>{html.escape(row.get('Version','-'))}</td>"
            f"<td>{html.escape(row.get('Architecture','-'))}</td>"
            f"<td>{html.escape(display_package_status(row.get('Status','-')))}</td>"
            "</tr>"
        )
    if len(rows) > limit:
        out.append(f"<tr><td colspan='4'>+{len(rows) - limit} {html.escape(tr(lang, 'other_more'))}</td></tr>")
    out.append("</table>")
    return "".join(out)


def build_backport_notes_html(run_dir: Path, lang: str, limit: int = 20) -> str:
    raw_rows = load_host_debian_backport_notes(run_dir)
    rows = group_backport_notes(raw_rows)
    if not rows:
        return f"<p>{html.escape(tr(lang, 'backport_notes_none'))}</p>"
    fixed_count, unfixed_count = summarize_backport_notes(raw_rows)
    out: List[str] = [
        f"<p style='color:#4b5563;'>{html.escape(tr(lang, 'backport_notes_note'))}</p>",
        f"<p style='color:#4b5563;'>{html.escape(tr(lang, 'backport_notes_fix_summary', fixed=fixed_count, unfixed=unfixed_count))}</p>",
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>",
        f"<tr><th>{html.escape(tr(lang, 'cve'))}</th><th>{html.escape(tr(lang, 'severity'))}</th><th>{html.escape(tr(lang, 'affected_packages'))}</th><th>{html.escape(tr(lang, 'installed'))}</th><th>{html.escape(tr(lang, 'fix'))}</th><th>{html.escape(tr(lang, 'backport_note'))}</th></tr>",
    ]
    for row in rows[:limit]:
        out.append(
            "<tr>"
            f"<td>{cve_link_html(row.get('CVE','-'))}</td>"
            f"<td>{severity_badge(row.get('Severity','UNKNOWN'), lang)}</td>"
            f"<td>{html.escape(str(row.get('PackageCount', 0)) + ' / ' + preview_values(row.get('Packages', []), lang, 6))}</td>"
            f"<td>{html.escape(preview_values(row.get('Installed', []), lang, 3))}</td>"
            f"<td>{html.escape(preview_values(row.get('Fixed', []), lang, 3))}</td>"
            f"<td>{html.escape('; '.join(display_backport_note(n, lang) for n in row.get('BackportNotes', [])[:2]) or '-')}</td>"
            "</tr>"
        )
    if len(rows) > limit:
        out.append(f"<tr><td colspan='6'>+{len(rows) - limit} {html.escape(tr(lang, 'other_more'))}</td></tr>")
    out.append("</table>")
    return "".join(out)



def compact_detail(label: str, value: str) -> str:
    return (
        f"<br><span style='font-weight:600;color:#374151;'>{html.escape(label)}: </span>"
        f"<span style='word-break:break-word;overflow-wrap:anywhere;'>{html.escape(value or '-')}</span>"
    )


def compact_detail_row(label: str, value: str) -> str:
    return (
        "<div style='margin-top:4px;line-height:1.35;word-break:break-word;overflow-wrap:anywhere;'>"
        f"<span style='font-weight:600;color:#374151;'>{html.escape(label)}: </span>"
        f"<span>{html.escape(value or '-')}</span>"
        "</div>"
    )


def finding_card(content: str) -> str:
    return (
        "<div style='border:1px solid #d1d5db;border-left:4px solid #6b7280;"
        "border-radius:10px;padding:10px 12px;margin:10px 0;background:#fafafa;'>"
        + content +
        "</div>"
    )


def build_backport_notes_html_cards(run_dir: Path, lang: str, limit: int = 80) -> str:
    raw_rows = load_host_debian_backport_notes(run_dir)
    rows = group_backport_notes(raw_rows)
    if not rows:
        return f"<p>{html.escape(tr(lang, 'backport_notes_none'))}</p>"

    fixed_count, unfixed_count = summarize_backport_notes(raw_rows)
    out: List[str] = [
        f"<p style='color:#4b5563;line-height:1.4;'>{html.escape(tr(lang, 'backport_notes_note'))}</p>",
        f"<p style='color:#4b5563;line-height:1.4;'>{html.escape(tr(lang, 'backport_notes_fix_summary', fixed=fixed_count, unfixed=unfixed_count))}</p>",
    ]

    for row in rows[:limit]:
        cve = str(row.get("CVE", "-"))
        header = (
            "<div style='margin-bottom:6px;font-size:15px;'>"
            f"{cve_link_html(cve)} {severity_badge(row.get('Severity','UNKNOWN'), lang)}"
            "</div>"
        )
        body = (
            compact_detail_row(tr(lang, "affected_packages"), str(row.get("PackageCount", 0)) + " / " + preview_values(row.get("Packages", []), lang, 8))
            + compact_detail_row(tr(lang, "installed"), preview_values(row.get("Installed", []), lang, 4))
            + compact_detail_row(tr(lang, "fix"), preview_values(row.get("Fixed", []), lang, 4))
            + compact_detail_row(tr(lang, "backport_note"), "; ".join(display_backport_note(n, lang) for n in row.get("BackportNotes", [])[:2]) or "-")
        )
        out.append(finding_card(header + body))

    if len(rows) > limit:
        out.append(
            "<p style='color:#4b5563;'>"
            + html.escape("+" + str(len(rows) - limit) + " " + tr(lang, "other_more"))
            + "</p>"
        )

    return "".join(out)


def build_grouped_finding_cards(findings: List[Dict[str, Any]], lang: str, limit: int = 80) -> str:
    grouped = grouped_findings_by_cve(findings)
    if not grouped:
        return ""

    out: List[str] = []
    for item in grouped[:limit]:
        source_preview = ", ".join(display_source(src, lang) for src in item.get("sources", [])[:3])
        if len(item.get("sources", [])) > 3:
            source_preview += f" (+{len(item.get('sources', [])) - 3} {tr(lang, 'other_more')})"

        target_preview = preview_values(item.get("targets", []), lang, limit=5)
        cve = item.get("cve", "-")
        header = (
            "<div style='margin-bottom:6px;font-size:15px;'>"
            f"{cve_link_html(cve, item.get('primary_url',''))} "
            f"<span style='color:#4b5563;'>CVSS {html.escape(item.get('score_text','-'))}</span> "
            f"{severity_badge(item.get('severity','UNKNOWN'), lang)}"
            "</div>"
        )
        body = (
            compact_detail_row(tr(lang, "affected_packages"), str(item.get("package_count", 0)) + " / " + preview_values(item.get("packages", []), lang, 8))
            + compact_detail_row(tr(lang, "installed"), preview_values(item.get("installed_versions", []), lang, 4))
            + compact_detail_row(tr(lang, "fix"), preview_values(item.get("fixed_versions", []), lang, 4))
            + compact_detail_row(tr(lang, "priority"), remediation_priority(item, lang))
            + compact_detail_row(tr(lang, "context_hint"), exposure_context(item, lang))
            + compact_detail_row(tr(lang, "occurrences"), str(item.get("occurrences", 1)))
            + compact_detail_row(tr(lang, "source"), source_preview or "-")
            + compact_detail_row(tr(lang, "targets_preview"), target_preview)
        )
        out.append(finding_card(header + body))

    if len(grouped) > limit:
        out.append(
            "<p style='color:#4b5563;'>"
            + html.escape("+" + str(len(grouped) - limit) + " " + tr(lang, "other_more"))
            + "</p>"
        )

    return "".join(out)


def footer_text(lang: str, script_version: str) -> str:
    version = script_version or "-"
    copyright_line = tr(lang, "copyright")
    return (
        f"{tr(lang, 'footer_generated')}\n"
        f"{tr(lang, 'script_version')}: {version}\n"
        f"{copyright_line}\n"
    )


def footer_html(lang: str, script_version: str) -> str:
    version = script_version or "-"
    copyright_line = tr(lang, "copyright")
    return (
        "<hr style='border:none;border-top:1px solid #d1d5db;margin-top:22px;'>"
        "<p style='font-size:12px;color:#6b7280;margin-top:10px;'>"
        f"{html.escape(tr(lang, 'footer_generated'))}<br>"
        f"{html.escape(tr(lang, 'script_version'))}: {html.escape(version)}<br>"
        f"{html.escape(copyright_line)}"
        "</p>"
    )


def build_text(findings: List[Dict[str, Any]], sources: List[Dict[str, Any]], raw_total: int, lang: str, run_dir: Path, script_version: str, show_host_inventory: bool = False, mail_host_limit: int = 30, mail_backport_limit: int = 30, mail_docker_limit: int = 10, mail_local_limit: int = 15, filesystem_scanned: bool = True, images_scanned: bool = True) -> str:
    overall_critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    overall_high = sum(1 for f in findings if f["severity"] == "HIGH")
    duplicates_removed = max(raw_total - len(findings), 0)

    host_summary = summarize_group(findings, "host")
    docker_summary = summarize_group(findings, "docker")

    host_findings = [f for f in findings if f["group"] == "host"]
    docker_findings = [f for f in findings if f["group"] == "docker"]
    docker_agg = aggregate_findings(findings, "docker")

    host_sources, _ = summarize_sources_for_mail(sources, "host")
    docker_sources, docker_minor = summarize_sources_for_mail(sources, "docker")
    local_images = load_local_built_images(run_dir)

    lines: List[str] = []
    lines.append(tr(lang, "report_title"))
    lines.append("")
    lines.append(f"{tr(lang, 'unique_total')}: {len(findings)}")
    lines.append(f"{tr(lang, 'critical_total')}: {overall_critical}")
    lines.append(f"{tr(lang, 'high_total')}: {overall_high}")
    lines.append("")
    if filesystem_scanned:
        lines.append(f"{tr(lang, 'host_section')}:")
        lines.append(tr(lang, "count_line", label=tr(lang, "unique"), value=host_summary["total"]))
        lines.append(tr(lang, "count_line", label=tr(lang, "critical"), value=host_summary["critical"]))
        lines.append(tr(lang, "count_line", label=tr(lang, "high"), value=host_summary["high"]))
        lines.append("")
    lines.append(f"{tr(lang, 'docker_section')}:")
    if images_scanned:
        lines.append(tr(lang, "count_line", label=tr(lang, "unique"), value=docker_summary["total"]))
        lines.append(tr(lang, "count_line", label=tr(lang, "critical"), value=docker_summary["critical"]))
        lines.append(tr(lang, "count_line", label=tr(lang, "high"), value=docker_summary["high"]))
    else:
        lines.append(tr(lang, "docker_scan_disabled"))
    lines.append("")

    if images_scanned:
        lines.extend(build_image_update_text(run_dir, lang))
        lines.extend(build_local_image_rebuild_text(run_dir, lang))

    if images_scanned:
        lines.append(tr(lang, "top_docker_heading_txt"))
        if docker_agg:
            for item in docker_agg[:mail_docker_limit]:
                lines.append(
                    tr(
                        lang,
                        "major_topic_line",
                        cve=item["cve"],
                        pkg=item["pkg"],
                        severity=display_severity(item["severity"], lang),
                        count=item["source_count"],
                    )
                )
        else:
            lines.append(tr(lang, "no_docker_findings"))
        lines.append("")

        if docker_findings:
            lines.append(tr(lang, "top_docker_single_heading_txt"))
            lines.append("")
            lines.extend(build_top_lines(docker_findings, lang, limit=mail_docker_limit))
            lines.append("")
    else:
        lines.append(tr(lang, "docker_scan_disabled"))
        lines.append("")

    lines.append(tr(lang, "sources_heading_txt"))
    if not host_sources and not docker_sources and docker_minor["count"] == 0:
        lines.append(tr(lang, "no_findings"))
    if filesystem_scanned:
        for src in host_sources:
            lines.append(
                tr(
                    lang,
                    "source_line",
                    source=display_source(src["source"], lang),
                    unique=src["unique_findings"],
                    raw=src["raw_findings"],
                    duplicates=src["duplicates_removed"],
                )
            )

    if images_scanned:
        for src in docker_sources:
            lines.append(
                tr(
                    lang,
                    "source_line",
                    source=display_source(src["source"], lang),
                    unique=src["unique_findings"],
                    raw=src["raw_findings"],
                    duplicates=src["duplicates_removed"],
                )
            )

        if docker_minor["count"] > 0:
            lines.append(
                tr(
                    lang,
                    "source_line_other",
                    count=docker_minor["count"],
                    unique=docker_minor["unique_findings"],
                )
            )

    lines.append("")
    if images_scanned:
        lines.extend(build_local_image_text(findings, local_images, lang, limit=mail_local_limit))
    if filesystem_scanned:
        lines.extend(build_backport_notes_text(run_dir, lang, limit=mail_backport_limit))
        lines.append(tr(lang, "triage_note"))
        lines.append("")

        if host_findings:
            lines.append(tr(lang, "top_host_heading_txt"))
            lines.append("")
            lines.extend(build_grouped_top_lines(host_findings, lang, limit=mail_host_limit))
            lines.append("")

        if show_host_inventory:
            lines.extend(build_host_inventory_text(run_dir, lang, limit=15))
        else:
            lines.append(tr(lang, "host_inventory_hidden"))
            lines.append("")

    lines.append(tr(lang, "mail_note"))
    lines.append("")
    lines.append(footer_text(lang, script_version))

    return "\n".join(lines) + "\n"

def build_source_rows(sources: List[Dict[str, Any]], group: str, lang: str) -> str:
    selected, minor = summarize_sources_for_mail(sources, group)
    if not selected and minor["count"] == 0:
        return f"<p>{html.escape(tr(lang, 'no_findings'))}</p>"

    rows = []
    for src in selected:
        rows.append(
            "<tr>"
            f"<td>{html.escape(display_source(src['source'], lang))}</td>"
            f"<td>{src['unique_findings']}</td>"
            "</tr>"
        )

    if group == "docker" and minor["count"] > 0:
        rows.append(
            "<tr>"
            f"<td>{html.escape(tr(lang, 'other_smaller_docker_sources', count=minor['count']))}</td>"
            f"<td>{minor['unique_findings']}</td>"
            "</tr>"
        )

    return (
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>"
        f"<tr><th>{html.escape(tr(lang, 'source'))}</th><th>{html.escape(tr(lang, 'unique'))}</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def build_finding_rows(findings: List[Dict[str, Any]], lang: str, limit: int) -> str:
    rows: List[str] = []

    for item in findings[:limit]:
        url = html.escape(item["primary_url"]) if item["primary_url"] else ""
        cve = html.escape(item["cve"])
        cve_html = f'<a href="{url}">{cve}</a>' if url else cve

        target_preview = ", ".join(item.get("targets", [])[:3])
        if len(item.get("targets", [])) > 3:
            target_preview += f" (+{len(item['targets']) - 3} {tr(lang, 'other_more')})"

        rows.append(
            "<tr>"
            f"<td>{cve_html}</td>"
            f"<td>{html.escape(item['score_text'])}</td>"
            f"<td>{severity_badge(item['severity'], lang)}</td>"
            f"<td>{html.escape(item['pkg'])}</td>"
            f"<td>{html.escape(item['installed'])}</td>"
            f"<td>{html.escape(item['fixed'])}</td>"
            f"<td>{html.escape(remediation_priority(item, lang))}</td>"
            f"<td>{html.escape(exposure_context(item, lang))}</td>"
            f"<td>{html.escape(str(item.get('occurrences', 1)))}</td>"
            f"<td>{html.escape(display_source(item['source'], lang))}</td>"
            f"<td>{html.escape(target_preview)}</td>"
            "</tr>"
        )

    if len(findings) > limit:
        rows.append(
            "<tr>"
            f"<td colspan='11'>+{len(findings) - limit} {html.escape(tr(lang, 'other_more'))}</td>"
            "</tr>"
        )
    return "".join(rows)



def build_grouped_finding_rows(findings: List[Dict[str, Any]], lang: str, limit: int) -> str:
    rows: List[str] = []
    grouped = grouped_findings_by_cve(findings)
    for item in grouped[:limit]:
        source_preview = ", ".join(display_source(src, lang) for src in item.get("sources", [])[:3])
        if len(item.get("sources", [])) > 3:
            source_preview += f" (+{len(item.get('sources', [])) - 3} {tr(lang, 'other_more')})"
        target_preview = preview_values(item.get("targets", []), lang, limit=3)
        rows.append(
            "<tr>"
            f"<td>{cve_link_html(item.get('cve','-'), item.get('primary_url',''))}</td>"
            f"<td>{html.escape(item.get('score_text','-'))}</td>"
            f"<td>{severity_badge(item.get('severity','UNKNOWN'), lang)}</td>"
            f"<td>{html.escape(str(item.get('package_count', 0)) + ' / ' + preview_values(item.get('packages', []), lang, 5))}</td>"
            f"<td>{html.escape(preview_values(item.get('installed_versions', []), lang, 3))}</td>"
            f"<td>{html.escape(preview_values(item.get('fixed_versions', []), lang, 3))}</td>"
            f"<td>{html.escape(remediation_priority(item, lang))}</td>"
            f"<td>{html.escape(exposure_context(item, lang))}</td>"
            f"<td>{html.escape(str(item.get('occurrences', 1)))}</td>"
            f"<td>{html.escape(source_preview or '-')}</td>"
            f"<td>{html.escape(target_preview)}</td>"
            "</tr>"
        )
    if len(grouped) > limit:
        rows.append(
            "<tr>"
            f"<td colspan='11'>+{len(grouped) - limit} {html.escape(tr(lang, 'other_more'))}</td>"
            "</tr>"
        )
    return "".join(rows)

def build_aggregate_rows(items: List[Dict[str, Any]], lang: str, limit: int) -> str:
    rows: List[str] = []

    for item in items[:limit]:
        url = html.escape(item["primary_url"]) if item["primary_url"] else ""
        cve = html.escape(item["cve"])
        cve_html = f'<a href="{url}">{cve}</a>' if url else cve

        source_preview = ", ".join(display_source(src, lang) for src in item["sources"][:3])
        if len(item["sources"]) > 3:
            source_preview += f" (+{len(item['sources']) - 3} {tr(lang, 'other_more')})"

        installed_preview = ", ".join(item["installed_versions"][:3]) if item["installed_versions"] else "-"
        if len(item["installed_versions"]) > 3:
            installed_preview += f" (+{len(item['installed_versions']) - 3} {tr(lang, 'other_more')})"

        fixed_preview = ", ".join(item["fixed_versions"][:3]) if item["fixed_versions"] else "-"
        if len(item["fixed_versions"]) > 3:
            fixed_preview += f" (+{len(item['fixed_versions']) - 3} {tr(lang, 'other_more')})"

        rows.append(
            "<tr>"
            f"<td>{cve_html}</td>"
            f"<td>{html.escape(item['score_text'])}</td>"
            f"<td>{severity_badge(item['severity'], lang)}</td>"
            f"<td>{html.escape(item['pkg'])}</td>"
            f"<td>{html.escape(installed_preview)}</td>"
            f"<td>{html.escape(fixed_preview)}</td>"
            f"<td>{item['source_count']}</td>"
            f"<td>{item['occurrences']}</td>"
            f"<td>{html.escape(source_preview)}</td>"
            "</tr>"
        )

    return "".join(rows)


def summary_box(title: str, total: int, critical: int, high: int, lang: str, disabled: bool = False) -> str:
    if disabled:
        body = f"<p style='margin:0'><strong>{html.escape(tr(lang, 'scan_disabled'))}</strong></p>"
    else:
        body = (
            f"<p style='margin:0'>{html.escape(tr(lang, 'summary_box_total'))}: <strong>{total}</strong><br>"
            f"{html.escape(tr(lang, 'summary_box_critical'))}: <strong>{critical}</strong><br>"
            f"{html.escape(tr(lang, 'summary_box_high'))}: <strong>{high}</strong></p>"
        )
    return (
        "<div style='border:1px solid #d1d5db;border-radius:10px;padding:12px;min-width:220px;background:#fafafa;'>"
        f"<h3 style='margin-top:0;margin-bottom:8px'>{html.escape(title)}</h3>"
        f"{body}"
        "</div>"
    )


def build_html(findings: List[Dict[str, Any]], sources: List[Dict[str, Any]], raw_total: int, lang: str, run_dir: Path, script_version: str, show_host_inventory: bool = False, mail_host_limit: int = 30, mail_backport_limit: int = 30, mail_docker_limit: int = 10, mail_local_limit: int = 15, filesystem_scanned: bool = True, images_scanned: bool = True) -> str:
    overall_critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    overall_high = sum(1 for f in findings if f["severity"] == "HIGH")
    duplicates_removed = max(raw_total - len(findings), 0)

    host_summary = summarize_group(findings, "host")
    docker_summary = summarize_group(findings, "docker")

    host_findings = [f for f in findings if f["group"] == "host"]
    docker_findings = [f for f in findings if f["group"] == "docker"]
    docker_agg = aggregate_findings(findings, "docker")
    local_images = load_local_built_images(run_dir)

    host_table = build_grouped_finding_cards(host_findings, lang, limit=mail_host_limit)
    docker_table = build_finding_rows(docker_findings, lang, limit=mail_docker_limit)
    docker_agg_table = build_aggregate_rows(docker_agg, lang, limit=mail_docker_limit)

    parts: List[str] = [
        "<html><body style='margin:0;padding:12px;font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111827;line-height:1.35;'><div style='max-width:980px;margin:0 auto;'>",
        f"<h2 style='margin-bottom:8px'>{html.escape(tr(lang, 'report_title'))}</h2>",
        (
            f"<p>{html.escape(tr(lang, 'unique_total'))}: <strong>{len(findings)}</strong><br>"
            f"{html.escape(tr(lang, 'critical_total'))}: <strong>{overall_critical}</strong><br>"
            f"{html.escape(tr(lang, 'high_total'))}: <strong>{overall_high}</strong></p>"
        ),
        "<div style='display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;'>",
    ]

    if filesystem_scanned:
        parts.append(summary_box(tr(lang, 'host_section'), host_summary["total"], host_summary["critical"], host_summary["high"], lang))
    parts.append(summary_box(tr(lang, 'docker_section'), docker_summary["total"], docker_summary["critical"], docker_summary["high"], lang, disabled=(not images_scanned)))
    parts.append("</div>")

    navigation = []
    if images_scanned:
        navigation.extend([
            ("update-ergebnisse", "Update-Ergebnisse" if lang == "de" else "Update results"),
            ("docker-funde", "Docker-Funde" if lang == "de" else "Docker findings"),
            ("lokale-images", "Lokale Images" if lang == "de" else "Local images"),
        ])
    if filesystem_scanned:
        navigation.extend([("host-funde", "Host-Funde" if lang == "de" else "Host findings"),
                           ("backports", "Backports")])
    if navigation:
        parts.append("<p style='padding:12px;border:1px solid #d7e3ee;background:#f4f8fb;'>"
                     + " · ".join(f'<a href="#{anchor}">{html.escape(label)}</a>' for anchor, label in navigation)
                     + "</p>")
    if images_scanned:
        parts.extend([
            '<a id="update-ergebnisse"></a>',
            f"<h3>{html.escape(tr(lang, 'image_update_heading'))}</h3>",
            build_image_update_table(run_dir, lang),
            f"<h3>{html.escape(tr(lang, 'local_image_rebuild_heading'))}</h3>",
            build_local_image_rebuild_table(run_dir, lang),
        ])

    if images_scanned:
        parts.extend([
            '<a id="docker-funde"></a>',
            f"<h3>{html.escape(tr(lang, 'major_docker_sources_html'))}</h3>",
            build_source_rows(sources, "docker", lang),
            f"<h3>{html.escape(tr(lang, 'docker_baselines'))}</h3>",
        ])

        if docker_agg_table:
            parts.extend(
                [
                    "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>",
                    f"<tr><th>{html.escape(tr(lang, 'cve'))}</th><th>{html.escape(tr(lang, 'cvss'))}</th>"
                    f"<th>{html.escape(tr(lang, 'severity'))}</th><th>{html.escape(tr(lang, 'package'))}</th>"
                    f"<th>{html.escape(tr(lang, 'installed_preview'))}</th><th>{html.escape(tr(lang, 'fix_preview'))}</th>"
                    f"<th>{html.escape(tr(lang, 'affected_images'))}</th><th>{html.escape(tr(lang, 'occurrences'))}</th>"
                    f"<th>{html.escape(tr(lang, 'sources_preview'))}</th></tr>",
                    docker_agg_table,
                    "</table>",
                ]
            )
        else:
            parts.append(f"<p>{html.escape(tr(lang, 'no_docker_findings'))}</p>")
    else:
        parts.append(f"<p style='color:#4b5563;'>{html.escape(tr(lang, 'docker_scan_disabled'))}</p>")

    if images_scanned:
        parts.append(f"<h3>{html.escape(tr(lang, 'top_docker_findings'))}</h3>")
        if docker_table:
            parts.extend(
                [
                    "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>",
                    f"<tr><th>{html.escape(tr(lang, 'cve'))}</th><th>{html.escape(tr(lang, 'cvss'))}</th>"
                    f"<th>{html.escape(tr(lang, 'severity'))}</th><th>{html.escape(tr(lang, 'package'))}</th>"
                    f"<th>{html.escape(tr(lang, 'installed'))}</th><th>{html.escape(tr(lang, 'fix'))}</th>"
                    f"<th>{html.escape(tr(lang, 'priority'))}</th><th>{html.escape(tr(lang, 'context_hint'))}</th>"
                    f"<th>{html.escape(tr(lang, 'occurrences'))}</th><th>{html.escape(tr(lang, 'source'))}</th>"
                    f"<th>{html.escape(tr(lang, 'targets_preview'))}</th></tr>",
                    docker_table,
                    "</table>",
                ]
            )
        else:
            parts.append(f"<p>{html.escape(tr(lang, 'no_docker_single_findings'))}</p>")

    if images_scanned:
        parts.extend(
            [
                '<a id="lokale-images"></a>',
                f"<h3>{html.escape(tr(lang, 'local_images_heading'))}</h3>",
                f"<p style='color:#4b5563;'>{html.escape(tr(lang, 'local_images_intro'))}</p>",
                build_local_image_summary_table(findings, local_images, lang),
                f"<h3>{html.escape(tr(lang, 'top_local_image_findings'))}</h3>",
                build_local_image_finding_table(findings, local_images, lang, limit=mail_local_limit),
            ]
        )

    if filesystem_scanned:
        parts.extend([
            '<a id="host-funde"></a>',
            f"<h3>{html.escape(tr(lang, 'major_host_sources_html'))}</h3>",
            build_source_rows(sources, "host", lang),
        ])

    if filesystem_scanned:
        parts.append(f"<h3>{html.escape(tr(lang, 'top_host_findings'))}</h3>")
        if host_table:
            parts.append(host_table)
        else:
            parts.append(f"<p>{html.escape(tr(lang, 'no_host_findings'))}</p>")

    if filesystem_scanned:
        parts.extend([
            '<a id="backports"></a>',
            f"<h3>{html.escape(tr(lang, 'backport_notes_heading'))}</h3>",
            build_backport_notes_html_cards(run_dir, lang, limit=mail_backport_limit),
            f"<p style='color:#4b5563;'><strong>{html.escape(tr(lang, 'triage_note'))}</strong></p>",
        ])

        if show_host_inventory:
            parts.extend([
                f"<h3>{html.escape(tr(lang, 'host_inventory_heading'))}</h3>",
                build_host_inventory_html(run_dir, lang, limit=15),
            ])
        else:
            parts.append(f"<p style='color:#4b5563;'>{html.escape(tr(lang, 'host_inventory_hidden'))}</p>")

    parts.extend(
        [
            "<p style='margin-top:18px;color:#4b5563;'>",
            html.escape(tr(lang, 'mail_note')),
            "</p>",
            footer_html(lang, script_version),
            "</div></body></html>",
        ]
    )

    return _apply_mail_design("".join(parts), lang)

def _apply_mail_design(document: str, lang: str = "de") -> str:
    """Presentation-only mobile patch 1 for Classic rc19b.

    Narrow/default view: labelled fields for wide tables, no horizontal scroll.
    Wide view: restore the original table through progressive CSS enhancement.
    The fallback is inline-styled and does not need media queries, JavaScript,
    duplicated data, CSS-generated labels or a second set of report values.
    """
    desktop_css = """
.sw-stacked{display:table!important;border:1px solid #dce5ed!important;border-collapse:collapse!important;table-layout:fixed!important;}
.sw-stacked tbody{display:table-row-group!important;}
.sw-stacked .sw-col-head,.sw-stacked .sw-record{display:table-row!important;margin:0!important;padding:0!important;border:0!important;}
.sw-stacked th,.sw-stacked td{display:table-cell!important;width:auto!important;padding:8px!important;border-bottom:1px solid #dce5ed!important;font-size:12px!important;line-height:1.5!important;}
.sw-stacked th{background-color:#e7eff4!important;color:#153047!important;text-align:left!important;}
.sw-stacked .sw-cell-label{display:none!important;}
.sw-stacked .sw-cell-value{font-size:12px!important;font-weight:400!important;}
.sw-stacked .sw-record-odd{background-color:#f5f8fb!important;}
.sw-stacked .sw-record-even{background-color:#ffffff!important;}
.sw-kpi-col{width:33.333%!important;max-width:none!important;}
.sw-summary-col{width:50%!important;max-width:none!important;}
.sw-kpi-label{min-height:36px!important;}
.sw-content{padding:22px 26px!important;}
.sw-title{padding:23px 28px!important;font-size:25px!important;}
"""
    css = """
html,body{margin:0;padding:0;}
body{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;}
.sw-shell{width:100%;max-width:1100px;table-layout:fixed;}
.sw-data td,.sw-data th{vertical-align:top;}
.sw-cell-value,.sw-simple td{overflow-wrap:anywhere;word-break:break-word;}
.sw-kpi-value,.sw-count{white-space:nowrap!important;word-break:normal!important;overflow-wrap:normal!important;}
a{color:#166b7c;}
""" + "\n@media screen and (min-width:1000px){\n" + desktop_css + "\n}\n" + """
@media print{body{padding:0!important;background:#fff!important;}
.sw-shell{max-width:none!important;} h3{break-after:avoid;}
.sw-record{break-inside:avoid;}}
"""

    def data_table(match: re.Match) -> str:
        original = match.group(0)
        opening, content = original.split(">", 1)
        if "role=" in opening:
            return original
        content = content.rsplit("</table>", 1)[0]
        rows = re.findall(r"<tr\b[^>]*>(.*?)</tr>", content, re.S)
        headers = re.findall(r"<th\b[^>]*>(.*?)</th>", rows[0], re.S) if rows else []
        columns = len(headers)
        cell = "padding:9px 10px;vertical-align:top;border-bottom:1px solid #dce5ed;"
        head = cell + "background-color:#e7eff4;color:#153047;text-align:left;font-weight:700;font-size:12px;line-height:1.4;"
        body = cell + "color:#253b50;font-size:13px;line-height:1.5;overflow-wrap:anywhere;word-break:break-word;"

        # The two-column overview is already readable on a phone: retain it.
        if columns <= 3:
            content = re.sub(r"<th>", lambda _: f'<th scope="col" bgcolor="#e7eff4" style="{head}">', content)
            content = re.sub(r"<td(\s+colspan=['\"]\d+['\"])?\s*>",
                             lambda m: f'<td{m.group(1) or ""} style="{body}">', content)
            row_number = [0]
            def shade(row: re.Match) -> str:
                row_number[0] += 1
                colour = "#f5f8fb" if row_number[0] % 2 == 0 else "#ffffff"
                return f'<tr bgcolor="{colour}" style="background-color:{colour};">'
            content = re.sub(r"<tr>", shade, content)
            # Numeric cells never split into individual digits.
            content = re.sub(r'(<td\b[^>]*>)(\s*\d+(?:[.,]\d+)?\s*)(</td>)',
                             lambda m: m.group(1) + '<span class="sw-count" style="white-space:nowrap;word-break:normal;overflow-wrap:normal;">' + m.group(2) + '</span>' + m.group(3), content)
            if columns == 2:
                content = '<colgroup><col style="width:75%;"><col style="width:25%;"></colgroup>' + content
            return ('<table class="sw-data sw-simple" border="0" cellspacing="0" cellpadding="0" width="100%" '
                    'style="width:100%;table-layout:fixed;border-collapse:collapse;border:1px solid #dce5ed;'
                    'font-family:Segoe UI,Arial,sans-serif;">' + content + '</table>')

        # A single representation of each field. Inline mobile-safe defaults also
        # apply when a mail client removes the complete <style> element.
        output = ['<table class="sw-data sw-stacked" border="0" cellspacing="0" cellpadding="0" width="100%" '
                  'style="display:block;width:100%;border:0;border-collapse:collapse;'
                  'font-family:Segoe UI,Arial,sans-serif;"><tbody style="display:block;">',
                  '<tr class="sw-col-head" style="display:none;">']
        output.extend(f'<th scope="col" style="{head}">{value}</th>' for value in headers)
        output.append('</tr>')
        for row_number, row in enumerate(rows[1:]):
            values = re.findall(r"<td\b([^>]*)>(.*?)</td>", row, re.S)
            if not values:
                continue
            colour = "#f5f8fb" if row_number % 2 == 0 else "#ffffff"
            parity = "odd" if row_number % 2 == 0 else "even"
            output.append(f'<tr class="sw-record sw-record-{parity}" bgcolor="{colour}" '
                          f'style="display:block;margin:0 0 10px;padding:10px 12px;border:1px solid #dce5ed;'
                          f'border-radius:6px;background-color:{colour};">')
            column = 0
            for attributes, value in values:
                colspan = re.search(r"\bcolspan\s*=\s*['\"]?(\d+)", attributes)
                span = int(colspan.group(1)) if colspan else 1
                span_attr = f' colspan="{span}"' if colspan else ''
                label = ''
                if span == 1 and column < len(headers):
                    label_text = html.unescape(re.sub(r'<[^>]*>', '', headers[column])).strip()
                    label = ('<span class="sw-cell-label" style="display:inline;font-size:12px;'
                             'font-weight:600;line-height:1.5;color:#42546a;word-break:normal;">'
                             + html.escape(label_text) + ': </span>')
                compact = bool(re.fullmatch(r'\s*(?:\d+(?:[.,]\d+)?|-)\s*', value))
                value_style = ('white-space:nowrap;word-break:normal;overflow-wrap:normal;' if compact
                               else 'white-space:normal;word-break:break-word;overflow-wrap:anywhere;')
                output.append(f'<td{span_attr} style="display:block;width:auto;padding:4px 0;'
                              'vertical-align:top;color:#253b50;font-size:14px;line-height:1.5;border:0;">'
                              + label + f'<span class="sw-cell-value" style="{value_style}">'
                              + value + '</span></td>')
                column += span
            output.append('</tr>')
        output.append('</tbody></table>')
        return ''.join(output)

    document = re.sub(r"<table\b[^>]*>.*?</table>", data_table, document, flags=re.S)

    def totals(match: re.Match) -> str:
        cells = []
        for item, background, accent in zip(match.groups(),
                ("#eff4f8", "#fff0f1", "#fff6eb"), ("#237e80", "#b91c1c", "#b45309")):
            label, value = item.split("<strong>", 1)
            value = value.replace("</strong>", "")
            cells.append(
                '<!--[if mso]><td width="33%" valign="top"><![endif]-->'
                '<div class="sw-kpi-col" style="display:inline-block;vertical-align:top;width:100%;max-width:340px;">'
                f'<div class="sw-kpi" style="margin:0 4px 10px;padding:12px 16px;background-color:{background};'
                f'border-top:3px solid {accent};border-radius:7px;">'
                f'<div class="sw-kpi-label" style="font-size:12px;line-height:18px;color:#42546a;word-break:normal;">{label}</div>'
                f'<strong class="sw-kpi-value" style="display:block;margin-top:4px;font-size:32px;'
                f'line-height:40px;white-space:nowrap;word-break:normal;overflow-wrap:normal;color:{accent};">'
                f'{value}</strong></div></div><!--[if mso]></td><![endif]-->')
        return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                'style="width:100%;table-layout:fixed;margin:0 0 8px;"><tr><td style="padding:0;font-size:0;">'
                '<!--[if mso]><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><![endif]-->'
                + ''.join(cells) + '<!--[if mso]></tr></table><![endif]--></td></tr></table>')
    piece = r"([^<>]*:\s*<strong>\d+</strong>)"
    document = re.sub(r"<p>\s*" + piece + r"\s*<br\s*/?>\s*" + piece
                      + r"\s*<br\s*/?>\s*" + piece + r"\s*</p>", totals, document, count=1)

    def summaries(match: re.Match) -> str:
        boxes = re.findall(r"<div\b[^>]*>(.*?)</div>", match.group(1), re.S)
        cells = []
        for content in boxes:
            content = re.sub(r"<h3\b[^>]*>",
                '<h3 class="sw-summary-title" style="margin:0 0 8px;font-size:17px;color:#153047;word-break:normal;">', content)
            content = re.sub(r"<p\b[^>]*>",
                '<p style="margin:0;font-size:14px;line-height:1.65;color:#42546a;">', content)
            content = content.replace('<strong>', '<strong style="white-space:nowrap;word-break:normal;">')
            cells.append('<!--[if mso]><td width="50%" valign="top"><![endif]-->'
                         '<div class="sw-summary-col" style="display:inline-block;vertical-align:top;width:100%;max-width:510px;">'
                         '<div style="margin:0 4px 10px;padding:14px 16px;border:1px solid #dce5ed;'
                         'border-radius:7px;background-color:#f5f8fb;">' + content
                         + '</div></div><!--[if mso]></td><![endif]-->')
        return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                'style="width:100%;table-layout:fixed;margin:0 0 12px;"><tr><td style="padding:0;font-size:0;">'
                '<!--[if mso]><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><![endif]-->'
                + ''.join(cells) + '<!--[if mso]></tr></table><![endif]--></td></tr></table>')
    document = re.sub(r'''<div style=['"]display:flex;[^'"]*['"]>\s*((?:<div\b[^>]*>.*?</div>\s*)+)</div>''',
                      summaries, document, count=1, flags=re.S)
    document = re.sub(r"<h3>",
        '<h3 style="margin:24px 0 12px;padding:10px 12px;border-left:4px solid #237e80;'
        'background-color:#eff5f7;font-size:17px;line-height:1.4;color:#153047;word-break:normal;">', document)
    document = re.sub(r"<p>", '<p style="margin:10px 0;font-size:13px;line-height:1.55;color:#42546a;">', document)
    document = document.replace(
        "border:1px solid #d1d5db;border-left:4px solid #6b7280;border-radius:10px;padding:10px 12px;margin:10px 0;background:#fafafa;",
        "border:1px solid #dce5ed;border-left:3px solid #237e80;border-radius:7px;padding:13px 15px;margin:9px 0;background:#ffffff;")
    document = document.replace("margin-top:4px;line-height:1.35;", "margin-top:5px;line-height:1.5;")
    document = document.replace("padding:2px 8px;border-radius:999px;",
                                "padding:3px 8px;border-radius:5px;white-space:nowrap;word-break:normal;overflow-wrap:normal;")
    document = re.sub(r"<a\s+href=", '<a style="color:#166b7c;text-decoration:underline;overflow-wrap:anywhere;" href=', document)
    document = re.sub(r"<head>.*?</head>", "", document, count=1, flags=re.S)
    document = re.sub(r"<html>", '<!DOCTYPE html><html lang="' + html.escape(lang, quote=True) + '"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light"><style>' + css + '</style>'
        '<!--[if mso]><style>' + desktop_css + '</style><![endif]--></head>', document, count=1)
    document = re.sub(r'''<body\b[^>]*>\s*<div\b[^>]*max-width:980px[^>]*>''',
        '<body style="margin:0;padding:12px 6px;background-color:#edf2f6;font-family:Segoe UI,Arial,sans-serif;'
        'font-size:14px;color:#253b50;line-height:1.5;-webkit-text-size-adjust:100%;">'
        '<!-- SecurityWatch Classic rc19b: Mobilfix 1, HTML presentation only -->'
        '<table role="presentation" class="sw-shell" align="center" width="100%" cellpadding="0" cellspacing="0" '
        'style="width:100%;max-width:1100px;table-layout:fixed;margin:0 auto;border:1px solid #dce5ed;border-radius:10px;'
        'background-color:#ffffff;"><tr><td bgcolor="#ffffff" style="padding:0;background-color:#ffffff;">', document, count=1)
    document = re.sub(r"<h2\b[^>]*>(.*?)</h2>",
        lambda m: '<h2 class="sw-title" style="margin:0;padding:18px 16px;border-top:5px solid #237e80;'
        'border-radius:9px 9px 0 0;background-color:#153047;color:#ffffff;font-size:23px;line-height:1.3;'
        'font-weight:700;word-break:normal;">' + m.group(1)
        + '</h2><div class="sw-content" style="padding:16px 12px;">', document, count=1, flags=re.S)
    document = re.sub(r"</div>\s*</body>\s*</html>\s*$", '</div></td></tr></table></body></html>', document)
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--mail-txt", required=True)
    parser.add_argument("--mail-html", required=True)
    parser.add_argument("--env-file")
    parser.add_argument("--lang")
    parser.add_argument("--script-version", default="")
    parser.add_argument("--filesystem-scanned", default="1")
    parser.add_argument("--images-scanned", default="1")
    parser.add_argument("--detail-html")
    parser.add_argument("--detail-txt")
    args = parser.parse_args()

    lang = normalize_lang(args.lang)
    env: Dict[str, str] = {}
    if args.env_file:
        env = parse_env(Path(args.env_file))
        lang = normalize_lang(args.lang or env.get("OUTPUT_LANG") or env.get("LANGUAGE") or env.get("MAIL_LANG"))

    show_host_inventory = env_bool(env, "HOST_PACKAGE_WATCHLIST_IN_REPORT", False)
    mail_host_limit = env_int(env, "MAIL_HOST_FINDINGS_LIMIT", 30, 0, 500)
    mail_backport_limit = env_int(env, "MAIL_BACKPORT_NOTES_LIMIT", mail_host_limit, 0, 500)
    mail_docker_limit = env_int(env, "MAIL_DOCKER_FINDINGS_LIMIT", 10, 0, 500)
    mail_local_limit = env_int(env, "MAIL_LOCAL_IMAGE_FINDINGS_LIMIT", 15, 0, 500)
    filesystem_scanned = option_bool(args.filesystem_scanned, True)
    images_scanned = option_bool(args.images_scanned, True)

    run_dir = Path(args.run_dir)
    run_status = load_run_status(run_dir)
    scan_paths, validation_errors = validated_scan_paths(run_dir, run_status)
    findings, sources, raw_total = collect_findings(run_dir, scan_paths)
    if run_status:
        scans = run_status.get("scans") or {}
        filesystem_scanned = (scans.get("host") or {}).get("status") == "ok"
        images_scanned = (scans.get("images") or {}).get("status") == "ok" or number((scans.get("images") or {}).get("succeeded")) > 0

    host_summary = summarize_group(findings, "host")
    docker_summary = summarize_group(findings, "docker")

    summary = {
        "language": lang,
        "total": len(findings),
        "raw_total": raw_total,
        "duplicates_removed": max(raw_total - len(findings), 0),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "host": host_summary,
        "docker": docker_summary,
        "script_version": args.script_version,
        "scan": {
            "filesystem_scanned": filesystem_scanned,
            "images_scanned": images_scanned,
        },
        "local_built_images": local_image_summary(findings, load_local_built_images(run_dir)),
        "local_built_image_findings": [localize_finding(item, lang) for item in local_image_finding_rows(findings, load_local_built_images(run_dir))],
        "local_built_image_rebuild_results": load_local_image_rebuild_results(run_dir),
        "image_update_results": load_image_update_results(run_dir),
        "host_package_watchlist": load_host_package_watchlist(run_dir),
        "host_debian_backport_notes": load_host_debian_backport_notes(run_dir),
        "findings": [localize_finding(item, lang) for item in findings],
        "docker_aggregated": [localize_aggregate(item, lang) for item in aggregate_findings(findings, "docker")],
        "sources": [localize_source(item, lang) for item in sources],
        "run_status": run_status,
        "image_outcomes": copy.deepcopy(run_status.get("image_outcomes", [])),
        "report_validation_errors": validation_errors,
        "report_path": str(run_dir / "bericht.html"),
        "package_findings": len(findings),
        "distinct_vulnerability_ids": len({f["cve"] for f in findings if f.get("cve") and f["cve"] != "-"}),
        "distinct_cves": len({f["cve"] for f in findings if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(f.get("cve") or ""), re.I)}),
        "count_definition": "Paketfunde zählen Quelle, Schwachstellenkennung, Paket sowie installierte und korrigierte Version. Dieselbe Schwachstelle kann mehrfach vorkommen.",
    }

    decision = mail_decision(summary, env)
    model = decision["model"]
    summary["image_security"] = model["image_security"]
    summary["maintenance"] = model["maintenance"]
    summary["notification"] = {k: decision[k] for k in ("send", "required", "subject")}
    summary["scan"]["complete"] = model["complete"]

    Path(args.summary_json).write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    detail_text = build_text(findings, sources, raw_total, lang, run_dir, args.script_version, show_host_inventory, mail_host_limit, mail_backport_limit, mail_docker_limit, mail_local_limit, filesystem_scanned, images_scanned)
    detail_html = build_html(findings, sources, raw_total, lang, run_dir, args.script_version, show_host_inventory, mail_host_limit, mail_backport_limit, mail_docker_limit, mail_local_limit, filesystem_scanned, images_scanned)
    scan_state = (run_status.get("scans") or {}).get("images") or {}
    if not images_scanned and scan_state.get("status") not in {None, "disabled"}:
        detail_text = detail_text.replace(tr(lang, "docker_scan_disabled"), "Für diesen Lauf liegt keine erfolgreich ausgewertete Image-Prüfung vor.")
        detail_html = detail_html.replace(tr(lang, "docker_scan_disabled"), "Für diesen Lauf liegt keine erfolgreich ausgewertete Image-Prüfung vor.")

    events = collect_events(summary, run_status)
    event_text = ["IMAGES: NEUBAU UND SICHERHEITSSTAND – ALLE ERGEBNISSE", ""]
    event_html = []
    inventory_html = ['<h2>Alle laufenden Images und ihr Sicherheitsstand</h2><p>Die Zahlen gelten je Image; mehrere Container desselben Images werden gemeinsam aufgeführt.</p>']
    for item in model["image_security"]:
        names = item["services"] or item["image"]
        lines = image_security_lines(item)
        body = ''.join(f'<p>{html.escape(line)}</p>' for line in lines)
        inventory_html.append(f'<div style="padding:12px 0;border-top:1px solid #dbe3ec;overflow-wrap:anywhere;"><h3>{html.escape(names)}</h3><p>{html.escape(item["image"])}</p>{body}</div>')
    inventory_html.append('<h2>Voraussetzungen für automatische Aktualisierungen</h2>')
    inventory_html.extend(f'<p>{html.escape(line)}</p>' for line in maintenance_lines(model))
    for group in model["maintenance"]["groups"]:
        affected = html.escape(', '.join(group["containers"]))
        action = f'<p>{html.escape(group["action"])}</p>' if group["action"] else ''
        inventory_html.append(f'<div style="padding:12px 0;border-top:1px solid #dbe3ec;overflow-wrap:anywhere;"><strong>{html.escape(group["reason"])}</strong><p>{affected}</p>{action}</div>')
    for item in model["image_outcomes"]:
        event_text.append(item["image"])
        if item["services"]:
            event_text.append("Dienste: " + item["services"])
        event_text.extend(outcome_lines(item))
        event_text.append("")
        services = f'<p>Dienste: {html.escape(item["services"])}</p>' if item["services"] else ""
        body = ''.join(f'<p>{html.escape(line)}</p>' for line in outcome_lines(item))
        event_html.append(f'<div style="padding:12px 0;border-top:1px solid #dbe3ec;overflow-wrap:anywhere;"><h3>{html.escape(item["image"])}</h3>{services}{body}</div>')
    event_text.extend(["VORGÄNGE DIESES LAUFS", ""])
    for event in events:
        event_text.extend([event["service"] or "SecurityWatch", event["message"]])
        if event["action"]:
            event_text.append("Nächster Schritt: " + event["action"])
        if event["url"]:
            event_text.append(event["url"])
        event_text.append("")
        link = f'<p><a href="{html.escape(event["url"], quote=True)}">Zugehörigen Vorgang öffnen</a></p>' if event["url"] else ""
        action = f'<p><strong>Nächster Schritt:</strong> {html.escape(event["action"])}</p>' if event["action"] else ""
        event_html.append(f'<div style="padding:12px 0;border-top:1px solid #dbe3ec;overflow-wrap:anywhere;"><strong>{html.escape(event["service"] or "SecurityWatch")}</strong><p>{html.escape(event["message"])}</p>{action}{link}</div>')

    coverage_html = ''.join(f'<p>{html.escape(line)}</p>' for line in model["coverage"])
    # Keep the expression outside the f-string for Python 3.11 compatibility.
    events_html = ''.join(event_html) or '<p>Keine gesonderten Vorgänge dokumentiert.</p>'
    inventory_block = ''.join(inventory_html)
    banner = f'<section style="margin:20px auto;padding:20px;max-width:1060px;background:#fff;border:2px solid #526d85;border-radius:10px;font-family:Arial,Helvetica,sans-serif;"><h1>{html.escape(model["headline"])}</h1><p>{html.escape(model["timestamp"])}</p><p>{html.escape(model["intro"])}</p>{coverage_html}<p><strong>Zählweise:</strong> {len(findings)} Paketfunde, {summary["distinct_vulnerability_ids"]} verschiedene Schwachstellenkennungen, darunter {summary["distinct_cves"]} CVE-Kennungen.</p><h2>Vorgänge dieses Laufs</h2>{events_html}{inventory_block}<p>Die folgenden Befundtabellen sind eine priorisierte Auswahl. Sämtliche erfassten Befunde stehen in summary.json.</p></section>'
    detail_html = re.sub(r"(<body\b[^>]*>)", lambda match: match.group(1) + banner, detail_html, count=1, flags=re.I)
    Path(args.detail_txt or run_dir / "bericht.txt").write_text(render_text(model) + "\n" + "\n".join(event_text) + "\n" + detail_text, encoding="utf-8")
    Path(args.detail_html or run_dir / "bericht.html").write_text(detail_html, encoding="utf-8")
    Path(args.mail_txt).write_text(render_text(model), encoding="utf-8")
    Path(args.mail_html).write_text(render_html(model), encoding="utf-8")


if __name__ == "__main__":
    main()
