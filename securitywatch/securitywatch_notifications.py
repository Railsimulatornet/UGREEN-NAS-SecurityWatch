#!/usr/bin/env python3
"""Gemeinsame, rein lokale Darstellung und Versandentscheidung für SecurityWatch.

Dieses Modul verschickt keine Nachrichten und führt keine Docker-Befehle aus.
HTML, Text und Betreff werden aus demselben normalisierten Ergebnis erzeugt.
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from zoneinfo import ZoneInfo


ERROR_STATUSES = {
    "failed", "build_failed", "pull_failed", "up_failed", "recreate_failed",
    "verification_failed", "rollback_failed", "rolled_back", "scan_failed",
    "cleanup_failed", "retention_failed", "unhealthy", "recovery_required",
}
UPDATE_STATUSES = {
    "update_applied", "applied", "updated", "rebuilt", "rebuilt_and_fixed",
    "rebuilt_still_vulnerable", "deployed", "success",
}
WAIT_STATUSES = {
    "candidate_not_improved", "skipped_cooldown", "no_fixed_version",
    "awaiting_release", "awaiting_fix", "blocked_by_policy",
}
WARNING_STATUSES = WAIT_STATUSES | {
    "update_available", "recreate_skipped", "digest_pinned", "unknown_origin",
    "missing_recipe", "missing_healthcheck", "no_healthcheck", "needs_config",
    "rebuilt_pending_rescan", "regression", "candidate_rejected", "overdue",
    "workflow_failed", "partial", "incomplete", "scan_incomplete",
}
STATUS_TEXT = {
    "failed": "Der Vorgang konnte nicht abgeschlossen werden.",
    "build_failed": "Das neue Image konnte nicht gebaut werden.",
    "pull_failed": "Die neue Image-Version konnte nicht geprüft oder geladen werden.",
    "up_failed": "Der Dienst konnte nach der Aktualisierung nicht gestartet werden.",
    "recreate_failed": "Der Dienst konnte nicht mit der neuen Version eingerichtet werden.",
    "verification_failed": "Die Prüfung nach der Aktualisierung ist fehlgeschlagen.",
    "rollback_failed": "Die vorherige Version konnte nicht vollständig wiederhergestellt werden.",
    "rolled_back": "Die Aktualisierung ist fehlgeschlagen; die vorherige Version wurde wiederhergestellt.",
    "scan_failed": "Die Sicherheitsprüfung ist fehlgeschlagen.",
    "cleanup_failed": "Die vorgesehene Bereinigung konnte nicht abgeschlossen werden.",
    "retention_failed": "Die Aufbewahrung oder Bereinigung konnte nicht vollständig geprüft werden.",
    "unhealthy": "Die Zustandsprüfung des Dienstes meldet einen Fehler.",
    "recovery_required": "Ein früherer Aktualisierungsvorgang ist noch ungeklärt.",
    "update_applied": "Die neue Version wurde übernommen und erfolgreich geprüft.",
    "applied": "Die neue Version wurde übernommen und erfolgreich geprüft.",
    "updated": "Die neue Version wurde übernommen und erfolgreich geprüft.",
    "deployed": "Die neue Version wurde übernommen und erfolgreich geprüft.",
    "success": "Der Vorgang wurde erfolgreich abgeschlossen.",
    "rebuilt": "Das Image wurde neu gebaut und übernommen.",
    "rebuilt_and_fixed": "Das Image wurde neu gebaut; die zuvor festgestellten Zielbefunde sind behoben.",
    "rebuilt_still_vulnerable": "Das Image wurde neu gebaut; Sicherheitsbefunde sind weiterhin vorhanden.",
    "rebuilt_pending_rescan": "Das Image wurde übernommen; die abschließende Sicherheitsprüfung steht noch aus.",
    "candidate_not_improved": "Der Neubau brachte keine nachgewiesene Sicherheitsverbesserung und wurde nicht übernommen.",
    "skipped_cooldown": "Der nächste Neubau wird nach der vorgesehenen Wartefrist erneut geprüft.",
    "no_fixed_version": "Für diesen Befund ist noch keine korrigierte Version bekannt.",
    "awaiting_release": "Die benötigte neue Image-Version wurde noch nicht veröffentlicht.",
    "awaiting_fix": "Eine geeignete Korrektur steht noch aus.",
    "blocked_by_policy": "Die automatische Übernahme ist für diesen Dienst zurückgestellt.",
    "update_available": "Eine neue Image-Version ist verfügbar und wurde noch nicht übernommen.",
    "recreate_skipped": "Eine automatische Übernahme war mit den vorhandenen Angaben nicht möglich.",
    "digest_pinned": "Die Image-Version ist fest vorgegeben; eine neue Version erfordert eine kontrollierte Anpassung der Konfiguration.",
    "unknown_origin": "Die Herkunft und der vorgesehene Aktualisierungsweg des Images sind noch nicht eindeutig zugeordnet.",
    "missing_recipe": "Für dieses Image fehlt eine verwendbare Bauanleitung.",
    "missing_healthcheck": "Für die automatische Übernahme fehlt eine aussagekräftige Zustandsprüfung.",
    "no_healthcheck": "Für die automatische Übernahme fehlt eine aussagekräftige Zustandsprüfung.",
    "needs_config": "Für diesen Dienst müssen die Angaben zur Aktualisierung ergänzt werden.",
    "regression": "Der Kandidat enthält neue hohe oder kritische Sicherheitsbefunde und wurde nicht übernommen.",
    "candidate_rejected": "Der Kandidat hat die erforderlichen Prüfungen nicht bestanden und wurde nicht übernommen.",
    "overdue": "Ein erwarteter Prüflauf oder eine Veröffentlichung ist überfällig.",
    "workflow_failed": "Der zugehörige GitHub-Arbeitsablauf ist fehlgeschlagen.",
    "partial": "Der Vorgang konnte nur teilweise geprüft werden.",
    "incomplete": "Die Prüfung ist unvollständig.",
    "scan_incomplete": "Die Sicherheitsprüfung ist unvollständig.",
    "up_to_date": "Die verwendete Version ist für die geprüfte Quelle aktuell.",
    "unchanged": "Die geprüfte Image-Version hat sich nicht geändert.",
    "no_change": "Die geprüfte Image-Version hat sich nicht geändert.",
    "skipped": "Für diesen Dienst wurde keine Änderung ausgeführt.",
    "disabled": "Dieser Prüfschritt ist deaktiviert.",
    "local_image": "Das Image wird aus einer lokalen Bauanleitung gepflegt.",
}


def text(value: Any, limit: int = 600) -> str:
    """Begrenzter Anzeigetext; keine mehrzeiligen Protokolle in der Hauptmail."""
    value = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def number(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def enabled(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def safe_url(value: Any) -> str:
    value = str(value or "").strip()
    if not value or len(value) > 1500 or re.search(r"[\x00-\x20\x7f]", value):
        return ""
    try:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            return ""
        # Abfrageparameter werden nicht in Benachrichtigungen übernommen: darin
        # können Zugriffsschlüssel stehen. GitHub-Vorgänge haben stabile Pfade.
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", parts.fragment))
    except ValueError:
        return ""


def local_time(value: Any) -> str:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return text(value, 60) + " (Zeitzone nicht angegeben)"
        return dt.astimezone(ZoneInfo("Europe/Berlin")).strftime("%d.%m.%Y, %H:%M Uhr")
    except (TypeError, ValueError, OverflowError):
        return "Zeitpunkt nicht dokumentiert"


def _event(raw: dict[str, Any], kind: str = "") -> dict[str, str]:
    status = text(raw.get("status") or raw.get("result"), 80)
    severity = str(raw.get("severity") or "").lower()
    if status in ERROR_STATUSES:
        severity = "error"
    elif status in WARNING_STATUSES and severity != "error":
        severity = "warning"
    elif severity not in {"info", "warning", "error"}:
        severity = "warning" if status in WARNING_STATUSES else "info"
    # Alte englische Detailprotokolle werden bewusst nicht als Mailtext benutzt.
    message = text(raw.get("message")) or STATUS_TEXT.get(status, "Ein weiterer Vorgang ist im Detailbericht dokumentiert.")
    action = text(raw.get("action"), 400)
    if not action and severity == "error":
        action = "Den zugehörigen Vorgang und die Diagnose im Berichtsordner prüfen."
    return {
        "kind": text(raw.get("kind") or kind, 40),
        "status": status,
        "severity": severity,
        "service": text(raw.get("service") or raw.get("container") or raw.get("project") or raw.get("image"), 160),
        "project": text(raw.get("project"), 140),
        "image": text(raw.get("image"), 240),
        "message": message,
        "action": action,
        "url": safe_url(raw.get("url")),
    }


def collect_events(summary: dict[str, Any], status: dict[str, Any]) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    seen: set[tuple[str, ...]] = set()
    structured = status.get("events")
    rows = [(r, "") for r in structured if isinstance(r, dict)] if isinstance(structured, list) else []
    # Vorhandene Versionen ohne Ereignismodell bleiben lesbar. Sobald ein
    # strukturiertes Modell vorliegt, ist es die maßgebliche Ereignisquelle.
    if not isinstance(structured, list):
        for key, kind in (("local_built_image_rebuild_results", "local"), ("image_update_results", "registry")):
            rows.extend((r, kind) for r in summary.get(key, []) if isinstance(r, dict))
    for raw, kind in rows:
        event = _event(raw, kind)
        key = tuple(event[k] for k in ("kind", "status", "service", "image", "message"))
        if key not in seen:
            seen.add(key)
            events.append(event)
    return events


def image_outcomes(status: dict[str, Any]) -> list[dict[str, Any]]:
    """Bau, Übernahme und der anschließend laufende Stand bleiben getrennt."""
    raw_outcomes = status.get("image_outcomes")
    if not isinstance(raw_outcomes, list):
        return []
    outcomes = []
    for raw in raw_outcomes:
        if not isinstance(raw, dict):
            continue
        services = raw.get("services")
        if isinstance(services, list):
            service_text = ", ".join(text(s, 100) for s in services)
        else:
            service_text = text(services or raw.get("service"), 300)
        outcome = {
            "image": text(raw.get("image") or "Image ohne dokumentierten Namen", 240),
            "services": text(service_text, 300),
            "build_status": text(raw.get("build_status"), 50),
            "deployment_status": text(raw.get("deployment_status"), 50),
            "verification_status": text(raw.get("verification_status"), 50),
            "message": text(raw.get("message"), 400),
            "action": text(raw.get("action"), 300),
            "comparison_scope": raw.get("comparison_scope"),
            "historical_update": raw.get("historical_update") is True,
            "historical_only": raw.get("historical_only") is True,
            "earlier_updates": [text(value, 400) for value in raw.get("earlier_updates", []) if isinstance(value, str)]
                               if isinstance(raw.get("earlier_updates"), list) else [],
        }
        for name in ("before", "candidate", "after"):
            counts = raw.get(name)
            outcome[name] = {
                field: number(counts[field]) if counts.get(field) is not None else None
                for field in ("critical", "high", "total", "fixable")
            } if isinstance(counts, dict) else None
        for field in ("resolved", "new", "remaining"):
            outcome[field] = number(raw[field]) if raw.get(field) is not None else None
        outcomes.append(outcome)
    # Tatsächlich angegangene Änderungen stehen vor nur inventarisierten Images.
    outcomes.sort(key=lambda item: (
        0 if item["deployment_status"] == "failed" or item["build_status"] == "failed" else
        1 if item["build_status"] == "succeeded" or item["deployment_status"] in {"applied", "rolled_back"} else 2,
        item["image"],
    ))
    return outcomes


def _objects(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _names(value: Any, limit: int = 180) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return sorted({text(item, limit) for item in values if isinstance(item, str) and text(item, limit)})


def _has_fix(item: dict[str, Any]) -> bool:
    return text(item.get("fixed")).lower() not in {"", "-", "unknown", "not available", "n/a"}


def image_security(summary: dict[str, Any], status: dict[str, Any]) -> list[dict[str, Any]]:
    """Aktueller Befundstand je geprüftem Image, auch ohne Aktualisierung.

    Die Ergebnisdatei verbindet die feste Image-ID mit den Befunden. Anzeigenamen
    sind nur für ältere Berichtsdaten ein Ersatz, wenn ihre Zuordnung eindeutig
    ist. Mehrere Container desselben Images vervielfachen die Zahlen nicht.
    """
    scans = status.get("scans") if isinstance(status.get("scans"), dict) else {}
    images = scans.get("images") if isinstance(scans.get("images"), dict) else {}
    sources = [item for item in _objects(summary.get("sources")) if item.get("group") == "docker"]
    by_file = {str(item.get("file")): item for item in sources if item.get("file")}
    source_files: dict[str, set[str]] = {}
    for source in sources:
        source_files.setdefault(str(source.get("source_internal") or source.get("source") or ""), set()).add(str(source.get("file") or ""))
    findings = [item for item in _objects(summary.get("findings")) if item.get("group") == "docker"]
    maintenance = status.get("maintenance") if isinstance(status.get("maintenance"), dict) else {}
    maintenance_items = _objects(maintenance.get("items"))
    local_refs = {str(item.get("image")) for item in _objects(summary.get("local_built_images"))}
    rows = []
    for raw in _objects(images.get("items")):
        filename = str(raw.get("file") or "")
        source = by_file.get(filename)
        name = str((source or {}).get("source_internal") or (source or {}).get("source") or "")
        selected = [item for item in findings if (
            item.get("source_file") == filename if item.get("source_file") else
            str(item.get("source_internal") or item.get("source") or "") == name and len(source_files.get(name, set())) == 1
        )]
        unambiguous = len(source_files.get(name, set())) <= 1 or all(
            item.get("source_file") for item in findings
            if str(item.get("source_internal") or item.get("source") or "") == name
        )
        confirmed = raw.get("status") == "ok" and source is not None and unambiguous and number(source.get("unique_findings")) == len(selected)
        refs = _names(raw.get("references"), 260)
        containers = _names(raw.get("containers"))
        image_id = text(raw.get("image_id"), 80)
        related = [item for item in maintenance_items if (
            image_id and item.get("image_id") == image_id or
            item.get("container") in containers or item.get("image") in refs
        )]
        local = any(item.get("kind") == "local" for item in related) or bool(set(refs) & local_refs)
        counts = {
            "critical": sum(item.get("severity") == "CRITICAL" for item in selected),
            "high": sum(item.get("severity") == "HIGH" for item in selected),
            "total": len(selected),
            "fixable": sum(_has_fix(item) for item in selected),
        } if confirmed else {"critical": None, "high": None, "total": None, "fixable": None}
        rows.append({
            "image_id": image_id,
            "image": text(" / ".join(refs) or name.removeprefix("Docker-Image: ") or image_id or "Image ohne dokumentierten Namen", 360),
            "containers": containers,
            "services": text(", ".join(containers), 600),
            "state": "ok" if confirmed else "unknown",
            "local": local,
            "counts": counts,
            "blocked": any(item.get("eligible") is False for item in related),
            "separate_update_path": any(item.get("separate_update_path") is True for item in related),
        })
    rows.sort(key=lambda item: (0 if item["state"] != "ok" else 1, -number(item["counts"]["critical"]), -number(item["counts"]["high"]), item["image"]))
    return rows


def image_security_lines(item: dict[str, Any]) -> list[str]:
    if item["state"] != "ok":
        return ["Sicherheitsstand unbekannt: kein vollständig bestätigtes Prüfergebnis."]
    values = item["counts"]
    line = f"{values['critical']} kritisch · {values['high']} hoch · {values['fixable']} mit bekannter Korrektur"
    flags = []
    if item["local"]:
        flags.append("lokaler Eigenbau")
    if item.get("separate_update_path"):
        flags.append("eigener Aktualisierungsweg")
    elif item["blocked"]:
        flags.append("automatischer Austausch zurückgestellt")
    label = " · ".join(flags)
    return [line] + ([label[0].upper() + label[1:]] if label else [])


def maintenance_overview(status: dict[str, Any]) -> dict[str, Any]:
    raw = status.get("maintenance") if isinstance(status.get("maintenance"), dict) else {}
    items = _objects(raw.get("items"))
    grouped: dict[str, dict[str, Any]] = {}
    for item in items:
        if item.get("eligible") is not False:
            continue
        reason = text(item.get("reason") or "Die Angaben für eine automatische Aktualisierung fehlen.", 240)
        group = grouped.setdefault(reason, {"reason": reason, "containers": [], "action": text(item.get("action"), 240)})
        label = text(item.get("container") or item.get("image") or "Unbenannter Dienst", 150)
        if label not in group["containers"]:
            group["containers"].append(label)
    groups = sorted(grouped.values(), key=lambda item: (-len(item["containers"]), item["reason"]))
    for group in groups:
        group["containers"].sort()
    return {
        "status": text(raw.get("status"), 30),
        "eligible": sum(item.get("eligible") is True for item in items),
        "blocked": sum(item.get("eligible") is False for item in items),
        "local_eligible": sum(item.get("eligible") is True and item.get("kind") == "local" for item in items),
        "local_blocked": sum(item.get("eligible") is False and item.get("kind") == "local" for item in items),
        "local_buildable": sum(item.get("build_allowed") is True and item.get("kind") == "local" for item in items),
        "build_known": all("build_allowed" in item for item in items if item.get("kind") == "local"),
        "groups": groups,
    }


def host_excerpt(summary: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for raw in _objects(summary.get("findings")):
        if raw.get("group") != "host" or raw.get("severity") not in {"CRITICAL", "HIGH"}:
            continue
        identifier = text(raw.get("cve"), 60)
        if not identifier or identifier == "-":
            continue
        item = grouped.setdefault(identifier, {"id": identifier, "severity": raw.get("severity"), "packages": set(), "versions": set(), "fixed": set(), "targets": set(), "url": safe_url(raw.get("primary_url")), "score": 0, "records": []})
        item["records"].append(raw)
        if raw.get("severity") == "CRITICAL":
            item["severity"] = "CRITICAL"
        item["packages"].add(text(raw.get("pkg"), 70))
        item["versions"].add(text(raw.get("installed"), 80))
        item["targets"].add(text(raw.get("target"), 100))
        if _has_fix(raw):
            item["fixed"].add(text(raw.get("fixed"), 120))
        if isinstance(raw.get("score"), (int, float)):
            item["score"] = max(item["score"], raw["score"])
    ordered = sorted(grouped.values(), key=lambda item: (item["severity"] != "CRITICAL", not item["fixed"], -item["score"], item["id"]))
    for item in ordered:
        # Different packages may share a CVE but require unrelated corrections.
        # Show one coherent group; never attribute its fixed version to another
        # affected package that has no known correction.
        representative = next((row for row in item["records"] if _has_fix(row)), item["records"][0])
        correction = text(representative.get("fixed"), 120) if _has_fix(representative) else ""
        matching = [row for row in item["records"] if (text(row.get("fixed"), 120) if _has_fix(row) else "") == correction]
        item["additional_packages"] = len(matching) < len(item["records"])
        item["packages"] = {text(row.get("pkg"), 70) for row in matching}
        item["versions"] = {text(row.get("installed"), 80) for row in matching}
        item["fixed"] = {correction} if correction else set()
        item["targets"] = {text(row.get("target"), 100) for row in matching}
        del item["records"]
        for key in ("packages", "versions", "fixed", "targets"):
            values = sorted(value for value in item[key] if value)
            item[key] = text(", ".join(values[:3]) + (f" (+{len(values) - 3} weitere)" if len(values) > 3 else ""), 240)
    return ordered[:limit]


def host_excerpt_lines(item: dict[str, Any]) -> list[str]:
    severity = "kritisch" if item["severity"] == "CRITICAL" else "hoch"
    lines = [f"{item['id']} · {severity} · {item['packages']}", "Installiert: " + (item["versions"] or "nicht dokumentiert")]
    lines.append("Laut Prüfdaten korrigiert ab: " + item["fixed"] if item["fixed"] else "Noch keine korrigierte Paketversion in den Prüfdaten.")
    if item.get("additional_packages"):
        lines.append("Weitere betroffene Paketstände zu dieser Kennung stehen im Detailbericht.")
    return lines


def overview_lines(model: dict[str, Any]) -> list[str]:
    lines = [f"Docker-Images: {model['image_critical']} kritisch · {model['image_high']} hoch"]
    if model["host_status"] == "ok":
        lines.append(f"NAS / UGOS Pro: {model['host_critical']} kritisch · {model['host_high']} hoch")
    else:
        lines.append("NAS / UGOS Pro: " + ("Prüfung deaktiviert." if model["host_status"] == "disabled" else "kein bestätigtes Prüfergebnis."))
    if model["report_only"]:
        lines.append("Reiner Berichtslauf: keine Anwendungsimages neu gebaut oder ausgetauscht.")
    else:
        lines.append(f"Bei diesem Lauf: {model['built_count']} Images neu gebaut · {model['update_count']} Images übernommen und geprüft.")
    if model.get("historical_update_count"):
        lines.append(f"Nachgemeldet: {model['historical_update_count']} bereits vor diesem Lauf ausgeführte Image-Übernahmen.")
    if not model["complete"]:
        lines.append("Die Zahlen enthalten nur auswertbare Ergebnisse. Fehlende Prüfungen sind kein Nachweis für einen sicheren Stand.")
    return lines


def host_summary_lines(model: dict[str, Any]) -> list[str]:
    if model["host_status"] != "ok":
        return ["Die NAS-Prüfung ist deaktiviert." if model["host_status"] == "disabled" else "Für das NAS-Dateisystem liegt kein bestätigtes Prüfergebnis vor."]
    return [f"{model['host_critical']} kritisch · {model['host_high']} hoch · {model['host_fixable']} mit bekannter Paketkorrektur"]


def maintenance_lines(model: dict[str, Any]) -> list[str]:
    maintenance = model["maintenance"]
    if maintenance["status"] != "ok":
        return ["Die Voraussetzungen für automatische Aktualisierungen wurden in diesem Lauf nicht vollständig erfasst."]
    lines = [f"{maintenance['eligible']} Dienste für die automatische Übernahme geeignet · {maintenance['blocked']} zurückgestellt."]
    if maintenance["build_known"]:
        lines.append(f"Lokale Eigenbauten: {maintenance['local_buildable']} Dienste neu baubar · {maintenance['local_eligible']} automatisch übernehmbar.")
    else:
        lines.append(f"Lokale Eigenbauten: {maintenance['local_eligible']} Dienste für die Übernahme geeignet · {maintenance['local_blocked']} zurückgestellt.")
    lines.append("Die Übernahme erfolgt erst nach Sicherheits- und Funktionsprüfung. Ein erfolgreich gebauter Kandidat allein repariert den laufenden Dienst noch nicht.")
    return lines


def outcome_lines(item: dict[str, Any]) -> list[str]:
    if item.get("historical_only"):
        return [item["message"], "Die aktuelle Sicherheitslage steht in der Image-Übersicht. Für diese frühere Übernahme wird kein Vorher/Nachher-Ergebnis behauptet."]
    build = {"succeeded": "erfolgreich", "failed": "fehlgeschlagen", "not_attempted": "nicht ausgeführt"}.get(item["build_status"], "nicht dokumentiert")
    deployment = {
        "applied": "neue Version übernommen",
        "rolled_back": "Rückkehr zur vorherigen Version",
        "kept_previous": "bisherige Version beibehalten",
        "failed": "Übernahme oder Wiederherstellung fehlgeschlagen",
    }.get(item["deployment_status"], "nicht dokumentiert")
    verification = {"ok": "erfolgreich", "failed": "fehlgeschlagen", "not_run": "nicht ausgeführt"}.get(item["verification_status"], "nicht dokumentiert")
    lines = [f"Neubau: {build}. Übernahme: {deployment}.", f"Funktionsprüfung: {verification}."]
    if item.get("historical_update"):
        lines.insert(0, "Frühere Übernahme · mit der Prüfgrundlage dieses Laufs nachgeprüft.")
    lines.extend(item.get("earlier_updates", []))

    def counts(label: str, values: dict[str, Any]) -> str:
        n = lambda key: str(values[key]) if values.get(key) is not None else "nicht ermittelt"
        return f"{label}: {n('critical')} kritisch · {n('high')} hoch · {n('fixable')} behebbar (Paketfunde)."

    if item["before"] is not None:
        lines.append(counts("Ausgangsversion", item["before"]))
    if item["candidate"] is not None and (item["deployment_status"] != "applied" or item["after"] is None):
        lines.append(counts("Geprüfter Kandidat", item["candidate"]))
    if item["after"] is not None:
        lines.append(counts("Tatsächlich laufende Version", item["after"]))
        if item["after"]["total"] == 0:
            lines.append("Im geprüften laufenden Image wurden keine Paketfunde gemeldet.")
        elif item["after"]["total"] is not None and item["after"]["total"] > 0:
            lines.append("Im laufenden Image sind weiterhin Sicherheitsbefunde vorhanden.")
            if item["after"]["fixable"] == 0:
                lines.append("Für diese verbleibenden Befunde meldet die Prüfung noch keine korrigierte Paketversion.")
    else:
        lines.append("Für den anschließend laufenden Stand liegt kein bestätigtes Sicherheitsprüfergebnis vor.")
    scope = item["comparison_scope"]
    if scope is None and item["deployment_status"] == "applied" and item["after"] is not None:
        scope = "running"
    if scope in {"candidate", "running"} and all(item[key] is not None for key in ("resolved", "new", "remaining")):
        label = "Kandidatenvergleich" if scope == "candidate" else "Vergleich des laufenden Images"
        lines.append(f"{label} nach Paket und Schwachstellenkennung: {item['resolved']} behoben · {item['new']} neu · {item['remaining']} weiterhin vorhanden.")
    if item["message"]:
        lines.append(item["message"])
    if item["action"]:
        lines.append("Nächster Schritt: " + item["action"])
    return lines


def build_model(summary: dict[str, Any], run_status: dict[str, Any] | None = None, env: dict[str, Any] | None = None) -> dict[str, Any]:
    env = env or {}
    raw = run_status if run_status is not None else summary.get("run_status")
    status = raw if isinstance(raw, dict) else {}
    run = status.get("run") if isinstance(status.get("run"), dict) else {}
    scans = status.get("scans") if isinstance(status.get("scans"), dict) else {}
    host = scans.get("host") if isinstance(scans.get("host"), dict) else {}
    images = scans.get("images") if isinstance(scans.get("images"), dict) else {}
    retention = status.get("retention") if isinstance(status.get("retention"), dict) else {}
    github = status.get("github") if isinstance(status.get("github"), dict) else {}
    events = collect_events(summary, status)
    outcomes = image_outcomes(status)
    security = image_security(summary, status)
    maintenance = maintenance_overview(status)
    for outcome in outcomes:
        bad_status = "build_failed" if outcome["build_status"] == "failed" else "failed" if outcome["deployment_status"] == "failed" else "verification_failed" if outcome["verification_status"] == "failed" else ""
        if bad_status and not any(e["severity"] == "error" and e["image"] == outcome["image"] for e in events):
            events.append(_event({"kind": "image", "status": bad_status, "image": outcome["image"], "service": outcome["services"] or outcome["image"], "message": outcome["message"] or STATUS_TEXT[bad_status], "action": outcome["action"]}))

    expected = number(images.get("expected"))
    succeeded = number(images.get("succeeded"))
    failed = number(images.get("failed"))
    host_state = host.get("status", "unknown")
    image_state = images.get("status", "unknown")
    run_state = run.get("status", "unknown")
    coverage_known = status.get("version") == 1
    host_complete = host_state in {"ok", "disabled"}
    image_complete = image_state == "disabled" or (
        image_state == "ok" and expected == succeeded and failed == 0
    )
    items = images.get("items")
    if isinstance(items, list) and image_state != "disabled":
        image_complete = image_complete and len(items) == expected and all(
            isinstance(item, dict) and item.get("status") == "ok" for item in items
        )
    elif image_state != "disabled" and expected > 0:
        image_complete = False
    no_scan = host_state == "disabled" and image_state == "disabled"
    validation_errors = summary.get("report_validation_errors") or []
    complete = coverage_known and run_state == "completed" and host_complete and image_complete and not validation_errors and not no_scan and github.get("status") not in {"partial", "failed"}

    if run_state == "failed" and not any(e["kind"] == "run" and e["severity"] == "error" for e in events):
        events.insert(0, _event({"kind": "run", "status": "failed", "service": "SecurityWatch", "message": "Der Wartungslauf wurde vorzeitig beendet. Die erfassten Teilergebnisse sind im Bericht enthalten.", "action": "Das Laufprotokoll prüfen; die fehlenden Prüfungen sind noch offen."}))
    if retention.get("errors") and not any(e["kind"] == "retention" and e["severity"] == "error" for e in events):
        events.append(_event({"kind": "retention", "status": "retention_failed", "service": "Aufbewahrung", "action": "Den Aufbewahrungsstatus prüfen. Geschützte Vorversionen müssen erhalten bleiben."}))
    if github.get("status") in {"failed", "partial"} and not any(e["kind"] == "github" and e["severity"] in {"error", "warning"} for e in events):
        events.append(_event({"kind": "github", "status": "partial", "service": "GitHub", "message": "Die GitHub-Prüfung konnte nicht vollständig abgeschlossen werden.", "action": "Verbindung, Zugriffsrechte und die zugeordneten Projekte prüfen."}))

    notices = [e for e in events if e["severity"] in {"error", "warning"}]
    errors = [e for e in notices if e["severity"] == "error"]
    notices.sort(key=lambda e: (0 if e["severity"] == "error" else 1, e["service"], e["message"]))
    updated = [e for e in events if e["status"] in UPDATE_STATUSES and e["severity"] != "error"]
    updated_keys = {e["image"] or (e["project"] + "/" + e["service"]) for e in updated}
    applied_outcomes = [item for item in outcomes if item["deployment_status"] == "applied" and item["verification_status"] == "ok"
                        and not item["historical_update"]]
    if outcomes:
        update_count = len({item["image"] for item in applied_outcomes})
    else:
        update_count = len(updated_keys)
    built_count = len({item["image"] for item in outcomes if item["build_status"] == "succeeded"})
    historical_update_count = len(_objects(status.get("project_updates")))
    waiting = [e for e in notices if e["status"] in WAIT_STATUSES and not e["action"]]
    actions = [e for e in notices if e not in waiting]
    total = number(summary.get("total"))
    critical, high = number(summary.get("critical")), number(summary.get("high"))
    findings = [f for f in summary.get("findings", []) if isinstance(f, dict)]
    identifiers = {str(f.get("cve") or f.get("VulnerabilityID") or "") for f in findings} - {"", "-"}
    distinct = number(summary.get("distinct_vulnerability_ids", len(identifiers)))
    cves = number(summary.get("distinct_cves", sum(bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", c, re.I)) for c in identifiers)))

    if errors:
        headline, level = "Handlung erforderlich", "error"
        intro = "Mindestens ein Vorgang ist fehlgeschlagen oder benötigt eine gezielte Prüfung."
    elif not complete:
        headline, level = "Prüfung unvollständig", "warning"
        intro = "Der erfolgreiche Abschluss aller vorgesehenen Prüfungen ist nicht nachgewiesen."
    elif update_count:
        headline, level = "Aktualisierungen durchgeführt", "warning" if total else "success"
        intro = "Die aufgeführten neuen Versionen wurden übernommen und geprüft. Verbleibende Befunde stehen bei den laufenden Images."
    elif built_count:
        headline, level = "Neubauten geprüft", "warning"
        intro = "Die neu gebauten Images und die tatsächlich verwendeten Versionen stehen unten getrennt."
    elif total:
        headline, level = "Sicherheitsbefunde vorhanden", "error" if critical else "warning"
        intro = "Die Prüfung ist abgeschlossen. Die betroffenen Container und die wichtigsten NAS-Befunde stehen unten."
    elif notices or maintenance["blocked"]:
        headline, level = "Aufgaben offen", "warning"
        intro = "Die Sicherheitsprüfung ist abgeschlossen. Für automatische Aktualisierungen stehen noch Schritte aus."
    elif historical_update_count:
        headline, level = "Frühere Aktualisierungen nachgemeldet", "success"
        intro = "Die aufgeführten Übernahmen erfolgten bereits vor diesem Lauf. Ihr Zeitpunkt und der aktuell geprüfte Stand stehen unten."
    else:
        headline, level = "Prüfung abgeschlossen", "success"
        intro = "In den erfolgreich geprüften Quellen wurden keine Befunde der ausgewählten Schweregrade gemeldet."

    if image_state == "disabled":
        image_line = "Image-Prüfung: deaktiviert."
    elif coverage_known:
        image_line = f"Images: {succeeded} von {expected} erfolgreich geprüft"
        if failed:
            image_line += f"; {failed} Prüfungen fehlgeschlagen"
        image_line += "."
    else:
        image_line = "Images: Vollständigkeit für diesen Bericht nicht nachgewiesen."
    host_line = {
        "ok": "NAS-Dateisystem: Sicherheitsprüfung erfolgreich abgeschlossen.",
        "disabled": "NAS-Dateisystem: Prüfung deaktiviert.",
        "failed": "NAS-Dateisystem: Sicherheitsprüfung fehlgeschlagen.",
    }.get(host_state, "NAS-Dateisystem: Prüfergebnis nicht nachgewiesen.")
    coverage = [image_line, host_line]
    if validation_errors:
        coverage.append(f"Berichtsauswertung: {len(validation_errors)} erwartete Ergebnisse fehlen oder sind ungültig.")
    if not coverage_known:
        coverage.append("Für diesen älteren oder unvollständigen Lauf fehlt ein verlässlicher Abschlussnachweis.")
    if run_state in {"running", "partial", "failed"}:
        coverage.append({"running": "Der Lauf ist noch nicht als abgeschlossen dokumentiert.", "partial": "Der Lauf wurde mit unvollständigen Ergebnissen beendet.", "failed": "Der Lauf wurde vorzeitig beendet."}[run_state])
    if no_scan:
        coverage.append("Für diesen Lauf wurde keine Sicherheitsprüfung ausgeführt.")

    retention_lines: list[str] = []
    if retention:
        days = number(retention.get("days", 7))
        retention_lines.append(f"Vorversionen bleiben mindestens {days} volle Tage nach erfolgreichem Austausch geschützt.")
        retention_lines.append(f"Geschützte Vorversionen: {number(retention.get('protected'))}. Bei diesem Lauf entfernt: {number(retention.get('removed'))}.")
        if retention.get("next_expiry"):
            retention_lines.append("Nächste frühestmögliche Freigabe: " + local_time(retention["next_expiry"]) + ".")
        retention_lines.append("Weiter verwendete Images und ungeklärte Wiederherstellungen bleiben geschützt.")
    else:
        retention_lines.append("Für diesen Lauf ist kein bestätigter Aufbewahrungsstatus vorhanden.")
    report_retention = status.get("report_retention") if isinstance(status.get("report_retention"), dict) else {}
    if report_retention.get("status") == "ok":
        retention_lines.append(f"Berichte: {number(report_retention.get('days'))} Tage, mindestens die letzten {number(report_retention.get('keep_last'))} Läufe. Bei diesem Lauf entfernt: {number(report_retention.get('removed'))}.")
    elif report_retention.get("status") == "partial":
        retention_lines.append(f"Berichtsbereinigung unvollständig: {number(report_retention.get('removed'))} entfernt; {number(report_retention.get('errors'))} Vorgänge konnten nicht abgeschlossen werden.")
    elif report_retention.get("status") == "disabled":
        retention_lines.append("Berichtsbereinigung: für diesen Lauf deaktiviert.")
    elif report_retention.get("status") == "deferred":
        retention_lines.append("Berichtsbereinigung: wegen einer noch offenen Wiederherstellung zurückgestellt.")

    github_line = {
        "ok": "GitHub: Die konfigurierten Projekte wurden geprüft.",
        "disabled": "GitHub: Für diesen Lauf nicht geprüft.",
        "partial": "GitHub: Prüfung nur teilweise abgeschlossen.",
        "failed": "GitHub: Prüfung fehlgeschlagen.",
    }.get(github.get("status"), "GitHub: Kein Prüfergebnis dokumentiert.")
    return {
        "headline": headline, "level": level, "intro": intro, "complete": complete,
        "actions": actions, "waiting": waiting, "completed": updated,
        "image_outcomes": outcomes,
        "mail_outcomes": [item for item in outcomes if item["build_status"] in {"succeeded", "failed"} or item["deployment_status"] in {"applied", "rolled_back", "failed"} or item["candidate"] is not None or item["earlier_updates"]],
        "image_security": security,
        "affected_images": [item for item in security if item["state"] != "ok" or number(item["counts"]["critical"]) or number(item["counts"]["high"])],
        "clean_images": sum(item["state"] == "ok" and not number(item["counts"]["critical"]) and not number(item["counts"]["high"]) for item in security),
        "maintenance": maintenance,
        "host_excerpt": host_excerpt(summary) if host_state == "ok" else [],
        "report_only": run.get("mode") == "report_only",
        "error_count": len(errors), "notice_count": len(notices), "update_count": update_count,
        "built_count": built_count,
        "historical_update_count": historical_update_count,
        "total": total, "critical": critical, "high": high,
        "distinct": distinct, "distinct_cves": cves,
        "host_total": number((summary.get("host") or {}).get("total")),
        "host_status": host_state,
        "host_critical": number((summary.get("host") or {}).get("critical")),
        "host_high": number((summary.get("host") or {}).get("high")),
        "host_fixable": sum(_has_fix(item) for item in findings if item.get("group") == "host"),
        "image_total": number((summary.get("docker") or {}).get("total")),
        "image_critical": number((summary.get("docker") or {}).get("critical")),
        "image_high": number((summary.get("docker") or {}).get("high")),
        "coverage": coverage, "retention": retention_lines, "github": github_line,
        "timestamp": local_time(run.get("finished_at") or run.get("started_at")),
        "run_id": text(run.get("id"), 90), "version": text(summary.get("script_version"), 60),
        "weekly_summary": bool(run.get("weekly_summary")),
        "report_path": text(summary.get("report_path") or "bericht.html und summary.json im Laufordner", 400),
        "report_url": safe_url(env.get("REPORT_PUBLIC_URL") or summary.get("report_url")),
        "failed_images": failed,
    }


def mail_decision(summary: dict[str, Any], env: dict[str, Any] | None = None, run_status: dict[str, Any] | None = None) -> dict[str, Any]:
    env = env or {}
    model = build_model(summary, run_status, env)
    prefix = text(env.get("MAIL_SUBJECT_PREFIX") or "[UGREEN SecurityWatch]", 100)
    if model["error_count"]:
        subject = f"Handlung erforderlich: {model['error_count']} " + ("Problem" if model["error_count"] == 1 else "Probleme")
    elif not model["complete"]:
        subject = "Prüfung unvollständig"
        if model["failed_images"]:
            subject += f": {model['failed_images']} Image-Prüfungen fehlgeschlagen"
    elif model["update_count"]:
        subject = f"{model['update_count']} " + ("Image aktualisiert" if model["update_count"] == 1 else "Images aktualisiert")
        if model["total"]:
            subject += f" – {model['critical']} kritisch, {model['high']} hoch verbleibend"
        elif model["notice_count"]:
            subject += f" – {model['notice_count']} " + ("Aufgabe offen" if model["notice_count"] == 1 else "Aufgaben offen")
    elif model["total"]:
        subject = f"{model['critical']} kritische, {model['high']} hohe Paketfunde"
        if model["notice_count"]:
            subject += f" · {model['notice_count']} " + ("Aufgabe offen" if model["notice_count"] == 1 else "Aufgaben offen")
    elif model["notice_count"]:
        subject = f"{model['notice_count']} " + ("Aufgabe offen" if model["notice_count"] == 1 else "Aufgaben offen")
    elif model["built_count"]:
        subject = f"{model['built_count']} " + ("Image neu gebaut – bisherige Version beibehalten" if model["built_count"] == 1 else "Images neu gebaut – bisherige Versionen beibehalten")
    elif model["maintenance"]["blocked"]:
        subject = f"Automatische Aktualisierung: {model['maintenance']['blocked']} Dienste zurückgestellt"
    elif model.get("historical_update_count"):
        subject = f"{model['historical_update_count']} frühere Image-Übernahmen nachgemeldet"
    else:
        subject = "Wochenbericht: Prüfung abgeschlossen" if model["weekly_summary"] else "Prüfung abgeschlossen: keine gemeldeten Funde"
    required = bool(model["error_count"] or not model["complete"])
    send = required or bool(model["total"]) or not enabled(env.get("MAIL_ONLY_ON_FINDINGS"), True) or enabled(env.get("MAIL_SEND_OK"), False)
    send = send or (model["weekly_summary"] and enabled(env.get("MAIL_SEND_WEEKLY_SUMMARY"), True))
    send = send or (bool(model["notice_count"] or model["update_count"] or model["built_count"] or model.get("historical_update_count") or model["maintenance"]["blocked"]) and enabled(env.get("MAIL_SEND_ON_IMAGE_UPDATES"), True))
    return {"send": bool(send), "required": required, "subject": prefix + " " + subject, "model": model}


def render_text(model: dict[str, Any]) -> str:
    lines = ["SECURITYWATCH", model["headline"], model["timestamp"] + " · Europe/Berlin", "", model["intro"], ""]
    lines.extend(["AUF EINEN BLICK", *overview_lines(model), ""])
    outcomes = model.get("mail_outcomes") or []
    if outcomes:
        lines.extend(["IMAGES: NEUBAU UND SICHERHEITSSTAND", ""])
        for item in outcomes[:15]:
            lines.append(item["image"])
            if item["services"]:
                lines.append("Dienste: " + item["services"])
            lines.extend(outcome_lines(item))
            lines.append("")
        if len(outcomes) > 15:
            lines.extend([f"Weitere {len(outcomes) - 15} Images mit Einzelheiten im Detailbericht:", *["- " + item["image"] for item in outcomes[15:35]], ""])
            if len(outcomes) > 35:
                lines.append(f"Zusätzlich {len(outcomes) - 35} weitere Images; vollständige Liste im Detailbericht.")
    sections = (("Was deine Aufmerksamkeit braucht", model["actions"], 5), ("Was erledigt wurde", [] if outcomes else model["completed"], 5), ("Was noch aussteht", model["waiting"], 3))
    for title, rows, limit in sections:
        if not rows:
            continue
        lines.extend([title.upper(), ""])
        for event in rows[:limit]:
            if event["service"]:
                lines.append(event["service"])
            lines.append(event["message"])
            if event["action"]:
                lines.append("Nächster Schritt: " + event["action"])
            if event["url"]:
                lines.append(event["url"])
            lines.append("")
        if len(rows) > limit:
            lines.extend([f"Weitere {len(rows) - limit} Vorgänge stehen im Detailbericht.", ""])
    affected = model["affected_images"]
    lines.extend(["CONTAINER UND SICHERHEITSSTAND", "Ein Image wird einmal gezählt, auch wenn mehrere Container es verwenden.", ""])
    for item in affected[:60]:
        lines.extend([item["services"] or item["image"]])
        if item["services"]:
            lines.append("Image: " + item["image"])
        lines.extend(image_security_lines(item))
        lines.append("")
    if len(affected) > 60:
        lines.extend([f"Weitere {len(affected) - 60} Images stehen vollständig im Detailbericht.", ""])
    if model["clean_images"]:
        lines.append(f"Weitere {model['clean_images']} Images wurden erfolgreich ohne kritische oder hohe Paketfunde geprüft.")
    if not model["image_security"]:
        lines.append("Für diesen Lauf liegt keine bestätigte Einzelübersicht der laufenden Images vor.")
    lines.extend(["Eine bekannte Paketkorrektur bedeutet noch nicht, dass eine passende neue Image-Version verfügbar ist.", ""])
    lines.extend(["NAS / UGOS PRO – KURZER AUSZUG", *host_summary_lines(model), ""])
    for item in model["host_excerpt"]:
        lines.extend(host_excerpt_lines(item) + [""])
    lines.extend(["Dies sind Paketbefunde im NAS-Dateisystem, kein Nachweis für eine ausnutzbare Lücke in UGOS Pro. Herstelleranpassungen und Rückportierungen müssen berücksichtigt werden. SecurityWatch verändert keine NAS-Systempakete.", ""])
    lines.extend(["AUTOMATISCHE AKTUALISIERUNG", *maintenance_lines(model), ""])
    for group in model["maintenance"]["groups"][:8]:
        lines.extend([group["reason"], "Betroffen: " + ", ".join(group["containers"])])
        if group["action"]:
            lines.append("Nächster Schritt: " + group["action"])
        lines.append("")
    if len(model["maintenance"]["groups"]) > 8:
        lines.extend(["Weitere Voraussetzungen stehen im Detailbericht.", ""])
    lines.extend(["PRÜFUMFANG", *model["coverage"], model["github"], ""])
    lines.extend(["SICHERHEITSBEFUNDE", f"{model['total']} Paketfunde über alle geprüften Quellen: {model['critical']} kritisch, {model['high']} hoch.", f"NAS-Dateisystem: {model['host_total']}. Images: {model['image_total']}.", f"{model['distinct']} verschiedene Schwachstellenkennungen, darunter {model['distinct_cves']} CVE-Kennungen.", "Dieselbe Schwachstelle kann in mehreren Paketen oder Images vorkommen."])
    if not model["complete"]:
        lines.append("Die Zahlen gelten nur für die vorhandenen auswertbaren Ergebnisse; sie belegen keine vollständige Prüfung.")
    lines.extend(["", "AUFBEWAHRUNG", *model["retention"], "", "DETAILBERICHT", model["report_url"] or model["report_path"], "Der HTML-Detailbericht enthält eine priorisierte Auswahl; summary.json enthält sämtliche erfassten Befunde.", "", f"SecurityWatch {model['version']} · Lauf {model['run_id'] or 'nicht dokumentiert'}"])
    return "\n".join(lines) + "\n"


def render_html(model: dict[str, Any]) -> str:
    esc = lambda s: html.escape(str(s), quote=True)
    palette = {"error": ("#a12d3e", "#fff1f3", "#ecc4cc"), "warning": ("#8a5b0b", "#fff8e9", "#ead6ae"), "success": ("#17655b", "#edf8f5", "#bddfd5")}
    accent, background, border = palette[model["level"]]
    blocks: list[str] = []

    def heading(title: str) -> str:
        return f'<h2 style="margin:0 0 12px;color:#17334a;font-size:21px;line-height:1.3;">{esc(title)}</h2>'

    def section(content: str) -> str:
        return '<tr><td style="padding:23px 22px 0;">' + content + '</td></tr>'

    def paragraphs(lines: list[str]) -> str:
        return ''.join(f'<p style="margin:0 0 9px;font-size:15px;line-height:1.6;overflow-wrap:anywhere;word-break:break-word;">{esc(line)}</p>' for line in lines)

    blocks.append(section(heading("Auf einen Blick") + paragraphs(overview_lines(model))))
    outcomes = model.get("mail_outcomes") or []
    if outcomes:
        content = heading("Images: Neubau und Sicherheitsstand")
        shown = 0
        for item in outcomes[:15]:
            failed = item["deployment_status"] == "failed" or item["build_status"] == "failed" or item["verification_status"] == "failed"
            has_findings = item["after"] is None or item["after"].get("total") is None or item["after"]["total"] > 0
            edge = "#b13c4f" if failed else "#c09232" if has_findings or item["deployment_status"] != "applied" else "#298675"
            card = f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;margin:0 0 13px;"><tr><td style="padding:15px;border:1px solid #dfe6ed;border-left:4px solid {edge};background-color:#f8fafc;">'
            card += f'<p style="margin:0 0 9px;color:#17334a;font-size:16px;font-weight:bold;line-height:1.5;overflow-wrap:anywhere;word-break:break-word;">{esc(item["image"])}</p>'
            if item["services"]:
                card += paragraphs(["Dienste: " + item["services"]])
            card += paragraphs(outcome_lines(item)) + '</td></tr></table>'
            if len((content + card).encode("utf-8")) > 20_000:
                break
            content += card
            shown += 1
        if len(outcomes) > shown:
            content += paragraphs([f"Weitere {len(outcomes) - shown} Images stehen mit Einzelheiten im Detailbericht."])
            listed = 0
            for item in outcomes[shown:]:
                extra = paragraphs([item["image"]])
                if len((content + extra).encode("utf-8")) > 22_000:
                    break
                content += extra
                listed += 1
            if shown + listed < len(outcomes):
                content += paragraphs([f"Weitere {len(outcomes) - shown - listed} Namen stehen ebenfalls in der vollständigen Liste."])
        blocks.append(section(content))

    for title, rows, limit in (("Was deine Aufmerksamkeit braucht", model["actions"], 5), ("Was erledigt wurde", [] if outcomes else model["completed"], 5), ("Was noch aussteht", model["waiting"], 3)):
        if not rows:
            continue
        content = heading(title)
        shown = 0
        for event in rows[:limit]:
            edge = "#b13c4f" if event["severity"] == "error" else "#c09232" if event["severity"] == "warning" else "#298675"
            card = f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;margin:0 0 12px;"><tr><td style="padding:14px 15px;border:1px solid #dfe6ed;border-left:4px solid {edge};background-color:#f8fafc;">'
            if event["service"]:
                card += f'<p style="margin:0 0 7px;color:#17334a;font-size:15px;font-weight:bold;overflow-wrap:anywhere;word-break:break-word;">{esc(event["service"])}</p>'
            card += paragraphs([event["message"]])
            if event["action"]:
                card += f'<p style="margin:8px 0 0;font-size:15px;line-height:1.6;overflow-wrap:anywhere;word-break:break-word;"><strong>Nächster Schritt:</strong> {esc(event["action"])}</p>'
            if event["url"]:
                card += f'<p style="margin:12px 0 0;"><a href="{esc(event["url"])}" style="display:inline-block;padding:9px 0;color:#126d80;font-weight:bold;font-size:15px;">Zugehörigen Vorgang öffnen</a></p>'
            card += '</td></tr></table>'
            # Auch extrem lange Namen oder stark zu maskierende Texte dürfen
            # die Hauptnachricht nicht wieder zu einer riesigen Tabelle machen.
            if len((''.join(blocks) + content + card).encode("utf-8")) > 27_000:
                break
            content += card
            shown += 1
        if len(rows) > shown:
            content += paragraphs([f"Weitere {len(rows) - shown} Vorgänge stehen im Detailbericht."])
        blocks.append(section(content))

    affected = model["affected_images"]
    content = heading("Container und Sicherheitsstand")
    content += paragraphs(["Ein Image wird einmal gezählt, auch wenn mehrere Container es verwenden."])
    shown = 0
    for item in affected[:60]:
        edge = "#a12d3e" if item["state"] != "ok" or number(item["counts"]["critical"]) else "#8a5b0b"
        title = item["services"] or item["image"]
        card = f'<div style="padding:12px 0;border-top:1px solid #dfe6ed;overflow-wrap:anywhere;word-break:break-word;"><p style="margin:0 0 4px;font-size:15px;font-weight:bold;color:#17334a;line-height:1.5;">{esc(title)}</p>'
        if item["services"]:
            card += f'<p style="margin:0 0 4px;font-size:12px;line-height:1.5;color:#566b7d;">{esc(item["image"])}</p>'
        for index, line in enumerate(image_security_lines(item)):
            color = edge if index == 0 else "#566b7d"
            card += f'<p style="margin:0 0 3px;font-size:14px;line-height:1.5;color:{color};">{esc(line)}</p>'
        card += '</div>'
        if len((''.join(blocks) + content + card).encode("utf-8")) > 40_000:
            break
        content += card
        shown += 1
    if shown < len(affected):
        content += paragraphs([f"Weitere {len(affected) - shown} Images stehen vollständig im Detailbericht."])
    if model["clean_images"]:
        content += paragraphs([f"Weitere {model['clean_images']} Images wurden erfolgreich ohne kritische oder hohe Paketfunde geprüft."])
    if not model["image_security"]:
        content += paragraphs(["Für diesen Lauf liegt keine bestätigte Einzelübersicht der laufenden Images vor."])
    content += '<p style="margin:9px 0 0;font-size:13px;line-height:1.55;color:#566b7d;">Eine bekannte Paketkorrektur bedeutet noch nicht, dass eine passende neue Image-Version verfügbar ist.</p>'
    blocks.append(section(content))

    content = heading("NAS / UGOS Pro – kurzer Auszug")
    content += paragraphs(host_summary_lines(model))
    for item in model["host_excerpt"]:
        lines = host_excerpt_lines(item)
        title = esc(lines[0])
        if item["url"]:
            title = f'<a href="{esc(item["url"])}" style="color:#176d78;text-decoration:underline;">{title}</a>'
        content += '<div style="padding:10px 0;border-top:1px solid #dfe6ed;overflow-wrap:anywhere;word-break:break-word;">'
        content += f'<p style="margin:0 0 5px;font-size:14px;font-weight:bold;line-height:1.5;">{title}</p>'
        content += ''.join(f'<p style="margin:0 0 3px;font-size:13px;line-height:1.5;">{esc(line)}</p>' for line in lines[1:]) + '</div>'
    content += '<p style="margin:10px 0 0;font-size:13px;line-height:1.55;color:#566b7d;">Dies sind Paketbefunde im NAS-Dateisystem, kein Nachweis für eine ausnutzbare Lücke in UGOS Pro. Herstelleranpassungen und Rückportierungen müssen berücksichtigt werden. SecurityWatch verändert keine NAS-Systempakete.</p>'
    blocks.append(section(content))

    content = heading("Automatische Aktualisierung") + paragraphs(maintenance_lines(model))
    shown = 0
    for group in model["maintenance"]["groups"][:8]:
        card = '<div style="padding:10px 0;border-top:1px solid #dfe6ed;overflow-wrap:anywhere;word-break:break-word;">'
        card += f'<p style="margin:0 0 5px;font-size:14px;font-weight:bold;line-height:1.5;">{esc(group["reason"])}</p>'
        card += f'<p style="margin:0;font-size:13px;line-height:1.55;">{esc(text(", ".join(group["containers"]), 900))}</p>'
        if group["action"]:
            card += f'<p style="margin:5px 0 0;font-size:13px;line-height:1.55;">{esc(group["action"])}</p>'
        card += '</div>'
        if len((''.join(blocks) + content + card).encode("utf-8")) > 50_000:
            break
        content += card
        shown += 1
    if shown < len(model["maintenance"]["groups"]):
        content += paragraphs(["Weitere Voraussetzungen stehen im Detailbericht."])
    blocks.append(section(content))

    blocks.append(section(heading("Prüfumfang") + paragraphs(model["coverage"] + [model["github"]])))
    counts = [f"{model['total']} Paketfunde über alle geprüften Quellen", f"{model['critical']} kritisch · {model['high']} hoch", f"NAS-Dateisystem: {model['host_total']} · Images: {model['image_total']}", f"{model['distinct']} verschiedene Schwachstellenkennungen, darunter {model['distinct_cves']} CVE-Kennungen.", "Dieselbe Schwachstelle kann in mehreren Paketen oder Images vorkommen."]
    if not model["complete"]:
        counts.append("Die Zahlen gelten nur für die vorhandenen auswertbaren Ergebnisse; sie belegen keine vollständige Prüfung.")
    blocks.append(section(heading("Sicherheitsbefunde") + paragraphs(counts)))
    blocks.append(section(heading("Aufbewahrung") + paragraphs(model["retention"])))
    detail = heading("Detailbericht")
    if model["report_url"]:
        detail += f'<p style="margin:0 0 12px;"><a href="{esc(model["report_url"])}" style="display:inline-block;padding:11px 16px;background-color:#176d78;color:#ffffff;border-radius:6px;text-decoration:none;font-size:16px;font-weight:bold;">Bericht öffnen</a></p>'
    else:
        detail += paragraphs([model["report_path"]])
    detail += '<p style="margin:0 0 23px;color:#566b7d;font-size:13px;line-height:1.6;">Der HTML-Detailbericht enthält eine priorisierte Auswahl. In <strong>summary.json</strong> stehen sämtliche erfassten Befunde.</p>'
    blocks.append(section(detail))
    return f'''<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>SecurityWatch – {esc(model['headline'])}</title></head>
<body style="margin:0;padding:0;background-color:#edf2f6;color:#283e50;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:1.55;-webkit-text-size-adjust:100%;">
<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;">{esc(model['intro'])}</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;"><tr><td align="center" style="padding:20px 8px;">
<!--[if mso]><table role="presentation" width="680" cellspacing="0" cellpadding="0" border="0"><tr><td><![endif]-->
<div style="width:100%;max-width:680px;margin:0 auto;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:680px;border-spacing:0;border-collapse:separate;background-color:#ffffff;border:1px solid #dce4eb;border-radius:12px;">
<tr><td style="padding:24px 22px;background-color:#142f44;border-radius:11px 11px 0 0;border-top:5px solid #43a99b;"><p style="margin:0 0 7px;color:#9bddd5;font-size:12px;font-weight:bold;letter-spacing:1.4px;">SECURITYWATCH</p><h1 style="margin:0;color:#ffffff;font-size:27px;line-height:1.25;">{esc(model['headline'])}</h1><p style="margin:11px 0 0;color:#d5e2ec;font-size:14px;">{esc(model['timestamp'])} · Europe/Berlin</p></td></tr>
<tr><td style="padding:18px 22px 0;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;"><tr><td style="padding:14px 15px;background-color:{background};border:1px solid {border};border-left:4px solid {accent};color:{accent};font-size:15px;line-height:1.6;">{esc(model['intro'])}</td></tr></table></td></tr>
{''.join(blocks)}
<tr><td style="padding:16px 22px;border-top:1px solid #dfe6ed;background-color:#f4f7fa;border-radius:0 0 11px 11px;"><p style="margin:0;color:#5b7081;font-size:12px;line-height:1.6;overflow-wrap:anywhere;word-break:break-word;">SecurityWatch {esc(model['version'])}<br>Lauf: {esc(model['run_id'] or 'nicht dokumentiert')}</p></td></tr>
</table></div><!--[if mso]></td></tr></table><![endif]--></td></tr></table></body></html>'''
