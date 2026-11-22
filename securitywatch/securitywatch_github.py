#!/usr/bin/env python3
"""Lesende, ausdrücklich zugeordnete GitHub-Bauüberwachung (Python 3.11+).

Diese Prüfung bestätigt GitHub-Ablaufergebnisse, nicht die Veröffentlichung
oder Übernahme eines Images. Beides prüft der Image-Ablauf gesondert.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import math
import os
import re
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

UTC = dt.timezone.utc
MAX_JSON_BYTES = 2 * 1024 * 1024
REPOSITORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")
WORKFLOW_RE = re.compile(r"(?:[1-9][0-9]*|[A-Za-z0-9_.-]+\.ya?ml)\Z")
ALLOWED_EVENTS = frozenset({"push", "schedule", "workflow_dispatch", "release", "repository_dispatch", "workflow_call", "workflow_run"})
DEFAULT_EVENTS = ("push", "schedule", "workflow_dispatch")


class GitHubError(Exception):
    """Nur unkritische Fehlerkennung und deutschsprachige Erklärung."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Insbesondere kein Authorization-Header an einen anderen Host.
        return None


def _read_regular(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise ValueError("Datei ist keine zulässige reguläre Datei.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = stream.read(limit + 1)
        if len(value) > limit:
            raise ValueError("Datei ist zu groß.")
        return value
    finally:
        os.close(fd)


def load_config(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(_read_regular(Path(path), MAX_JSON_BYTES))
    except (OSError, ValueError, UnicodeError) as exc:
        raise GitHubError("configuration_error", "Die GitHub-Zuordnung konnte nicht gelesen werden.") from exc
    if not isinstance(data, dict):
        raise GitHubError("configuration_error", "Die GitHub-Zuordnung muss ein JSON-Objekt sein.")
    return data


def read_token_file(path: str | Path) -> str:
    try:
        token_path = Path(path)
        st = token_path.lstat()
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
            raise ValueError("Zugriffsrechte")
        token = _read_regular(token_path, 8192).decode("utf-8").strip()
    except (OSError, ValueError, UnicodeError) as exc:
        raise GitHubError("credentials_error", "Die GitHub-Zugangsschlüsseldatei fehlt oder ist nicht ausreichend geschützt (0600).") from exc
    return _validate_token(token)


def _validate_token(token: str | None) -> str | None:
    if token is None:
        return None
    if not isinstance(token, str) or not token or len(token) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise GitHubError("credentials_error", "Der GitHub-Zugangsschlüssel ist leer oder ungültig.")
    return token


class GitHubClient:
    def __init__(self, token: str | None = None, timeout: float = 15.0):
        self.token = _validate_token(token)
        if not math.isfinite(float(timeout)):
            raise ValueError("Zeitlimit ist ungültig")
        self.timeout = min(max(float(timeout), 1.0), 30.0)
        self.opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def get_json(self, path: str) -> dict[str, Any]:
        if not path.startswith("/repos/") or "\\" in path or any(ord(c) < 32 for c in path):
            raise GitHubError("request_error", "Ungültiger GitHub-Abfragepfad.")
        parsed = urllib.parse.urlsplit("https://api.github.com" + path)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com" or parsed.fragment:
            raise GitHubError("request_error", "Ungültiges GitHub-Abfrageziel.")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "SecurityWatch/4.1 (read-only-build-monitor)",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        for attempt in range(2):
            request = urllib.request.Request(parsed.geturl(), headers=headers, method="GET")
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    if response.status != 200:
                        raise GitHubError("api_error", "GitHub hat kein vollständiges Prüfergebnis geliefert.")
                    raw = response.read(MAX_JSON_BYTES + 1)
                    if len(raw) > MAX_JSON_BYTES:
                        raise GitHubError("response_error", "Die GitHub-Antwort überschreitet die zulässige Größe.")
                    data = json.loads(raw)
                    if not isinstance(data, dict):
                        raise GitHubError("response_error", "Die GitHub-Antwort hat ein unerwartetes Format.")
                    return data
            except urllib.error.HTTPError as exc:
                code = exc.code
                error_headers = exc.headers or {}
                remaining = error_headers.get("X-RateLimit-Remaining", "")
                # Keine Antworttexte: Sie können private Projektinformationen enthalten.
                if code == 429 or (code == 403 and (remaining == "0" or error_headers.get("Retry-After"))):
                    raise GitHubError("rate_limited", "Das GitHub-Abfragelimit wurde erreicht; die Prüfung ist unvollständig.") from None
                if code in (401, 403, 404):
                    raise GitHubError("access_error", "Repository oder Bauablauf ist nicht lesbar. Zuordnung und GitHub-Leserechte prüfen.") from None
                if code in (502, 503, 504) and attempt == 0:
                    time.sleep(1)
                    continue
                raise GitHubError("api_error", f"GitHub-Abfrage fehlgeschlagen (HTTP {code}).") from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt == 0:
                    time.sleep(1)
                    continue
                raise GitHubError("connection_error", "GitHub war innerhalb des Zeitlimits nicht erreichbar.") from None
            except (ValueError, UnicodeError):
                raise GitHubError("response_error", "GitHub hat keine auswertbare JSON-Antwort geliefert.") from None
        raise GitHubError("connection_error", "GitHub war nicht erreichbar.")


def _stamp(value: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("Zeitangabe fehlt")
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Zeitzone fehlt")
    return result.astimezone(UTC)


def _event(repo: str, status: str, severity: str, message: str, action: str, *, url: str = "", patterns: list[str] | None = None) -> dict[str, Any]:
    return {
        "kind": "github", "status": status, "severity": severity,
        "service": "", "project": repo, "image": ", ".join(patterns or []),
        "message": message, "action": action, "url": url,
    }


def _repository_settings(entry: Any) -> tuple[str, str, str | None, float, list[str], list[str]]:
    if not isinstance(entry, dict):
        raise GitHubError("configuration_error", "Ein GitHub-Eintrag ist kein JSON-Objekt.")
    repo = entry.get("repository", "")
    if not isinstance(repo, str) or not REPOSITORY_RE.fullmatch(repo) or repo.split("/")[1] in {".", ".."}:
        raise GitHubError("configuration_error", "Repository als Eigentümer/Projekt angeben.")
    workflow = str(entry.get("workflow", ""))
    if not workflow or not WORKFLOW_RE.fullmatch(workflow):
        raise GitHubError("configuration_error", "Der zu prüfende Bauablauf fehlt. Den tatsächlichen Workflow-Dateinamen oder seine Nummer eintragen.")
    branch = entry.get("branch")
    if branch is not None and (not isinstance(branch, str) or not branch or len(branch) > 255 or any(ord(c) < 32 for c in branch)):
        raise GitHubError("configuration_error", "Der GitHub-Zweig ist ungültig.")
    age = entry.get("max_age_hours", 168)
    if isinstance(age, bool) or not isinstance(age, (int, float)) or not 1 <= age <= 8760:
        raise GitHubError("configuration_error", "Die zulässige Baupause muss zwischen 1 und 8760 Stunden liegen.")
    events = entry.get("events", list(DEFAULT_EVENTS))
    if not isinstance(events, list) or not events or len(events) > 7 or any(e not in ALLOWED_EVENTS for e in events):
        raise GitHubError("configuration_error", "Die gewünschten GitHub-Auslöser sind ungültig.")
    patterns = entry.get("image_patterns", [])
    if not isinstance(patterns, list) or not patterns or len(patterns) > 30 or any(not isinstance(p, str) or not p or len(p) > 255 or any(ord(c) < 32 for c in p) for p in patterns):
        raise GitHubError("configuration_error", "Die ausdrückliche Zuordnung zu mindestens einem Image fehlt.")
    return repo, workflow, branch, float(age), list(dict.fromkeys(events)), patterns


def deployment_advice(config: dict[str, Any], image_references) -> list[dict[str, Any]]:
    """Meldet ausdrücklich belegte Unterschiede zwischen NAS-Tag und Wochenbau.

    Verwendet die aktuellen logischen Image-Referenzen aus den Compose-
    Beschreibungen, keine internen Kandidaten-/Rückfallnamen. Ausschließlich
    ``published_image_patterns`` erlaubt diese Aussage; es gibt weder
    Netzwerkzugriffe noch eine abgeleitete Repository- oder Tag-Zuordnung.
    """
    if not isinstance(config, dict) or config.get("enabled") is not True:
        return []
    entries = config.get("repositories")
    if not isinstance(entries, list):
        return []
    if isinstance(image_references, str):
        image_references = [image_references]
    references = sorted({reference for reference in (image_references or [])
                         if isinstance(reference, str) and reference and len(reference) <= 512
                         and not any(ord(c) < 32 for c in reference)})
    advice = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or "published_image_patterns" not in entry:
            continue
        try:
            repo, workflow, _branch, _age, _triggers, image_patterns = _repository_settings(entry)
        except GitHubError:
            # Die eigentliche GitHub-Prüfung meldet ungültige Grundzuordnungen.
            continue
        published = entry["published_image_patterns"]
        workflow_url = f"https://github.com/{repo}/actions/workflows/{urllib.parse.quote(workflow, safe='')}"
        if (not isinstance(published, list) or not published or len(published) > 30
                or any(not isinstance(p, str) or not p or len(p) > 255
                       or any(ord(c) < 32 for c in p) for p in published)):
            advice.append(_event(repo, "configuration_error", "warning",
                                 "Die ausdrücklich hinterlegten Veröffentlichungsmuster sind ungültig.",
                                 "published_image_patterns in securitywatch.github.json anhand des tatsächlichen Wochenablaufs prüfen.",
                                 url=workflow_url))
            continue
        for reference in references:
            if ((repo, reference) in seen
                    or not any(fnmatch.fnmatchcase(reference, pattern) for pattern in image_patterns)
                    or any(fnmatch.fnmatchcase(reference, pattern) for pattern in published)):
                continue
            seen.add((repo, reference))
            advice.append(_event(
                repo, "published_tag_mismatch", "warning",
                f"Der Wochenneubau erreicht die verwendete Image-Version nicht: {reference}.",
                f"Gepflegter Kanal: {', '.join(published)}. "
                "Die einmalige Compose-Umstellung mit Sicherheitsprüfung, Zustandsprüfung und Rückfall ausführen; Anleitung im Paket.",
                url=workflow_url, patterns=[reference]))
    return advice


def monitor_github(config: dict[str, Any], *, token: str | None = None, token_file: str | Path | None = None,
                   fetch_json: Callable[[str], dict[str, Any]] | None = None,
                   now: dt.datetime | None = None) -> dict[str, Any]:
    """Prüft nur explizit konfigurierte Abläufe; keine Schreibzugriffe.

    ``status`` beschreibt die Vollständigkeit der Prüfung. Handlungsbedarf
    steht auch bei ``status='ok'`` in den Ereignissen (z.B. Bau fehlgeschlagen).
    """
    now = now or dt.datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("now benötigt eine Zeitzone")
    now = now.astimezone(UTC)
    result: dict[str, Any] = {"status": "disabled", "events": [], "repositories": [], "checked_at": now.isoformat()}
    if not isinstance(config, dict):
        result["status"] = "partial"
        result["events"].append(_event("", "configuration_error", "warning", "GitHub-Zuordnung ist ungültig.", "securitywatch.github.json prüfen."))
        return result
    if not isinstance(config.get("enabled", False), bool):
        result["status"] = "partial"
        result["events"].append(_event("", "configuration_error", "warning", "enabled muss in der GitHub-Zuordnung true oder false sein.", "securitywatch.github.json prüfen."))
        return result
    if not config.get("enabled", False):
        return result
    entries = config.get("repositories", [])
    if not isinstance(entries, list) or not entries or len(entries) > 30:
        result["status"] = "partial"
        result["events"].append(_event("", "configuration_error", "warning", "GitHub-Prüfung ist aktiviert, aber es fehlen gültige Projektzuordnungen.", "1 bis 30 konkrete Repository-/Image-/Bauablauf-Zuordnungen eintragen."))
        return result
    result["status"] = "ok"
    try:
        if token_file:
            token = read_token_file(token_file)
        else:
            token = _validate_token(token)
        fetch = fetch_json or GitHubClient(token, config.get("timeout_seconds", 15)).get_json
    except (GitHubError, ValueError, TypeError) as exc:
        message = str(exc) if isinstance(exc, GitHubError) else "Die GitHub-Verbindungseinstellungen sind ungültig."
        result["status"] = "partial"
        result["events"].append(_event("", "credentials_error", "warning", message, "GitHub-Konfiguration und geschützte Zugangsschlüsseldatei prüfen."))
        return result

    for entry in entries:
        repo = entry.get("repository", "") if isinstance(entry, dict) else ""
        # Ungültige Konfigurationswerte werden nicht ungekürzt in Meldungen übernommen.
        safe_repo = repo if isinstance(repo, str) and REPOSITORY_RE.fullmatch(repo) else ""
        try:
            repo, workflow, branch, max_age, events, patterns = _repository_settings(entry)
            base = "/repos/" + repo
            workflow_path = base + "/actions/workflows/" + urllib.parse.quote(workflow, safe="")
            workflow_doc = fetch(workflow_path)
            if not isinstance(workflow_doc, dict) or not isinstance(workflow_doc.get("state"), str):
                raise GitHubError("response_error", "Der Zustand des GitHub-Bauablaufs konnte nicht gelesen werden.")
            workflow_url = f"https://github.com/{repo}/actions/workflows/{urllib.parse.quote(workflow, safe='')}"
            if workflow_doc["state"] not in {"active", "disabled_manually", "disabled_inactivity", "disabled_fork", "deleted"}:
                raise GitHubError("response_error", "GitHub hat einen unbekannten Zustand des Bauablaufs geliefert.")
            if workflow_doc["state"] != "active":
                result["repositories"].append({"repository": repo, "workflow": workflow, "status": "disabled"})
                result["events"].append(_event(repo, "workflow_disabled", "warning", "Der zugeordnete GitHub-Bauablauf ist deaktiviert.", "Den Bauablauf auf GitHub prüfen und bei Bedarf wieder aktivieren.", url=workflow_url, patterns=patterns))
                continue
            if branch is None:
                repo_doc = fetch(base)
                branch = repo_doc.get("default_branch") if isinstance(repo_doc, dict) else None
                if not isinstance(branch, str) or not branch or len(branch) > 255 or any(ord(c) < 32 for c in branch):
                    raise GitHubError("response_error", "Der Standardzweig des GitHub-Projekts konnte nicht ermittelt werden.")
            runs = []
            for trigger in events:
                query = urllib.parse.urlencode({"branch": branch, "event": trigger, "per_page": 1, "page": 1})
                doc = fetch(workflow_path + "/runs?" + query)
                if not isinstance(doc, dict) or not isinstance(doc.get("workflow_runs"), list) or not isinstance(doc.get("total_count"), int):
                    raise GitHubError("response_error", "Die GitHub-Laufliste ist unvollständig oder ungültig.")
                rows = doc["workflow_runs"]
                if doc["total_count"] > 0 and not rows:
                    raise GitHubError("response_error", "GitHub meldet vorhandene Läufe, liefert aber keine Laufdaten.")
                for run in rows:
                    if not isinstance(run, dict) or run.get("event") != trigger or run.get("head_branch") != branch:
                        raise GitHubError("response_error", "Die GitHub-Antwort passt nicht zum ausgewählten Zweig und Auslöser.")
                    if isinstance(workflow_doc.get("id"), int) and run.get("workflow_id") != workflow_doc["id"]:
                        raise GitHubError("response_error", "Die GitHub-Antwort gehört nicht zum ausgewählten Bauablauf.")
                    try:
                        started = _stamp(run["created_at"])
                    except (KeyError, ValueError, TypeError):
                        raise GitHubError("response_error", "Die Zeitangabe eines GitHub-Laufs ist ungültig.") from None
                    if started > now + dt.timedelta(minutes=10):
                        raise GitHubError("response_error", "Die Zeitangabe eines GitHub-Laufs liegt unerwartet in der Zukunft.")
                    runs.append((started, run))
            if not runs:
                result["repositories"].append({"repository": repo, "workflow": workflow, "branch": branch, "status": "never"})
                result["events"].append(_event(repo, "build_missing", "warning", "Für den zugeordneten Bauablauf wurde noch kein passender Lauf gefunden.", "Zweig und Auslöser prüfen; anschließend den vorgesehenen Bau auf GitHub starten.", url=workflow_url, patterns=patterns))
                continue
            started, latest = max(runs, key=lambda r: (r[0], r[1].get("id", 0)))
            run_id = latest.get("id")
            if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
                raise GitHubError("response_error", "Die GitHub-Laufnummer ist ungültig.")
            url = f"https://github.com/{repo}/actions/runs/{run_id}"
            age_hours = max(0, (now - started).total_seconds() / 3600)
            row = {"repository": repo, "workflow": workflow, "branch": branch, "run_id": run_id,
                   "started_at": started.isoformat(), "age_hours": round(age_hours, 1), "url": url}
            status, conclusion = latest.get("status"), latest.get("conclusion")
            if status == "completed" and conclusion == "success":
                if age_hours > max_age:
                    row["status"] = "overdue"
                    event = _event(repo, "build_overdue", "warning", f"Der letzte erfolgreiche Bauablauf liegt mehr als {max_age:g} Stunden zurück.", "Zeitplan und neue Abhängigkeitsstände im Repository prüfen.", url=url, patterns=patterns)
                else:
                    row["status"] = "ok"
                    event = _event(repo, "build_success", "info", "Der letzte zugeordnete GitHub-Bauablauf war erfolgreich.", "", url=url, patterns=patterns)
            elif status == "completed":
                row["status"] = "failed"
                labels = {"failure": "fehlgeschlagen", "cancelled": "abgebrochen", "timed_out": "am Zeitlimit beendet", "action_required": "mit erforderlichem Eingriff beendet", "skipped": "übersprungen", "neutral": "ohne Erfolgsnachweis beendet", "stale": "ohne aktuellen Erfolgsnachweis beendet"}
                label = labels.get(conclusion, "ohne Erfolgsnachweis beendet")
                event = _event(repo, "build_failed", "error", f"Der letzte zugeordnete GitHub-Bauablauf wurde {label}.", "Den verlinkten Lauf öffnen, Fehler beheben und den vorgesehenen Bau erneut ausführen.", url=url, patterns=patterns)
            elif status in {"queued", "in_progress", "waiting", "pending", "requested"}:
                row["status"] = "pending"
                overdue = age_hours > max_age
                event = _event(repo, "build_pending", "warning" if overdue else "info", "Der zugeordnete GitHub-Bauablauf ist noch nicht abgeschlossen." + (" Das vorgesehene Zeitfenster wurde überschritten." if overdue else ""), "Den verlinkten Lauf prüfen." if overdue else "Das Ergebnis des laufenden Baus abwarten.", url=url, patterns=patterns)
            else:
                raise GitHubError("response_error", "GitHub hat einen unbekannten Laufzustand geliefert.")
            result["repositories"].append(row)
            result["events"].append(event)
        except GitHubError as exc:
            result["status"] = "partial"
            result["repositories"].append({"repository": safe_repo, "status": "unknown", "error_code": exc.code})
            result["events"].append(_event(safe_repo, exc.code, "warning", str(exc), "GitHub-Zuordnung und Leserechte prüfen; ein unbekanntes Ergebnis ist kein erfolgreicher Bau.", url=f"https://github.com/{safe_repo}/actions" if safe_repo else ""))
        except (OSError, ValueError, TypeError, KeyError):
            result["status"] = "partial"
            result["repositories"].append({"repository": safe_repo, "status": "unknown", "error_code": "response_error"})
            result["events"].append(_event(safe_repo, "response_error", "warning", "Der GitHub-Bauzustand konnte nicht zuverlässig ausgewertet werden.", "Zuordnung und GitHub-Erreichbarkeit prüfen."))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Explizit zugeordnete GitHub-Bauabläufe ausschließlich lesen.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--token-file")
    args = parser.parse_args()
    try:
        result = monitor_github(load_config(args.config), token_file=args.token_file)
    except GitHubError as exc:
        result = {"status": "partial", "events": [_event("", exc.code, "warning", str(exc), "GitHub-Konfiguration prüfen.")], "repositories": []}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if result["status"] == "partial" else 0


if __name__ == "__main__":
    raise SystemExit(main())
