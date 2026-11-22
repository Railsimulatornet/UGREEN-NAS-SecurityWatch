#!/usr/bin/env python3
"""Ergänzende, nur lesende NAS-Paketdaten und begrenzte Berichtsaufbewahrung."""
from __future__ import annotations

import csv
import fnmatch
import json
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from securitywatch_common import patterns, safe_field

DEFAULT_WATCHLIST = ("samba,samba-*,smbclient,winbind,ffmpeg,libavcodec*,libavformat*,"
                     "libavutil*,libswscale*,nginx,nginx-*,openssl,libssl*,openssh-client,"
                     "openssh-server,ssh,bash,busybox,python3*,systemd,containerd,docker*,runc")


def _tsv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle, delimiter="\t", lineterminator="\n").writerows(
            [[safe_field(value) for value in row] for row in rows])


def host_package_inventory(run_dir: Path, env: dict, run=subprocess.run):
    """dpkg-query reads the installed database; apt is deliberately never invoked."""
    proc = run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\n"],
               text=True, capture_output=True, timeout=60)
    if proc.returncode:
        raise RuntimeError("Die installierten NAS-Pakete konnten nicht gelesen werden.")
    labels = {"ii": "installed", "rc": "removed-config-files", "un": "not-installed",
              "iF": "install-failed", "iU": "unpacked", "iH": "half-installed",
              "iW": "triggers-awaited", "iT": "triggers-pending", "hi": "hold-installed"}
    rows = []
    for line in proc.stdout.splitlines():
        row = line.split("\t")
        if len(row) != 5:
            raise RuntimeError("Die Paketdatenbank lieferte unvollständige Paketdaten.")
        row[3] = labels.get(row[3].strip(), row[3].strip())
        rows.append(row)
    if not rows:
        raise RuntimeError("Die Paketdatenbank lieferte keine Paketdaten.")
    rows.sort()
    header = ["Package", "Version", "Architecture", "Status", "Source"]
    _tsv(run_dir / "host_package_inventory.tsv", [header] + rows)
    watchlist = patterns(env.get("HOST_PACKAGE_WATCHLIST", DEFAULT_WATCHLIST))
    _tsv(run_dir / "host_package_watchlist.tsv", [header] + [
        row for row in rows if any(fnmatch.fnmatchcase(row[0], pattern) for pattern in watchlist)])
    release = Path("/etc/os-release")
    if release.is_file():
        (run_dir / "host_os_release.txt").write_text(release.read_text(encoding="utf-8"), encoding="utf-8")


def host_backport_notes(run_dir: Path):
    document = json.loads((run_dir / "host_rootfs.json").read_text(encoding="utf-8"))
    rows = []
    for result in document.get("Results", []):
        if result.get("Class") != "os-pkgs" and result.get("Type") not in {"debian", "ubuntu"}:
            continue
        for finding in result.get("Vulnerabilities") or []:
            fixed = finding.get("FixedVersion") or ""
            note = ("Laut Prüfwerkzeug ist eine korrigierte Distributions-Paketversion verfügbar."
                    if fixed else "Das Prüfwerkzeug nennt derzeit keine korrigierte Paketversion.")
            rows.append([finding.get("VulnerabilityID", "-"), finding.get("PkgName", "-"),
                         finding.get("InstalledVersion") or "-", fixed or "-", finding.get("Severity", "UNKNOWN"),
                         result.get("Type", "-"), result.get("Target", "-"), note])
    rows.sort(key=lambda row: (row[3] == "-", row[4] != "CRITICAL", row[1], row[0]))
    _tsv(run_dir / "host_debian_backport_notes.tsv",
         [["CVE", "Package", "Installed", "Fixed", "Severity", "Type", "Target", "BackportNote"]] + rows)


def _finished_report_time(path: Path) -> float | None:
    """Recognize our marked reports and completed original SecurityWatch runs.

    A timestamp-looking directory alone is never a deletion authorization.
    Legacy ownership requires matching summary, mail header and completed log.
    """
    marker, status_file = path / ".securitywatch-report", path / "run-status.json"
    if marker.exists() or marker.is_symlink() or status_file.exists() or status_file.is_symlink():
        if (marker.is_symlink() or status_file.is_symlink()
                or marker.read_text(encoding="ascii").strip() != "1"):
            return None
        status = json.loads(status_file.read_text(encoding="utf-8"))
        run = status["run"]
        if status.get("version") != 1 or run.get("id") != path.name or not run.get("finished_at"):
            return None
        completed = datetime.fromisoformat(run["finished_at"])
        return completed.timestamp() if completed.tzinfo is not None else None

    # Old releases used plain timestamps. Do not adopt unrelated hash folders.
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}", path.name):
        return None
    summary, mail, log = path / "summary.json", path / "mail.txt", path / "scan.log"
    if any(file.is_symlink() or not file.is_file() for file in (summary, mail, log)):
        return None
    document = json.loads(summary.read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or not isinstance(document.get("script_version"), str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+[A-Za-z0-9._-]*", document["script_version"])
            or document.get("language") not in {"de", "en"}
            or not isinstance(document.get("scan"), dict)
            or not isinstance(document.get("findings"), list)):
        return None
    for counts in (document, document.get("host"), document.get("docker")):
        if not isinstance(counts, dict):
            return None
        if any(type(counts.get(key)) is not int or counts[key] < 0 for key in ("total", "critical", "high")):
            return None
        if counts["total"] != counts["critical"] + counts["high"]:
            return None
    with mail.open("r", encoding="utf-8") as handle:
        if handle.readline().strip() not in {"UGREEN SecurityWatch Bericht", "UGREEN SecurityWatch Report"}:
            return None
    # Read only the start and tail of large logs; require both signatures and
    # the exact version from summary. This also keeps interrupted runs intact.
    with log.open("rb") as handle:
        start = handle.read(4096).decode("utf-8", "replace")
        handle.seek(max(0, log.stat().st_size - 8192))
        tail = handle.read().decode("utf-8", "replace")
    if ("SecurityWatch-Scan gestartet" not in start
            or f"Version: {document['script_version']}" not in start.splitlines()):
        return None
    match = re.search(r"\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\] SecurityWatch-Scan beendet\s*$", tail)
    if not match:
        return None
    zone = ZoneInfo("Europe/Berlin")
    started = datetime.strptime(path.name, "%Y-%m-%d_%H-%M-%S").replace(tzinfo=zone)
    completed = datetime.strptime(match[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=zone)
    return completed.timestamp() if completed >= started else None


def cleanup_reports(report_dir: Path, current: Path, *, days=30, keep_last=10, now=None):
    """Remove expired completed SecurityWatch reports, including old releases.

    Unrecognized or interrupted directories are preserved. Time starts at a
    verified completion, not at copying/extracting the report directory.
    """
    now = time.time() if now is None else now
    candidates = []
    errors = 0
    for path in report_dir.iterdir():
        if (path == current or path.is_symlink() or not path.is_dir() or
            not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}(?:_[0-9a-f]{6})?", path.name)):
            continue
        try:
            completed = _finished_report_time(path)
            if completed is not None:
                candidates.append((completed, path))
        except (OSError, UnicodeError, ValueError, KeyError, TypeError, AttributeError):
            # Unverifiable folders remain untouched.
            continue
    candidates.sort(reverse=True)
    removed = []
    for completed, path in candidates[max(0, keep_last - 1):]:
        if not days or now - completed < days * 86400:
            continue
        try:
            if path.is_symlink() or path.parent != report_dir or path == current:
                continue
            if not shutil.rmtree.avoids_symlink_attacks:
                errors += 1
                continue
            shutil.rmtree(path)
            removed.append(path.name)
        except OSError:
            errors += 1
    return {"days": days, "keep_last": keep_last, "removed": len(removed), "errors": errors}
