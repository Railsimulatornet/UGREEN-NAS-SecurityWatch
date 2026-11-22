#!/usr/bin/env python3
"""Report Java advisories and server-image updates through SecurityWatch."""
import argparse
from datetime import datetime, timedelta, timezone
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path("/volume2/docker/securitywatch")
STATE = ROOT / "state" / "minecraft-java"
PROJECT = "ugreen_minecraft_java"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REPO = "itzg/minecraft-server"
TAG = "java25"
FIX = (25, 0, 5, 1, 2)
JAVA4SHELL = "CVE-2026-114938"
MARKER = "AVX-512 VBMI"
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json"))


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=45)


def fetch(url, headers=None):
    request = Request(url, headers={"User-Agent": "SecurityWatch-Minecraft-Java/1", **(headers or {})})
    with urlopen(request, timeout=18) as response:
        return json.load(response)


def version(value):
    match = re.fullmatch(r"(?:jdk-)?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\+(\d+)(?:-LTS)?", value)
    if not match:
        raise ValueError("Java-Buildnummer konnte nicht gelesen werden")
    return tuple(int(part or 0) for part in match.groups())


def read_runtime():
    ids = run("docker", "ps", "-q", "--filter", "label=com.docker.compose.project=" + PROJECT,
              "--filter", "label=com.docker.compose.service=minecraft").split()
    if len(ids) != 1:
        raise RuntimeError("Der Minecraft-Dienst wurde nicht eindeutig gefunden")
    image = run("docker", "inspect", "--format", "{{.Image}}", ids[0]).strip()
    pids = [line.split()[0] for line in run("docker", "top", ids[0], "-eo", "pid,comm").splitlines()[1:]
            if line.split()[-1] == "java"]
    if len(pids) != 1:
        raise RuntimeError("Der laufende Minecraft-Java-Prozess wurde nicht eindeutig gefunden")
    proc = Path("/proc") / pids[0]
    binary = Path(os.readlink(proc / "exe"))
    release = proc / "root" / str(binary.parent.parent / "release").lstrip("/")
    fields = dict(line.split("=", 1) for line in release.read_text().splitlines() if "=" in line)
    java = fields["JAVA_RUNTIME_VERSION"].strip('"')
    vendor = fields.get("IMPLEMENTOR", "").strip('"')
    cpu = [set(line.split(":", 1)[1].split()) for line in Path("/proc/cpuinfo").read_text().splitlines()
           if re.match(r"^flags\s*:", line)]
    if not cpu:
        raise RuntimeError("CPU-Eigenschaften konnten nicht ermittelt werden")
    if "Adoptium" not in vendor:
        raise RuntimeError("Die bisher überwachte Temurin-Laufzeit wurde durch einen anderen Anbieter ersetzt")
    flags = {"avx512f", "avx512bw", "avx512vbmi", "bmi2"}
    return {"version": java, "vendor": vendor, "image": image, "hardware": any(flags <= item for item in cpu)}


def image_version():
    auth = urlencode({"service": "registry.docker.io", "scope": f"repository:{REPO}:pull"})
    token = fetch("https://auth.docker.io/token?" + auth)["token"]
    headers = {"Authorization": "Bearer " + token, "Accept": ACCEPT}
    url = "https://registry-1.docker.io/v2/" + REPO
    index = fetch(f"{url}/manifests/{TAG}", headers)
    arch = [m["digest"] for m in index["manifests"]
            if m["platform"].get("os") == "linux" and m["platform"].get("architecture") == "amd64"]
    digest, = arch
    layers = fetch(f"{url}/manifests/{digest}", headers)
    config = fetch(f"{url}/blobs/{layers['config']['digest']}", headers)
    java, = [entry.split("=", 1)[1] for entry in config["config"]["Env"] if entry.startswith("JAVA_VERSION=")]
    version(java)
    return {"version": java, "digest": digest}



def vendor_fix_available():
    url = ("https://api.github.com/repos/adoptium/temurin25-binaries/releases/tags/"
           "jdk-25.0.5.1%2B2")
    try:
        release = fetch(url)
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    return not release["prerelease"] and any(
        asset["name"].startswith("OpenJDK25U-jre_x64_linux_hotspot_")
        and asset["name"].endswith(".tar.gz") and asset["state"] == "uploaded"
        for asset in release["assets"]
    )

def nvd_reports(now):
    records = {}
    window = {"lastModStartDate": (now - timedelta(days=21)).isoformat(timespec="milliseconds"),
              "lastModEndDate": now.isoformat(timespec="milliseconds"),
              "noRejected": "", "keywordExactMatch": "", "resultsPerPage": 200}
    for terms in ("Oracle Java SE", "OpenJDK", "Eclipse Temurin"):
        start = 0
        while True:
            query = urlencode({**window, "keywordSearch": terms, "startIndex": start})
            page = fetch(f"{NVD}?{query}")
            rows = page["vulnerabilities"]
            for row in rows:
                item = row["cve"]
                records[item["id"]] = item
            start += len(rows)
            if start >= page["totalResults"]:
                break
            if not rows:
                raise RuntimeError("NVD lieferte eine unvollständige Seite")
    result = {}
    for key, item in records.items():
        description = next((row["value"].lower() for row in item["descriptions"]
                            if row["lang"] == "en"), "")
        if "openjdk-orb" in description and ("jboss" in description or "eap" in description):
            continue  # JBoss CORBA component, outside this Java runtime check.
        values = [m["cvssData"].get("baseScore", 0) for v, rows in item.get("metrics", {}).items()
                  if v.startswith("cvssMetric") for m in rows]
        score = max(values, default=0)
        if score >= 7 and re.fullmatch(r"CVE-\d{4}-\d+", key):
            result[key] = score
    return result


def current(now):
    return {"checked_at": now.isoformat(), "live": read_runtime(),
            "upstream": image_version(), "temurin_fix_available": vendor_fix_available(),
            "advisories": nvd_reports(now)}


def notices(status, previous):
    changes = []
    live, upstream = status["live"], status["upstream"]
    if version(live["version"])[0] != 25:
        raise RuntimeError("Die überwachte Java-Hauptversion hat sich geändert")
    old = previous.get("advisories", {})
    for cve, score in sorted(status["advisories"].items()):
        if cve != JAVA4SHELL and (cve not in old or score > old[cve]):
            changes.append(f"{cve} (CVSS {score:g}). Relevanz für Temurin {live['version']} prüfen. "
                           f"https://nvd.nist.gov/vuln/detail/{cve}")
    if version(live["version"]) < FIX and version(upstream["version"]) >= FIX:
        if version(previous.get("upstream", {}).get("version", "25.0.0+0")) < FIX:
            changes.append(f"Java4Shell-Fix im Server-Image verfügbar. {REPO}:{TAG} enthält "
                           f"{upstream['version']}. Auf dem iDX läuft {live['version']}. "
                           "Das Image zuerst auf dem DXP testen.")
    elif previous.get("upstream") and previous["upstream"]["digest"] != upstream["digest"]:
        if previous["upstream"]["version"] != upstream["version"] and version(upstream["version"]) > version(live["version"]):
            changes.append(f"Das Server-Image enthält jetzt {upstream['version']}. Live läuft "
                           f"{live['version']}. Release Notes und enthaltene Fixes prüfen.")
    if (version(live["version"]) < FIX and version(upstream["version"]) < FIX
            and status["temurin_fix_available"] and not previous.get("temurin_fix_available")):
        changes.append("Adoptium hat Temurin 25.0.5.1+2 für Linux x64 veröffentlicht. "
                       "Das passende Minecraft-Server-Image steht noch aus.")
    before = previous.get("live", {})
    if before and not before.get("hardware") and live["hardware"] and version(live["version"]) < FIX:
        changes.append(f"{JAVA4SHELL}. Der Rechner stellt jetzt die benötigten CPU-Funktionen bereit. "
                       "Sicherheitsupdate priorisieren.")
    return changes


def mail(lines):
    with tempfile.TemporaryDirectory(prefix="mail-", dir=STATE) as tmp:
        p = Path(tmp)
        body = "Minecraft-Liveserver · Java-Sicherheit\n\n" + "\n\n".join(lines) + "\n"
        (p / "mail.txt").write_text(body, encoding="utf-8")
        (p / "mail.html").write_text("<pre>" + html.escape(body) + "</pre>", encoding="utf-8")
        (p / "summary.json").write_text(json.dumps({"total": len(lines), "high": len(lines)}))
        run(sys.executable, str(ROOT / "securitywatch_mail.py"), "--env-file", str(ROOT / ".env"),
            "--summary-json", str(p / "summary.json"), "--mail-txt", str(p / "mail.txt"),
            "--mail-html", str(p / "mail.html"))


def write_state(name, data):
    path = STATE / name
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--check", action="store_true", help="Nur prüfen, ohne Mail oder Zustandsänderung")
    options = cli.parse_args()
    os.umask(0o077)
    now = datetime.now(timezone.utc)
    history = STATE / "last_success.json"
    previous = json.loads(history.read_text()) if history.is_file() else {}
    try:
        status = current(now)
        lines = notices(status, previous)
    except Exception as failure:
        if options.check:
            raise
        error_path = STATE / "error.json"
        recent = json.loads(error_path.read_text()) if error_path.is_file() else {}
        count = int(recent.get("count", 0)) + 1
        notified = bool(recent.get("notified"))
        write_state("error.json", {"checked_at": now.isoformat(), "type": type(failure).__name__,
                                   "count": count, "notified": notified})
        if count >= 2 and not notified:
            mail(["Die tägliche Java-Prüfung des Minecraft-Liveservers ist zweimal fehlgeschlagen. "
                  "Letzten erfolgreichen Lauf und Erreichbarkeit der Quellen prüfen."])
            write_state("error.json", {"checked_at": now.isoformat(), "type": type(failure).__name__,
                                       "count": count, "notified": True})
        raise SystemExit("Java-Prüfung fehlgeschlagen: " + type(failure).__name__)
    status["java4shell"] = (
        "gepatcht" if version(status["live"]["version"]) >= FIX
        else "CPU-Voraussetzung erfüllt" if status["live"]["hardware"] else f"{MARKER} fehlt"
    )
    if options.check:
        print(json.dumps(status | {"new_notices": lines}, ensure_ascii=False))
        return
    deliver = lines if previous else [
        line for line in lines if line.startswith(("Java4Shell-Fix", "Adoptium hat"))
    ]
    if deliver:
        mail(deliver)
    status["advisories"] = previous.get("advisories", {}) | status["advisories"]
    write_state("last_success.json", status)
    (STATE / "error.json").unlink(missing_ok=True)
    print(json.dumps(status, ensure_ascii=False))


if __name__ == "__main__":
    main()

