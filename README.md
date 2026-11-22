# UGREEN SecurityWatch

[![Quality](https://github.com/Railsimulatornet/UGREEN-NAS-SecurityWatch/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/Railsimulatornet/UGREEN-NAS-SecurityWatch/actions/workflows/quality.yml)
[![CodeQL](https://github.com/Railsimulatornet/UGREEN-NAS-SecurityWatch/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Railsimulatornet/UGREEN-NAS-SecurityWatch/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

![UGREEN SecurityWatch](Screens/SecurityWatch.png)

[Deutsch](#deutsch) · [English](#english)

## Deutsch

Skriptpaket für **UGREEN NAS mit UGOS**. SecurityWatch prüft das Host-Dateisystem und die Docker-Images laufender Container mit Trivy. Es erstellt Berichte und kann diese als Text- und HTML-Mail versenden. Über die Konfiguration lassen sich außerdem Docker-Bereinigung und automatische Image-Aktualisierungen steuern.

### Funktionen

- Host-Scan mit Trivy `rootfs` gegen `/host` und Scan der Images laufender Container.
- Berichte als `summary.json`, `mail.txt` und `mail.html`, ein Ordner pro Lauf unter `reports/`.
- Deutsche oder englische Ausgaben über `OUTPUT_LANG`.
- Zusatzbericht für lokal gebaute Images und deren behebbare Paketfunde.
- Konfigurierbare Docker-Bereinigung, Rebuilds lokaler Compose-Images und Aktualisierung von Registry-Images.
- E-Mail nur bei Treffern oder zusätzlich als OK-Meldung; konfigurierbare Berichtaufbewahrung.

### Voraussetzungen

- UGREEN NAS mit aktivem Docker-Dienst und SSH-Zugang.
- Bash, Python 3 und ausreichende Rechte für den Host- und Docker-Zugriff; die Beispiele verwenden eine Root-Sitzung.
- Zugriff auf das Trivy-Image und dessen Schwachstellendatenbank.
- Für automatische Image-Aktualisierungen: passende Compose-Projekte und verfügbare Projektdateien.
- Für Mailberichte: erreichbarer SMTP-Server und gültige Versanddaten.

### Schnellstart

1. Kopiere den **inneren Ordner [securitywatch/](securitywatch/)** nach `/volume2/docker/securitywatch/`. Der Repository-Root enthält zusätzlich Handbuch, Bilder und Projektdateien.
2. Verbinde dich per SSH und bereite die Erstinstallation vor:

```bash
sudo -i
cd /volume2/docker/securitywatch
cp .env.example .env
chmod +x securitywatch_scan.sh securitywatch_report.py securitywatch_mail.py
```

3. Bearbeite `.env`: Setze Sprache, Pfade und SMTP-Daten. Entscheide vor dem ersten regulären Lauf über die automatischen Aktionen im nächsten Abschnitt. Bei einer bestehenden Installation behältst du deine `.env`.
4. Starte einen ersten Scan ohne Docker-Bereinigung, lokale Rebuilds oder Container-Image-Updates:

```bash
./securitywatch_scan.sh --no-cleanup --no-local-image-rebuild \
  --no-image-update-check --no-image-update-recreate
```

Mit `--no-mail` erzeugst du Berichte ohne E-Mail-Versand. Prüfe den neuen Report-Ordner und richte danach den Zeitplan ein.

### Konfiguration

Die Datei [.env.example](securitywatch/.env.example) beschreibt alle Werte auf Deutsch und Englisch.

| Bereich | Wichtige Werte |
|---|---|
| Sprache | `OUTPUT_LANG=de` oder `OUTPUT_LANG=en` |
| Ablage | `BASE_DIR`, `REPORT_DIR`, `CACHE_DIR`, `STATE_DIR` |
| Trivy | `TRIVY_IMAGE`, `TRIVY_SEVERITIES`, `TRIVY_TIMEOUT`, `TRIVY_IGNORE_UNFIXED` |
| Scanumfang | `TRIVY_SCAN_FILESYSTEM`, `TRIVY_SCAN_IMAGES`, `TRIVY_SKIP_DIRS` |
| SMTP | `SMTP_SERVER`, `SMTP_PORT`, `SMTP_STARTTLS`, `SMTP_FROM`, `SMTP_TO` |
| Anmeldung | `SMTP_USER`, `SMTP_PASS` oder `SMTP_PASS_FILE` |
| Mailauswahl | `MAIL_ONLY_ON_FINDINGS`, `MAIL_SEND_OK`, `MAIL_SUBJECT_PREFIX` |
| Berichte | `REPORT_CLEANUP_ENABLED`, `REPORT_RETENTION_DAYS`, `REPORT_KEEP_LAST` |

Die Vorlage scannt `HIGH,CRITICAL` und blendet Funde ohne verfügbaren Fix nicht aus (`TRIVY_IGNORE_UNFIXED=0`). `TRIVY_SKIP_DIRS` nimmt unter anderem `/host/volume1`, `/host/volume2` und `/host/volume3` vom Host-Scan aus. Prüfe diese Auswahl für deine NAS.

#### Automatische Aktionen

**Die mitgelieferte ENV-Vorlage aktiviert die folgenden Aktionen.** Ein regulärer Aufruf kann deshalb Images entfernen oder Compose-Services neu erstellen.

| Einstellung in der Vorlage | Wirkung |
|---|---|
| `DOCKER_CLEANUP_BEFORE_SCAN=1` | Docker-Bereinigung vor dem Scan |
| `DOCKER_PRUNE_UNUSED_IMAGES=1` | Unbenutzte Images entfernen; bei `0` nur Images ohne Tag und ohne Verwendung |
| `DOCKER_PRUNE_BUILD_CACHE=1` | Ungenutzten Build-Cache entfernen |
| `LOCAL_IMAGE_AUTO_REBUILD_ENABLED=1` | Betroffene lokale Compose-Images mit behebbaren Funden neu bauen und den Service neu erstellen |
| `IMAGE_UPDATE_CHECK_ENABLED=1` | Neuere Registry-Images per `docker pull` laden |
| `IMAGE_UPDATE_AUTO_RECREATE_ENABLED=1` | Betroffene Compose-Services mit dem neu geladenen Image neu erstellen |

Mit `DOCKER_CLEANUP_BEFORE_SCAN=0` deaktivierst du die gesamte Docker-Bereinigung. Für reine Prüfung ohne automatische Service-Änderungen setze `LOCAL_IMAGE_AUTO_REBUILD_ENABLED=0` und `IMAGE_UPDATE_AUTO_RECREATE_ENABLED=0`. Mit `IMAGE_UPDATE_CHECK_ENABLED=0` entfällt auch das Laden neuer Container-Images. Die CLI-Schalter im Schnellstart gelten jeweils nur für diesen Lauf.

### Zeitplan und Berichte

Ein Aufruf ohne Zusatzoptionen verwendet deine `.env`:

```bash
cd /volume2/docker/securitywatch
./securitywatch_scan.sh
```

Nach einem erfolgreichen manuellen Test kannst du mit `crontab -e` einen täglichen Lauf um 06:30 Uhr einrichten:

```cron
30 6 * * * cd /volume2/docker/securitywatch && /volume2/docker/securitywatch/securitywatch_scan.sh >> /volume2/docker/securitywatch/cron.log 2>&1
```

Jeder Lauf legt einen eigenen Report-Ordner an. Die Vorlage verwendet für die Bereinigung alter Berichte `REPORT_RETENTION_DAYS=30` und `REPORT_KEEP_LAST=10`. Mit `--no-report-cleanup` setzt du diese Bereinigung für einen Lauf aus. Alle Aufrufoptionen zeigt `./securitywatch_scan.sh --help` bei vorhandener `.env`.

![Beispielbericht Deutsch](Screens/Securitywatch.jpg)

### Aktualisierung

Ersetze die drei Skripte aus [securitywatch/](securitywatch/) durch den aktuellen Stand. Behalte deine `.env`, Berichte, Cache- und Zustandsordner. Vergleiche neue Einstellungen in `.env.example` mit deiner Konfiguration und führe danach einen manuellen Test aus.

### Projektstruktur und Dokumentation

| Datei | Aufgabe |
|---|---|
| [securitywatch_scan.sh](securitywatch/securitywatch_scan.sh) | Scan und konfigurierte Wartungsaktionen |
| [securitywatch_report.py](securitywatch/securitywatch_report.py) | Zusammenfassung und Mailinhalt |
| [securitywatch_mail.py](securitywatch/securitywatch_mail.py) | SMTP-Versand |
| [.env.example](securitywatch/.env.example) | Deutsche und englische Konfigurationsvorlage |
| [Handbuch DE/EN](UGREEN_SecurityWatch_Handbuch_DE-EN.pdf) | Ausführliche Anleitung als PDF |

### Lizenz

[MIT-Lizenz](LICENSE). Roman Glos / Railsimulatornet.

## English

Script package for **UGREEN NAS running UGOS**. SecurityWatch scans the host filesystem and the Docker images of running containers with Trivy. It generates reports and can send them as plain text and HTML email. Configuration also controls Docker cleanup and automatic image updates.

### Features

- Host scan with Trivy `rootfs` against `/host`, plus scans of images used by running containers.
- Reports as `summary.json`, `mail.txt` and `mail.html`, with one folder per run under `reports/`.
- German or English output through `OUTPUT_LANG`.
- Additional report for locally built images and their fixable package findings.
- Configurable Docker cleanup, rebuilds of local Compose images and registry image updates.
- Email only on findings or additionally as an OK report; configurable report retention.

### Requirements

- UGREEN NAS with a running Docker service and SSH access.
- Bash, Python 3 and sufficient permissions for host and Docker access; the examples use a root session.
- Access to the Trivy image and its vulnerability database.
- For automatic image updates: suitable Compose projects and accessible project files.
- For email reports: a reachable SMTP server and valid delivery settings.

### Quick start

1. Copy the **inner [securitywatch/](securitywatch/) folder** to `/volume2/docker/securitywatch/`. The repository root also contains the manual, images and project files.
2. Connect over SSH and prepare the first installation:

```bash
sudo -i
cd /volume2/docker/securitywatch
cp .env.example .env
chmod +x securitywatch_scan.sh securitywatch_report.py securitywatch_mail.py
```

3. Edit `.env`: Set the language, paths and SMTP details. Choose the automatic actions described below before your first regular run. Keep your existing `.env` when updating an installation.
4. Run an initial scan without Docker cleanup, local rebuilds or container image updates:

```bash
./securitywatch_scan.sh --no-cleanup --no-local-image-rebuild \
  --no-image-update-check --no-image-update-recreate
```

Add `--no-mail` to generate reports without sending email. Check the new report folder before setting up a schedule.

### Configuration

[.env.example](securitywatch/.env.example) documents all values in German and English.

| Area | Important values |
|---|---|
| Language | `OUTPUT_LANG=de` or `OUTPUT_LANG=en` |
| Storage | `BASE_DIR`, `REPORT_DIR`, `CACHE_DIR`, `STATE_DIR` |
| Trivy | `TRIVY_IMAGE`, `TRIVY_SEVERITIES`, `TRIVY_TIMEOUT`, `TRIVY_IGNORE_UNFIXED` |
| Scan scope | `TRIVY_SCAN_FILESYSTEM`, `TRIVY_SCAN_IMAGES`, `TRIVY_SKIP_DIRS` |
| SMTP | `SMTP_SERVER`, `SMTP_PORT`, `SMTP_STARTTLS`, `SMTP_FROM`, `SMTP_TO` |
| Authentication | `SMTP_USER`, `SMTP_PASS` or `SMTP_PASS_FILE` |
| Email selection | `MAIL_ONLY_ON_FINDINGS`, `MAIL_SEND_OK`, `MAIL_SUBJECT_PREFIX` |
| Reports | `REPORT_CLEANUP_ENABLED`, `REPORT_RETENTION_DAYS`, `REPORT_KEEP_LAST` |

The template scans `HIGH,CRITICAL` and includes findings without an available fix (`TRIVY_IGNORE_UNFIXED=0`). `TRIVY_SKIP_DIRS` excludes paths including `/host/volume1`, `/host/volume2` and `/host/volume3` from the host scan. Review this selection for your NAS.

#### Automatic actions

**The supplied ENV template enables the following actions.** A regular run can therefore remove images or recreate Compose services.

| Template setting | Effect |
|---|---|
| `DOCKER_CLEANUP_BEFORE_SCAN=1` | Clean up Docker before scanning |
| `DOCKER_PRUNE_UNUSED_IMAGES=1` | Remove unused images; with `0`, remove only untagged, unused images |
| `DOCKER_PRUNE_BUILD_CACHE=1` | Remove unused build cache |
| `LOCAL_IMAGE_AUTO_REBUILD_ENABLED=1` | Rebuild affected local Compose images with fixable findings and recreate their services |
| `IMAGE_UPDATE_CHECK_ENABLED=1` | Download newer registry images using `docker pull` |
| `IMAGE_UPDATE_AUTO_RECREATE_ENABLED=1` | Recreate affected Compose services with the newly downloaded image |

Set `DOCKER_CLEANUP_BEFORE_SCAN=0` to disable all Docker cleanup. For scanning without automatic service changes, set `LOCAL_IMAGE_AUTO_REBUILD_ENABLED=0` and `IMAGE_UPDATE_AUTO_RECREATE_ENABLED=0`. Setting `IMAGE_UPDATE_CHECK_ENABLED=0` also prevents downloading newer container images. The command-line switches in the quick start apply to that run only.

### Schedule and reports

A run without additional options uses your `.env`:

```bash
cd /volume2/docker/securitywatch
./securitywatch_scan.sh
```

After a successful manual test, use `crontab -e` to schedule a daily run at 06:30:

```cron
30 6 * * * cd /volume2/docker/securitywatch && /volume2/docker/securitywatch/securitywatch_scan.sh >> /volume2/docker/securitywatch/cron.log 2>&1
```

Each run creates a separate report folder. The template uses `REPORT_RETENTION_DAYS=30` and `REPORT_KEEP_LAST=10` to clean up old reports. Add `--no-report-cleanup` to skip that cleanup for one run. With an existing `.env`, `./securitywatch_scan.sh --help` lists all command-line options.

![Example report in English](Screens/SecuritywatchEN.jpg)

### Updates

Replace the three scripts from [securitywatch/](securitywatch/) with the current versions. Keep your `.env`, reports, cache and state folders. Compare new settings in `.env.example` with your configuration, then run a manual test.

### Project structure and documentation

| File | Purpose |
|---|---|
| [securitywatch_scan.sh](securitywatch/securitywatch_scan.sh) | Scanning and configured maintenance actions |
| [securitywatch_report.py](securitywatch/securitywatch_report.py) | Summary and email content |
| [securitywatch_mail.py](securitywatch/securitywatch_mail.py) | SMTP delivery |
| [.env.example](securitywatch/.env.example) | German and English configuration template |
| [DE/EN manual](UGREEN_SecurityWatch_Handbuch_DE-EN.pdf) | Detailed PDF guide |

### License

[MIT License](LICENSE). Roman Glos / Railsimulatornet.
