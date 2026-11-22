# UGREEN SecurityWatch 4.2

[![Quality](https://github.com/Railsimulatornet/UGREEN-NAS-SecurityWatch/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/Railsimulatornet/UGREEN-NAS-SecurityWatch/actions/workflows/quality.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

SecurityWatch prüft das NAS-Dateisystem und die Images laufender Docker-Container mit Trivy. Es baut zugeordnete lokale Images regelmäßig neu und übernimmt geeignete lokale oder veröffentlichte Kandidaten mit Zustandsprüfung und geschütztem Rückfall. Berichte und E-Mails sind auf Deutsch.

## Inhalt der Mail

- Betroffene Container mit kritischen und hohen Paketbefunden und bekannten Paketkorrekturen — auch bei einem reinen Berichtslauf.
- Welche Images neu gebaut wurden, ob sie tatsächlich übernommen wurden und welche Befunde im laufenden Stand verbleiben.
- Getrennte Ergebnisse für verworfene Kandidaten, zurückgesetzte Dienste und unbekannte Prüfstände.
- Ein kurzer Auszug der NAS-/UGOS-Paketbefunde und konkrete offene Aktualisierungsvoraussetzungen.
- Aufbewahrung und Bereinigung von Vorversionen und Berichten.

Ein Image wird bei mehreren Containern einmal gezählt. Die Zahlen bezeichnen Paketbefunde, nicht ausschließlich verschiedene CVE-Nummern oder nachgewiesene Angriffswege. Herstelleranpassungen und unbekannte Schwachstellen können nicht allein aus Versionsangaben beurteilt werden. SecurityWatch installiert keine UGOS- oder Host-Paketaktualisierungen.

Die HTML-Mail ist einspaltig, auf 680 Pixel begrenzt und besitzt eine Klartextalternative. Sie benötigt keine externen Bilder oder Schriftarten.

## Voraussetzungen

Python **3.11 oder neuer**, Bash und Docker mit Compose und Buildx. Außerdem Zugriff auf den lokalen Docker-Dienst und die tatsächlichen Compose-Projekte, genügend Speicher für Prüfdatenbanken und Kandidaten sowie ein SMTP-Server für E-Mails.

Die automatisierten Tests laufen ausdrücklich unter Python 3.11 und 3.12. Docker-, Registry- und SMTP-Interaktionen werden in diesen Tests nachgebildet. Ein tatsächlicher Durchlauf auf dem eigenen NAS bleibt erforderlich.

## Bestehende Installation aktualisieren

Den Ordner [`securitywatch/`](securitywatch/) als separaten Paketordner auf das NAS kopieren. Die bestehende Installation samt `.env` nicht manuell überschreiben:

```bash
(
  set -e
  paket=/volume2/docker/securitywatch-update-4.2.0
  sudo python3 "$paket/install_securitywatch.py" --check
  sudo python3 "$paket/install_securitywatch.py" --install
  sudo /volume2/docker/securitywatch/securitywatch_scan.sh --check
)
```

Der Installer prüft das Paket, sichert die bisherigen Programme und erhält Konfiguration und Zustandsdaten. Er startet keinen Wartungslauf und verändert keinen Zeitplan. Eine unterbrochene Installation sperrt normale Läufe bis zur vollständigen Installation oder Wiederherstellung.

Für eine Erstinstallation den Ordner `securitywatch/` am gewünschten Ort ablegen, `.env.example` als `.env` übernehmen und Pfade sowie Maildaten anpassen. Danach mit Vorprüfung und Bericht beginnen.

## Aufrufe und Zeitplan

```bash
# Bestand und Voraussetzungen prüfen
sudo /volume2/docker/securitywatch/securitywatch_scan.sh --check

# Sicherheitsbericht und Mail ohne Austausch der Anwendungsimages
sudo /volume2/docker/securitywatch/securitywatch_scan.sh --report-only

# Bericht ohne Versand
sudo /volume2/docker/securitywatch/securitywatch_scan.sh --report-only --no-mail

# Reguläre Prüfung mit freigegebenen Wartungsaktionen
sudo /volume2/docker/securitywatch/securitywatch_scan.sh
```

Auch Vorprüfungen und reine Berichtsläufe wenden die konfigurierte Berichtsaufbewahrung an. `--no-report-cleanup` setzt sie einmalig aus. Anwendungsimages werden bei `--report-only` weder neu gebaut noch ersetzt oder gelöscht.

Für einen Wochenlauf kann der vorhandene NAS-Zeitplan verwendet werden. Beispiel für einen Host in Europe/Berlin:

```cron
0 6 * * 0 /volume2/docker/securitywatch/securitywatch_scan.sh >> /volume2/docker/securitywatch/cron.log 2>&1
```

GitHub-Bauten sollten bereits am Samstag stattfinden, damit ihre geprüften Veröffentlichungen vor dem Sonntagslauf bereitliegen. SecurityWatch richtet keinen zweiten Zeitplan ein.

## Lokale Neubauten und Übernahme

Ein lokaler Kandidat wird mit der tatsächlich zugeordneten Compose-Bauanleitung getrennt gebaut. Ausgangsimage und Kandidat werden anhand ihrer festen Image-IDs mit derselben Schwachstellendatenbank verglichen. Neue oder höher bewertete hohe/kritische Befunde verhindern die Übernahme.

Für den Austausch ist zusätzlich eine belastbare Zustandsprüfung notwendig. Fehlt sie, kann SecurityWatch einen lokalen Kandidaten trotzdem bauen und prüfen. Das laufende Image bleibt erhalten und wird nicht als repariert dargestellt. Ein ausschließlich vorübergehend erzeugter Kandidat wird anschließend entfernt.

Regelmäßige Neubauten haben standardmäßig 144 Stunden Abstand. Fehlgeschlagene Versuche dürfen nach 24 Stunden wiederholt werden. Geänderte Baugrundlagen, geänderte Befunde oder eine inzwischen mögliche Übernahme erlauben eine frühere Prüfung. `--force-rebuild` überspringt die Wartefrist, ohne Schutzprüfungen abzuschalten.

Ein Neubau aktualisiert nicht automatisch festgeschriebene Anwendungsabhängigkeiten oder einen Git-Arbeitsstand. Diese Quellen gehören zur Pflege des jeweiligen Projekts. Verbleibende Paketbefunde werden weiter gemeldet.

## Aufbewahrung

| Inhalt | Standard und Schutz |
|---|---|
| Ersetzte Images | Mindestens sieben volle Tage ab dem erfolgreich geprüften Austausch |
| Berichte | 30 Tage, mindestens die letzten zehn Läufe |
| Aktueller Bericht | Wird durch seinen eigenen Lauf niemals entfernt |
| Offene Wiederherstellung | Betroffene Images geschützt; Berichtsbereinigung zurückgestellt |

Vorversionen werden beim nächsten zulässigen Wartungslauf entfernt, sofern sie nicht mehr verwendet werden und ihr Nachfolger weiterhin bestätigt ist. Es gibt kein pauschales `docker image prune` und keine pauschale Leerung des Bauzwischenspeichers.

Neue Berichtsordner heißen `JJJJ-MM-TT_HH-MM-SS`. Bei einer Kollision wird kurz auf die nächste tatsächliche Sekunde gewartet. Vorhandene Berichte werden nie überschrieben. Bisherige Ordner mit Zusatz und nachweisbar vollständige ältere SecurityWatch-Berichte werden ebenfalls berücksichtigt. Unbekannte Ordner bleiben erhalten.

## GitHub

Die Datei [`securitywatch.github.example.json`](securitywatch/securitywatch.github.example.json) zeigt die Zuordnung von Repository, tatsächlichem Veröffentlichungsablauf, Zweig und Image-Mustern. Die aktive allgemeine Vorlage ist zunächst deaktiviert. Die Überwachung liest nur; sie verändert keine Repository-Dateien und startet keine Builds.

Ein erfolgreicher beliebiger GitHub-Ablauf beweist keine Image-Veröffentlichung. Feste Versionsnamen und Prüfsummen werden nicht stillschweigend auf andere Aktualisierungskanäle umgestellt.

`securitywatch_project_updates.py` ist ein begrenzter Helfer für drei ausdrücklich zugeordnete bestehende Projekte, kein allgemeiner Umstellungsassistent. `--check` zeigt den Plan, `--apply` übernimmt einen geprüften Kandidaten. Eine Rückkehr zum alten Image stellt keine Anwendungsdaten wieder her.

## Einstellungen

Die vollständige Vorlage liegt in [`.env.example`](securitywatch/.env.example). Vorhandene Zugangsdaten bleiben bei der Installation erhalten.

| Einstellung | Bedeutung |
|---|---|
| `LOCAL_IMAGE_AUTO_REBUILD_ENABLED` | Regelmäßige lokale Neubauten erlauben |
| `IMAGE_UPDATE_CHECK_ENABLED` | Veröffentlichte Versionen prüfen |
| `IMAGE_UPDATE_AUTO_RECREATE_ENABLED` | Geeignete Veröffentlichungen übernehmen |
| `IMAGE_RETENTION_DAYS` | Vorversionen aufbewahren; mindestens 7 |
| `REPORT_CLEANUP_ENABLED` | Berichtsbereinigung ein-/ausschalten |
| `REPORT_RETENTION_DAYS` | Altersschwelle für Berichte |
| `REPORT_KEEP_LAST` | Mindestanzahl der letzten Berichte |
| `MAIL_SEND_ON_IMAGE_UPDATES` | Aktualisierungen und Wartungshindernisse melden |
| `MAIL_SEND_WEEKLY_SUMMARY` | Zusammenfassung des regulären Wartungslaufs |

Der dauerhafte Ordner `state/` enthält Image-Zuordnungen, Fristen und Wiederherstellungsjournale. Er gehört zur Installation und darf nicht als Zwischenspeicher gelöscht werden. Anwendungsdaten benötigen weiterhin eigene Sicherungen.

## Dokumentation und Lizenz

Dieses README beschreibt die aktuelle Fassung. Ältere Bildschirmbilder und das vorhandene PDF-Handbuch dokumentieren die frühere Oberfläche. Deren Bereinigungs- und Installationsanweisungen gelten nicht für Version 4.2.

[MIT-Lizenz](LICENSE). Roman Glos / Railsimulatornet.
