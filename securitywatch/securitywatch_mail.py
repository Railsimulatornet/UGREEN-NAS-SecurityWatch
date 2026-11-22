#!/usr/bin/env python3
# Copyright Roman Glos 2026
"""Versand der kurzen SecurityWatch-Nachricht mit gemeinsamer Statusentscheidung."""

import argparse
import json
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from securitywatch_notifications import enabled, mail_decision
from securitywatch_common import atomic_json, load_env, now_iso


def parse_env(path: Path) -> dict:
    return load_env(path)


def to_bool(value: str, default: bool = False) -> bool:
    return enabled(value, default)


def normalize_lang(value: str) -> str:
    return "de" if str(value or "de").strip().lower() != "en" else "en"


def create_message(env: dict, subject: str, plain_text: str, html_text: str) -> EmailMessage:
    missing = [key for key in ("SMTP_SERVER", "SMTP_FROM", "SMTP_TO") if not str(env.get(key) or "").strip()]
    if missing:
        raise ValueError("Fehlende SMTP-Pflichtwerte: " + ", ".join(missing))
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = env["SMTP_FROM"]
    message["To"] = env["SMTP_TO"]
    message.set_content(plain_text)
    message.add_alternative(html_text, subtype="html")
    return message


def send_message(env: dict, message: EmailMessage) -> None:
    port = int(env.get("SMTP_PORT") or "587")
    if not 1 <= port <= 65535:
        raise ValueError("Ungültiger SMTP-Port")
    implicit_tls = enabled(env.get("SMTP_SSL"), port == 465)
    starttls = enabled(env.get("SMTP_STARTTLS"), True)
    context = ssl.create_default_context()
    user = env.get("SMTP_USER", "")
    password = env.get("SMTP_PASS", "")
    if not password and env.get("SMTP_PASS_FILE"):
        password = Path(env["SMTP_PASS_FILE"]).read_text(encoding="utf-8").strip()

    # Zertifikats- und Hostnamenprüfung bleiben für beide TLS-Arten aktiv.
    if implicit_tls:
        connection = smtplib.SMTP_SSL(env["SMTP_SERVER"], port, timeout=30, context=context)
    else:
        connection = smtplib.SMTP(env["SMTP_SERVER"], port, timeout=30)
    with connection as smtp:
        smtp.ehlo()
        if not implicit_tls and starttls:
            smtp.starttls(context=context)
            smtp.ehlo()
        if user:
            smtp.login(user, password)
        smtp.send_message(message)


def write_delivery_result(path: str | None, status: str, subject: str = "") -> None:
    if path:
        atomic_json(Path(path), {"version": 1, "status": status, "recorded_at": now_iso(), "subject": subject})


def main() -> None:
    parser = argparse.ArgumentParser(description="Kurze deutsche SecurityWatch-Nachricht versenden.")
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--mail-txt", required=True)
    parser.add_argument("--mail-html", required=True)
    parser.add_argument("--render-only", action="store_true", help="Nur Betreff und Versandentscheidung ausgeben; keine Verbindung zum Mailserver.")
    parser.add_argument("--result-json", help="Versandstatus atomar in dieser JSON-Datei festhalten.")
    args = parser.parse_args()

    try:
        env = parse_env(Path(args.env_file))
        summary = json.loads(Path(args.summary_json).read_text(encoding="utf-8"))
        if not isinstance(summary, dict):
            raise ValueError("Ungültige Zusammenfassung")
        decision = mail_decision(summary, env)
    except (OSError, UnicodeError, ValueError, TypeError):
        write_delivery_result(args.result_json, "failed")
        raise SystemExit("Die Mailgrundlagen konnten nicht gelesen werden. Konfiguration und Zusammenfassung prüfen.")

    if args.render_only:
        write_delivery_result(args.result_json, "rendered", decision["subject"])
        print(json.dumps({key: decision[key] for key in ("subject", "send", "required")}, ensure_ascii=False, indent=2))
        return
    if not decision["send"]:
        write_delivery_result(args.result_json, "skipped", decision["subject"])
        print("Keine meldepflichtigen Ereignisse. Für diesen Lauf wird keine E-Mail versendet.")
        return

    missing = [key for key in ("SMTP_SERVER", "SMTP_FROM", "SMTP_TO") if not str(env.get(key) or "").strip()]
    if missing:
        write_delivery_result(args.result_json, "failed", decision["subject"])
        raise SystemExit("Fehlende SMTP-Pflichtwerte in der .env: " + ", ".join(missing))
    try:
        message = create_message(env, decision["subject"], Path(args.mail_txt).read_text(encoding="utf-8"), Path(args.mail_html).read_text(encoding="utf-8"))
        write_delivery_result(args.result_json, "sending", decision["subject"])
        send_message(env, message)
    except (OSError, UnicodeError, ValueError, smtplib.SMTPException):
        # Serverantworten und Ausnahmen können Adressen, Zugangsdaten oder
        # Bestandteile einer fehlgeschlagenen Anmeldung enthalten.
        write_delivery_result(args.result_json, "failed", decision["subject"])
        raise SystemExit("Die E-Mail konnte nicht versendet werden. Mailserver, Verbindung, Zertifikat und Zugangseinstellungen prüfen.")
    try:
        write_delivery_result(args.result_json, "sent", decision["subject"])
    except OSError:
        raise SystemExit("Die Nachricht wurde dem Mailserver übergeben; der Versandnachweis konnte nicht gespeichert werden.")
    print("E-Mail erfolgreich versendet.")


if __name__ == "__main__":
    main()
