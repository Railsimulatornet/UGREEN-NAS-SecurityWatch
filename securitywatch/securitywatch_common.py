#!/usr/bin/env python3
"""Gemeinsame, ohne Shell-Auswertung verwendete Einstellungen und Dateizugriffe."""
from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

VERSION = "4.2.0"
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


class ConfigurationError(ValueError):
    pass


def _strip_env_comment(value: str) -> str:
    """Only an unquoted # after whitespace begins an inline comment.

    An embedded # (including NAME=#password) belongs to the assignment.
    No shell expansions, substitutions or commands are evaluated.
    """
    quote = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "#" and index > 0 and value[index - 1].isspace():
            return value[:index]
    return value


def load_env(path: Path) -> dict[str, str]:
    """Read assignments as data. In particular, never source or eval an .env file."""
    return parse_env_text(path.read_text(encoding="utf-8-sig"))


def parse_env_text(text: str) -> dict[str, str]:
    """Shared parser for the running program and the standalone installer."""
    result: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ConfigurationError(f"Ungültige Einstellungszeile {number}; erwartet wird NAME=WERT.")
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ConfigurationError(f"Ungültiger Einstellungsname in Zeile {number}.")
        try:
            fields = shlex.split(_strip_env_comment(value).strip(), comments=False, posix=True)
        except ValueError as exc:
            raise ConfigurationError(f"Nicht geschlossene Anführungszeichen in Zeile {number}.") from exc
        result[key] = " ".join(fields)
    return result


def enabled(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def bounded_int(env: dict, name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(env.get(name, default)))
    except (ValueError, TypeError) as exc:
        raise ConfigurationError(f"{name} muss eine ganze Zahl sein.") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} muss zwischen {minimum} und {maximum} liegen.")
    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def berlin_now() -> datetime:
    return datetime.now(ZoneInfo("Europe/Berlin"))


def private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ConfigurationError("Ein benötigter Arbeitsordner ist nicht verfügbar.")
    return path


def atomic_json(path: Path, data: object) -> None:
    private_directory(path.parent)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


class RunLock:
    """One lock for scan/update and installer. Do not delete the lock inode."""
    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def __enter__(self):
        private_directory(self.path.parent)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.handle = os.fdopen(fd, "r+")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.handle.close()
            self.handle = None
            raise ConfigurationError("SecurityWatch oder die Installation läuft bereits. Kein zweiter Lauf gestartet.")
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(f"{os.getpid()}\n")
        self.handle.flush()
        return self

    def __exit__(self, *_):
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()


def patterns(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def safe_field(value: object) -> str:
    return str(value or "").replace("\t", " ").replace("\n", " ").replace("\r", " ")
