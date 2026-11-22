#!/usr/bin/env python3
"""Read-only local-image classification for SecurityWatch Classic.

No pull, build, registry request or Docker modification. Uses only stdlib.
Missing RepoDigests alone and registry failures NEVER imply a local build.
Compose build+image is not sufficient when pull_policy chooses the registry.
Only the small classification result is returned; resolved configs (which
may contain secrets) and subprocess stderr are never logged or persisted.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Optional, Sequence, Tuple

TIMEOUT_SECONDS = 12


def clean(value: str) -> str:
    value = (value or "").strip()
    return "" if value in {"<no value>", "<nil>", "null"} else value


def matches(value: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern.strip())
               for pattern in patterns if pattern.strip())


def explicit_patterns(path: str) -> list[str]:
    if not path or not Path(path).is_file():
        return []
    return [s.strip() for s in Path(path).read_text(encoding="utf-8-sig").splitlines()
            if s.strip() and not s.lstrip().startswith("#")]


def normalized_ref(ref: str) -> str:
    # Only compare local/tag aliases. Never rewrite qualified names or digest pins.
    if "@" not in ref and ":" not in ref.rsplit("/", 1)[-1]:
        return ref + ":latest"
    return ref


def json_command(command: list[str], cwd: Optional[str] = None) -> Any:
    try:
        result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=TIMEOUT_SECONDS, check=False,
                                encoding="utf-8", errors="replace")
        if result.returncode:
            return None
        return json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def image_metadata(image_id: str) -> Optional[dict]:
    if not image_id:
        return None
    doc = json_command(["docker", "image", "inspect", image_id])
    if isinstance(doc, list) and len(doc) == 1 and isinstance(doc[0], dict):
        return doc[0]
    return None


def compose_service(project: str, service: str, workdir: str,
                    config_files: str, compose_bin: str = "") -> Optional[dict]:
    """Resolve the actual local Compose inputs, without building/pulling anything."""
    if not service or not workdir or not Path(workdir).is_dir() or not config_files:
        return None
    files = []
    for raw in config_files.split(","):
        raw = raw.strip()
        if not raw or "://" in raw or "\n" in raw or "\r" in raw:
            return None
        path = Path(raw)
        if not path.is_absolute():
            path = Path(workdir) / path
        if not path.is_file():
            return None
        files += ["-f", str(path)]
    prefixes = ([["docker-compose"]] if compose_bin == "docker-compose" else
                [["docker", "compose"], ["docker-compose"]])
    for prefix in prefixes:
        args = prefix + (["-p", project] if project else []) + files
        # Older Compose releases may not support --no-env-resolution. The fallback
        # remains read-only; neither version's output is persisted or logged.
        for optional in (["--no-env-resolution"], []):
            doc = json_command(args + ["config", "--format", "json"] + optional, workdir)
            if isinstance(doc, dict) and isinstance(doc.get("services"), dict):
                value = doc["services"].get(service)
                return value if isinstance(value, dict) else None
    return None


def classify(image_ref: str, project: str = "", service: str = "",
             include: Sequence[str] = (), exclude: Sequence[str] = (),
             overrides: Sequence[str] = (), metadata: Optional[dict] = None,
             config: Optional[dict] = None) -> Tuple[str, str]:
    """Pure decision function: origin and non-sensitive evidence code."""
    image_ref, project, service = map(clean, (image_ref, project, service))
    if not image_ref:
        return "unknown", "missing_image_reference"
    if matches(image_ref, exclude):
        return "registry", "explicit_exclude"
    if matches(image_ref, include) or matches(image_ref, overrides):
        return "local", "explicit_local_mapping"
    if "@" in image_ref or image_ref.startswith("sha256:"):
        return "registry", "pinned_reference"

    digests = metadata.get("RepoDigests") if isinstance(metadata, dict) else None
    has_registry_digest = isinstance(digests, list) and bool(digests)
    inspected_without_digest = isinstance(metadata, dict) and digests in (None, [])
    if isinstance(config, dict):
        build = config.get("build")
        buildable = isinstance(build, (dict, str)) and bool(build)
        declared_image = clean(str(config.get("image") or ""))
        same_ref = not declared_image or normalized_ref(declared_image) == normalized_ref(image_ref)
        if declared_image and not same_ref:
            return "registry", "compose_image_mismatch"
        if buildable and same_ref:
            policy = str(config.get("pull_policy") or "").lower()
            if policy in {"build", "never"}:
                return "local", "compose_build_policy"
            if not declared_image:
                return "local", "compose_build_only"
            # An explicit registry-refresh policy must not silently become local.
            if policy in {"always", "daily", "weekly"} or policy.startswith("every_"):
                return "registry", "compose_registry_policy"
            if has_registry_digest:
                return "registry", "compose_build_with_registry_image"
            if inspected_without_digest:
                return "local", "compose_build_without_registry_digest"

    # Do not misclassify known pulled or registry-qualified images by a tag suffix.
    if has_registry_digest:
        return "registry", "registry_digest"
    short_name = "/" not in image_ref
    tail = image_ref.rsplit("/", 1)[-1]
    tag = tail.split(":", 1)[1] if ":" in tail else ""
    if short_name and (tag == "local" or tag.endswith("-local") or tag.startswith("local-")):
        return "local", "local_tag_convention"
    if short_name and project and service:
        bare_name = tail.split(":", 1)[0]
        if bare_name in {f"{project}-{service}", f"{project}_{service}"}:
            return "local", "compose_default_name"
    return "registry", "no_local_evidence"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("image-ref", "project", "service", "working-dir", "config-files",
                 "image-id", "include", "exclude", "overrides-file", "compose-bin"):
        ap.add_argument("--" + name, default="")
    ns = ap.parse_args()
    include, exclude = ns.include.split(","), ns.exclude.split(",")
    overrides = explicit_patterns(ns.overrides_file)
    # Explicit mappings do not depend on Compose availability or registry access.
    direct = classify(ns.image_ref, ns.project, ns.service, include, exclude, overrides)
    if direct[1] in {"explicit_exclude", "explicit_local_mapping", "pinned_reference", "missing_image_reference"}:
        answer = direct
    else:
        metadata = image_metadata(clean(ns.image_id))
        config = compose_service(clean(ns.project), clean(ns.service),
                                 clean(ns.working_dir), clean(ns.config_files), ns.compose_bin)
        answer = classify(ns.image_ref, ns.project, ns.service, include, exclude,
                          overrides, metadata, config)
    print("\t".join(answer))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError):
        # No tracebacks or config contents in mail/process logs. The caller
        # reports an explicit error and must not initiate a registry update.
        print("unknown\tclassification_unavailable")
        raise SystemExit(2)
