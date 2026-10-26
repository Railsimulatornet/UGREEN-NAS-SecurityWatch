#!/usr/bin/env python3
"""Fail-closed automatic merge of CodeQL-only patch updates.

Trusted code from the repository default branch performs the merge. Never
checks out or executes the Dependabot PR branch with a write token.
"""
import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

OWNER = "Railsimulatornet"
REPOSITORIES = {"UGREEN-NAS-EmbyConvert", "UGREEN-NAS-SecurityWatch"}
PIN = re.compile(
    r"^\s*uses:\s*github/codeql-action/(init|analyze)@([a-f0-9]{40})(?:\s*#.*)?\s*$"
)
VERSIONS = re.compile(
    r"Updates \x60github/codeql-action(?:/(?:init|analyze))?\x60 from "
    r"(\d+\.\d+\.\d+) to (\d+\.\d+\.\d+)"
)
REQUIRED_RUNS = {"CodeQL", "Quality checks"}
REQUIRED_CHECKS = {"CodeQL", "Analyze (actions)", "Analyze (python)", "validate"}
ALLOWED_SKIPPED = {"classify", "merge"}


class StopMerge(Exception):
    """Expected, safe rejection of an unverified candidate."""


class API:
    def __init__(self, repository, token):
        self.repository = repository
        self.token = token

    def request(self, path, method="GET", data=None):
        url = "https://api.github.com" + path
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self.token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codeql-verified-automerge",
        }
        body = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, headers=headers, data=body, method=method)
        try:
            with urllib.request.urlopen(req, timeout=25) as reply:
                raw = reply.read()
                return json.loads(raw) if raw else None
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise RuntimeError(f"GitHub {method} {path}: {exc}") from exc

    def get(self, path):
        return self.request(path)

    def pages(self, path, field=None):
        items = []
        for page in range(1, 11):
            delim = "&" if "?" in path else "?"
            obj = self.get(f"{path}{delim}per_page=100&page={page}")
            part = obj[field] if field else obj
            if not isinstance(part, list):
                raise StopMerge("GitHub returned a non-list page")
            items.extend(part)
            if len(part) < 100:
                return items
        raise StopMerge("Unbounded GitHub pagination")

    def file(self, path, sha):
        encoded = urllib.parse.quote(path, safe="/")
        obj = self.get(f"/repos/{self.repository}/contents/{encoded}?ref={sha}")
        import base64
        if obj.get("encoding") != "base64":
            raise StopMerge("Unexpected file encoding")
        return base64.b64decode(obj["content"]).decode("utf-8")


def parse_diff(files):
    """Only exactly two CodeQL SHA pin changes in codeql.yml may pass."""
    if len(files) != 1:
        raise StopMerge("Exactly one workflow file must change")
    f = files[0]
    if (f.get("filename") != ".github/workflows/codeql.yml"
            or f.get("status") != "modified"
            or f.get("additions") != 2
            or f.get("deletions") != 2
            or not f.get("patch")):
        raise StopMerge("Unexpected changed file, diff or change count")
    sides = {"-": [], "+": []}
    for line in f["patch"].splitlines():
        if line.startswith("--- a/") or line.startswith("+++ b/"):
            continue
        if not line.startswith(("+", "-")):
            continue
        match = PIN.fullmatch(line[1:])
        if match is None:
            raise StopMerge("Unexpected workflow change")
        sides[line[0]].append(match.groups())
    if len(sides["-"]) != 2 or len(sides["+"]) != 2:
        raise StopMerge("Expected two removed and two added CodeQL pins")
    for sym in ("-", "+"):
        actions = [entry[0] for entry in sides[sym]]
        pins = {entry[1] for entry in sides[sym]}
        if set(actions) != {"init", "analyze"} or len(pins) != 1:
            raise StopMerge("init/analyze must share one pin")
    old_sha = sides["-"][0][1]
    new_sha = sides["+"][0][1]
    if old_sha == new_sha:
        raise StopMerge("Old and new CodeQL pins are identical")
    return old_sha, new_sha


def codeql_versions(pr):
    versions = set(VERSIONS.findall(pr.get("body") or ""))
    if len(versions) != 1:
        raise StopMerge("Dependabot did not report one unambiguous CodeQL version change")
    old, new = next(iter(versions))
    before = tuple(map(int, old.split(".")))
    after = tuple(map(int, new.split(".")))
    if before[:2] != after[:2] or after[2] <= before[2]:
        raise StopMerge("Not a patch update of CodeQL")
    return old, new


def tag_commit(api, version):
    ref = api.get(f"/repos/github/codeql-action/git/ref/tags/v{version}")
    obj = ref["object"]
    for _ in range(3):
        if obj["type"] == "commit":
            return obj["sha"]
        if obj["type"] != "tag":
            break
        tag = api.get(f"/repos/github/codeql-action/git/tags/{obj['sha']}")
        obj = tag["object"]
    raise StopMerge("CodeQL version tag could not be verified")


def verify_ci(api, sha):
    base = f"/repos/{api.repository}"
    runs = api.pages(f"{base}/actions/runs?event=pull_request&head_sha={sha}", "workflow_runs")
    if not runs:
        raise StopMerge("No PR workflows were found")
    names = {r["name"] for r in runs}
    if not REQUIRED_RUNS.issubset(names):
        raise StopMerge("CodeQL or Quality checks workflow is missing")
    if any(r["status"] != "completed" or r.get("conclusion") != "success" for r in runs):
        raise StopMerge("A workflow failed or is still running")
    checks = api.pages(f"{base}/commits/{sha}/check-runs", "check_runs")
    passed = {c["name"] for c in checks if c["status"] == "completed" and c.get("conclusion") == "success"}
    if not REQUIRED_CHECKS.issubset(passed):
        raise StopMerge("Required CodeQL and/or quality checks missing")
    for check in checks:
        if check.get("status") != "completed":
            raise StopMerge("An individual check is pending")
        status = check.get("conclusion")
        if status == "success" or (status == "skipped" and check["name"] in ALLOWED_SKIPPED):
            continue
        raise StopMerge(f"Unverified check {check['name']}: {status}")
    old = api.get(f"{base}/commits/{sha}/status")
    if any(c.get("state") != "success" for c in old.get("statuses", [])):
        raise StopMerge("Legacy commit status failed or is pending")


def verify_pr(api, pr_number):
    base = f"/repos/{api.repository}"
    pr = api.get(f"{base}/pulls/{int(pr_number)}")
    if (pr.get("state") != "open" or pr.get("draft")
            or pr.get("user", {}).get("login") != "dependabot[bot]"
            or pr.get("base", {}).get("ref") != "main"
            or pr.get("head", {}).get("repo", {}).get("full_name") != api.repository
            or not pr.get("head", {}).get("ref", "").startswith("dependabot/")):
        raise StopMerge("Not a same-repository Dependabot PR into main")
    head = pr["head"]["sha"]
    old_version, new_version = codeql_versions(pr)
    files = api.pages(f"{base}/pulls/{int(pr_number)}/files")
    before_sha, after_sha = parse_diff(files)
    if tag_commit(api, old_version) != before_sha or tag_commit(api, new_version) != after_sha:
        raise StopMerge("CodeQL SHA pins do not match published release tag refs")
    contents = api.file(".github/workflows/codeql.yml", head)
    pins = [match.groups() for line in contents.splitlines() if (match := PIN.fullmatch(line))]
    if len(pins) != 2 or {action for action, _ in pins} != {"init", "analyze"} or {sha for _, sha in pins} != {after_sha}:
        raise StopMerge("CodeQL workflow has inconsistent effective pins")
    main = api.get(f"{base}/git/ref/heads/main")["object"]["sha"]
    if pr["base"]["sha"] != main:
        raise StopMerge("PR base is not current main")
    compare = api.get(f"{base}/compare/{main}...{head}")
    if compare.get("behind_by") != 0 or compare.get("ahead_by", 0) < 1:
        raise StopMerge("Dependabot branch is behind main")
    if pr.get("mergeable") is not True or pr.get("mergeable_state") != "clean":
        raise StopMerge("PR is not cleanly mergeable")
    verify_ci(api, head)
    return head, main


def process(api, number, dry_run=False):
    head, main = verify_pr(api, number)
    if dry_run:
        print(f"DRY RUN: verified PR #{number} at {head}")
        return
    pr = api.get(f"/repos/{api.repository}/pulls/{int(number)}")
    current_main = api.get(f"/repos/{api.repository}/git/ref/heads/main")["object"]["sha"]
    if pr["head"]["sha"] != head or pr["base"]["sha"] != main or current_main != main:
        raise StopMerge("Head or main advanced during verification")
    result = api.request(f"/repos/{api.repository}/pulls/{int(number)}/merge",
                         "PUT", {"sha": head, "merge_method": "squash"})
    if not result or result.get("merged") is not True:
        raise RuntimeError("GitHub did not confirm merge")
    print(f"MERGED: PR #{number} -> {result['sha']}")
    # GITHUB_TOKEN merges suppress push-triggered Actions. Explicit, non-publishing
    # CodeQL and Quality workflows are the only intended post-merge jobs.
    for workflow in ("codeql.yml", "quality.yml"):
        api.request(f"/repos/{api.repository}/actions/workflows/{workflow}/dispatches",
                    "POST", {"ref": "main"})
        print(f"Post-merge validation requested: {workflow}")


def candidates(api, event, event_name):
    if event_name == "workflow_run":
        run = event.get("workflow_run", {})
        if run.get("event") != "pull_request" or run.get("actor", {}).get("login") != "dependabot[bot]":
            return []
        return sorted({p["number"] for p in run.get("pull_requests", [])})
    if event_name in ("schedule", "workflow_dispatch"):
        prs = api.pages(f"/repos/{api.repository}/pulls?state=open")
        return [p["number"] for p in prs if p.get("user", {}).get("login") == "dependabot[bot]"]
    return []


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--dry-run", action="store_true")
    opts = cli.parse_args()
    repo = os.environ["GITHUB_REPOSITORY"]
    if repo not in {f"{OWNER}/{name}" for name in REPOSITORIES}:
        raise SystemExit("Repository not allowlisted")
    api = API(repo, os.environ["GH_TOKEN"])
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fp:
        event = json.load(fp)
    for n in candidates(api, event, os.environ["GITHUB_EVENT_NAME"]):
        try:
            process(api, n, opts.dry_run)
        except StopMerge as exc:
            print(f"BLOCKED: #{n}: {exc}")
            # Expected rejection: no changes, safe by design.
        # Any GitHub API or post-merge dispatch failure propagates.


if __name__ == "__main__":
    main()
