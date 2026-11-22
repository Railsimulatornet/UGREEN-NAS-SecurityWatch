import datetime as dt
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import securitywatch_github as github

NOW = dt.datetime(2026, 11, 22, 12, tzinfo=dt.timezone.utc)


def configuration(**updates):
    row = {"repository": "Railsimulatornet/autoheal", "workflow": "publish.yml",
           "image_patterns": ["railsimulatornet/autoheal:*"], "branch": "main", "max_age_hours": 168}
    row.update(updates)
    return {"enabled": True, "repositories": [row]}


def deployment_configuration():
    # The test fixture is independent of the operator's active configuration.
    return {"enabled": True, "repositories": [
        {"repository": "Railsimulatornet/schulmanager-homework-watcher",
         "workflow": "security-scan.yml", "branch": "main",
         "image_patterns": ["railsimulatornet/schulmanager-homework-watcher:*"],
         "published_image_patterns": ["railsimulatornet/schulmanager-homework-watcher:latest"]},
        {"repository": "Railsimulatornet/UGREEN-NAS-Minecraft-Docker-Pack",
         "workflow": "docker-maintenance.yml", "branch": "main",
         "image_patterns": ["railsimulatornet/minecraft-maintenance:*"],
         "published_image_patterns": ["railsimulatornet/minecraft-maintenance:latest"]},
    ]}


def run(event="push", age=1, conclusion="success", status="completed", identity=12):
    return {"id": identity, "workflow_id": 42, "event": event, "head_branch": "main",
            "created_at": (NOW - dt.timedelta(hours=age)).isoformat(), "status": status, "conclusion": conclusion}


class FakeFetch:
    def __init__(self, runs=(), state="active"):
        self.runs = list(runs)
        self.state = state
        self.paths = []

    def __call__(self, path):
        self.paths.append(path)
        if "?" in path:
            event = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["event"][0]
            rows = [r for r in self.runs if r.get("event") == event]
            rows.sort(key=lambda r: r["created_at"], reverse=True)
            return {"total_count": len(rows), "workflow_runs": rows[:1]}
        if path.endswith("/actions/workflows/publish.yml"):
            return {"id": 42, "state": self.state}
        if path == "/repos/Railsimulatornet/autoheal":
            return {"default_branch": "main"}
        raise AssertionError(path)


class GitHubTests(unittest.TestCase):
    def test_deployment_advice_for_confirmed_fixed_tags(self):
        cfg = deployment_configuration()
        references = ["railsimulatornet/schulmanager-homework-watcher:3.0.1",
                      "railsimulatornet/minecraft-maintenance:1.0.3"]
        before = json.dumps(cfg, sort_keys=True)
        events = github.deployment_advice(cfg, references + references)
        self.assertEqual(2, len(events))
        self.assertEqual(set(references), {e["image"] for e in events})
        self.assertTrue(all(e["kind"] == "github" and e["severity"] == "warning"
                            and e["status"] == "published_tag_mismatch" for e in events))
        self.assertTrue(all("Zustandsprüfung" in e["action"] and "Compose" in e["action"]
                            and ":latest" in e["action"] for e in events))
        self.assertTrue(all("/actions/workflows/" in e["url"] for e in events))
        self.assertEqual(before, json.dumps(cfg, sort_keys=True))

    def test_deployment_advice_does_not_warn_for_published_or_unmapped_tags(self):
        cfg = deployment_configuration()
        references = ["railsimulatornet/schulmanager-homework-watcher:latest",
                      "railsimulatornet/minecraft-maintenance:latest",
                      "unmapped/my-image:1.2.3", "railsimulatornet/autoheal:1.2.3"]
        self.assertEqual([], github.deployment_advice(cfg, references))
        self.assertEqual([], github.deployment_advice(configuration(), ["railsimulatornet/autoheal:1.2.3"]))

    def test_deployment_advice_disabled_and_invalid_published_patterns(self):
        cfg = configuration(published_image_patterns=["railsimulatornet/autoheal:latest"])
        cfg["enabled"] = False
        self.assertEqual([], github.deployment_advice(cfg, ["railsimulatornet/autoheal:1.2.3"]))
        cfg["enabled"] = True
        cfg["repositories"][0]["published_image_patterns"] = "not-a-list"
        events = github.deployment_advice(cfg, ["railsimulatornet/autoheal:1.2.3"])
        self.assertEqual(["configuration_error"], [e["status"] for e in events])

    def test_disabled_makes_no_request(self):
        fetch = FakeFetch()
        result = github.monitor_github({"enabled": False}, fetch_json=fetch, now=NOW)
        self.assertEqual("disabled", result["status"])
        self.assertEqual([], fetch.paths)

    def test_missing_workflow_is_configuration_gap(self):
        fetch = FakeFetch()
        result = github.monitor_github(configuration(workflow=""), fetch_json=fetch, now=NOW)
        self.assertEqual("partial", result["status"])
        self.assertEqual("configuration_error", result["events"][0]["status"])
        self.assertEqual([], fetch.paths)

    def test_only_explicit_workflow_events_branch_checked(self):
        fetch = FakeFetch([run()])
        result = github.monitor_github(configuration(), fetch_json=fetch, now=NOW)
        self.assertEqual("ok", result["status"])
        self.assertEqual("build_success", result["events"][0]["status"])
        self.assertTrue(all(p.startswith("/repos/Railsimulatornet/autoheal/actions/workflows/publish.yml") for p in fetch.paths))
        self.assertTrue(all("branch=main" in p for p in fetch.paths if "?" in p))

    def test_latest_failure_wins_over_older_success(self):
        fetch = FakeFetch([run(age=12), run(event="schedule", age=1, conclusion="failure", identity=13)])
        result = github.monitor_github(configuration(), fetch_json=fetch, now=NOW)
        self.assertEqual("ok", result["status"], "API coverage can be complete despite a build failure")
        self.assertEqual("error", result["events"][0]["severity"])
        self.assertEqual("build_failed", result["events"][0]["status"])
        self.assertTrue(result["events"][0]["url"].endswith("/13"))

    def test_success_older_than_window_is_overdue(self):
        result = github.monitor_github(configuration(), fetch_json=FakeFetch([run(age=169)]), now=NOW)
        self.assertEqual("build_overdue", result["events"][0]["status"])

    def test_no_runs_and_disabled_workflow_are_actionable(self):
        missing = github.monitor_github(configuration(), fetch_json=FakeFetch(), now=NOW)
        disabled = github.monitor_github(configuration(), fetch_json=FakeFetch(state="disabled_inactivity"), now=NOW)
        self.assertEqual("build_missing", missing["events"][0]["status"])
        self.assertEqual("workflow_disabled", disabled["events"][0]["status"])

    def test_queued_run_is_not_a_success(self):
        result = github.monitor_github(configuration(), fetch_json=FakeFetch([run(status="queued", conclusion=None)]), now=NOW)
        self.assertEqual("build_pending", result["events"][0]["status"])
        self.assertNotEqual("ok", result["repositories"][0]["status"])

    def test_wrong_workflow_or_branch_is_unknown(self):
        for key, value in (("workflow_id", 43), ("head_branch", "other")):
            row = run()
            row[key] = value
            result = github.monitor_github(configuration(), fetch_json=FakeFetch([row]), now=NOW)
            self.assertEqual("partial", result["status"])
            self.assertEqual("unknown", result["repositories"][0]["status"])

    def test_api_error_does_not_look_empty(self):
        def fail(path):
            raise github.GitHubError("rate_limited", "Das GitHub-Abfragelimit wurde erreicht.")
        result = github.monitor_github(configuration(), fetch_json=fail, now=NOW)
        self.assertEqual("partial", result["status"])
        self.assertEqual("rate_limited", result["events"][0]["status"])

    def test_unsafe_configuration_never_becomes_request(self):
        for options in ({"repository": "https://evil.example/repo"}, {"workflow": "../../secrets"}, {"image_patterns": []}):
            fetch = FakeFetch()
            result = github.monitor_github(configuration(**options), fetch_json=fetch, now=NOW)
            self.assertEqual("partial", result["status"])
            self.assertEqual([], fetch.paths)

    def test_token_file_permissions_and_no_secret_in_result(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("SUPERSECRET_FIXTURE_TOKEN")
            token.chmod(0o644)
            result = github.monitor_github(configuration(), token_file=token, fetch_json=FakeFetch([run()]), now=NOW)
            self.assertEqual("partial", result["status"])
            self.assertNotIn("SUPERSECRET", json.dumps(result))
            token.chmod(0o600)
            self.assertEqual("ok", github.monitor_github(configuration(), token_file=token, fetch_json=FakeFetch([run()]), now=NOW)["status"])

    def test_rate_limit_is_not_retried_and_request_is_get(self):
        requests = []
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                raise urllib.error.HTTPError(request.full_url, 429, "SUPERSECRET_BODY", {"Retry-After": "600"}, None)
        client = github.GitHubClient("FAKE_TOKEN_ONLY")
        client.opener = Opener()
        with self.assertRaises(github.GitHubError) as err:
            client.get_json("/repos/Railsimulatornet/autoheal")
        self.assertEqual("rate_limited", err.exception.code)
        self.assertNotIn("SUPERSECRET", str(err.exception))
        self.assertEqual(1, len(requests))
        self.assertEqual("GET", requests[0].method)
        self.assertTrue(requests[0].full_url.startswith("https://api.github.com/"))
        self.assertIsNone(github._NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.invalid/"))


if __name__ == "__main__":
    unittest.main()
