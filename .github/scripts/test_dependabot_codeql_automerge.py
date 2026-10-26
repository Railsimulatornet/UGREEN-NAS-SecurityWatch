"""Regression tests: fail-closed CodeQL patch merger."""
import unittest
import dependabot_codeql_automerge as gate

OLD = "6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee"
NEW = "9b3254085494b55a0f7c4c2b3d2d52cc712ce370"
REPO = "Railsimulatornet/UGREEN-NAS-SecurityWatch"
BASE = "b" * 40
HEAD = "h" * 40
ROOT = "/repos/" + REPO


def changes(old=OLD, new=NEW):
    return [{"filename": ".github/workflows/codeql.yml", "status": "modified",
             "additions": 2, "deletions": 2,
             "patch": "@@ -1,2 +1,2 @@\n"
                      f"-        uses: github/codeql-action/init@{old} # v4\n"
                      f"+        uses: github/codeql-action/init@{new} # v4\n"
                      f"-        uses: github/codeql-action/analyze@{old} # v4\n"
                      f"+        uses: github/codeql-action/analyze@{new} # v4"}]


class FakeAPI:
    def __init__(self):
        self.repository = REPO
        self.calls = []
        self.data = {
            ROOT + "/pulls/3": {
                "state": "open", "draft": False, "user": {"login": "dependabot[bot]"},
                "base": {"ref": "main", "sha": BASE},
                "head": {"repo": {"full_name": REPO},
                         "ref": "dependabot/github_actions/codeql-patch", "sha": HEAD},
                "mergeable": True, "mergeable_state": "clean",
                "body": "Updates " + chr(96) + "github/codeql-action/init" + chr(96)
                        + " from 4.39.0 to 4.39.1\nUpdates "
                        + chr(96) + "github/codeql-action/analyze" + chr(96)
                        + " from 4.39.0 to 4.39.1",
            },
            ROOT + "/git/ref/heads/main": {"object": {"sha": BASE}},
            ROOT + f"/compare/{BASE}...{HEAD}": {"behind_by": 0, "ahead_by": 1},
            ROOT + f"/commits/{HEAD}/status": {"statuses": []},
        }
        self.arrays = {
            ROOT + "/pulls/3/files": changes(),
            ROOT + f"/actions/runs?event=pull_request&head_sha={HEAD}": [
                {"name": name, "status": "completed", "conclusion": "success"}
                for name in ("CodeQL", "Quality checks")],
            ROOT + f"/commits/{HEAD}/check-runs": [
                {"name": name, "status": "completed", "conclusion": "success"}
                for name in gate.REQUIRED_CHECKS],
        }
        self.codeql = (f"uses: github/codeql-action/init@{NEW} # v4\n"
                       f"uses: github/codeql-action/analyze@{NEW} # v4\n")

    def get(self, path):
        self.calls.append(("GET", path))
        if path.endswith("/git/ref/tags/v4.39.0"):
            return {"object": {"type": "commit", "sha": OLD}}
        if path.endswith("/git/ref/tags/v4.39.1"):
            return {"object": {"type": "commit", "sha": NEW}}
        return self.data[path]

    def pages(self, path, field=None):
        self.calls.append(("PAGES", path))
        return self.arrays[path]

    def file(self, path, sha):
        self.calls.append(("FILE", path, sha))
        return self.codeql

    def request(self, path, method="GET", data=None):
        self.calls.append((method, path, data))
        return {"merged": True, "sha": "merged-sha"}


class DiffValidation(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(gate.parse_diff(changes()), (OLD, NEW))

    def test_extra_file_rejected(self):
        with self.assertRaises(gate.StopMerge):
            gate.parse_diff(changes() + changes())

    def test_wrong_path_rejected(self):
        x = changes()
        x[0]["filename"] = "malicious.py"
        with self.assertRaises(gate.StopMerge):
            gate.parse_diff(x)

    def test_modified_script_rejected(self):
        x = changes()
        x[0]["patch"] += "\n+        run: echo hacked"
        with self.assertRaises(gate.StopMerge):
            gate.parse_diff(x)

    def test_wrong_diff_counts_rejected(self):
        x = changes()
        x[0]["additions"] = 3
        with self.assertRaises(gate.StopMerge):
            gate.parse_diff(x)

    def test_wrong_sha_on_analyze_rejected(self):
        x = changes()
        x[0]["patch"] = x[0]["patch"].replace("analyze@" + NEW, "analyze@" + "f" * 40)
        with self.assertRaises(gate.StopMerge):
            gate.parse_diff(x)

    def test_missing_patch_rejected(self):
        x = changes()
        del x[0]["patch"]
        with self.assertRaises(gate.StopMerge):
            gate.parse_diff(x)


class VersionValidation(unittest.TestCase):
    def test_patch(self):
        a = FakeAPI()
        self.assertEqual(gate.codeql_versions(a.data[ROOT + "/pulls/3"]), ("4.39.0", "4.39.1"))

    def test_minor_rejected(self):
        a = FakeAPI()
        a.data[ROOT + "/pulls/3"]["body"] = (
            "Updates " + chr(96) + "github/codeql-action/init" + chr(96)
            + " from 4.38.3 to 4.39.1")
        with self.assertRaises(gate.StopMerge):
            gate.codeql_versions(a.data[ROOT + "/pulls/3"])

    def test_major_rejected(self):
        a = FakeAPI()
        a.data[ROOT + "/pulls/3"]["body"] = (
            "Updates " + chr(96) + "github/codeql-action/init" + chr(96)
            + " from 4.39.1 to 5.0.0")
        with self.assertRaises(gate.StopMerge):
            gate.codeql_versions(a.data[ROOT + "/pulls/3"])


class CIVerification(unittest.TestCase):
    def test_valid(self):
        gate.verify_ci(FakeAPI(), HEAD)

    def test_missing_quality_blocks(self):
        a = FakeAPI()
        a.arrays[ROOT + f"/actions/runs?event=pull_request&head_sha={HEAD}"].pop()
        with self.assertRaises(gate.StopMerge):
            gate.verify_ci(a, HEAD)

    def test_missing_check_blocks(self):
        a = FakeAPI()
        a.arrays[ROOT + f"/commits/{HEAD}/check-runs"].pop()
        with self.assertRaises(gate.StopMerge):
            gate.verify_ci(a, HEAD)

    def test_neutral_check_blocks(self):
        a = FakeAPI()
        a.arrays[ROOT + f"/commits/{HEAD}/check-runs"].append(
            {"name": "Trivy", "status": "completed", "conclusion": "neutral"})
        with self.assertRaises(gate.StopMerge):
            gate.verify_ci(a, HEAD)


class MergeVerification(unittest.TestCase):
    def test_candidate(self):
        self.assertEqual(gate.verify_pr(FakeAPI(), 3), (HEAD, BASE))

    def test_author_rejected(self):
        a = FakeAPI()
        a.data[ROOT + "/pulls/3"]["user"]["login"] = "untrusted"
        with self.assertRaises(gate.StopMerge):
            gate.verify_pr(a, 3)

    def test_outdated_branch_rejected(self):
        a = FakeAPI()
        a.data[ROOT + f"/compare/{BASE}...{HEAD}"]["behind_by"] = 1
        with self.assertRaises(gate.StopMerge):
            gate.verify_pr(a, 3)

    def test_sha_mismatch_rejected(self):
        a = FakeAPI()
        a.arrays[ROOT + "/pulls/3/files"] = changes("f" * 40, NEW)
        with self.assertRaises(gate.StopMerge):
            gate.verify_pr(a, 3)

    def test_dry_run_does_not_write(self):
        a = FakeAPI()
        gate.process(a, 3, dry_run=True)
        self.assertFalse(any(x[0] in ("POST", "PUT") for x in a.calls))

    def test_merge_dispatches_checks_only(self):
        a = FakeAPI()
        gate.process(a, 3, dry_run=False)
        writes = [x for x in a.calls if x[0] in ("PUT", "POST")]
        self.assertEqual([x[0] for x in writes], ["PUT", "POST", "POST"])
        self.assertIn("codeql.yml", writes[1][1])
        self.assertIn("quality.yml", writes[2][1])

    def test_untrusted_workflow_event_ignored(self):
        a = FakeAPI()
        event = {"workflow_run": {"event": "pull_request", "actor": {"login": "attacker"},
                                  "pull_requests": [{"number": 3}]}}
        self.assertEqual(gate.candidates(a, event, "workflow_run"), [])


if __name__ == "__main__":
    unittest.main()
