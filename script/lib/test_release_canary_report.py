"""Offline release-canary observation and issue lifecycle regressions."""

import json
import unittest
from unittest.mock import Mock

from release_canary_report import DIAGNOSTICS, JOBS, REPOSITORY, SAMPLE, describe, log_evidence, observe, report


PIN = "a" * 40
PIN_LOG = f"time Canary Action commit: {PIN}\n".encode()
LOG = PIN_LOG + "".join(f"time ##[warning]{message}\n" for message in DIAGNOSTICS).encode()


def sample(outcome="success", *, run_id=50, overrides=None, jobs=None, log=None):
    repo = {"full_name": REPOSITORY}
    run = {"id": run_id, "run_attempt": 1, "run_number": run_id, "event": "schedule", "head_branch": "main",
           "path": ".github/workflows/action-drift-canary.yml", "head_repository": repo, "repository": repo,
           "status": "completed", "conclusion": outcome, **(overrides or {})}
    if jobs is None:
        jobs = [{"name": name, "run_id": run_id, "run_attempt": 1, "id": 100 + i,
                 "status": "completed", "conclusion": outcome} for i, name in enumerate(JOBS)]
    if log is None:
        log = PIN_LOG if outcome == "success" else LOG
    responses = [json.dumps(run), json.dumps({"jobs": jobs}), *([log] * len(jobs))]
    api = Mock(side_effect=responses)
    result = observe(run_id, api)
    for job in jobs:
        api.assert_any_call(f"actions/jobs/{job['id']}/logs", "--allow-escape-sequences")
    return result


class CanaryReport(unittest.TestCase):
    def test_only_fixed_diagnostics_and_full_distribution_pin_leave_the_observer(self):
        hostile = b"\x1b[31mtime ##[warning]Fence host resolver: not public\n"
        pin, messages = log_evidence(LOG + hostile)
        self.assertEqual((pin, messages), (PIN, list(DIAGNOSTICS)))
        self.assertEqual(log_evidence(hostile + b"time Canary Action commit: latest\n"), (None, []))
        self.assertEqual(log_evidence(LOG + LOG.replace(b"a" * 40, b"b" * 40))[0], None)
        passed, evidence = describe(50, sample("failure", log=LOG + hostile))
        self.assertFalse(passed)
        self.assertIn("unsupported_resolver_layout; link not symlink", evidence)
        self.assertNotIn("not public", evidence)
        self.assertNotIn("\x1b", evidence)

    def test_action_first_and_diagnostic_canaries_can_pass_with_different_pins(self):
        pin = "b" * 40
        log = f"time Download action repository 'openai/fence@{pin}' (SHA:{pin})\n".encode()
        result = sample(log=log)
        self.assertEqual(result["jobs"][JOBS[0]]["pin"], pin)
        result["jobs"][JOBS[1]]["pin"] = PIN
        self.assertTrue(describe(50, result)[0])
        # E.g. all canary jobs passed but a separate first-step verifier failed.
        result["run"] = "failure"
        self.assertFalse(describe(50, result)[0])

    def test_missing_cancelled_unknown_and_incomplete_evidence_stay_visible(self):
        for result, expected in [(sample(jobs=[]), "missing"), (sample("cancelled"), "cancelled"),
                                 (sample("unexpected"), "unknown"), (sample(log=RuntimeError()), "not established")]:
            passed, evidence = describe(50, result)
            self.assertFalse(passed)
            self.assertIn(expected, evidence)
            for name in JOBS:
                self.assertIn(name, evidence)

    def test_only_first_attempt_of_completed_scheduled_main_canary_is_eligible(self):
        for bad in [{"event": "workflow_dispatch"}, {"event": "push"}, {"event": "pull_request"},
                    {"run_attempt": 2}, {"head_branch": "other"}, {"path": "other"}, {"status": "in_progress"},
                    {"head_repository": {"full_name": "other/fork"}}]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sample(overrides=bad)

    def test_keep_first_failure_across_repeated_failures_and_a_later_passing_sample(self):
        issue, comments = [], []

        def issues_api(path, *args):
            # Model GitHub returning our bot markers alongside separately maintained human notes.
            if path.startswith("issues?"):
                return f"open\t17\t{issue[0].splitlines()[1]}".encode() if issue else b""
            if path == "issues":
                self.assertEqual(issue, [], "created a duplicate issue")
                issue.extend(arg.removeprefix("body=") for arg in args if arg.startswith("body="))
                return b"17"
            if path.startswith("issues/17/comments?"):
                return "\n".join(body.splitlines()[0] for body in comments).encode()
            self.assertEqual(path, "issues/17/comments", "edited an existing issue, note or state")
            comments.extend(arg.removeprefix("body=") for arg in args if arg.startswith("body="))

        def record(run_id, result):
            report(run_id, sample(result, run_id=run_id), api=issues_api)

        record(49, "success")
        self.assertFalse(issue)
        record(50, "failure")
        self.assertIn("/runs/50/attempts/1", issue[0])
        initial = issue[0] + "\nMaintainer investigation notes."
        issue[0] = initial
        record(50, "failure")
        record(49, "success")  # Reporters need not complete in source-run order.
        self.assertFalse(comments)
        record(51, "failure")
        record(51, "failure")  # Re-running the reporter must not duplicate its comment.
        record(52, "success")
        record(53, "success")
        self.assertEqual(len(comments), 2)
        self.assertIn("/runs/51/attempts/1", comments[0])
        self.assertIn("not evidence of a fix", comments[1])
        self.assertIn("/runs/52/attempts/1", comments[1])
        self.assertEqual(issue, [initial])

    def test_respect_human_closure_but_open_an_issue_for_a_newer_failure_on_the_same_pin(self):
        issue = f"closed\t17\t{SAMPLE} 50 50 unresolved -->".encode()
        comment = f"{SAMPLE} 51 51 unresolved -->".encode()
        for run_id in (50, 51, 52):
            api = Mock(side_effect=[issue, comment, b"18"])
            report(run_id, sample("failure", run_id=run_id), api)
            paths = [args[0] for args, _ in api.call_args_list]
            self.assertIn("state=all", paths[0])
            self.assertEqual(paths[1:], ["issues/17/comments?per_page=100"] + (["issues"] if run_id == 52 else []))


if __name__ == "__main__":
    unittest.main()
