"""Record the first unexplained scheduled release-canary failure; never infer recovery."""

import functools
import json
import os
import re
import subprocess
import sys


REPOSITORY = "openai/fence"
URL = f"https://github.com/{REPOSITORY}"
JOBS = [f"{runner} {mode} canary" for runner in ("ubuntu-24.04", "ubuntu-latest") for mode in ("block", "audit")]
OUTCOMES = {"success", "failure", "cancelled", "timed_out", "skipped", "neutral", "startup_failure", "unknown", "missing"}
DIAGNOSTICS = (
    "Fence resident error code: unsupported_resolver_layout",
    "Fence host resolver: link not symlink",
)
ISSUE = "<!-- fence release canary: first unresolved sample -->"
SAMPLE = "<!-- fence release canary sample:"
BOT = '.[] | select(.user.login == "github-actions[bot]" and .pull_request == null)'
GUIDANCE = (
    "If this affects your workflow, keep failing closed. There may be no safe workaround; do not widen "
    "your allowlist, treat audit mode as protection, or post private job logs here.\n\n"
    "Keep this issue open across passing samples: runner labels can cover different host configurations. "
    "Close it only when a maintainer confirms the affected runner configuration works with a finalized "
    "replacement release and records its full Action commit pin here."
)


@functools.cache
def log_read_flags():
    # Newer gh refuses runner logs containing terminal escapes; older gh doesn't have this flag.
    # Either way we capture the bytes privately and publish only the fixed fields from log_evidence().
    help_text = subprocess.check_output(["gh", "api", "--help"], stderr=subprocess.DEVNULL, timeout=10)
    flag = "--allow-escape-sequences"
    return (flag,) if flag.encode() in help_text else ()


def github(path, *args):
    """Bound responses (including job logs); do not print raw errors, signed URLs or log text."""
    cmd = ["gh", "api", "--hostname", "github.com", f"repos/{REPOSITORY}/{path}", *args]
    if path.endswith("/logs"):
        cmd.extend(log_read_flags())
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        limit = 8 * 1024 * 1024
        data = proc.stdout.read(limit + 1)
        if len(data) > limit:
            proc.kill()
            raise RuntimeError("GitHub response exceeded the report limit")
        if proc.wait() != 0:
            raise RuntimeError("GitHub API request failed (no raw response is shown)")
    return data


def log_evidence(payload):
    # Diagnostic and action-first jobs identify the distribution differently. Never use a branch or a short SHA.
    pins = re.findall(rb" Canary Action commit: ([a-f0-9]{40})\r?$", payload, re.MULTILINE)
    pins += re.findall(rb" Download action repository 'openai/fence@([a-f0-9]{40})' \(SHA:\1\)\r?$", payload, re.MULTILINE)
    pins = set(pins)
    pin = pins.pop().decode("ascii") if len(pins) == 1 else None
    diagnostics = [message for message in DIAGNOSTICS if
                   re.search(rb"##\[warning\]" + re.escape(message.encode()) + rb"\r?$", payload, re.MULTILINE)]
    return pin, diagnostics


def outcome(record):
    value = record.get("conclusion") if record.get("status") == "completed" else None
    return value if value in OUTCOMES else "unknown"


def observe(run_id, api=github):
    path = f"actions/runs/{run_id}/attempts/1"
    run = json.loads(api(path))
    if not (run["id"] == run_id and run["run_attempt"] == 1 and run["status"] == "completed"
            and run["event"] == "schedule" and run["head_branch"] == "main"
            and run["path"] == ".github/workflows/action-drift-canary.yml"
            and run["head_repository"]["full_name"] == run["repository"]["full_name"] == REPOSITORY):
        raise ValueError("expected the first attempt of a completed, scheduled main release canary")

    # Missing jobs or expired logs are reportable observations, not grounds to discard a failed sample.
    try:
        jobs = json.loads(api(f"{path}/jobs?per_page=100"))["jobs"]
    except RuntimeError:
        jobs = []
    sample = {"run": outcome(run), "number": int(run["run_number"]), "jobs": {}}
    for name in JOBS:
        matching = [j for j in jobs if j["name"] == name and j["run_id"] == run_id and j["run_attempt"] == 1]
        if len(matching) != 1:
            sample["jobs"][name] = {"outcome": "unknown" if matching else "missing"}
            continue
        job, = matching
        job_id = int(job["id"])
        row = {"outcome": outcome(job), "id": job_id}
        try:
            log = api(f"actions/jobs/{job_id}/logs")
            row["pin"], row["diagnostics"] = log_evidence(log)
        except RuntimeError:
            pass
        sample["jobs"][name] = row
    return sample


def describe(run_id, sample):
    """Render only typed, allowlisted observations, including at the issue-writer boundary."""
    state = sample["run"]
    if state not in OUTCOMES or set(sample["jobs"]) != set(JOBS):
        raise ValueError("unexpected canary result")
    url = f"{URL}/actions/runs/{run_id:d}"
    lines = [f"[Scheduled canary #{sample['number']:d}, attempt 1]({url}/attempts/1): `{state}`.",
             "", "| Runner and mode | Job result | Observed Action commit | Diagnostic |", "|---|---|---|---|"]
    # Block may retain a reviewed release pin while diagnostic jobs exercise a newer release.
    passed = state == "success"
    for name in JOBS:
        row = sample["jobs"][name]
        result, job_id, pin = row["outcome"], row.get("id"), row.get("pin")
        if result not in OUTCOMES or (pin is not None and not re.fullmatch("[a-f0-9]{40}", pin)):
            raise ValueError("unexpected canary job result")
        passed = passed and result == "success" and bool(pin)
        result_link = f"[{result}]({url}/job/{job_id:d})" if job_id is not None else result
        commit = f"[`{pin}`]({URL}/commit/{pin})" if pin else "not established"
        notes = [s.split(": ")[1] for s in DIAGNOSTICS if s in row.get("diagnostics", [])]
        detail = "; ".join(notes) or ("—" if result == "success" else "not classified")
        lines.append(f"| {name} | {result_link} | {commit} | {detail} |")
    return passed, "\n".join(lines)


def observations(number, first, api):
    path = f"issues/{int(number)}/comments?per_page=100"
    query = f'{BOT} | (.body | split("\\n")[0]) | select(startswith("{SAMPLE}"))'
    return [first, *api(path, "--paginate", "--jq", query).decode().splitlines()]


def report(run_id, sample, api=github):
    passed, summary = describe(run_id, sample)
    # Only find our bot-authored marker. Never edit an issue body, human notes, or issue state.
    path = "issues?state=all&sort=created&direction=desc&creator=github-actions%5Bbot%5D&per_page=100"
    query = f'{BOT} | select(.body | startswith("{ISSUE}")) | [.state, .number, (.body | split("\\n")[1])] | @tsv'
    issues = [line.split("\t") for line in api(path, "--paginate", "--jq", query).decode().splitlines()]
    opened = [(number, first) for state, number, first in issues if state == "open"]
    kind = "passing" if passed else "unresolved"
    marker = f"{SAMPLE} {sample['number']:d} {run_id:d} {kind} -->"
    if not opened:
        if passed:
            return "Expected jobs passed with known Action commits; no issue to update."
        if issues:
            # Respect the latest human closure, even if someone reruns an old reporter after it.
            _, number, first = issues[0]
            seen = observations(number, first, api)
            if sample["number"] <= max(int(s.removeprefix(SAMPLE).split()[0]) for s in seen):
                return f"{URL}/issues/{number} covers this or a later sample; left it closed."
        body = f"{ISSUE}\n{marker}\n\n{summary}\n\n{GUIDANCE}"
        issue = api("issues", "-f", "title=Release canary: compatibility needs investigation", "-f", f"body={body}",
                    "--jq", ".number")
        return f"Recorded the first unresolved sample in {URL}/issues/{int(issue)}."
    if len(opened) != 1:
        raise ValueError("multiple open release-canary issues; maintainer resolution required")
    number, first = opened[0]
    # A delayed or re-run reporter may arrive out of order; compare source workflow run numbers.
    if passed and sample["number"] <= int(first.removeprefix(SAMPLE).split()[0]):
        return f"Sample does not follow the first failure in {URL}/issues/{number}; left unchanged."
    seen = observations(number, first, api)
    if marker in seen or (passed and any(s.endswith(" passing -->") for s in seen)):
        return f"{URL}/issues/{number} already records this observation; left unchanged."
    note = "First later passing sample, not evidence of a fix." if passed else "Another unresolved first attempt."
    body = f"{marker}\n\n{note}\n\n{summary}"
    api(f"issues/{int(number)}/comments", "-f", f"body={body}", "--silent")
    return f"Recorded the {kind} sample in {URL}/issues/{number}; left the issue open."


if __name__ == "__main__":
    command, raw_id = sys.argv[1:]
    run_id = int(raw_id)
    if command == "observe":
        sample = observe(run_id)
        _, summary = describe(run_id, sample)
        print(summary)
        if path := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(path, "a") as summary_file:
                print(summary, file=summary_file)
        if path := os.environ.get("GITHUB_OUTPUT"):
            with open(path, "a") as output:
                print(f"sample={json.dumps(sample, separators=(',', ':'))}", file=output)
    elif command == "report":
        print(report(run_id, json.loads(os.environ["CANARY_SAMPLE"])))
    else:
        sys.exit("usage: release_canary_report.py observe RUN_ID")
