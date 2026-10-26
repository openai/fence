# Troubleshooting 🔍

Start with the Fence job summary. It lists network activity, blocked destinations, warnings, and whether the runner's protections remained in place.

## Fence Fails To Start

Open the Fence setup step and look for `Fence could not verify readiness`. That error names the check the resident reported, when recognized, or says no recognized reason was available. It does not mean protection never started or that cleanup succeeded. Keep the job failed; don't use `continue-on-error` or weaken the policy to get past this check.

If setup says `could not confirm whether the resident started`, Fence doesn't use the service journal to guess why: it could belong to an earlier failed launch. Run Fence only once per job.

Check [current and resolved runner compatibility issues](https://github.com/openai/fence/issues?q=is%3Aissue+in%3Atitle+%22Release+canary%22) for the affected version and a verified replacement pin, if available. A green run on a different runner doesn't mean your issue is fixed. Share the Fence version, runner image version, and error code if needed, not private job logs.

Check that the job runs on a GitHub-hosted x64 runner with `ubuntu-24.04` or `ubuntu-latest`. Self-hosted runners, container jobs, and other architectures are not supported.

Run Fence first. Checkout, setup actions, and other commands can change the runner before Fence checks it.

`local_control_inventory_unavailable` means Fence could not fully inspect local services and their socket owners. During startup it can rescan if the only thing missing is a socket owner. It won't accept an unexpected owner or start with incomplete checks, even in audit mode. The setup error can include the scan status, attempt count, and fixed reason codes, without process names or paths. An allowlist change will not fix this error.

`dns_proxy_bind_failed` means Fence could not start a required DNS listener. For example, `docker UDP bind: address unavailable` means the required Docker address was not available. If only the error code is shown, the specific listener and reason aren't known. Changing the allowlist will not fix this error.

`unsupported_resolver_layout` means Fence could not verify `/etc/resolv.conf`. It can be a root-owned regular file or a symlink to a supported systemd-resolved file; you don't need to convert one to the other. The setup error can name the failed check, never observed paths, ownership, permissions, or process IDs. Changing the allowlist will not help.

`lockdown_command_timeout` means a trusted host command did not complete within its deadline. `lockdown_command_output_too_large` means the command produced more than 8 KiB total output. The setup error can identify the executable, whether it ran as root or runner, and its deadline in milliseconds; it never includes arguments, paths, or command output. An allowlist change will not fix either error.

For more detail, set the `ACTIONS_STEP_DEBUG` repository secret to `true` and rerun the job. Fence does not include raw service journal text, even in debug logs.

## A Network Request Is Blocked

Switch to audit mode temporarily:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    mode: audit
```

Check the job summary, add the required hostname or IP address to your allowlist, and return to block mode. Allow only the destination, protocol, and port the job actually needs.

If the request still fails, check whether the service redirects to another hostname, uses a CDN or storage domain, or listens on a different port.

## Artifact Uploads Or Pages Fail

Artifact uploads, GitHub Pages, and caches may need access to GitHub Actions storage:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    allow_github_artifacts: true
```

Enable this only for jobs that need it. Do not allowlist all Azure Blob Storage or manually add GitHub storage domains that can change between runs.

## Docker Does Not Work

Fence disables Docker and containerd by default. If your job needs containers, keep them available explicitly:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    container_policy: unsafe_preserve
```

Keeping Docker available weakens runner isolation. Image pulls may also require registry, authentication, CDN, or storage destinations in your allowlist.

## The Job Reports Critical Drift

Critical drift means a required protection changed or a Fence component stopped working. Fence fails the job because it cannot confirm that the original protections still hold.

Check the job summary and debug logs to identify what changed. Expanding the allowlist will not fix a broken protection.

## Job Summary Unavailable

If Fence cannot write the job summary, look in the post-job log for the network report. A summary warning alone does not mean protection failed.

## Post-Job Evidence Validation Fails

If active Action mount evidence is missing, check the earlier Fence setup step first. If setup failed, use its error. If setup reported ready, the protected mount may have been removed. Fence cannot safely distinguish these cases from job-writable state, so post-job verification still fails.

A `Fence failure diagnostic (unverified)` line shows the evidence source, reported resident status, verification sequence, heartbeat age, and at most five recognized critical codes. Unknown values are omitted or marked unavailable; unknown codes appear as `unrecognized`. These details help explain rejected evidence and do not prove that protection remained healthy.

A stale heartbeat can follow an earlier critical finding because failed verification does not advance the last successful timestamp. Check the diagnostic codes before treating staleness as a timing issue. Missing or unreadable evidence may leave only the original error. Fence still fails the job and leaves its controls in place.

## The Agent Cannot Run Directly

`fence check-support` and `fence render-plan` are inspection commands. Running `fence run` directly returns `trusted_launcher_required`; production protection must start through the GitHub Action.

See the [CLI reference](cli.md), [security guide](security.md), and [allowlist guide](allowlist.md) for more detail.
