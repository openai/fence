# Troubleshooting 🔍

Start with the Fence job summary. It lists network activity, blocked destinations, warnings, and whether the runner's protections remained in place.

## Fence Fails To Start

Check that the job runs on a GitHub-hosted x64 runner with `ubuntu-24.04` or `ubuntu-latest`. Self-hosted runners, container jobs, and other architectures are not supported.

Run Fence first. Checkout, setup actions, and other commands can change the runner before Fence checks it.

`local_control_inventory_unavailable` means Fence could not fully inspect local services and their socket owners. Fence retries acquisition failures within a fixed limit and still requires a complete, stable inventory in both audit and block mode. The `Fence local control inspection` log line shows the scan status, attempt count, and fixed reason codes, without process names or paths. An allowlist change will not fix this error.

`lockdown_command_timeout` means a trusted host command did not complete within its deadline. `lockdown_command_output_too_large` means the command produced more than 8 KiB total output. Fence drains stdout and stderr during execution and fails either check in both modes. The `Fence host command` line identifies the trusted executable, root or runner principal, error code, and deadline in milliseconds; it never includes command arguments, job paths, or command output. Check this line before considering a retry. These are host verification failures, so an allowlist change will not fix them.

For more detail, set the `ACTIONS_STEP_DEBUG` repository secret to `true` and rerun the job.

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

## Post-Job Evidence Validation Fails

Missing active Action mount evidence can follow a setup failure before readiness, when provisional mounts have already been removed. Check the earlier Fence setup log first. The same missing evidence can also mean a protected mount was removed after readiness; Fence cannot safely distinguish these cases using job-writable state, so it still fails post-job verification and never claims protection succeeded.

A `Fence failure diagnostic (unverified)` line shows the evidence source, reported resident status, verification sequence, heartbeat age, and at most five recognized critical codes. Unknown values are omitted or marked unavailable; unknown codes appear as `unrecognized`. These details help explain rejected evidence and do not prove that protection remained healthy.

A stale heartbeat can follow an earlier critical finding because failed verification does not advance the last successful timestamp. Check the diagnostic codes before treating staleness as a timing issue. Missing or unreadable evidence may leave only the original error. Fence still fails the job and leaves its controls in place.

## The Agent Cannot Run Directly

`fence check-support` and `fence render-plan` are inspection commands. Running `fence run` directly returns `trusted_launcher_required`; production protection must start through the GitHub Action.

See the [CLI reference](cli.md), [security guide](security.md), and [allowlist guide](allowlist.md) for more detail.
