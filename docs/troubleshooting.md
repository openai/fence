# Troubleshooting 🔍

Start with the Fence job summary. It lists network activity, blocked destinations, warnings, and whether the runner's protections remained in place.

## Fence Fails To Start

Check that the job runs on a GitHub-hosted x64 runner with `ubuntu-24.04` or `ubuntu-latest`. Self-hosted runners, container jobs, and other architectures are not supported.

Run Fence first. Checkout, setup actions, and other commands can change the runner before Fence checks it.

`local_control_inventory_unavailable` means Fence could not fully inspect local services and their socket owners. Fence retries acquisition failures within a fixed limit and still requires a complete, stable inventory in both audit and block mode. The `Fence local control inspection` log line shows the scan status, attempt count, and fixed reason codes, without process names or paths. An allowlist change will not fix this error.

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

## The Agent Cannot Run Directly

`fence check-support` and `fence render-plan` are inspection commands. Running `fence run` directly returns `trusted_launcher_required`; production protection must start through the GitHub Action.

See the [CLI reference](cli.md), [security guide](security.md), and [allowlist guide](allowlist.md) for more detail.
