# Getting Started 🚀

Fence limits where a GitHub Actions job can send network traffic. Add it as the first step so the rest of the job runs with those limits in place.

## Add Fence To Your Workflow

```yaml
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: openai/fence@<commit-sha> # pin@vX.Y.Z

      - uses: actions/checkout@<checkout-commit-sha>

      - name: Run tests
        run: script/test
```

Copy the full commit SHA and version from the [latest verified release](https://github.com/openai/fence/releases/latest). The `main` branch does not contain the bundled Action, so it cannot be used directly.

Use a GitHub-hosted x64 runner with `ubuntu-24.04` or `ubuntu-latest`. Releases are tested on both, and Fence verifies the runner's security controls even when GitHub updates its images.

## What Happens By Default?

Without additional configuration, Fence:

- Keeps required GitHub Actions and runner connections available.
- Blocks other outbound connections.
- Turns off passwordless `sudo`.
- Disables Docker and container access.
- Reports network activity in the job summary and post-job log.

Required GitHub and runner platform connections are built in. You do not need to add GitHub's job-reporting domains yourself.

## Allow A Domain

Allow only the destinations your workflow needs:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    allowlist: |
      api.example.com
      registry.example.com:8443
```

A hostname without a port uses TCP port `443`. The [allowlist guide](allowlist.md) covers other ports, IP addresses, network ranges, and wildcards.

## Start With Audit Mode

Not sure which connections your job needs? Start in audit mode:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    mode: audit
```

Audit mode records what Fence would block without blocking traffic or disabling `sudo` and Docker. It may still restore root ownership of `/etc` and `/usr`. Check the job summary, add the destinations you need, and remove `mode: audit` when you are ready to enforce the allowlist.

## Upload Artifacts Or Deploy Pages

Artifact uploads, GitHub Pages, and caches can need access to GitHub Actions storage:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    allow_github_artifacts: true
```

> [!IMPORTANT]
> Later workflow steps can also use this storage access to send data out of the runner. Enable it only when your job needs artifacts, Pages, or caches.

## Use Docker

If your job needs Docker or containerd, keep container access available:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    container_policy: unsafe_preserve
```

> [!WARNING]
> Container access weakens Fence's runner isolation. Enable it only when the job requires containers.

See [configuration examples](examples.md), [allowlist syntax](allowlist.md), and [troubleshooting](troubleshooting.md) for more help.
