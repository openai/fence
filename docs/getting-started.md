# Getting Started

Fence is a GitHub Action for supported GitHub-hosted `ubuntu-24.04` x64 host jobs. It must run before checkout and any other steps you want it to constrain.

## Add Fence To A Job

Use the full 40-character `action_commit` value from the release's `action-release.json` asset:

```yaml
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: openai/fence@<fence-commit-sha>
      - uses: actions/checkout@<checkout-commit-sha>
      - run: script/test
```

The root `main` branch is source-only and intentionally omits the generated agent bundle. A release-specific `vX.Y.Z` tag identifies a signed distribution commit, but consumers should pin the immutable distribution commit from `action-release.json` rather than the tag.

## Default Behavior

With no inputs, the Action starts Fence in `block` mode with an empty user `allowlist`. Fence permits the bounded platform traffic required for the GitHub-hosted runner, blocks other outbound traffic, disables passwordless sudo, and disables Docker and containerd control paths.

Fence allows the core GitHub Actions status and finalization endpoints. The default compatibility profile also includes `github.com`, `api.github.com`, `release-assets.githubusercontent.com`, the exact optional hosted-runner watchdog endpoint, and a bounded class of GitHub application hostnames. Set `disable_broad_github_domains: true` to remove those broader platform-origin destinations while retaining the core Actions path.

GitHub uploads job logs and summaries to per-run Azure storage accounts. Fence always permits the exact reviewed compatibility account and can authorize at most four additional exact results-storage hostnames when the DNS request is attributable to the pinned GitHub runner process; it never permits the general `*.blob.core.windows.net` suffix.

GitHub artifact uploads, Pages, and caches use a separate action process rather than the pinned runner process. If a job needs those operations, explicitly enable the bounded compatibility option:

```yaml
- uses: openai/fence@<fence-commit-sha>
  with:
    allow_github_artifacts: true
```

This option is off by default. When enabled, uniquely attributed runner-owned descendants of the pinned GitHub runner can authorize exact GitHub-shaped results-storage accounts over TCP port `443`, sharing the existing four-account lifetime limit. Other workflow steps can also use an authorized account, and a matching account name does not prove GitHub owns it. Enable this option only when the job needs artifact access; it does not authorize the general Azure Blob Storage suffix.

The supported hosted VM also depends on Azure platform services. The selected profile permits root-only host access to WireServer at `168.63.129.16` on TCP ports `80` and `32526`, plus host and forwarded access to Azure IMDS at `169.254.169.254` on TCP port `80`. These are separate platform rules, not user allowlist entries.

## Startup And Readiness

Before reporting readiness, Fence checks the supported runner fingerprint, prepares the selected network policy, applies and verifies the required controls, and resolves required exact hostnames. Transient or addressless DNS results receive at most three attempts within one shared ten-second startup deadline; malformed or integrity-invalid responses fail immediately.

After readiness, Fence remains resident and verifies the controls every five seconds. It never restores access at the end of the job; the disposable GitHub-hosted VM teardown removes the state.

## Choose A Mode

- Use the default `block` mode for the strongest supported containment claim.
- Add `allow_github_artifacts: true` only when a block-mode job needs GitHub artifacts, Pages, or caches and you accept the additional bounded data-egress channel.
- Use `audit` to observe the policy before enabling blocking.
- Use `container_policy: unsafe_preserve` only when the workflow requires Docker or containerd access and you accept the weaker containment boundary.

See [configuration examples](examples.md), [allowlist syntax](allowlist.md), and the normative [Fence v0 specification](v0.md) for the complete contract.
