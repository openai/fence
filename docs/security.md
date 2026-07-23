# Security Boundaries And Operational Guidance

Fence reduces where later workflow steps can send data and removes common ways for those steps to undo the restriction. It is a narrow security control for one supported runner class, not a general sandbox or a claim that the job is fully hermetic.

## Supported Boundary

The protected v0 target is a GitHub-hosted `ubuntu-24.04` x64 host job running the native Linux GNU Action bundle. Container jobs, other runner images, self-hosted runners, other architectures, and direct CLI launches do not establish the protected production lifecycle.

Two non-required workflows provide operational compatibility evidence without expanding that boundary. `nightly` builds an ephemeral production-shaped candidate from the exact current `main` source SHA and runs the complete unique-case Action-acceptance suite on `ubuntu-latest`. Scheduled and input-free manual `action drift canary` runs resolve the newest non-prerelease immutable release, validate its `action-release.json`, and run the mapped release's zero-input standard lifecycle on both `ubuntu-24.04` and `ubuntu-latest`; explicit-SHA diagnostics and reusable release-candidate validation remain fixed to `ubuntu-24.04`. The scheduled compatibility signals are not branch-protection or release gates; the fixed-label reusable canary remains part of release validation. A green floating-label result means only that the image currently selected by `ubuntu-latest` matched Fence's reviewed fingerprint and passed its applicable suite; a future image is not automatically trusted.

Fence should run before checkout and all other steps that need restriction. It checks a reviewed hosted-runner fingerprint before mutation, but it does not authenticate a privileged command or platform component that was already compromised before Fence started.

## Mode Boundaries

- Standard `block` applies the bounded network policy, disables measured passwordless sudo, disables accepted Docker/containerd control paths, and verifies the post-mutation baseline before readiness.
- `block` with `container_policy: unsafe_preserve` keeps container access available. It still applies the network policy and disables passwordless sudo, but the retained container control plane invalidates the ordinary containment claim.
- `audit` observes policy activity without blocking traffic and preserves passwordless sudo and container access. Its readiness is explicitly observation-only.

Fence never silently downgrades from standard block mode to a weaker mode.

## Allowed Destinations Remain Reachable

The built-in GitHub policy is a compatibility tradeoff. Core Actions status and finalization endpoints must remain reachable, and the default profile also permits broader GitHub web, API, release-asset, watchdog, and bounded GitHub application destinations. Later workflow code can send data to any destination that remains allowed.

Set `disable_broad_github_domains: true` to remove `github.com`, `api.github.com`, `release-assets.githubusercontent.com`, the exact optional hosted-runner watchdog, and new platform-origin broad GitHub application authorizations. This does not remove the core reporting path, exact results-storage compatibility, or an explicit user wildcard.

GitHub's authorized results-storage accounts are also reachable over TCP port `443` for the rest of the job after authorization. Fence limits dynamic authorization to DNS requests from the pinned runner process and records the bounded authorization locally; it does not permit the general Azure Blob Storage suffix.

Separate hosted-runner platform rules permit root-only access to Azure WireServer at `168.63.129.16` on TCP ports `80` and `32526`, plus host and forwarded access to Azure IMDS at `169.254.169.254` on TCP port `80`. These are built-in platform channels rather than user allowlist entries: later workflow code can use the shared IMDS rule, while any root-owned host process can use the WireServer rules.

## Integrity And Drift

The Action validates its checked-in manifest, copies the bundled agent into a protected root-owned launcher directory, and starts only that protected copy. The agent validates trusted executable identities, reviewed path ancestors, sudo-policy sources, runner identity, and the bounded root TCP, Unix, and container inventory before protection is claimed.

After readiness, Fence rechecks its firewall, lockdown or observation state, local-control inventory, required worker health, and evidence every five seconds. A critical resident failure is permanent and causes the protected post-job hook to fail the job. Fence intentionally does not restore network, sudo, or container access before the disposable VM is torn down.

## Local Evidence And Privacy

Fence does not upload telemetry. Local reports contain bounded control results, network decisions, and findings. Best-effort process attribution may include attribution status, actor class, PID, executable basename, and up to four parent executable basenames; it excludes command arguments, full executable paths, environments, working directories, and packet payloads.

The protected post hook also writes a bounded network activity table and exactly one schema-`1` `FENCE_REPORT_JSON=` record to ordinary job logs after verifying its resident service and evidence. These public-facing reports contain at most 20 grouped destinations and never exceed 16 KiB for the structured record. They may expose observed hostnames, literal IP addresses, and the same approved actor class, executable basename, and PID already shown in the job summary to anyone with access to the workflow run. They do not expose parent-process details, raw reports, credentials, environment variables, packet contents, full paths, or process arguments. Critical results are recorded before the hook fails the job; malformed or unverified evidence is never reported as healthy.

Uniquely owned unconnected host UDP sockets with wildcard local or remote endpoints can be correlated. Forwarded or container UDP traffic is not matched against the host socket table, so it cannot be linked to an unrelated host program. Process races and shared sockets can still produce `not_found` or `ambiguous` attribution. Attribution enriches local evidence but does not decide whether a destination is allowed.

## Pinning And Provenance

Consumers should pin the full immutable `action_commit` SHA from the release's `action-release.json` asset. Do not consume Fence from `main` or rely on a version tag as the workflow reference. See [Release Provenance](release-provenance.md) for the source, distribution commit, artifact, and attestation model.

For the formal claims and residual risks, read the [Fence v0 specification](v0.md), [threat model](threat-model.md), and [security review](security-review.md). Report vulnerabilities according to the repository [security policy](../SECURITY.md).
