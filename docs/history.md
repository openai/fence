# Fence Implementation History

This page tracks the major changes that shaped Fence. For current behavior and security guarantees, see the [v0 specification](v0.md) and [threat model](threat-model.md).

## Bootstrap and policy model

- Fence started as a Rust project with pinned toolchains, vendored dependencies, offline development scripts, and Linux x64 packaging.
- The first agent added a strict JSON configuration, typed allowlist entries, bounded hostname resolution, stable policy hashes, and the `render-plan` CLI command.
- The public `run` command remained disabled until hosted tests could verify the privileged runner lifecycle.

## Native network evidence

- Fence uses a dedicated `nftables` table, predictable firewall rules, and separate hashes for the intended policy and active rules.
- Privileged tests verified atomic firewall updates, rollback, IPv4 and IPv6 traffic, forwarded traffic, and the difference between audit and block modes.
- NFLOG added bounded network findings. Fence discards raw packet data after parsing and never includes it in reports.

## Resident protection lifecycle

- Hosted tests established a trusted GitHub-hosted `ubuntu-24.04` x64 runner fingerprint.
- Fence added root-owned runtime files, `systemd` supervision, checks every five seconds, ordered readiness, and rollback before protection starts.
- Runner fingerprinting later accepted specific generated cloud-init headers while continuing to verify the rest of the sudo policy and detect later changes.
- Standard block mode disables passwordless sudo and Docker. `unsafe_preserve` keeps Docker available with weaker isolation, while audit mode leaves sudo and Docker available without claiming containment.
- Hosted observation added bounded inventories of Unix sockets, TCP listeners, and root-owned container processes while excluding inaccessible, irrelevant Unix-socket churn.
- Later fingerprint updates tightened trusted executable checks, local-control verification, and scheduled runner-drift detection.

## Hosted workflow compatibility

- A fixed list of guessed endpoints could not reliably support GitHub-hosted jobs, so Fence adopted a bounded DNS-mediated GitHub Actions policy.
- The policy uses explicit platform destinations, limited GitHub hostname discovery, canonical `A` and `AAAA` queries, bounded CNAME handling, and short-lived firewall rules.
- Broad GitHub destinations are available by default for compatibility. `disable_broad_github_domains: true` removes those broad destinations while keeping required job-reporting endpoints.

## Public agent and Action

- The trusted launcher starts standard block, degraded block, or audit mode only from the expected root-owned service and configuration.
- Releases added checksummed and attested Linux x64 binaries, bundled directly into the GitHub Action.
- Native Action inputs replaced raw JSON for common configuration. Raw JSON remains available for advanced use, alongside job summaries and audit-mode allowlist suggestions.

## One-PR Action publication

- Releases through `v0.6.3` used two stages: first a source release, then a reviewed update to the Action binary and manifest. Their original tags and commit pins remain unchanged.
- The current release process keeps `main` source-only. One reviewed version bump authorizes automation to build source commit `M`, create signed distribution commit `D`, test it, and publish an immutable release.
- `action-release.json` maps each release to its exact distribution commit. Users copy the full commit SHA from the finalized release notes. The Action never downloads an agent or policy at runtime.

## v0 hardening

- An unmaintained netlink dependency was replaced with a small safe-Rust NFLOG configuration writer.
- DNS handling, root-owned files, subprocess timeouts, first connections, and evidence reporting received additional checks.
- DNS authorization now follows a response-local CNAME chain rooted at the original question. Responses without matching addresses grant no access, and duplicate addresses use the shortest TTL.
- One firewall owner validates, applies, verifies, and publishes each DNS authorization in order. Waiting in the queue cannot extend an expired authorization.
- Fence preloads required exact hostnames, refreshes them while running, and keeps temporary IP addresses out of the logical policy hash.
- Fence trusts a small fixed set of storage accounts used for GitHub Actions. Additional accounts require the pinned GitHub runner identity or an eligible runner descendant when artifact support is enabled; direct allowlist entries, CNAMEs, and wildcards cannot bypass the four-account limit.
- Local TCP and UDP DNS requests both use the same root-only UDP upstream resolver; no upstream TCP firewall exception is needed.
- User allowlists support one- and two-label wildcard hostnames with a shared limit of eight discovered names.
- All resident workers report through one health channel. Post-job checks require fresh evidence and the expected live service.
- Fence copies its runtime and bundled agent into root-owned storage and mounts them read-only, so later workflow steps cannot replace the post hook.
- Process attribution can identify a likely program without logging command arguments, full paths, environment variables, packet contents, or unrelated container traffic.
- Azure WireServer access is limited to root-owned host processes at `168.63.129.16` on TCP ports `80` and `32526`.
- Azure Instance Metadata Service remains available at `169.254.169.254` on TCP port `80` only.

Future release details belong in GitHub Releases rather than this document.
