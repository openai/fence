# Fence Implementation History

This page records the major implementation milestones that led to the current
v0 contract. It is historical context, not a support or security-claim source.
See [`v0.md`](v0.md) for normative behavior and
[`threat-model.md`](threat-model.md) for the current security model.

## Bootstrap and policy model

- The repository began from a hermetic Rust template with pinned toolchains,
  vendored dependencies, offline routine scripts, and Linux x64 packaging.
- The initial agent model replaced the scaffold commands with the four-command
  JSON CLI, strict schema-`1` configuration, typed allowlist entries, bounded
  hostname resolution, deterministic policy hashing, and `render-plan`.
- Public `run` remained fail-closed until the privileged lifecycle had hosted
  evidence.

## Native network evidence

- Fence adopted a fixed singleton native `nftables` table, deterministic
  ruleset rendering, structured active-state verification, and separate
  logical-policy and backend-ruleset hashes.
- Privileged namespace tests proved atomic apply, exact verification,
  Fence-owned rollback, IPv4/IPv6 behavior, forward-path behavior, and audit
  versus block verdicts before public activation.
- NFLOG collection added bounded metadata-only findings. Raw packet prefixes
  are discarded after parsing and are never serialized.

## Resident protection lifecycle

- Hosted-runner observation established one accepted GitHub-hosted
  `ubuntu-24.04` x64 fingerprint.
- Root-owned runtime storage, transient `systemd` supervision, five-second
  resident verification, readiness ordering, and pre-ready rollback were
  proved before public activation.
- Later hosted evidence added additional exact accepted digests for the fixed cloud-init sudo-policy source without broadening any other fingerprint fact.
- A bounded Action-acceptance classifier removed the source-before-bundle
  release deadlock while continuing to reject every unreviewed host drift.
- The subsequent attested Action bundle refresh adopted profile v4, policy-hash
  schema `7`, runtime-evidence schema `4`, and the root-only WireServer rules.
- Standard block added measured passwordless-sudo and Docker/containerd
  lockdown. `unsafe_preserve` retained container access with degraded
  assurance, while audit preserved sudo and containers and made no containment
  claim.
- The evidence-only hosted observer advanced to schema `4` and added stable,
  bounded, privacy-reduced Unix/TCP listener and root container-process
  inventory for review before any closed-host enforcement change.
- The attested Action bundle later published fingerprint schema `2`, enforced
  the reviewed trusted-path, effective-access, and local-control facts during
  host classification, and added a fatal scheduled fixed-runner drift canary.

## Hosted workflow compatibility

- Fixed endpoint guesses could not reliably complete hosted jobs. Controlled
  evidence selected a bounded DNS-mediated workflow-bootstrap profile instead
  of broad arbitrary DNS or HTTPS access.
- The selected profile uses explicit roots, bounded Actions-suffix discovery,
  canonical `A`/`AAAA` forwarding, bounded CNAME descendants, TTL-derived
  address rules, and completion-driven firewall materialization.
- Broad `github.com`, `api.github.com`, and release-asset roots are enabled for
  first-step compatibility and can be removed with
  `disable_broad_github_domains: true` while core job-reporting endpoints remain.

## Public agent and Action

- The trusted launcher activated standard block, degraded block, and audit only
  for a matching root transient service with pinned root-owned input.
- Stable publication added checksum- and attestation-verified Linux x64 release
  artifacts and a same-repository Action carrying the reviewed binary.
- The Action moved from raw JSON as its primary interface to native inputs while
  retaining strict JSON as an advanced escape hatch. It also added compact
  progress logs, result-oriented job summaries, and audit allowlist guidance.

## v0 hardening

- The agent replaced an unmaintained general netlink packet dependency with a
  narrow safe-Rust NFLOG configuration serializer.
- DNS, privileged file handling, subprocess deadlines, response binding,
  first-connection ordering, and evidence propagation received focused
  hardening.
- Derived DNS authorization moved from process-wide answer-owner matching to a
  response-local chain rooted at the echoed question, with atomic validation
  and queried-root policy retention. Address-family NODATA responses retain no
  derived authorization, and duplicate terminal endpoints use the minimum TTL.
- The single firewall owner now rechecks, applies, verifies, and publishes DNS
  authorization and materialization candidates as one ordered transaction;
  queued work cannot restart validation-time expiry.
- The logical policy now merges platform and user hostname transports,
  prehydrates exact roots, refreshes them during the resident lifecycle, and
  keeps transient addresses out of the logical hash.
- Source-built policy added exact-depth one- and two-label user wildcard
  hostnames with one shared eight-name lifetime budget, lazy DNS-mediated
  materialization, deterministic transport union, and explicit local evidence.
  The subsequent atomic Action refresh adopted the attested v0.5.0 agent,
  native wildcard parsing, policy-hash schema `8`, runtime-evidence schema `5`,
  bounded wildcard warnings, and hosted Docker-registry endpoint evidence.
- Resident workers now report through one health channel; fresh evidence and a
  live matching service are required at post-job time.
- The Action runtime and bundled agent are copied to root-owned storage and
  mounted read-only after launch so later runner-user code cannot replace the
  registered post hook.
- Bounded local `/proc` correlation may add best-effort process attribution to
  actual findings without telemetry, command arguments, full paths,
  environments, or payload data.
- Hosted evidence pinned the root-owned `walinuxagent.service` identity and
  observed the same service process naturally connecting to both Azure
  WireServer ports. The next profile version added exact UID `0` TCP `80` and
  `32526` rules for `168.63.129.16` as a dedicated platform-service class while
  leaving workflow traffic and Azure IMDS blocked.
- A later profile revision added an exact shared TCP `80` rule for Azure IMDS at `169.254.169.254`, with structural active-state verification and an updated logical policy-hash schema. No other IMDS port is part of the platform contract.

Future release details belong in GitHub Releases rather than this document.
