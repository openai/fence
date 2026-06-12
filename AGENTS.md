# AGENTS.md

This repository is the Rust implementation scaffold for Fence, a security agent intended to harden a narrowly supported CI runner class. The v0 protected target is GitHub-hosted `ubuntu-24.04` x64 with a native Linux GNU agent artifact; see `docs/v0.md` for the normative behavior contract and `docs/threat-model.md` for security claims and residual risks. It is bootstrapped from a hermetic, reproducible, air-gapped-leaning Rust template. Treat it as public open source infrastructure: every file, comment, workflow, log line, and document change may be visible to anyone.

Fence must pass the "airplane test": a normal developer or CI worker should be able to build, test, lint, and package the project without reaching the network after dependencies and toolchains have been explicitly prepared.

`Cargo.toml` is the source-agent version authority. `action/bundle-manifest.json` is the bundled-agent version and provenance authority; prose must not duplicate either as a current-version claim. The root `action.yml` wrapper carries the attested Linux x64 agent and exposes native Action inputs for the common configuration path. `render-plan` emits a deterministic native `nftables` preview, `check-support` exposes an accepted hosted-runner fingerprint reference without claiming active protection, and ordinary direct `run` execution fails with `trusted_launcher_required` before reading configuration. On matching GitHub-hosted `ubuntu-24.04` x64 runners, Linux `run` accepts standard `block` mode with disabled container access, explicit degraded `unsafe_preserve` block mode with preserved container access, or `audit` observation mode with the selected `github_hosted_workflow_bootstrap_v2` descriptor when it executes as root inside the matching `fence-<invocation-id>.service` transient unit with pinned root-owned runtime input. Block paths apply the bounded DNS-mediated host-network policy, write production readiness only after required verification, remain resident, and never restore access after readiness. Standard block disables and verifies measured passwordless sudo plus container control paths. Degraded `unsafe_preserve` disables passwordless sudo and reports that retained Docker/containerd access invalidates the ordinary containment claim. Audit applies owned non-blocking observation rules and local DNS mediation, preserves passwordless sudo and container access, and emits observation-only readiness without a containment claim. Source production runtime evidence uses schema version `3`, logical profile identifier `github_hosted_workflow_bootstrap_v2`, and stable realization identifier `github_hosted_workflow_bootstrap_dns_provenance_v2`. The wrapper selects strict standard block with an empty `allowlist` when no input is supplied, accepts `mode: audit` as a zero-config observation-only shortcut, accepts native `allowlist`, `container_policy`, `platform_profile`, `invocation_id`, and `disable_broad_github_domains` inputs, delegates policy validation and enforcement to the agent, and checks bounded local evidence without downloading an agent, fetching policy, stopping the service, or restoring access. The advanced `config` input remains available for raw strict JSON and must not be combined with native config inputs.

Until the source `0.3.0` release is bundled, the committed wrapper continues requiring policy-hash schema `4` and runtime-evidence schema `2`. The bundle refresh must update the binary and wrapper validators atomically to policy-hash schema `5`, runtime-evidence schema `3`, and the v2 profile identifiers while preserving the live matching systemd PID, fresh verification evidence, and exact five-worker resident set.

The compatibility research converged on a bounded model: fixed bootstrap roots remain explicit, previously unseen Actions-suffix names are limited to eight unique lifetime authorizations and at most two prefix labels, only `A` and `AAAA` questions are forwarded in block mode, outbound questions are rebuilt into a canonical lowercase form before forwarding upstream, and derived CNAME authorizations retain their existing TTL and depth bounds. Host DNS bypasses `systemd-resolved` through a reviewed read-only resolver mount so Fence can attribute the original caller socket. The unique runner-owned `Runner.Worker` process is pinned by PID, start time, executable device/inode, and reviewed `Runner.Listener` ancestry. At most four exact `productionresultssa<1-to-5-decimal-digits>.blob.core.windows.net` accounts may be authorized, only for host DNS requests attributed to that pinned identity, and only as TCP `443` materializations. Approved block-mode address answers are released only after the single resident firewall owner explicitly reports that the matching transport rules are applied and structurally verified; rejected or disconnected requests receive a minimal retryable `SERVFAIL` response instead of an unusable address. Four DNS listener workers and one bounded local process-attribution worker report startup and fatal exits through one resident channel. Readiness waits for all required workers, and the resident report advances a five-second verification sequence only after firewall, lockdown, worker, and local-evidence checks all succeed. Critical resident health never returns to healthy. By default the descriptor includes `github.com`, `api.github.com`, and `release-assets.githubusercontent.com` for first-step checkout/setup compatibility; `disable_broad_github_domains: true` removes only those three broad roots and keeps core Actions status/finalization endpoints plus runner-authorized results storage. The required `integration` aggregate includes disposable-host healthy and worker-failure selected-profile evidence, packaged production-shaped standard block, broad-domain opt-out block, degraded block, and audit observation scenarios, and three quiet finalization replicas with downstream job-log verification. The planner selects the versioned `github_hosted_workflow_bootstrap_v2` descriptor when `platform_profile` is omitted or explicitly supplied; every other profile value is rejected before mutation.

Production runtime intake accepts only `/run/fence/<invocation-id>/config.json`, requires pinned root-owned directories containing only a root-owned `0600` regular config file before activation, uses no-follow and close-on-exec config opens, and validates that production execution is the root `MainPID` of `fence-<invocation-id>.service`. The public worker composes DNS-mediated network policy, mode-specific lockdown or observation semantics, production readiness, resident verification, and no-restore operation onto those primitives.

## North-Star Principles

- Hermetic by default: routine build, test, lint, and run workflows must not need the network.
- Explicit inputs: dependency versions, toolchain versions, release helper versions, and GitHub Actions must be pinned.
- Vendored dependencies: Cargo resolves from `vendor/cache` through `.cargo/config.toml`.
- Script-first workflow: use `script/*` entrypoints instead of ad hoc command sequences.
- Testing excellence: first-party behavior should be designed for fast unit tests and near-total line, function, and region coverage.
- Public-safe maintenance: do not add private paths, secrets, organization context, or machine-specific assumptions to tracked files.
- Repo-scoped local artifacts: keep disposable build, install, and tool extraction outputs under the working tree when practical.
- Durable documentation: if behavior changes, update `README.md`, `AGENTS.md`, and any relevant docs in the same change.

## Public Repository Hygiene

- This repository is public. Do not commit secrets, tokens, internal hostnames, private repo names, personal infrastructure details, or local absolute paths.
- Keep PR descriptions and comments generic enough for public readers.
- Prefer durable public URLs for policy references. Avoid links to private dashboards, local files, or transient logs.
- When adding examples, use placeholder names and domains instead of real private systems.
- Do not add telemetry, remote policy services, or opaque downloaded agents to Fence without explicit design approval.

## Non-Negotiable Policy

- No network calls during `script/bootstrap`, `script/test`, `script/test-package-smoke`, `script/test-action-wrapper`, `script/validate-action-bundle`, `script/lint`, `script/build`, or `script/server`.
- `script/test-lockdown` is intentionally restricted to disposable GitHub-hosted Linux evidence jobs because its successful block and degraded scenarios disable host access without restore.
- `script/test-protected-run` is intentionally restricted to disposable GitHub-hosted Linux integration jobs because it launches a production lifecycle and leaves owned host network state plus DNS mediation resident without restore; standard block and standard broad-domain opt-out block also disable sudo/container controls, degraded block disables sudo while preserving containers, and audit preserves sudo/containers while applying non-blocking observation rules.
- `script/test-action-setup-failure` and `script/test-action-tamper` are intentionally restricted to disposable GitHub-hosted Linux Action-acceptance jobs. The former proves malformed wrapper input fails before mutation. The latter launches the bundled audit lifecycle, deletes owned network state after readiness, proves resident critical drift, invokes the post hook expecting failure, and never restores access.
- `script/update` is the only normal Cargo dependency update path and is intentionally online-only.
- `script/vendor-rust` is the only normal Rust distribution lock refresh path and is intentionally online-only.
- `script/prepare-rust` is the only normal Rust installation path. It is intentionally online, checksum-gated, and must validate `.cargo/tooling/rust-toolchain.lock.toml` before invoking `rustup`.
- `script/vendor-update-tools` is the only normal `cargo-audit` / `cargo-deny` lock refresh path and is intentionally online-only.
- `script/vendor-release-tools` is the only retained cross-build-tool refresh path and is intentionally online-only.
- `script/vendor-test-tools` is the only `cargo-llvm-cov` refresh path and is intentionally online-only.
- `script/update-action-bundle` is the only normal Action-binary refresh path and is intentionally online-only.
- `script/install-zig` must stay offline-only. It installs retained Zig and `cargo-zigbuild` tooling from committed artifacts under `vendor/release-tools`.
- `script/install-test-tools` must stay offline-only. It installs `cargo-llvm-cov` from committed artifacts under `vendor/test-tools`.
- Release build jobs must not run direct `curl`, `cargo install --version`, `rustup target add`, or Rust toolchain setup actions outside the repo scripts.
- Jobs that install retained cross-build tools must verify exact tool versions after installing from committed artifacts.
- Coverage jobs must install `cargo-llvm-cov` from committed artifacts and must not enable unstable branch coverage.
- Release workflows must not expose `workflow_dispatch`; releases are created only from `Cargo.toml` version bumps merged to `main`.
- All direct Cargo dependencies in `Cargo.toml` must use exact versions such as `=1.2.3`.
- `Cargo.lock` is committed and treated as source of truth.
- Vendored crates live in `vendor/cache` and are required for offline builds.
- Local non-CI scripts should prefer ignored repo-local temp roots such as `target/tmp` for Rust, Zig, Cargo, and prepared-tool scratch artifacts. Respect caller-provided `TMPDIR` and `RUNNER_TEMP`.
- Cleanup paths for generated directories should use shared helpers from `script/lib/common.bash` instead of open-coded `rm -rf`.
- `rust-toolchain.toml`, `.rust-version`, `Cargo.toml` `rust-version`, `.cargo/tooling/rust-toolchain.lock.toml`, `.cargo/tooling/zig-version`, `.cargo/tooling/cargo-zigbuild-version`, `.cargo/tooling/cargo-llvm-cov-version`, `.cargo/tooling/cargo-audit-version`, `.cargo/tooling/cargo-deny-version`, `.cargo/tooling/update-tools.lock.toml`, `.cargo/tooling/release-tools.lock.toml`, `.cargo/tooling/test-tools.lock.toml`, `vendor/release-tools/manifest.toml`, and `vendor/test-tools/manifest.toml` must stay consistent with actual supported tools.
- GitHub Actions must be pinned to full commit SHAs.
- Checkout steps should use `persist-credentials: false` unless a job explicitly needs credentials persisted.
- Rust distribution artifacts are not committed. `.cargo/tooling/rust-toolchain.lock.toml` pins the official Rust distribution URLs and SHA-256s that `script/prepare-rust` verifies before installing with `rustup`.

## Hermeticity Model

There are three different levels in this repository. Keep them distinct when editing docs or workflows.

1. Local project workflow: checksum-gated online Rust preparation with `script/prepare-rust` when needed, then offline Cargo validation through vendored sources. `script/bootstrap`, `script/test`, `script/test-package-smoke`, `script/test-action-wrapper`, `script/validate-action-bundle`, `script/lint`, `script/build`, and `script/server` enforce the offline phase.
2. GitHub-hosted validation: `lint`, `test`, `coverage`, PR `build`, packaged-artifact `acceptance`, bundled `action acceptance`, and release build jobs run the relevant prepared-input validation paths. Hosted runners are not air-gapped infrastructure because checkout, action loading, Rust preparation, and artifact services still use network access.
3. Egress-blocked build/package jobs: after checkout, action loading, and Rust preparation, native Linux x64 build/test/package scripts can run without third-party network access because application crates are committed. Retained cross-build-tool smoke jobs additionally install committed tool artifacts offline. Release publish/sign/verify jobs still need GitHub API access.

Do not describe GitHub-hosted runners as fully air-gapped. They can validate offline script behavior, but they are not an egress-blocked environment.

## Local Artifact Placement

Keep transient tool outputs close to the repo when reasonable.

- Outside CI, `script/env` defaults `RUNNER_TEMP` and `TMPDIR` to `target/tmp` when the caller has not already set them.
- Use ignored directories under `target/` for disposable Rust, Zig, Cargo, archive extraction, and prepared-tool build artifacts.
- Do not hard-code absolute machine-specific temp paths in scripts, docs, workflows, or examples.
- Do not commit generated temp files, extracted tool directories, build-script executables, or local cache contents.
- Preserve explicit caller or CI temp roots. GitHub Actions jobs should continue using the runner-provided environment where appropriate.
- Privileged hosted test-only lifecycle evidence that must prove runner-readable root-owned state may create fixed non-production directories under `/run/fence-*-evidence-*`; only `script/test-protected-run` may exercise production `/run/fence/` readiness, and only on a disposable hosted runner.
- If a future script needs a scratch directory, derive it from `TMPDIR`, `RUNNER_TEMP`, `target/`, or another ignored repo-local path instead of choosing an OS-global location by default.

## Bash Maintainability

Keep the Bash support layer DRY enough to audit.

- New `script/*` entrypoints should source `script/env` and use shared helpers from `script/lib` instead of copying hash, TOML, archive, temp-directory, fetch, version, or lockfile parsing logic.
- Put generic helpers in `script/lib/common.bash`; put Rust distribution, update-tool, and release-tool helpers in their domain-specific `script/lib/*.bash` files.
- Keep top-level scripts as orchestration: argument parsing, online/offline intent, command ordering, and script-specific policy checks should stay easy to read.
- Do not hide security-critical workflow guardrails behind opaque abstractions when the explicit pattern is easier to audit.
- DRY refactors must preserve hermeticity, offline defaults, path-safety checks, checksum checks, exact version checks, and the intentional online-only boundaries.
- Small script-local helpers are acceptable when generalizing them would make the script harder to understand or weaken reviewability.

## Script Contracts

All scripts live in `script/` and should use `set -euo pipefail` unless there is a documented reason not to.

- `script/env`
  - Shared environment and helper functions.
  - Sources `script/lib/common.bash`; domain-specific scripts may also source focused helpers under `script/lib/`.
  - Exports offline Cargo defaults and disables rustup proxy auto-installation.
  - Outside CI, defaults `RUNNER_TEMP` and `TMPDIR` to `target/tmp` unless the caller already set them.
  - In CI, defaults an unset `RUNNER_TEMP` to `TMPDIR` or `target/tmp` for tool installs and lookups.
  - Defines `DIR`, `VENDOR_DIR`, Rust toolchain checks, vendor checks, and common `die`/`warn` helpers.
  - Do not add network behavior here.

- `script/prepare-rust`
  - Explicit online Rust preparation path for local developers and hosted validation.
  - Runs `script/validate-rust-toolchain --ci` before installing anything.
  - Installs the exact Rust toolchain from `rust-toolchain.toml` with the minimal profile plus `rustfmt` and `clippy`.
  - Installs extra target standard libraries only when `PREPARE_RUST_TARGETS` or `VERIFY_RUST_TARGETS` is set.
  - Does not run from offline project scripts.

- `script/bootstrap`
  - Validates Rust and Cargo availability.
  - Verifies pinned Rust toolchain files and vendor cache presence.
  - Runs `cargo check --frozen`.
  - Must stay offline.

- `script/test`
  - Validates the release-tool lockfile and manifest before running tests.
  - Validates the test-tool lockfile and manifest before running tests.
  - Runs `cargo test --frozen` by default.
  - `--coverage`, `--cov`, or `-c` requires `cargo-llvm-cov` from `script/install-test-tools` and `llvm-tools-preview` from `script/prepare-rust`.
  - Coverage mode writes text, JSON, LCOV, and HTML reports under `coverage/`.
  - Coverage mode enforces 100% line, function, and region coverage for first-party code.
  - Coverage mode must not install tools, use the network, or enable unstable branch coverage.
  - `cargo test` itself does not emit coverage; coverage mode relies on stable Rust source-based coverage instrumentation through `cargo-llvm-cov`.
  - Rootless coverage intentionally excludes `src/attribution.rs`, `src/dns_mediator.rs`, `src/nft_backend.rs`, `src/nflog.rs`, `src/runtime.rs`, `src/lifecycle.rs`, and `src/lockdown.rs`; those Linux `/proc`, privileged kernel/socket, DNS-routing, no-follow runtime-file, transient-service, and host-lockdown boundaries are proved through deterministic unit tests plus hosted privileged evidence on `ubuntu-24.04`.

- `script/test-privileged`
  - Linux x64-only privileged evidence entrypoint; it must not run on ordinary local or portable test paths.
  - Verifies `/usr/sbin/nft`, transient `systemd` service, namespace, IPv6, and NFLOG-rule prerequisites before invoking ignored backend tests.
  - Runs native apply/verify/rollback, bounded NFLOG collection, and resident transient-service evidence only inside disposable network namespaces and writes protected test-only lifecycle evidence below root-created non-production `/run/fence-resident-evidence-*` paths.
  - Proves five-second resident verification emits a bounded critical finding on owned-network drift and that setup failures roll back before any test-only readiness is written.
  - NFLOG handling may inspect at most the configured 64-byte packet prefix transiently in memory and must serialize approved endpoint metadata only. Source tuples used for bounded `/proc` attribution remain internal; reports may contain only attribution status, actor class, PID, executable basename, and at most four parent executable basenames.
  - May write only explicitly labelled `test_only_ready_no_protection` readiness evidence below a root-created non-production runtime root; it must not invoke the public `run` command, write production `/run/fence` readiness, mutate host firewall rules, or make a protection claim.

- `script/test-lockdown`
  - Linux x64-only, GitHub-Actions-only hosted lockdown evidence entrypoint; do not run it on developer machines or reusable runners.
  - Executes exactly one `audit`, `rollback`, `unsafe-preserve`, or `standard` scenario inside a root transient `systemd` service after comparing the fixed hosted-runner fingerprint.
  - Relocates only the accepted runner sudo drop-in and runtime-masks only the accepted Docker/containerd units in the mutating scenarios; rollback proves the restored sudo mode, pinned digest, and measured runner capability and permits only a bounded 30-second daemon restart deadline, while standard and degraded success paths intentionally do not restore before ephemeral VM teardown.
  - Emits root-owned, runner-readable `lockdown_evidence_test_only` reports below non-production `/run/fence-lockdown-evidence-*`, emits no readiness, does not apply host network policy, and cannot claim protection.

- `script/test-selected-profile-runtime`
  - Linux x64-only, GitHub-Actions-only destructive selected-profile runtime-evidence entrypoint; do not run it on developer machines or reusable runners.
  - Plans `github_hosted_workflow_bootstrap_v2` by omission, refuses any mismatched planning descriptor or user allowlist entry, and reports the schema-`5` logical policy hash plus base-ruleset hash separately from the active TTL-derived ruleset hash.
  - Routes host and Docker DNS through fixed local listeners, forwards exact bootstrap roots, the exact GitHub app receiver compatibility name, at most eight previously unseen Actions-suffix names with no more than two prefix labels, and bounded TTL-derived CNAME descendants returned by approved response chains; only `A` and `AAAA` questions are forwarded in block mode, each outbound question is rebuilt into a canonical lowercase form with a mediator-owned upstream identifier and without caller-controlled additional bytes, and upstream UDP DNS is permitted only from the root-resident mediator through an owned nftables rule.
  - Prehydrates every exact platform and user hostname before readiness. Platform roots refresh every five seconds; user roots refresh from bounded observed TTLs no later than sixty seconds. With `disable_broad_github_domains: true`, the active prehydrated root set excludes `github.com`, `api.github.com`, and `release-assets.githubusercontent.com` while retaining the four core Actions roots and exact compatibility name.
  - Materializes every configured TCP/UDP transport from bounded prehydrated exact-root addresses, bounded A/AAAA answers, or bounded derived CNAME descendants, retains materialized rules for at most bounded observed TTL plus a fixed thirty-second refresh overlap, and atomically verifies each structured replacement; CNAME descendants inherit their source hostname transports.
  - Wakes the resident firewall owner when approved materialization work arrives and returns an approved address answer only after an explicit applied-and-verified result. Queue rejection or service disconnection returns retryable `SERVFAIL` and bounded warning evidence; backend update failures remain critical.
  - Runs a separate hosted worker-failure scenario that proves a required listener failure becomes persistent critical resident health without restoring controls.
  - Routes host DNS directly through the mediator with a reviewed read-only resolver mount, pins and revalidates the unique runner-owned `Runner.Worker`, and permits at most four exact results-storage accounts requested by that process. Workflow, Docker, ambiguous, drifted, or spoofed requesters cannot authorize the class. Authorized results-storage addresses, bounded Actions-suffix DNS authorization, DNS query timing and count, approved HTTPS destinations, bounded CNAME delegation, and the root-resident resolver path remain egress limitations.
  - Disables and verifies measured sudo/container paths, leaves all controls resident until ephemeral teardown, writes only `selected_profile_runtime_test_only` evidence below `/run/fence-selected-profile-runtime-*`, and cannot establish a public protection or activation claim.

- `script/report-selected-profile-runtime`
  - Linux x64-only, GitHub-Actions-only late-report helper for the destructive selected-profile runtime evidence; do not run it on developer machines or reusable runners.
  - Emits a short bounded heartbeat window after the blocking step returns, then reads the existing runner-readable test-only report and emits capped sanitized DNS, derived-CNAME, counter, finding, and critical-finding summaries so late connection failures can be reviewed.
  - Does not use sudo, mutate policy, select a profile, write readiness, or establish a protection claim.

- `script/test-protected-run`
  - Linux x64-only, GitHub-Actions-only production-shaped lifecycle entrypoint; do not run it on developer machines or reusable runners.
  - Builds the packaged binary from prepared local inputs, creates one pinned root-owned `/run/fence/<invocation-id>/config.json`, launches the matching `fence-<invocation-id>.service`, and waits for production readiness.
  - Proves that omitted `platform_profile` selects `github_hosted_workflow_bootstrap_v2`, native host network policy applies and verifies, direct host DNS mediation remains resident, and late verification reports no critical findings.
  - Runs three independent standard-block replicas with immediate, zero-client-retry HTTPS probes for the broad default GitHub roots so first-connection races fail the stable `integration` gate; the opt-out scenario proves those same roots remain unavailable.
  - Runs `standard` to prove container paths are disabled, `standard-opt-out` to prove the broad GitHub roots are removed while core Actions roots remain active, and `unsafe-preserve` to prove container paths remain usable while the report denies ordinary containment assurance.
  - Runs `audit` to prove owned non-blocking observation rules emit bounded `would_block` findings with local process attribution when ownership remains observable, while passwordless sudo, Docker access, and arbitrary traffic remain available without a containment claim.
  - Runs three quiet `standard-finalization` replicas without artificial post-ready network warming. A downstream verifier must prove each reaches terminal success within 180 seconds and exposes a nonempty downloadable job-log archive.
  - Leaves applied state resident until ephemeral runner teardown. It must not restore access, intentionally initiate optional post-ready artifact/cache/API operations, or claim support beyond the reviewed paths.

- `script/verify-protected-finalization`
  - GitHub-Actions-only downstream verifier for the quiet protected-run replicas and broad-domain opt-out scenario.
  - Uses a read-only Actions token to inspect only the current workflow run, requires the expected jobs to finish successfully within 180 seconds, follows the job-log redirect without forwarding the bearer token, and verifies each bounded downloaded log payload is nonempty. A naturally observed runner-authorized results-storage request is additional evidence rather than a required event because the runner may resolve or establish that path before Fence readiness or after the final readable report snapshot.
  - Accepts only bounded HTTPS redirects to reviewed GitHub Actions, GitHub content, or Azure Blob host suffixes. It must not print signed URLs, query strings, tokens, archive contents, or unrelated job metadata.

- `script/observe-hosted-runner`
  - Linux x64-only, read-only hosted-runner fingerprint candidate collector for the `integration` workflow.
  - Emits bounded JSON describing only the runner principal/group names, fixed security-relevant paths, reviewed resolver symlink target/type/mode/owner, fixed systemd unit state, fixed runtime socket state, aggregate Docker workload count, and sudo-policy source digests plus reduced principal/group `NOPASSWD` marker classification for review.
  - Must not emit sudo policy contents, environment values, process arguments, workload identifiers, credentials, or arbitrary host files.
  - Must not establish support, mutate host state, enable public enforcement, or write readiness.

- `script/test-package-smoke`
  - Linux x64-only offline packaged-artifact acceptance entrypoint; it accepts exactly one already-built Fence binary path.
  - Uses only a literal-IP/CIDR policy fixture and Python standard-library JSON parsing; it must not resolve hostnames, install tools, or use network access.
  - Verifies versioned JSON output, deterministic `render-plan`, direct-invocation `trusted_launcher_required` failure before config read, no `inet fence_v0` table creation, and no `/run/fence/package-acceptance/` state creation.
  - Proves only the public trusted-launcher boundary of a packaged binary; production readiness and controls are proved separately by `script/test-protected-run`.

- `script/validate-action-bundle`
  - Offline-only validation for the committed Action binary and provenance manifest.
  - Verifies manifest schema `2`, immutable stable or prerelease release identity, matching release channel, Linux x64 artifact name, source commit, signer workflow, executable mode, and SHA-256 match.
  - Runs from `script/validate-locks`; it must not fetch releases, attestations, agents, or policy.

- `script/update-action-bundle`
  - Intentional online-only maintainer path for refreshing the Action binary from an already-published immutable stable or prerelease release tag.
  - Downloads the selected Linux x64 release asset and `checksums.txt`, verifies the checksum, verifies GitHub provenance against `.github/workflows/release.yml`, installs the binary under `action/bin/fence`, and writes `action/bundle-manifest.json`.
  - Requires the GitHub Release prerelease flag to match the selected semver tag channel.
  - Must never become an Action runtime step.

- `script/test-action-wrapper`
  - Offline-only dependency-free TypeScript and Node built-in `node:test` checks for the Action launcher, protected-runtime integrity records, read-only mount evidence, report validation, compact control and network-activity summary tables, bounded finding attribution, audit allowlist guidance, critical-finding propagation, runtime-path derivation, and bundle checksum validation.
  - The wrapper uses Node 24 built-in type stripping and Node standard-library modules only. Do not add `npm`, `package.json`, `node_modules`, external Node packages, or a runtime compilation step.
  - Action logs should stay concise by default and may use emoji plus ANSI colors for human readability. Debug logs are allowed only through GitHub Actions debug mode, must remain bounded and sanitized, and must not print raw config bodies, environment dumps, tokens, packet payloads, raw DNS packets, unrelated system logs, or arbitrary report JSON.
  - Job summaries should prefer bounded result tables over explanatory prose: show mode, network, sudo, and container outcomes plus reportable destinations and decisions; show sanitized local attribution only beside actual findings, keep detailed evidence in local JSON, and keep audit allowlist guidance collapsed.
  - Proves that omitted Action input derives a bounded invocation identifier from GitHub run metadata and emits strict schema-`1` standard block with an empty `allowlist`; also proves native `mode`, `invocation_id`, `container_policy`, `platform_profile`, `disable_broad_github_domains`, and multiline `allowlist` inputs without requiring raw JSON config.
  - Keeps raw `config` as an advanced strict-JSON escape hatch and rejects any attempt to combine it with native config inputs.
  - The wrapper and hosted acceptance assertions require policy-hash schema `4`, runtime-evidence schema `2`, stable profile-realization fields, a live matching systemd PID, fresh verification evidence, and the exact five-worker resident set including process attribution.

- `script/test-action-acceptance`
  - Linux x64-only, GitHub-Actions-only hosted acceptance entrypoint invoked after `uses: ./`.
  - Proves standard block, degraded `unsafe_preserve`, and audit behavior from the bundled release binary while controls remain resident until ephemeral teardown. Standard block also proves the root-owned Action runtime is mounted read-only, `nodev`, and `nosuid`, and that runner-user overwrite, unlink, chmod, rename, and replacement attempts fail for every executable wrapper file and the bundled agent. Audit acceptance also exercises a non-profile public hostname so the Action summary has DNS-backed would-block evidence to turn into `allowlist` guidance.
  - Must not stop the service, restore controls, download an agent, or fetch policy.

- `script/test-action-setup-failure`
  - Linux x64-only, GitHub-Actions-only hosted failure-path evidence entrypoint.
  - Invokes the dependency-free Action launcher with a malformed invocation slug and proves rejection occurs before Action state, runtime directories, or owned nftables state are created.

- `script/test-action-tamper`
  - Linux x64-only, GitHub-Actions-only hosted failure-path evidence entrypoint.
  - Launches the bundled audit lifecycle through the Action entrypoint, proves direct runner-user modification of the registered protected post hook fails, deletes only the owned nftables table after readiness, proves five-second resident verification records critical drift, and proves the protected post hook fails without stopping the service or restoring network state.

- `script/lint`
  - Runs format check, clippy, `cargo verify-project`, and docs.
  - Uses frozen Cargo commands for lint/doc generation.
  - `--auto-fix` may run `cargo fmt`; do not use it in CI.

- `script/build`
  - Builds release binaries by default.
  - `--release` enables dist artifact packaging and supports `--targets` and `--universal-darwin`.
  - Release artifact labels use an explicit `BUILD_VERSION` when supplied; otherwise they default to the checked-out `Cargo.toml` package version rather than a potentially stale local Git tag.
  - Cross builds require matching `zig` and `cargo-zigbuild`, normally installed by `script/install-zig` from committed release-tool artifacts.
  - Tool version mismatches must fail, not warn.
  - Uses `SOURCE_DATE_EPOCH` when provided for reproducible build metadata.
  - `--dist-dir` is for generated artifact directories; unsafe roots and unrelated source directories must be rejected.

- `script/server`
  - Runs the CLI/app through `cargo run --frozen`.
  - Must stay offline.

- `script/update`
  - Online-only dependency refresh path.
  - Temporarily moves `.cargo/config.toml` aside to allow Cargo registry access.
  - Runs `cargo update`, re-vendors with `cargo vendor --locked --versioned-dirs`, installs checksum-locked `cargo-audit` and `cargo-deny` from `.cargo/tooling/update-tools.lock.toml`, runs audit/deny checks, restores offline config, then verifies with offline scripts.
  - Dependency update PRs must include `Cargo.lock` and `vendor/cache` changes.

- `script/vendor-update-tools`
  - Online-only update-tool refresh path.
  - Fetches the locked `cargo-audit` and `cargo-deny` top-level crates from crates.io, verifies that each package includes `Cargo.lock`, and writes crate plus packaged-lockfile checksums to `.cargo/tooling/update-tools.lock.toml`.
  - Must be run intentionally and reviewed like any other supply-chain update.

- `script/validate-update-tools`
  - Offline validation for `.cargo/tooling/update-tools.lock.toml` schema, version-file consistency, crates.io URLs, and checksum formats.
  - With `--ci`, fetches the top-level crates and verifies crate SHA-256s plus packaged `Cargo.lock` SHA-256s before expensive CI work runs.

- `script/vendor-rust`
  - Online-only Rust distribution lock refresh path.
  - Fetches the official Rust channel manifest, verifies the manifest `.sha256`, and writes `.cargo/tooling/rust-toolchain.lock.toml`.
  - Locks upstream URLs and SHA-256s for `rustc`, `cargo`, `rustfmt`, `clippy`, and configured Rust target standard libraries.
  - Must be run intentionally and reviewed like any other supply-chain update.

- `script/validate-rust-toolchain`
  - Offline validation for Rust version-file consistency and lockfile coverage.
  - With `--ci`, fetches the official Rust channel metadata and fails if locked URLs or SHA-256s differ.

- `script/validate-locks`
  - Top-level fast lock gate for CI.
  - Runs Rust, update-tool, release-tool, Cargo/vendor, GitHub Actions SHA, and workflow image digest checks.
  - CI should run `script/validate-locks --ci` immediately after checkout.

- `script/install-zig`
  - Offline-only retained cross-build-tool installer.
  - Selects the host Zig tarball from `vendor/release-tools/manifest.toml`.
  - Verifies SHA-256 before extracting Zig under `${RUNNER_TEMP}`.
  - Verifies and expands committed `cargo-zigbuild` source/vendor archives under `${RUNNER_TEMP}`.
  - Installs `cargo-zigbuild` from expanded source and vendored dependencies with `cargo install --path --locked --offline`.
  - Must fail if installed versions do not match pinned version files.
  - Must not call `curl`, `rustup target add`, `cargo install --version`, or unset offline environment variables.

- `script/vendor-release-tools`
  - Online-only retained cross-build-tool refresh path.
  - Reads upstream release-tool URLs and checksums from `.cargo/tooling/release-tools.lock.toml`.
  - Fetches locked Zig host archives and the locked `cargo-zigbuild` crate.
  - Generates/preserves the `cargo-zigbuild` lockfile, commits a standalone reviewable lockfile copy, vendors its transitive crates, writes deterministic source/vendor `.tar.gz` archives, and writes `vendor/release-tools/manifest.toml`.
  - Must be run intentionally and reviewed like any other supply-chain update.

- `script/validate-release-tools`
  - Offline validation for committed retained cross-build-tool artifacts.
  - Verifies lockfile and manifest version consistency, lockfile/manifest agreement, artifact existence, SHA-256 checksums, archive path safety, standalone lockfile consistency, `cargo-zigbuild` source/lock/vendor archive state, and release workflow/install-script network guardrails.
  - Must fail if release-tool scripts contain embedded SHA-256 literals; expected upstream hashes belong in `.cargo/tooling/release-tools.lock.toml`.
  - Must fail if the release workflow exposes a manual `workflow_dispatch` trigger.

- `script/vendor-test-tools`
  - Online-only test-tool refresh path.
  - Reads upstream `cargo-llvm-cov` artifact URLs and checksums from `.cargo/tooling/test-tools.lock.toml`.
  - Fetches locked Linux and macOS `cargo-llvm-cov` archives and writes `vendor/test-tools/manifest.toml`.
  - Must be run intentionally and reviewed like any other supply-chain update.

- `script/validate-test-tools`
  - Offline validation for committed test-tool artifacts.
  - Verifies version-file, lockfile, and manifest consistency, artifact existence, SHA-256 checksums, archive path safety, and workflow/install-script guardrails.
  - Must fail if `script/test` enables unstable branch coverage.
  - Must fail if test-tool scripts contain embedded SHA-256 literals; expected upstream hashes belong in `.cargo/tooling/test-tools.lock.toml`.

- `script/install-test-tools`
  - Offline-only coverage-tool installer.
  - Selects the host `cargo-llvm-cov` tarball from `vendor/test-tools/manifest.toml`.
  - Verifies SHA-256 before extracting under `${RUNNER_TEMP}`.
  - Installs `cargo-llvm-cov` under `${RUNNER_TEMP}` and verifies the exact pinned version.
  - Must not call `curl`, `cargo install --version`, or unset offline environment variables.

- `script/verify-release-toolchain`
  - Offline verification for jobs that install retained cross-build tools.
  - Confirms Rust, Zig, `cargo-zigbuild`, and optional `VERIFY_RUST_TARGETS`.
  - Use this after `script/install-zig` in the cross-build-tool smoke path or a future reviewed cross-target job.

## Dependency Policy

- Direct dependencies in `Cargo.toml` must be exact-pinned.
- Do not run `cargo add`, `cargo update`, `cargo vendor`, or `cargo install` manually as a tracked application workflow replacement. Use or update `script/update`.
- Do not edit vendored crates by hand.
- Do not add git dependencies unless the change is explicitly justified and pinned to an immutable revision.
- Do not add path dependencies unless Fence intentionally becomes a workspace.
- `vendor/cache` should be generated by Cargo, not manually curated.
- `.cargo/tooling/rust-toolchain.lock.toml` is the human-reviewed lock for upstream Rust distribution URLs and checksums.
- `.cargo/tooling/update-tools.lock.toml` is the human-reviewed lock for online update-path Cargo tool crate URLs, crate checksums, and packaged `Cargo.lock` checksums.
- `.cargo/tooling/release-tools.lock.toml` is the human-reviewed lock for upstream release-tool URLs and checksums.
- `.cargo/tooling/test-tools.lock.toml` is the human-reviewed lock for upstream test-tool URLs and checksums.
- `vendor/release-tools` should be generated by `script/vendor-release-tools`, not manually curated. Review release-tool updates by checking pinned versions, upstream URLs, `.cargo/tooling/release-tools.lock.toml`, generated manifest checksums, archive regeneration behavior, and install/validation scripts; do not treat archived third-party tool contents as first-party Fence code.
- `vendor/test-tools` should be generated by `script/vendor-test-tools`, not manually curated. Review test-tool updates by checking pinned versions, upstream URLs, `.cargo/tooling/test-tools.lock.toml`, generated manifest checksums, and install/validation scripts; do not treat archived third-party tool contents as first-party Fence code.
- New dependency governance tools must be pinned and either preinstalled for offline paths or limited to `script/update`.
- Fence uses exact-pinned, Linux-target-only `netlink-sys` for the privileged NFLOG socket boundary. Keep its default features disabled. Fence owns a narrow safe-Rust serializer for the three fixed NFLOG configuration messages and a bounded local parser because Linux netlink is unavailable on portable macOS validation hosts.
- Fence uses exact-pinned, Linux-target-only `libc` constants for `O_NOFOLLOW`, `O_CLOEXEC`, and the NFLOG UAPI contract. Fence code still forbids first-party `unsafe_code`.
- The online dependency refresh path treats audit warnings as failures and applies unmaintained and unsound advisory policy across the full transitive graph.
- `cargo-vet`, SBOM generation, and auditable binaries are intended staged follow-ups. Do not quietly add online release downloads for those tools.

## Version Files

Keep these aligned:

- `rust-toolchain.toml`: exact Rust toolchain and components.
- `.rust-version`: same Rust version as `rust-toolchain.toml`.
- `Cargo.toml` `rust-version`: same enforced Rust version unless the repo intentionally adopts a separate MSRV policy with CI coverage.
- `.cargo/tooling/rust-toolchain.lock.toml`: upstream Rust distribution URL and checksum lock.
- `.cargo/tooling/zig-version`: Zig version retained for prepared future cross-target builds.
- `.cargo/tooling/cargo-zigbuild-version`: `cargo-zigbuild` version retained for prepared future cross-target builds.
- `.cargo/tooling/cargo-llvm-cov-version`: `cargo-llvm-cov` version required for coverage jobs.
- `.cargo/tooling/cargo-audit-version`: online update path `cargo-audit` version.
- `.cargo/tooling/cargo-deny-version`: online update path `cargo-deny` version.
- `.cargo/tooling/update-tools.lock.toml`: upstream update-tool crate URL, crate checksum, and packaged `Cargo.lock` checksum lock.
- `.cargo/tooling/release-tools.lock.toml`: upstream release-tool URL and checksum lock.
- `.cargo/tooling/test-tools.lock.toml`: upstream test-tool URL and checksum lock.
- `vendor/release-tools/manifest.toml`: committed release-tool artifact inventory and checksums.
- `vendor/test-tools/manifest.toml`: committed test-tool artifact inventory and checksums.

If any version file changes, update docs and verify the corresponding script behavior.

## CI Expectations

- The `build` workflow is the PR-based native Linux x64 package smoke test. It should validate locks, prepare Rust, run `script/bootstrap`, and run `script/build --release --targets "x86_64-unknown-linux-gnu"` on `ubuntu-24.04`.
- The `acceptance` workflow should run only on `ubuntu-24.04`, build its own Linux x64 package from the current commit, verify its checksum, and invoke `script/test-package-smoke` as the `acceptance` check.
- The `action acceptance` workflow should run only on disposable `ubuntu-24.04` runners, validate the committed release-bound Action bundle, invoke the root wrapper through `uses: ./`, and prove standard block, degraded `unsafe_preserve`, and audit behavior while controls remain resident. Separate jobs under the same stable aggregate must prove setup rejection before mutation and post-ready critical-drift failure propagation without restore.
- The non-required `action acceptance ubuntu latest` workflow is an observational floating-label canary. It should exercise zero-input standard block through `uses: ./` on `ubuntu-latest`, but a pass must not expand the supported protected target beyond fixed `ubuntu-24.04` x64.
- The `build` workflow should exercise retained Zig/`cargo-zigbuild` artifacts in a distinct offline install/verify smoke job. That job is not a protected release artifact claim.
- Hosted lint/test workflows may remain portable on fixed Ubuntu and macOS labels while their behavior is platform-neutral. Protected integration, package, and release jobs target fixed `ubuntu-24.04` x64 only.
- Hosted lint/test/build workflows should run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/bootstrap`, then their offline validation command or native package-smoke path.
- Hosted coverage workflows should run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/install-test-tools`, then `script/bootstrap`, then `script/test --coverage`.
- The `integration` workflow should run only on `ubuntu-24.04`, prepare the pinned Rust toolchain through repository scripts, invoke `script/observe-hosted-runner` for bounded read-only runner-shape evidence, invoke `script/test-privileged` for namespace-isolated `network_enforcement_test_only` and `resident_lifecycle_test_only` evidence, isolate `script/test-lockdown` audit, rollback, degraded, and standard host-lockdown scenarios on disposable runners, run one disposable-host selected-profile runtime scenario through `script/test-selected-profile-runtime`, and run packaged production-shaped standard block, broad-domain opt-out block, degraded block, and audit observation services through `script/test-protected-run` while preserving the stable aggregate `integration` context. Keep integration concurrency commit-scoped because a stranded host-block job may be unable to receive cancellation.
- `acceptance` and `integration` must remain separate evidence boundaries: the former exercises the packaged direct-invocation trusted-launcher boundary without mutation, while the latter observes the hosted shape, proves privileged kernel/network and transient-service behavior, and launches disposable production-shaped standard block, degraded block, and audit observation services.
- Hosted validation should rely on offline defaults from `script/env` after explicit preparation completes.
- Do not add Rust toolchain setup actions to hosted lint/test/build workflows; use `script/prepare-rust` so the preparation path stays explicit, checksum-gated, and repo-owned.
- The supported agent release build job should run on `ubuntu-24.04`, run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/bootstrap`, then `script/build --release --targets "x86_64-unknown-linux-gnu"`.
- Supported v0 agent releases must contain no macOS or ARM agent artifact. A future cross-target release must be explicitly designed, documented, tested, and must fail if its required prepared tools or Rust targets are missing.
- Release publication should use a protected `release` environment.
- Final release assets should be re-downloaded from GitHub Releases, checksum-verified, and attestation-verified.
- Job permissions should be least-privilege. Keep top-level workflow permissions empty where practical.
- It is acceptable for publish/sign/verify jobs to use GitHub API access. Do not claim those jobs are zero-network.
- Be explicit about CI time tradeoffs. Building `cargo-zigbuild` from committed source on PR runners is slower than downloading a binary or using a runner image, but it removes release-time crates.io/tool availability from the build path.

## Release Expectations

- `Cargo.toml` `version` is the release trigger.
- Merging a version bump to `main` creates the `vX.Y.Z` release through CI.
- The release workflow is intentionally not manually dispatchable.
- Do not create or push release tags manually unless the workflow is intentionally being recovered.
- Protected release packages include the Linux x64 binary, checksums, and attestations; the narrow four-command agent CLI does not publish generated completion or man-page artifacts.
- Release timestamps should come from `SOURCE_DATE_EPOCH`, normally the commit timestamp.
- The first protected agent release artifact is `x86_64-unknown-linux-gnu` only and is supported only on the tested GitHub-hosted `ubuntu-24.04` x64 target.

## Rust Code Standards

- Keep `#![forbid(unsafe_code)]` in first-party crates.
- Prefer small modules and minimal public API.
- Avoid build scripts unless they are essential and reviewed as part of the supply-chain surface.
- Treat clippy warnings as errors.
- Keep example code simple, but avoid teaching unsafe or surprising production patterns.
- Preserve public API stability unless the task explicitly calls for a breaking Fence change.
- If changing CLI output or release archive layout, update README examples.
- Keep unsupported `run` modes fail-closed. Production readiness may be emitted only by reviewed trusted-launcher lifecycles after their mode-specific controls or observation state verify.
- Keep the root `action.yml` wrapper thin: it must use dependency-free TypeScript executed by Node 24 built-in type stripping, use Node standard-library modules only, use the committed attested Linux binary, delegate policy semantics to the agent, use immutable external references in documentation, and avoid runtime agent downloads, policy fetches, service stop operations, or access restoration.

## Testing Standards

Tests are a design requirement for Fence.

- Treat `script/test` as the primary test entrypoint. Do not ask maintainers or future agents to remember ad hoc Cargo command sequences.
- Prefer Rust-native, stdlib-first tests: `#[cfg(test)]`, `#[test]`, `assert_eq!`, `assert!`, `matches!`, `Result`-returning tests when useful, and explicit fixtures.
- Keep unit tests next to the implementation they exercise so they can test private helpers without widening the public API.
- Put integration tests under `tests/` when validating public APIs, binary behavior, CLI output, filesystem boundaries, process exit status, or downstream-consumer workflows.
- For the CLI binary, use Cargo's `CARGO_BIN_EXE_<name>` integration-test environment instead of shelling through a hard-coded `target/` path.
- Every behavior change must add or update tests before relying on `script/lint` or `script/build`.
- Keep tests fast, deterministic, parallel-safe, and offline. Avoid sleeps, real network calls, wall-clock dependence, and machine-specific paths.
- Prefer small pure functions and narrow IO boundaries so important behavior can be unit tested without process, filesystem, or network setup.
- Use integration tests for IO and process behavior, but do not substitute a few broad end-to-end tests for meaningful unit coverage.
- The default first-party target is 100% line, function, and region coverage through `script/test --coverage`.
- Document explicit coverage exceptions in the change that introduces them. Acceptable exceptions are narrow: unreachable defensive code, platform-specific code not runnable on the current CI host, generated code, or behavior proven by a separate higher-fidelity test harness.
- `src/attribution.rs`, `src/dns_mediator.rs`, `src/lifecycle.rs`, `src/lockdown.rs`, `src/nft_backend.rs`, `src/nflog.rs`, and `src/runtime.rs` are explicit privileged-boundary exceptions: their bounded `/proc` inspection, DNS-routing, host-lockdown, kernel-state, netlink-socket, no-follow root-file, and transient-service execution paths are validated by hosted privileged evidence, while deterministic model, bounding, path-safety, scheduling, and prefix-to-metadata logic retain ordinary unit tests.
- Do not enable branch coverage with `cargo-llvm-cov` until that support is stable. Region coverage is the stable high-granularity gate for now.
- Do not add `cargo-tarpaulin` or another coverage tool just because it is locally installed; `cargo-llvm-cov` is the repo-owned coverage path.

## Documentation Requirements

Update docs in the same PR when changing:

- Script behavior or script arguments.
- Hermetic/offline guarantees.
- Dependency update process.
- Toolchain/version files.
- Test tooling, test strategy, or coverage guarantees.
- Release artifact layout or release verification.
- GitHub Actions permissions or release environment assumptions.
- Public Fence expectations for users and contributors.
- The Action, agent, trusted-launcher, policy, lockdown, resident-verification,
  report, or post-hook flow. Keep the Mermaid diagram in the `README.md`
  `How It Works` section aligned with the current user-facing lifecycle.

`README.md` is for users of Fence. `docs/v0.md` is the normative behavior and schema specification. `docs/threat-model.md` is the security-claim and residual-risk source and must change with any material trust-boundary change. `docs/security-review.md` records focused review findings, while `docs/history.md` contains non-normative implementation chronology. `AGENTS.md` is for maintainers and coding agents. `SECURITY.md` is for security policy and vulnerability reporting. `docs/repository-settings.md` is for settings that cannot be fully represented in tracked files.

## Validation Checklist

Use the smallest validation set that proves the change:

- Script/workflow/doc changes: `git diff --check`.
- Packaged Linux public-contract changes: build the Linux x64 artifact on `ubuntu-24.04`, verify its checksum, then run `script/test-package-smoke <artifact>`.
- Action-wrapper changes: run `script/validate-action-bundle` and `script/test-action-wrapper`, then rely on the disposable hosted `action acceptance` workflow for `uses: ./` lifecycle proof plus setup-failure and post-ready tamper evidence.
- Rust behavior changes: `script/bootstrap`, `script/test`, `script/lint`, and `script/build`.
- Coverage changes: `script/install-test-tools`, then `script/test --coverage`. Do not add a static coverage badge unless CI enforces and publishes the measured result.
- Dependency updates: `script/update`, then inspect `Cargo.lock` and `vendor/cache`, then rerun offline validation.
- Lock surface changes: run `script/validate-locks --ci`.
- Rust toolchain updates: run `script/vendor-rust`, inspect `.cargo/tooling/rust-toolchain.lock.toml`, then run `script/validate-rust-toolchain --ci` and `script/prepare-rust` on a supported host.
- Update-tool changes: run `script/vendor-update-tools`, inspect `.cargo/tooling/update-tools.lock.toml`, then run `script/validate-update-tools --ci`.
- Retained cross-build-tool updates: inspect `.cargo/tooling/release-tools.lock.toml`, run `script/vendor-release-tools`, then inspect `vendor/release-tools`, run `script/validate-release-tools`, and run `script/install-zig` on a supported host.
- Test-tool updates: inspect `.cargo/tooling/test-tools.lock.toml`, run `script/vendor-test-tools`, then inspect `vendor/test-tools`, run `script/validate-test-tools`, and run `script/install-test-tools` on a supported host.
- Release workflow changes: inspect YAML carefully and ensure release jobs still verify published release assets.

If local validation is blocked by missing tools or a local toolchain issue, report the exact blocker instead of implying the repo passed.
