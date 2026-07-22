# AGENTS.md

This repository is the Rust implementation scaffold for Fence, a security agent intended to harden a narrowly supported CI runner class. The v0 protected target is GitHub-hosted `ubuntu-24.04` x64 with a native Linux GNU agent artifact; see `docs/v0.md` for the normative behavior contract and `docs/threat-model.md` for security claims and residual risks. It is bootstrapped from a hermetic, reproducible, air-gapped-leaning Rust template. Treat it as public open source infrastructure: every file, comment, workflow, log line, and document change may be visible to anyone.

Fence must pass the "airplane test": a normal developer or CI worker should be able to build, test, lint, and package the project without reaching the network after dependencies and toolchains have been explicitly prepared.

`Cargo.toml` is the source-agent version authority. The protected `main` branch is source-only and intentionally omits `action/bin/fence` and `action/bundle-manifest.json`. A published distribution commit adds those two generated files; its schema-`4` manifest is the bundled-agent version and provenance authority, so prose must not duplicate it as a current-version claim. The root `action.yml` wrapper exposes native Action inputs for the common configuration path and runs the bundled Linux x64 agent only from a checksum-validated, protected root-owned executable copy. `render-plan` emits a deterministic native `nftables` preview, `check-support` exposes an accepted hosted-runner fingerprint reference without claiming active protection, and ordinary direct `run` execution fails with `trusted_launcher_required` before reading configuration. On matching GitHub-hosted `ubuntu-24.04` x64 runners, Linux `run` accepts standard `block` mode with disabled container access, explicit degraded `unsafe_preserve` block mode with preserved container access, or `audit` observation mode with the selected `github_hosted_workflow_bootstrap_v5` descriptor when it executes as root inside the matching `fence-<invocation-id>.service` transient unit with pinned root-owned runtime input. Block paths apply the bounded DNS-mediated host-network policy, write production readiness only after required verification, remain resident, and never restore access after readiness. Standard block disables and verifies measured passwordless sudo plus container control paths. Degraded `unsafe_preserve` disables passwordless sudo and reports that retained Docker/containerd access invalidates the ordinary containment claim. Audit applies owned non-blocking observation rules and local DNS mediation, preserves passwordless sudo and container access, and emits observation-only readiness without a containment claim. Fingerprint schema `3` pins twelve trusted executables, their reviewed ancestors, effective runner access, accepted sudo sources, and the closed root container/TCP/Unix inventory. Every sudo source declares a digest profile: fixed sources use exact-file SHA-256, while only `/etc/sudoers.d/90-cloud-init-users` accepts one strictly validated cloud-init generated header and pins a domain-separated SHA-256 of all exact remaining bytes. Acceptance still retains the raw whole-file digest in the runtime pin so any later mutation, including a header-only change, fails verification. Production requires an exact inventory before mutation; standard block may reduce accepted container processes and owners and may remove only the exact fingerprint-tagged Docker Unix listener after its reviewed `dockerd` owner exits and the accepted socket unit stops, then pins that reduction, while degraded block and audit remain exact. Every mode rechecks the post-mutation baseline before readiness and during five-second resident verification. Production runtime evidence uses schema version `5`, logical profile identifier `github_hosted_workflow_bootstrap_v5`, and stable realization identifier `github_hosted_workflow_bootstrap_dns_provenance_v5`. The checked-in wrapper validates that same contract for the binary identified by `action/bundle-manifest.json`. The wrapper selects strict standard block with an empty `allowlist` when no input is supplied, accepts `mode: audit` as a zero-config observation-only shortcut, accepts native `allowlist` entries including exact-depth one- and two-label hostname wildcards, accepts `container_policy`, `platform_profile`, `invocation_id`, and `disable_broad_github_domains` inputs, delegates policy validation and enforcement to the agent, and checks bounded local evidence without downloading an agent, fetching policy, stopping the service, or restoring access. The advanced `config` input remains available for raw strict JSON and must not be combined with native config inputs.

The compatibility research converged on a bounded model: fixed bootstrap roots remain explicit, previously unseen Actions-suffix names are limited to eight unique lifetime authorizations and at most two prefix labels, and broad-compatible single-label `*.githubapp.com` names are limited to eight unique lifetime authorizations. User hostname policy additionally accepts one- or two-label leading wildcard patterns with exact-depth matching and one shared eight-name lifetime authorization budget; wildcard names never prehydrate or delay readiness. Only `A` and `AAAA` questions are forwarded in block mode, outbound questions are rebuilt into a canonical lowercase form before forwarding upstream, and derived CNAME authorizations must form one acyclic response-local chain rooted at the echoed question, preserve that queried root's policy, and remain within the existing TTL, depth, and capacity bounds. Address records must match the echoed question family, and duplicate terminal endpoints use the minimum TTL. A rooted CNAME response with no address records is treated as address-family NODATA and retains no derived authorization. Host DNS bypasses `systemd-resolved` through a reviewed read-only resolver mount so Fence can attribute the original caller socket. The exact Azure platform address `168.63.129.16` has separate structurally verified root-only rules for mediator UDP `53` and WireServer TCP `80` and `32526`; WireServer is not a workflow allowance. Azure IMDS at `169.254.169.254` is a separate structurally verified shared platform rule for TCP `80` only, available to host and forwarded traffic. The unique runner-owned `Runner.Worker` process is pinned by PID, start time, executable device/inode, and reviewed `Runner.Listener` ancestry. The exact `productionresultssa19.blob.core.windows.net` compatibility account is always available at TCP `443`; at most four other exact `productionresultssa<1-to-5-decimal-digits>.blob.core.windows.net` accounts may be authorized only for host DNS requests attributed to the pinned runner identity. Exact user entries for those non-static accounts are rejected before mutation, and user wildcards cannot bypass the provenance check or the four-account cap. Approved block-mode address answers are all-or-nothing: the single resident firewall owner rechecks queued transactions in order, applies and structurally verifies only accepted candidates, and then publishes authorization and active-materialization state before releasing the answer. Validation-time expiry is absolute and is not restarted by queue delay. An approved zero-TTL address uses a one-second materialization lifetime, and a valid zero-TTL CNAME edge uses a one-second effective lineage lifetime, before the existing refresh overlap; malformed, incomplete, or response-lineage-invalid responses, incomplete coverage, attribution failure, materialization-capacity rejection, or backend failure receive a minimal retryable `SERVFAIL`, while names outside policy and over-budget user wildcard names receive a minimal `REFUSED` containing only the original question without forwarding. Four DNS listener workers and one bounded local process-attribution worker report startup and fatal exits through one resident channel. Readiness waits for all required workers, and the resident report advances a five-second verification sequence only after firewall, lockdown, local-control, worker, and local-evidence checks all succeed. Critical resident health never returns to healthy. By default the descriptor includes `github.com`, `api.github.com`, `release-assets.githubusercontent.com`, the exact optional watchdog endpoint, and the bounded `*.githubapp.com` class; `disable_broad_github_domains: true` removes those platform-origin broad channels and keeps core Actions status/finalization endpoints plus exact reporting compatibility names without removing an explicit user wildcard. Required exact platform roots and valid exact user hostnames prehydrate before readiness; startup retries only transient or addressless A/AAAA rounds, at most three attempts per required hostname within one shared ten-second deadline. Malformed, response-lineage-invalid, oversized, or otherwise integrity-invalid replies fail immediately, and post-ready refresh remains single-round. Wildcard user hostnames materialize only after matching runtime DNS queries. After required roots complete, the optional watchdog receives one bounded round; a transiently empty answer does not block readiness, but any later watchdog address is still released only after its TCP `443` rule is applied and verified. The required `integration` aggregate includes disposable-host healthy, worker-failure, and local-control-drift selected-profile evidence, packaged production-shaped standard block, broad-domain opt-out block, degraded block, bounded wildcard Docker compatibility, and audit observation scenarios, and three quiet finalization replicas with downstream job-log verification. The planner selects the versioned `github_hosted_workflow_bootstrap_v5` descriptor when `platform_profile` is omitted or explicitly supplied; every other profile value is rejected before mutation.

Packets to the fixed upstream DNS tuple are dispatched through current-socket policy before generic established/related acceptance.

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

## Release Publication Model

- A reviewed pull request containing the behavior change and matching `Cargo.toml`/root `Cargo.lock` version bump is the sole human release authorization. The protected `release` environment is restricted to protected `main` and has no required reviewer.
- The signed source merge commit `M` remains on `main`. Release automation builds and attests one Linux x64 artifact from `M`, then uses GitHub's commit API to create a signed one-parent distribution commit `D` on `release-candidate/vX.Y.Z` with `M` as its sole parent and exactly `action/bin/fence` plus `action/bundle-manifest.json` as its diff.
- The schema-`4` manifest records `repository`, `release_tag`, `release_channel`, `release_url`, `source_commit`, `source_ref`, `artifact_name`, `artifact_sha256`, `bundle_path`, `signer_workflow`, and `signer_digest`. Both `source_commit` and `signer_digest` identify `M`; `source_ref` is `refs/heads/main`. Live release properties and the self-referential distribution SHA are not embedded in the manifest.
- Full fixed-`ubuntu-24.04` Action acceptance and the fixed-label zero-input drift-canary invocation must pass against exact `D` before publication. The immutable `vX.Y.Z` release tag targets `D`, and `action-release.json` maps the version, `M`, `D`, artifact name and digest, manifest schema version, signer workflow, and signer digest.
- Consumers must pin the full 40-character `action_commit` value from `action-release.json`; neither `main` nor the version tag is the consumption reference. Release notes and the final workflow summary must show the ready-to-copy form `uses: openai/fence@<D> # pin@vX.Y.Z` with the actual release tag so Dependabot can update the same-line version comment. Releases through `v0.6.3` retain their historical tag semantics, and releases through `v0.8.3` retain their truthful `GrantBirki/fence` provenance.
- No release path may download the agent or policy at Action runtime. Pull-request and ordinary `main` validation build an ephemeral production-shaped candidate from the current source; generated bundle files never land on `main`.

## Non-Negotiable Policy

- No network calls during `script/bootstrap`, `script/test`, `script/test-package-smoke`, `script/test-action-wrapper`, `script/assemble-action-bundle`, `script/validate-action-bundle`, `script/lint`, `script/build`, or `script/server`.
- `script/test-lockdown` is intentionally restricted to disposable GitHub-hosted Linux evidence jobs because its successful block and degraded scenarios disable host access without restore.
- `script/test-protected-run` is intentionally restricted to disposable GitHub-hosted Linux integration jobs because it launches a production lifecycle and leaves owned host network state plus DNS mediation resident without restore; standard block and standard broad-domain opt-out block also disable sudo/container controls, degraded block disables sudo while preserving containers, and audit preserves sudo/containers while applying non-blocking observation rules.
- `script/test-action-setup-failure` and `script/test-action-tamper` are intentionally restricted to disposable GitHub-hosted Linux Action-acceptance jobs. The former proves malformed wrapper input fails before mutation and that a source-side configuration rejection is reported promptly through a retained failed transient unit without mutating controls. The latter launches the bundled audit lifecycle, deletes owned network state after readiness, proves resident critical drift, invokes the post hook expecting failure, and never restores access.
- `script/update` is the only normal Cargo dependency update path and is intentionally online-only.
- `script/vendor-rust` is the only normal Rust distribution lock refresh path and is intentionally online-only.
- `script/prepare-rust` is the only normal Rust installation path. It is intentionally online, checksum-gated, and must validate `.cargo/tooling/rust-toolchain.lock.toml` before invoking `rustup`.
- `script/vendor-update-tools` is the only normal `cargo-audit` / `cargo-deny` lock refresh path and is intentionally online-only.
- `script/vendor-release-tools` is the only retained cross-build-tool refresh path and is intentionally online-only.
- `script/vendor-test-tools` is the only `cargo-llvm-cov` refresh path and is intentionally online-only.
- `script/assemble-action-bundle` is the only normal Action-bundle assembly path and is offline-only.
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
2. GitHub-hosted validation: the individual `lint`, `test`, `build`, and `acceptance` jobs, bundled `action acceptance`, privileged `integration`, and release build jobs run the relevant prepared-input validation paths. Hosted runners are not air-gapped infrastructure because checkout, action loading, Rust preparation, and artifact services still use network access.
3. Egress-blocked build/package jobs: after checkout, action loading, and Rust preparation, native Linux x64 build/test/package scripts can run without third-party network access because application crates are committed. Retained cross-build-tool verification additionally installs committed tool artifacts offline within `acceptance`. Release publish/sign/verify jobs still need GitHub API access.

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
  - Downloads the locked manifest and selected component archives, verifies every SHA-256, and exposes only that verified set to rustup through a temporary loopback mirror.
  - Ignores caller-provided Rust distribution, update-root, toolchain, and proxy overrides while rustup installs from the verified loopback mirror.
  - Replaces the fully qualified version-and-host toolchain only after the complete selected artifact set is locally verified, and disables rustup self-update during installation.
  - Installs the exact Rust toolchain from `rust-toolchain.toml` with the minimal profile plus `rustfmt` and `clippy`.
  - Installs extra target standard libraries only when `PREPARE_RUST_TARGETS` or `VERIFY_RUST_TARGETS` is set.
  - Does not run from offline project scripts.

- `script/test-rust-toolchain-preparation`
  - Offline-only regression coverage for the verified Rust distribution mirror.
  - Proves unlisted targets fail before fetch, modified archives fail checksum verification, and rustup replaces the selected toolchain from only the loopback mirror with source overrides removed and self-update disabled.

- `script/bootstrap`
  - Validates Rust and Cargo availability.
  - Verifies pinned Rust toolchain files and vendor cache presence.
  - Runs `cargo check --frozen`.
  - Must stay offline.

- `script/test`
  - Validates the release-tool lockfile and manifest before running tests.
  - Validates the test-tool lockfile and manifest before running tests.
  - Runs the offline Action release-state regression suite before Rust tests.
  - Runs `cargo test --frozen` by default.
  - `--coverage`, `--cov`, or `-c` requires `cargo-llvm-cov` from `script/install-test-tools` and `llvm-tools-preview` from `script/prepare-rust`.
  - Coverage mode writes text, JSON, LCOV, and HTML reports under `coverage/`.
  - Coverage mode enforces 100% line, function, and region coverage for first-party code.
  - Coverage mode must not install tools, use the network, or enable unstable branch coverage.
  - `cargo test` itself does not emit coverage; coverage mode relies on stable Rust source-based coverage instrumentation through `cargo-llvm-cov`.
  - Rootless coverage intentionally excludes `src/attribution.rs`, `src/dns_mediator.rs`, `src/nft_backend.rs`, `src/nflog.rs`, `src/runtime.rs`, `src/lifecycle.rs`, `src/local_control.rs`, `src/trusted_executable.rs`, and `src/lockdown.rs`; those Linux `/proc`, privileged kernel/socket, DNS-routing, trusted-descriptor, no-follow runtime-file, transient-service, and host-lockdown boundaries are proved through deterministic unit tests plus hosted privileged evidence on `ubuntu-24.04`.

- `script/test-privileged`
  - Linux x64-only privileged evidence entrypoint; it must not run on ordinary local or portable test paths.
  - Verifies `/usr/sbin/nft`, transient `systemd` service, namespace, IPv6, and NFLOG-rule prerequisites before invoking ignored backend tests.
  - Runs native apply/verify/rollback, bounded NFLOG collection, and resident transient-service evidence only inside disposable network namespaces and writes protected test-only lifecycle evidence below root-created non-production `/run/fence-resident-evidence-*` paths.
  - Proves five-second resident verification emits a bounded critical finding on owned-network drift and that setup failures roll back before any test-only readiness is written.
  - NFLOG handling may inspect at most the configured 64-byte packet prefix transiently in memory and must serialize approved endpoint metadata only. Source tuples used for bounded `/proc` attribution remain internal; reports may contain only attribution status, actor class, PID, executable basename, and at most four parent executable basenames.
  - May write only explicitly labelled `test_only_ready_no_protection` readiness evidence below a root-created non-production runtime root; it must not invoke the public `run` command, write production `/run/fence` readiness, mutate host firewall rules, or make a protection claim.

- `script/test-lockdown`
  - Linux x64-only, GitHub-Actions-only hosted lockdown evidence entrypoint; do not run it on developer machines or reusable runners.
  - Executes exactly one `acl-reject`, `audit`, `local-control-reject`, `rollback`, `unsafe-preserve`, or `standard` scenario inside a root transient `systemd` service after comparing the fixed hosted-runner fingerprint.
  - `acl-reject` proves a mode-preserving effective ACL grant is rejected by pinned sudo-to-test execution, and `local-control-reject` proves an unexpected root TCP listener fails before mutation or readiness.
  - Removes only the accepted runner sudo drop-in while retaining exact bounded rollback state in memory and runtime-masks only the accepted Docker/containerd units in the mutating scenarios; rollback proves the restored sudo bytes, mode, ownership, pinned digest, inventory, syntax, and uncached measured runner capability and permits only a bounded 30-second daemon restart deadline, while standard and degraded success paths intentionally do not restore before ephemeral VM teardown.
  - Emits root-owned, runner-readable `lockdown_evidence_test_only` reports below non-production `/run/fence-lockdown-evidence-*`, emits no readiness, does not apply host network policy, and cannot claim protection.

- `script/test-selected-profile-runtime`
  - Linux x64-only, GitHub-Actions-only destructive selected-profile runtime-evidence entrypoint; do not run it on developer machines or reusable runners.
  - Plans `github_hosted_workflow_bootstrap_v5` by omission, refuses any mismatched planning descriptor or user allowlist entry, and reports the schema-`9` logical policy hash plus base-ruleset hash separately from the active TTL-derived ruleset hash.
  - Routes host and Docker DNS through fixed local listeners, forwards exact bootstrap roots, exact reporting compatibility names, at most eight previously unseen Actions-suffix names with no more than two prefix labels, at most eight single-label `*.githubapp.com` names when broad compatibility is enabled, and bounded TTL-derived CNAME descendants returned by approved response chains; only `A` and `AAAA` questions are forwarded in block mode, each outbound question is rebuilt into a canonical lowercase form with a mediator-owned upstream identifier and without caller-controlled additional bytes, and upstream UDP DNS is permitted only from the root-resident mediator through an owned nftables rule.
  - Prehydrates every required exact platform hostname and every valid exact user hostname before readiness. Exact user entries for non-static runner-authorized results-storage accounts are rejected before mutation, and bootstrap processing independently rejects any runner-gated materialization. Startup retries only transient or addressless A/AAAA rounds, at most three attempts per required hostname within one shared ten-second deadline; integrity-invalid replies fail immediately, and resident refresh remains single-round. Wildcard user hostnames remain lazy and do not delay readiness. After required roots complete, the optional `hosted-compute-watchdog-prod-eus-01.githubapp.com` endpoint receives one bounded round, but a transient empty answer does not block activation; a later answer still uses the completion-driven apply-and-verify gate. Platform roots refresh every five seconds; exact user roots refresh from bounded observed TTLs no later than sixty seconds. With `disable_broad_github_domains: true`, the active broad set excludes `github.com`, `api.github.com`, `release-assets.githubusercontent.com`, the watchdog endpoint, and new platform `*.githubapp.com` authorizations while retaining the four core Actions roots, exact reporting compatibility names, and any explicit user wildcard.
  - Materializes every configured TCP/UDP transport from bounded prehydrated exact-root addresses, bounded A/AAAA answers, or bounded derived CNAME descendants, retains materialized rules for at most bounded observed TTL plus a fixed thirty-second refresh overlap, and atomically verifies each structured replacement; CNAME descendants inherit their source hostname transports.
  - Wakes the resident firewall owner when approved materialization work arrives and returns an address-bearing answer only after every returned address and configured transport receives an explicit applied-and-verified result. Approved zero-TTL addresses use a one-second materialization lifetime, and valid zero-TTL CNAME edges use a one-second effective lineage lifetime, before the existing overlap. Partial coverage, queue rejection, or service disconnection returns retryable `SERVFAIL` and bounded warning evidence; backend update failures remain critical.
  - Runs separate hosted worker-failure and post-ready local-control-drift scenarios that prove a required listener failure or additive root listener becomes persistent critical resident health without restoring controls.
  - Routes host DNS directly through the mediator with a reviewed read-only resolver mount, pins and revalidates the unique runner-owned `Runner.Worker`, permits the exact `productionresultssa19.blob.core.windows.net` compatibility root, and permits at most four other exact results-storage accounts requested by that process. Workflow, Docker, ambiguous, drifted, or spoofed requesters cannot authorize the dynamic class, and response-local CNAME lineage cannot derive a non-static results-storage account from an otherwise approved hostname. Authorized results-storage addresses, bounded Actions/GitHub-app suffix DNS authorization, DNS query timing and count, approved HTTPS destinations, bounded CNAME delegation, and the root-resident resolver path remain egress limitations.
  - Disables and verifies measured sudo/container paths, leaves all controls resident until ephemeral teardown, writes only `selected_profile_runtime_test_only` evidence below `/run/fence-selected-profile-runtime-*`, and cannot establish a public protection or activation claim.

- `script/report-selected-profile-runtime`
  - Linux x64-only, GitHub-Actions-only late-report helper for the destructive selected-profile runtime evidence; do not run it on developer machines or reusable runners.
  - Emits a short bounded heartbeat window after the blocking step returns, then reads the existing runner-readable test-only report and emits capped sanitized DNS, derived-CNAME, counter, finding, and critical-finding summaries so late connection failures can be reviewed.
  - Does not use sudo, mutate policy, select a profile, write readiness, or establish a protection claim.

- `script/test-protected-run`
  - Linux x64-only, GitHub-Actions-only production-shaped lifecycle entrypoint; do not run it on developer machines or reusable runners.
  - Builds the packaged binary from prepared local inputs, creates one pinned root-owned `/run/fence/<invocation-id>/config.json`, launches the matching `fence-<invocation-id>.service`, and waits for production readiness.
  - Proves that omitted `platform_profile` selects `github_hosted_workflow_bootstrap_v5`, native host network policy applies and verifies, direct host DNS mediation remains resident, and late verification reports no critical findings.
  - Runs three independent standard-block replicas with immediate, zero-client-retry HTTPS probes for the broad default GitHub roots so first-connection races fail the stable `integration` gate; the opt-out scenario proves those same roots remain unavailable.
  - Runs `standard` to prove container paths are disabled, `standard-opt-out` to prove the broad GitHub roots are removed while core Actions roots remain active, and `unsafe-preserve` to prove container paths remain usable while the report denies ordinary containment assurance.
  - Runs `wildcard-docker` with `unsafe_preserve` to prove exact-depth `*.docker.io` user policy authorizes concrete registry names lazily, retains Docker access, and emits bounded user-origin materialization evidence without claiming that every Docker layer CDN is covered.
  - Runs `malformed-wildcard` to prove a three-label wildcard is rejected by the source agent under the trusted launcher before Fence writes readiness or state, creates its nftables table, disables sudo, or changes Docker availability.
  - Runs `audit` to prove owned non-blocking observation rules emit bounded `would_block` findings with local process attribution when ownership remains observable, while passwordless sudo, Docker access, and arbitrary traffic remain available without a containment claim.
  - Runs three quiet `standard-finalization` replicas without artificial post-ready network warming. A downstream verifier must prove each reaches terminal success within 180 seconds and exposes a nonempty downloadable job-log archive.
  - Leaves applied state resident until ephemeral runner teardown. It must not restore access, intentionally initiate optional post-ready artifact/cache/API operations, or claim support beyond the reviewed paths.

- `script/verify-protected-finalization`
  - GitHub-Actions-only downstream verifier for either the quiet protected-run replicas plus broad-domain opt-out scenario or the quiet bundled-Action replicas selected by its fixed argument.
  - Uses a read-only Actions token to inspect only the current workflow run, requires the expected jobs to finish successfully within 180 seconds, follows the job-log redirect without forwarding the bearer token, and verifies each bounded downloaded log payload is nonempty. A naturally observed runner-authorized results-storage request is additional evidence rather than a required event because the runner may resolve or establish that path before Fence readiness or after the final readable report snapshot.
  - Accepts only bounded HTTPS redirects to reviewed GitHub Actions, GitHub content, or Azure Blob host suffixes. It must not print signed URLs, query strings, tokens, archive contents, or unrelated job metadata.

- `script/observe-hosted-runner`
  - Linux x64-only, GitHub-Actions-only hosted-runner fingerprint candidate collector for the `integration` workflow.
  - Emits and retains under the runner-provided temporary root schema-`4` bounded JSON describing only the runner principal/group names; fixed command canonical targets, types, owner/group classifications, modes, device/inode identities, and runner writability; the same metadata for bounded sudo-policy sources; reviewed resolver symlink target/type/mode/owner; fixed systemd unit state; the root-owned `walinuxagent.service` MainPID, control-group identity, and at most sixteen member PIDs with start time and executable basename/device/inode; fixed runtime socket state; aggregate Docker workload count; sudo-policy source digests plus reduced principal/group `NOPASSWD` marker classification; and a bounded closed local-control candidate inventory.
  - Serializes only the exact reviewed Ubuntu identity, runner principal, runner groups, fixed canonical targets, resolver target, sudo source identities, systemd states, and container-socket owner/group names. Unknown runner groups and sudo source names use domain-separated SHA-256 identities where uniqueness matters; other unreviewed values use fixed classifications. Raw runner group names remain private to the collector only for effective identity and sudo-marker classification, and every serialized dynamic string is printable ASCII.
  - Tries at most three times to obtain two matching security-relevant private local-control snapshots fifty milliseconds apart and reports stability, collection bounds, incomplete ownership or reachability, root `dockerd`/`containerd` identities, runner-reachable root Unix stream/seqpacket listeners, and root TCP listeners reduced to address family, wildcard/loopback/other-local class, and port. Evidence-only inaccessible Unix listener identities and counts do not affect stability, but unresolved listeners, acquisition failures, and all retained root process, reachable listener, and owner identities remain fail-closed; an excluded socket that becomes reachable enters the enforced inventory. Filesystem Unix reachability is tested after dropping to the full runner identity so ordinary mode bits and ACLs are both effective; abstract listeners owned by a resolved root process are treated as reachable. Unix names are emitted only as domain-separated SHA-256 values. Owner evidence is limited to UID, a sanitized executable basename, one exact source-reviewed canonical executable path or the `unreviewed_executable_path` classification, one exact reviewed unified-cgroup identity or the `unreviewed_cgroup` classification, and process count. An unavailable or unreviewed executable or cgroup identity makes ownership incomplete. Socket inode/UID, process PID/start-time/executable device/inode pins, and private executable-path and cgroup fingerprints for security-relevant entries participate only in private stability comparison; the public projection strips them and aggregates equivalent listeners and container processes with positive multiplicities.
  - Tests replacement capability only in the fixed `/`, `/etc`, `/etc/sudoers.d`, `/usr`, `/usr/bin`, and `/usr/sbin` ancestor directories by attempting to create and immediately delete one exclusive empty synthetic file as the runner. Root cleanup is mandatory after any partial probe. It must not probe arbitrary directories or modify commands or sudo policy.
  - Must not emit sudo policy contents, environment values, process arguments, raw Unix socket names, local listener addresses, unreviewed cgroup paths, WireServer request or response content, workload identifiers, credentials, or arbitrary host files.
  - Must not establish support, enable public enforcement, write readiness, or leave host state after its bounded synthetic probes and runner-temporary evidence. Schema-`4` observations remain evidence-only and are not themselves an authorization mechanism. The Action classifier recursively validates the envelope and compares every enforced field against the published schema-`3` fingerprint, including `/usr/bin/test`, permission ancestors, effective access, profile-specific sudo policy digests, and the complete local-control inventory. Observation-local device, inode, PID, start-time, probe-result, attempt-count, and bounded inaccessible-root-listener values remain evidence-only where schema `3` intentionally does not pin them. Malformed or internally inconsistent evidence, truncated or oversized sudo enumeration, incomplete or unstable local-control acquisition, and every enforced-field mismatch fail closed.

- `script/observe-wireserver-agent`
  - Linux x64-only, GitHub-Actions-only evidence helper for the disposable hosted `audit` scenario; it must not run on developer machines or reusable runners.
  - Observes natural connect attempts only from the fixed root-owned Python PIDs already present in `/azure.slice/walinuxagent.service`, retains matches only for the exact Azure platform address and TCP ports `80` and `32526`, and bounds process count, transient trace bytes, duration, and results.
  - Retains only root-owned process PID, start time, executable basename/device/inode, and destination port. It must not generate traffic, persist the syscall stream, or inspect command lines, environment values, local tuples, HTTP paths, payloads, responses, VM identifiers, goal-state data, certificates, or arbitrary processes.
  - Writes runner-readable observation-only evidence under the runner-provided temporary root. It must not mutate policy, establish support, write readiness, or make a protection claim.

- `script/test-package-smoke`
  - Linux x64-only offline packaged-artifact acceptance entrypoint; it accepts exactly one already-built Fence binary path.
  - Uses only a literal-IP/CIDR policy fixture and Python standard-library JSON parsing; it must not resolve hostnames, install tools, or use network access.
  - Verifies versioned JSON output, deterministic `render-plan`, direct-invocation `trusted_launcher_required` failure before config read, no `inet fence_v0` table creation, and no `/run/fence/package-acceptance/` state creation.
  - Proves only the public trusted-launcher boundary of a packaged binary; production readiness and controls are proved separately by `script/test-protected-run`.

- `script/validate-action-bundle`
  - Offline-only validation for a production-shaped Action binary and provenance manifest. It accepts an optional `--root <candidate-root>` so CI can validate an ephemeral source-built candidate without changing the checkout; `--allow-source` accepts the both-files-absent source state while still rejecting half-present state.
  - Verifies manifest schema `4`, stable or prerelease channel agreement, Linux x64 artifact name, source commit, `refs/heads/main` source ref, signer workflow and digest, bundle path, and SHA-256 match. The manifest must not claim live release draft/immutability state, attestation verification, or the distribution commit's self-referential SHA.
  - Runs from `script/validate-locks` for distribution trees; it must not fetch releases, attestations, agents, or policy.

- `script/assemble-action-bundle`
  - Offline-only assembler invoked as `script/assemble-action-bundle --artifact <path> --version <X.Y.Z[-prerelease]> --source-commit <40-lowercase-hex> --output-root <path>`.
  - Requires an explicit already-built Linux x64 artifact, package version, source commit, and safe output root; verifies the Cargo version, artifact naming, digest, schema, source/signer identity, and output containment before writing `<root>/action/bin/fence` and `<root>/action/bundle-manifest.json`.
  - Writes deterministic canonical schema-`4` JSON and preserves the binary bytes as a mode-`0644` Git-compatible blob. The wrapper, not the assembler, installs the validated bytes as a root-owned mode-`0555` executable before launch.
  - Must never fetch a release, checksum, attestation, agent, policy, or other remote input and must never become an Action runtime step.

- `script/lib/action_release.py` and `script/test-action-release`
  - Dependency-free release decision helper plus offline regression suite for strict SemVer ordering, root Cargo version agreement, exact schema-`1` release mappings, new/candidate/tag/draft/complete/withdrawn rerun state classification, conflicting state rejection, interrupted-draft identity and asset validation, and signed one-parent two-file distribution commit metadata. Its `probe-release` subcommand is an explicitly online release-workflow boundary that uses bounded authenticated pagination and never treats an API failure as absence; offline tests exercise only its pure selection and validation logic.
  - The release workflow must use the helper for the decisions it tests; keep GitHub API mutation and publication orchestration explicit in the workflow.

- `script/test-action-wrapper`
  - Offline-only dependency-free TypeScript, Node built-in `node:test`, Python standard-library host-classifier checks, and synthetic `gh`-shim checks for the Action launcher, registered-path guard selection, protected-runtime integrity records, exact writable guard and read-only runtime mount evidence, report validation, compact control and network-activity summary tables, bounded finding attribution, hostname and IPv4/IPv6 audit allowlist guidance, critical-finding propagation, runtime-path derivation, and release/bundle provenance validation.
  - The wrapper uses Node 24 built-in type stripping and Node standard-library modules only. Do not add `npm`, `package.json`, `node_modules`, external Node packages, or a runtime compilation step.
  - Action logs should stay concise by default and may use emoji plus ANSI colors for human readability. Debug logs are allowed only through GitHub Actions debug mode, must remain bounded and sanitized, and must not print raw config bodies, environment dumps, tokens, packet payloads, raw DNS packets, unrelated system logs, or arbitrary report JSON.

- `script/classify-action-bundle-host`
  - GitHub-Actions-only compatibility classifier for an ephemeral candidate or published distribution bundle before destructive activation.
  - Recursively validates the schema-`4` live observation and compares every enforced field against the bundled binary's schema-`3` `check-support` fingerprint, including trusted executables, permission ancestors, effective access, complete profile-specific sudo policy, and the exact local-control inventory.
  - Authorizes activation only when the complete fingerprint matches. Transition skips are not accepted by release validation or the fixed-runner canary.
  - Unknown digests, malformed or incomplete evidence, executable, ancestor, effective-access, resolver, principal, group, unit, socket, workload, local-control, or any other enforced fingerprint drift fail the job.
  - Job summaries should prefer bounded result tables over explanatory prose: show mode, network, sudo, and container outcomes plus reportable destinations and decisions; show sanitized local attribution only beside actual findings, keep detailed evidence in local JSON, and keep bounded hostname plus literal IPv4/IPv6 audit allowlist guidance collapsed.
  - Proves that omitted Action input derives a bounded invocation identifier from GitHub run metadata and emits strict schema-`1` standard block with an empty `allowlist`; also proves native `mode`, `invocation_id`, `container_policy`, `platform_profile`, `disable_broad_github_domains`, and multiline `allowlist` inputs without requiring raw JSON config.
  - Keeps raw `config` as an advanced strict-JSON escape hatch and rejects any attempt to combine it with native config inputs.
  - The wrapper and hosted acceptance assertions must match the source agent contract; update wrapper schema/profile constants, tests, and the source version in the same reviewed PR. Release automation builds the matching bundle after merge. They require stable profile-realization fields, bounded results-storage evidence, a live matching systemd PID, fresh verification evidence, and the exact five-worker resident set including process attribution.

- `script/test-action-acceptance`
  - Linux x64-only, GitHub-Actions-only hosted acceptance entrypoint invoked after `uses: ./`.
  - Proves standard block, degraded `unsafe_preserve`, and audit behavior from the bundled release binary while controls remain resident until ephemeral teardown. Standard block also proves the root-owned Action runtime is mounted read-only, `nodev`, and `nosuid`, and that runner-user overwrite, unlink, chmod, rename, and replacement attempts fail for every executable wrapper file and the bundled agent. The registered pathname is protected separately by writable self-bind guards on every runner-renameable ancestor. Audit acceptance also exercises a non-profile public hostname so the Action summary has DNS-backed would-block evidence to turn into `allowlist` guidance.
  - The `wildcard-docker` scenario builds a local scratch image without network access and repeatedly creates, starts, stops, and removes containers across at least three resident verification intervals without weakening local-control checks.
  - Must not stop the service, restore controls, download an agent, or fetch policy.

- `script/test-action-setup-failure`
  - Linux x64-only, GitHub-Actions-only hosted failure-path evidence entrypoint.
  - Invokes the dependency-free Action launcher with malformed invocation and wildcard inputs and proves rejection occurs before Action state, runtime directories, or owned nftables state are created.
  - Passes one bounded unsupported profile through the raw-config wrapper boundary, proves the bundled source agent rejects it before control mutation, and requires the launcher to retain the failed transient unit, fail before the readiness timeout, and emit only the structured Fence error code from the unit journal.

- `script/test-action-tamper`
  - Linux x64-only, GitHub-Actions-only hosted failure-path evidence entrypoint.
  - Launches the bundled audit lifecycle through the Action entrypoint, proves direct runner-user modification of the protected post hook fails, verifies the closest registered-path guard retains its mounted device/inode identity, proves the guarded ancestor cannot be renamed and recreated, deletes only the owned nftables table after readiness, proves five-second resident verification records critical drift, and proves the protected post hook fails without stopping the service or restoring network state.

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
  - Accepts exactly two Action-tree states: source state with both `action/bin/fence` and `action/bundle-manifest.json` absent, or distribution state with both present and passing offline bundle validation. A half-present bundle always fails.
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
  - Reads upstream `cargo-llvm-cov` artifact and Apache-2.0/MIT license URLs and checksums from `.cargo/tooling/test-tools.lock.toml`.
  - Fetches locked Linux and macOS `cargo-llvm-cov` archives plus version-matched `LICENSE-APACHE` and `LICENSE-MIT` texts, then writes `vendor/test-tools/manifest.toml`.
  - Must be run intentionally and reviewed like any other supply-chain update.

- `script/validate-test-tools`
  - Offline validation for committed test-tool artifacts.
  - Verifies version-file, lockfile, and manifest consistency, artifact and retained-license existence, SHA-256 checksums, archive path safety, expected license names and paths, and workflow/install-script guardrails.
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
- `.cargo/tooling/test-tools.lock.toml` is the human-reviewed lock for upstream test-tool artifact and license URLs and checksums.
- `vendor/release-tools` should be generated by `script/vendor-release-tools`, not manually curated. Review release-tool updates by checking pinned versions, upstream URLs, `.cargo/tooling/release-tools.lock.toml`, generated manifest checksums, archive regeneration behavior, and install/validation scripts; do not treat archived third-party tool contents as first-party Fence code.
- `vendor/test-tools` should be generated by `script/vendor-test-tools`, not manually curated. Review test-tool updates by checking pinned versions, upstream URLs, `.cargo/tooling/test-tools.lock.toml`, generated manifest checksums, retained upstream license texts, and install/validation scripts; do not treat archived third-party tool contents as first-party Fence code.
- New dependency governance tools must be pinned and either preinstalled for offline paths or limited to `script/update`.
- Fence uses exact-pinned, Linux-target-only `netlink-sys` for the privileged NFLOG socket boundary. Keep its default features disabled. Fence owns a narrow safe-Rust serializer for the three fixed NFLOG configuration messages and a bounded local parser because Linux netlink has no macOS equivalent.
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

- The protected source-check set is exactly `lint`, `test`, `build`, `acceptance`, `action acceptance`, and `integration`. The four non-destructive workflows should each expose one same-named required job on fixed `ubuntu-24.04`.
- The `lint` job should validate locks, prepare Rust through the checksum-gated repository path, bootstrap offline inputs, and run `script/lint`.
- The `test` job should validate locks, prepare Rust through the checksum-gated repository path, install committed coverage tooling, bootstrap offline inputs, and run the complete all-features test suite through `script/test --coverage`.
- The `build` job should validate locks, prepare Rust through the checksum-gated repository path, bootstrap offline inputs, and prove the native Linux x64 GNU release build.
- The `acceptance` job should validate locks, prepare Rust, bootstrap offline inputs, install and verify the committed Zig/`cargo-zigbuild` tools, build one Linux x64 GNU package, verify its checksum, and invoke `script/test-package-smoke`. Retained-tool verification remains preparation for future investigation, not a supported cross-platform artifact claim.
- The four non-destructive workflows should cancel stale pull-request runs but retain every `main` push by using pull-request-number-or-commit-SHA concurrency keys.
- The `action acceptance` workflow should expose reusable execution for an explicit full Action SHA. Pull requests and ordinary `main` validation must build one source artifact, assemble and validate an ephemeral production-shaped candidate, and run only unique disposable-`ubuntu-24.04` end-to-end cases without committing its bundle. Release validation must check out exact distribution commit `D`, validate its committed schema-`4` bundle, and invoke the root wrapper through `uses: ./`. Across zero-input standard, broad-domain opt-out, degraded wildcard-Docker, nested-layout audit, setup-rejection, tamper, and three quiet-finalization cases, the workflow must prove every supported mode, registered-path ancestor rename denial, and post-ready critical-drift failure propagation without restore. Preserve the stable `action acceptance` aggregate name and fold the read-only downloadable-log verifier into that fail-closed aggregate.
- The non-required `nightly` workflow should run daily and by input-free manual dispatch, fail closed unless the exact selected ref is `main`, build an ephemeral production-shaped candidate from that exact `main` source SHA on fixed `ubuntu-24.04`, and reuse the complete unique-case Action-acceptance suite on `ubuntu-latest`. It is not a branch-protection or release gate. A pass means only that the image currently selected by the floating label matched the reviewed fingerprint and passed the complete suite; a future image selected by `ubuntu-latest` is not automatically trusted, and the supported protected target remains fixed `ubuntu-24.04` x64.
- The non-required `action drift canary` must remain read-only, run daily, support manual dispatch with an optional full Action SHA, and expose reusable execution with a required full Action SHA. Scheduled and input-free manual runs resolve the newest non-prerelease immutable release, validate its `action-release.json`, and execute the mapped `action_commit` with `fail-fast: false` on the reviewed `ubuntu-24.04` and `ubuntu-latest` runner matrix. Manual runs that supply an explicit SHA and all reusable release-validation calls run on fixed `ubuntu-24.04` only. Every leg must fail unless the complete schema-`3` classifier authorizes normal activation, then execute and verify the zero-input standard-block lifecycle without classifier skips, fallback, cancellation-dependent cleanup, access restoration, or unbounded diagnostic output. A green `ubuntu-latest` leg is point-in-time compatibility evidence and does not expand the fixed `ubuntu-24.04` protected target.
- Fence provides no pre-merge macOS validation assurance. macOS remains outside the protected runtime boundary; adding it requires an explicit implementation, test strategy, and public support decision.
- The `integration` workflow should run only on `ubuntu-24.04`. A lightweight `preflight` job must validate repository locks before any privileged matrix launches, while every destructive leaf must retain its own preparation, hosted-runner observation, classification, and authorization. Keep ACL rejection, local-control rejection, audit, rollback, degraded, and standard lockdown cases isolated on disposable runners; run namespace-contained `script/test-privileged` immediately before terminal standard lockdown in that standard matrix leg so the proof executes in the initial parallel fan-out; retain healthy and failure selected-profile scenarios, every production-shaped protected-run case, three first-connect replicas, and three quiet-finalization replicas. Fold the read-only protected-finalization log verifier into the fail-closed stable `integration` aggregate. Keep integration concurrency commit-scoped because a stranded host-block job may be unable to receive cancellation.
- `acceptance` and `integration` must remain separate evidence boundaries: the former exercises the packaged direct-invocation trusted-launcher boundary without mutation, while the latter observes the hosted shape, proves privileged kernel/network and transient-service behavior, and launches disposable production-shaped standard block, degraded block, and audit observation services.
- Hosted validation should rely on offline defaults from `script/env` after explicit preparation completes.
- Do not add Rust toolchain setup actions to hosted validation workflows; use `script/prepare-rust` so the preparation path stays explicit, checksum-gated, and repo-owned.
- The supported agent release build job should run on `ubuntu-24.04`, run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/bootstrap`, then `script/build --release --targets "x86_64-unknown-linux-gnu"`.
- Supported v0 agent releases must contain no macOS or ARM agent artifact. A future cross-target release must be explicitly designed, documented, tested, and must fail if its required prepared tools or Rust targets are missing.
- Release publication should use a protected `release` environment restricted to protected `main` with no required reviewer; the reviewed version PR merge is the sole human authorization.
- Final release assets should be re-downloaded from GitHub Releases, checksum-verified, and attestation-verified.
- Job permissions should be least-privilege. Keep top-level workflow permissions empty where practical.
- It is acceptable for publish/sign/verify jobs to use GitHub API access. Do not claim those jobs are zero-network.
- Be explicit about CI time tradeoffs. Building `cargo-zigbuild` from committed source on PR runners is slower than downloading a binary or using a runner image, but it removes release-time crates.io/tool availability from the build path.

## Release Expectations

- `Cargo.toml` `version` is the release trigger.
- Merging one reviewed change plus version-bump PR to `main` creates the `vX.Y.Z` release through CI without a second bundle PR or separate approval.
- The release workflow is intentionally not manually dispatchable.
- Keep one repository-wide release concurrency group with `queue: max` and cancellation disabled so pending version releases are retained and processed serially instead of replacing one another.
- Do not create or push release tags manually unless the workflow is intentionally being recovered.
- The release workflow must wait for all required checks on source commit `M`, build the Linux x64 artifact exactly once, create and verify signed child distribution commit `D`, run complete Action acceptance and the strict fixed-runner canary against `D`, attest the final asset set against `M`, then publish one complete immutable release whose tag targets `D`.
- Protected release publication includes the Linux x64 binary, tarball, checksums, `action-release.json`, and artifact attestations; the narrow four-command agent CLI does not publish generated completion or man-page artifacts.
- Publication and reruns are fail-closed and idempotent: matching candidate/tag/release state may be reused only after complete re-verification, conflicting state is rejected, and no consumer SHA is emitted before final published-state verification succeeds. Publication, post-publication verification, cleanup, and final reporting must use release-state outputs produced in the same `github.run_attempt`; a partial “re-run failed jobs” attempt fails closed and instructs the operator to re-run all jobs so classification cannot be bypassed.
- Delete a temporary `release-candidate/vX.Y.Z` branch only through a server-side Git lease that still expects the source `M` after interrupted branch setup or the distribution `D` after candidate validation; never force-move or unconditionally delete an unexpected ref. After successful final verification, create a matching temporary `release-verified/vX.Y.Z` ref at `D` before deleting the candidate, then lease-delete the verification ref before emitting the consumer SHA. This marker and the exact prior `verify-release` job result make interrupted cleanup or marker creation resumable. If immutable publication occurs but its first final verification does not succeed, retain the candidate at `D` without a successful verification result as the durable withdrawal state so reruns reject the version and require a corrected new release. A matching interrupted draft may be removed and recreated only after its target, notes, channel, bot author, and every uploaded asset identity agree with the prepared release.
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
- `src/attribution.rs`, `src/dns_mediator.rs`, `src/lifecycle.rs`, `src/local_control.rs`, `src/trusted_executable.rs`, `src/lockdown.rs`, `src/nft_backend.rs`, `src/nflog.rs`, and `src/runtime.rs` are explicit privileged-boundary exceptions: their bounded `/proc` inspection, DNS-routing, trusted-descriptor execution, host-lockdown, kernel-state, netlink-socket, no-follow root-file, and transient-service execution paths are validated by hosted privileged evidence, while deterministic model, bounding, path-safety, scheduling, and prefix-to-metadata logic retain ordinary unit tests.
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
