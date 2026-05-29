# AGENTS.md

This repository is the Rust implementation scaffold for Fence, a security agent intended to harden a narrowly supported CI runner class. The v0 protected target is GitHub-hosted `ubuntu-24.04` x64 with a native Linux GNU agent artifact; see `docs/v0.md` for the normative security contract. It is bootstrapped from a hermetic, reproducible, air-gapped-leaning Rust template. Treat it as public open source infrastructure: every file, comment, workflow, log line, and document change may be visible to anyone.

Fence must pass the "airplane test": a normal developer or CI worker should be able to build, test, lint, and package the project without reaching the network after dependencies and toolchains have been explicitly prepared.

The current binary remains the Phase 3 non-enforcing agent model while Phase 4 evidence is collected: `render-plan` emits a deterministic native `nftables` preview, `check-support` exposes an accepted but not runtime-checked hosted-runner fingerprint reference, and `run` fails closed without writing readiness or claiming protection. Hidden Linux code reaches native network apply/verify/rollback, NFLOG ingestion, measured sudo/container lockdown, non-blocking host audit measurement, DNS-mediated audit measurement, DNS-mediated host-block candidate measurement, and composed test-only ordering only through privileged hosted evidence. Resident network evidence, including non-blocking host audit measurement, may emit explicitly test-only readiness below a root-created non-production runtime root; separate disposable-host lockdown scenarios emit no readiness. Composed evidence may emit explicitly non-protecting readiness only after namespace-isolated block networking and measured host lockdown both verify; because its blocking rules do not protect the host network, it is not containment proof. Phase 4B rejected fixed GitHub status-channel and fixed service/results-storage candidates, including a measured hosted-runner platform-channel expansion, after host-block jobs completed visible local steps but failed to become terminal. The explicit-only `github_hosted_https_baseline_candidate_v1` test profile then opened TCP `443` plus measured hosted-runner DNS/host-control channels and reached terminal success in three disposable-host jobs. An HTTPS-only reduction left one of three jobs non-terminal after visible completion. The reduced `github_hosted_https_udp_dns_candidate_v1` profile retained open TCP `443`, added back only UDP DNS to the measured platform resolver, and reached terminal success in three disposable-host jobs; it remains a broad, non-default diagnostic candidate. A non-required DNS-mediated audit experiment routes host and Docker DNS through a local mediator and classifies bounded GitHub-related queries against four fixed GitHub compatibility patterns. A DNS-mediated host-block candidate then reached terminal success while applying root-resident upstream DNS and TTL-derived HTTPS address grants, but its unrestricted wildcard DNS authorization remained unsuitable as a default. Exact-name reductions also remained non-terminal. The constrained follow-up limits previously unseen Actions-suffix names, canonicalizes forwarded DNS, retains bounded CNAME-derived HTTPS grants, and now runs behind required hosted evidence. The planner models that reviewed mechanism as `github_hosted_job_status_v1` when `platform_profile` is omitted, while runtime realization, production readiness, and public activation remain later trusted-launcher work.

The compatibility-first diagnostic reached terminal success in three hosted jobs. Removing `codeload.github.com` because v0 does not support post-ready action downloads also reached terminal success in three hosted jobs. Removing the results-storage wildcard because v0 does not support post-ready artifact or cache storage traffic also reached terminal success in three hosted jobs. Replacing the remaining Actions wildcard with four exact bootstrap roots while retaining the exact GitHub app receiver compatibility name and bounded TTL-derived CNAME descendants again left all three jobs non-terminal after visible completion. The constrained follow-up replaces the unrestricted Actions suffix with a test-only model: fixed bootstrap roots remain explicit, previously unseen suffix names are limited to eight unique lifetime authorizations and at most two prefix labels, only `A` and `AAAA` questions are forwarded in block mode, outbound questions are rebuilt into a canonical lowercase form before forwarding upstream, and derived CNAME authorizations retain their existing TTL and depth bounds. Six disposable-host replicas across two executions reached terminal success. The required `integration` aggregate now includes one disposable-host bounded DNS-mediated block scenario so compatibility regressions fail the stable evidence gate. The non-enforcing planner selects the versioned `github_hosted_job_status_v1` descriptor when `platform_profile` is omitted and retains explicit `"none"` as the strict override. Runtime TTL-derived materialization, production readiness, and public activation remain deferred to the trusted-launcher implementation.

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

- No network calls during `script/bootstrap`, `script/test`, `script/test-package-smoke`, `script/lint`, `script/build`, or `script/server`.
- `script/test-lockdown` is intentionally restricted to disposable GitHub-hosted Linux evidence jobs because its successful block and degraded scenarios disable host access without restore.
- `script/update` is the only normal Cargo dependency update path and is intentionally online-only.
- `script/vendor-rust` is the only normal Rust distribution lock refresh path and is intentionally online-only.
- `script/prepare-rust` is the only normal Rust installation path. It is intentionally online, checksum-gated, and must validate `.cargo/tooling/rust-toolchain.lock.toml` before invoking `rustup`.
- `script/vendor-update-tools` is the only normal `cargo-audit` / `cargo-deny` lock refresh path and is intentionally online-only.
- `script/vendor-release-tools` is the only retained cross-build-tool refresh path and is intentionally online-only.
- `script/vendor-test-tools` is the only `cargo-llvm-cov` refresh path and is intentionally online-only.
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

1. Local project workflow: checksum-gated online Rust preparation with `script/prepare-rust` when needed, then offline Cargo validation through vendored sources. `script/bootstrap`, `script/test`, `script/test-package-smoke`, `script/lint`, `script/build`, and `script/server` enforce the offline phase.
2. GitHub-hosted validation: `lint`, `test`, `coverage`, PR `build`, packaged-artifact `acceptance`, and release build jobs run `script/validate-locks --ci`, then `script/prepare-rust`, then the normal offline scripts. Hosted runners are not air-gapped infrastructure because checkout, action loading, Rust preparation, and artifact services still use network access.
3. Egress-blocked build/package jobs: after checkout, action loading, and Rust preparation, native Linux x64 build/test/package scripts can run without third-party network access because application crates are committed. Retained cross-build-tool smoke jobs additionally install committed tool artifacts offline. Release publish/sign/verify jobs still need GitHub API access.

Do not describe GitHub-hosted runners as fully air-gapped. They can validate offline script behavior, but they are not an egress-blocked environment.

## Local Artifact Placement

Keep transient tool outputs close to the repo when reasonable.

- Outside CI, `script/env` defaults `RUNNER_TEMP` and `TMPDIR` to `target/tmp` when the caller has not already set them.
- Use ignored directories under `target/` for disposable Rust, Zig, Cargo, archive extraction, and prepared-tool build artifacts.
- Do not hard-code absolute machine-specific temp paths in scripts, docs, workflows, or examples.
- Do not commit generated temp files, extracted tool directories, build-script executables, or local cache contents.
- Preserve explicit caller or CI temp roots. GitHub Actions jobs should continue using the runner-provided environment where appropriate.
- Privileged hosted lifecycle evidence that must prove runner-readable root-owned state may create fixed non-production directories under `/run/fence-*-evidence-*`; it must never write production `/run/fence/` readiness.
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
  - Rootless coverage intentionally excludes `src/composed.rs`, `src/dns_mediator.rs`, `src/nft_backend.rs`, `src/nflog.rs`, `src/runtime.rs`, `src/lifecycle.rs`, and `src/lockdown.rs`; those Linux privileged kernel/socket, DNS-routing, no-follow runtime-file, transient-service, composed-ordering, and host-lockdown boundaries are proved through deterministic unit tests plus hosted privileged evidence on `ubuntu-24.04`.

- `script/test-privileged`
  - Linux x64-only privileged evidence entrypoint; it must not run on ordinary local or portable test paths.
  - Verifies `/usr/sbin/nft`, transient `systemd` service, namespace, IPv6, and NFLOG-rule prerequisites before invoking ignored backend tests.
  - Runs native apply/verify/rollback, bounded NFLOG collection, and resident transient-service evidence only inside disposable network namespaces and writes protected test-only lifecycle evidence below root-created non-production `/run/fence-resident-evidence-*` paths.
  - Proves five-second resident verification emits a bounded critical finding on owned-network drift and that setup failures roll back before any test-only readiness is written.
  - NFLOG handling may inspect at most the configured 64-byte packet prefix transiently in memory and must serialize approved endpoint metadata only.
  - May write only explicitly labelled `test_only_ready_no_protection` readiness evidence below a root-created non-production runtime root; it must not invoke the public `run` command, write production `/run/fence` readiness, mutate host firewall rules, or make a protection claim.

- `script/test-lockdown`
  - Linux x64-only, GitHub-Actions-only hosted lockdown evidence entrypoint; do not run it on developer machines or reusable runners.
  - Executes exactly one `audit`, `rollback`, `unsafe-preserve`, or `standard` scenario inside a root transient `systemd` service after comparing the fixed hosted-runner fingerprint.
  - Relocates only the accepted runner sudo drop-in and runtime-masks only the accepted Docker/containerd units in the mutating scenarios; rollback proves the restored sudo mode, pinned digest, and measured runner capability and permits only a bounded 30-second daemon restart deadline, while standard and degraded success paths intentionally do not restore before ephemeral VM teardown.
  - Emits root-owned, runner-readable `lockdown_evidence_test_only` reports below non-production `/run/fence-lockdown-evidence-*`, emits no readiness, does not apply host network policy, and cannot claim protection.

- `script/test-composed`
  - Linux x64-only, GitHub-Actions-only composed evidence entrypoint; do not run it on developer machines or reusable runners.
  - Launches one root transient service in a disposable network namespace; that service applies/verifies standard block networking inside the namespace, disables/verifies the measured host sudo/container paths, and remains resident after test-only readiness.
  - Emits root-owned, runner-readable `composed_lifecycle_test_only` evidence and `composed_test_only_ready_no_protection` below non-production `/run/fence-composed-evidence-*`; the namespace-local network policy means it is an ordering/lifecycle proof, not protected host execution.
  - Leaves verified host lockdown and the isolated resident service in place until ephemeral VM teardown; it must not write production readiness, restore controls after readiness, or select a platform profile.

- `script/measure-platform-egress`
  - Linux x64-only, GitHub-Actions-only Phase 4A compatibility-measurement entrypoint; do not run it on developer machines or reusable runners.
  - `start` compiles the ignored measurement worker from prepared vendored inputs, launches it as a root transient service, and applies only non-blocking host `audit` policy with no declared allowances.
  - `report` emits bounded approved metadata from controlled GitHub metadata/artifact activity before hosted teardown; it does not download policy, write production readiness, select a platform profile, or claim protection.
  - The script itself stays on prepared local inputs; the surrounding workflow steps intentionally exercise GitHub network services after audit activation to generate measurement evidence.

- `script/test-dns-measurement`
  - Linux x64-only, GitHub-Actions-only DNS-mediated audit experiment entrypoint; do not run it on developer machines or reusable runners.
  - Launches a root transient service that forwards host and Docker DNS through fixed local listeners to the measured platform resolver, while applying only non-blocking host `audit` rules.
  - Retains only bounded normalized GitHub-related query names, canonical A/AAAA answer addresses, and minimum observed answer TTLs, and classifies them against the fixed test-only compatibility hypothesis `*.actions.githubusercontent.com`, `codeload.github.com`, `actions-results-receiver-production.githubapp.com`, and `productionresultssa*.blob.core.windows.net`.
  - DNS answer addresses are bounded attribution evidence only; they must not authorize firewall rules or create a selected/default profile in this measurement path.
  - Uses only a fixed non-GitHub DNS probe to prove host and Docker-address forwarding after activation; that probe is counted but its hostname is not retained. It performs no intentional post-activation API, cache, artifact, or action-download operation, writes evidence only below non-production `/run/fence-dns-measurement-*`, and cannot select a platform profile or claim protection.

- `script/test-dns-block-candidate`
  - Linux x64-only, GitHub-Actions-only destructive DNS-mediated candidate entrypoint; do not run it on developer machines or reusable runners.
  - Routes host and Docker DNS through fixed local listeners, forwards exact bootstrap roots, the exact GitHub app receiver compatibility name, at most eight previously unseen Actions-suffix names with no more than two prefix labels, and bounded TTL-derived CNAME descendants returned by approved response chains; only `A` and `AAAA` questions are forwarded in block mode, each outbound question is rebuilt into a canonical lowercase form with a mediator-owned upstream identifier and without caller-controlled additional bytes, and upstream UDP DNS is permitted only from the root-resident mediator through an owned nftables rule.
  - Refreshes exact `vstoken.actions.githubusercontent.com`, `pipelines.actions.githubusercontent.com`, `payload.pipelines.actions.githubusercontent.com`, and `results-receiver.actions.githubusercontent.com` bootstrap roots every five seconds while reporting derived CNAME authorizations even when delegated DNS operator names leave GitHub suffixes.
  - Materializes owned HTTPS address rules only from bounded A/AAAA answers for those approved compatibility names or derived CNAME descendants, retains materialized rules for at most bounded observed TTL plus a fixed thirty-second refresh overlap, and atomically verifies each structured replacement; it proves unrelated GitHub API traffic is refused locally.
  - Reports that post-ready codeload and results-storage traffic are unsupported and that bounded Actions-suffix DNS authorization, DNS query timing and count, approved HTTPS destinations, their resolved IP-address realization, bounded CNAME delegation, and the root-resident resolver path remain egress limitations; required integration exercises the test-only mechanism and the planner models it as the versioned default descriptor, but runtime materialization cannot become active protection before the trusted-launcher review.
  - Disables and verifies measured sudo/container paths, leaves all controls resident until ephemeral teardown, writes only `dns_mediated_host_block_candidate_test_only` evidence below `/run/fence-dns-block-candidate-*`, and cannot establish a public protection or activation claim.

- `script/report-dns-block-candidate`
  - Linux x64-only, GitHub-Actions-only late-report helper for the destructive DNS-mediated candidate; do not run it on developer machines or reusable runners.
  - Emits a short bounded heartbeat window after the blocking step returns, then reads the existing runner-readable test-only report and emits capped sanitized DNS, derived-CNAME, counter, finding, and critical-finding summaries so late connection failures can be reviewed.
  - Does not use sudo, mutate policy, select a profile, write readiness, or establish a protection claim.

- `script/test-profile-candidate`
  - Linux x64-only, GitHub-Actions-only destructive compatibility entrypoint; do not run it on developer machines or reusable runners.
  - Launches standard block networking plus measured sudo/container lockdown on the disposable workflow host using only explicit `github_hosted_https_udp_dns_candidate_v1` and zero user allowances.
  - The candidate is an intentionally open diagnostic reduction rather than a final status-only profile: it permits arbitrary outbound TCP `443` and UDP DNS to the measured platform resolver while removing TCP DNS and host-control allowances, and reports that later workflow code can use both permitted channels for egress.
  - Leaves all verified controls resident so the hosted workflow conclusion tests compatibility; it emits only `host_block_candidate_test_only` evidence under a non-production runtime root, never public readiness or a protection claim.
  - The candidate workflow remains non-required after terminal success because arbitrary HTTPS and DNS still require a separately reviewed constrained design before any integration/default-profile decision.

- `script/observe-hosted-runner`
  - Linux x64-only, read-only hosted-runner fingerprint candidate collector for the `integration` workflow.
  - Emits bounded JSON describing only the runner principal/group names, fixed security-relevant paths, fixed systemd unit state, fixed runtime socket state, aggregate Docker workload count, and sudo-policy source digests plus reduced principal/group `NOPASSWD` marker classification for review.
  - Must not emit sudo policy contents, environment values, process arguments, workload identifiers, credentials, or arbitrary host files.
  - Must not establish support, mutate host state, enable public enforcement, or write readiness.

- `script/test-package-smoke`
  - Linux x64-only offline packaged-artifact acceptance entrypoint; it accepts exactly one already-built Fence binary path.
  - Uses only a literal-IP/CIDR policy fixture and Python standard-library JSON parsing; it must not resolve hostnames, install tools, or use network access.
  - Verifies versioned JSON output, deterministic `render-plan`, fail-closed `run`, no `inet fence_v0` table creation, and no `/run/fence/package-acceptance/` state creation.
  - Proves only the current non-enforcing public CLI contract of a packaged binary; it is distinct from hosted-runner observation and privileged network evidence and cannot make a protection claim.

- `script/lint`
  - Runs format check, clippy, `cargo verify-project`, and docs.
  - Uses frozen Cargo commands for lint/doc generation.
  - `--auto-fix` may run `cargo fmt`; do not use it in CI.

- `script/build`
  - Builds release binaries by default.
  - `--release` enables dist artifact packaging and supports `--targets` and `--universal-darwin`.
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
- Phase 2C uses exact-pinned, Linux-target-only `netlink-packet-netfilter` and `netlink-sys` dependencies for privileged NFLOG evidence. Keep them scoped to Linux because netlink is unavailable on portable macOS validation hosts, and keep `netlink-sys` default features disabled.
- Phase 3B uses exact-pinned, Linux-target-only `libc` constants for `O_NOFOLLOW` and `O_CLOEXEC` on secure test-lifecycle evidence files. Fence code still forbids first-party `unsafe_code`; the crate was already present transitively in the vendored Linux graph before becoming an explicit runtime-safety input.
- The selected typed netlink message stack currently pulls the unmaintained `paste` crate transitively through `netlink-packet-utils`; `cargo audit` reports it as an allowed maintenance warning rather than a known vulnerability. Reassess that dependency before a protection-bearing release.
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
- The `build` workflow should exercise retained Zig/`cargo-zigbuild` artifacts in a distinct offline install/verify smoke job. That job is not a protected release artifact claim.
- Hosted lint/test workflows may remain portable on fixed Ubuntu and macOS labels while their behavior is platform-neutral. Protected integration, package, and release jobs target fixed `ubuntu-24.04` x64 only.
- Hosted lint/test/build workflows should run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/bootstrap`, then their offline validation command or native package-smoke path.
- Hosted coverage workflows should run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/install-test-tools`, then `script/bootstrap`, then `script/test --coverage`.
- The `integration` workflow should run only on `ubuntu-24.04`, prepare the pinned Rust toolchain through repository scripts, invoke `script/observe-hosted-runner` for bounded read-only runner-shape evidence, invoke `script/test-privileged` for namespace-isolated `network_enforcement_test_only` and `resident_lifecycle_test_only` evidence, isolate `script/test-lockdown` audit, rollback, degraded, and standard host-lockdown scenarios on disposable runners, run `script/test-composed` for namespace-network plus host-lockdown ordering evidence, run `script/measure-platform-egress` around controlled GitHub metadata/artifact operations in a separate non-blocking host-audit job, and run one disposable-host bounded DNS-mediated block scenario through `script/test-dns-block-candidate` while preserving the stable aggregate `integration` context. Keep integration concurrency commit-scoped because a stranded host-block evidence job may be unable to receive cancellation.
- The non-required `platform DNS measurement` workflow may invoke `script/test-dns-measurement` to mediate host and Docker DNS during a non-blocking host audit and emit bounded GitHub-related query evidence; it remains separate from required `integration` until a reviewed blocking design exists.
- The `platform DNS block candidate` workflow may continue invoking three disposable `script/test-dns-block-candidate` replicas for broader measurement after one bounded DNS-mediated block scenario joins required `integration`; neither path activates public protection or writes production readiness. The non-enforcing planner separately models the bounded mechanism as the versioned default hosted job-status descriptor.
- The non-required `platform profile candidate` workflow may invoke `script/test-profile-candidate` for destructive hosted finalization experiments; it must not be promoted into required `integration`, selected by omission, or represented as a protected profile until terminal evidence is reviewed.
- `acceptance` and `integration` must remain separate evidence boundaries: the former exercises the packaged non-enforcing CLI, while the latter observes the hosted shape and proves privileged kernel/network and transient-service behavior without activating protection.
- Hosted validation should rely on offline defaults from `script/env` after explicit preparation completes.
- Do not add Rust toolchain setup actions to hosted lint/test/build workflows; use `script/prepare-rust` so the preparation path stays explicit, checksum-gated, and repo-owned.
- The first publishable agent release build job should run on `ubuntu-24.04`, run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/bootstrap`, then `script/build --release --targets "x86_64-unknown-linux-gnu"`.
- The first publishable agent release must contain no macOS or ARM agent artifact. A future cross-target release must be explicitly designed, documented, tested, and must fail if its required prepared tools or Rust targets are missing.
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
- Phase 2A and the first protected release package should include the Linux x64 binary, checksums, and attestations; the narrow four-command agent CLI does not publish generated completion or man-page artifacts.
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
- Until the protected lifecycle is implemented, `run` must remain fail-closed and no first-party code may emit a ready-state protection assertion.
- Do not add a public `action.yml` wrapper until the protected lifecycle can truthfully report readiness; the intended later wrapper lives in this repository, uses an immutable external reference, carries a reviewed Linux binary, and does not download an agent at runtime.

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
- `src/composed.rs`, `src/dns_mediator.rs`, `src/lifecycle.rs`, `src/lockdown.rs`, `src/nft_backend.rs`, `src/nflog.rs`, and `src/runtime.rs` are explicit privileged-boundary exceptions: their composed-ordering, DNS-routing, host-lockdown, kernel-state, netlink-socket, no-follow root-file, and transient-service execution paths are validated by hosted privileged evidence, while deterministic model, bounding, path-safety, scheduling, and prefix-to-metadata logic retain ordinary unit tests.
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

`README.md` is for users of Fence. `docs/v0.md` is the normative security and implementation specification. `AGENTS.md` is for maintainers and coding agents. `SECURITY.md` is for security policy and vulnerability reporting. `docs/repository-settings.md` is for settings that cannot be fully represented in tracked files.

## Validation Checklist

Use the smallest validation set that proves the change:

- Script/workflow/doc changes: `git diff --check`.
- Packaged Linux public-contract changes: build the Linux x64 artifact on `ubuntu-24.04`, verify its checksum, then run `script/test-package-smoke <artifact>`.
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
