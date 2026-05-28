# AGENTS.md

This repository is the Rust implementation scaffold for Fence, a security agent intended to harden a narrowly supported CI runner class. The v0 protected target is GitHub-hosted `ubuntu-24.04` x64 with a native Linux GNU agent artifact; see `docs/v0.md` for the normative security contract. It is bootstrapped from a hermetic, reproducible, air-gapped-leaning Rust template. Treat it as public open source infrastructure: every file, comment, workflow, log line, and document change may be visible to anyone.

Fence must pass the "airplane test": a normal developer or CI worker should be able to build, test, lint, and package the project without reaching the network after dependencies and toolchains have been explicitly prepared.

The current Phase 2B binary is still non-enforcing: `render-plan` emits a deterministic native `nftables` preview, while `run` fails closed and no code writes readiness or claims protection. Native apply/verify/rollback code is reachable only from privileged evidence tests; the complete protected lifecycle is a later reviewed change.

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

- No network calls during `script/bootstrap`, `script/test`, `script/lint`, `script/build`, or `script/server`.
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

1. Local project workflow: checksum-gated online Rust preparation with `script/prepare-rust` when needed, then offline Cargo validation through vendored sources. `script/bootstrap`, `script/test`, `script/lint`, `script/build`, and `script/server` enforce the offline phase.
2. GitHub-hosted validation: `lint`, `test`, `coverage`, PR `build`, and release build jobs run `script/validate-locks --ci`, then `script/prepare-rust`, then the normal offline scripts. Hosted runners are not air-gapped infrastructure because checkout, action loading, Rust preparation, and artifact services still use network access.
3. Egress-blocked build/package jobs: after checkout, action loading, and Rust preparation, native Linux x64 build/test/package scripts can run without third-party network access because application crates are committed. Retained cross-build-tool smoke jobs additionally install committed tool artifacts offline. Release publish/sign/verify jobs still need GitHub API access.

Do not describe GitHub-hosted runners as fully air-gapped. They can validate offline script behavior, but they are not an egress-blocked environment.

## Local Artifact Placement

Keep transient tool outputs close to the repo when reasonable.

- Outside CI, `script/env` defaults `RUNNER_TEMP` and `TMPDIR` to `target/tmp` when the caller has not already set them.
- Use ignored directories under `target/` for disposable Rust, Zig, Cargo, archive extraction, and prepared-tool build artifacts.
- Do not hard-code absolute machine-specific temp paths in scripts, docs, workflows, or examples.
- Do not commit generated temp files, extracted tool directories, build-script executables, or local cache contents.
- Preserve explicit caller or CI temp roots. GitHub Actions jobs should continue using the runner-provided environment where appropriate.
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
  - Rootless coverage intentionally excludes `src/nft_backend.rs`; that Linux privileged backend is proved through deterministic unit tests plus `script/test-privileged` namespace behavior tests on `ubuntu-24.04`.

- `script/test-privileged`
  - Linux x64-only privileged evidence entrypoint; it must not run on ordinary local or portable test paths.
  - Verifies `/usr/sbin/nft`, namespace, IPv6, and NFLOG-rule prerequisites before invoking ignored backend tests.
  - Runs native apply/verify/rollback behavior only inside disposable network namespaces and writes test-only evidence beneath `RUNNER_TEMP`.
  - Must not invoke the public `run` command, create a readiness file, mutate host firewall rules, or make a protection claim.

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
- The `build` workflow should exercise retained Zig/`cargo-zigbuild` artifacts in a distinct offline install/verify smoke job. That job is not a protected release artifact claim.
- Hosted lint/test workflows may remain portable on fixed Ubuntu and macOS labels while their behavior is platform-neutral. Protected integration, package, and release jobs target fixed `ubuntu-24.04` x64 only.
- Hosted lint/test/build workflows should run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/bootstrap`, then their offline validation command or native package-smoke path.
- Hosted coverage workflows should run `script/validate-locks --ci`, then `script/prepare-rust`, then `script/install-test-tools`, then `script/bootstrap`, then `script/test --coverage`.
- The `privileged-integration` workflow should run only on `ubuntu-24.04`, prepare the pinned Rust toolchain through repository scripts, and invoke `script/test-privileged` for namespace-isolated `network_enforcement_test_only` evidence.
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
- `src/nft_backend.rs` is an explicit Phase 2B exception: its privileged execution and kernel-state failure paths are validated by `privileged-integration`, while its deterministic normalization and boundary helpers retain ordinary unit tests.
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
