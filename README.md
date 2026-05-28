# Fence

[![lint](https://github.com/GrantBirki/fence/actions/workflows/lint.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/lint.yml)
[![test](https://github.com/GrantBirki/fence/actions/workflows/test.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/test.yml)
[![build](https://github.com/GrantBirki/fence/actions/workflows/build.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/build.yml)
[![acceptance](https://github.com/GrantBirki/fence/actions/workflows/acceptance.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/acceptance.yml)
[![privileged-integration](https://github.com/GrantBirki/fence/actions/workflows/privileged-integration.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/privileged-integration.yml)

Fence is an early-stage, source-auditable Rust project for hardening supported
CI runners against undeclared outbound network access and ordinary
runner-privilege bypass paths. The intended first enforcement target is a
GitHub-hosted `ubuntu-24.04` x64 runner executing a native Linux GNU binary.

Fence is not an enforcement agent yet. The current Phase 2C executable strictly
validates local JSON policy, renders a frozen policy and deterministic native
`nftables` ruleset preview, and reports read-only host support observations. It
never applies a network boundary, changes privilege state, writes readiness, or
reports protection as available.

Phase 2C additionally exercises native apply, verification, rollback,
forwarded-path behavior, and bounded NFLOG connection findings in disposable
privileged test namespaces on `ubuntu-24.04`. The event path immediately
reduces a bounded packet prefix to approved endpoint metadata and never writes
raw packet bytes to evidence. This is test-only proof, not a usable protection
mode.

Pull requests also build a Linux x64 package independently and execute that
artifact through the Phase 2 JSON CLI contract. This proves the distributed
binary remains non-enforcing and fail-closed; it is not a public GitHub Action
or a protection claim.

Read [docs/v0.md](docs/v0.md) for the normative v0 security boundary,
interfaces, proof requirements, and implementation roadmap.

## Design Direction

Fence is intended to:

- run before untrusted later workflow steps on a supported hosted Linux runner;
- enforce a verified native `nftables` outbound network policy in protected
  `block` mode;
- provide a local-only `audit` observation mode that makes no containment
  claim;
- remove default passwordless-sudo and container escape paths in the standard
  protected `block` configuration;
- produce bounded local evidence rather than uploading telemetry; and
- remain source-owned, reproducible, and inspectable without a remote control
  plane or runtime agent downloads.

Fence must not be described as a complete sandbox. Allowed endpoints and any
explicit lower-assurance container-preserving configuration remain possible
exfiltration or bypass paths, and kernel, platform, or pre-start compromise is
outside the initial boundary.

## Hermetic Build Model

This repository follows the "airplane test" model described in
[Hermetic Builds](https://software.birki.io/posts/hermetic-builds/):
dependencies and required tooling are prepared deliberately, while routine
Cargo validation operates from committed inputs without network access.

The normal local flow is:

```console
script/prepare-rust
script/bootstrap
script/test
script/lint
script/build
script/server
```

`script/prepare-rust` is intentionally online and checksum-gated. Once the
pinned Rust toolchain exists locally, `script/bootstrap`, `script/test`,
`script/lint`, `script/build`, and `script/server` run with offline Cargo
defaults and vendored crates from `vendor/cache`.

Outside CI, scratch output defaults to ignored paths below `target/tmp` unless
the caller provides `TMPDIR` or `RUNNER_TEMP`.

## Prepared Inputs

The bootstrap imports these explicit supply-chain inputs:

- `Cargo.lock` plus vendored application crates in `vendor/cache`;
- Linux-only, exact-pinned MIT netlink crates used solely by Phase 2C
  privileged NFLOG evidence tests;
- a checksum lock for the Rust distribution in
  `.cargo/tooling/rust-toolchain.lock.toml`;
- committed Zig and `cargo-zigbuild` artifacts in `vendor/release-tools`,
  retained as prepared tooling for future cross-platform investigation rather
  than evidence of a supported protected target;
- committed `cargo-llvm-cov` artifacts in `vendor/test-tools`; and
- SHA-pinned GitHub Actions in `.github/workflows`.

Online refresh operations are intentionally separate from routine work:

```console
script/update
script/vendor-rust
script/vendor-update-tools
script/vendor-release-tools
script/vendor-test-tools
```

Each refresh operation changes a reviewed lock or vendored artifact surface.
Do not manually curate generated third-party vendored contents.

## Validation

The local project checks are:

```console
script/bootstrap
script/test
script/lint
script/build
```

Coverage additionally uses the committed test-tool artifact:

```console
script/install-test-tools
script/test --coverage
```

`script/test --coverage` enforces 100 percent line, function, and region
coverage for current first-party Rust code. It intentionally does not enable
unstable branch coverage.

CI additionally runs `script/validate-locks --ci` and
`script/prepare-rust` before entering the offline script surface. Hosted
runners are not fully air-gapped: checkout, action loading, Rust preparation,
artifact operations, and release publication still require network access.
On `ubuntu-24.04`, `script/test-package-smoke` verifies the built Linux
artifact's public non-enforcing contract separately from the privileged
namespace evidence workflow.

## Phase 2 CLI

The current binary emits versioned JSON only. `render-plan` includes the fixed
`inet fence_v0` ruleset preview, policy hash schema version `2`, and a ruleset
hash. `run` fails closed until the privileged lifecycle is implemented.

```console
script/build
./target/release/fence --version
./target/release/fence check-support
./target/release/fence render-plan --config policy.json
./target/release/fence run --config /run/fence/example/config.json
```

The last command intentionally returns an `enforcement_not_implemented` error
through Phase 2. Do not use this planner or its ruleset preview as a runner
security control.

A public GitHub Action wrapper is deferred until a later protected lifecycle
can truthfully establish readiness. That future wrapper is intended to live
in this repository and carry a reviewed Linux binary in an immutable action
reference; Phase 2 does not publish an `action.yml` interface or download an
agent at workflow runtime.

## Release Baseline

The initial package version is `0.0.0`. Importing the initial `Cargo.toml` to
`main` establishes a baseline and does not publish a release. After the
security boundary and supported behavior are implemented and reviewed, a
deliberate version bump merged to `main` is the release trigger.

The first publishable agent artifact is limited to
`x86_64-unknown-linux-gnu` and must be proved on GitHub-hosted
`ubuntu-24.04` x64 before release. Its narrow CLI package contains the binary
and provenance/checksum assets, not generated shell completion or man-page
artifacts. Portable validation and retained cross-build tooling may continue
to run on other prepared hosts, but do not establish protected platform
support. Publication, artifact attestations, and verification remain
GitHub-networked operations by design.

## Security

See [SECURITY.md](SECURITY.md) for reporting and verification policy and
[docs/repository-settings.md](docs/repository-settings.md) for repository
controls that must be configured in GitHub.
