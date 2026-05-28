# Fence

[![lint](https://github.com/GrantBirki/fence/actions/workflows/lint.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/lint.yml)
[![test](https://github.com/GrantBirki/fence/actions/workflows/test.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/test.yml)
[![build](https://github.com/GrantBirki/fence/actions/workflows/build.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/build.yml)
[![acceptance](https://github.com/GrantBirki/fence/actions/workflows/acceptance.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/acceptance.yml)
[![integration](https://github.com/GrantBirki/fence/actions/workflows/integration.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/integration.yml)

Fence is an early-stage, source-auditable Rust project for hardening supported
CI runners against undeclared outbound network access and ordinary
runner-privilege bypass paths. The intended first enforcement target is a
GitHub-hosted `ubuntu-24.04` x64 runner executing a native Linux GNU binary.

Fence is not an enforcement agent yet. The current Phase 3 non-enforcing executable builds
on the Phase 2 network-evidence backend: it strictly validates local JSON
policy, renders a frozen policy and deterministic native `nftables` ruleset
preview, and reports an accepted but not runtime-checked hosted-runner
fingerprint reference needed before the privileged lifecycle can be activated.
It never applies a network boundary, changes privilege state, writes
readiness, or reports protection as available.

The hosted `integration` workflow additionally exercises native apply, verification, rollback,
forwarded-path behavior, and bounded NFLOG connection findings in disposable
privileged test namespaces on `ubuntu-24.04`. The event path immediately
reduces a bounded packet prefix to approved endpoint metadata and never writes
raw packet bytes to evidence. This is test-only proof, not a usable protection
mode. Phase 3B extends that proof with a transient `systemd` service,
root-owned test runtime state, test-only readiness, five-second resident
verification, critical drift reporting, and pre-ready rollback. Phase 3C adds
separate disposable-runner evidence for measured sudo and Docker/containerd
lockdown, rollback, degraded container preservation, and audit preservation.
Phase 4A begins controlled compatibility measurement by applying only
non-blocking host audit rules on an ephemeral runner, exercising GitHub
metadata and artifact paths, and emitting bounded endpoint evidence before
runner teardown. A follow-up composed evidence service applies block rules
only inside a disposable network namespace while disabling the measured host
sudo/container paths in one transient service. Neither path emits protection
readiness, applies blocking policy to the host network, or selects an implicit
platform profile from observed addresses. Separate disposable-host
finalization experiments applied the same controls with zero allowances and
with only GitHub's documented log/summary receiver permitted; each completed
local assertions but failed to yield a terminal successful hosted job while
the controls remained resident. Phase 4B adds an explicit, non-default
`github_hosted_job_status_v1` candidate containing only
`pipelines.actions.githubusercontent.com:443` and
`results-receiver.actions.githubusercontent.com:443`. A separate
non-required workflow applies that fixed candidate on disposable hosts; six
terminal successful jobs are required before it may be considered for
default selection. No built-in default platform profile is selected.

Pull requests also build a Linux x64 package independently and execute that
artifact through the non-enforcing JSON CLI contract. The `integration`
workflow additionally records a bounded, read-only hosted-runner fingerprint
observation before its namespace and resident-service evidence tests. These
checks do not establish public protection or create a GitHub Action interface.

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
- Linux-only, exact-pinned MIT netlink crates used solely by privileged NFLOG
  evidence tests, plus exact-pinned `libc` constants used for no-follow
  lifecycle-evidence file opens without first-party unsafe code;
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
artifact's public non-enforcing contract separately from
`script/observe-hosted-runner` and the privileged namespace evidence workflow.
The `integration` workflow may intentionally exercise GitHub-hosted metadata
and artifact services while `script/measure-platform-egress` keeps a
non-blocking test-only audit service resident; that measurement is online
evidence, not part of the offline developer script contract.
It separately runs `script/test-composed`, whose block-mode network rules are
confined to a disposable namespace while the associated host lockdown remains
test-only evidence on an ephemeral runner.
The separate `platform profile candidate` workflow may run
`script/test-profile-candidate` on disposable hosts with the explicit
two-endpoint candidate. It is destructive, test-only compatibility evidence
and deliberately does not participate in the required `integration` result
until the candidate proves terminal completion.

## Phase 4B Evidence Boundary

The current binary emits versioned JSON only. `render-plan` includes the fixed
`inet fence_v0` ruleset preview, policy hash schema version `2`, and a ruleset
hash. `check-support` reports a versioned hosted-runner fingerprint gate as
an accepted reference that is not yet checked or enforced by public execution.
`run` fails closed until the privileged lifecycle is implemented and proved.

```console
script/build
./target/release/fence --version
./target/release/fence check-support
./target/release/fence render-plan --config policy.json
./target/release/fence run --config /run/fence/example/config.json
```

The last command intentionally returns an `enforcement_not_implemented` error
through the Phase 4B evidence-only slices. Privileged hosted tests may emit
explicitly test-only resident, lockdown, or composed evidence. Resident
network measurement and composed namespace-network evidence may emit
non-protecting test readiness; public CLI execution cannot. The composed
evidence does not protect the workflow host network and cannot be used as a
runner security control. Phase 4A host-block finalization experiments are
recorded as negative evidence: strict zero-egress and a candidate permitting
only the documented log/summary receiver both stranded hosted job completion.
Phase 4B permits an explicitly selected static job-status candidate in
`render-plan` and test-only host-block evidence:

```json
{
  "platform_profile": "github_hosted_job_status_v1"
}
```

That candidate permits only the fixed GitHub-owned pipelines and results
receiver HTTPS hostnames after they are resolved and frozen before mutation.
It is not the omitted-field default, does not cover cache, artifact,
repository API, action-download, or storage traffic, and exposes an egress
channel that later workflow code could use. It does not activate the public
agent or justify a default profile unless repeated terminal hosted completion
proof passes.

A public GitHub Action wrapper is deferred until a later protected lifecycle
can truthfully establish readiness and an attested alpha agent has been
published. That future wrapper is intended to live in this repository and
carry the reviewed Linux release binary in an immutable action reference; the
current project does not publish an `action.yml` interface or download an
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
