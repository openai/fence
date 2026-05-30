# Fence

[![lint](https://github.com/GrantBirki/fence/actions/workflows/lint.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/lint.yml)
[![test](https://github.com/GrantBirki/fence/actions/workflows/test.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/test.yml)
[![build](https://github.com/GrantBirki/fence/actions/workflows/build.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/build.yml)
[![acceptance](https://github.com/GrantBirki/fence/actions/workflows/acceptance.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/acceptance.yml)
[![action acceptance](https://github.com/GrantBirki/fence/actions/workflows/action-acceptance.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/action-acceptance.yml)
[![integration](https://github.com/GrantBirki/fence/actions/workflows/integration.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/integration.yml)

Fence is a source-auditable Rust project for hardening supported CI runners
against undeclared outbound network access and ordinary runner-privilege
bypass paths. The v0 enforcement target is a GitHub-hosted `ubuntu-24.04` x64
runner executing a native Linux GNU binary.

Fence is stabilizing its first v0 Linux x64 release. The current v0
executable strictly validates local JSON policy, renders a frozen policy and
deterministic native `nftables` ruleset preview, and models the selected
bounded DNS-mediated hosted job-status compatibility descriptor. On supported
GitHub-hosted `ubuntu-24.04` x64 runners, the Linux binary can now enter a
protected block lifecycle only when invoked as root inside its matching trusted transient
`systemd` service with a root-owned configuration. Standard block verifies
the pinned runner shape, applies and verifies host network policy, disables
measured passwordless sudo and container control paths, writes production
readiness, and remains resident without restoring access. Explicit
`unsafe_preserve` keeps the same network and sudo controls while preserving
Docker/containerd access and reporting degraded assurance without an
ordinary containment claim. Audit installs owned non-blocking observation
rules and local DNS mediation while preserving passwordless sudo,
Docker/containerd access, and arbitrary outbound traffic. It reports
observation-only readiness and never claims containment. Ordinary direct
execution is rejected before configuration intake.

The bundled root Action is also exercised on disposable hosted runners. Its
acceptance gate proves standard, degraded, and audit activation through
`uses: ./`, setup rejection before mutation, and post-ready drift propagation:
critical resident findings fail the post hook without stopping the service or
restoring access.

The hosted `integration` workflow exercises native apply, verification,
rollback, forwarded-path behavior, bounded NFLOG metadata, read-only hosted
runner fingerprint observation, disposable lockdown scenarios, one
selected-profile runtime finalization scenario, and packaged
production-shaped standard block, degraded block, and audit services on
`ubuntu-24.04`. The event path immediately reduces a bounded packet prefix to
approved endpoint metadata and never writes raw packet bytes to evidence.

Compatibility research converged on the versioned
`github_hosted_job_status_v1` descriptor. It routes host and Docker DNS through
a root-resident mediator, forwards canonical `A` and `AAAA` questions to the
platform resolver, refreshes four exact bootstrap roots, accepts one exact
GitHub app receiver compatibility name, permits at most eight previously unseen
`*.actions.githubusercontent.com` names with at most two prefix labels, derives
at most bounded TTL-limited CNAME authorizations, and materializes only TCP
`443` address rules. Six disposable-host replicas across two executions
reached terminal success, and required integration now checks the selected
runtime path on every change. The permitted DNS timing/count, bounded query
label, CNAME delegation, HTTPS destination, and address-plus-port channels are
explicitly disclosed egress limitations.

Omitting `platform_profile` selects `github_hosted_job_status_v1`; explicitly
supplying that same identifier is equivalent. Fence v0 rejects every other
profile value before mutation. Post-ready action downloads, cache traffic,
artifact storage, and repository API traffic are not included in the default
compatibility boundary.

Pull requests also build a Linux x64 package independently and execute that
artifact through the trusted-launcher JSON CLI boundary. The current
`0.1.0-alpha.2` publication remains limited to the Linux x64 agent artifact,
and the root Action bundles that attested binary without runtime downloads.

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
- a Linux-only, exact-pinned MIT `netlink-sys` socket boundary, a narrow
  first-party safe NFLOG request serializer, and exact-pinned `libc` constants
  used for no-follow lifecycle-evidence file opens without first-party unsafe
  code;
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
artifact's public trusted-launcher boundary separately from
`script/observe-hosted-runner` and the privileged namespace evidence workflow.
The `integration` workflow also runs one disposable-host
`script/test-selected-profile-runtime` scenario through the required aggregate
after six terminal-success proofs. That worker plans the selected
`github_hosted_job_status_v1` descriptor by omission, applies bounded
DNS-mediated host blocking and measured sudo/container lockdown, and retains
only test-only readiness and reports below a non-production runtime root.

## v0 Evidence Boundary

The current binary emits versioned JSON only. `render-plan` includes the fixed
`inet fence_v0` base-ruleset preview, policy hash schema version `3`, a ruleset
hash, and the selected bounded DNS-mediated hosted job-status descriptor.
`check-support` reports a versioned hosted-runner fingerprint gate as an
accepted reference that is checked during activation rather than by the
read-only support probe. `run` rejects ordinary direct execution and accepts
only the supported production-shaped standard block, explicit degraded block,
or audit observation transient service.

```console
script/build
./target/release/fence --version
./target/release/fence check-support
./target/release/fence render-plan --config policy.json
./target/release/fence run --config /run/fence/example/config.json
```

The last command succeeds only when a trusted launcher has already created
the pinned root-owned configuration and invoked the binary as the root
`MainPID` of `fence-<invocation-id>.service`. Ordinary direct invocation
returns `trusted_launcher_required` without reading configuration. Privileged
hosted tests may still emit explicitly test-only resident, lockdown, or
selected-profile runtime evidence. The selected DNS-mediated reduction
constrains dynamic
`*.actions.githubusercontent.com` authorization to eight unique lifetime
names with no more than two prefix labels, canonicalizes block-mode upstream
`A`/`AAAA` questions, and retains bounded TTL-derived CNAME descendants. Six
disposable-host replicas across two executions reached terminal success. The
required `integration` aggregate now exercises one copy of this test-only
selected-profile runtime evidence. Its DNS timing/count channel, bounded
query-label channel, approved HTTPS destinations, CNAME delegation, and
address-plus-port realization remain disclosed limitations. This evidence
preceded activation of the standard production path.

The trusted-launcher paths now make that boundary reachable from the
Linux CLI under a narrowly validated service context. Production
runtime intake accepts only a root-owned `/run/fence/<invocation-id>/config.json`
file as the only initial invocation-directory entry beneath pinned root-owned
directories, opens it with no-follow and close-on-exec protections, and
derives the fixed state/report/readiness paths.
The matching service validator accepts only a root process running as the
`MainPID` of `fence-<invocation-id>.service`. The activated lifecycle accepts
standard block with disabled container access or explicit degraded
`unsafe_preserve` with preserved container access, always with the selected
`github_hosted_job_status_v1` descriptor. Audit accepts the same selected
descriptor, applies only non-blocking observation rules, routes host and
Docker DNS through the local root-resident mediator, and preserves sudo and
container access. Every unsupported `platform_profile` value is rejected before
mutation.

Production `state.json`, `ready.json`, and `report.json` documents carry
`runtime_evidence_schema_version: 1`, the logical
`github_hosted_job_status_v1` profile identifier, and the stable
`github_hosted_job_status_dns_mediation_v1` realization identifier.

The root `action.yml` wrapper carries an exact, checksum-validated copy of an
attested Linux release binary. Its schema-`2` manifest distinguishes immutable
prerelease and stable release channels. The wrapper accepts one inline
strict-JSON configuration, writes the untouched bytes into the pinned
root-owned runtime path, launches the trusted transient service, waits for
agent readiness, and renders bounded local evidence from its post hook. It
does not download an agent, fetch policy, stop the resident service, or restore
access at workflow runtime. External consumers should pin Fence to a full
immutable commit SHA rather than a floating branch:

```yaml
- uses: GrantBirki/fence@<full-commit-sha>
  with:
    config: >-
      {"schema_version":1,"mode":"block","invocation_id":"example-run","allowances":[]}
```

## Release Baseline

The initial package version was `0.0.0`. Importing that initial `Cargo.toml`
to `main` established a baseline without publishing a release. The current
`0.1.0-alpha.2` release is the first usable Linux x64 alpha publication. The
next publication sequence is a final `0.1.0-alpha.3` prerelease soak followed
by stable `0.1.0`. Future deliberate version bumps merged to `main` remain
release triggers.

The supported agent artifact remains limited to `x86_64-unknown-linux-gnu`
and must be proved on GitHub-hosted `ubuntu-24.04` x64 before release. Its
narrow CLI package contains the binary and provenance/checksum assets, not
generated shell completion or man-page artifacts. Portable validation and
retained cross-build tooling may continue to run on other prepared hosts, but
do not establish protected platform support. Publication, artifact
attestations, and verification remain GitHub-networked operations by design.

## Post-v0 Hardening

Stable v0 does not end supply-chain hardening work. Follow-up releases should
add a checksum-bound release SBOM, evaluate `cargo-vet`, evaluate auditable or
reproducible binary comparison, and review whether the bounded Actions-suffix
profile can be narrowed further without stranding hosted job completion.

## Security

See [SECURITY.md](SECURITY.md) for reporting and verification policy and
[docs/repository-settings.md](docs/repository-settings.md) for repository
controls that must be configured in GitHub.
