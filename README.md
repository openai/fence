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

Fence is still unreleased. The current Phase 4 executable strictly validates
local JSON policy, renders a frozen policy and deterministic native
`nftables` ruleset preview, and models the selected bounded DNS-mediated
hosted job-status compatibility descriptor. On supported GitHub-hosted
`ubuntu-24.04` x64 runners, the Linux binary can now enter one protected
standard-block lifecycle only when invoked as root inside its matching
trusted transient `systemd` service with a root-owned configuration. That
path verifies the pinned runner shape, applies and verifies host network
policy, disables measured passwordless sudo and container control paths,
writes production readiness, and remains resident without restoring access.
Ordinary direct execution is rejected before configuration intake.

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
the controls remained resident. A Phase 4B experiment then permitted exactly
the GitHub-owned pipelines and results-receiver HTTPS endpoints in three
independent hosted jobs. All three completed their visible local steps but
remained non-terminal past the configured five-minute observation limit, so
that candidate was rejected as insufficient. A subsequent experiment allowing
fixed GitHub service/results-storage hosts and measured hosted-runner
platform DNS/host-control traffic also finished local completion steps without
yielding a terminal job result. An intentionally open diagnostic baseline,
`github_hosted_https_baseline_candidate_v1`, then permitted arbitrary outbound
TCP `443` plus those measured platform channels and reached terminal success
in three independent disposable-host jobs. A follow-up HTTPS-only reduction
stranded one of three jobs after visible completion. A reduced non-required
experiment using explicit
`github_hosted_https_udp_dns_candidate_v1`: arbitrary outbound TCP `443` plus
UDP DNS to the measured platform resolver, with TCP DNS and host-control
allowances removed, then reached terminal success in three independent
disposable-host jobs. It is not a candidate final allowlist: general HTTPS
and DNS are usable by later workflow code for egress and still must be
replaced with a constrained design before any default profile decision. It
remains test-only and non-default.
A separate, non-required DNS-mediated audit experiment routes host and Docker
resolver traffic through a local test-only mediator and records only bounded
GitHub-related queried hostnames. For those retained names only, it records
bounded canonical answer addresses and the minimum observed DNS TTL to support
later correlation and refresh design; it does not use those answers to add
firewall authorization. It classifies observations against a fixed GitHub
compatibility hypothesis consisting of
`*.actions.githubusercontent.com`, `codeload.github.com`,
`actions-results-receiver-production.githubapp.com`, and
`productionresultssa*.blob.core.windows.net`. That hypothesis is not an
accepted `platform_profile`, does not change the default policy, and must be
proved by a later blocking terminal-completion experiment before it can
support any protection claim. The experiment sends only a fixed non-GitHub
DNS probe to prove host and Docker-address forwarding; that name is counted
but not retained as platform evidence.

A non-required DNS-mediated host-block experiment then pre-resolved approved
job-status names through the local mediator, permitted upstream UDP DNS only
from that root-resident mediator, materialized bounded TCP `443` address
grants with DNS TTL expiry, and retained verified sudo and container lockdown
until teardown. Its broad suffix-matched authorization reached terminal
success on three disposable hosted runners, but remained unsuitable as a
default because later code could encode data in permitted DNS query labels.
A first exact-name reduction that forwarded and materialized only
`pipelines.actions.githubusercontent.com` and
`results-receiver.actions.githubusercontent.com` completed its visible
steps but did not publish terminal job conclusions. GitHub's public runner
checks also identify `vstoken.actions.githubusercontent.com` as a required
Actions service endpoint. Adding that third name still left hosted jobs
non-terminal. A bounded late report consistently observed the stable
`payload.pipelines.actions.githubusercontent.com` service name and a generated
`glb-...github.com` DNS alias. Public DNS inspection also shows that the
pipeline roots delegate through bounded Microsoft edge aliases. Authorizing
four exact root names plus bounded TTL-derived CNAME descendants and retaining
their HTTPS rules for DNS TTL plus a fixed thirty-second refresh overlap still
left three hosted jobs non-terminal after their visible completion steps.
The compatibility-first diagnostic therefore forwarded the four
GitHub-related DNS classes already modeled by the audit experiment, refreshed
the four bootstrap roots every five seconds, and continued to materialize
only TTL-bounded TCP `443` address rules. All three hosted jobs reached
terminal success. Removing `codeload.github.com` because v0 does not support
post-ready action downloads also reached terminal success in three hosted
jobs. Removing the results-storage wildcard because v0 does not support
post-ready artifact or cache storage traffic also reached terminal success in
three hosted jobs. A further reduction replaced the remaining Actions DNS
wildcard with the four measured bootstrap roots while retaining the exact
GitHub app receiver compatibility name and bounded TTL-derived CNAME
descendants, but all three hosted jobs again completed visible steps without
publishing terminal conclusions. The retained no-storage candidate therefore
still includes the Actions wildcard. This remains *test-only*: it neither
selects a default `platform_profile` nor activates public protection, and the
wildcard query-label channel is a disclosed egress limitation. The current
follow-up replaces that unrestricted wildcard with a constrained suffix
experiment: exact bootstrap roots remain explicit, previously unseen
`*.actions.githubusercontent.com` names are limited to eight unique names for
the candidate lifetime and at most two labels before the suffix, only `A` and
`AAAA` questions are forwarded in block mode, outbound questions are rebuilt
into a canonical lowercase form before upstream forwarding, and bounded
TTL-derived CNAME descendants remain available. This test-only design still
has disclosed DNS query timing and count channels, but bounds caller-controlled
query content while testing whether GitHub-hosted job finalization remains
compatible. A following
workflow step emits a capped sanitized DNS summary so late DNS and network
findings can be reviewed without changing policy. Its reported limitations
also state that the approved DNS and HTTPS channels remain usable for egress
and that resolved address grants may represent colocated services. Six
disposable-host replicas across two executions reached terminal success. One
selected-profile runtime scenario now runs behind the stable required
`integration` aggregate so future compatibility regressions fail closed. It
plans `github_hosted_job_status_v1` by omission, reports the schema-`3` logical
policy hash separately from the active TTL-derived ruleset hash, and still
emits only test-only readiness below a non-production runtime root. This
established the evidence gate used by the trusted-launcher activation. The
production standard-block path now applies the same reviewed mechanism.
Explicit `"none"` remains available for strict no-implicit-egress planning
but is not accepted by the production activation slice.

Pull requests also build a Linux x64 package independently and execute that
artifact through the trusted-launcher JSON CLI boundary. The `integration`
workflow additionally records a bounded, read-only hosted-runner fingerprint
observation before its namespace and resident-service evidence tests, and
runs a packaged production-shaped standard-block transient service on a
disposable runner. This does not publish an alpha release or create a GitHub
Action interface.

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
artifact's public trusted-launcher boundary separately from
`script/observe-hosted-runner` and the privileged namespace evidence workflow.
The `integration` workflow may intentionally exercise GitHub-hosted metadata
and artifact services while `script/measure-platform-egress` keeps a
non-blocking test-only audit service resident; that measurement is online
evidence, not part of the offline developer script contract.
It separately runs `script/test-composed`, whose block-mode network rules are
confined to a disposable namespace while the associated host lockdown remains
test-only evidence on an ephemeral runner.
It also runs one disposable-host `script/test-dns-block-candidate` scenario
through the required aggregate after six non-required terminal-success proofs.
Despite the historical script name, that worker plans the selected
`github_hosted_job_status_v1` descriptor by omission, applies bounded
DNS-mediated host blocking and measured sudo/container lockdown, and retains
only test-only readiness and reports below a non-production runtime root.

## Phase 4 Evidence Boundary

The current binary emits versioned JSON only. `render-plan` includes the fixed
`inet fence_v0` base-ruleset preview, policy hash schema version `3`, a ruleset
hash, and the selected bounded DNS-mediated hosted job-status descriptor.
`check-support` reports a versioned hosted-runner fingerprint gate as an
accepted reference that is checked during activation rather than by the
read-only support probe. `run` rejects ordinary direct execution and accepts
only the supported production-shaped standard-block transient service.

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
composed evidence. Resident network measurement and composed
namespace-network evidence may emit non-protecting test readiness. The composed
evidence does not protect the workflow host network and cannot be used as a
runner security control. Phase 4A host-block finalization experiments are
recorded as negative evidence: strict zero-egress and a candidate permitting
only the documented log/summary receiver both stranded hosted job completion.
Phase 4B also rejected a static candidate permitting only
`pipelines.actions.githubusercontent.com:443` and
`results-receiver.actions.githubusercontent.com:443`: three independent jobs
completed visible local assertions and remained non-terminal past the
five-minute observation limit while controls were resident. These negative
results do not activate the public agent or justify a default platform
profile. A follow-up fixed-host candidate with measured hosted-runner
platform DNS/host-control channels also failed to become terminal. The
explicit `github_hosted_https_baseline_candidate_v1` diagnostic baseline
subsequently reached terminal success in three disposable-host jobs by
permitting arbitrary outbound TCP `443` and the measured platform channels.
An HTTPS-only reduction then left one of three replicas non-terminal past the
observation limit. The narrower passing non-required candidate may be
selected explicitly as `github_hosted_https_udp_dns_candidate_v1`; it adds
back only UDP DNS to the measured platform resolver while retaining arbitrary
outbound TCP `443` and excluding TCP DNS and host-control paths. Its three
replicas reached terminal success, but general HTTPS and DNS remain broad
disclosed egress channels. It is neither a public enforcement interface nor a
default profile.

The later DNS-mediated reduction now constrains dynamic
`*.actions.githubusercontent.com` authorization to eight unique lifetime
names with no more than two prefix labels, canonicalizes block-mode upstream
`A`/`AAAA` questions, and retains bounded TTL-derived CNAME descendants. Six
disposable-host replicas across two executions reached terminal success. The
required `integration` aggregate now exercises one copy of this test-only
selected-profile runtime evidence. Its DNS timing/count channel, bounded
query-label channel, approved HTTPS destinations, CNAME delegation, and
address-plus-port realization remain disclosed limitations. This evidence
preceded activation of the standard production path. Explicit `"none"`
remains the strict planning override but is not accepted for production
activation in this slice.

The trusted-launcher standard-block path now makes that boundary reachable
from the Linux CLI under a narrowly validated service context. Production
runtime intake accepts only a root-owned `/run/fence/<invocation-id>/config.json`
file as the only initial invocation-directory entry beneath pinned root-owned
directories, opens it with no-follow and close-on-exec protections, and
derives the fixed state/report/readiness paths.
The matching service validator accepts only a root process running as the
`MainPID` of `fence-<invocation-id>.service`. The activated lifecycle accepts
only standard block with disabled container access and the selected
`github_hosted_job_status_v1` descriptor. Production audit, degraded
`unsafe_preserve`, and strict `"none"` activation remain deferred.

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
