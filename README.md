# Fence 🛡️

[![lint](https://github.com/GrantBirki/fence/actions/workflows/lint.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/lint.yml)
[![test](https://github.com/GrantBirki/fence/actions/workflows/test.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/test.yml)
[![build](https://github.com/GrantBirki/fence/actions/workflows/build.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/build.yml)
[![acceptance](https://github.com/GrantBirki/fence/actions/workflows/acceptance.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/acceptance.yml)
[![action acceptance](https://github.com/GrantBirki/fence/actions/workflows/action-acceptance.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/action-acceptance.yml)
[![integration](https://github.com/GrantBirki/fence/actions/workflows/integration.yml/badge.svg)](https://github.com/GrantBirki/fence/actions/workflows/integration.yml)

A GitHub Action that locks down undeclared outbound network access and ordinary runner-privilege bypass paths on supported GitHub-hosted Linux runners.

## Quick Start ⚡

Add Fence before any untrusted workflow steps:

```yaml
- uses: GrantBirki/fence@eb175bb3c7d4b28007e01d2c26b93ea8df820e6f
```

The zero-input form selects strict `block` mode with an empty user `allowlist`.
Fence currently supports GitHub-hosted `ubuntu-24.04` x64 host jobs only.
The pinned Action currently carries the attested stable `0.1.2` agent. The
source `0.1.3` release candidate expands the default compatibility profile for
first-step workflow bootstrap and will reach the Action after its attested
release and bundle refresh.

Advanced callers may provide an explicit strict JSON configuration:

```yaml
- uses: GrantBirki/fence@eb175bb3c7d4b28007e01d2c26b93ea8df820e6f
  with:
    config: >-
      {"schema_version":1,"mode":"block","invocation_id":"example-run","allowlist":[]}
```

## Features 🌟

- 🔒 Applies and verifies a native Linux `nftables` outbound policy.
- 🧱 Disables ordinary passwordless sudo and Docker/containerd control paths in
  the default protected mode.
- 📡 Preserves narrowly bounded GitHub-hosted workflow-bootstrap and
  finalization traffic.
- 🔎 Keeps a resident root-owned agent running after readiness and reports
  critical policy drift.
- 📦 Bundles a checksum-validated, attested Linux x64 release binary without
  runtime agent downloads or remote policy fetches.
- 🧪 Provides explicit degraded and observation-only modes for workflows that
  need a narrower assurance claim.

## How It Works 🔧

1. The Action writes a bounded root-owned configuration and launches the
   bundled Fence agent as a transient `systemd` service.
2. The agent verifies the supported hosted-runner shape, installs the native
   network policy, and enables bounded DNS mediation for required GitHub
   workflow-bootstrap and finalization traffic.
3. Standard `block` mode disables ordinary passwordless sudo and
   Docker/containerd control paths before emitting readiness.
4. The agent remains resident, records bounded local evidence, and checks for
   policy drift. Fence never restores access after readiness.
5. The Action post hook renders a bounded summary and fails the job when
   critical resident findings are present.

## Modes 🎛️

| Mode | Behavior | Assurance |
| --- | --- | --- |
| `block` | Enforces the network policy, disables ordinary passwordless sudo, and disables Docker/containerd control paths. | Default protected posture. |
| `block` with `container_policy: "unsafe_preserve"` | Enforces the network policy and disables ordinary passwordless sudo while preserving container access. | Degraded: retained container control invalidates the ordinary containment claim. |
| `audit` | Applies non-blocking observation rules while preserving sudo, containers, and outbound traffic. | Observation only: no containment claim. |

## Security 🔒

Fence reduces arbitrary outbound egress and ordinary runner-privilege bypass
paths. It is not a complete sandbox and does not make GitHub-hosted runners
fully hermetic. The source `0.1.3` release candidate selects the
`github_hosted_workflow_bootstrap_v1` profile, which intentionally permits
bounded GitHub-owned bootstrap and finalization channels; later workflow code
can also use permitted channels for egress. The pinned Quick Start Action still
carries stable `0.1.2` and its narrower `github_hosted_job_status_v1` profile
until the attested bundle refresh lands. Kernel compromise, platform
compromise, and pre-start compromise remain outside the v0 boundary.

Fence is intentionally narrow: the supported protected target is a
GitHub-hosted `ubuntu-24.04` x64 host job. A separate `ubuntu-latest` canary is
observational only and does not expand the support claim. Pin Fence to a full
immutable commit SHA, as shown above.

## Hermetic Development ✈️

Fence follows the airplane-test model described in
[Hermetic Builds](https://software.birki.io/posts/hermetic-builds/). Rust
toolchains and dependencies are prepared deliberately; routine project work
then operates from pinned, vendored inputs without network access.

```console
script/prepare-rust
script/bootstrap
script/test
script/lint
script/build
```

`script/prepare-rust` is intentionally online and checksum-gated. The remaining
commands use the repository's offline Cargo defaults after preparation.

## CLI 🧰

The bundled Rust agent exposes a narrow JSON-only interface:

```console
fence --version
fence check-support
fence render-plan --config policy.json
fence run --config /run/fence/example/config.json
```

The root Action is the supported public launcher. Direct `run` execution is
rejected unless the trusted transient-service contract is satisfied.

## Further Reading 📚

- [Fence v0 security contract](docs/v0.md)
- [Security policy](SECURITY.md)
- [Security review](docs/security-review.md)
- [Repository settings](docs/repository-settings.md)
- [Hermetic Builds](https://software.birki.io/posts/hermetic-builds/)

## License ⚖️

Fence is released under the [MIT License](LICENSE).
