# Local Development 🛠️

Fence keeps its Rust dependencies in the repository, so normal development commands run offline after you prepare the toolchain.

## Get Started

```console
script/prepare-rust
script/bootstrap
script/test
script/lint
script/build
```

`script/prepare-rust` is the only normal setup step that needs the network. It downloads the pinned Rust toolchain and verifies its checksums before installing it.

Once the toolchain is ready, `script/bootstrap`, `script/test`, `script/lint`, and `script/build` run offline using the checked-in dependencies and toolchain locks.

`script/test` includes offline tests for the hosted blocked-event check. That check allows a bounded wait for all test events so DNS refreshes and security checks can finish between batches. Missing events still fail the check; enforcement and the protected-finalization deadline are unchanged.

## Update Dependencies

These update scripts need network access:

- `script/update` updates Rust dependencies.
- `script/vendor-rust` updates the pinned Rust toolchain.
- `script/vendor-update-tools` updates dependency-audit tools.
- `script/vendor-release-tools` updates retained release tools.
- `script/vendor-test-tools` updates retained test tools.

Builds and tests must not install or download tools.

## Build The GitHub Action

`script/assemble-action-bundle` builds an Action bundle from an existing agent artifact. It does not download an agent or policy.

The `main` branch does not contain generated Action binaries. Release automation adds the agent and its manifest to a separate signed distribution commit.

## Temporary Files

Local builds and tool preparation use `target/tmp` unless `TMPDIR` or `RUNNER_TEMP` is already set.

> [!WARNING]
> Do not run hosted-runner or lockdown tests on your computer or a reusable runner. They change host settings and are intended for disposable GitHub-hosted runners.

For the complete build and test contracts, see [AGENTS.md](../AGENTS.md) and the [v0 specification](v0.md#hermetic-repository-contract).
