# Local Development

Fence follows the airplane-test model described in [Hermetic Builds](https://software.birki.io/posts/hermetic-builds/): prepare toolchains deliberately, then build, test, lint, and package from pinned vendored inputs without network access.

## Prepare And Validate

```console
script/prepare-rust
script/bootstrap
script/test
script/lint
script/build
```

`script/prepare-rust` is the explicit online Rust preparation path. It validates the checked-in distribution lock, downloads only the selected manifest, host components, and requested target libraries, verifies every SHA-256, and lets rustup install only from a temporary loopback mirror. Caller-provided Rust distribution and update sources are ignored, and rustup self-update is disabled.

The routine project scripts are offline:

- `script/bootstrap` validates the pinned toolchain and vendored crates, then runs a frozen Cargo check.
- `script/test` runs the offline regression suite and frozen Rust tests.
- `script/lint` runs the repository's pinned formatting, lint, and policy checks.
- `script/build` creates the supported build outputs from vendored inputs.
- `script/server` runs the local project entrypoint without adding network behavior.

Use `script/update`, `script/vendor-rust`, and the focused `script/vendor-*-tools` entrypoints only when intentionally refreshing dependencies or retained tools. Those are explicit online maintenance boundaries, not part of the normal offline workflow.

## Action Bundle Assembly

`script/assemble-action-bundle` is the offline-only path for constructing a production-shaped Action tree from an explicit artifact, version, source SHA, and output root. It verifies those inputs and writes only below the requested output root; it does not fetch a release, agent, attestation, or policy.

Pull-request and ordinary `main` validation use this path to test an ephemeral candidate. Generated `action/bin/fence` and `action/bundle-manifest.json` files do not land on `main`; release automation adds them only to the signed distribution commit.

## Local Artifacts

Outside CI, `script/env` defaults `RUNNER_TEMP` and `TMPDIR` to ignored paths below `target/tmp` when the caller has not supplied them. Keep disposable Rust, Cargo, Zig, archive-extraction, and prepared-tool output inside the repository's ignored `target/` tree when practical.

Do not run the destructive hosted-runner evidence scripts on a developer machine or reusable runner. The script contracts in [AGENTS.md](../AGENTS.md) identify the entrypoints restricted to disposable GitHub-hosted jobs.

For exact build, test, coverage, release, and hermeticity requirements, see the [Fence v0 specification](v0.md#hermetic-repository-contract).
