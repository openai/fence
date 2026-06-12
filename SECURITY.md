# Security Policy

## Supported Versions

Fence publishes a stable v0 release. Security fixes are applied to the
latest `main` branch and the latest published stable release. The implemented
protection boundary is intentionally limited to GitHub-hosted `ubuntu-24.04`
x64 host jobs as documented in `docs/v0.md`. Audit mode is observation-only,
and `unsafe_preserve` is explicitly degraded because it retains container
control paths. `Cargo.toml` is the checked-out source-agent version authority,
and `action/bundle-manifest.json` identifies the agent carried by the Action.
The latest stable GitHub Release is the supported publication; this policy does
not duplicate a version number that can become stale.

## Dependency Policy

- Cargo dependencies must be exact-pinned where practical.
- `Cargo.lock` must be committed.
- `vendor/cache` must be committed.
- Routine repo scripts must not implicitly download third-party tools; hosted validation runs checksum-gated Rust preparation with `script/prepare-rust` before entering the offline script surface.
- Cargo dependency updates must use `script/update`.
- Dependency update changes must include any required `Cargo.lock` and `vendor/cache` changes.
- Rust toolchain updates must use `script/vendor-rust` and commit `.cargo/tooling/rust-toolchain.lock.toml` changes.
- Update-tool lock refreshes for `cargo-audit` and `cargo-deny` must use `script/vendor-update-tools`.
- Prepared cross-build-tool updates must use `script/vendor-release-tools` and commit `vendor/release-tools` changes.

## Offline Expectations

The normal offline project scripts are intended to validate offline Cargo behavior:

```console
script/bootstrap
script/test
script/lint
script/build
```

GitHub-hosted runners are not fully air-gapped infrastructure. Hosted lint, test, PR build, and release build validation run `script/validate-locks --ci` and `script/prepare-rust` first, then the repository scripts stay on the offline surface. Those offline scripts do not ask Cargo or rustup to hydrate dependencies or toolchains implicitly. Checkout, action loading, Rust preparation, artifact transfer, release publication, and attestation verification still require network access.

## Tooling

Rust tooling is checksum-locked in `.cargo/tooling/rust-toolchain.lock.toml`:

- Rust distribution URLs and SHA-256s for `rustc`, `cargo`, `rustfmt`, `clippy`, and configured Rust target standard libraries are committed.
- `script/prepare-rust` verifies the lock against the official Rust channel metadata before installing with `rustup`.
- `script/vendor-rust` is the only normal Rust toolchain lock refresh path.

Online update tooling is checksum-locked in `.cargo/tooling/update-tools.lock.toml`:

- `cargo-audit` and `cargo-deny` top-level crate URLs and SHA-256s are committed.
- The packaged `Cargo.lock` inside each tool crate is checksum-verified after extraction.
- `script/vendor-update-tools` is the only normal update-tool lock refresh path.

Prepared cross-build tooling is vendored in `vendor/release-tools`:

- Zig host archives are committed and checksum-verified before extraction.
- `cargo-zigbuild` crate, source archive, lockfile, and vendored transitive dependency archive are committed and checksum-verified before extraction.
- `script/install-zig` installs retained cross-build tools from committed artifacts only.
- `script/vendor-release-tools` is the only online refresh path for those tools.
- Retaining these tools does not establish macOS, ARM, or other protected-agent support.

The published Fence agent target is limited to `x86_64-unknown-linux-gnu` on
GitHub-hosted `ubuntu-24.04` x64 after its documented security assertions are
proved. Release publication, Action-bundle refresh, artifact upload/download,
and attestation verification are intentionally GitHub-networked operations.
The current threat model and residual boundaries are recorded in
[`docs/threat-model.md`](docs/threat-model.md). Focused review findings are
recorded in [`docs/security-review.md`](docs/security-review.md).

## Reporting Vulnerabilities

Report vulnerabilities through GitHub Security Advisories for this repository when available. If that is not available, contact the maintainer directly. Do not open public issues with exploit details for unresolved vulnerabilities.

## Verifying Release Artifacts

Release assets include checksums and GitHub artifact attestations. Verify downloaded assets with:

```console
shasum -a 256 -c checksums.txt
gh attestation verify <artifact> \
  --repo GrantBirki/fence \
  --signer-workflow GrantBirki/fence/.github/workflows/release.yml
```

Use `sha256sum -c checksums.txt` instead of `shasum` on systems where that is the standard checksum tool.
