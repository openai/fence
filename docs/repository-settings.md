# Required Repository Settings

Some security controls cannot be fully represented in tracked files. Configure these settings in GitHub for this repository.

## Branch Protection For `main`

- Require a pull request before merging.
- Require CODEOWNER review.
- Require status checks before merge:
  - `build`
  - `coverage`
  - `lint (macos-14)`
  - `lint (ubuntu-24.04)`
  - `acceptance`
  - `action acceptance`
  - `integration`
  - `test (macos-14)`
  - `test (ubuntu-24.04)`
- Require branches to be up to date before merging if that matches the repository's merge policy.
- Block force-pushes.
- Block branch deletion.
- Restrict who can dismiss reviews.

## Actions

- Set default `GITHUB_TOKEN` permissions to read-only.
- Require approval for first-time contributor workflows.
- Keep GitHub Actions pinned to full commit SHAs.
- Do not allow untrusted pull request workflows to receive write tokens.
- Test, coverage, lint, PR build, and release build jobs should run `script/validate-locks --ci`, then `script/prepare-rust`, then stay on the normal offline script surface.
- Coverage jobs should install `cargo-llvm-cov` with `script/install-test-tools`, then run `script/test --coverage`.
- Keep portable lint/test validation separate from protected-platform claims; fixed macOS validation does not constitute macOS enforcement support.
- Protected package and release jobs should run only on GitHub-hosted `ubuntu-24.04` x64 and publish only the `x86_64-unknown-linux-gnu` agent artifact until an additional protected target is implemented and tested.
- Keep the `build` workflow as the PR-based Linux x64 package smoke test: validate locks, prepare Rust, bootstrap, then run native release-mode packaging.
- Keep the `acceptance` workflow as the distinct Linux x64 packaged public-contract gate: independently package the current commit, verify its checksum, then execute `script/test-package-smoke` to prove direct invocation rejects an untrusted launcher without mutation.
- Keep the `action acceptance` workflow as the distinct bundled-wrapper gate: validate the committed release-bound bundle, invoke the root Action through `uses: ./`, prove standard block, degraded `unsafe_preserve`, and audit behavior on disposable GitHub-hosted runners while controls remain resident, prove quiet terminal jobs retain downloadable logs, prove the registered post runtime and bundled binary resist runner-user replacement, reject malformed setup before mutation, and prove post-ready critical drift fails the protected post hook without restore.
- Keep `action acceptance ubuntu latest` non-required. It is an observational floating-label canary for the zero-input wrapper path, not evidence that expands the supported protected target beyond fixed `ubuntu-24.04` x64.
- Keep the `integration` workflow required as the distinct hosted-runner observation and privileged lifecycle gate. It includes namespace-isolated native network/resident proof, separate disposable-runner lockdown scenarios, one disposable selected-profile runtime finalization scenario, packaged production-shaped standard block, broad-domain opt-out block, degraded block, and audit observation transient services, plus quiet terminal-finalization replicas whose downstream verifier requires nonempty downloadable job logs. Its stable aggregate must run even after a prerequisite failure and explicitly reject every prerequisite result other than success. Keep its concurrency commit-scoped because a stranded host-block job may be unable to receive cancellation. Source-built protected services select `github_hosted_workflow_bootstrap_v3` by omission and record logical policy, base-ruleset, and active ruleset hashes separately.
- Exercise retained Zig/`cargo-zigbuild` inputs through a separate offline installation/verification smoke job; those inputs are reserved for future cross-platform investigation and are not current release artifacts.
- Keep the root `action.yml` wrapper in this repository and document external consumption only through immutable commit SHAs. It must carry a checksum-validated attested Linux release binary, bind that binary to a schema-`2` manifest with a matching immutable stable or prerelease release channel, default omitted input to strict standard block with an empty `allowlist`, launch the root transient service from fixed local inputs, render bounded local evidence, and avoid runtime agent downloads, policy fetches, stop operations, or access restoration. New Action-level shortcuts for source-level config fields should land only with a matching release-bundle refresh.
- Apply an egress-blocking action to build/test/package jobs after checkout and before scripts run only where the selected compatibility profile is sufficient. Do not apply it to release publishing, signing, or verification jobs unless those jobs are split into an explicitly GitHub-network-allowed phase.

## CODEOWNERS

Require CODEOWNER review for sensitive paths:

- `.github/workflows/**`
- `.github/dependabot.yml`
- `.github/CODEOWNERS`
- `action.yml`
- `action/**`
- `script/**`
- `.cargo/config.toml`
- `Cargo.toml`
- `Cargo.lock`
- `deny.toml`
- `.cargo/tooling/**`
- `vendor/**`
- `vendor/test-tools/**`
- `vendor/release-tools/**`
- Security and repository policy docs

## Releases

- Maintain the protected `release` environment.
- Require reviewer approval before jobs using that environment can publish release assets.
- Keep immutable releases enabled and create each release with its complete asset list before publication.
- Keep release publication permissions limited to the release job.
- Verify release assets after publication by re-downloading them, checking `checksums.txt`, and verifying artifact attestations.
- Release build jobs should prepare Rust through `script/prepare-rust`, package only the native Linux x64 agent artifact, and must not run direct `curl`, `cargo install --version`, `rustup target add`, or Rust toolchain setup actions outside the repo scripts.
- Retained Zig/`cargo-zigbuild` artifacts should continue to be checksum-validated and exercised in their separate smoke path until a future supported cross-platform target justifies using them for publication.

## Dependabot

- Keep GitHub Actions and Rust toolchain update checks enabled if they are useful, but Rust toolchain bumps must be completed through `script/vendor-rust`.
- Do not enable Cargo version update PRs unless there is automation that also regenerates `Cargo.lock` and `vendor/cache`.
- Cargo dependency updates should normally be performed with `script/update`.
