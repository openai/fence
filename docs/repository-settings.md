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
- Keep the `integration` workflow required as the distinct hosted-runner observation and privileged lifecycle gate. It includes namespace-isolated native network/resident proof, separate disposable-runner lockdown scenarios, composed namespace-network plus host-lockdown ordering evidence, non-blocking host-audit platform-profile measurement around controlled GitHub service traffic, one disposable selected-profile runtime finalization scenario after six non-required terminal-success proofs, and packaged production-shaped standard block, degraded block, and audit observation transient services. Keep its concurrency commit-scoped because a stranded host-block job may be unable to receive cancellation. The selected-profile worker and protected services select `github_hosted_job_status_v1` by omission and record logical policy, base-ruleset, and active ruleset hashes separately.
- Keep the `platform selected profile runtime evidence` workflow as the separate three-replica measurement surface for the bounded DNS-mediated Actions-suffix design even after one disposable copy joins required `integration`. Its test-only reports must continue disclosing the bounded DNS timing/count, query-label, CNAME-delegation, HTTPS, and address-plus-port egress limitations.
- Keep the `platform profile candidate` workflow non-required while it tests explicit disposable-host egress candidates. An open HTTPS-plus-platform-channel baseline reached terminal compatibility, an HTTPS-only reduction stranded one replica, and the reduced HTTPS-plus-UDP-DNS candidate reached terminal compatibility while excluding TCP DNS and host-control allowances. It still permits arbitrary outbound TCP `443` plus UDP DNS to the measured platform resolver, so it is not a public protection gate or a default profile. Keep its concurrency commit-scoped because a deliberately blocking failed candidate may be unable to receive cancellation and must not queue a corrected candidate indefinitely.
- Exercise retained Zig/`cargo-zigbuild` inputs through a separate offline installation/verification smoke job; those inputs are reserved for future cross-platform investigation and are not current release artifacts.
- Do not add a public root `action.yml` before the reviewed production modes are complete and an attested alpha binary exists. A later wrapper should remain in this repository and be consumed externally only through an immutable reference.
- If an egress-blocking action is added, apply it to build/test/package jobs after checkout and before scripts run. Do not apply it to release publishing, signing, or verification jobs unless those jobs are split into an explicitly GitHub-network-allowed phase.

## CODEOWNERS

Require CODEOWNER review for sensitive paths:

- `.github/workflows/**`
- `.github/dependabot.yml`
- `.github/CODEOWNERS`
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
- Keep release publication permissions limited to the release job.
- Verify release assets after publication by re-downloading them, checking `checksums.txt`, and verifying artifact attestations.
- Release build jobs should prepare Rust through `script/prepare-rust`, package only the native Linux x64 agent artifact, and must not run direct `curl`, `cargo install --version`, `rustup target add`, or Rust toolchain setup actions outside the repo scripts.
- Retained Zig/`cargo-zigbuild` artifacts should continue to be checksum-validated and exercised in their separate smoke path until a future supported cross-platform target justifies using them for publication.

## Dependabot

- Keep GitHub Actions and Rust toolchain update checks enabled if they are useful, but Rust toolchain bumps must be completed through `script/vendor-rust`.
- Do not enable Cargo version update PRs unless there is automation that also regenerates `Cargo.lock` and `vendor/cache`.
- Cargo dependency updates should normally be performed with `script/update`.
