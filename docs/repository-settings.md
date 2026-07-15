# Required Repository Settings

Some security controls cannot be fully represented in tracked files. Configure these settings in GitHub for this repository.

## Branch Protection For `main`

- Require a pull request before merging.
- Require CODEOWNER review.
- Require status checks before merge:
  - `lint`
  - `test`
  - `build`
  - `acceptance`
  - `action acceptance`
  - `integration`
- Require branches to be up to date before merging if that matches the repository's merge policy.
- Block force-pushes.
- Block branch deletion.
- Restrict who can dismiss reviews.

## Actions

- Set default `GITHUB_TOKEN` permissions to read-only.
- Require approval for first-time contributor workflows.
- Keep GitHub Actions pinned to full commit SHAs.
- Do not allow untrusted pull request workflows to receive write tokens.
- Keep the `lint` job on fixed `ubuntu-24.04`: run `script/validate-locks --ci`, prepare Rust through the checksum-gated repository path, bootstrap offline inputs, and run `script/lint`.
- Keep the `test` job on fixed `ubuntu-24.04`: run `script/validate-locks --ci`, prepare Rust through the checksum-gated repository path, install committed coverage tooling, bootstrap offline inputs, and run the complete all-features test suite through `script/test --coverage`.
- Keep the `build` job on fixed `ubuntu-24.04`: run `script/validate-locks --ci`, prepare Rust through the checksum-gated repository path, bootstrap offline inputs, and prove the native Linux x64 GNU release build.
- Fence has no pre-merge macOS validation assurance. macOS remains outside the protected target and requires its own implementation, tests, and public support decision before any enforcement claim.
- Protected package and release jobs should run only on GitHub-hosted `ubuntu-24.04` x64 and publish only the `x86_64-unknown-linux-gnu` agent artifact until an additional protected target is implemented and tested.
- Keep the `acceptance` job on fixed `ubuntu-24.04` as the Linux x64 retained-tool and packaged public-contract gate: validate locks, prepare Rust, bootstrap, install and verify the committed Zig/`cargo-zigbuild` inputs, package the current commit once, verify its checksum, then execute `script/test-package-smoke` to prove the public binary contract and direct-invocation rejection without mutation. Retained-tool verification is not a supported cross-platform artifact claim.
- Keep the `action acceptance` workflow as the distinct bundled-wrapper gate and preserve its stable required-check name. Pull requests and ordinary `main` validation build one Linux x64 artifact, assemble an ephemeral production-shaped bundle outside the checkout, and run each unique end-to-end case against that candidate. Release validation calls the same reusable workflow with exact distribution commit `D`. Across the zero-input standard, broad-domain opt-out, degraded wildcard-Docker, nested-layout audit, setup-rejection, tamper, and three quiet-finalization cases, both paths must prove every supported mode, bounded `*.docker.io` authorization, registered-runtime and ancestor-guard integrity, pre-mutation setup rejection, post-ready critical-drift failure, and finalization without restore. Every candidate must activate normally against the complete schema-`3` fingerprint; skipped classification or unknown drift fails.
- Keep `nightly` non-required and outside branch protection and release gates. It runs daily and by input-free manual dispatch, fails closed unless the exact selected ref is `main`, builds an ephemeral production-shaped candidate from that exact `main` source SHA on fixed `ubuntu-24.04`, and reuses the complete unique-case Action-acceptance suite on `ubuntu-latest`. A pass means only that the image currently selected by the floating label matched the reviewed fingerprint and passed the complete suite; a future image selected by `ubuntu-latest` is not automatically trusted, and the supported protected target remains fixed `ubuntu-24.04` x64.
- Keep `action drift canary` non-required and read-only. Scheduled and input-free manual runs must locate the newest non-prerelease immutable release, validate its `action-release.json`, and run the mapped `action_commit` with `fail-fast: false` on a reviewed matrix containing only `ubuntu-24.04` and `ubuntu-latest`. Manual runs with an explicit full SHA and reusable release-validation calls must run only on fixed `ubuntu-24.04`; the release workflow must continue passing exact distribution commit `D`. Every leg must require normal schema-`3` compatibility, reject classifier skips, activate zero-input standard block, and verify the lifecycle without restoring access. A green floating-label leg is point-in-time compatibility evidence and does not expand the fixed `ubuntu-24.04` support boundary.
- Keep the `integration` workflow required as the distinct hosted-runner observation and privileged lifecycle gate. A lightweight preflight must validate repository locks before any privileged matrix starts. The fresh-runner fan-out includes namespace-isolated native network/resident proof immediately before the terminal standard-lockdown case, separate disposable-runner lockdown scenarios, selected-profile healthy and failure scenarios, packaged production-shaped standard block, broad-domain opt-out block, degraded block, wildcard-Docker and malformed-wildcard cases, audit observation transient services, and three first-connect plus three quiet-finalization replicas. The read-only terminal verifier and stable aggregate must run even after a prerequisite failure and explicitly reject every prerequisite result other than success. Keep its concurrency commit-scoped because a stranded host-block job may be unable to receive cancellation. Protected services select `github_hosted_workflow_bootstrap_v5` by omission and record logical policy, base-ruleset, and active ruleset hashes separately.
- Keep the root `action.yml` wrapper source on `main` and document external consumption only through the full immutable distribution SHA reported as `action_commit` in `action-release.json`. Source `main` intentionally omits the production bundle. A distribution commit must bind the checksum-validated Linux release binary to a schema-`4` manifest, default omitted input to strict standard block with an empty `allowlist`, copy the validated mode-`0644` bundle bytes into a protected root-owned mode-`0555` executable, launch the root transient service from fixed local inputs, render bounded local evidence, and avoid runtime agent downloads, policy fetches, stop operations, or access restoration. New Action-level shortcuts and source-level contract changes must land with their version bump in the same reviewed PR.
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

- Maintain the protected `release` environment, restrict it to protected `main`, and configure no required reviewer. Merging the reviewed version PR is the sole human release authorization.
- Keep immutable releases enabled and create each release with its complete asset list only after all source and candidate gates pass.
- Keep `main` source-only. The release workflow must build once from signed source merge `M`, create GitHub-signed child distribution commit `D` with `M` as its sole parent and exactly the two generated bundle paths as its diff, then target the immutable `vX.Y.Z` tag at `D`.
- Keep `contents: write` limited to candidate-commit creation, guarded candidate-ref cleanup, and publication jobs. Keep `id-token: write` and `attestations: write` limited to the attestation job; all other jobs remain read-only and checkout credentials remain non-persistent.
- Require the release asset `action-release.json` to map version, `M`, `D`, artifact name/digest, manifest schema, and signer identity. Release notes must contain `uses: GrantBirki/fence@<D>` when the release is published, while the workflow summary must not report that consumer pin until final published-state verification and temporary-ref cleanup succeed.
- Verify release assets after publication by re-downloading them, checking `checksums.txt`, verifying artifact attestations against `M`, and rechecking the release mapping, tag target `D`, signed one-parent `D -> M` relationship, exact two-file diff, manifest identity, and byte-for-byte bundled artifact.
- Candidate/tag/draft/release reruns must be idempotent and fail closed: matching state may be resumed only after full verification, conflicting state is rejected, API errors are never interpreted as absence, and a temporary candidate branch is deleted only by a server-side lease that still expects the source or distribution commit. Publication and finalization must consume state classified in the same workflow run attempt; use “re-run all jobs,” because a partial failed-job rerun is deliberately blocked from reusing earlier classification. Successful final verification uses a matching temporary `release-verified/vX.Y.Z` ref plus the exact prior verification job result to distinguish recoverable cleanup interruption from withdrawal, and the consumer pin is reported only after both temporary refs are lease-deleted. If the first final verification fails after immutable publication, retain the candidate branch at the distribution commit without a successful verification result as the durable withdrawal state and reject attempts to reuse that version. Scheduled canaries must reject releases with either temporary ref still present.
- Releases through `v0.6.3` retain their historical source-commit tag semantics. Do not rewrite old tags or consumer pins.
- Release build jobs should prepare Rust through `script/prepare-rust`, package only the native Linux x64 agent artifact, and must not run direct `curl`, `cargo install --version`, `rustup target add`, or Rust toolchain setup actions outside the repo scripts.
- Retained Zig/`cargo-zigbuild` artifacts should continue to be checksum-validated and exercised within the fixed-Linux `acceptance` job until a future supported cross-platform target justifies using them for publication.

## Dependabot

- Keep GitHub Actions and Rust toolchain update checks enabled if they are useful, but Rust toolchain bumps must be completed through `script/vendor-rust`.
- Do not enable Cargo version update PRs unless there is automation that also regenerates `Cargo.lock` and `vendor/cache`.
- Cargo dependency updates should normally be performed with `script/update`.
