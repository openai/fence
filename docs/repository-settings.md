# Required Repository Settings

Some security controls live in GitHub settings instead of repository files. Configure the following settings for this repository.

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
- Require branches to be up to date before merging when that matches the repository's merge policy.
- Block force-pushes.
- Block branch deletion.
- Restrict who can dismiss reviews.

## Actions

- Set default `GITHUB_TOKEN` permissions to read-only.
- Require approval for first-time contributor workflows.
- Keep GitHub Actions pinned to full commit SHAs.
- Do not allow untrusted pull request workflows to receive write tokens.
- Run `lint` on `ubuntu-24.04`: validate repository locks, prepare the verified Rust toolchain, bootstrap offline inputs, and run `script/lint`.
- Run `test` on `ubuntu-24.04`: validate repository locks, prepare the verified Rust toolchain, install committed coverage tools, bootstrap offline inputs, and run `script/test --coverage`.
- Run `build` on `ubuntu-24.04`: validate repository locks, prepare the verified Rust toolchain, bootstrap offline inputs, and build the Linux x64 GNU release binary.
- Fence has no pre-merge macOS validation assurance. Do not claim macOS protection without a separate implementation, tests, and support decision.
- Run protected packaging and release jobs on GitHub-hosted `ubuntu-24.04` x64. Publish only the `x86_64-unknown-linux-gnu` agent until another target is implemented and tested.
- Keep `acceptance` on `ubuntu-24.04`. It must validate locks, prepare Rust, verify the committed Zig and `cargo-zigbuild` tools, package the current commit, verify its checksum, and run `script/test-package-smoke`. Verifying those tools does not mean other platforms are supported.
- Keep `action acceptance` as its own required check. Pull requests and `main` build a temporary Linux x64 Action bundle; releases test exact distribution commit `D` through the same reusable workflow. Cover standard mode, restricted GitHub domains, opted-in artifact uploads, Docker compatibility, audit mode, invalid setup, tampering, and three finalization replicas. Reject skipped runner checks, unexpected drift, unsafe storage authorization, invalid startup, failed cleanup, and any attempt to restore access.
- Keep `nightly` optional and outside release requirements. Scheduled and manual runs test the exact `main` commit; same-repository pull requests test their GitHub-created merge commit. Build on `ubuntu-24.04`, then run the complete Action acceptance suite on `ubuntu-latest`. A passing run confirms only the current runner image; it does not automatically trust future images or change the fixed release target.
- Keep `action drift canary` optional and read-only. Every run tests the selected immutable Action in block and audit modes on both `ubuntu-24.04` and `ubuntu-latest`. Validate the release mapping and runner security checks. Verify that block-mode restrictions remain active until the job ends.
- Keep `integration` as a required check. Validate repository locks before starting disposable-runner tests for firewall behavior, runner lockdown, startup failures, standard and degraded block modes, Docker wildcards, audit mode, first connections, and finalization. Run the final verifier even when an earlier job fails, reject unsuccessful prerequisites, and scope cancellation to each commit. Record the logical policy, base firewall rules, and active firewall rules separately.
- Keep `action.yml` on `main`, but tell users to copy the pin from the finalized release notes. Use `action-release.json` to verify that pin, not to decide when to upgrade. The `main` branch does not include the bundled agent. The published Action must verify its Linux binary and manifest, start from root-owned local files, default to standard block mode, and avoid downloading an agent, fetching policy, stopping protection, or restoring access. Release behavior changes and their version bump must land together.
- Apply egress blocking to build, test, and package jobs only after checkout and only when the compatibility profile supports it. Release publishing, signing, and verification still need the GitHub network.

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

- Protect the `release` environment, restrict it to `main`, and do not add a required reviewer. Merging the reviewed version pull request authorizes the release.
- Keep immutable releases enabled. Publish a release and all its assets only after the source and distribution commit pass their checks.
- Keep `main` source-only. Build from signed source commit `M`, create GitHub-signed distribution commit `D` with `M` as its only parent and only the two generated bundle files, and point the immutable `vX.Y.Z` tag at `D`.
- Grant `contents: write` only to jobs that create the distribution commit, clean up temporary refs, or publish the release. Grant `id-token: write` and `attestations: write` only to the attestation job. Keep every other job read-only and do not persist checkout credentials.
- Require `action-release.json` to identify the version, source and distribution commits, artifact and checksum, manifest schema, and signer. Publish initially as a non-latest prerelease with verification pending; only after verifying the published assets and clearing temporary refs may the release notes and workflow summary offer `uses: openai/fence@<D> # pin@vX.Y.Z`.
- After publication, download the release assets again and verify their checksums, attestations, release mapping, tag target, signed `D -> M` relationship, two-file diff, manifest, and bundled binary.
- Resume an interrupted release only after verifying that every existing branch, tag, draft, release, and asset still matches. Reject conflicting state and API errors. Delete temporary branches only with a server-side lease, use “re-run all jobs” instead of reusing an earlier attempt, and report the consumer pin only after verification and cleanup finish. If final verification fails after publication, keep the candidate branch as the withdrawal record and never reuse that version. Scheduled canaries must reject releases with leftover temporary refs.
- Releases through `v0.6.3` retain their historical source-commit tag semantics. Do not rewrite old tags or consumer pins.
- Release build jobs must prepare Rust with `script/prepare-rust` and package only the Linux x64 agent. Do not add direct `curl`, `cargo install --version`, `rustup target add`, or separate Rust setup actions.
- Continue verifying Zig and `cargo-zigbuild` in the Linux `acceptance` job. Do not use them to publish another platform until that platform is supported.

## Dependabot

- Keep GitHub Actions and Rust toolchain update checks enabled when useful. Finish Rust toolchain updates with `script/vendor-rust`.
- Do not enable Cargo version update PRs unless there is automation that also regenerates `Cargo.lock` and `vendor/cache`.
- Update Cargo dependencies with `script/update`.
