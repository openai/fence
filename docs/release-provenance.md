# Release Provenance

A reviewed pull request containing the behavior change and matching `Cargo.toml` and root `Cargo.lock` version bump is the sole human release authorization. Release workflows do not expose a manual dispatch path.

## Source And Distribution Commits

After the pull request merges, the release workflow treats the signed `main` merge commit as source commit `M`. It builds and attests one Linux x64 artifact from `M`, then creates a GitHub-signed one-parent distribution commit `D` whose sole parent is `M`.

The only files added by `D` are:

- `action/bin/fence`
- `action/bundle-manifest.json`

The schema-`4` manifest records the repository, release tag and channel, release URL, source commit and ref, artifact name and SHA-256, bundle path, signer workflow, and signer digest. Both `source_commit` and `signer_digest` identify `M`; the manifest does not attempt to embed the self-referential distribution commit SHA.

## Acceptance And Publication

Before constructing a candidate, the release workflow requires the exact protected source checks `lint`, `test`, `build`, `acceptance`, `action acceptance`, and `integration` on source commit `M`. It then runs the complete unique-case Action-acceptance suite and fixed-runner zero-input canary against exact distribution commit `D` before publication. The immutable `vX.Y.Z` release tag targets `D`, and the release's `action-release.json` asset maps:

- version
- source commit `M`
- distribution commit `D`
- artifact name and digest
- manifest schema version
- signer workflow and signer digest

Release assets remain attested to reviewed source commit `M`, while the generated distribution commit records the bundled bytes and their source provenance.

## Consumer Pinning

Consumers must pin the full 40-character `action_commit` value from `action-release.json`:

```yaml
- uses: GrantBirki/fence@<action-commit> # pin@vX.Y.Z
```

Use the tag from the same release in the `# pin@vX.Y.Z` comment. Release notes fill in both values, and the same-line version comment lets Dependabot keep the label in sync when it updates the pinned Action commit. Do not consume Fence from `main`; it is intentionally source-only and omits the generated bundle. A version tag identifies the release, but the immutable distribution commit is the supported workflow reference. Releases through `v0.6.3` retain their historical tag semantics; the one-parent distribution-commit model begins with the first later release.

## Runtime Bundle Integrity

Fence never downloads an agent, policy, or attestation at Action runtime. The wrapper validates the checked-in bundle manifest and checksum, copies the agent into a protected root-owned launcher directory with executable mode, and launches only that protected copy.

See the [CI and release contract](v0.md#ci-and-release-contract) for the normative pipeline requirements and [Required Repository Settings](repository-settings.md) for the GitHub configuration that supports them.
