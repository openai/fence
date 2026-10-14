# Release Provenance 🔏

Each Fence release connects reviewed source code to the exact GitHub Action you run. Releases start only when a reviewed version bump merges into `main`.

## How A Release Is Built

1. A pull request updates the source version in `Cargo.toml` and `Cargo.lock`.
2. The pull request merges into protected `main` as signed commit `M`.
3. Release automation builds and attests the Linux agent from `M`.
4. GitHub creates signed distribution commit `D` with `M` as its only parent.
5. The Action acceptance tests and runner canary validate `D`.
6. The workflow publishes the immutable tag and assets as a prerelease marked "Verification pending."
7. It downloads and verifies the published files, removes the temporary release refs, and adds the ready-to-use pin. Only then does a stable release become Latest.

The distribution commit adds exactly two generated files:

```text
action/bin/fence
action/bundle-manifest.json
```

Neither file is added to `main`.

## Pin The Published Action

Each release includes `action-release.json`, which identifies the source commit, distribution commit, binary checksum, manifest version, and signing workflow.

Use its full `action_commit` value in your workflow:

```yaml
- uses: openai/fence@<action-commit> # pin@vX.Y.Z
```

Copy the pin from the [latest verified release](https://github.com/openai/fence/releases/latest). Dependabot uses the matching version in the `# pin@vX.Y.Z` comment when updating the commit.

The tag and `action-release.json` are public while verification is pending; their existence is not an invitation to upgrade. If verification fails, stay on the previous release. This does not revoke a SHA someone already pinned, and Fence does not check release status at Action runtime.

Use the full distribution commit SHA, not the tag or `main`. The `main` branch does not contain the Action bundle.

## Verify Release Artifacts

A release is complete only after Fence verifies its binary, manifest, checksums, build attestations, and signed `D -> M` relationship. The Action runs the verified bundled binary; it never downloads an agent or policy at runtime.

Historical releases through `v0.6.3` keep their original tag behavior. Releases through `v0.8.3` retain their original pre-transfer provenance.

See the [security policy](../SECURITY.md) for artifact verification commands and the [v0 specification](v0.md#ci-and-release-contract) for the full release contract.
