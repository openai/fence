# Release Provenance 🔏

Each Fence release connects reviewed source code to the exact GitHub Action you run. Releases start only when a reviewed version bump merges into `main`.

## How A Release Is Built

1. A pull request updates the source version in `Cargo.toml` and `Cargo.lock`.
2. The pull request merges into protected `main` as signed commit `M`.
3. Release automation builds and attests the Linux agent from `M`.
4. GitHub creates signed distribution commit `D` with `M` as its only parent.
5. The Action acceptance tests and runner canary validate `D`.
6. The workflow publishes the immutable tag and assets as a prerelease marked "Not verified for use."
7. It downloads and verifies the published files, removes the temporary release refs, and adds the ready-to-use pin. Only then does a stable release become Latest.

The distribution commit adds exactly two generated files:

```text
action/bin/fence
action/bundle-manifest.json
```

Neither file is added to `main`.

## Pin The Published Action

Copy the full commit SHA and version comment from the [latest verified release notes](https://github.com/openai/fence/releases/latest). If the notes say "Not verified for use," keep your current pin.

```yaml
- uses: openai/fence@<action-commit> # pin@vX.Y.Z
```

The tag and `action-release.json` are public before verification finishes. A tag-based update tool could propose a pending or withdrawn version; compare its proposed SHA and version with the pin in the finalized release notes before accepting. Fence does not check release status at Action runtime or revoke a SHA someone already pinned.

Use the full distribution commit SHA, not the tag or `main`. The `main` branch does not contain the Action bundle.

After publication, maintainers update the [first-step canary](../.github/workflows/action-drift-canary.yml) in a normal pull request, using the same pin we give users. That tests adopting the release; it doesn't gate publication or require the previous release to keep working.

## Verify Release Artifacts

`action-release.json` records the source commit, distribution commit, binary checksum, manifest version, and signing workflow. Use it to verify the published pin, not to decide whether the release is ready.

A release is complete only after Fence verifies its binary, manifest, checksums, build attestations, and signed `D -> M` relationship. The Action runs the verified bundled binary; it never downloads an agent or policy at runtime.

Historical releases through `v0.6.3` keep their original tag behavior. Releases through `v0.8.3` retain their original pre-transfer provenance.

See the [security policy](../SECURITY.md) for artifact verification commands and the [v0 specification](v0.md#ci-and-release-contract) for the full release contract.
