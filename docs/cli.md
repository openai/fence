# CLI Reference

Most users should use the GitHub Action. The native Rust agent exposes a narrow command-line interface for version inspection, support checks, deterministic plan rendering, and the trusted production lifecycle.

```console
fence --version
fence check-support
fence render-plan --config policy.json
fence run --config /run/fence/example/config.json
```

## `fence --version`

Prints the source-agent version. `Cargo.toml` is the version authority for source builds; a published bundle's schema-`4` manifest is the bundled-agent version and provenance authority.

## `fence check-support`

Checks whether the current host matches the accepted hosted-runner fingerprint reference. This is an inspection result and does not apply controls or claim active protection.

## `fence render-plan`

Parses strict JSON configuration and emits a deterministic native nftables preview without applying the production lifecycle:

```console
fence render-plan --config policy.json
```

The configuration must satisfy the same schema and bounded policy validation used by the agent.

## `fence run`

Production `run` is intentionally not a general-purpose root CLI. It accepts only `/run/fence/<invocation-id>/config.json`, requires pinned root-owned runtime directories and a root-owned `0600` regular configuration file, and validates that the process is the root `MainPID` of the matching `fence-<invocation-id>.service` transient unit.

An ordinary direct invocation fails with `trusted_launcher_required` before reading configuration:

```console
fence run --config /run/fence/example/config.json
```

Use the checked-in GitHub Action to create the protected launcher path and production lifecycle. See [Architecture and Lifecycle](how-it-works.md) for the full sequence and the [configuration interface](v0.md#configuration-interface) for the normative CLI contract.
