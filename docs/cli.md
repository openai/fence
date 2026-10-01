# CLI Reference 💻

Most people should use Fence as a GitHub Action. Its Rust agent also includes a CLI for checking the version, inspecting a runner, and previewing a policy:

```console
fence --version
fence check-support
fence render-plan --config policy.json
fence run --config /run/fence/example/config.json
```

## Print The Version

```console
fence --version
```

This prints the agent version. Source builds use `Cargo.toml`; published Action bundles record their version and provenance in `action/bundle-manifest.json`.

## Check Runner Information

```console
fence check-support
```

This shows the operating system, architecture, available backend, and reference runner profile. It does not check every required security control, activate Fence, or protect the runner.

## Preview A Policy

```console
fence render-plan --config policy.json
```

This validates a JSON configuration and prints the firewall rules without applying them. Exact hostname allowlist entries are resolved through the system resolver while the plan is built, so a preview that contains hostnames can perform DNS lookups and can fail if resolution is unavailable.

## Run The Agent

```console
fence run --config /run/fence/example/config.json
```

Fence must start through its GitHub Action. Running the command directly fails with `trusted_launcher_required`, so an ordinary process cannot claim the runner is protected.

See [how Fence works](how-it-works.md) and the [configuration contract](v0.md#configuration-interface) for more detail.
