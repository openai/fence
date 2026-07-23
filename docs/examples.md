# Configuration Examples

All examples use `<commit-sha>` as a placeholder. Replace it with the full `action_commit` value from the release's `action-release.json` asset.

## Minimal Block Mode

The zero-input configuration enables standard `block` mode with no user-defined destinations:

```yaml
- uses: openai/fence@<commit-sha>
```

## Audit A Workflow

Use `audit` to observe activity without blocking traffic or disabling passwordless sudo and container access:

```yaml
- uses: openai/fence@<commit-sha>
  with:
    mode: audit
```

Review the final **Fence Summary**, add only the destinations the job needs, and then move to `block` mode. Its collapsed allowlist example includes DNS-backed hostnames and explicit `ip <address> <tcp|udp> <port>` entries for direct IPv4 or IPv6 destinations.

## Allow GitHub Artifacts And Pages

GitHub artifact uploads, Pages deployments, and caches may use a dynamically selected results-storage account. Enable their bounded compatibility path only for jobs that need it:

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: openai/fence@<commit-sha>
        with:
          allow_github_artifacts: true
      - uses: actions/checkout@<checkout-commit-sha>
      - run: script/build
      - uses: actions/upload-artifact@<upload-artifact-commit-sha>
        with:
          name: build-output
          path: dist/
```

The option is off by default. It admits only exact GitHub-shaped storage accounts, only on TCP port `443`, within the shared four-account lifetime budget and existing DNS and firewall checks. Because any later workflow step may use an authorized account, artifact uploads are an intentional data-egress channel; an account's name alone does not establish GitHub ownership. This option does not allow `*.blob.core.windows.net`.

## Allow HTTPS Destinations

Bare hostnames use TCP port `443`:

```yaml
- uses: openai/fence@<commit-sha>
  with:
    allowlist: |
      api.example.com
      artifacts.example.com
```

Exact hostname entries resolve before readiness and refresh from bounded DNS lifetimes while Fence remains active.

## Use Custom Ports And Protocols

The short URI forms and explicit line forms can be mixed:

```yaml
- uses: openai/fence@<commit-sha>
  with:
    allowlist: |
      registry.example.com:8443
      tcp://cache.example.com:9443
      udp://dns.example.com:53
      ip 192.0.2.10 tcp 443
      ip 2001:db8::10 udp 53
      cidr 192.0.2.0/24 udp 123
      cidr 2001:db8::/64 tcp 443
```

Use the explicit `ip` and `cidr` forms for literal addresses, especially IPv6.

## Preserve Container Access

Standard block mode disables Docker and containerd control paths. If the workflow needs containers, explicitly select the degraded policy:

```yaml
- uses: openai/fence@<commit-sha>
  with:
    container_policy: unsafe_preserve
    allowlist: |
      auth.docker.io
      registry-1.docker.io
```

This still applies the network policy and disables passwordless sudo, but retained container access invalidates the standard containment claim.

## Use A Bounded Hostname Wildcard

One- and two-label leading wildcards are exact-depth patterns:

```yaml
- uses: openai/fence@<commit-sha>
  with:
    allowlist: |
      *.docker.io
      *.*.example.com
```

`*.docker.io` can match `auth.docker.io`, but it does not match `docker.io` or `one.two.docker.io`. All user wildcard patterns share an eight-name lifetime authorization budget and materialize only after matching runtime DNS queries.

## Narrow The Built-In GitHub Policy

Remove the broad GitHub web, API, release-asset, and watchdog destinations and new platform-origin `*.githubapp.com` authorizations while keeping the core Actions reporting and finalization path:

```yaml
- uses: openai/fence@<commit-sha>
  with:
    disable_broad_github_domains: true
```

An explicit user wildcard is not removed by this input.

## Supply A Platform Profile Explicitly

The only accepted profile is the supported v5 profile, which is also selected when the input is omitted:

```yaml
- uses: openai/fence@<commit-sha>
  with:
    platform_profile: github_hosted_workflow_bootstrap_v5
```

Other profile values are rejected before mutation.

## Use Raw JSON

The advanced `config` input exposes the strict agent schema:

```yaml
- uses: openai/fence@<commit-sha>
  with:
    config: >-
      {"schema_version":1,"mode":"block","invocation_id":"my-job-1","allowlist":[]}
```

Do not combine `config` with native configuration inputs. Most users should let the Action generate `invocation_id`; raw JSON callers must provide a lowercase unique slug for the job run.

See [allowlist syntax](allowlist.md) for every accepted line form and the [Fence v0 specification](v0.md#configuration-interface) for the strict configuration contract.
