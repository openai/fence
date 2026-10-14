# Configuration Examples 🧪

Copy the full commit SHA and matching version from the [latest verified Fence release](https://github.com/openai/fence/releases/latest). Add Fence before checkout and the rest of your job.

## Default Block Mode

Fence blocks unexpected outbound connections by default:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
```

It also disables passwordless `sudo`, Docker, and container access.

## Audit A Workflow

Record which connections your job needs without blocking them:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    mode: audit
```

Check the job summary, add the required hostnames or IP addresses to your allowlist, and switch back to block mode.

## Allow HTTPS Destinations

A hostname without a port uses TCP port `443`:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    allowlist: |
      api.example.com
      artifacts.example.com
```

## Use Custom Ports And Protocols

Hostnames, custom ports, IP addresses, and network ranges can share one allowlist:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
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

See the [allowlist guide](allowlist.md) for limits, supported formats, and validation rules.

## Upload GitHub Artifacts

Allow GitHub Actions storage when your job needs artifacts, GitHub Pages, or caches:

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: openai/fence@<commit-sha> # pin@vX.Y.Z
        with:
          allow_github_artifacts: true

      - uses: actions/checkout@<checkout-commit-sha>

      - run: script/build

      - uses: actions/upload-artifact@<upload-artifact-commit-sha>
        with:
          name: build-output
          path: dist/
```

> [!IMPORTANT]
> Later workflow steps can use the same storage access to send data out of the runner. Enable this option only when the job needs it.

## Use Docker

Keep container access available when your job requires Docker or containerd:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    container_policy: unsafe_preserve
    allowlist: |
      auth.docker.io
      registry-1.docker.io
```

Image pulls may also need registry, layer, or storage domains. Use audit mode to identify them.

> [!WARNING]
> Keeping Docker access weakens runner isolation.

## Use A Hostname Wildcard

Use one or two `*` labels to match specific hostname depths:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    allowlist: |
      *.docker.io
      *.*.example.com
```

`*.docker.io` matches `auth.docker.io`, but not `docker.io` or `one.two.docker.io`. All wildcard entries share a limit of eight unique matched hostnames per job.

## Restrict Optional GitHub Domains

Remove optional GitHub website, API, release, and application destinations:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    disable_broad_github_domains: true
```

GitHub Actions can still report job status and finish the run. Steps such as `actions/checkout` may need `github.com` added back to your allowlist.

## Set The Platform Profile

Fence chooses its supported platform profile automatically. Set it explicitly only if your workflow needs to:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    platform_profile: github_hosted_workflow_bootstrap_v5
```

Other profile values are not supported.

## Use Raw JSON

Use raw JSON only when you need the advanced configuration format:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    config: >-
      {"schema_version":1,"mode":"block","invocation_id":"my-job-1","allowlist":[]}
```

The `config` input cannot be combined with native inputs such as `allowlist` or `mode`. Most jobs should use native inputs and let Fence choose the invocation ID.

For the complete configuration contract, see the [v0 specification](v0.md#configuration-interface).
