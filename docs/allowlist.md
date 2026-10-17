# Allowlist Guide 📝

An allowlist tells Fence which network destinations your job is allowed to reach:

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
  with:
    allowlist: |
      api.example.com
      registry.example.com:8443
      udp://dns.example.com:53
```

Put one destination on each line. Fence ignores blank lines and comments that start with `#`.

## Supported Formats

```text
# HTTPS hostname
example.com

# Hostname with a custom TCP port
example.com:8443
tcp://example.com:443

# Hostname with a UDP port
udp://dns.example.com:53

# Explicit hostname
hostname example.com tcp 443

# Hostname wildcards
*.example.com
*.*.example.com

# IPv4 and IPv6 addresses
ip 192.0.2.10 tcp 443
ip 2001:db8::10 udp 53

# IPv4 and IPv6 networks
cidr 192.0.2.0/24 udp 123
cidr 2001:db8::/64 tcp 443
```

A hostname without a port uses TCP port `443`. Use the explicit `ip` or `cidr` form for addresses and networks, especially IPv6.

## Entry Limit

The native multiline `allowlist` input can contain up to 64 unique normalized entries. Fence normalizes hostnames and IP addresses before counting that input, so duplicates, capitalization differences, and equivalent address formats count only once. Different ports, protocols, and destination types count separately.

The 65th unique native entry fails before Fence changes the runner.

> [!NOTE]
> The advanced JSON `config` input uses a stricter physical-entry boundary: its `allowlist` array may contain at most 64 entries before normalization and deduplication. Repeating the same JSON allowance still consumes an array entry. Advanced `config` cannot be combined with native Action inputs.

## Wildcards

Each `*` matches exactly one part of a hostname:

- `*.example.com` matches `api.example.com`.
- `*.example.com` does not match `example.com` or `one.two.example.com`.
- `*.*.example.com` matches `one.two.example.com`.
- `*.*.example.com` does not match `api.example.com` or `three.one.two.example.com`.

Across the entire job, wildcard entries can match at most eight unique hostnames. Prefer exact hostnames when possible: every wildcard gives the job more places to send data.

## CIDR Networks

CIDR entries must start at the network address:

```text
# Valid
cidr 192.0.2.0/24 udp 123

# Invalid: host bits are set
cidr 192.0.2.1/24 udp 123
```

Fence rejects invalid entries before changing the runner.

## GitHub Storage

GitHub's normal job-reporting storage is already covered. You do not need to add its storage accounts to your allowlist.

If your job uses GitHub artifacts, Pages, or caches, set `allow_github_artifacts: true` instead of adding storage domains yourself. This option is off by default because later workflow steps can also use that storage access.

See the [configuration examples](examples.md) for complete workflows or the [v0 specification](v0.md#effective-policy) for the full policy.
