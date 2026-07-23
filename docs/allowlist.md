# Allowlist Syntax And DNS Behavior

The native Action `allowlist` input accepts one entry per line and supports up to 64 unique, normalized destinations. Blank lines and lines beginning with `#` are ignored. Equivalent entries are deduplicated using the destination type, normalized destination, protocol, and port before the limit is applied; a 65th unique entry fails before privileged setup.

## Accepted Forms

```text
example.com
example.com:8443
tcp://example.com:443
udp://dns.example.com:53
hostname example.com tcp 443
*.example.com
*.*.example.com
ip 192.0.2.10 tcp 443
ip 2001:db8::10 udp 53
cidr 192.0.2.0/24 udp 123
cidr 2001:db8::/64 tcp 443
```

- `example.com` means TCP port `443`.
- `example.com:8443`, `tcp://...`, and `udp://...` select a specific transport and port.
- `hostname ...`, `ip ...`, and `cidr ...` are the explicit forms.
- Literal IPv6 addresses and address ranges should use `ip` or `cidr` so the port remains unambiguous.
- CIDR entries must identify a canonical network without host bits; for example, `192.0.2.0/24` is valid but `192.0.2.1/24` is rejected before privileged setup.

## Exact Hostnames

Fence resolves every required exact hostname before readiness, applies and verifies rules for all approved addresses, and refreshes those addresses while the job runs. Each refreshed address retains the protocol and port from its allowlist entry.

Non-static `productionresultssa<1-to-5-decimal-digits>.blob.core.windows.net` accounts are runner-authorized platform destinations, not exact user destinations. Fence rejects an exact user entry for one of those accounts before mutation; the selected profile authorizes up to four of them at TCP port `443` only after an attributable request from the pinned runner process. The source-defined `productionresultssa19.blob.core.windows.net` compatibility account remains the sole static exception.

Only `A` and `AAAA` questions are forwarded in block mode. Fence rebuilds outbound questions in canonical lowercase form and releases an approved address-bearing answer only after the corresponding firewall access has been applied and structurally verified.

## Wildcard Hostnames

The supported wildcard forms are `*.example.com` and `*.*.example.com`. Each `*` matches exactly one DNS label:

- `*.example.com` matches `api.example.com` but not `example.com` or `one.two.example.com`.
- `*.*.example.com` matches `one.two.example.com` but not `api.example.com` or `three.one.two.example.com`.

All user wildcard entries share one eight-name lifetime authorization budget. Wildcard names materialize only after matching runtime DNS queries, do not prehydrate, and do not delay readiness.

Fence validates DNS structure, not registrable-domain ownership. A wildcard over a broad or shared suffix therefore creates both an egress choice and a DNS data channel; use the narrowest suffix that fits the workflow.

## CNAME And Address Handling

Derived CNAME authorization must form one acyclic response-local chain rooted at the echoed question. Every alias inherits the queried root's transport policy and stays within bounded TTL, depth, and capacity limits. An unrelated alias, address-family mismatch, malformed response, incomplete address coverage, or attribution failure fails closed without creating later authorization.

Duplicate terminal addresses use the minimum observed TTL. Valid zero-TTL addresses and zero-TTL CNAME edges receive a one-second materialization lifetime before the fixed refresh overlap.

For the complete normative policy, see [Effective Policy](v0.md#effective-policy) in the Fence v0 specification.
