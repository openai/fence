# Troubleshooting

Fence prints a short progress log during setup and a compact **Fence Summary** with control and network-activity tables at the end of the job.

## Enable Action Debug Logging

If setup fails and you need more detail, set the standard GitHub Actions repository secret `ACTIONS_STEP_DEBUG` to `true` and rerun the job. Debug output includes bounded transient-service status and Fence-specific diagnostics while avoiding raw configuration bodies, environment values, packet payloads, and unrelated system logs.

## Check The Supported Runner

Fence's protected target is a GitHub-hosted `ubuntu-24.04` x64 host job. A job using `ubuntu-latest`, another architecture, a container job, or a self-hosted runner may fail the support check or may not establish the protected lifecycle.

Fence must be the first meaningful step in the job. Move checkout, setup actions, and workflow commands after Fence so the Action can validate the expected runner state before other code changes it.

## Investigate A Blocked Destination

Start with `mode: audit` and inspect the final **Fence Summary**. Add the narrowest exact hostname, protocol, and port that the workflow needs, then return to `block` mode. Avoid broad wildcard suffixes when a small set of exact hostnames is sufficient.

If a hostname is allowlisted but still fails, check whether the service redirects to a different hostname, uses a CDN or object-storage domain, or opens a non-default port. Container image pulls commonly span authentication, registry, layer, CDN, and storage destinations.

## Investigate Container Failures

Standard block mode intentionally disables Docker and containerd control paths. Workflows that require containers must set `container_policy: unsafe_preserve` and accept that the result no longer carries the standard containment claim.

## Investigate Critical Drift

A critical finding after readiness is permanent for that Fence lifecycle. The post-job hook fails the job because a required worker exited, an owned firewall object changed, a privilege or container control drifted, an unexpected root control endpoint appeared, or another verified invariant stopped holding.

Do not paper over a critical drift failure with a broader network allowlist. Use the summary and debug diagnostics to identify the failed control, then compare it with the [supported security boundary](security.md) and [normative v0 contract](v0.md).

## Direct Agent Execution

`fence render-plan` and `fence check-support` are inspection commands. An ordinary direct `fence run` is rejected with `trusted_launcher_required`; production activation must come through the checked-in Action and matching transient systemd service.

See the [CLI reference](cli.md) for command details.
