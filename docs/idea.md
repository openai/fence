# Fence Agent Idea And Handoff

This document is a public-safe design handoff for building `fence`: a dedicated
Rust-based security agent for GitHub Actions hosted runners. It captures the
architecture discussions, security decisions, rejected approaches, edge cases,
testing expectations, and implementation lessons from prior Airlock design work.

Fence is the new project name. The future GitHub Action wrapper will likely be
named `fence-action`, but this repository should focus first on the core Rust
agent.

The intended reader is another engineering agent or maintainer who has not seen
the earlier design conversations. This file should be enough context to start a
fresh implementation discussion without rediscovering the same threat-model
issues.

## Executive Summary

Fence should become a source-owned, source-auditable Rust agent for CI runner
egress control and hosted-runner lockdown.

The central goal is:

```text
Start early in a GitHub Actions job
-> apply explicit network egress controls
-> remove default sudo and container escape paths
-> keep enough local evidence for reports
-> avoid all remote control planes, telemetry, and runtime downloads
```

Fence is being separated from Airlock because the privileged Linux agent is the
real security boundary. A TypeScript GitHub Action can be useful as a wrapper,
but the difficult part is a hardened, auditable, root-owned Linux enforcement
component. That component deserves its own repository, test strategy, release
process, and security review surface.

The design should stay close to the proven parts of StepSecurity Harden-Runner's
open-source Linux agent model:

- A privileged local agent starts before untrusted later workflow steps.
- The agent owns firewall mutation.
- The agent removes default hosted-runner privilege paths such as passwordless
  sudo and Docker/containerd access.
- Firewall rules cover the host `OUTPUT` path and Docker's `DOCKER-USER` path
  where relevant.
- The system provides local evidence about denied or would-have-denied egress.

Fence should not copy the parts that do not match the project values:

- No telemetry.
- No vendor backend.
- No hosted dashboard.
- No remote policy service.
- No subscription or private-repository checks.
- No runtime binary downloads.
- No opaque third-party enforcement binary.
- No hidden undocumented endpoint bundles.
- No broad feature parity chase before the core boundary is proven.

Fence should be narrow first:

- GitHub-hosted Ubuntu x64 first.
- Rust agent first.
- Explicit inline policy/config first.
- Egress firewall plus sudo/container lockdown first.
- Strong local tests and privileged hosted-runner integration tests first.

Everything else is secondary.

## Design Constitution

Fence exists because security defaults matter. The default path must be the
secure path. A one-line action invocation should provide the strongest practical
default security boundary for the supported runner class.

The project should follow these principles:

1. Extra features are liabilities unless they buy a clear security win.
   Complexity creates parser surface, ordering ambiguity, edge cases,
   misconfiguration paths, and bypass opportunities.

2. The easy path and the secure path should be the same path. If a safer mode
   requires users to understand a complicated configuration model, many users
   will run a weaker configuration.

3. Fence should prefer a narrow, auditable security promise over broad feature
   parity with larger products.

4. Fence should be source-owned. A committed binary is acceptable only if it is
   built from source in this repository, rebuilt in CI, and checked for
   freshness.

5. Fence must not be described as a full sandbox or kernel containment boundary.
   It can remove default hosted-runner privilege paths, but it cannot promise to
   survive arbitrary root or kernel compromise.

6. Fence is SLSA-adjacent, not SLSA-generating. It can help enforce hermetic
   build discipline by constraining network access, but it does not make a
   workflow SLSA Build L3 by itself.

7. Host and port allowlisting is not semantic authorization. Allowing
   `github.com:443` does not mean the runner is restricted to a repository,
   URL path, API route, TLS SNI value, HTTP method, package, or organization.

8. Audit mode must stay honest. It can report IP/port evidence, aggregate
   counters, and best-effort kernel log data. It must not claim process
   attribution, step attribution, package attribution, or full hostname
   attribution unless those features are actually implemented locally.

9. Public documentation and comments must be safe for an open-source repository.
   Avoid private environment details, machine-specific paths, secret-shaped
   examples, or overly candid operational notes that do not belong in a public
   repo.

10. StepSecurity Harden-Runner and the Apache-2.0 StepSecurity Linux agent are
    prior art. They are useful for architecture, threat modeling, and
    implementation patterns. Fence should not depend on StepSecurity at runtime.

## Why Fence Needs A Privileged Agent

A firewall-only GitHub Action is not enough on GitHub-hosted Linux runners.

The core problem is passwordless sudo. On hosted Ubuntu runners, later workflow
steps normally run as a user that can invoke `sudo` without a password. If Fence
only inserts iptables rules and then leaves passwordless sudo intact, a malicious
dependency or third-party action can try to run:

```bash
sudo iptables -F
sudo iptables -I OUTPUT 1 -j ACCEPT
sudo ip6tables -F
sudo systemctl stop some-local-agent
```

If Docker or containerd remains available, disabling sudo alone is also not
enough. A runner user with Docker/containerd access may be able to regain host
root privileges through a privileged container or host mount. This is the same
lesson behind StepSecurity's stronger `disable-sudo-and-containers` model.

Therefore the core Fence boundary must be:

```text
firewall first
then remove broad sudo
then remove Docker/containerd access
then run later workflow steps
```

This turns Fence from "tamper-evident only" into "tamper-resistant against the
default GitHub-hosted sudo/container escape paths." That wording matters. Fence
is not tamper-proof, but it should close the default privilege paths that make
plain egress rules easy to bypass.

## Goals

Fence v0.0.x should aim for these concrete outcomes:

- Provide a Rust agent that runs on GitHub-hosted Ubuntu x64.
- Apply explicit egress firewall controls before later workflow steps run.
- Support block mode and, optionally, audit mode.
- Resolve hostnames before firewall mutation and freeze the resolved IP policy.
- Allow explicit `host:port` endpoints and explicit CIDRs.
- Reject wildcards, URL schemes, URL paths, userinfo, queries, fragments, and
  implicit ports.
- Deny outbound network access by default except loopback, established traffic,
  and explicitly allowed policy.
- Disable passwordless sudo by default after firewall enforcement is active.
- Disable Docker/containerd access by default after firewall enforcement is
  active.
- Apply strict tamper-evidence checks for the firewall state.
- Produce local reports without uploading anything.
- Use committed source, committed lockfiles, and a committed binary that CI
  verifies from source.
- Avoid remote policy fetches, telemetry, backend APIs, and runtime binary
  downloads.

## Non-Goals For The First Phase

Do not spend the first phase on:

- macOS support.
- Windows support.
- self-hosted runner support.
- Actions Runner Controller support.
- job container support.
- persistent local DNS proxying.
- direct nftables support.
- eBPF.
- TLS inspection.
- process attribution.
- workflow step attribution.
- package-manager attribution.
- hidden endpoint presets.
- remote policy files.
- policy-file support.
- hosted dashboards.
- uploaded reports.
- vendored opaque third-party binaries.
- StepSecurity API compatibility.
- full Harden-Runner feature parity.

These can be revisited only after the core Linux agent boundary is proven.

## Threat Model

### Assets

Fence is meant to protect:

- CI secrets that are available to later workflow steps.
- Repository tokens with limited job permissions.
- Cloud credentials or OIDC-derived credentials that may become available in a
  job.
- Build artifacts from dependency-driven tampering or exfiltration.
- Hermetic build assumptions about where dependencies and tools can come from.
- The integrity of local egress policy evidence.

Fence is not enough by itself to protect all of these assets. It is one layer.
Workflows still need pinned actions, minimal `GITHUB_TOKEN` permissions, careful
secret scoping, environment gates, and separation between untrusted build/test
jobs and secret-bearing deploy jobs.

### In-Scope Attackers

Fence should assume an attacker may control code that runs after Fence starts:

- A compromised third-party action.
- A compromised package install script.
- A malicious transitive dependency.
- A malicious build tool downloaded before policy was tightened.
- PR-controlled code in a maintainer-approved workflow run.
- A test script that tries to exfiltrate secrets.

Fence should assume that attacker starts with the normal runner user's
privileges. On GitHub-hosted Ubuntu this includes passwordless sudo unless Fence
removes it. It may also include Docker/containerd access unless Fence removes
it.

### In-Scope Attacks

Fence should resist or detect:

- Direct egress to undeclared hosts.
- DNS lookups after the policy has been resolved and frozen.
- Attempts to flush or reorder iptables rules through sudo after lockdown.
- Attempts to insert early `OUTPUT ACCEPT` or `RETURN` rules.
- Attempts to bypass host firewall rules through Docker/containerd.
- Attempts to use Docker privileged containers to regain root.
- Attempts to mutate runner-visible state files used by the wrapper.
- Attempts to exploit weak policy parsing, such as wildcard domains or URL
  paths passed as hosts.
- Attempts to create excessive firewall rules through unbounded DNS responses or
  large allowlists.

### Out-Of-Scope Attacks

Fence should document, not claim to solve:

- Kernel exploits.
- Hypervisor or GitHub Actions platform compromise.
- A malicious step that runs before Fence starts.
- Allowed endpoint abuse, such as exfiltration through an explicitly allowed
  `github.com:443` endpoint.
- Data exfiltration through GitHub service channels, logs, artifacts, caches, or
  annotations when those channels are available.
- Misuse of `GITHUB_TOKEN` against allowed GitHub API endpoints.
- Secrets passed directly to malicious actions.
- Application-layer policy such as URL path, package name, repository, TLS SNI,
  or HTTP method restrictions.
- Non-network tampering in the same workspace.

## The Most Important Lesson: Egress Alone Does Not Contain Root

The single most important learning is that network egress controls are weak if
the attacker can still become root.

This example is not theoretical:

```yaml
steps:
  - uses: fence-action@...
    with:
      allowed-endpoints: github.com:443

  - uses: some/action@main
```

If `some/action@main` becomes malicious and passwordless sudo still works, it
can attempt to remove the firewall, then exfiltrate. The firewall may detect
tampering later, but detection after exfiltration is not prevention.

The security boundary only becomes meaningful when Fence removes the ordinary
hosted-runner privilege escalation paths after the firewall is in place.

This is why the dedicated Rust agent is not overengineering. The agent is the
core product.

## StepSecurity Prior Art

StepSecurity Harden-Runner is a valuable reference point because it is widely
used and has already confronted the same hosted-runner threat model.

The useful prior-art patterns are:

- A privileged local agent enforces rules.
- The agent is started early.
- The agent uses iptables to control outbound traffic.
- The agent handles Docker's `DOCKER-USER` chain.
- The stronger security mode disables sudo and container escape paths.
- Audit/block mode distinction is useful.
- Egress evidence is locally collected and surfaced.

The parts Fence should not copy are:

- Remote telemetry.
- Policy APIs.
- Subscription checks.
- Private repository restrictions.
- Runtime agent downloads.
- Backend dashboards.
- Hidden control-plane behavior.

If Fence copies or adapts any Apache-2.0 code from StepSecurity's open-source
agent, it must preserve attribution and license notices. A cleaner first
implementation is to use StepSecurity as architectural prior art and write the
Fence agent in-house.

## Rejected Design: Token-Gated Root Restore Helper

An earlier design explored a small root-owned helper that would restore the
firewall in post when called with a secret token. That design should stay
rejected.

The problem is not cryptography. The problem is runner state exposure.

GitHub Actions `pre` and `post` coordination normally uses file-command state
such as `GITHUB_STATE`. A token saved there for post can be discoverable by
later processes running in the job. Even if the token is not directly logged, a
malicious step can search runner temp directories, process environments, or file
command state locations depending on timing and permissions.

If an attacker can steal the token, they can call the helper early, restore
egress, then exfiltrate. That turns the restore token into a privileged unlock
capability.

The safer design is:

```text
no privileged post unlock token
no root restore helper callable by later steps
no privileged lifecycle signal that restores network
```

If Fence keeps a resident root agent, the post step should read reports or
snapshots. It should not send a secret that unlocks egress.

## Open Design Tension: Restore Firewall Or Leave It Locked

There is one hard operational question that must be tested carefully:

```text
Should Fence restore firewall state at job post/finalization time?
```

### Leaving The Firewall Locked

This is the strictest security posture. If Fence never restores network, a
malicious downstream step cannot race an unlock path. The ephemeral hosted
runner is destroyed at the end of the job, so cleanup is less important than
preventing exfiltration.

Benefits:

- No post unlock capability.
- No token.
- No privileged restore command available to attacker-controlled later steps.
- Stronger story for secret-bearing workflows.

Costs:

- GitHub Actions post-job behavior may need network access for logs, summaries,
  action post steps, artifact uploads, caches, or service finalization.
- If there is no hidden GitHub runtime baseline, users must explicitly allow
  required GitHub endpoints for their workflow.
- Some actions may have post steps that need network access and will fail under
  strict no-restore behavior.

### Restoring Firewall In Post

This improves compatibility, but creates a dangerous unlock phase. If any
attacker-controlled process can trigger or race the restore, exfiltration is
possible after the firewall is removed.

Benefits:

- Better compatibility with normal GitHub post-job behavior.
- Less surprise for users.
- Easier summary/artifact/report upload flows.

Costs:

- Requires a privileged restore path.
- Restore token designs are risky.
- A compromised job may intentionally wait for post-restore or exploit the
  restore mechanism.

### Current Recommendation

Fence should start with the stricter model:

```text
Do not restore egress after the agent reaches ready state.
```

The root agent may perform setup-failure rollback before it declares itself
ready. That is different from post restore. If firewall setup fails before
lockdown, rollback is reasonable because enforcement never became active.

After ready, Fence should leave firewall, sudo, Docker, and containerd locked
until the ephemeral runner is destroyed.

This recommendation must be validated with hosted-runner integration tests. If
strict no-restore breaks unavoidable GitHub finalization behavior, the project
must explicitly choose between compatibility and stronger containment. Do not
silently add a hidden restore path.

## Policy Model

Fence should use explicit local policy only.

The initial policy should support:

- `mode`: `block` or `audit`.
- `allowed-endpoints`: explicit `host:port` entries.
- `allowed-cidrs`: explicit CIDR entries with clear port semantics.
- `dns-mode`: default `resolve-then-freeze`.
- `report-json`: optional local path handled by a future action wrapper.
- `fail-on-audit-findings`: optional wrapper behavior.
- `allow-unsupported`: optional wrapper behavior.
- `log-level`: optional local verbosity.
- Docker compatibility knob, if supported, clearly marked unsafe.

Fence should reject:

- Wildcards.
- URL schemes such as `https://`.
- URL paths.
- Query strings.
- Fragments.
- Userinfo.
- Missing ports for endpoints.
- Invalid ports.
- Ambiguous IPv6 endpoint syntax.
- Unknown keys.
- Remote policy URLs.
- Policy files in the first phase.

## Why Policy Files Were Removed

Policy files look attractive because they are reviewable and can be covered by
CODEOWNERS. However, they create dangerous ordering ambiguity in GitHub Actions.

Inline policy can run before checkout:

```yaml
- uses: fence-action@...
  with:
    allowed-endpoints: github.com:443
```

Policy files require checkout before Fence can read them:

```yaml
- uses: actions/checkout@...
- uses: fence-action@...
  with:
    policy-file: .github/fence.yml
```

That means the checkout and action fetch already happened before the network was
sealed. In a pull request workflow, the checked-out policy can also be
PR-controlled unless the workflow goes out of its way to check out a trusted
base branch copy.

This extra complexity did not buy enough security value for the early project.
It adds parser surface, workflow-order footguns, docs burden, and review
ambiguity. StepSecurity Harden-Runner also does not expose policy files in its
action metadata, which is a useful signal that the simpler inline model is
practical.

For Fence v0.0.x:

```text
no policy files
no remote policy
no alternate policy source
```

## GitHub Runtime Baseline

There was an important design debate around hidden GitHub runtime endpoints.

One approach is to include a fixed baseline of GitHub endpoints so the runner
can continue talking to GitHub services for logs, summaries, action lifecycle
traffic, and artifacts.

The safer and more honest approach is:

```text
No hidden endpoint baseline.
All non-loopback outbound endpoints must be explicit.
```

Benefits:

- Users can inspect the entire policy.
- No hidden convenience bundle turns into a broad exfiltration channel.
- Reports match what the user configured.
- The project stays aligned with hermetic-build discipline.

Costs:

- Workflows may need to explicitly allow GitHub endpoints.
- GitHub's runtime endpoint needs can be hard to document completely.
- Some post-job behavior may fail if users do not allow the right endpoints.

Fence should default to no hidden runtime baseline unless integration testing
proves that GitHub Actions cannot reliably function without a minimal explicit
baseline. If a baseline is ever added, it must be:

- Small.
- Static.
- Documented.
- Printed in reports.
- Not fetched from a network API.
- Not presented as a secret internal endpoint group.

## Endpoint Semantics

Fence should be precise about what an allow rule means.

`github.com:443` means:

```text
allow TCP connections to resolved IP addresses for github.com on port 443
```

It does not mean:

- only this repository.
- only this organization.
- only this URL path.
- only Git fetch.
- only GitHub API calls.
- only package downloads.
- only a specific TLS SNI.
- only a specific HTTP method.

An attacker with data and an allowed endpoint may still use that endpoint as an
exfiltration channel. That is a residual risk, not a firewall bug.

Documentation should repeat this often enough that users do not over-trust
host/port allowlists.

## DNS Model

The first DNS mode should be `resolve-then-freeze`.

The agent or wrapper resolves all allowed hostnames before firewall mutation.
The resulting IP addresses become concrete firewall allow rules. After that,
new DNS traffic should be denied unless explicitly allowed.

Important behavior:

- DNS failure should fail before firewall mutation.
- DNS timeout should fail before firewall mutation.
- Excessive DNS results should fail before firewall mutation.
- Endpoint counts should be bounded.
- Addresses should be deduplicated and sorted for deterministic policy hashes
  and rule rendering.

Suggested limits from prior design:

```text
max endpoints: 64
max addresses per endpoint: 32
DNS timeout per endpoint: 5 seconds
```

These are not magic numbers. They are reasonable first guardrails to prevent a
malicious or broken policy from creating enormous firewall plans or hanging a
job.

DNS should not be treated as hostname attribution. If a blocked IP later matches
something that was once resolved, the report may include a hint, but Fence
should not claim complete hostname attribution.

## CIDR Semantics

CIDR policy needs a clean schema.

String forms can get ambiguous, especially with IPv6:

```text
192.0.2.0/24:443
[2001:db8::/64]:443
2001:db8::/64:443  # ambiguous
```

Early Airlock design deferred IPv6 CIDR-with-port support because plain
`cidr:port` parsing collides with IPv6 colons. Fence can choose a better model
from the start.

Recommended v0.0.x approach:

- Support endpoint strings as `host:port`.
- Support CIDR objects or a strict delimited config representation internally.
- If user-facing CLI/config must be string-based, require bracket syntax for
  IPv6 CIDR ports.
- Treat CIDR without port as broader and document whether that means all TCP
  ports or all protocols.

Do not quietly treat IPv4 and IPv6 differently unless the docs and tests make
that limitation obvious.

## Firewall Architecture

Fence should use iptables/ip6tables first. Direct nftables support should be
deferred until the iptables backend is correct and tested on hosted runners.

### Command Paths

Use fixed absolute command paths where practical:

```text
/usr/sbin/iptables
/usr/sbin/ip6tables
/usr/sbin/iptables-save
/usr/sbin/ip6tables-save
/usr/sbin/iptables-restore
/usr/sbin/ip6tables-restore
/usr/bin/systemctl
/usr/bin/chmod
/usr/bin/truncate
/usr/bin/rm
```

Do not rely on attacker-controlled `PATH`.

### Chains

Use unique per-invocation chain names:

```text
FENCE_<short-policy-or-invocation-id>
```

Requirements:

- Chain names must match a strict safe pattern.
- Avoid static chain names.
- Avoid same-policy collisions inside one workflow run.
- Clean up only Fence-owned chains.
- Do not flush arbitrary user chains.

### Apply Order

The safer apply flow is:

1. Validate support.
2. Resolve DNS.
3. Render firewall plan.
4. Backup firewall state for setup-failure rollback.
5. Create the Fence chain.
6. Populate the Fence chain completely.
7. Insert the jump into `OUTPUT` at position 1.
8. Add Docker `DOCKER-USER` hook where applicable.
9. Verify the active firewall state.
10. Disable sudo/container paths.
11. Mark the agent ready.

The `OUTPUT` jump should not be inserted until the chain is fully populated.
If IPv4 succeeds and IPv6 fails before ready, cleanup or rollback should run.

Longer term, `iptables-restore` and `ip6tables-restore` batch application may
be cleaner than individual commands. Do not jump to that until tests prove the
incremental backend's behavior.

### Baseline Rules

The chain should normally include:

- allow loopback.
- allow established/related traffic.
- allow explicit resolved endpoints.
- allow explicit CIDRs.
- log denied or would-deny new traffic with rate limiting.
- reject or return depending on block/audit mode.

Example block-mode shape:

```text
-A FENCE_x -o lo -j ACCEPT
-A FENCE_x -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FENCE_x -p tcp -d 140.82.112.4/32 --dport 443 -j ACCEPT
-A FENCE_x -m conntrack --ctstate NEW -m limit --limit 30/min --limit-burst 30 -j LOG --log-prefix "FENCE_BLOCK ..."
-A FENCE_x -j REJECT
```

Example audit-mode shape:

```text
-A FENCE_x -o lo -j ACCEPT
-A FENCE_x -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FENCE_x -p tcp -d 140.82.112.4/32 --dport 443 -j ACCEPT
-A FENCE_x -m conntrack --ctstate NEW -m limit --limit 30/min --limit-burst 30 -j LOG --log-prefix "FENCE_AUDIT ..."
-A FENCE_x -j RETURN
```

The exact rule order matters.

## Strict Tamper Evidence

Tamper detection should be strict. It is not enough to verify that expected rules
exist as a subsequence. A malicious root-capable process could insert an early
accept rule while leaving the expected rules intact.

Fence should require:

- Exactly one active `OUTPUT` jump to the current Fence chain.
- The active `OUTPUT` jump must be the first `OUTPUT` rule.
- No extra `OUTPUT` bypass rule before the Fence jump.
- The Fence chain must contain exactly the expected normalized rule sequence.
- No extra early rules.
- No trailing bypass rules.
- No duplicate rules.
- No reordered rules.
- Semantic verification of LOG rules, not prefix-only matching.

Tamper cases that must fail:

```text
iptables -I OUTPUT 1 -j ACCEPT
iptables -I OUTPUT 1 -d 1.2.3.4/32 -j ACCEPT
iptables -I OUTPUT 1 -j RETURN
iptables -I FENCE_x 1 -j RETURN
iptables -A FENCE_x -j ACCEPT
duplicate OUTPUT jump to FENCE_x
LOG prefix unchanged but rate limit removed
LOG prefix unchanged but conntrack state removed
expected rules intact but bypassed by earlier rule
```

Canonicalization matters. iptables may output semantically equivalent rules with
extra tokens, `/32`, `/128`, `-m tcp`, reordered conntrack options, or normalized
addresses. Tests should cover valid canonicalized output so strict verification
does not become brittle.

## Counters And Findings

Kernel logs are useful but lossy:

- dmesg access may be restricted.
- logs may be rate-limited.
- old logs may pollute output.
- logs may be truncated.
- kernel formatting can vary.

iptables counters should be the primary evidence. Kernel logs can enrich
destination-level findings when available.

Recommended finding model:

```json
{
  "source": "counter",
  "scope": "aggregate",
  "destination": "0.0.0.0/0",
  "port": 0,
  "packets": 12,
  "bytes": 3456
}
```

```json
{
  "source": "kernel-log",
  "scope": "destination",
  "destination": "203.0.113.10",
  "port": 443,
  "packets": 1,
  "bytes": 0
}
```

Do not attach aggregate packet/byte totals to the first kernel-log finding.
That makes one destination look responsible for all aggregate traffic.

Fence should cap findings, summaries, and annotations. A malicious build should
not be able to create unbounded logs or huge JSON reports.

## Sudo Lockdown

Sudo should be disabled by default.

The important behavior is:

```text
after Fence is ready, sudo -n true must fail
```

Potential implementation pattern:

- Apply firewall first.
- Verify firewall.
- Remove or truncate the default hosted-runner sudoers grant.
- Confirm `sudo -n true` no longer works.
- Mark lockdown status in the report.

Be very careful with order. If sudo is removed before firewall setup completes,
Fence may strand itself without the ability to enforce or rollback. The
privileged agent should already be running as root and should not depend on
later `sudo` calls once it starts.

Do not restore broad sudo later. Restoring sudo at the end of a job creates a
late privilege window and does not help the security objective on ephemeral
hosted runners.

## Docker And Containerd Lockdown

Disabling sudo alone is insufficient if the runner user can still access Docker
or containerd.

Fence should disable container escape paths by default. Prior art suggests
multiple layers:

- Stop Docker/containerd services where present.
- Mask Docker/containerd services where present.
- Lock known sockets with mode `000`:
  - `/var/run/docker.sock`
  - `/run/docker.sock`
  - `/run/containerd/containerd.sock`
- Remove or restrict runner access to Docker/containerd sockets.
- Remove Docker/containerd state and config paths best-effort.
- Remove Docker apt source/key files best-effort.
- Avoid relying on `apt-get purge`, because hosted image package names and
  package state may vary.

After Fence is ready:

```text
docker ps should fail if Docker is present
containerd socket access should fail if containerd is present
docker run --privileged ... should fail
```

### Compatibility Knob

Some workflows need Docker after Fence starts. If Fence supports this, the knob
must be intentionally ugly and clearly unsafe, for example:

```text
unsafe-allow-docker-after-fence: true
```

or for the agent:

```text
allow_docker_after_fence=true
```

The default should disable Docker/containerd. Sudo should still be disabled even
if Docker compatibility is allowed, unless a future design explicitly chooses
otherwise.

## Docker `DOCKER-USER` Chain

Docker can create network paths that bypass assumptions about host `OUTPUT`.
StepSecurity's agent uses the `DOCKER-USER` chain as part of its enforcement.

Fence should:

- Detect whether Docker chains exist.
- Insert a Fence jump into `DOCKER-USER` where available.
- Make the Fence jump first where possible.
- Verify it stays first.
- Treat Docker-preserved mode as lower assurance.

Open question:

```text
If Docker is disabled by default, how much DOCKER-USER handling is needed?
```

Recommendation:

- Still implement `DOCKER-USER` enforcement if Docker chains exist before
  lockdown.
- Test both Docker-present and Docker-absent hosted images.
- Keep the code defensive and fail closed unless compatibility mode says
  otherwise.

## Agent Lifecycle

The future `fence-action` wrapper may be a Node action with `pre`, `main`, and
`post`, but the Rust agent should own privileged enforcement.

Possible lifecycle:

```text
pre wrapper
  -> parse action inputs
  -> generate strict local config
  -> install committed agent binary to /opt/fence/bin/fence-agent
  -> install systemd service as root
  -> start service
  -> wait for root-owned ready/report file

fence-agent service
  -> validate config
  -> resolve DNS
  -> apply firewall
  -> disable sudo/container paths
  -> write ready
  -> periodically refresh report snapshots
  -> keep running until runner teardown

main wrapper
  -> emit current state outputs

post wrapper
  -> read latest report snapshot
  -> render summary/annotations/JSON
  -> do not restore firewall, sudo, Docker, or containerd
```

The Rust repo can start without the action wrapper. However, agent CLI shape
should anticipate this lifecycle.

## Agent CLI Shape

Keep the CLI narrow.

Suggested commands:

```text
fence-agent --version
fence-agent run --config /run/fence/<id>/config
fence-agent check-support
fence-agent render-plan --config <path>  # optional, for tests/debugging
```

Avoid adding an interactive API or daemon control socket in the first phase.
Control sockets become privileged interfaces. If the only long-running behavior
needed is periodic report refresh, the agent can read config at startup and then
write reports.

The agent should not expose:

- unlock.
- restore.
- disable.
- flush.
- add allow rule.
- arbitrary command execution.

## Config Format

The config format is a major security surface.

Options:

### Minimal line-based config

Example:

```text
version=1
invocation_id=4f9a0db6c4e8442a
mode=block
policy_hash=sha256:...
chain=FENCE_4f9a0db6c4e8442a
allow_docker_after_fence=false
ready_path=/run/fence/4f9a0db6c4e8442a/ready.json
report_path=/run/fence/4f9a0db6c4e8442a/report.json
allow_endpoint=github.com|443
allow_cidr=192.0.2.0/24|443|4
```

Benefits:

- Can be parsed with the Rust standard library.
- No YAML/TOML/JSON parser dependency.
- Small attack surface.
- Easy strict unknown-key rejection.

Costs:

- Less ergonomic for humans.
- Needs careful escaping rules or must reject values that need escaping.

### JSON or TOML config

Benefits:

- More standard.
- Easier to evolve.
- Better tooling.

Costs:

- Adds dependencies.
- Adds parser behavior to audit.
- Requires vendoring and strict schema validation.

Recommendation:

Start with a minimal, strict, line-based or other std-only config for v0.0.x.
Fence is an agent, not a human-authored policy language. The future action
wrapper can handle friendly input parsing and write strict agent config.

If JSON/TOML is chosen, vendor the exact dependency versions, reject unknown
fields, and test malicious/ambiguous input heavily.

## Root-Owned Runtime Layout

Use a root-owned per-invocation directory:

```text
/run/fence/<invocation-id>/
  config
  ready.json
  report.json
  iptables.backup
  ip6tables.backup
```

Permissions:

```text
/run/fence                    root:root 0755 or stricter
/run/fence/<invocation-id>    root:root 0700
files                         root:root 0600 unless wrapper must read
report snapshots              consider 0644 only if post wrapper runs unprivileged
```

Be intentional about read access. If the post wrapper must read reports after
sudo is disabled, reports may need to be world-readable or copied into a
runner-readable path. That is acceptable only if reports contain no secrets and
paths are validated.

Do not put secret unlock tokens in runner-readable state. The current direction
is to avoid unlock tokens entirely.

## State Integrity

If a future action wrapper stores any runner-temp state, it should:

- Include a per-invocation ID.
- Store a SHA-256 digest through GitHub action state.
- Verify the digest before loading in post.
- Fail closed if the state file changed.
- Validate all paths before use.
- Avoid storing privileged paths that can unlock enforcement.

Runner-temp state should be treated as attacker-writable after Fence starts.
It can be useful for summaries, but it is not a root trust anchor.

The root agent's own trust anchor should be root-owned files and active kernel
state, not user-writable JSON.

## Reports

Reports should be local only.

Suggested report fields:

```json
{
  "schema_version": 1,
  "agent": {
    "name": "fence-agent",
    "version": "0.0.1",
    "status": "running"
  },
  "invocation_id": "4f9a0db6c4e8442a",
  "mode": "block",
  "policy_hash": "sha256:...",
  "chain": "FENCE_4f9a0db6c4e8442a",
  "platform": {
    "os": "linux",
    "arch": "x64",
    "runner": "github-hosted-ubuntu"
  },
  "lockdown": {
    "sudo": "disabled",
    "docker": "disabled",
    "containerd": "disabled"
  },
  "firewall": {
    "ipv4": "applied",
    "ipv6": "applied",
    "docker_user": "applied"
  },
  "tamper": [],
  "findings": [],
  "resolved_endpoints": [],
  "generated_at": "2026-01-01T00:00:00Z"
}
```

Reports must not contain:

- secrets.
- restore tokens.
- raw environment dumps.
- full process lists.
- unbounded logs.
- arbitrary dmesg output.
- local machine-specific details that are not needed for debugging.

Reports should distinguish:

- active enforcement state.
- tamper evidence.
- aggregate counters.
- destination-level kernel-log hints.
- unsupported/skipped platform status.

## Hermetic Rust Repository Shape

Fence should borrow the hermetic Rust patterns already used in the maintainer's
Rust template work:

- `rust-toolchain.toml` pins the toolchain.
- `Cargo.lock` is committed.
- Dependencies are vendored under `vendor/cache`.
- Cargo is configured for offline builds.
- Scripts are repo-owned and deterministic.
- CI proves the committed binary is fresh.

Suggested layout:

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
.cargo/config.toml
src/
  main.rs
  cli.rs
  config.rs
  command.rs
  dns.rs
  firewall.rs
  lockdown.rs
  platform.rs
  report.rs
  state.rs
  support.rs
tests/
  cli.rs
  fixtures/
script/
  bootstrap
  test
  lint
  build
  package
  vendor
  verify-binary
vendor/
  cache/
dist/
  linux-x64/
    fence-agent
    fence-agent.sha256
docs/
  idea.md
```

If the first implementation is std-only, `vendor/cache` may be empty or absent
initially. The repo should still be prepared for offline dependency handling if
dependencies are added later.

Suggested `.cargo/config.toml` once dependencies are vendored:

```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor/cache"

[net]
offline = true
```

## Dependency Strategy

Prefer Rust standard library for the first agent.

Reasoning:

- The agent runs as root.
- The parser surface should be tiny.
- The first target is Linux only.
- Firewall and lockdown commands can be rendered with std types.
- JSON output can be written carefully with small helpers if the data model is
  simple, or a vendored `serde_json` can be introduced deliberately later.

If dependencies are introduced, each one needs a security reason. Good
candidates may eventually include:

- `serde` and `serde_json` for safer report serialization.
- `tempfile` for tests only.
- a small CIDR/IP network crate if std-only parsing becomes too error-prone.

Avoid:

- async runtimes in v0.0.x.
- HTTP clients.
- TLS libraries.
- DNS resolver crates unless the std resolver proves insufficient.
- broad CLI frameworks unless the CLI grows beyond a few flags.

## Build And Binary Freshness

Fence is allowed to ship a committed binary only if the repository proves it was
built from source.

Recommended behavior:

- Build `x86_64-unknown-linux-musl` or another clearly documented Linux x64
  target.
- Store the binary at `dist/linux-x64/fence-agent`.
- Store `dist/linux-x64/fence-agent.sha256`.
- CI rebuilds from source and fails if the committed binary or checksum differs.
- Release workflow performs the same rebuild and freshness check.
- Release workflow uploads archive and checksum artifacts.
- Release workflow creates artifact attestations.

Possible release profile:

```toml
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = "symbols"
opt-level = "z"
```

For reproducibility, investigate:

- `SOURCE_DATE_EPOCH`.
- path remapping with `--remap-path-prefix`.
- stable target image.
- pinned Rust toolchain.
- no build scripts if avoidable.

Perfect byte-for-byte reproducibility may take effort. The immediate goal is
CI freshness from source for the committed artifact.

## CI Rules

Fence is security-sensitive. CI should be boring and strict.

Recommended:

- No dependency caches in release workflows.
- Consider no dependency caches in all workflows, especially while the project
  is young.
- Full SHA-pin third-party GitHub Actions.
- Read-only permissions for read-only jobs.
- `persist-credentials: false` on checkout where possible.
- No `pull_request_target`.
- No secrets in PR jobs.
- Privileged integration tests should be explicitly reviewed if they run on PRs.
- Release job should use a protected environment.
- Release job should verify committed binary freshness.
- Release job should generate artifact attestations.

For the future action wrapper:

- Use `npm ci --ignore-scripts`.
- Keep committed `dist/` freshness checks.
- Do not use Actions dependency caches in release paths.

## Coverage Expectations

Fence should have excellent test coverage because it is security-sensitive.

That said, avoid unstable or misleading metrics. Prior Rust-template guidance
favored strong, stable coverage gates over brittle branch-coverage gates when
the tooling is unstable.

Recommended:

- Unit tests for every parser and planner edge case.
- Function/line/region coverage via a pinned coverage tool if used.
- Integration tests for privileged behavior on hosted Ubuntu.
- Mutation-style attacker simulations for the bypass classes that matter.
- Golden tests for firewall rule rendering and verification.
- Regression tests for rejected features such as policy files and remote
  downloads if they become relevant in a wrapper repository.

Coverage should be a quality bar, not theater. A small amount of untested root
command execution glue may be acceptable if all command planning and parsing is
well-covered and privileged integration tests exercise the real flow.

## Rust Unit Test Plan

The Rust agent should include unit tests for:

Config parsing:

- Unknown keys rejected.
- Duplicate singleton keys rejected.
- Missing required keys rejected.
- Invalid mode rejected.
- Invalid invocation ID rejected.
- Invalid chain name rejected.
- Unsafe paths rejected.
- Endpoint without port rejected.
- Endpoint with wildcard rejected.
- Endpoint with URL scheme rejected.
- Endpoint with path/query/fragment rejected.
- IPv6 endpoint bracket parsing.
- CIDR parser handles IPv4 and IPv6.
- IPv6 CIDR-with-port ambiguity rejected unless bracket syntax is implemented.

DNS planning:

- Endpoint cap enforced.
- Address cap enforced.
- Timeout error fails before firewall mutation.
- Duplicate addresses deduplicated.
- Addresses sorted deterministically.
- IPv4/IPv6 separation correct.

Firewall rendering:

- Loopback allow rule rendered.
- Established/related allow rule rendered.
- Endpoint allow rules rendered.
- CIDR allow rules rendered.
- Block-mode terminal reject rendered.
- Audit-mode terminal return rendered.
- LOG rate limit rendered.
- IPv4 and IPv6 rule families separated.
- Docker `DOCKER-USER` plan rendered when applicable.
- Empty allowlist creates no-egress plan.

Firewall verification:

- Valid canonical iptables output passes.
- `/32` and `/128` canonicalization passes.
- `-m tcp` insertion passes.
- Conntrack state ordering normalization passes.
- Early `OUTPUT ACCEPT` fails.
- Early `OUTPUT RETURN` fails.
- Early destination-specific `OUTPUT ACCEPT` fails.
- Duplicate `OUTPUT` jump fails.
- Missing `OUTPUT` jump fails.
- Jump not first fails.
- Early chain `RETURN` fails.
- Trailing chain `ACCEPT` fails.
- Missing rule fails.
- Reordered rule fails.
- Duplicate chain rule fails.
- LOG prefix-only tamper fails.
- LOG limit removal fails.
- LOG burst removal fails.
- LOG conntrack removal fails.

Counter and log parsing:

- iptables-save counters parsed.
- Aggregate counter findings produced.
- Kernel-log findings parsed when available.
- Malformed kernel log ignored safely.
- Aggregate bytes not assigned to a single destination.
- Finding cap enforced.

Lockdown planning:

- Sudoers lockdown command plan correct.
- Docker service stop/mask plan correct.
- Socket chmod plan correct.
- Missing Docker socket handled.
- Missing systemctl handled according to support policy.
- Compatibility mode preserves Docker/containerd plan while still disabling
  sudo.

Report rendering:

- Valid JSON generated.
- Strings escaped.
- No token fields exist.
- No raw environment dump exists.
- Findings include `source` and `scope`.
- Unsupported/skipped status represented.

## Hosted Ubuntu Integration Test Plan

Privileged integration tests should run on GitHub-hosted Ubuntu x64.

Tests should cover:

Default startup:

- Fence starts successfully.
- Agent writes ready file.
- Agent writes report file.
- Firewall chain exists.
- `OUTPUT` jump is first.
- Chain matches expected normalized sequence.

Lockdown:

- `sudo -n true` fails after ready.
- `sudo iptables -F` fails after ready.
- unprivileged `iptables -F` fails.
- Docker access fails if Docker exists.
- containerd socket access fails if containerd exists.
- `docker run --privileged ...` fails if Docker exists.

Network behavior:

- Declared endpoint succeeds.
- Undeclared endpoint fails in block mode.
- Empty user allowlist blocks new outbound traffic.
- DNS is frozen after initial resolution.
- Audit mode reports would-block traffic without blocking if audit mode ships.

Attacker simulations:

- Try to flush iptables with sudo.
- Try to insert early `OUTPUT ACCEPT`.
- Try to insert destination-specific bypass.
- Try to insert early `RETURN` in the Fence chain.
- Try to use Docker privileged container escape.
- Try to use containerd socket.
- Try to mutate runner-temp wrapper state.
- Verify denied egress still fails after these attempts.
- Verify report shows tamper or failed attempts where observable.

Lifecycle:

- Post/report step succeeds without restoring network.
- Later broad sudo remains disabled.
- Docker/container access remains disabled.
- GitHub job finalization still works for the tested workflow shape.

The last point is important. Strict no-restore security is only useful if the
workflow can still produce enough logs and reports for users to understand what
happened.

## Future `fence-action` Wrapper

Fence should not require a TypeScript action wrapper to develop the agent, but
the wrapper is likely the user-facing entry point later.

Expected wrapper responsibilities:

- Parse action inputs.
- Validate policy before installing agent.
- Resolve or pass hostnames depending on final agent design.
- Write strict agent config.
- Install committed `fence-agent` binary as root.
- Install and start systemd service.
- Wait for ready file.
- Emit action outputs.
- Render summaries/annotations from local report.
- Write optional local JSON report.

Wrapper should not:

- implement privileged firewall logic itself.
- store unlock tokens.
- restore firewall.
- restore sudo.
- restore Docker.
- fetch remote policy.
- download agent binaries.
- upload reports.

Action lifecycle must use a real remote-ref workflow to test `runs.pre`.
Local `uses: ./` testing is not enough because GitHub Actions has lifecycle
limitations for local actions.

## Branch Deploy And IssueOps

Fence can work with IssueOps and `github/branch-deploy`, but only if policy is
fixed in the trusted workflow.

Important rule:

```text
Issue comments, branch names, PR files, and command parser outputs must not
choose Fence mode, DNS mode, allowed endpoints, or allowed CIDRs.
```

Secure Branch Deploy shape:

```text
branch-deploy gate
-> Fence with fixed inline policy from default-branch workflow
-> checkout deploy target SHA
-> deploy
```

Recommended Branch Deploy posture:

- `allow_forks: "false"`.
- `commit_verification: "true"`.
- `deployment_confirmation: "true"` for production or open-source flows.
- keep `allow_sha_deployments: "false"`.
- avoid `skip_ci`.
- avoid `skip_reviews`.
- avoid broad `ignored_checks`.
- pin `github/branch-deploy`, `fence-action`, and `actions/checkout` by SHA.
- use protected environments for secret-bearing deploys.

Because policy files are out of scope, the safe policy source is the trusted
workflow file itself.

## Supported Platform Detection

Fence v0.0.x should support only:

```text
GitHub-hosted Ubuntu x64
```

Support checks should include:

- OS is Linux.
- Architecture is x86_64.
- Running under GitHub Actions.
- Runner looks like hosted Ubuntu, not self-hosted.
- Required commands exist at expected paths.
- iptables/ip6tables are usable.
- systemd is available if service lifecycle depends on it.
- sudoers layout is compatible if disabling sudo.

Unsupported platforms should fail closed unless a wrapper explicitly chooses an
`allow-unsupported` skip mode. If skipped, reports should say enforcement was
skipped, not silently imply protection.

Do not claim support for:

- Ubuntu ARM.
- `ubuntu-slim`.
- self-hosted runners.
- ARC.
- macOS.
- Windows.
- job containers.

Add platforms only when binaries, docs, support checks, and privileged
integration tests land together.

## Failure Modes

Fence should fail before mutation when:

- Config is invalid.
- DNS resolution fails.
- DNS resolution times out.
- Endpoint/address caps are exceeded.
- Required commands are missing.
- Platform unsupported and not explicitly skipped.

Fence should rollback setup if:

- Firewall mutation starts but fails before ready.
- IPv4 succeeds but IPv6 setup fails before ready.
- Docker chain setup fails before ready and the policy treats it as required.

Fence should fail closed after ready when:

- Tamper is detected.
- Report generation fails in a way that prevents knowing enforcement status.
- The agent cannot verify its active chain.

Do not create a broad post-restore path for after-ready failures. The strict
model leaves the runner locked.

## Command Execution Rules

The agent will run as root, so command execution must be strict:

- Use absolute command paths.
- Use argument arrays, not shell strings.
- No `sh -c` unless there is no alternative and the input is fully static.
- No `eval`.
- No user-controlled command names.
- No user-controlled file paths outside validated roots.
- Clear environment where practical.
- Bound command timeouts.
- Capture stdout/stderr with size limits.
- Treat command failure as structured error.

For tests, separate command planning from command execution. Most logic should
be testable without root.

## Public Documentation Tone

Fence docs should be direct and honest.

Good phrasing:

```text
Fence hardens the default GitHub-hosted Ubuntu runner privilege model by
applying egress controls and removing passwordless sudo and container access
before later workflow steps run.
```

Good caveat:

```text
Fence is not a kernel sandbox. A kernel exploit, GitHub platform compromise, or
abuse of explicitly allowed endpoints remains out of scope.
```

Avoid:

- "airtight"
- "impossible to exfiltrate"
- "SLSA L3"
- "zero trust" unless precisely defined
- "full sandbox"
- "guaranteed containment"

## Example User-Facing Policy

For a future action wrapper, the safest quickstart should be inline:

```yaml
permissions:
  contents: read

steps:
  - uses: GrantBirki/fence-action@<pinned-sha>
    with:
      mode: block
      allowed-endpoints: |
        github.com:443
        api.github.com:443

  - uses: actions/checkout@<pinned-sha>
    with:
      persist-credentials: false

  - run: ./script/test
```

This keeps the policy in the trusted workflow and allows Fence to run before
checkout. It also makes the user explicitly choose GitHub endpoints rather than
receiving a hidden baseline.

## Security Regression Tests

Fence should include tests that fail if risky features appear.

Examples:

- No StepSecurity API hosts.
- No StepSecurity telemetry strings.
- No subscription/private-repo check strings.
- No runtime binary download code.
- No remote policy URL support.
- No policy file support.
- No unlock token support.
- No broad sudo restoration path.
- No Docker restoration path.
- No action workflow `pull_request_target` if action wrapper exists.
- No GitHub Actions dependency caches in release workflow.
- No unpinned third-party actions in workflows.
- No hidden/bidirectional Unicode control characters in source, docs, scripts,
  workflows, or generated artifacts.

For a standalone Rust repo, these can be simple text-level tests plus script
checks.

## Release Model

The first release model should be conservative:

- Version controlled in a source file.
- Release job runs from protected main or protected tags.
- Release job uses a protected environment.
- Release job uses no dependency cache.
- Release job rebuilds the binary from source.
- Release job verifies committed binary freshness.
- Release job verifies checksums.
- Release job creates a release archive.
- Release job emits artifact attestations.

If Fence later provides a GitHub Action, exact-SHA consumers should be able to
use the repository without downloading runtime binaries. That means committed
action assets and committed agent binaries must be kept fresh.

## Suggested Implementation Sequence

### Milestone 0: Repository Constitution And Skeleton

- Add AGENTS.md with the security constitution.
- Add this idea document.
- Add Rust workspace skeleton.
- Add pinned toolchain.
- Add scripts.
- Add initial CI.
- Decide std-only vs minimal vendored dependencies.

### Milestone 1: Config And Planning

- Implement config parser.
- Implement endpoint/CIDR validation.
- Implement policy hashing.
- Implement DNS abstraction.
- Implement firewall plan rendering.
- Add comprehensive unit tests.

### Milestone 2: Firewall Backend

- Implement iptables/ip6tables command runner.
- Implement backup for setup rollback.
- Implement apply flow.
- Implement strict verification.
- Implement counter parsing.
- Add privileged integration smoke tests.

### Milestone 3: Lockdown Backend

- Implement sudo lockdown.
- Implement Docker/containerd lockdown.
- Implement compatibility knob if needed.
- Add hosted Ubuntu integration tests for sudo/Docker/container attacks.

### Milestone 4: Reporting

- Implement report snapshots.
- Implement bounded findings.
- Implement tamper reporting.
- Implement JSON output.
- Add report schema tests.

### Milestone 5: Packaging

- Build Linux x64 binary.
- Commit binary and checksum.
- Add binary freshness check.
- Add release archive and attestation workflow.

### Milestone 6: Action Wrapper

- Build `fence-action` wrapper later, after the agent boundary is proven.
- Keep wrapper thin.
- Use remote-ref lifecycle tests to prove `pre/main/post`.

## Major Open Questions

These should be resolved deliberately:

1. Does Fence permanently leave firewall locked after ready, or is there any
   safe restore story?

2. If no restore, what exact explicit GitHub endpoints are needed for common
   workflow finalization? Should docs provide examples without making them a
   hidden baseline?

3. Should audit mode ship in the first agent, or should v0.0.x be block-only
   until enforcement is stable?

4. Should the agent resolve DNS itself, or should a future wrapper resolve and
   pass IPs? Agent-side resolution keeps privileged enforcement self-contained,
   but wrapper-side resolution can simplify tests.

5. Is a std-only config/report writer worth the manual JSON escaping risk, or
   should the repo vendor `serde_json` immediately?

6. How should Docker-preserved compatibility mode interact with `DOCKER-USER`
   enforcement?

7. Should Fence fail if IPv6 enforcement is unavailable, or allow IPv4-only
   enforcement with an explicit warning? The secure default should probably fail
   closed.

8. How much of StepSecurity's Docker/containerd cleanup should be mirrored
   exactly, and what should be adapted for maintainability?

9. What does the first public alpha promise? Be very careful not to overstate
   it.

## Things Another Agent Should Read Before Implementing

Another implementing agent should inspect:

- StepSecurity Harden-Runner action metadata.
- StepSecurity open-source Linux agent, especially firewall and
  sudo/container lockdown behavior.
- GitHub hosted runner docs for passwordless sudo.
- GitHub Actions event and action lifecycle docs.
- SLSA Build requirements and threat docs.
- The maintainer's Rust template patterns for hermetic builds, vendoring,
  coverage, and release scripts.

Useful public references:

- StepSecurity Harden-Runner: https://github.com/step-security/harden-runner
- StepSecurity Linux agent: https://github.com/step-security/agent
- Harden-Runner docs: https://docs.stepsecurity.io/harden-runner
- GitHub-hosted runners: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- GitHub action metadata syntax: https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax
- GitHub events that trigger workflows: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- SLSA v1.2 Build requirements: https://slsa.dev/spec/v1.2/build-requirements
- SLSA v1.2 threats: https://slsa.dev/spec/v1.2/threats
- GitHub artifact attestations: https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
- actions/attest: https://github.com/actions/attest
- github/branch-deploy: https://github.com/github/branch-deploy

Important: prior art is not a license to copy blindly. If code is copied from
Apache-2.0 sources, preserve notices and attribution. Prefer in-house code where
the behavior is straightforward.

## Final Handoff Summary

Fence should be a small, hardened Rust root agent. Its value is not a prettier
allowlist parser. Its value is closing the default GitHub-hosted runner escape
path that makes egress-only actions weak:

```text
passwordless sudo + Docker/containerd access
```

The first credible version should prove:

- explicit egress policy works.
- sudo is disabled after enforcement.
- Docker/containerd access is disabled after enforcement.
- firewall tamper is detected strictly.
- no privileged unlock token exists.
- reports are local and bounded.
- the committed binary is built from source and verified in CI.
- the project has no telemetry, no remote policy, and no runtime binary
  downloads.

If Fence can do that narrowly and honestly on GitHub-hosted Ubuntu x64, it will
be a strong foundation for a future `fence-action`.
