# Fence Security Review

## Scope

This review covers the v0 Linux agent, DNS-mediated selected platform profile,
native `nftables` and NFLOG boundaries, root-owned runtime storage, hosted
lockdown controls, bundled Action wrapper, release provenance workflow, and
offline validation scripts as of June 2026.

This document records focused review findings. The current trust assumptions,
attacker capabilities, abuse paths, and residual-risk priorities are defined in
the frozen [`threat-model.md`](threat-model.md); normative behavior and schemas
remain in [`v0.md`](v0.md).

Fence intentionally supports only GitHub-hosted `ubuntu-24.04` x64 host jobs.
Standard block mode reduces arbitrary outbound egress, disables measured
passwordless sudo and container-control paths, and keeps resident controls
active until ephemeral runner teardown. It does not claim sandboxing, kernel
isolation, or elimination of every exfiltration channel. The selected GitHub
workflow-bootstrap profile and its bounded DNS mediation remain disclosed
channels that later workflow code may use. The exact `github.com`,
`api.github.com`, `release-assets.githubusercontent.com`, the optional exact
watchdog root, and up to eight single-label `*.githubapp.com` names are
intentional compatibility exceptions by default. Workflows may set
`disable_broad_github_domains: true` to remove those broad GitHub channels while
keeping core Actions status and finalization endpoints available. GitHub
results storage has one exact static compatibility root,
`productionresultssa19.blob.core.windows.net`; Fence may additionally authorize
at most four exact matching accounts requested by the pinned `Runner.Worker`
process. Every approved answer remains withheld until its TCP `443` rule is
applied and verified.

## Release Provenance

Release builds upload Linux x64 artifacts, generate GitHub artifact
attestations in a dedicated least-privilege job, re-download immutable release
assets, verify checksums, and bind each attestation to the repository release
workflow at the release source commit on `refs/heads/main`. The committed
Action binary is installed only through the online maintainer refresh script,
which also requires a non-draft immutable release and a tag resolving to that
source commit before writing the reviewed offline manifest. See GitHub's
[artifact attestation documentation](https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).

## Findings Addressed

### DNS TCP client deadlines

The local TCP DNS listeners previously served connections serially without a
client read deadline. A local workflow process could hold a connection open and
strand subsequent TCP DNS requests on that listener. Accepted client sockets,
upstream TCP connects, upstream reads, and upstream writes now use bounded
deadlines. This limits accidental stalls and bounds one connection attempt.

### DNS upstream response binding

The UDP mediator previously accepted the first datagram received on its
ephemeral upstream socket without binding the socket to the fixed resolver or
checking the transaction identifier. The mediator now connects the UDP socket
to the fixed resolver and rejects UDP or TCP responses whose identifier does
not match the mediator-owned upstream query.

### Docker DNS configuration file safety

The provisional Docker DNS rewrite previously read the existing daemon
configuration through an unbounded path-following file read. Existing input is
now opened with no-follow, close-on-exec, and non-blocking flags; non-regular,
symlink, and oversized files fail closed. Replacement refuses non-regular or
symlink destinations and validates the opened output file before writing.

### Bounded fixed-command execution

DNS routing setup previously waited indefinitely for fixed `systemctl` and
`resolvectl` subprocesses. The trusted-launcher `systemctl show MainPID`
identity query also used an unbounded wait. Those commands now have fixed
execution deadlines and are killed on timeout.

### Bounded nftables subprocess input

The native `nftables` executor previously wrote its generated program to child
stdin before beginning deadline enforcement. A child that stopped reading
could block that write indefinitely. Stdin writing now occurs in a joined
worker while the parent enforces the command deadline and kills a stalled
child.

### NFLOG attribute ambiguity

The NFLOG parser previously accepted duplicate payload or prefix attributes and
could ignore trailing bytes outside aligned attributes. It now rejects those
ambiguous event shapes before approved metadata extraction.

### Bounded local incident attribution

Retained NFLOG findings can now be correlated with a unique local Linux socket
owner through bounded `/proc` snapshots. Fence records only attribution status,
actor class, PID, executable basename, and at most four parent executable
basenames. The worker has fixed queue, socket, process, and file-descriptor
limits and is supervised with the other resident workers. Local socket tuples
remain internal, and Fence does not record command arguments, full paths,
environments, working directories, payloads, or telemetry.

### Sudo policy source file type

The hosted-runner fingerprint path previously bounded sudo policy bytes and
rejected symlinks but did not require a regular file after opening. Policy
sources now use a non-blocking open and fail closed unless the opened object is
a bounded regular file.

### Exact hosted sudo-policy variants

Fresh hosted evidence has shown additional exact digests for the fixed `90-cloud-init-users` sudo-policy source. During a later mixed image rollout, three independent hosted VMs on the new image matched one additional digest while a separate older-image control retained an already accepted variant; after excluding non-enforced volatile device, inode, PID, and start-time identifiers, the complete bounded observations were otherwise identical. The fingerprint accepts each observed digest only as an additional exact value and retains the same source name, regular-file, ownership, mode, non-writability, marker, unit, socket, resolver, principal, group, and local-control checks.

### Effective sudo and trusted-path access

The production fingerprint previously relied on ownership and ordinary mode
metadata without proving the runner's effective access after ACL processing.
Fingerprint schema `2` now records every trusted executable, its reviewed
ancestor directories, and every accepted sudo source. Before mutation, Fence
uses descriptor-pinned `sudo` and descriptor-pinned `/usr/bin/test` to require
that the runner cannot write any of those paths, can execute the fixed commands
and searchable ancestors, and cannot search `/etc/sudoers.d`. Each probe is
bound to exact path or policy identity immediately before and after execution,
followed by a full trusted-executable and sudo-inventory recheck. Disposable
hosted evidence adds an ACL that grants runner search without changing the
root-owned directory's accepted `0750` mode and proves the effective-access
check rejects it before readiness or mutation.

### Descriptor-pinned privileged commands

Security-critical host commands previously executed reviewed absolute paths
after a metadata check, leaving a path replacement window between validation
and execution. Fence now captures the twelve accepted root-owned command files
with no-follow, close-on-exec descriptors and revalidates canonical path,
device, inode, owner, group, and mode before every use. Root commands execute
the captured inode through `/proc/self/fd`; effective runner probes use pinned
outer sudo to execute the pinned target without a raw-path fallback. Standard
descriptors are reserved throughout capture and retained executable descriptors
must be at least `3`. The sudo transport requires the transient service to have
no controlling terminal, and hosted audit evidence exercises that path.

This provides forward identity under the first-step and trusted hosted-image
assumptions. It does not hash or authenticate pre-capture bytes, same-inode
modification by an already privileged process, the dynamic loader or shared
libraries, or a malicious root/platform component.

### Closed local root-control inventory

Standard lockdown previously verified only named Docker/containerd units and
sockets, so an additive rootful control endpoint outside that fixed list could
escape the support gate. Three corrected same-image observations supplied one
stable, within-bounds, reachability-complete, and ownership-complete reference.
Fingerprint schema `2` now accepts the exact two root container identities,
wildcard IPv4/IPv6 TCP port `22` listeners, and ten domain-separated Unix
listener identities with reviewed owner sets and multiplicities.

Production re-observes that inventory before mutation. Standard block may only
remove accepted container processes or owners, plus the exact
fingerprint-tagged Docker Unix listener after its reviewed `dockerd` owner has
exited and the accepted socket unit is stopped. If that listener remains, its
non-container owners and multiplicity remain exact. Fence then pins the
verified reduction as its resident baseline; audit and degraded block require
the full exact reference. The baseline is checked again before readiness and
every five seconds afterward. Relative filesystem socket names, incomplete
ownership, unavailable or unreviewed root identity, collection bounds,
unreviewed reductions, additive endpoints, and post-ready drift fail closed.
Filesystem reachability probes are limited to possible root-control candidates,
capped at forty, and share a five-second deadline so nonroot socket volume
cannot create unbounded privileged probes. Hosted rejection evidence covers an
unexpected pre-ready root listener and a separate post-ready listener that
makes resident health permanently critical.

### In-memory pre-ready rollback and no-restore commit

The accepted runner sudo source is now captured only in bounded memory and
compared exactly again before removal. Pre-ready rollback recreates it with
exclusive no-follow creation and verifies bytes, mode, ownership, digest,
complete policy inventory, `visudo`, and uncached runner capability. Sudo and
container rollback are attempted independently and dual failures are
aggregated. Once readiness is created, the control enters an explicit
no-restore state before any later fallible report update, and every rollback
attempt is rejected.

### Source-before-bundle host compatibility

The published bundle exposes fingerprint schema `2`. Action acceptance recursively validates the bounded schema-`4` live observation and compares every enforced executable, ancestor, effective-access, resolver, sudo source, principal, group, unit, socket, workload, and local-control fact before destructive activation. The current transition set is empty, so the bundle must activate normally. A future immutable bundle may temporarily predate one newly source-accepted hosted-runner sudo-policy digest even though source-built integration already accepts and tests that host shape. The classifier may skip activation only when all non-digest schema-`2` facts match and every mismatched digest is explicitly listed in the checked-in transition file. Malformed, incomplete, and unknown drift fails. After a refreshed bundle includes the digest, classification automatically returns to normal bundled activation.

### Invocation slug consistency

The Action wrapper rejected consecutive hyphens in invocation identifiers,
while several Rust validators accepted them. The Rust configuration, runtime,
and service validators now enforce the same lowercase internal-hyphen grammar
as the wrapper.

### DNS evidence write propagation

Late DNS observation report write failures were previously ignored by the
proxy threads. The recorder now retains a failure flag that resident audit or
block verification converts into a bounded critical finding in the primary
report.

### DNS answer and firewall activation ordering

The DNS mediator previously waited for an approved HTTPS address to enter the
owned `nftables` ruleset but returned the upstream answer before the verified
firewall update was active. Block mode now submits bounded materialization
requests to the single resident firewall owner and releases an approved address
answer only after that owner applies and structurally verifies the matching
rules. Address-bearing responses are all-or-nothing: every returned address
must be materializable before any answer is released. An approved zero-TTL
address receives a one-second materialization lifetime, and a valid zero-TTL
CNAME edge receives a one-second effective lineage lifetime, before the
existing refresh overlap. Partial coverage, queue rejection, service disconnection, or
an explicit failed result returns a minimal retryable `SERVFAIL` response. The
response contains the original DNS question but no answer, authority,
additional, or raw upstream data. Rejections increment bounded warning
evidence; backend apply and verification failures remain critical findings.

### Response-local DNS alias authorization

CNAME retention previously evaluated every answer edge against process-wide
hostname authorization. An unrelated answer owner that was independently
allowed could therefore seed a derived authorization unrelated to the echoed
question. Fence now parses each complete DNS response once and accepts only one
linear, acyclic alias chain rooted at that question. Every CNAME must belong to
the chain, every address must belong to its terminal name, and the chain keeps
the queried root's origins and transports even if an intermediate name is also
directly allowed. Address records must match the echoed question family, and
duplicate terminal endpoints use the minimum TTL. Conflicts, cycles, unrelated
records, self-referential aliases, invalid depth, and capacity failures reject the whole
block-mode response without committing partial state. In block mode, valid
derived authorization is committed only
after the address rules are applied and verified. Audit may forward invalid
upstream data but does not retain authorization from it. A fully rooted CNAME
response with no address records is forwarded as address-family NODATA and
retains no derived authorization in either mode.

The resident firewall owner rechecks queued block responses in order against a
cloned authorization state before rendering any replacement. Stale, expired,
or over-capacity transactions contribute no candidate address rules. After
successful structural verification, the owner publishes the candidate
authorization and active-materialization states before reporting success to
the DNS worker. Validation-time expiry is absolute and is not restarted by
queue delay.

### Runner-bound results-storage authorization

GitHub's runner uploads job logs and summaries to signed Azure Blob URLs. A
static numeric account list would be brittle, while a general
`*.blob.core.windows.net` rule would authorize unrelated globally registered
storage accounts. Fence instead routes host DNS directly to its local mediator,
pins the unique reviewed `Runner.Worker` identity, and authorizes at most four
exact `productionresultssa<digits>.blob.core.windows.net` accounts only when a
matching host DNS socket belongs to that pinned process. PID reuse, executable
replacement, ambiguous ownership, Docker-originated requests, and ordinary
workflow-process requests fail closed. The DNS answer remains withheld until
TCP `443` access is atomically applied and structurally verified.

The exact `productionresultssa19.blob.core.windows.net` account is a deliberate
compatibility exception published in [GitHub's Actions domain
inventory](https://api.github.com/meta). It is
available without process attribution, while every other matching account
continues to require the runner-bound authorization above. Fence does not allow
the general Azure Blob suffix.

### Action child-process deadlines and dependency surface

The Action launcher previously had no timeout for fixed privileged subprocess
calls. It now enforces a bounded deadline. The wrapper source is also
dependency-free TypeScript executed directly through Node 24 built-in type
stripping. Its unit suite uses Node's built-in `node:test` and `node:assert`
modules. Fence does not carry an npm dependency tree, install Node packages, or
compile TypeScript at workflow runtime. See Node's
[built-in TypeScript documentation](https://nodejs.org/docs/latest-v24.x/api/typescript.html#type-stripping).

## Residual Risks And Boundaries

- Approved GitHub workflow-bootstrap DNS and HTTPS channels remain available to
  later workflow code and therefore remain possible exfiltration channels. By
  default this includes `github.com`, `api.github.com`,
  `release-assets.githubusercontent.com`, the optional exact watchdog root, and
  up to eight single-label `*.githubapp.com` names;
  `disable_broad_github_domains: true` removes those broad channels but retains
  core Actions status/finalization channels.
- Explicit user wildcard patterns authorize at most eight concrete names per
  invocation across all patterns. Each wildcard matches exactly one DNS label,
  but the admitted query labels, matching HTTPS destinations, shared resolved
  addresses, and bounded external CNAME descendants remain exfiltration
  channels. Fence validates DNS structure rather than registrable-domain
  ownership and carries no public-suffix database.
- The exact `productionresultssa19.blob.core.windows.net` account is always a
  reachable TCP `443` compatibility channel. Other matching results-storage
  accounts remain runner-authorized and bounded.
- An exact GitHub results-storage account authorized for the pinned runner is
  also reachable by later workflow code at its resolved HTTPS addresses. Fence
  does not inspect signed URLs, credentials, or encrypted request content.
- The fixed upstream DNS resolver remains a trusted platform dependency. Fence
  bounds, canonicalizes, and filters requests and validates response source and
  transaction identity, but does not add DNSSEC validation.
- [Azure documents `168.63.129.16`](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16)
  as its fixed platform virtual address for DNS, VM-agent, and health
  communication. Fence permits its root-resident DNS mediator to reach UDP `53`
  and UID `0` host traffic to reach WireServer TCP `80` and `32526`. The latter is a dedicated platform-service rule class, not a workflow or user allowance. Unprivileged and forwarded traffic does not match it. A separate shared platform rule permits host and forwarded traffic to Azure IMDS at `169.254.169.254` on TCP `80` only.
- Any root-owned host process can use the two WireServer ports. Standard block
  relies on verified sudo and container lockdown to prevent later workflow code
  from obtaining UID `0`; degraded block and audit already disclaim ordinary
  containment.
- Untrusted workflow code can intentionally deny service to its own job. Fence
  bounds individual mediator and subprocess waits but does not claim local
  availability against malicious later steps.
- Process attribution is best effort. Short-lived processes, shared sockets,
  namespace boundaries, and bounded scan limits can produce missing or
  ambiguous ownership instead of a guessed actor.
- Trusted executable capture prevents path replacement after capture but is not
  a content-authentication boundary for an already compromised image or root
  process. Pre-capture byte modification with restored metadata, same-inode
  privileged writes, the dynamic loader, and shared libraries remain inside
  the trusted hosted-image/platform assumption.
- GitHub-hosted runner image drift intentionally fails closed until the pinned
  fingerprint is reviewed and updated.
- macOS, Windows, ARM, self-hosted runners, and job-container protection remain
  unsupported.
