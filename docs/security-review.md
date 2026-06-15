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
`api.github.com`, `release-assets.githubusercontent.com`, and
`hosted-compute-watchdog-prod-eus-01.githubapp.com` HTTPS channels are
intentional compatibility exceptions by default. Workflows may set
`disable_broad_github_domains: true` to remove those four broad GitHub roots
while keeping core Actions status and finalization endpoints available. The
watchdog endpoint is optional: a transient empty lookup does not block Fence
readiness, but any later approved answer is still withheld until its TCP `443`
rule is applied and verified.
GitHub results-storage accounts are authorized separately: Fence accepts only a
bounded exact hostname requested by the pinned `Runner.Worker` process and then
materializes HTTPS access after verified firewall application.

## Release Provenance

Release builds upload Linux x64 artifacts, generate GitHub artifact
attestations in a dedicated least-privilege job, re-download immutable release
assets, verify checksums, and verify each attestation against the repository
release workflow. The committed Action binary is installed only through the
online maintainer refresh script, which verifies its checksum and attestation
before writing the reviewed offline manifest. See GitHub's
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
rules. Queue rejection, service disconnection, or an explicit failed result
returns a minimal retryable `SERVFAIL` response. The response contains the
original DNS question but no answer, authority, additional, or raw upstream
data. Queue rejections increment bounded warning evidence; backend apply and
verification failures remain critical findings.

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
  `release-assets.githubusercontent.com`, and the exact hosted-runner watchdog
  endpoint; `disable_broad_github_domains: true` removes those four broad roots
  but retains core Actions status/finalization channels.
- An exact GitHub results-storage account authorized for the pinned runner is
  also reachable by later workflow code at its resolved HTTPS addresses. Fence
  does not inspect signed URLs, credentials, or encrypted request content.
- The fixed upstream DNS resolver remains a trusted platform dependency. Fence
  bounds, canonicalizes, and filters requests and validates response source and
  transaction identity, but does not add DNSSEC validation.
- Untrusted workflow code can intentionally deny service to its own job. Fence
  bounds individual mediator and subprocess waits but does not claim local
  availability against malicious later steps.
- Process attribution is best effort. Short-lived processes, shared sockets,
  namespace boundaries, and bounded scan limits can produce missing or
  ambiguous ownership instead of a guessed actor.
- GitHub-hosted runner image drift intentionally fails closed until the pinned
  fingerprint is reviewed and updated.
- macOS, Windows, ARM, self-hosted runners, and job-container protection remain
  unsupported.
