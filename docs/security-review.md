# Fence Security Review

## Scope

This review covers the v0 Linux agent, DNS-mediated selected platform profile,
native `nftables` and NFLOG boundaries, root-owned runtime storage, hosted
lockdown controls, bundled Action wrapper, release provenance workflow, and
offline validation scripts as of June 2026.

Fence intentionally supports only GitHub-hosted `ubuntu-24.04` x64 host jobs.
Standard block mode reduces arbitrary outbound egress, disables measured
passwordless sudo and container-control paths, and keeps resident controls
active until ephemeral runner teardown. It does not claim sandboxing, kernel
isolation, or elimination of every exfiltration channel. The selected GitHub
workflow-bootstrap profile and its bounded DNS mediation remain disclosed
channels that later workflow code may use. The exact `github.com`,
`api.github.com`, and `release-assets.githubusercontent.com` HTTPS bootstrap
channels are intentional compatibility exceptions by default. Workflows may set
`disable_broad_github_domains: true` to remove those three broad GitHub roots
while keeping core Actions status and finalization endpoints available.

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
  default this includes `github.com`, `api.github.com`, and
  `release-assets.githubusercontent.com`; `disable_broad_github_domains: true`
  removes those three broad roots but retains core Actions status/finalization
  channels.
- The fixed upstream DNS resolver remains a trusted platform dependency. Fence
  bounds, canonicalizes, and filters requests and validates response source and
  transaction identity, but does not add DNSSEC validation.
- Untrusted workflow code can intentionally deny service to its own job. Fence
  bounds individual mediator and subprocess waits but does not claim local
  availability against malicious later steps.
- GitHub-hosted runner image drift intentionally fails closed until the pinned
  fingerprint is reviewed and updated.
- macOS, Windows, ARM, self-hosted runners, and job-container protection remain
  unsupported.
