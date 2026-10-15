# Fence Security Review

## Scope

This review covers Fence's Linux agent, DNS policy, firewall, root-owned runtime files, runner lockdown, GitHub Action, release process, and offline validation scripts.

The [threat model](threat-model.md) describes attacker capabilities, trust assumptions, and remaining risks. The [v0 specification](v0.md) defines the full technical contract.

Fence supports GitHub-hosted x64 jobs running `ubuntu-24.04` or `ubuntu-latest`. Releases are tested on both runner labels in block and audit mode. Fence verifies actual runner security controls instead of rejecting routine image updates. Standard block mode limits outbound connections, disables passwordless sudo and container access, and keeps those protections active until the job ends. Fence is not a sandbox and does not prevent data from being sent to allowed destinations.

The default network policy allows the GitHub and runner services needed for compatibility. `disable_broad_github_domains: true` removes optional GitHub destinations while preserving required job-reporting connections. Fence also permits five reviewed storage endpoints and up to four additional accounts requested by the verified `Runner.Worker`. Enabling `allow_github_artifacts` lets verified descendants of that worker use the same four-account limit; it does not prove GitHub owns an account or that an upload is safe. Fence releases an approved DNS response only after applying and verifying its TCP `443` firewall rule.

## Release Provenance

The protected `main` branch contains source code, not the published Action binary or manifest. A reviewed version bump authorizes a release. The workflow builds the Linux x64 agent from signed source commit `M`, creates attestations for `M` and `refs/heads/main`, and assembles the candidate offline with `script/assemble-action-bundle`.

GitHub creates signed distribution commit `D` as the direct child of `M`. Its only changes are the mode-`0644` binary and schema-`4` manifest. The workflow verifies the commit, manifest, and binary, then runs full Action acceptance and tests both modes on both supported runner labels against `D`. After those checks and artifact verification pass, the immutable release tag points to `D`. The `action-release.json` asset records the version, source and distribution commits, binary checksum, manifest schema, and signer. Both the tag and this mapping are public while final verification is still pending.

After publication, the workflow downloads the assets again and verifies their checksums, attestations, release mapping, tag, commit relationship, and bundled bytes. After verification and cleanup, the workflow puts the ready-to-copy pin in the release notes. The release environment accepts only protected `main`; merging the reviewed version change remains the only release approval. The Action never downloads an agent or policy at runtime. Releases through `v0.6.3` retain their original tag behavior. See GitHub's [artifact attestation documentation](https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).

## Findings Addressed

### DNS TCP client deadlines

The local TCP DNS listeners previously served connections serially without a client read deadline, and forwarded their queries over upstream TCP even though the protected firewall permits only root-owned upstream UDP DNS. Accepted client sockets now use bounded deadlines, and both TCP and UDP clients share the same bounded, connected UDP resolver path without widening the firewall exception.

### DNS upstream response binding

The UDP mediator previously accepted the first datagram received on its ephemeral upstream socket without binding the socket to the fixed resolver or checking the transaction identifier. The mediator now connects every UDP upstream socket to the fixed resolver and rejects responses whose identifier does not match the mediator-owned upstream query for either local transport.

### Docker DNS configuration file safety

Docker DNS configuration previously followed file paths without bounding the read. Fence now opens existing files without following symlinks, refuses oversized or non-regular files, and verifies replacement files before writing them.

### Bounded fixed-command execution

DNS setup and the launcher's `systemctl show MainPID` check previously waited indefinitely for subprocesses. Those commands now have fixed deadlines and are stopped if they time out.

### Bounded nftables subprocess input

The `nftables` executor previously wrote to a child process before starting its timeout, so a child that stopped reading could block forever. Fence now writes in a separate worker while enforcing the command deadline.

### NFLOG attribute ambiguity

The NFLOG parser now rejects duplicate payload or prefix attributes and unexpected trailing bytes before extracting approved metadata.

### Bounded local incident attribution

Fence can match a network finding to a uniquely owned local socket using bounded `/proc` snapshots. Reports contain only the attribution status, actor class, PID, executable name, and up to four parent executable names. The worker has fixed limits and is supervised like the other resident workers. Socket details, command arguments, full paths, environment variables, working directories, packet contents, and telemetry are never reported.

### Sudo policy source file type

Fence now checks that every opened sudo policy source is a bounded regular file, not a symlink, pipe, device, or another special file.

### Hosted runner sudo policy

GitHub runner images can change sudo policy filenames, comments, or generated headers. Fence discovers bounded, root-owned policy files, checks their permissions and syntax, identifies every sudo grant available to the runner, and pins each file's complete contents. Block mode removes those grants and verifies sudo access is gone. Audit mode preserves the original policy. Later policy changes fail verification.

### Effective sudo and trusted-path access

File ownership and mode alone do not prove what the runner can access when ACLs are present. Fence checks every trusted executable, its parent directories, and accepted sudo sources using pinned `sudo` and `/usr/bin/test` descriptors. The runner must not be able to write those paths or search `/etc/sudoers.d`. Each check verifies the same file identity before and after execution. Hosted tests confirm that an unexpected ACL fails before Fence changes the runner.

### Descriptor-pinned privileged commands

Security-critical commands previously had a small replacement window between checking a path and executing it. Fence now opens all twelve reviewed root-owned executables first, verifies their path and file identity before every use, and executes the captured inode through `/proc/self/fd`. Runner-access checks use pinned `sudo` and the pinned target without falling back to an unchecked path.

These checks protect executable identity after capture. They do not authenticate earlier file contents, prevent same-inode changes by an already privileged process, or protect against a compromised loader, shared library, root process, or hosted image.

### Closed local root-control inventory

Checking known Docker and containerd services is not enough: an unexpected root-owned listener can provide another way around runner lockdown. Fence therefore records the accepted root container processes, SSH listeners, and Unix sockets before changing the host.

Standard block mode disables Docker and container access, including on runners where Docker is already absent. Audit mode and `unsafe_preserve` retain available container access. Fence records the actual root-process and socket inventory after setup, then checks it before readiness and every five seconds afterward. Unexpected listeners, missing ownership information, incomplete scans, and later drift fail closed. Filesystem checks are capped at 40 candidates and share a five-second deadline.

### In-memory pre-ready rollback and no-restore commit

Fence keeps the runner's sudo policy only in bounded memory and checks it again before removal. If startup fails, it restores and verifies the exact policy, permissions, digest, configuration validity, and runner capability. Sudo and container rollback are attempted independently. Once Fence reports readiness, restoration is permanently disabled for that job.

### Source-before-bundle host compatibility

The source-built candidate and published Action use the same runner checks. Fence validates complete, bounded runner observations before its agent checks executable identity, sudo access, container controls, and local services. Release validation tests block and audit modes on `ubuntu-24.04` and `ubuntu-latest`; no test can skip agent activation. Malformed observations, incomplete evidence, or unsafe runner changes fail closed.

### Invocation slug consistency

The Action wrapper and Rust agent now apply the same lowercase, internal-hyphen rules to invocation identifiers.

### DNS evidence write propagation

DNS report-write failures are now recorded and surfaced as critical findings instead of being silently ignored.

### DNS answer and firewall activation ordering

The DNS mediator previously waited for an approved HTTPS address to enter the owned `nftables` ruleset but returned the upstream answer before the verified firewall update was active. Block mode now submits bounded materialization requests to the single resident firewall owner and releases an approved address answer only after that owner applies and structurally verifies the matching rules. Address-bearing responses are all-or-nothing: every returned address must be materializable before any answer is released. An approved zero-TTL address receives a one-second materialization lifetime, and a valid zero-TTL CNAME edge receives a one-second effective lineage lifetime, before the existing refresh overlap. Partial coverage, queue rejection, service disconnection, or an explicit failed result returns a minimal retryable `SERVFAIL` response. Names outside policy and over-budget user wildcard names receive a minimal `REFUSED` response without forwarding. Both responses contain the original DNS question but no answer, authority, additional, or raw upstream data. Rejections increment bounded warning evidence; backend apply and verification failures remain critical findings.

### Response-local DNS alias authorization

Fence accepts only one acyclic CNAME chain rooted at the requested hostname. Every alias must belong to that chain, every returned address must belong to its final hostname, and the original hostname's policy remains in effect. Address records must match the requested address family; duplicate addresses use the shortest TTL. Conflicts, cycles, unrelated records, invalid depth, and capacity failures reject the entire response. A CNAME response without addresses grants no derived access.

The firewall owner processes approved responses in order, rejects stale or expired requests, and applies and verifies all matching address rules before publishing an authorization. Waiting in the queue never extends an authorization's original expiry.

### Runner-Bound And Explicitly Opted-In Results-Storage Authorization

GitHub's runner uploads job logs and summaries to signed Azure Blob URLs. An unbounded static numeric account list would be brittle, while a general `*.blob.core.windows.net` rule would authorize unrelated globally registered storage accounts. Fence instead permits five exact reviewed static compatibility roots, routes host DNS directly to its local mediator, pins the unique reviewed `Runner.Worker` identity, and authorizes at most four additional exact `productionresultssa<1-to-5-decimal-digits>.blob.core.windows.net` accounts only when a matching host DNS socket belongs to that pinned process by default. PID reuse, executable replacement, ambiguous ownership, Docker-originated requests, and ordinary workflow-process requests fail closed. The DNS answer remains withheld until TCP `443` access is atomically applied and structurally verified.

Block-only `allow_github_artifacts: true` is an explicit, default-off compatibility exception for GitHub artifact, Pages, and cache actions. It accepts a uniquely owned host DNS socket from a runner-UID-matching, bounded descendant of the pinned `Runner.Worker`, records origin `opt_in_github_artifact_dns`, and shares the existing maximum of four exact dynamic accounts with runner-authorized traffic. It revalidates the reviewed worker identity, descendant start time and ancestry, unique socket owner, strict account grammar, CNAME and TTL bounds, TCP-`443`-only materialization, and structural firewall verification. It rejects Docker, wrong-UID, unrelated or ambiguous sockets, general Azure Blob Storage, and enabled artifact compatibility in audit mode.

The opt-in changes the trust boundary: neither the account-name grammar nor the requesting process proves GitHub owns the account, that the official artifact action made the request, or that uploaded files are safe. Later workflow code can use an authorized account to upload source, secrets, or other data. Runtime evidence and the post-job report must explicitly identify the enabled option, exact account provenance, and artifact-upload warning.

The exact `productionresultssa19.blob.core.windows.net` compatibility account appears in [GitHub's Actions domain inventory](https://api.github.com/meta). Fence also permits the exact source-reviewed `productionresultssa13.blob.core.windows.net`, `productionresultssa9.blob.core.windows.net`, `productionresultssa15.blob.core.windows.net`, and `productionresultssa17.blob.core.windows.net` accounts. These five static roots are available without process attribution, while every other matching account continues to require the runner-bound authorization above. Fence does not allow the general Azure Blob suffix.

Configuration rejects exact user entries for every non-static matching account before mutation, and bootstrap response processing independently refuses to materialize any hostname marked as requiring runner provenance. Response-local CNAME lineage also rejects non-static matching targets, so exact and wildcard user hostnames cannot turn a restricted account into an unattributed derived allowance. User wildcard policy remains lazy and cannot bypass the same attribution and four-account cap.

### Action child-process deadlines and dependency surface

The Action launcher now enforces deadlines for privileged subprocesses. Its dependency-free TypeScript runs directly through Node 24's built-in type stripping, and its tests use Node's built-in `node:test` and `node:assert` modules. Fence does not install npm packages or compile TypeScript while a workflow runs. See Node's [built-in TypeScript documentation](https://nodejs.org/docs/latest-v24.x/api/typescript.html#type-stripping).

## Residual Risks And Boundaries

- Approved GitHub DNS and HTTPS destinations remain available to later workflow steps and can carry data off the runner. By default, these include `github.com`, `api.github.com`, release assets, an optional watchdog endpoint, and up to eight `*.githubapp.com` names. `disable_broad_github_domains: true` removes those broad destinations but keeps required job reporting.
- Explicit user wildcard patterns may contain one or two leading whole-label wildcards and authorize at most eight concrete names per invocation across all patterns. Each `*` matches exactly one DNS label, but the admitted query labels, matching HTTPS destinations, shared resolved addresses, and bounded external CNAME descendants remain exfiltration channels. Fence validates DNS structure rather than registrable-domain ownership and carries no public-suffix database.
- The five exact reviewed static results-storage accounts are always reachable TCP `443` compatibility channels. Other exact matching results-storage accounts are restricted to the pinned runner by default; explicitly enabled artifact compatibility extends the same bounded four-account dynamic budget to uniquely attributed, runner-UID-matching descendants of the pinned worker.
- A runner-authorized or explicitly artifact-authorized results-storage account is also reachable by later workflow code at its resolved HTTPS addresses. Fence does not prove GitHub account ownership, authenticate an official action, inspect signed URLs, credentials, or encrypted request content, or prevent artifact-based data exfiltration.
- The upstream DNS resolver is trusted. Fence limits and validates DNS requests and responses but does not perform DNSSEC validation.
- [Azure's platform address `168.63.129.16`](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16) remains available to Fence's root-owned DNS mediator over UDP `53` and to root-owned host sockets over TCP `80` and `32526`. Block mode denies other host and forwarded traffic to those WireServer ports; audit records it without blocking. Azure IMDS at `169.254.169.254:80` remains available to host and forwarded traffic.
- Any root-owned host process can use the WireServer ports. Standard block mode depends on verified sudo and container lockdown; audit mode and `unsafe_preserve` do not provide the same isolation.
- A malicious workflow step can still intentionally slow down or fail its own job.
- Process attribution is best effort. Short-lived processes, shared sockets, namespaces, and scan limits can leave ownership unknown or ambiguous.
- Verified executable capture does not protect against an already compromised runner image, root process, dynamic loader, or shared library.
- Runner changes that weaken required security controls fail closed; routine image updates do not require a new fingerprint.
- macOS, Windows, ARM, self-hosted runners, and jobs running inside containers are unsupported.
