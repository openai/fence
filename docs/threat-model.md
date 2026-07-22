# Fence v0 Threat Model

Status: security-claim source for the v0 protected target
Audience: workflow authors, maintainers, adopters, and security reviewers
Last reviewed: 2026-07-15

This model must be reviewed before changing the supported runner class,
platform profile, trusted launcher, privilege controls, evidence trust model,
or public protection claims. Normative behavior and schemas remain in
[`v0.md`](v0.md); implementation chronology remains in
[`history.md`](history.md).

The source tree and released Action define the schema-`9` policy and schema-`5` runtime-evidence contract. Protected `main` is source-only; each published Action is a signed generated distribution commit containing the reviewed wrapper source plus the exact binary and schema-`4` `action/bundle-manifest.json`. The wrapper rejects older evidence, stale verification state, malformed wildcard evidence, an incomplete worker set, or a resident PID that does not match the active systemd service. Future contract changes must update the agent, wrapper validators, tests, and source version atomically in one reviewed pull request.

## Executive summary

Fence protects one narrow environment: a GitHub-hosted `ubuntu-24.04` x64 host
job in which Fence is the first workflow step. Its highest-risk boundaries are
the transition from runner-user code to the root resident agent, the exact
network policy realized from DNS, the privileged host controls that prevent
later bypass, and the local evidence consumed by the protected post hook. Fence
reduces arbitrary outbound access; it does not eliminate exfiltration because
approved GitHub destinations, DNS behavior, exact and wildcard user allowlist
entries, and shared destination IP addresses remain usable channels.

The versioned platform contract separately permits UID `0` host traffic to Azure WireServer at exact destination `168.63.129.16` on TCP `80` and `32526`. Unprivileged and forwarded traffic does not match those rules. The contract also permits host and forwarded traffic to Azure IMDS at exact destination `169.254.169.254` on TCP `80`; later workflow code can use that endpoint as an egress channel. Any root-owned host process can use the two WireServer ports, so standard block depends on its verified sudo/container lockdown; degraded block and audit do not claim that containment boundary.

## Scope and assumptions

In scope:

- the root GitHub Action wrapper and bundled Linux agent under `action/`;
- strict configuration, planning, DNS mediation, native `nftables`, NFLOG,
  lockdown, runtime storage, resident supervision, and local attribution under
  `src/`;
- protected-host validation in `.github/workflows/integration.yml` and
  `.github/workflows/action-acceptance.yml`;
- agent and Action-bundle provenance in `.github/workflows/release.yml`, `script/assemble-action-bundle`, and `script/validate-action-bundle`.

Assumptions that materially define the model:

- Fence runs before checkout, setup, or other untrusted workflow steps.
- The runner is an ephemeral GitHub-hosted `ubuntu-24.04` x64 host job that
  matches the reviewed fingerprint.
- The reviewed hosted image and privileged platform processes have not
  modified a trusted executable and restored its accepted metadata before
  Fence captures it. Fence provides forward executable identity from capture;
  it does not authenticate pre-capture file contents.
- Later workflow code may execute arbitrary commands as the unprivileged
  `runner` user and may possess workflow credentials or sensitive source.
- The Linux kernel, GitHub runner control plane, GitHub-hosted image supply
  chain, and GitHub Actions service are trusted.
- Standard block mode uses `container_policy: disable`; `unsafe_preserve` and
  `audit` have explicitly weaker claims.
- Fence has no remote control plane, telemetry upload, or runtime agent/policy
  download.

Out of scope:

- kernel, hypervisor, or GitHub platform compromise;
- self-hosted, long-lived, ARM, Windows, macOS, and job-container protection;
- semantic restrictions inside TLS or HTTP requests to approved endpoints;
- confidentiality from an endpoint intentionally placed in the user
  `allowlist`;
- preventing data encoding in the bounded concrete names queried beneath an
  explicitly allowed wildcard suffix;
- preventing a malicious workflow from denying service to its own job; and
- guaranteed process ownership attribution or process isolation.

There are no unresolved context questions for the v0 risk ranking. Expanding
the supported runner class, allowing job containers, or changing the default
GitHub profile requires a new threat-model review.

## System model

### Primary components

- **Action launcher:** dependency-free TypeScript validates native inputs,
  creates root-owned launcher state, protects its registered runtime with a
  read-only bind mount, launches the service, and waits for readiness
  (`action/main.cts`, `action/lib.cts`).
- **Resident Rust agent:** validates the trusted service context and strict
  configuration, applies controls, emits readiness, supervises workers, and
  verifies state every five seconds (`src/cli.rs`, `src/lifecycle.rs`,
  `src/dns_mediator.rs`).
- **Network boundary:** a generated native `inet` ruleset, local DNS mediator,
  pinned `Runner.Worker` identity, and NFLOG reader implement and verify host egress policy
  (`src/nft.rs`, `src/nft_backend.rs`, `src/nflog.rs`).
- **Privilege boundary:** schema-`3` hosted-runner fingerprint checks,
  descriptor-pinned privileged commands, ACL-aware effective-access probes,
  in-memory passwordless-sudo rollback state, Docker/containerd stop and
  runtime masking, and the bounded local root-control inventory remove ordinary
  root-equivalent bypass paths (`src/hosted_runner.rs`,
  `src/trusted_executable.rs`, `src/local_control.rs`, `src/lockdown.rs`).
- **Evidence boundary:** root-owned readiness and reports, resident health,
  bounded findings, and the protected post hook provide local evidence without
  restoring controls (`src/runtime.rs`, `src/findings.rs`, `action/post.cts`).
- **Publication boundary:** pinned offline inputs, an offline bundle assembler, GitHub-signed one-parent distribution commits, complete candidate acceptance, release checksums, artifact attestations bound to source commit `M`, and the verified `action-release.json` mapping connect reviewed source `M` to published Action commit `D` (`.github/workflows/release.yml`, `script/assemble-action-bundle`).

### Data flows and trust boundaries

- **Workflow author -> Action launcher:** native inputs or bounded raw JSON
  cross through Action environment variables. The wrapper rejects conflicting
  input modes and constructs schema-`1` JSON; the agent performs strict
  unknown-field and semantic validation (`action/lib.cts`,
  `src/config.rs::parse_and_normalize`).
- **Runner user -> root launcher:** fixed `sudo` and `systemd-run` arguments
  launch one root service. Configuration and launcher files are copied to fixed
  root-owned paths; arbitrary executable paths and shell evaluation are not
  accepted (`action/main.cts`, `src/lifecycle.rs`).
- **Root agent -> Linux host controls:** captured executable descriptors and
  typed generated rules mutate only reviewed sudo, container, resolver, and
  owned `nftables` state. The runner cannot write the captured paths, their
  reviewed ancestors, or accepted sudo sources; subprocess output and
  execution time are bounded (`src/trusted_executable.rs`, `src/lockdown.rs`,
  `src/nft_backend.rs`, `src/dns_mediator.rs`).
- **Workflow process -> DNS mediator:** a reviewed read-only resolver mount
  sends host UDP/TCP DNS directly to Fence so caller sockets remain visible;
  Docker uses its separate local route. Block mode canonicalizes and forwards
  only authorized `A`/`AAAA` names; audit forwards observation traffic while
  simulating the same bounded name policy without a containment claim
  (`src/dns_mediator.rs`).
- **DNS mediator -> fixed resolver and firewall owner:** local UDP and TCP queries share the bounded root-only UDP resolver path. An approved answer is withheld until all matching transport rules are applied and structurally verified (`src/dns_mediator.rs::MaterializationSubmitter`).
- **Platform compatibility -> GitHub service domains:** Fence permits fixed
  workflow roots, one exact results-storage compatibility account, and at most
  eight single-label `*.githubapp.com` names unless broad GitHub compatibility
  is disabled. Each resulting HTTPS grant is available to other local code and
  remains an explicit residual channel (`src/platform_profile.rs`,
  `src/dns_mediator.rs`).
- **User wildcard policy -> concrete DNS names:** one- and two-label leading
  patterns share eight lifetime concrete-name admissions. Names materialize
  lazily, all matching transports are unioned, and failed or empty lookups
  still consume a slot because the query label is itself a data channel.
  Derived CNAME targets may leave the configured suffix only through one
  bounded response-local chain rooted at the queried concrete name. Every
  returned address owner must be the terminal name, and the derived policy
  remains the queried root's policy. A rooted CNAME response without address
  records retains no derived authorization (`src/hostname_policy.rs`,
  `src/dns_mediator.rs`).
- **Pinned runner -> additional GitHub results storage:** Fence accepts up to
  four other exact results-storage names only when their host DNS sockets belong
  to the unique pinned `Runner.Worker` identity. The resulting HTTPS grants are
  also available to other local code (`src/attribution.rs::TrustedRunnerWorker`,
  `src/dns_mediator.rs`).
- **CNAME lineage -> runner-restricted storage:** exact and wildcard user hostnames cannot derive non-static GitHub results-storage accounts; every restricted account remains subject to pinned-runner attribution and the four-account cap.
- **Kernel NFLOG -> resident agent:** group `4242` may copy at most 64 packet
  bytes. Fence immediately reduces this to endpoint metadata and drops raw
  bytes (`src/nflog.rs`, `src/findings.rs`).
- **Finding tuple -> attribution worker:** an internal source/destination tuple
  enters a queue of 128 requests. Bounded `/proc` snapshots return only a
  status, actor class, PID, executable basename, and four parent basenames;
  local endpoints are not serialized (`src/attribution.rs`).
- **Resident agent -> post hook:** root-owned `ready.json`, `report.json`, and
  `dns-report.json` are runner-readable but not runner-writable. Schema-`5`
  preserves the live systemd PID, worker health, evidence freshness, bounded
  concrete wildcard authorizations, and rejection counters that the post hook
  validates before trusting the report. Writable self-bind guards pin every
  runner-renameable ancestor of the registered Action path, while protected
  mount, device/inode, and runtime-digest checks apply at the wrapper boundary
  (`src/runtime.rs`, `action/post.cts`).
- **Release workflow -> distribution commit:** after all protected checks pass on source commit `M`, the workflow builds the artifact once, assembles the bundle offline, and creates signed child `D` with exactly the two generated bundle files. Full Action acceptance, the strict fixed-runner canary, final-asset attestations, and release-state verification must pass before the immutable tag targets `D` and `action-release.json` exposes it to consumers (`.github/workflows/release.yml`, `script/assemble-action-bundle`).

#### Diagram

```mermaid
flowchart TD
    W["Workflow and later steps"] --> A["Protected Action launcher"]
    A --> S["Root resident agent"]
    W --> D["Local DNS mediator"]
    D --> S
    D --> G["Approved GitHub endpoints"]
    S --> K["Kernel and host controls"]
    S --> E["Root-owned local evidence"]
    E --> P["Protected post hook"]
```

## Assets and security objectives

| Asset | Why it matters | Security objective (C/I/A) |
| --- | --- | --- |
| Workflow credentials and tokens | Later steps may receive credentials capable of repository or release changes. | C, I |
| Checked-out source and build outputs | Exfiltration or modification can compromise proprietary source or published artifacts. | C, I |
| Effective network policy | A missing or broader rule changes the core protection claim. | I, A |
| Sudo and container lockdown | Either path can restore root-equivalent authority and bypass network controls. | I |
| Trusted executable and local root-control identity | A replaced privileged command or additive root listener can invalidate the host-control claim. | I |
| Resident agent and protected Action runtime | Replacement can forge evidence, disable monitoring, or restore access. | I, A |
| Local readiness and report evidence | Operators and the post hook use it to decide whether the job remained protected. | I, A |
| Release agent and bundle provenance | A substituted binary compromises every adopting workflow. | I |
| Supported-host fingerprint | Silent runner-image drift can invalidate lockdown assumptions. | I |

## Attacker model

### Capabilities

- Run arbitrary native code as the later workflow's `runner` user.
- Read workflow-readable files, source, environment values, and credentials.
- Generate DNS and network traffic, including traffic to approved endpoints.
- Race local files and processes before readiness and attempt post-ready
  modification of runner-writable paths.
- Create high event volume within the fixed NFLOG, DNS, report, and attribution
  limits.
- Use passwordless sudo or Docker/containerd before Fence verifies their
  removal, or retain container access in explicit `unsafe_preserve` mode.

### Non-capabilities

- Compromise the Linux kernel, GitHub service, or reviewed hosted-runner image.
- Begin after Fence readiness with undisclosed root authority in standard block
  mode on a matching supported host.
- Modify root-owned runtime files, the protected read-only Action mount, or the
  bundled binary after successful readiness without exploiting a kernel or
  privileged-component vulnerability.
- Cause Fence to semantically inspect encrypted content sent to an approved
  destination.

## Entry points and attack surfaces

| Surface | How reached | Trust boundary | Notes | Evidence (repo path / symbol) |
| --- | --- | --- | --- | --- |
| Action native inputs | Workflow YAML | Author -> launcher | Bounded strings and multiline allowlist grammar; raw JSON is mutually exclusive. | `action/lib.cts::defaultInlineConfig` |
| Agent configuration | Root-owned config file | Launcher -> root agent | 256 KiB cap, strict schema, typed hostname/IP/CIDR and port validation. | `src/config.rs::read_config_bounded`, `parse_and_normalize` |
| Trusted service entry | `fence run --config` | Root process -> protected lifecycle | Requires root, fixed config path, matching systemd unit and MainPID. | `src/lifecycle.rs::validate_production_service_context` |
| Local DNS UDP/TCP | Host and Docker resolver traffic | Workflow process -> root mediator | Direct host resolver mount, separate Docker routing, canonical bounded queries, fixed listeners, deadlines, policy classification. | `src/dns_mediator.rs::start_dns_proxy` |
| Results-storage DNS | Exact GitHub storage hostname | Pinned runner -> root mediator | Unique `Runner.Worker` identity, socket ownership, strict grammar, four-account cap, HTTPS-only materialization. | `src/attribution.rs::TrustedRunnerWorker`, `src/platform_profile.rs::matches_results_storage_hostname`, `src/dns_mediator.rs::requires_runner_results_storage_provenance` |
| NFLOG netlink socket | Owned kernel log group | Kernel -> agent | Fixed group/prefix, 64-byte copy bound, duplicate/trailing attribute rejection. | `src/nflog.rs::extract_logged_prefix` |
| `/proc` attribution | Internal finding tuple | Agent -> kernel process metadata | Fixed queue and scan caps; ambiguous ownership is not guessed. | `src/attribution.rs::ProcAttributor` |
| `nft` subprocess | Generated program and structured state | Agent -> kernel firewall | Fixed binary/args, bounded IO/time, JSON verification, singleton owned table. | `src/nft_backend.rs::NativeNftBackend` |
| Trusted executable set | Twelve fixed command paths | Agent -> privileged host execution | No-follow descriptor capture, exact metadata/device/inode revalidation, ACL-aware effective access, no raw-path fallback. | `src/trusted_executable.rs::TrustedExecutableSet` |
| Local root-control inventory | Bounded `/proc` TCP/Unix and container state | Agent -> host privilege state | Stable complete schema-`3` match before mutation, container-only reductions plus one exact fingerprint-tagged removable Docker listener during standard lockdown, exact resident baseline. | `src/local_control.rs::observe_local_control_inventory` |
| Sudo/container controls | Fixed files, units, sockets, and one sudo source | Agent -> host privilege state | Fingerprint-gated exact-file digests except one strictly parsed generated cloud-init header, raw runtime digest pins, in-memory pre-ready rollback, exact removal/restoration checks, runtime masking, irreversible post-ready commit. | `src/lockdown.rs::SystemLockdownControl` |
| Runtime evidence files | Root writes, runner reads | Agent -> post hook | No-follow fixed paths, exclusive readiness, atomic reports, owner/mode checks. | `src/runtime.rs::ProductionRuntimeStore` |
| Protected post hook | GitHub post-job invocation | Runner -> evidence validator | Writable self-bind guards on renameable ancestors, read-only mounted source, device/inode and digest records, live PID, and fresh report validation. | `action/post.cts::main` |
| Release and bundle publication | Merge-triggered release workflow and offline assembler | Source `M` -> distribution `D` -> consumer | Pinned actions, protected-main-only environment, reviewed version merge as sole human authorization, signed one-parent exact-diff commit, complete acceptance/canary gates, checksums, source-bound attestations, immutable tag to `D`, and verified `action-release.json`. | `.github/workflows/release.yml`, `script/assemble-action-bundle` |

## Top abuse paths

1. **Exfiltrate through an approved channel:** malicious later code reads a
   token, sends it to an allowed GitHub, exact user, or wildcard-derived user
   destination, and the
   firewall permits it because Fence does not inspect TLS/HTTP semantics.
2. **Regain root and rewrite policy:** later code uses a residual sudo or
   container-control path, modifies `inet fence_v0`, and opens arbitrary
   egress. Fence prevents readiness unless trusted path access, the closed
   root-control inventory, and the measured privilege paths verify; later
   inventory drift is critical. Pre-capture image or privileged-platform
   compromise remains the key prerequisite.
3. **Exploit DNS authorization:** later code requests an allowed suffix or
   triggers a CNAME/address transition that broadens usable IP space, then
   sends data to another service sharing an authorized address. Fence bounds
   names, depth, TTL, and transports but cannot bind an IP to TLS identity.
4. **Race answer before firewall state:** a client attempts the first
   connection immediately after DNS resolution. Fence withholds the answer
   until the resident firewall owner applies and verifies the entire rule
   batch; queue rejection returns `SERVFAIL`.
5. **Replace the post hook:** later code overwrites the registered Action code
   or renames an ancestor and recreates the registered pathname so post-job
   validation reports success. Fence self-bind-guards each renameable
   ancestor, root-copies and bind-mounts the runtime read-only, then checks the
   exact mounts, device/inode identities, and digest in post.
6. **Forge or replay evidence:** later code writes a false report or leaves a
   stale healthy file after killing the service. In the schema-`5` runtime
   contract, root ownership, active MainPID checks, worker health, monotonic
   verification sequence, and a 20-second freshness bound reject the evidence.
7. **Disable or alter firewall state after readiness:** later code or host drift
   removes an owned rule. Five-second structured verification records a
   critical finding; the post hook fails the job, but traffic during the
   verification window remains a residual risk.
8. **Substitute a release binary:** an attacker changes the bundled executable independently of reviewed source. The release workflow reuses one artifact built from `M`, requires `D` to be a signed one-parent child with an exact two-file diff, compares the committed bytes to the artifact, runs complete acceptance and canary gates on `D`, verifies source-bound attestations, and publishes the full-SHA mapping only after final immutable-release verification. Offline CI revalidates the schema-`4` manifest and binary digest.
9. **Exhaust local evidence work:** later code floods DNS, NFLOG, or attribution
   paths. Fixed queues, sample rates, scan caps, finding caps, and report size
   bounds protect memory, but the attacker can still slow or fail its own job.
10. **Reuse an authorized results account:** after the pinned runner authorizes
    one exact storage account, later workflow code connects to the same resolved
    HTTPS addresses. Fence cannot determine whether an encrypted request carries
    a GitHub-issued signed URL, another valid credential, or unrelated data.

## Threat model table

| Threat ID | Threat source | Prerequisites | Threat action | Impact | Impacted assets | Existing controls (evidence) | Gaps | Recommended mitigations | Detection ideas | Likelihood | Impact severity | Priority |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TM-001 | Malicious workflow process | Residual root-equivalent path, additive root control, or unsupported host drift | Regain privilege and change firewall or agent state | Arbitrary egress and forged evidence | Credentials, policy, reports | Schema-`3` fingerprint, descriptor-pinned commands, ACL-aware path checks, exact pre-mutation local-control inventory, container-only reductions plus one exact fingerprint-tagged removable Docker listener during standard lockdown, resident baseline, and verified sudo/container controls (`src/hosted_runner.rs`, `src/trusted_executable.rs`, `src/local_control.rs`, `src/lockdown.rs`) | Pre-capture same-inode/content modification, dynamic loader/shared-library compromise, malicious root/platform processes, and new runner layouts remain trusted or unsupported | Keep fail-closed fingerprint updates reviewable; add support only with same-image and destructive hosted proof | Daily fixed-target classifier/activation failure, pre-ready support failure, or terminal critical local-control/lockdown finding | Low | High | High |
| TM-002 | Malicious workflow process | Access to an approved GitHub, exact user, or wildcard-derived destination | Exfiltrate sensitive data through allowed HTTPS or DNS behavior | Credential/source disclosure | Credentials, source | Exact profile roots, opt-out for broad platform roots, exact-depth wildcard grammar, shared eight-name lifetime cap, typed transports, and disclosed limits (`src/hostname_policy.rs`, `README.md`) | Core GitHub reporting, wildcard query labels, CNAME delegation, and shared IPs remain channels | Keep wildcard use explicit, use least-privilege job tokens, and prefer exact names where practical | DNS/finding summary, wildcard admission/rejection evidence, and audit-mode tuning | High | High | High |
| TM-003 | Malicious workflow process or DNS response | Authorized exact name, wildcard match, CNAME, or address rotation | Expand usable addresses or race first connection | Policy broadening or unexpected denial | Effective policy, job availability | Canonical A/AAAA queries, response-local linear CNAME validation rooted at the echoed question, terminal address-owner checks, exact label-depth matching, shared name/depth/TTL caps, queried-root policy retention, and owner-coordinated atomic authorization plus verified materialization (`src/dns_mediator.rs`) | IP authorization cannot prove TLS service identity; no public-suffix ownership validation is performed | Preserve response-local lineage, ordered owner-side revalidation, exact-depth matching, lifetime admission bounds, and complete apply-and-verify gating | DNS evidence counters, wildcard admissions, materialized allowances, and critical backend findings | Medium | High | High |
| TM-004 | Malicious workflow process | Writable launcher/post/binary, renameable registered-path ancestor, or evidence path | Replace validator or forge healthy evidence | False success after lost controls | Agent, post hook, reports | Root-owned copy, writable self-bind ancestor guards, read-only runtime bind mount, device/inode and digest records, no-follow files, live PID/freshness checks, schema-`5` wildcard-evidence validation, and hosted tamper coverage (`action/main.cts`, `action/post.cts`, `src/runtime.rs`) | Kernel or privileged mount bypass is out of scope; resident verification remains periodic | Keep exact path-guard/runtime manifests, worker set, freshness bounds, atomic schema adoption, and hosted tamper tests | Post-hook integrity or freshness failure | Low | High | Medium |
| TM-005 | Local process or host drift | Ability to alter owned kernel state after readiness | Remove or replace firewall rules | Temporary or persistent unintended egress | Network policy | Exact structured state verification every five seconds and terminal critical health (`src/nft_backend.rs`, `src/dns_mediator.rs`) | Detection is periodic rather than instantaneous | Keep interval fixed and evaluate event-driven integrity only with bounded complexity | Critical drift finding; Action post failure | Medium | High | High |
| TM-006 | Workflow author or malicious config producer | Control of Action inputs before launcher validation | Inject paths, nft syntax, oversized policy, or ambiguous JSON | Privileged mutation or resource exhaustion | Host state, availability | Strict JSON, unknown-field rejection, fixed paths, typed entries, fixed limits (`action/lib.cts`, `src/config.rs`) | Raw JSON remains an advanced surface | Preserve schema-`1` strictness; add fields only through reviewed typed models | Structured pre-mutation setup failure | Low | High | Medium |
| TM-007 | Supply-chain attacker | Ability to alter a release asset, workflow dependency, candidate commit, or release mapping | Distribute an agent not built by the reviewed workflow | Fleet-wide compromise | Release agent, downstream workflows | SHA-pinned actions, protected-main-only release environment, one reviewed source/version merge, exact one-parent signed `D`, exact two-file diff, complete acceptance/canary gates on `D`, checksums, non-draft immutable release tag targeting `D`, source-ref/source-commit/signer-digest-bound attestations, verified `action-release.json`, and offline bundle validation (`.github/workflows/release.yml`, `script/validate-action-bundle`) | Attestation and commit signing trust GitHub identity and the reviewed workflow commit | Add SBOM and auditable/reproducible binary work as post-v0 hardening | Candidate verification, release verification, bundle validation, and mapped-SHA canary | Low | High | Medium |
| TM-008 | Malicious workflow process | Ability to generate local load | Saturate DNS, NFLOG, reports, or attribution scans | Job slowdown or failure | Job availability, evidence completeness | Queue/sample/query/scan/report caps and explicit truncation (`src/dns_mediator.rs`, `src/attribution.rs`, `src/findings.rs`) | Fence does not guarantee availability against later code | Keep limits non-configurable in v0; review CPU cost with real workloads | Warning counters, truncation, critical worker health | High | Medium | Medium |
| TM-009 | Local process race or namespace boundary | Socket disappears, is shared, or is outside the scanned namespace | Produce missing or ambiguous process attribution | Reduced incident context, not control bypass | Local evidence | Unique-owner requirement, bounded statuses, no guessing (`src/attribution.rs`) | Attribution is inherently best effort | Keep attribution advisory; do not gate containment on individual matches | `not_found`, `ambiguous`, and limit statuses | High | Low | Low |
| TM-010 | Malicious workflow process | The static compatibility account or a runner-authorized results-storage account is reachable | Reuse its resolved HTTPS address or a usable signed URL | Data exfiltration through a required GitHub channel | Credentials, source | One source-defined exact account, strict provenance for all other matching accounts, four-account dynamic cap, TTL bounds, and explicit evidence (`src/platform_profile.rs`, `src/attribution.rs`, `src/dns_mediator.rs`) | Fence cannot inspect TLS semantics or revoke per-request signed URLs | Keep the static exception exact and ensure exact or wildcard user policy cannot bypass pinned-runner provenance for other matching accounts | Authorized-account evidence and DNS counters | Medium | High | High |

## Criticality calibration

- **Critical:** a supported standard-block run reports healthy while arbitrary
  egress or a root bypass remains available; a published bundle is not the
  attested reviewed agent; or remote/untrusted input gains pre-readiness root
  code execution.
- **High:** an attacker can exfiltrate protected credentials through an
  unintended default channel, persistently disable controls, or forge post-job
  evidence with realistic runner-user capabilities.
- **Medium:** a bounded race creates temporary policy drift, a malicious step
  can reliably deny service to its own job, or a release/control weakness needs
  an additional privileged or platform prerequisite.
- **Low:** local attribution is missing or ambiguous, low-sensitivity metadata
  is exposed, or a noisy failure is already fail-closed and clearly reported.

Examples are context-dependent: an allowed GitHub channel is **high** residual
risk for a credential-bearing job, while attribution ambiguity is **low**
because attribution is not an enforcement input. Kernel compromise would be
**critical** in impact but is outside this threat model.

## Focus paths for security review

| Path | Why it matters | Related Threat IDs |
| --- | --- | --- |
| `action/main.cts` | Builds privileged launcher state, protects the runtime, and starts the root service. | TM-001, TM-004, TM-006 |
| `action/post.cts` | Converts local evidence and live service state into final job success or failure. | TM-004, TM-005 |
| `action/lib.cts` | Owns wrapper input parsing, path derivation, evidence validation, and summary sanitization. | TM-004, TM-006, TM-009 |
| `src/config.rs` | Defines the strict public policy parser and fixed input bounds. | TM-006 |
| `src/lifecycle.rs` | Enforces root/MainPID trusted-service identity and resident lifecycle rules. | TM-001, TM-004 |
| `src/runtime.rs` | Protects root-owned config, readiness, state, and report filesystem boundaries. | TM-004, TM-006 |
| `src/hostname_policy.rs` | Merges platform and user hostname transports into the logical policy. | TM-002, TM-003 |
| `src/dns_mediator.rs` | Implements DNS authorization, runner-bound results storage, refresh, materialization ordering, worker supervision, and reports. | TM-002, TM-003, TM-005, TM-008, TM-010 |
| `src/nft.rs` | Renders the deterministic owned firewall program and rule classes. | TM-001, TM-005 |
| `src/nft_backend.rs` | Applies and structurally verifies privileged kernel state through bounded subprocesses. | TM-001, TM-005 |
| `src/nflog.rs` | Parses the bounded kernel event wire format and rejects ambiguous attributes. | TM-008, TM-009 |
| `src/findings.rs` | Reduces packet prefixes to approved report metadata and keeps local tuples internal. | TM-008, TM-009 |
| `src/attribution.rs` | Scans bounded `/proc` state, pins `Runner.Worker`, attributes DNS sockets, and defines the local metadata privacy boundary. | TM-008, TM-009, TM-010 |
| `src/trusted_executable.rs` | Captures and revalidates the fixed privileged executable set and descriptor-only execution boundary. | TM-001 |
| `src/local_control.rs` | Acquires and verifies the bounded root TCP/Unix and container-control inventory before readiness and during resident checks. | TM-001, TM-005, TM-008 |
| `src/lockdown.rs` | Enforces ACL-aware path invariants, removes and verifies sudo/container bypass paths, and owns pre-ready rollback state. | TM-001 |
| `.github/workflows/release.yml` | Connects reviewed source `M` to signed distribution `D`, validated release assets, and the immutable full-SHA consumer mapping. | TM-007 |
| `.github/workflows/action-drift-canary.yml` | Resolves a verified release mapping or explicit full SHA, detects supported-runner fingerprint drift, and refuses skipped activation. | TM-001, TM-007 |
| `script/assemble-action-bundle` | Deterministically assembles the mode-`0644` binary and schema-`4` manifest from explicit local release inputs without network access. | TM-007 |
