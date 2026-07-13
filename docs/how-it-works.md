# Architecture And Lifecycle

Fence combines an immutable GitHub Action wrapper, a native Rust agent, local DNS mediation, Linux nftables policy, privilege and container controls, resident verification, and a protected post-job summary.

## Lifecycle

1. The workflow invokes the pinned Fence Action before checkout or other untrusted steps.
2. The wrapper validates its bundled manifest and protects the registered Action path with a root-owned read-only mount.
3. The wrapper validates native inputs, writes a root-owned configuration below `/run/fence/<invocation-id>/`, and launches the bundled agent as the main process of a matching transient systemd service.
4. The agent checks the supported GitHub-hosted runner fingerprint, including trusted executables and ancestors, sudo-policy sources, runner identity, and the bounded local root-control inventory.
5. The agent builds the selected profile and user policy, starts local DNS mediation, applies mode-specific nftables and privilege controls, and verifies the resulting state before writing readiness.
6. In block mode, approved DNS answers are released only after all corresponding firewall rules have been applied and structurally verified.
7. The agent remains resident and rechecks the firewall, privilege/container state, local-control inventory, worker health, and local evidence every five seconds. Critical resident health never returns to healthy.
8. The protected post-job hook validates the active service and evidence, prints a compact **Fence Summary**, and fails the job when critical drift is present. Fence does not restore access; disposable runner teardown removes the VM.

## Detailed Flow

```mermaid
flowchart TD
    start["GitHub-hosted Linux job starts"] --> action["Fence Action runs first"]
    action --> input["Read native Action inputs<br/>default: block mode + empty allowlist"]
    input --> protect["Protect registered Action path<br/>stable ancestors + read-only runtime"]
    protect --> config["Write root-owned config<br/>under /run/fence/"]
    config --> launch["Launch bundled agent<br/>with sudo + systemd"]

    launch --> support["Check supported runner shape"]
    support --> plan["Build network plan<br/>Built-in platform policy + allowlist"]
    plan --> network["Apply Linux nftables rules<br/>and local DNS handling"]
    network --> gate["Release approved DNS answers<br/>after matching firewall access is verified"]

    gate --> mode{"Selected mode"}
    mode --> block["block<br/>turn off passwordless sudo<br/>turn off Docker"]
    mode --> degraded["unsafe_preserve<br/>turn off passwordless sudo<br/>keep Docker"]
    mode --> audit["audit<br/>observe only<br/>keep sudo and Docker"]

    block --> ready["Write ready/report files"]
    degraded --> ready
    audit --> ready

    ready --> resident["Fence keeps running<br/>checks controls every 5 seconds"]
    resident --> post["Protected post hook<br/>verifies runtime + evidence"]
    post --> summary["Render Fence Summary<br/>fail on critical drift"]
    summary --> teardown["Runner teardown removes the VM"]
```

## Major Components

- **Action wrapper:** Converts the common native inputs into strict agent configuration, validates the bundled artifact, creates the protected launcher path, and registers the post-job hook.
- **Runtime intake:** Accepts only the expected root-owned, no-follow configuration path and matching transient service identity.
- **Platform profile:** Describes the supported runner fingerprint and the bounded GitHub Actions, Azure platform, DNS, sudo, container, and local-control expectations.
- **DNS mediator and firewall owner:** Attribute DNS requests, validate policy and response lineage, serialize firewall updates, and publish answers only after access is verified.
- **Resident verifier:** Rechecks controls and worker health every five seconds and records bounded local evidence.
- **Post-job hook:** Validates the live service and evidence, renders the final summary, and converts critical findings into job failure.

The [Fence v0 specification](v0.md) is the normative behavior contract. The [threat model](threat-model.md) explains the trust boundaries and attacker assumptions.
