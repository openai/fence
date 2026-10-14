# Security Guide 🔒

Fence limits where a GitHub Actions job can send network traffic and removes common ways to undo those limits. It is not a sandbox.

## Supported Runners

Fence supports GitHub-hosted x64 jobs using `ubuntu-24.04` or `ubuntu-latest`.

- Releases are tested on both runner labels in block and audit mode.
- Fence checks the runner's security controls even when GitHub updates its images.
- Self-hosted runners, container jobs, other architectures, Windows, and macOS are not supported.

Fence may restore root ownership of `/etc` and `/usr`, including in audit mode. Setup fails if the runner's security controls do not meet Fence's requirements.

Run Fence before checkout and the other steps you want it to protect.

## Protection Modes

- **Block:** Allows required runner connections and your allowlist, blocks other outbound traffic, and disables passwordless `sudo` and Docker. This is the default.
- **Audit:** Shows what block mode would deny without blocking traffic or disabling `sudo` and Docker.
- **Preserved containers:** `container_policy: unsafe_preserve` keeps Docker and containerd available. Network filtering stays active, but the runner is less isolated.

Fence never switches to audit mode or preserved containers automatically.

## Built-In Network Access

GitHub-hosted jobs need some network access to run, report their status, and finish. Fence keeps the GitHub and Azure connections needed for those tasks available.

The default policy allows GitHub's website, API, release downloads, and job reporting. Set `disable_broad_github_domains: true` to remove optional GitHub destinations when your job does not need them. Job reporting still works.

Fence also allows the storage endpoints needed for job reporting without allowing all Azure Blob Storage. GitHub artifacts, Pages, and caches may need `allow_github_artifacts: true` for additional storage access.

> [!IMPORTANT]
> Any destination a job can reach can also receive its data. Keep your allowlist narrow and enable artifact access only when needed.

## Azure Platform Services

GitHub-hosted runners depend on Azure platform services:

- **Azure Instance Metadata Service (IMDS):** `169.254.169.254:80` remains reachable from host and forwarded traffic, including later workflow steps.
- **Azure WireServer:** `168.63.129.16` on TCP ports `80` and `32526` is available only to root-owned host processes.

These platform connections are built in; you do not need to add them to `allowlist`. Fence does not block IMDS.

## GitHub Artifacts

`allow_github_artifacts: true` lets approved runner-owned processes reach a limited number of storage endpoints used by GitHub Actions over HTTPS. It is off by default.

Once Fence allows a storage endpoint, later workflow steps can reach it too. Fence cannot inspect encrypted uploads or prove that the account belongs to GitHub. Artifact uploads are an intentional way to send data out of the runner.

## Runtime Integrity

Fence verifies its bundled agent, runs it from a protected root-owned location, and keeps checking the runner's network and privilege settings.

If a required protection changes, Fence records the problem and fails the job. It does not restore network, `sudo`, or Docker access. GitHub discards the hosted runner when the job ends.

## Reports And Privacy

Fence does not upload telemetry. Job summaries and logs can include destination hostnames, IP addresses, process names, process IDs, protection status, and warnings.

Reports never include credentials, environment variables, full executable paths, command arguments, or packet contents. Anyone who can read the workflow job log can read its Fence report.

See [network reports](how-it-works.md#network-reports) for the report format and GitHub API example.

## Release Pinning

Pin the full `action_commit` SHA from the [latest verified release](https://github.com/openai/fence/releases/latest):

```yaml
- uses: openai/fence@<commit-sha> # pin@vX.Y.Z
```

Do not reference `main`; it contains source code rather than the production Action bundle. See [release provenance](release-provenance.md) for the signed source, bundled artifact, and verification model.

For the complete security contract, see the [v0 specification](v0.md), [threat model](threat-model.md), and [security review](security-review.md). Report vulnerabilities using the [security policy](../SECURITY.md).
