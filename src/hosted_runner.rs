use serde::Serialize;

pub const HOSTED_RUNNER_FINGERPRINT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct HostedRunnerFingerprintV1 {
    pub schema_version: u32,
    pub protected_target: &'static str,
    pub status: &'static str,
    pub observation_method: &'static str,
    pub accepted: AcceptedHostedRunnerFactsV1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedHostedRunnerFactsV1 {
    pub os_id: &'static str,
    pub os_version_id: &'static str,
    pub architecture: &'static str,
    pub expected_principal: &'static str,
    pub required_runner_groups: Vec<&'static str>,
    pub executable_paths: Vec<&'static str>,
    pub resolver: AcceptedResolverV1,
    pub sudo_policy_sources: Vec<AcceptedSudoPolicySourceV1>,
    pub container_units: Vec<AcceptedUnitV1>,
    pub container_sockets: Vec<AcceptedSocketV1>,
    pub required_docker_running_workload_count: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedResolverV1 {
    pub resolv_conf_path: &'static str,
    pub canonical_target: &'static str,
    pub target_uid: u32,
    pub target_mode: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedSudoPolicySourceV1 {
    pub path_class: &'static str,
    pub name: &'static str,
    pub sha256: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alternate_sha256: Vec<&'static str>,
    pub runner_nopasswd_markers: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedUnitV1 {
    pub name: &'static str,
    pub load_state: &'static str,
    pub active_state: &'static str,
    pub unit_file_state: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedSocketV1 {
    pub path: &'static str,
    pub present: bool,
    pub kind: &'static str,
    pub mode: &'static str,
    pub owner: &'static str,
    pub group: &'static str,
}

pub fn hosted_runner_fingerprint_requirement() -> HostedRunnerFingerprintV1 {
    HostedRunnerFingerprintV1 {
        schema_version: HOSTED_RUNNER_FINGERPRINT_SCHEMA_VERSION,
        protected_target: "github_hosted_ubuntu_24_04_x86_64",
        status: "accepted_reference_not_checked",
        observation_method: "integration_read_only_observation",
        accepted: AcceptedHostedRunnerFactsV1 {
            os_id: "ubuntu",
            os_version_id: "24.04",
            architecture: "x86_64",
            expected_principal: "runner",
            required_runner_groups: vec!["adm", "users", "docker", "systemd-journal", "runner"],
            executable_paths: vec![
                "/usr/bin/docker",
                "/usr/bin/id",
                "/usr/bin/mount",
                "/usr/bin/stat",
                "/usr/bin/sudo",
                "/usr/bin/systemctl",
                "/usr/bin/systemd-run",
                "/usr/bin/true",
                "/usr/bin/umount",
                "/usr/sbin/visudo",
                "/usr/sbin/nft",
            ],
            resolver: AcceptedResolverV1 {
                resolv_conf_path: "/etc/resolv.conf",
                canonical_target: "/run/systemd/resolve/stub-resolv.conf",
                target_uid: 991,
                target_mode: "0644",
            },
            sudo_policy_sources: vec![
                AcceptedSudoPolicySourceV1 {
                    path_class: "main_policy",
                    name: "sudoers",
                    sha256: "5bac27ce5ff1a78ace8f3ef81bfd60cbd44810ac3f3d280da9d7649fe90c18f8",
                    alternate_sha256: vec![],
                    runner_nopasswd_markers: vec![],
                },
                AcceptedSudoPolicySourceV1 {
                    path_class: "drop_in",
                    name: "90-cloud-init-users",
                    sha256: "55b0a6eab1edea9a2151c9b73deff81fb365854a070045452766aa4a0397ab13",
                    alternate_sha256: vec![
                        "9a1d51e1aac764ffaa94a1dd1c5f74bcc2f667bc495c5bf559ff47a5eda46950",
                        "af0e90e05aa9a9afd0ac195de498c3080626d50dbb3366f4e7046a6b2eb5a92d",
                    ],
                    runner_nopasswd_markers: vec![],
                },
                AcceptedSudoPolicySourceV1 {
                    path_class: "drop_in",
                    name: "README",
                    sha256: "b428c9b673c3c806370f2aa28a98293a9cb578c70c3a8a2d1a39031861b3dbd8",
                    alternate_sha256: vec![],
                    runner_nopasswd_markers: vec![],
                },
                AcceptedSudoPolicySourceV1 {
                    path_class: "drop_in",
                    name: "runner",
                    sha256: "661b4f06df1e149cc4d88457270d9ce39d2597963042718fb0da9573398f8714",
                    alternate_sha256: vec![],
                    runner_nopasswd_markers: vec!["principal"],
                },
            ],
            container_units: vec![
                AcceptedUnitV1 {
                    name: "docker.service",
                    load_state: "loaded",
                    active_state: "active",
                    unit_file_state: "enabled",
                },
                AcceptedUnitV1 {
                    name: "docker.socket",
                    load_state: "loaded",
                    active_state: "active",
                    unit_file_state: "enabled",
                },
                AcceptedUnitV1 {
                    name: "containerd.service",
                    load_state: "loaded",
                    active_state: "active",
                    unit_file_state: "enabled",
                },
                AcceptedUnitV1 {
                    name: "containerd.socket",
                    load_state: "not-found",
                    active_state: "inactive",
                    unit_file_state: "",
                },
            ],
            container_sockets: vec![
                AcceptedSocketV1 {
                    path: "/var/run/docker.sock",
                    present: true,
                    kind: "socket",
                    mode: "0660",
                    owner: "root",
                    group: "docker",
                },
                AcceptedSocketV1 {
                    path: "/run/docker.sock",
                    present: true,
                    kind: "socket",
                    mode: "0660",
                    owner: "root",
                    group: "docker",
                },
                AcceptedSocketV1 {
                    path: "/run/containerd/containerd.sock",
                    present: true,
                    kind: "socket",
                    mode: "0660",
                    owner: "root",
                    group: "root",
                },
            ],
            required_docker_running_workload_count: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_pins_the_reviewed_non_activated_hosted_reference() {
        let requirement = hosted_runner_fingerprint_requirement();

        assert_eq!(requirement.schema_version, 1);
        assert_eq!(
            requirement.protected_target,
            "github_hosted_ubuntu_24_04_x86_64"
        );
        assert_eq!(requirement.status, "accepted_reference_not_checked");
        assert_eq!(requirement.accepted.expected_principal, "runner");
        assert_eq!(
            requirement.accepted.resolver.canonical_target,
            "/run/systemd/resolve/stub-resolv.conf"
        );
        assert_eq!(requirement.accepted.resolver.target_uid, 991);
        assert!(
            requirement
                .accepted
                .required_runner_groups
                .contains(&"docker")
        );
        assert_eq!(
            requirement.accepted.sudo_policy_sources[3].runner_nopasswd_markers,
            vec!["principal"]
        );
        assert_eq!(
            requirement.accepted.sudo_policy_sources[1].alternate_sha256,
            vec![
                "9a1d51e1aac764ffaa94a1dd1c5f74bcc2f667bc495c5bf559ff47a5eda46950",
                "af0e90e05aa9a9afd0ac195de498c3080626d50dbb3366f4e7046a6b2eb5a92d",
            ]
        );
        assert_eq!(
            requirement.accepted.container_units[0].name,
            "docker.service"
        );
        assert_eq!(
            requirement.accepted.required_docker_running_workload_count,
            0
        );
    }
}
