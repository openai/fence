use serde::Serialize;

pub const HOSTED_RUNNER_FINGERPRINT_SCHEMA_VERSION: u32 = 3;
pub const UNIX_NAME_HASH_SCHEMA_V1: &str = "fence-unix-name-v1";
pub const SUDO_POLICY_DIGEST_PROFILE_EXACT_FILE_V1: &str = "exact_file_v1";
pub const SUDO_POLICY_DIGEST_PROFILE_CLOUD_INIT_GENERATED_HEADER_V1: &str =
    "cloud_init_generated_header_v1";

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct HostedRunnerFingerprintV3 {
    pub schema_version: u32,
    pub protected_target: &'static str,
    pub status: &'static str,
    pub observation_method: &'static str,
    pub accepted: AcceptedHostedRunnerFactsV3,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedHostedRunnerFactsV3 {
    pub os_id: &'static str,
    pub os_version_id: &'static str,
    pub architecture: &'static str,
    pub expected_principal: &'static str,
    pub required_runner_groups: Vec<&'static str>,
    pub trusted_executables: Vec<AcceptedTrustedExecutableV2>,
    pub permission_ancestor_directories: Vec<AcceptedPermissionAncestorV2>,
    pub resolver: AcceptedResolverV2,
    pub sudo_policy_sources: Vec<AcceptedSudoPolicySourceV3>,
    pub container_units: Vec<AcceptedUnitV2>,
    pub container_sockets: Vec<AcceptedSocketV2>,
    pub required_docker_running_workload_count: u32,
    pub local_control_inventory: AcceptedLocalControlInventoryV2,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedTrustedExecutableV2 {
    pub path: &'static str,
    pub canonical_target: &'static str,
    pub mode: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedPermissionAncestorV2 {
    pub path: &'static str,
    pub canonical_target: &'static str,
    pub mode: &'static str,
    pub runner_searchable: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedResolverV2 {
    pub resolv_conf_path: &'static str,
    pub canonical_target: &'static str,
    pub target_uid: u32,
    pub target_mode: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedSudoPolicySourceV3 {
    pub path_class: &'static str,
    pub name: &'static str,
    pub canonical_target: &'static str,
    pub mode: &'static str,
    pub digest_profile: &'static str,
    pub sha256: &'static str,
    pub runner_nopasswd_markers: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedUnitV2 {
    pub name: &'static str,
    pub load_state: &'static str,
    pub active_state: &'static str,
    pub unit_file_state: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedSocketV2 {
    pub path: &'static str,
    pub present: bool,
    pub kind: &'static str,
    pub mode: &'static str,
    pub owner: &'static str,
    pub group: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedLocalControlInventoryV2 {
    pub unix_name_hash_schema: &'static str,
    pub root_container_processes: Vec<AcceptedRootContainerProcessV2>,
    pub tcp_listeners: Vec<AcceptedTcpListenerV2>,
    pub unix_listeners: Vec<AcceptedUnixListenerV2>,
    pub standard_lockdown_removable_unix_listener_name_sha256: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedRootContainerProcessV2 {
    pub uid: u32,
    pub executable_basename: &'static str,
    pub canonical_executable: &'static str,
    pub unified_cgroup: &'static str,
    pub instances: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct AcceptedLocalControlOwnerV2 {
    pub uid: u32,
    pub executable_basename: &'static str,
    pub canonical_executable: &'static str,
    pub unified_cgroup: &'static str,
    pub processes: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedTcpListenerV2 {
    pub family: &'static str,
    pub bind_class: &'static str,
    pub port: u16,
    pub owners: Vec<AcceptedLocalControlOwnerV2>,
    pub instances: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedUnixListenerV2 {
    pub socket_type: &'static str,
    pub name_kind: &'static str,
    pub name_sha256: &'static str,
    pub owners: Vec<AcceptedLocalControlOwnerV2>,
    pub instances: u32,
}

const SYSTEMD_OWNER: AcceptedLocalControlOwnerV2 = AcceptedLocalControlOwnerV2 {
    uid: 0,
    executable_basename: "systemd",
    canonical_executable: "/usr/lib/systemd/systemd",
    unified_cgroup: "/init.scope",
    processes: 1,
};

const DOCKERD_OWNER: AcceptedLocalControlOwnerV2 = AcceptedLocalControlOwnerV2 {
    uid: 0,
    executable_basename: "dockerd",
    canonical_executable: "/usr/bin/dockerd",
    unified_cgroup: "/system.slice/docker.service",
    processes: 1,
};

const MULTIPATHD_OWNER: AcceptedLocalControlOwnerV2 = AcceptedLocalControlOwnerV2 {
    uid: 0,
    executable_basename: "multipathd",
    canonical_executable: "/usr/sbin/multipathd",
    unified_cgroup: "/system.slice/multipathd.service",
    processes: 1,
};

const JOURNALD_OWNER: AcceptedLocalControlOwnerV2 = AcceptedLocalControlOwnerV2 {
    uid: 0,
    executable_basename: "systemd-journald",
    canonical_executable: "/usr/lib/systemd/systemd-journald",
    unified_cgroup: "/system.slice/systemd-journald.service",
    processes: 1,
};

const DBUS_OWNER: AcceptedLocalControlOwnerV2 = AcceptedLocalControlOwnerV2 {
    uid: 101,
    executable_basename: "dbus-daemon",
    canonical_executable: "/usr/bin/dbus-daemon",
    unified_cgroup: "/system.slice/dbus.service",
    processes: 1,
};

pub fn hosted_runner_fingerprint_requirement() -> HostedRunnerFingerprintV3 {
    HostedRunnerFingerprintV3 {
        schema_version: HOSTED_RUNNER_FINGERPRINT_SCHEMA_VERSION,
        protected_target: "github_hosted_ubuntu_24_04_x86_64",
        status: "accepted_reference_not_checked",
        observation_method: "integration_read_only_observation",
        accepted: AcceptedHostedRunnerFactsV3 {
            os_id: "ubuntu",
            os_version_id: "24.04",
            architecture: "x86_64",
            expected_principal: "runner",
            required_runner_groups: vec!["adm", "users", "docker", "systemd-journal", "runner"],
            trusted_executables: vec![
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/docker",
                    canonical_target: "/usr/bin/docker",
                    mode: "0755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/id",
                    canonical_target: "/usr/bin/id",
                    mode: "0755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/mount",
                    canonical_target: "/usr/bin/mount",
                    mode: "4755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/stat",
                    canonical_target: "/usr/bin/stat",
                    mode: "0755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/sudo",
                    canonical_target: "/usr/bin/sudo",
                    mode: "4755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/systemctl",
                    canonical_target: "/usr/bin/systemctl",
                    mode: "0755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/systemd-run",
                    canonical_target: "/usr/bin/systemd-run",
                    mode: "0755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/test",
                    canonical_target: "/usr/bin/test",
                    mode: "0755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/true",
                    canonical_target: "/usr/bin/true",
                    mode: "0755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/bin/umount",
                    canonical_target: "/usr/bin/umount",
                    mode: "4755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/sbin/visudo",
                    canonical_target: "/usr/sbin/visudo",
                    mode: "0755",
                },
                AcceptedTrustedExecutableV2 {
                    path: "/usr/sbin/nft",
                    canonical_target: "/usr/sbin/nft",
                    mode: "0755",
                },
            ],
            permission_ancestor_directories: vec![
                AcceptedPermissionAncestorV2 {
                    path: "/",
                    canonical_target: "/",
                    mode: "0755",
                    runner_searchable: true,
                },
                AcceptedPermissionAncestorV2 {
                    path: "/etc",
                    canonical_target: "/etc",
                    mode: "0755",
                    runner_searchable: true,
                },
                AcceptedPermissionAncestorV2 {
                    path: "/etc/sudoers.d",
                    canonical_target: "/etc/sudoers.d",
                    mode: "0750",
                    runner_searchable: false,
                },
                AcceptedPermissionAncestorV2 {
                    path: "/usr",
                    canonical_target: "/usr",
                    mode: "0755",
                    runner_searchable: true,
                },
                AcceptedPermissionAncestorV2 {
                    path: "/usr/bin",
                    canonical_target: "/usr/bin",
                    mode: "0755",
                    runner_searchable: true,
                },
                AcceptedPermissionAncestorV2 {
                    path: "/usr/sbin",
                    canonical_target: "/usr/sbin",
                    mode: "0755",
                    runner_searchable: true,
                },
            ],
            resolver: AcceptedResolverV2 {
                resolv_conf_path: "/etc/resolv.conf",
                canonical_target: "/run/systemd/resolve/stub-resolv.conf",
                target_uid: 991,
                target_mode: "0644",
            },
            sudo_policy_sources: vec![
                AcceptedSudoPolicySourceV3 {
                    path_class: "main_policy",
                    name: "sudoers",
                    canonical_target: "/etc/sudoers",
                    mode: "0440",
                    digest_profile: SUDO_POLICY_DIGEST_PROFILE_EXACT_FILE_V1,
                    sha256: "5bac27ce5ff1a78ace8f3ef81bfd60cbd44810ac3f3d280da9d7649fe90c18f8",
                    runner_nopasswd_markers: vec![],
                },
                AcceptedSudoPolicySourceV3 {
                    path_class: "drop_in",
                    name: "90-cloud-init-users",
                    canonical_target: "/etc/sudoers.d/90-cloud-init-users",
                    mode: "0440",
                    digest_profile: SUDO_POLICY_DIGEST_PROFILE_CLOUD_INIT_GENERATED_HEADER_V1,
                    sha256: "86edf54fdaf109a4da119f9fbbff9ff565d911b05076a500830e4b2d15ab6b10",
                    runner_nopasswd_markers: vec![],
                },
                AcceptedSudoPolicySourceV3 {
                    path_class: "drop_in",
                    name: "README",
                    canonical_target: "/etc/sudoers.d/README",
                    mode: "0440",
                    digest_profile: SUDO_POLICY_DIGEST_PROFILE_EXACT_FILE_V1,
                    sha256: "b428c9b673c3c806370f2aa28a98293a9cb578c70c3a8a2d1a39031861b3dbd8",
                    runner_nopasswd_markers: vec![],
                },
                AcceptedSudoPolicySourceV3 {
                    path_class: "drop_in",
                    name: "runner",
                    canonical_target: "/etc/sudoers.d/runner",
                    mode: "0644",
                    digest_profile: SUDO_POLICY_DIGEST_PROFILE_EXACT_FILE_V1,
                    sha256: "661b4f06df1e149cc4d88457270d9ce39d2597963042718fb0da9573398f8714",
                    runner_nopasswd_markers: vec!["principal"],
                },
            ],
            container_units: vec![
                AcceptedUnitV2 {
                    name: "docker.service",
                    load_state: "loaded",
                    active_state: "active",
                    unit_file_state: "enabled",
                },
                AcceptedUnitV2 {
                    name: "docker.socket",
                    load_state: "loaded",
                    active_state: "active",
                    unit_file_state: "enabled",
                },
                AcceptedUnitV2 {
                    name: "containerd.service",
                    load_state: "loaded",
                    active_state: "active",
                    unit_file_state: "enabled",
                },
                AcceptedUnitV2 {
                    name: "containerd.socket",
                    load_state: "not-found",
                    active_state: "inactive",
                    unit_file_state: "",
                },
            ],
            container_sockets: vec![
                AcceptedSocketV2 {
                    path: "/var/run/docker.sock",
                    present: true,
                    kind: "socket",
                    mode: "0660",
                    owner: "root",
                    group: "docker",
                },
                AcceptedSocketV2 {
                    path: "/run/docker.sock",
                    present: true,
                    kind: "socket",
                    mode: "0660",
                    owner: "root",
                    group: "docker",
                },
                AcceptedSocketV2 {
                    path: "/run/containerd/containerd.sock",
                    present: true,
                    kind: "socket",
                    mode: "0660",
                    owner: "root",
                    group: "root",
                },
            ],
            required_docker_running_workload_count: 0,
            local_control_inventory: AcceptedLocalControlInventoryV2 {
                unix_name_hash_schema: UNIX_NAME_HASH_SCHEMA_V1,
                root_container_processes: vec![
                    AcceptedRootContainerProcessV2 {
                        uid: 0,
                        executable_basename: "containerd",
                        canonical_executable: "/usr/bin/containerd",
                        unified_cgroup: "/system.slice/containerd.service",
                        instances: 1,
                    },
                    AcceptedRootContainerProcessV2 {
                        uid: 0,
                        executable_basename: "dockerd",
                        canonical_executable: "/usr/bin/dockerd",
                        unified_cgroup: "/system.slice/docker.service",
                        instances: 1,
                    },
                ],
                tcp_listeners: vec![
                    AcceptedTcpListenerV2 {
                        family: "ipv4",
                        bind_class: "wildcard",
                        port: 22,
                        owners: vec![SYSTEMD_OWNER],
                        instances: 1,
                    },
                    AcceptedTcpListenerV2 {
                        family: "ipv6",
                        bind_class: "wildcard",
                        port: 22,
                        owners: vec![SYSTEMD_OWNER],
                        instances: 1,
                    },
                ],
                unix_listeners: vec![
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "abstract",
                        name_sha256: "2098ac544ed7672deda4863cf7f1ec11fd3916b31f7f02f8b1190394218612ec",
                        owners: vec![MULTIPATHD_OWNER, SYSTEMD_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "abstract",
                        name_sha256: "caf0d5ac99f3b95f921556138b2adbf4ceb0e8d48c61ef23d5180aa480b45743",
                        owners: vec![SYSTEMD_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "filesystem",
                        name_sha256: "1f76b0a726958dc80a872b9ae4fb414457f7ee9cc80f419ff7dfc509f236e469",
                        owners: vec![SYSTEMD_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "filesystem",
                        name_sha256: "2a5962ed41259a31b1587bcae589fcee6b9d6767ef064ac317e6d398b96a81f2",
                        owners: vec![DOCKERD_OWNER, SYSTEMD_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "filesystem",
                        name_sha256: "68c0b0a26da3ac420889ddd0ab629df3f9defb482cf5a9daf7fdcd28ee545f29",
                        owners: vec![SYSTEMD_OWNER, JOURNALD_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "filesystem",
                        name_sha256: "8b5e213b2b72a7033476e1f46afb302f0e4123c6e6fd746f77eeb744050e3b91",
                        owners: vec![SYSTEMD_OWNER, DBUS_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "filesystem",
                        name_sha256: "ac10a069436547a18b02df8078e06421de7fc8953887fcc32f817af06b1b09bb",
                        owners: vec![SYSTEMD_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "filesystem",
                        name_sha256: "ded56518cb66a7ddcdf9434f3280745cbb457869ea692d34cf0df494949bca96",
                        owners: vec![SYSTEMD_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "filesystem",
                        name_sha256: "e84916b142c7b55bdf364843e9360867ec403fc602cfb662c95d6299ebfb8e77",
                        owners: vec![SYSTEMD_OWNER],
                        instances: 1,
                    },
                    AcceptedUnixListenerV2 {
                        socket_type: "stream",
                        name_kind: "filesystem",
                        name_sha256: "f7978cc2493e0ecd56d54a3f49e36c3bde79b3ac281baa0a0aed0efab0898c23",
                        owners: vec![SYSTEMD_OWNER],
                        instances: 1,
                    },
                ],
                standard_lockdown_removable_unix_listener_name_sha256: "2a5962ed41259a31b1587bcae589fcee6b9d6767ef064ac317e6d398b96a81f2",
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_v3_preserves_reviewed_host_facts_without_an_active_transition() {
        let requirement = hosted_runner_fingerprint_requirement();

        assert_eq!(requirement.schema_version, 3);
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
        assert_eq!(requirement.accepted.sudo_policy_sources.len(), 4);
        let runner_source = requirement
            .accepted
            .sudo_policy_sources
            .iter()
            .find(|source| source.name == "runner")
            .unwrap();
        assert_eq!(runner_source.canonical_target, "/etc/sudoers.d/runner");
        assert_eq!(runner_source.mode, "0644");
        assert_eq!(runner_source.runner_nopasswd_markers, vec!["principal"]);
        assert_eq!(
            requirement.accepted.sudo_policy_sources[0].digest_profile,
            SUDO_POLICY_DIGEST_PROFILE_EXACT_FILE_V1
        );
        assert_eq!(
            requirement.accepted.sudo_policy_sources[1].digest_profile,
            SUDO_POLICY_DIGEST_PROFILE_CLOUD_INIT_GENERATED_HEADER_V1
        );
        assert_eq!(
            requirement.accepted.container_units[0].name,
            "docker.service"
        );
        assert_eq!(
            requirement.accepted.required_docker_running_workload_count,
            0
        );

        let transitions: serde_json::Value = serde_json::from_str(include_str!(
            "../.github/action-bundle-host-transitions.json"
        ))
        .unwrap();
        assert_eq!(transitions["schema_version"], 1);
        let transitions = transitions["transitions"].as_array().unwrap();
        assert!(transitions.is_empty());
    }

    #[test]
    fn fingerprint_v3_pins_trusted_paths_and_permission_ancestors() {
        let requirement = hosted_runner_fingerprint_requirement();

        assert_eq!(requirement.accepted.trusted_executables.len(), 12);
        assert_eq!(
            requirement
                .accepted
                .trusted_executables
                .iter()
                .map(|executable| (
                    executable.path,
                    executable.canonical_target,
                    executable.mode
                ))
                .collect::<Vec<_>>(),
            vec![
                ("/usr/bin/docker", "/usr/bin/docker", "0755"),
                ("/usr/bin/id", "/usr/bin/id", "0755"),
                ("/usr/bin/mount", "/usr/bin/mount", "4755"),
                ("/usr/bin/stat", "/usr/bin/stat", "0755"),
                ("/usr/bin/sudo", "/usr/bin/sudo", "4755"),
                ("/usr/bin/systemctl", "/usr/bin/systemctl", "0755"),
                ("/usr/bin/systemd-run", "/usr/bin/systemd-run", "0755"),
                ("/usr/bin/test", "/usr/bin/test", "0755"),
                ("/usr/bin/true", "/usr/bin/true", "0755"),
                ("/usr/bin/umount", "/usr/bin/umount", "4755"),
                ("/usr/sbin/visudo", "/usr/sbin/visudo", "0755"),
                ("/usr/sbin/nft", "/usr/sbin/nft", "0755"),
            ]
        );
        assert_eq!(
            requirement
                .accepted
                .trusted_executables
                .iter()
                .filter(|executable| executable.mode == "4755")
                .map(|executable| executable.path)
                .collect::<Vec<_>>(),
            vec!["/usr/bin/mount", "/usr/bin/sudo", "/usr/bin/umount"]
        );
        let test = requirement
            .accepted
            .trusted_executables
            .iter()
            .find(|executable| executable.path == "/usr/bin/test")
            .unwrap();
        assert_eq!(test.canonical_target, test.path);
        assert_eq!(test.mode, "0755");

        assert_eq!(
            requirement
                .accepted
                .permission_ancestor_directories
                .iter()
                .map(|ancestor| (
                    ancestor.path,
                    ancestor.canonical_target,
                    ancestor.mode,
                    ancestor.runner_searchable,
                ))
                .collect::<Vec<_>>(),
            vec![
                ("/", "/", "0755", true),
                ("/etc", "/etc", "0755", true),
                ("/etc/sudoers.d", "/etc/sudoers.d", "0750", false),
                ("/usr", "/usr", "0755", true),
                ("/usr/bin", "/usr/bin", "0755", true),
                ("/usr/sbin", "/usr/sbin", "0755", true),
            ]
        );
        let sudoers_directory = requirement
            .accepted
            .permission_ancestor_directories
            .iter()
            .find(|ancestor| ancestor.path == "/etc/sudoers.d")
            .unwrap();
        assert_eq!(sudoers_directory.mode, "0750");
        assert!(!sudoers_directory.runner_searchable);
        assert!(
            requirement
                .accepted
                .permission_ancestor_directories
                .iter()
                .filter(|ancestor| ancestor.path != "/etc/sudoers.d")
                .all(|ancestor| ancestor.runner_searchable)
        );

        let accepted_json = serde_json::to_value(&requirement.accepted).unwrap();
        assert!(accepted_json.get("executable_paths").is_none());
        assert!(!accepted_json.to_string().contains("\"device\""));
        assert!(!accepted_json.to_string().contains("\"inode\""));
    }

    #[test]
    fn fingerprint_v3_pins_exact_local_control_inventory_and_hash_contract() {
        let requirement = hosted_runner_fingerprint_requirement();

        let inventory = &requirement.accepted.local_control_inventory;
        assert_eq!(inventory.unix_name_hash_schema, UNIX_NAME_HASH_SCHEMA_V1);
        assert_eq!(inventory.root_container_processes.len(), 2);
        assert_eq!(inventory.tcp_listeners.len(), 2);
        assert_eq!(inventory.unix_listeners.len(), 10);
        assert_eq!(
            inventory
                .root_container_processes
                .iter()
                .map(|process| (
                    process.executable_basename,
                    process.canonical_executable,
                    process.unified_cgroup,
                    process.instances,
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "containerd",
                    "/usr/bin/containerd",
                    "/system.slice/containerd.service",
                    1,
                ),
                (
                    "dockerd",
                    "/usr/bin/dockerd",
                    "/system.slice/docker.service",
                    1,
                ),
            ]
        );
        assert!(inventory.tcp_listeners.iter().all(|listener| {
            listener.bind_class == "wildcard"
                && listener.port == 22
                && listener.instances == 1
                && listener.owners == vec![SYSTEMD_OWNER]
        }));
        assert_eq!(
            inventory
                .tcp_listeners
                .iter()
                .map(|listener| listener.family)
                .collect::<Vec<_>>(),
            vec!["ipv4", "ipv6"]
        );
        assert_eq!(
            inventory
                .unix_listeners
                .iter()
                .map(|listener| listener.name_sha256)
                .collect::<Vec<_>>(),
            vec![
                "2098ac544ed7672deda4863cf7f1ec11fd3916b31f7f02f8b1190394218612ec",
                "caf0d5ac99f3b95f921556138b2adbf4ceb0e8d48c61ef23d5180aa480b45743",
                "1f76b0a726958dc80a872b9ae4fb414457f7ee9cc80f419ff7dfc509f236e469",
                "2a5962ed41259a31b1587bcae589fcee6b9d6767ef064ac317e6d398b96a81f2",
                "68c0b0a26da3ac420889ddd0ab629df3f9defb482cf5a9daf7fdcd28ee545f29",
                "8b5e213b2b72a7033476e1f46afb302f0e4123c6e6fd746f77eeb744050e3b91",
                "ac10a069436547a18b02df8078e06421de7fc8953887fcc32f817af06b1b09bb",
                "ded56518cb66a7ddcdf9434f3280745cbb457869ea692d34cf0df494949bca96",
                "e84916b142c7b55bdf364843e9360867ec403fc602cfb662c95d6299ebfb8e77",
                "f7978cc2493e0ecd56d54a3f49e36c3bde79b3ac281baa0a0aed0efab0898c23",
            ]
        );
        assert_eq!(
            inventory
                .unix_listeners
                .iter()
                .map(|listener| listener.name_kind)
                .collect::<Vec<_>>(),
            vec![
                "abstract",
                "abstract",
                "filesystem",
                "filesystem",
                "filesystem",
                "filesystem",
                "filesystem",
                "filesystem",
                "filesystem",
                "filesystem",
            ]
        );
        assert!(inventory.unix_listeners.iter().all(|listener| {
            listener.socket_type == "stream"
                && listener.instances == 1
                && listener.name_sha256.len() == 64
                && listener
                    .name_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }));
        assert_eq!(
            inventory.unix_listeners[0].owners,
            vec![MULTIPATHD_OWNER, SYSTEMD_OWNER]
        );
        assert_eq!(
            inventory.unix_listeners[3].owners,
            vec![DOCKERD_OWNER, SYSTEMD_OWNER]
        );
        assert_eq!(
            inventory.unix_listeners[5].owners,
            vec![SYSTEMD_OWNER, DBUS_OWNER]
        );
        assert_eq!(
            inventory.standard_lockdown_removable_unix_listener_name_sha256,
            "2a5962ed41259a31b1587bcae589fcee6b9d6767ef064ac317e6d398b96a81f2"
        );

        let accepted_json = serde_json::to_value(&requirement.accepted).unwrap();
        let serialized_inventory = &accepted_json["local_control_inventory"];
        assert!(serialized_inventory.get("stable").is_none());
        assert!(serialized_inventory.get("ownership_complete").is_none());
        assert!(serialized_inventory.get("reachability_complete").is_none());
        assert!(
            !serialized_inventory
                .to_string()
                .contains("runner_reachable")
        );
    }
}
