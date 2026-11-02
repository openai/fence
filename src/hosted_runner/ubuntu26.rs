//! Checked Ubuntu 26.04 service endpoints. These are the pre-lockdown/audit reference.
//! Being in this reference does not authorize a reachable endpoint after block lockdown.
use super::{
    AcceptedLocalControlInventoryV2, AcceptedLocalControlOwnerV2, AcceptedUnixListenerV2,
    JOURNALD_OWNER, MULTIPATHD_OWNER, SYSTEMD_OWNER,
};

pub(crate) const LOGIN_SOCKET_SHA256: &str =
    "ed9ec594491cbf51f1942cfaf87d6eb017724ff2a244c2106bec48c7264fa470";
pub(crate) const LOGIND_PATH: &str = "/usr/lib/systemd/systemd-logind";
pub(crate) const LOGIND_CGROUP: &str = "/system.slice/systemd-logind.service";
pub(crate) const SSHD_PATH: &str = "/usr/sbin/sshd";
pub(crate) const SSHD_CGROUP: &str = "/system.slice/ssh.service";

#[derive(Clone, Copy)]
enum Owners {
    Manager,
    Multipath,
    Network,
    Resolver,
    Journal,
    Login,
}

pub(crate) struct ControlSocket {
    pub(crate) path: &'static str,
    pub(crate) name_sha256: &'static str,
    owners: Owners,
}

impl ControlSocket {
    pub(crate) fn requires_block_seal(&self) -> bool {
        // Nonroot multipath commands are restricted by peer UID. This networkd hook
        // only answers from local DHCP leases; the separate management API is sealed.
        !matches!(
            (self.path, self.owners),
            ("/run/multipathd.socket", Owners::Multipath)
                | (
                    "/run/systemd/resolve.hook/io.systemd.Network",
                    Owners::Network
                )
        )
    }
}

pub(crate) const CONTROL_SOCKETS: &[ControlSocket] = &[
    ControlSocket {
        path: "/run/multipathd.socket",
        name_sha256: "204f387fae128795b510e2ad04a1add8b40aea6ab67475e0b1d9e0c7fa8234b5",
        owners: Owners::Multipath,
    },
    ControlSocket {
        path: "/run/systemd/resolve.hook/io.systemd.Network",
        name_sha256: "1b69773ca2b8b171b23ebd0ff8aeb8c1c4ec2a42c0e8437692e1c4e354c7298d",
        owners: Owners::Network,
    },
    ControlSocket {
        path: "/run/systemd/resolve/io.systemd.Resolve",
        name_sha256: "449a7f1ea88bcc0cc691c7d4264ef489328020137b3f2810e2cf9747aa3f8e83",
        owners: Owners::Resolver,
    },
    ControlSocket {
        path: "/run/systemd/io.systemd.FactoryReset",
        name_sha256: "53627dcb5f40414980a24040e43b49c0932412344287b63f2a6b09aef4f5a42d",
        owners: Owners::Manager,
    },
    ControlSocket {
        path: "/run/systemd/journal/io.systemd.journal",
        name_sha256: "6b13e8ac90711b42aeecc8d85e1422ee79c1491b7ce2393ae024d207098dbc48",
        owners: Owners::Journal,
    },
    ControlSocket {
        path: "/run/systemd/io.systemd.Hostname",
        name_sha256: "7464c24a58e5d2cd87b34dac5ae497f3a38cb118f98a683c15e1d83ba4f6f786",
        owners: Owners::Manager,
    },
    ControlSocket {
        path: "/run/ssh-unix-local/socket",
        name_sha256: "76c19f8bbb94053b996fce94f7c090eaa7b2a3508da25ed54737409557322ce6",
        owners: Owners::Manager,
    },
    ControlSocket {
        path: "/run/systemd/io.systemd.Manager",
        name_sha256: "916d0972b7bebedbf622b464303f12106be99ae1fcf07612d4e7a2886ff6d838",
        owners: Owners::Manager,
    },
    ControlSocket {
        path: "/run/systemd/io.systemd.AskPassword",
        name_sha256: "9da664bdedc28e440d9b1b54197da79e80645a16e188edfbecf995ccfb6bbaeb",
        owners: Owners::Manager,
    },
    ControlSocket {
        path: "/run/systemd/io.systemd.Credentials",
        name_sha256: "ab469ecec36b0604726510d0569bacdc3c2ffffa4ed2494d69f1cee42c42c092",
        owners: Owners::Manager,
    },
    ControlSocket {
        path: "/run/systemd/resolve/io.systemd.Resolve.Monitor",
        name_sha256: "d95936f0cff64930e551eaaae2748bb89436eff9d982dbbba836502c3646cd48",
        owners: Owners::Resolver,
    },
    ControlSocket {
        path: "/run/polkit/agent-helper.socket",
        name_sha256: "de581bf1cfbef58a93e636f3ae095dc40bd638fa86b25432a301b3380ead094d",
        owners: Owners::Manager,
    },
    ControlSocket {
        path: "/run/systemd/io.systemd.Login",
        name_sha256: LOGIN_SOCKET_SHA256,
        owners: Owners::Login,
    },
    ControlSocket {
        path: "/run/systemd/netif/io.systemd.Network",
        name_sha256: "f9e84dd3b07e74eb100a9ad2bcfe3dae928f5e7e3707ea924a7e918dd5751508",
        owners: Owners::Network,
    },
];

pub(crate) fn extend_inventory(
    accepted: &mut AcceptedLocalControlInventoryV2,
    network_uid: u32,
    resolver_uid: u32,
    messagebus_uid: u32,
) {
    accepted.ubuntu26 = true;
    // Both LTS images expose the system bus. Ubuntu chooses its service UID at installation.
    for socket in &mut accepted.unix_listeners {
        if socket.name_sha256 == super::SYSTEM_BUS_NAME_SHA256 {
            socket.owners = vec![
                SYSTEMD_OWNER,
                super::AcceptedLocalControlOwnerV2 {
                    uid: messagebus_uid,
                    ..super::DBUS_OWNER
                },
            ];
        }
    }
    for entry in CONTROL_SOCKETS {
        let owners = match entry.owners {
            Owners::Manager => vec![SYSTEMD_OWNER],
            Owners::Multipath => vec![MULTIPATHD_OWNER],
            Owners::Journal => vec![JOURNALD_OWNER],
            Owners::Network => vec![
                SYSTEMD_OWNER,
                service(
                    network_uid,
                    "systemd-networkd",
                    "/usr/lib/systemd/systemd-networkd",
                    "/system.slice/systemd-networkd.service",
                ),
            ],
            Owners::Resolver => vec![
                SYSTEMD_OWNER,
                service(
                    resolver_uid,
                    "systemd-resolved",
                    "/usr/lib/systemd/systemd-resolved",
                    "/system.slice/systemd-resolved.service",
                ),
            ],
            Owners::Login => vec![
                SYSTEMD_OWNER,
                service(0, "systemd-logind", LOGIND_PATH, LOGIND_CGROUP),
            ],
        };
        accepted.unix_listeners.push(AcceptedUnixListenerV2 {
            name_kind: "filesystem",
            socket_type: "stream",
            instances: 1,
            name_sha256: entry.name_sha256,
            owners,
        });
    }
    for listener in &mut accepted.tcp_listeners {
        if listener.bind_class == "wildcard" && listener.port == 22 {
            listener
                .owners
                .push(service(0, "sshd", SSHD_PATH, SSHD_CGROUP));
        }
    }
}

fn service(
    uid: u32,
    basename: &'static str,
    executable: &'static str,
    cgroup: &'static str,
) -> AcceptedLocalControlOwnerV2 {
    AcceptedLocalControlOwnerV2 {
        uid,
        executable_basename: basename,
        canonical_executable: executable,
        unified_cgroup: cgroup,
        processes: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted_runner::{AcceptedTcpListenerV2, hosted_runner_fingerprint_requirement};
    use sha2::{Digest, Sha256};

    #[test]
    fn only_the_two_read_only_path_and_service_pairs_remain_reachable() {
        let unsealed: std::collections::BTreeSet<_> = CONTROL_SOCKETS
            .iter()
            .filter(|entry| !entry.requires_block_seal())
            .map(|entry| entry.path)
            .collect();
        assert_eq!(
            unsealed,
            [
                "/run/multipathd.socket",
                "/run/systemd/resolve.hook/io.systemd.Network"
            ]
            .into()
        );
        for (path, owners) in [
            ("/run/multipathd.socket", Owners::Manager),
            (
                "/run/systemd/resolve.hook/io.systemd.Network",
                Owners::Resolver,
            ),
            ("/run/systemd/netif/io.systemd.Network", Owners::Network),
        ] {
            assert!(
                ControlSocket {
                    path,
                    name_sha256: "",
                    owners
                }
                .requires_block_seal()
            );
        }
    }

    #[test]
    fn each_reviewed_path_has_its_own_digest_and_exact_service_owners() {
        let network = AcceptedLocalControlOwnerV2 {
            uid: 507,
            executable_basename: "systemd-networkd",
            canonical_executable: "/usr/lib/systemd/systemd-networkd",
            unified_cgroup: "/system.slice/systemd-networkd.service",
            processes: 1,
        };
        let resolver = AcceptedLocalControlOwnerV2 {
            uid: 508,
            executable_basename: "systemd-resolved",
            canonical_executable: "/usr/lib/systemd/systemd-resolved",
            unified_cgroup: "/system.slice/systemd-resolved.service",
            processes: 1,
        };
        let login = AcceptedLocalControlOwnerV2 {
            uid: 0,
            executable_basename: "systemd-logind",
            canonical_executable: "/usr/lib/systemd/systemd-logind",
            unified_cgroup: "/system.slice/systemd-logind.service",
            processes: 1,
        };
        let paths_by_owners: &[(&[&str], &[AcceptedLocalControlOwnerV2])] = &[
            (
                &[
                    "/run/polkit/agent-helper.socket",
                    "/run/ssh-unix-local/socket",
                    "/run/systemd/io.systemd.AskPassword",
                    "/run/systemd/io.systemd.Credentials",
                    "/run/systemd/io.systemd.FactoryReset",
                    "/run/systemd/io.systemd.Hostname",
                    "/run/systemd/io.systemd.Manager",
                ],
                &[SYSTEMD_OWNER],
            ),
            (&["/run/multipathd.socket"], &[MULTIPATHD_OWNER]),
            (
                &["/run/systemd/journal/io.systemd.journal"],
                &[JOURNALD_OWNER],
            ),
            (&["/run/systemd/io.systemd.Login"], &[SYSTEMD_OWNER, login]),
            (
                &[
                    "/run/systemd/resolve.hook/io.systemd.Network",
                    "/run/systemd/netif/io.systemd.Network",
                ],
                &[SYSTEMD_OWNER, network],
            ),
            (
                &[
                    "/run/systemd/resolve/io.systemd.Resolve",
                    "/run/systemd/resolve/io.systemd.Resolve.Monitor",
                ],
                &[SYSTEMD_OWNER, resolver],
            ),
        ];
        let mut accepted = hosted_runner_fingerprint_requirement()
            .accepted
            .local_control_inventory;
        let baseline = accepted.unix_listeners.clone();
        extend_inventory(&mut accepted, 507, 508, super::super::DBUS_OWNER.uid);
        let added = accepted
            .unix_listeners
            .strip_prefix(baseline.as_slice())
            .unwrap();
        let expected_count = paths_by_owners
            .iter()
            .map(|(paths, _)| paths.len())
            .sum::<usize>();
        assert_eq!(added.len(), expected_count);
        assert_eq!(CONTROL_SOCKETS.len(), expected_count);
        for &(paths, owners) in paths_by_owners {
            for &path in paths {
                let digest = Sha256::new()
                    .chain_update(b"fence-unix-name-v1\0")
                    .chain_update(path)
                    .finalize();
                let key: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                let control = CONTROL_SOCKETS
                    .iter()
                    .find(|control| control.path == path)
                    .unwrap();
                assert_eq!(control.name_sha256, key);
                let entry = added.iter().find(|entry| entry.name_sha256 == key).unwrap();
                assert_eq!(
                    (entry.name_kind, entry.socket_type, entry.instances),
                    ("filesystem", "stream", 1)
                );
                assert_eq!(entry.owners, owners);
            }
        }
    }

    #[test]
    fn sshd_is_added_only_to_the_reviewed_wildcard_ssh_listeners() {
        let mut accepted = hosted_runner_fingerprint_requirement()
            .accepted
            .local_control_inventory;
        let mut expected = accepted.tcp_listeners.clone();
        for listener in &mut expected {
            assert_eq!((listener.bind_class, listener.port), ("wildcard", 22));
            listener.owners.push(AcceptedLocalControlOwnerV2 {
                uid: 0,
                executable_basename: "sshd",
                canonical_executable: "/usr/sbin/sshd",
                unified_cgroup: "/system.slice/ssh.service",
                processes: 1,
            });
        }
        for (bind_class, port) in [("loopback", 22), ("wildcard", 2222)] {
            let other = AcceptedTcpListenerV2 {
                family: "ipv4",
                bind_class,
                port,
                owners: vec![SYSTEMD_OWNER],
                instances: 1,
            };
            accepted.tcp_listeners.push(other.clone());
            expected.push(other);
        }
        extend_inventory(&mut accepted, 507, 508, super::super::DBUS_OWNER.uid);
        assert_eq!(accepted.tcp_listeners, expected);
    }
}
