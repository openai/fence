//! Protect the original socket inode and its host pathname through readiness.
use super::{LockdownError, TrustedExecutable, TrustedExecutableSet, fixed_command};
use crate::hosted_runner::ubuntu26::CONTROL_SOCKETS;
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const ORIGINAL: u32 = 0o666;
const SEALED: u32 = 0o600;

#[derive(Default, Debug)]
pub(super) struct SocketSeals {
    sockets: Vec<Seal>,
}

#[derive(Debug)]
struct Seal {
    path: &'static str,
    service_uid: u32,
    original: File,
    parent: File,
    identity: (u64, u64, u32, u32),
    original_mount: u64,
    bind_attempted: bool,
    // Keep the mount ID even when releasing its pin just before a normal unmount.
    owned_mount: Option<(u64, Option<File>)>,
    chmod_attempted: bool,
}

fn failed() -> LockdownError {
    LockdownError::new(
        "unsupported_host_fingerprint",
        "host control socket isolation could not be verified",
    )
}

fn check(value: bool) -> Result<(), LockdownError> {
    value.then_some(()).ok_or_else(failed)
}

impl SocketSeals {
    pub(super) fn restrict(&mut self, tools: &TrustedExecutableSet) -> Result<(), LockdownError> {
        check(tools.uses_ubuntu26_layout() && self.sockets.is_empty())?;
        verify_host_namespace()?;
        let inventory = tools
            .reviewed_local_control_inventory()
            .map_err(|_| failed())?;
        // Capture every original before changing even one pathname or mode.
        self.sockets = CONTROL_SOCKETS
            .iter()
            .filter(|entry| entry.requires_block_seal())
            .map(|entry| {
                let listener = inventory
                    .unix_listeners
                    .iter()
                    .find(|row| row.name_sha256 == entry.name_sha256)
                    .ok_or_else(failed)?;
                let service_uid = listener
                    .owners
                    .iter()
                    .map(|owner| owner.uid)
                    .max()
                    .ok_or_else(failed)?;
                Seal::capture(entry.path, service_uid)
            })
            .collect::<Result<_, _>>()?;
        verify_acls(tools, &self.sockets, ORIGINAL)?;
        for seal in &mut self.sockets {
            seal.bind(tools)?;
        }
        for seal in &mut self.sockets {
            seal.verify_owned(ORIGINAL)?;
            seal.chmod_attempted = true;
            mode(&seal.original, SEALED)?;
        }
        self.verify(tools)
    }

    pub(super) fn verify(&self, tools: &TrustedExecutableSet) -> Result<(), LockdownError> {
        check(
            tools.uses_ubuntu26_layout()
                && self.sockets.len()
                    == CONTROL_SOCKETS
                        .iter()
                        .filter(|entry| entry.requires_block_seal())
                        .count(),
        )?;
        verify_host_namespace()?;
        for seal in &self.sockets {
            check(seal.chmod_attempted)?;
            seal.verify_owned(SEALED)?;
        }
        verify_acls(tools, &self.sockets, SEALED)
    }

    pub(super) fn rollback(&mut self, tools: &TrustedExecutableSet) -> Result<bool, LockdownError> {
        if self.sockets.is_empty() {
            return Ok(false);
        }
        verify_host_namespace()?;
        let mut changed = false;
        let mut complete = true;
        for seal in self.sockets.iter_mut().rev() {
            match seal.rollback(tools) {
                Ok(restored) => changed |= restored,
                Err(_) => complete = false,
            }
        }
        check(complete)?;
        self.sockets.clear();
        Ok(changed)
    }
}

impl Seal {
    fn capture(path: &'static str, service_uid: u32) -> Result<Self, LockdownError> {
        safe_parents(path, service_uid)?;
        let parent = pin(Path::new(path).parent().ok_or_else(failed)?)?;
        let original = pin(path)?;
        let meta = original.metadata().map_err(|_| failed())?;
        check(
            meta.file_type().is_socket()
                && meta.nlink() == 1
                && meta.mode() & 0o7777 == ORIGINAL
                && (meta.uid() == 0 || meta.uid() == service_uid)
                && (meta.gid() == 0 || meta.gid() == service_uid),
        )?;
        let original_mount = mount_id(&original)?;
        check(mount_id(&parent)? == original_mount)?;
        let seal = Self {
            path,
            service_uid,
            identity: identity(&meta),
            original,
            parent,
            original_mount,
            bind_attempted: false,
            owned_mount: None,
            chmod_attempted: false,
        };
        check(seal.visible(ORIGINAL)?.1 == original_mount)?;
        Ok(seal)
    }

    fn visible(&self, expected_mode: u32) -> Result<(File, u64), LockdownError> {
        safe_parents(self.path, self.service_uid)?;
        let parent = pin(Path::new(self.path).parent().ok_or_else(failed)?)?;
        let current = pin(self.path)?;
        let host = pin(format!("/proc/1/root{}", self.path))?;
        let id = mount_id(&current)?;
        check(
            same_file(&self.parent, &parent)?
                && mount_id(&parent)? == self.original_mount
                && mount_id(&host)? == id,
        )?;
        for file in [&self.original, &current, &host] {
            let meta = file.metadata().map_err(|_| failed())?;
            check(
                identity(&meta) == self.identity
                    && meta.file_type().is_socket()
                    && meta.nlink() == 1
                    && meta.mode() & 0o7777 == expected_mode,
            )?;
        }
        Ok((current, id))
    }

    fn bind(&mut self, tools: &TrustedExecutableSet) -> Result<(), LockdownError> {
        check(self.visible(ORIGINAL)?.1 == self.original_mount)?;
        let anchor = descriptor_path(&self.original);
        self.bind_attempted = true;
        let result = fixed_command(
            tools,
            TrustedExecutable::Mount,
            &["--no-canonicalize", "--bind", "--", &anchor, &anchor],
        );
        // A killed or timed-out mount helper may already have completed the bind.
        let (current, id) = self.visible(ORIGINAL)?;
        if id != self.original_mount && mounted_here(self.path, id, self.original_mount)? {
            self.owned_mount = Some((id, Some(current)));
        }
        let output = result?;
        check(output.status.success() && output.stderr.is_empty() && self.owned_mount.is_some())
    }

    fn verify_owned(&self, expected_mode: u32) -> Result<(), LockdownError> {
        let (id, held) = self.owned_mount.as_ref().ok_or_else(failed)?;
        let (_, visible) = self.visible(expected_mode)?;
        check(
            visible == *id
                && *id != self.original_mount
                && held
                    .as_ref()
                    .is_some_and(|file| mount_id(file).ok() == Some(*id))
                && mounted_here(self.path, *id, self.original_mount)?,
        )
    }

    fn rollback(&mut self, tools: &TrustedExecutableSet) -> Result<bool, LockdownError> {
        if !self.bind_attempted {
            return Ok(false);
        }
        let current_mode = self.original.metadata().map_err(|_| failed())?.mode() & 0o7777;
        check(current_mode == ORIGINAL || self.chmod_attempted && current_mode == SEALED)?;
        verify_acls(tools, std::slice::from_ref(self), current_mode)?;
        let changed = self.owned_mount.is_some() || self.chmod_attempted;
        let (current, visible) = self.visible(current_mode)?;
        if visible != self.original_mount {
            let (owned_id, held) = self.owned_mount.as_mut().ok_or_else(failed)?;
            check(*owned_id == visible && mounted_here(self.path, visible, self.original_mount)?)?;
            // An open FD on this mount would make normal unmount return EBUSY.
            drop(current);
            held.take();
            let result = fixed_command(
                tools,
                TrustedExecutable::Umount,
                &["--no-canonicalize", "--internal-only", "--", self.path],
            );
            let (after, id) = self.visible(current_mode)?;
            if id == visible {
                self.owned_mount = Some((id, Some(after)));
            }
            check(id == self.original_mount)?;
            // The namespace and pinned original prove completion even after an ambiguous helper exit.
            drop(result);
            self.owned_mount = None;
        } else {
            // An owned mount that vanished before our unmount is unexplained drift.
            check(self.owned_mount.is_none())?;
        }
        if current_mode == SEALED {
            mode(&self.original, ORIGINAL)?;
        }
        check(self.visible(ORIGINAL)?.1 == self.original_mount)?;
        verify_acls(tools, std::slice::from_ref(self), ORIGINAL)?;
        self.bind_attempted = false;
        self.chmod_attempted = false;
        Ok(changed)
    }
}

fn mode(file: &File, value: u32) -> Result<(), LockdownError> {
    fs::set_permissions(descriptor_path(file), Permissions::from_mode(value)).map_err(|_| failed())
}

fn descriptor_path(file: &File) -> String {
    format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd())
}

fn identity(meta: &Metadata) -> (u64, u64, u32, u32) {
    (meta.dev(), meta.ino(), meta.uid(), meta.gid())
}

fn same_file(left: &File, right: &File) -> Result<bool, LockdownError> {
    Ok(identity(&left.metadata().map_err(|_| failed())?)
        == identity(&right.metadata().map_err(|_| failed())?))
}

fn verify_host_namespace() -> Result<(), LockdownError> {
    let host = fs::metadata("/proc/1/ns/mnt").map_err(|_| failed())?;
    let current = fs::metadata("/proc/self/ns/mnt").map_err(|_| failed())?;
    check((host.dev(), host.ino()) == (current.dev(), current.ino()))
}

fn safe_parents(path: &str, service_uid: u32) -> Result<(), LockdownError> {
    let parent = Path::new(path).parent().ok_or_else(failed)?;
    for ancestor in parent.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| failed())?;
        let owner_ok = meta.uid() == 0 || ancestor == parent && meta.uid() == service_uid;
        check(meta.is_dir() && owner_ok && meta.mode() & 0o022 == 0)?;
    }
    Ok(())
}

fn pin(path: impl AsRef<Path>) -> Result<File, LockdownError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| failed())
}

fn proc_text(path: impl AsRef<Path>, limit: u64) -> Result<String, LockdownError> {
    let mut data = String::new();
    File::open(path)
        .map_err(|_| failed())?
        .take(limit + 1)
        .read_to_string(&mut data)
        .map_err(|_| failed())?;
    check(data.len() as u64 <= limit)?;
    Ok(data)
}

fn mount_id(file: &File) -> Result<u64, LockdownError> {
    let info = proc_text(format!("/proc/self/fdinfo/{}", file.as_raw_fd()), 8192)?;
    let mut ids = info
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:\t"));
    let id = ids
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(failed)?;
    check(id != 0 && ids.next().is_none())?;
    Ok(id)
}

fn mounted_here(path: &str, id: u64, parent_id: u64) -> Result<bool, LockdownError> {
    let info = proc_text("/proc/self/mountinfo", 1024 * 1024)?;
    Ok(matches_mount(&info, path, id, parent_id))
}

fn matches_mount(info: &str, path: &str, id: u64, parent_id: u64) -> bool {
    let mut records = info
        .lines()
        .filter(|line| line.split_ascii_whitespace().nth(4) == Some(path));
    let Some(mut fields) = records.next().map(str::split_ascii_whitespace) else {
        return false;
    };
    fields.next().and_then(|value| value.parse().ok()) == Some(id)
        && fields.next().and_then(|value| value.parse().ok()) == Some(parent_id)
        && records.next().is_none()
}

fn verify_acls(
    tools: &TrustedExecutableSet,
    sockets: &[Seal],
    expected: u32,
) -> Result<(), LockdownError> {
    let paths: Vec<_> = sockets
        .iter()
        .map(|socket| descriptor_path(&socket.original))
        .collect();
    let mut args = vec!["--absolute-names", "--omit-header", "--numeric", "--"];
    args.extend(paths.iter().map(String::as_str));
    let output = fixed_command(tools, TrustedExecutable::Getfacl, &args)?;
    check(
        output.status.success()
            && output.stderr.is_empty()
            && exact_acls(&output.stdout, paths.len(), expected),
    )
}

fn exact_acls(data: &[u8], count: usize, expected: u32) -> bool {
    let entries = match expected {
        ORIGINAL => ["user::rw-", "group::rw-", "other::rw-"],
        SEALED => ["user::rw-", "group::---", "other::---"],
        _ => return false,
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    count != 0
        && text
            .lines()
            .filter(|line| !line.is_empty())
            .eq((0..count).flat_map(|_| entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_require_exact_base_acl_for_every_descriptor() {
        let plain = b"user::rw-\ngroup::rw-\nother::rw-\n\n";
        let sealed = b"user::rw-\ngroup::---\nother::---\n\n";
        assert!(exact_acls(&plain.repeat(2), 2, ORIGINAL));
        assert!(exact_acls(sealed, 1, SEALED));
        assert!(!exact_acls(plain, 2, ORIGINAL));
        assert!(!exact_acls(plain, 1, SEALED));
        assert!(!exact_acls(
            b"user::rw-\nuser:1001:rw-\ngroup::---\nmask::---\nother::---\n",
            1,
            SEALED
        ));
        assert!(!exact_acls(&[], 0, SEALED));
    }

    #[test]
    fn only_one_mount_at_the_expected_path_with_its_original_parent_is_owned() {
        let line = "101 37 0:23 /socket /run/socket rw - tmpfs tmpfs rw\n";
        assert!(matches_mount(line, "/run/socket", 101, 37));
        assert!(!matches_mount(line, "/run/other", 101, 37));
        assert!(!matches_mount(line, "/run/socket", 102, 37));
        assert!(!matches_mount(line, "/run/socket", 101, 38));
        assert!(!matches_mount(&line.repeat(2), "/run/socket", 101, 37));
    }
}
