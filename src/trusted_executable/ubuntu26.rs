use super::{TrustedExecutable, TrustedExecutableError, validate_retained_descriptor};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

// These entries are the actual link bytes, including the two relative spellings.
const LINKS: &[(&str, &str)] = &[
    ("/usr/bin/id", "../lib/cargo/bin/coreutils/id"),
    ("/usr/bin/stat", "../lib/cargo/bin/coreutils/stat"),
    ("/usr/bin/test", "../lib/cargo/bin/coreutils/test"),
    ("/usr/bin/true", "gnutrue"),
    ("/usr/bin/sudo", "/etc/alternatives/sudo"),
    ("/etc/alternatives/sudo", "/usr/lib/cargo/bin/sudo"),
    ("/usr/sbin/visudo", "/etc/alternatives/visudo"),
    ("/etc/alternatives/visudo", "/usr/lib/cargo/bin/visudo"),
];

pub(super) const EXTRA_DIRECTORIES: &[&str] = &[
    "/etc/alternatives",
    "/usr/lib",
    "/usr/lib/cargo",
    "/usr/lib/cargo/bin",
    "/usr/lib/cargo/bin/coreutils",
];

pub(super) fn target(executable: TrustedExecutable) -> &'static str {
    match executable {
        TrustedExecutable::Id => "/usr/lib/cargo/bin/coreutils/id",
        TrustedExecutable::Stat => "/usr/lib/cargo/bin/coreutils/stat",
        TrustedExecutable::Test => "/usr/lib/cargo/bin/coreutils/test",
        TrustedExecutable::True => "/usr/bin/gnutrue",
        TrustedExecutable::Sudo => "/usr/lib/cargo/bin/sudo",
        TrustedExecutable::Visudo => "/usr/lib/cargo/bin/visudo",
        other => other.path(),
    }
}

#[derive(Debug)]
enum EntryKind {
    Directory,
    Link(&'static str),
}

#[derive(Debug)]
struct PinnedEntry {
    path: PathBuf,
    kind: EntryKind,
    // Keeping the link or directory inode open prevents replacement and inode reuse
    // from looking like the original. O_PATH|O_NOFOLLOW opens the link itself.
    file: File,
}

impl PinnedEntry {
    fn capture(
        path: &Path,
        kind: EntryKind,
        owner: (u32, u32),
    ) -> Result<Self, TrustedExecutableError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| TrustedExecutableError::unavailable())?;
        validate_retained_descriptor(file.as_raw_fd())?;
        let entry = Self {
            path: path.to_owned(),
            kind,
            file,
        };
        if !entry.matches(owner) {
            return Err(TrustedExecutableError::unavailable());
        }
        Ok(entry)
    }

    fn matches(&self, owner: (u32, u32)) -> bool {
        let (Ok(pinned), Ok(current)) = (self.file.metadata(), fs::symlink_metadata(&self.path))
        else {
            return false;
        };
        if pinned.dev() != current.dev()
            || pinned.ino() != current.ino()
            || (current.uid(), current.gid()) != owner
        {
            return false;
        }
        let mode = current.permissions().mode() & 0o7777;
        match self.kind {
            EntryKind::Directory => current.is_dir() && mode == 0o755,
            EntryKind::Link(literal) => {
                current.is_symlink()
                    && mode == 0o777
                    && fs::read_link(&self.path).is_ok_and(|link| link.as_os_str() == literal)
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct Layout(Vec<PinnedEntry>);

impl Layout {
    pub(super) fn capture() -> Result<Self, TrustedExecutableError> {
        let mut entries = Vec::new();
        // Establish the whole parent chain before reading any link or executable.
        for directory in ["/", "/etc", "/usr", "/usr/bin", "/usr/sbin"]
            .into_iter()
            .chain(EXTRA_DIRECTORIES.iter().copied())
        {
            entries.push(PinnedEntry::capture(
                Path::new(directory),
                EntryKind::Directory,
                (0, 0),
            )?);
        }
        for &(path, literal) in LINKS {
            entries.push(PinnedEntry::capture(
                Path::new(path),
                EntryKind::Link(literal),
                (0, 0),
            )?);
        }
        Ok(Self(entries))
    }

    pub(super) fn matches(&self) -> bool {
        self.0.iter().all(|entry| entry.matches((0, 0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_executable::tests::test_directory;
    use std::os::unix::fs::symlink;

    #[test]
    fn link_bytes_and_inode_are_both_pinned() {
        let root = test_directory();
        let meta = root.metadata().unwrap();
        let owner = (meta.uid(), meta.gid());
        let link = root.join("tool");
        let replacement = root.join("replacement");
        symlink("./tool.bin", &link).unwrap();
        assert!(PinnedEntry::capture(&link, EntryKind::Link("tool.bin"), owner).is_err());
        let pinned = PinnedEntry::capture(&link, EntryKind::Link("./tool.bin"), owner).unwrap();
        assert!(pinned.matches(owner));
        assert!(!pinned.matches((owner.0.wrapping_add(1), owner.1)));
        symlink("./tool.bin", &replacement).unwrap();
        fs::rename(replacement, &link).unwrap();
        assert!(!pinned.matches(owner));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redirected_replaced_or_writable_directory_is_rejected() {
        let root = test_directory();
        let meta = root.metadata().unwrap();
        let owner = (meta.uid(), meta.gid());
        let directory = root.join("bin");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        let pinned = PinnedEntry::capture(&directory, EntryKind::Directory, owner).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(!pinned.matches(owner));
        assert!(PinnedEntry::capture(&directory, EntryKind::Directory, owner).is_err());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&directory, root.join("old")).unwrap();
        symlink("old", &directory).unwrap();
        assert!(!pinned.matches(owner));
        assert!(PinnedEntry::capture(&directory, EntryKind::Directory, owner).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runner_probe_requires_classic_sudo_and_standalone_test() {
        use super::super::{PinnedExecutable, TrustedExecutableSet};
        use std::collections::BTreeMap;

        let root = test_directory();
        let mut executables = BTreeMap::new();
        for tool in [TrustedExecutable::ClassicSudo, TrustedExecutable::GnuTest] {
            let name = Path::new(tool.path()).file_name().unwrap();
            let path = root.join(name);
            fs::copy("/usr/bin/true", &path).unwrap();
            let meta = path.metadata().unwrap();
            let pinned =
                PinnedExecutable::capture(&path, meta.uid(), meta.gid(), meta.mode() & 0o7777)
                    .unwrap();
            executables.insert(tool, pinned);
        }
        let set = TrustedExecutableSet {
            executables,
            ubuntu26: Some(Layout(Vec::new())),
        };
        let probe = || {
            set.runner_command_with_process_stat(
                TrustedExecutable::Test,
                &["-x", "/"],
                "123 (fence) S 1 2 3 0 5 6\n",
            )
        };
        let command = probe().unwrap();
        assert_eq!(
            command.get_program(),
            set.get(TrustedExecutable::ClassicSudo)
                .unwrap()
                .descriptor_path()
        );
        assert!(
            command
                .get_args()
                .any(|argument| argument == "/proc/self/fd/0")
        );
        fs::rename(root.join("gnutest"), root.join("removed")).unwrap();
        assert_eq!(probe().unwrap_err().code, "trusted_executable_drift");
        fs::remove_dir_all(root).unwrap();
    }
}
