use crate::hosted_runner::{AcceptedTrustedExecutableV2, hosted_runner_fingerprint_requirement};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const ROOT_UID: u32 = 0;
const ROOT_GID: u32 = 0;
const RUNNER_PRINCIPAL: &str = "runner";
const MIN_RETAINED_EXECUTABLE_FD: i32 = 3;
const STANDARD_DESCRIPTOR_RESERVATION_COUNT: usize = 3;
const PROC_SELF_STAT_PATH: &str = "/proc/self/stat";
const MAX_PROC_SELF_STAT_BYTES: u64 = 4 * 1024;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum TrustedExecutable {
    Docker,
    Id,
    Mount,
    Nft,
    Stat,
    Sudo,
    Systemctl,
    SystemdRun,
    Test,
    True,
    Umount,
    Visudo,
}

impl TrustedExecutable {
    const ALL: [Self; 12] = [
        Self::Docker,
        Self::Id,
        Self::Mount,
        Self::Nft,
        Self::Stat,
        Self::Sudo,
        Self::Systemctl,
        Self::SystemdRun,
        Self::Test,
        Self::True,
        Self::Umount,
        Self::Visudo,
    ];

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Docker => "/usr/bin/docker",
            Self::Id => "/usr/bin/id",
            Self::Mount => "/usr/bin/mount",
            Self::Nft => "/usr/sbin/nft",
            Self::Stat => "/usr/bin/stat",
            Self::Sudo => "/usr/bin/sudo",
            Self::Systemctl => "/usr/bin/systemctl",
            Self::SystemdRun => "/usr/bin/systemd-run",
            Self::Test => "/usr/bin/test",
            Self::True => "/usr/bin/true",
            Self::Umount => "/usr/bin/umount",
            Self::Visudo => "/usr/sbin/visudo",
        }
    }

    fn from_path(path: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|executable| executable.path() == path)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TrustedExecutableSpec {
    pub(crate) executable: TrustedExecutable,
    pub(crate) canonical_path: &'static str,
    pub(crate) mode: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TrustedExecutableError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

impl TrustedExecutableError {
    fn unavailable() -> Self {
        Self {
            code: "trusted_executable_unavailable",
            message: "the fixed trusted-executable boundary is unavailable",
        }
    }

    fn drift() -> Self {
        Self {
            code: "trusted_executable_drift",
            message: "a fixed trusted executable changed after capture",
        }
    }
}

fn reserve_standard_descriptors() -> Result<Vec<File>, TrustedExecutableError> {
    let mut reservations = Vec::with_capacity(STANDARD_DESCRIPTOR_RESERVATION_COUNT);
    for _ in 0..STANDARD_DESCRIPTOR_RESERVATION_COUNT {
        reservations.push(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open("/dev/null")
                .map_err(|_| TrustedExecutableError::unavailable())?,
        );
    }
    Ok(reservations)
}

fn validate_retained_descriptor(fd: i32) -> Result<(), TrustedExecutableError> {
    if fd < MIN_RETAINED_EXECUTABLE_FD {
        Err(TrustedExecutableError::unavailable())
    } else {
        Ok(())
    }
}

fn read_process_stat(path: &Path) -> Result<String, TrustedExecutableError> {
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| TrustedExecutableError::unavailable())?;
    let mut contents = String::new();
    source
        .take(MAX_PROC_SELF_STAT_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|_| TrustedExecutableError::unavailable())?;
    if contents.len() as u64 > MAX_PROC_SELF_STAT_BYTES {
        return Err(TrustedExecutableError::unavailable());
    }
    Ok(contents)
}

fn parse_process_tty_nr(contents: &str) -> Result<i32, TrustedExecutableError> {
    let opening_parenthesis = contents
        .find('(')
        .ok_or_else(TrustedExecutableError::unavailable)?;
    let closing_parenthesis = contents
        .rfind(')')
        .filter(|closing| *closing > opening_parenthesis)
        .ok_or_else(TrustedExecutableError::unavailable)?;
    contents[..opening_parenthesis]
        .trim()
        .parse::<u32>()
        .map_err(|_| TrustedExecutableError::unavailable())?;

    let mut fields = contents[closing_parenthesis + 1..].split_ascii_whitespace();
    let state = fields
        .next()
        .filter(|value| value.len() == 1)
        .ok_or_else(TrustedExecutableError::unavailable)?;
    if !state.as_bytes()[0].is_ascii_alphabetic() {
        return Err(TrustedExecutableError::unavailable());
    }
    for _ in 0..3 {
        fields
            .next()
            .ok_or_else(TrustedExecutableError::unavailable)?
            .parse::<i64>()
            .map_err(|_| TrustedExecutableError::unavailable())?;
    }
    fields
        .next()
        .ok_or_else(TrustedExecutableError::unavailable)?
        .parse::<i32>()
        .map_err(|_| TrustedExecutableError::unavailable())
}

fn require_no_controlling_terminal(contents: &str) -> Result<(), TrustedExecutableError> {
    if parse_process_tty_nr(contents)? == 0 {
        Ok(())
    } else {
        Err(TrustedExecutableError::unavailable())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct TrustedExecutableIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct PinnedExecutable {
    path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    identity: TrustedExecutableIdentity,
    file: File,
}

impl PinnedExecutable {
    fn capture(
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
        expected_mode: u32,
    ) -> Result<Self, TrustedExecutableError> {
        if !path.is_absolute() || fs::canonicalize(path).ok().as_deref() != Some(path) {
            return Err(TrustedExecutableError::unavailable());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| TrustedExecutableError::unavailable())?;
        validate_retained_descriptor(file.as_raw_fd())?;
        let metadata = file
            .metadata()
            .map_err(|_| TrustedExecutableError::unavailable())?;
        validate_metadata(
            &metadata,
            expected_uid,
            expected_gid,
            expected_mode,
            TrustedExecutableError::unavailable,
        )?;
        let captured = Self {
            path: path.to_path_buf(),
            expected_uid,
            expected_gid,
            expected_mode,
            identity: TrustedExecutableIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            file,
        };
        captured
            .verify_path_with(TrustedExecutableError::unavailable)
            .map(|()| captured)
    }

    fn verify_path(&self) -> Result<(), TrustedExecutableError> {
        self.verify_path_with(TrustedExecutableError::drift)
    }

    fn verify_path_with(
        &self,
        error: fn() -> TrustedExecutableError,
    ) -> Result<(), TrustedExecutableError> {
        if fs::canonicalize(&self.path).ok().as_deref() != Some(self.path.as_path()) {
            return Err(error());
        }
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| error())?;
        validate_metadata(
            &metadata,
            self.expected_uid,
            self.expected_gid,
            self.expected_mode,
            error,
        )?;
        if metadata.dev() != self.identity.device || metadata.ino() != self.identity.inode {
            return Err(error());
        }
        Ok(())
    }

    fn descriptor_path(&self) -> OsString {
        OsString::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    fn command(&self) -> Result<Command, TrustedExecutableError> {
        self.verify_path()?;
        let mut command = Command::new(self.descriptor_path());
        command.arg0(&self.path);
        Ok(command)
    }
}

fn validate_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    error: fn() -> TrustedExecutableError,
) -> Result<(), TrustedExecutableError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != expected_mode
    {
        return Err(error());
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct TrustedExecutableSet {
    executables: BTreeMap<TrustedExecutable, PinnedExecutable>,
}

impl TrustedExecutableSet {
    pub(crate) fn capture_reviewed_hosted() -> Result<Self, TrustedExecutableError> {
        let specs = reviewed_hosted_specs()?;
        Self::capture(&specs)
    }

    pub(crate) fn capture(specs: &[TrustedExecutableSpec]) -> Result<Self, TrustedExecutableError> {
        if !specs_are_complete(specs) {
            return Err(TrustedExecutableError::unavailable());
        }
        let standard_descriptor_reservations = reserve_standard_descriptors()?;
        let mut executables = BTreeMap::new();
        for spec in specs {
            let pinned = PinnedExecutable::capture(
                Path::new(spec.canonical_path),
                ROOT_UID,
                ROOT_GID,
                spec.mode,
            )?;
            executables.insert(spec.executable, pinned);
        }
        drop(standard_descriptor_reservations);
        Ok(Self { executables })
    }

    pub(crate) fn verify_all(&self) -> Result<(), TrustedExecutableError> {
        for executable in self.executables.values() {
            executable.verify_path()?;
        }
        Ok(())
    }

    pub(crate) fn command(
        &self,
        executable: TrustedExecutable,
    ) -> Result<Command, TrustedExecutableError> {
        self.get(executable)?.command()
    }

    pub(crate) fn runner_command(
        &self,
        executable: TrustedExecutable,
        arguments: &[&str],
    ) -> Result<Command, TrustedExecutableError> {
        let process_stat = read_process_stat(Path::new(PROC_SELF_STAT_PATH))?;
        self.runner_command_with_process_stat(executable, arguments, &process_stat)
    }

    fn runner_command_with_process_stat(
        &self,
        executable: TrustedExecutable,
        arguments: &[&str],
        process_stat: &str,
    ) -> Result<Command, TrustedExecutableError> {
        require_no_controlling_terminal(process_stat)?;
        let sudo = self.get(TrustedExecutable::Sudo)?;
        let target = self.get(executable)?;
        sudo.verify_path()?;
        target.verify_path()?;
        let target_file = target
            .file
            .try_clone()
            .map_err(|_| TrustedExecutableError::drift())?;
        let mut command = sudo.command()?;
        // The retained descriptors remain close-on-exec. A short-lived clone is
        // deliberately mapped to the child's standard input so sudo can execute
        // the captured target through /proc without inheriting an ambient fd.
        // These fixed non-interactive probes do not consume standard input.
        command.args([
            "--non-interactive",
            "--user",
            RUNNER_PRINCIPAL,
            "--",
            "/proc/self/fd/0",
        ]);
        command.args(arguments);
        command.stdin(Stdio::from(target_file));
        Ok(command)
    }

    fn get(
        &self,
        executable: TrustedExecutable,
    ) -> Result<&PinnedExecutable, TrustedExecutableError> {
        self.executables
            .get(&executable)
            .ok_or_else(TrustedExecutableError::unavailable)
    }

    #[cfg(test)]
    fn capture_for_test(
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
        expected_mode: u32,
    ) -> Result<PinnedExecutable, TrustedExecutableError> {
        PinnedExecutable::capture(path, expected_uid, expected_gid, expected_mode)
    }
}

fn reviewed_hosted_specs() -> Result<Vec<TrustedExecutableSpec>, TrustedExecutableError> {
    let accepted = hosted_runner_fingerprint_requirement()
        .accepted
        .trusted_executables;
    let specs = accepted
        .iter()
        .map(trusted_spec_from_accepted)
        .collect::<Result<Vec<_>, _>>()?;
    if specs_are_complete(&specs) {
        Ok(specs)
    } else {
        Err(TrustedExecutableError::unavailable())
    }
}

fn trusted_spec_from_accepted(
    accepted: &AcceptedTrustedExecutableV2,
) -> Result<TrustedExecutableSpec, TrustedExecutableError> {
    let executable = TrustedExecutable::from_path(accepted.path)
        .ok_or_else(TrustedExecutableError::unavailable)?;
    let mode =
        u32::from_str_radix(accepted.mode, 8).map_err(|_| TrustedExecutableError::unavailable())?;
    if accepted.canonical_target != accepted.path || format!("{mode:04o}") != accepted.mode {
        return Err(TrustedExecutableError::unavailable());
    }
    Ok(TrustedExecutableSpec {
        executable,
        canonical_path: accepted.canonical_target,
        mode,
    })
}

fn specs_are_complete(specs: &[TrustedExecutableSpec]) -> bool {
    specs.len() == TrustedExecutable::ALL.len()
        && specs.iter().all(|spec| {
            spec.canonical_path == spec.executable.path()
                && spec.mode & !0o7777 == 0
                && spec.mode & 0o111 != 0
        })
        && specs
            .iter()
            .map(|spec| spec.executable)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == TrustedExecutable::ALL.len()
        && TrustedExecutable::ALL
            .iter()
            .all(|executable| specs.iter().any(|spec| spec.executable == *executable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_EXECUTABLE_MODE: u32 = 0o755;
    static TEST_DIRECTORY_INDEX: AtomicUsize = AtomicUsize::new(0);

    fn test_directory() -> PathBuf {
        let index = TEST_DIRECTORY_INDEX.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "target/tmp/trusted-executable-unit-{}-{index}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::canonicalize(root).unwrap()
    }

    fn copy_executable(source: &str, destination: &Path, mode: u32) {
        fs::copy(source, destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn capture_test_executable(path: &Path, mode: u32) -> PinnedExecutable {
        let metadata = fs::metadata(path).unwrap();
        TrustedExecutableSet::capture_for_test(path, metadata.uid(), metadata.gid(), mode).unwrap()
    }

    fn descriptor_is_close_on_exec(file: &File) -> bool {
        let Ok(fdinfo) = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        else {
            return false;
        };
        fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("flags:\t"))
            .and_then(|value| u32::from_str_radix(value, 8).ok())
            .is_some_and(|flags| flags & libc::O_CLOEXEC as u32 != 0)
    }

    #[test]
    fn descriptor_executes_captured_object_while_revalidation_detects_replacement() {
        let root = test_directory();
        let executable = root.join("command");
        let replacement = root.join("replacement");
        copy_executable("/usr/bin/true", &executable, TEST_EXECUTABLE_MODE);
        copy_executable("/usr/bin/false", &replacement, TEST_EXECUTABLE_MODE);
        let pinned = capture_test_executable(&executable, TEST_EXECUTABLE_MODE);
        let captured_identity = pinned.identity;

        fs::rename(&replacement, &executable).unwrap();

        assert_eq!(
            pinned.verify_path().unwrap_err().code,
            "trusted_executable_drift"
        );
        assert_ne!(
            fs::metadata(&executable).unwrap().ino(),
            captured_identity.inode
        );
        let mut command = Command::new(pinned.descriptor_path());
        command.arg0(&executable);
        assert!(command.status().unwrap().success());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capture_rejects_symlinks_noncanonical_paths_and_metadata_drift() {
        let root = test_directory();
        let executable = root.join("command");
        let linked = root.join("linked");
        copy_executable("/usr/bin/true", &executable, TEST_EXECUTABLE_MODE);
        std::os::unix::fs::symlink(&executable, &linked).unwrap();
        let metadata = fs::metadata(&executable).unwrap();

        assert_eq!(
            TrustedExecutableSet::capture_for_test(
                &linked,
                metadata.uid(),
                metadata.gid(),
                TEST_EXECUTABLE_MODE,
            )
            .unwrap_err()
            .code,
            "trusted_executable_unavailable"
        );
        let pinned = capture_test_executable(&executable, TEST_EXECUTABLE_MODE);
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            pinned.verify_path().unwrap_err().code,
            "trusted_executable_drift"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capture_requires_exact_owner_group_and_mode() {
        let root = test_directory();
        let executable = root.join("command");
        copy_executable("/usr/bin/true", &executable, TEST_EXECUTABLE_MODE);
        let metadata = fs::metadata(&executable).unwrap();

        for (uid, gid, mode) in [
            (
                metadata.uid().saturating_add(1),
                metadata.gid(),
                TEST_EXECUTABLE_MODE,
            ),
            (
                metadata.uid(),
                metadata.gid().saturating_add(1),
                TEST_EXECUTABLE_MODE,
            ),
            (metadata.uid(), metadata.gid(), 0o700),
        ] {
            assert_eq!(
                TrustedExecutableSet::capture_for_test(&executable, uid, gid, mode)
                    .unwrap_err()
                    .code,
                "trusted_executable_unavailable"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capture_opens_the_retained_descriptor_close_on_exec() {
        let root = test_directory();
        let executable = root.join("command");
        copy_executable("/usr/bin/true", &executable, TEST_EXECUTABLE_MODE);
        let pinned = capture_test_executable(&executable, TEST_EXECUTABLE_MODE);
        assert!(pinned.file.as_raw_fd() >= MIN_RETAINED_EXECUTABLE_FD);
        assert!(descriptor_is_close_on_exec(&pinned.file));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capture_rejects_standard_descriptors_and_reserves_all_three() {
        assert_eq!(
            STANDARD_DESCRIPTOR_RESERVATION_COUNT,
            MIN_RETAINED_EXECUTABLE_FD as usize
        );
        for fd in 0..MIN_RETAINED_EXECUTABLE_FD {
            assert_eq!(
                validate_retained_descriptor(fd).unwrap_err().code,
                "trusted_executable_unavailable"
            );
        }
        validate_retained_descriptor(MIN_RETAINED_EXECUTABLE_FD).unwrap();

        let reservations = reserve_standard_descriptors().unwrap();
        assert_eq!(reservations.len(), STANDARD_DESCRIPTOR_RESERVATION_COUNT);
        assert!(reservations.iter().all(descriptor_is_close_on_exec));
    }

    #[test]
    fn process_stat_tty_parser_accepts_zero_with_tricky_command_names() {
        for contents in [
            "123 (fence) S 1 2 3 0 5 6\n",
            "987 (fence worker ) tricky) R 11 12 13 0 14 15\n",
        ] {
            assert_eq!(parse_process_tty_nr(contents).unwrap(), 0);
            require_no_controlling_terminal(contents).unwrap();
        }
    }

    #[test]
    fn process_stat_tty_gate_rejects_nonzero_and_malformed_values() {
        let attached = "123 (fence) S 1 2 3 34817 5 6\n";
        assert_eq!(parse_process_tty_nr(attached).unwrap(), 34817);
        assert_eq!(
            require_no_controlling_terminal(attached).unwrap_err().code,
            "trusted_executable_unavailable"
        );

        for malformed in [
            "",
            "123 fence S 1 2 3 0",
            "not-a-pid (fence) S 1 2 3 0",
            "123 (fence) SS 1 2 3 0",
            "123 (fence) ? 1 2 3 0",
            "123 (fence) S 1 2 3",
            "123 (fence) S 1 2 invalid 0",
            "123 (fence S 1 2 3 0",
        ] {
            assert_eq!(
                parse_process_tty_nr(malformed).unwrap_err().code,
                "trusted_executable_unavailable"
            );
        }
    }

    #[test]
    fn process_stat_reader_is_bounded() {
        let root = test_directory();
        let oversized = root.join("oversized-stat");
        fs::write(
            &oversized,
            vec![b'x'; MAX_PROC_SELF_STAT_BYTES as usize + 1],
        )
        .unwrap();
        assert_eq!(
            read_process_stat(&oversized).unwrap_err().code,
            "trusted_executable_unavailable"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runner_command_uses_only_pinned_outer_and_target_descriptors() {
        let root = test_directory();
        let sudo = root.join("sudo");
        let target = root.join("target");
        copy_executable("/usr/bin/true", &sudo, TEST_EXECUTABLE_MODE);
        copy_executable("/usr/bin/true", &target, TEST_EXECUTABLE_MODE);
        let mut executables = BTreeMap::new();
        executables.insert(
            TrustedExecutable::Sudo,
            capture_test_executable(&sudo, TEST_EXECUTABLE_MODE),
        );
        executables.insert(
            TrustedExecutable::Test,
            capture_test_executable(&target, TEST_EXECUTABLE_MODE),
        );
        let set = TrustedExecutableSet { executables };

        let command = set
            .runner_command_with_process_stat(
                TrustedExecutable::Test,
                &["!", "-w", "/fixed/path"],
                "123 (fence) S 1 2 3 0 5 6\n",
            )
            .unwrap();
        assert!(
            command
                .get_program()
                .to_string_lossy()
                .starts_with("/proc/self/fd/")
        );
        assert_eq!(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec![
                "--non-interactive",
                "--user",
                "runner",
                "--",
                "/proc/self/fd/0",
                "!",
                "-w",
                "/fixed/path",
            ]
        );
        assert_eq!(
            set.runner_command_with_process_stat(
                TrustedExecutable::Test,
                &["-x", "/fixed/path"],
                "123 (fence) S 1 2 3 1 5 6\n",
            )
            .unwrap_err()
            .code,
            "trusted_executable_unavailable"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepted_host_set_is_fixed_and_complete() {
        assert_eq!(TrustedExecutable::ALL.len(), 12);
        assert!(specs_are_complete(&reviewed_hosted_specs().unwrap()));
        assert_eq!(TrustedExecutable::Docker.path(), "/usr/bin/docker");
        assert_eq!(TrustedExecutable::SystemdRun.path(), "/usr/bin/systemd-run");
        assert_eq!(TrustedExecutable::Test.path(), "/usr/bin/test");
        assert_eq!(TrustedExecutable::Nft.path(), "/usr/sbin/nft");
    }

    #[test]
    fn reviewed_specs_must_be_complete_exact_and_executable() {
        let specs = TrustedExecutable::ALL.map(|executable| TrustedExecutableSpec {
            executable,
            canonical_path: executable.path(),
            mode: TEST_EXECUTABLE_MODE,
        });
        assert!(specs_are_complete(&specs));

        let mut wrong_path = specs;
        wrong_path[0].canonical_path = "/usr/local/bin/docker";
        assert!(!specs_are_complete(&wrong_path));

        let mut non_executable = specs;
        non_executable[0].mode = 0o644;
        assert!(!specs_are_complete(&non_executable));

        let mut invalid_mode = specs;
        invalid_mode[0].mode = 0o10_0755;
        assert!(!specs_are_complete(&invalid_mode));

        let mut duplicate = specs;
        duplicate[1] = duplicate[0];
        assert!(!specs_are_complete(&duplicate));

        assert!(!specs_are_complete(&specs[..specs.len() - 1]));
    }
}
