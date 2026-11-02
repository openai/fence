mod descriptors;

use super::TrustedExecutable;
pub(super) use descriptors::Layout;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_six_executable_paths_are_redirected() {
        use TrustedExecutable::*;

        let redirected = [
            (Id, "/usr/lib/cargo/bin/coreutils/id"),
            (Stat, "/usr/lib/cargo/bin/coreutils/stat"),
            (Test, "/usr/lib/cargo/bin/coreutils/test"),
            (True, "/usr/bin/gnutrue"),
            (Sudo, "/usr/lib/cargo/bin/sudo"),
            (Visudo, "/usr/lib/cargo/bin/visudo"),
        ];
        for executable in
            TrustedExecutable::ALL
                .into_iter()
                .chain([ClassicSudo, ClassicVisudo, GnuTest, Getfacl])
        {
            let expected = redirected.iter().find(|(tool, _)| *tool == executable);
            assert_eq!(
                target(executable),
                expected.map_or(executable.path(), |(_, path)| *path)
            );
        }
    }
}
