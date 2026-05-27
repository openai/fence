#![forbid(unsafe_code)]

pub mod math;

// Re-export functions from the math module for easier use.
pub use math::{add, subtract};

pub fn greet(name: &str, shout: bool, times: u8) -> String {
    let base = format!("Hello, {name}!");
    let message = if shout { base.to_uppercase() } else { base };

    let repeat = times.max(1);
    (0..repeat)
        .map(|_| message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VersionInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub build_version: &'static str,
    pub commit: &'static str,
    pub build_date: &'static str,
}

impl VersionInfo {
    pub fn render(&self) -> String {
        format!(
            "{name} {version}\nbuild: {build_version}\ncommit: {commit}\nbuilt: {build_date}",
            name = self.name,
            version = self.version,
            build_version = self.build_version,
            commit = self.commit,
            build_date = self.build_date
        )
    }
}

pub fn version_info() -> VersionInfo {
    VersionInfo {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        build_version: option_env!("BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
        commit: option_env!("BUILD_COMMIT").unwrap_or("unknown"),
        build_date: option_env!("BUILD_DATE").unwrap_or("unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_numbers() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn subtracts_numbers() {
        assert_eq!(subtract(5, 3), 2);
    }

    #[test]
    fn greets_by_name() {
        assert_eq!(greet("Grant", false, 1), "Hello, Grant!");
    }

    #[test]
    fn greets_multiple_times() {
        assert_eq!(greet("Codex", false, 2), "Hello, Codex!\nHello, Codex!");
    }

    #[test]
    fn greets_at_least_once() {
        assert_eq!(greet("Codex", false, 0), "Hello, Codex!");
    }

    #[test]
    fn shouts_when_requested() {
        assert_eq!(greet("world", true, 1), "HELLO, WORLD!");
    }

    #[test]
    fn version_metadata_matches_package() {
        let info = version_info();
        assert_eq!(info.name, env!("CARGO_PKG_NAME"));
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn renders_version_metadata() {
        let info = VersionInfo {
            name: "example",
            version: "1.2.3",
            build_version: "v1.2.3",
            commit: "abc1234",
            build_date: "2026-05-19T00:00:00Z",
        };

        assert_eq!(
            info.render(),
            "example 1.2.3\nbuild: v1.2.3\ncommit: abc1234\nbuilt: 2026-05-19T00:00:00Z"
        );
    }
}
