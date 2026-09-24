#!/usr/bin/env python3

import pathlib
import sys
import tomllib
import unittest

DEPENDENCY_KINDS = ("dependencies", "dev-dependencies", "build-dependencies")


def dependency_tables(document):
    for kind in DEPENDENCY_KINDS:
        table = document.get(kind)
        if table is not None:
            yield f"[{kind}]", table

    targets = document.get("target", {})
    if not isinstance(targets, dict):
        raise ValueError("Cargo.toml target configuration must be a table")
    for selector, target in targets.items():
        if not isinstance(target, dict):
            raise ValueError(f"Cargo.toml target {selector!r} must be a table")
        for kind in DEPENDENCY_KINDS:
            table = target.get(kind)
            if table is not None:
                yield f"[target.{selector!r}.{kind}]", table


def exact_version(specification):
    if isinstance(specification, str):
        version = specification
    elif isinstance(specification, dict):
        version = specification.get("version")
    else:
        return False
    return isinstance(version, str) and version.startswith("=") and len(version) > 1


def validate_document(document):
    if not isinstance(document, dict):
        raise ValueError("Cargo.toml root must be a table")

    violations = []
    for location, table in dependency_tables(document):
        if not isinstance(table, dict):
            raise ValueError(f"Cargo.toml dependency section {location} must be a table")
        for name, specification in sorted(table.items()):
            if not exact_version(specification):
                violations.append(f"{location} {name}")
    return violations


def validate_path(path):
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    violations = validate_document(document)
    if violations:
        joined = ", ".join(violations)
        raise ValueError(f"direct Cargo dependencies must use exact versions: {joined}")


class CargoDependencyPinTests(unittest.TestCase):
    def parse(self, raw):
        return tomllib.loads(raw)

    def test_accepts_exact_versions_in_every_direct_dependency_table(self):
        document = self.parse(
            '''
[dependencies]
serde = "=1.0.228"

[dev-dependencies]
tempfile = { version = "=3.23.0", features = ["nightly"] }

[build-dependencies]
cc = "=1.2.43"

[target.'cfg(target_os = "linux")'.dependencies]
libc = "=0.2.186"
netlink-sys = { version = "=0.8.8", features = ["tokio_socket"] }

[target.'cfg(target_os = "linux")'.dev-dependencies]
nix = "=0.30.1"

[target.'cfg(target_os = "linux")'.build-dependencies]
bindgen = { version = "=0.72.1" }
'''
        )
        self.assertEqual(validate_document(document), [])

    def test_rejects_non_exact_versions_outside_plain_dependencies(self):
        cases = (
            (
                '''
[target.'cfg(target_os = "linux")'.dependencies]
libc = "0.2.186"
''',
                "libc",
            ),
            (
                '''
[dev-dependencies]
tempfile = { version = "3.23.0" }
''',
                "tempfile",
            ),
            (
                '''
[build-dependencies]
cc = { path = "vendor/cc" }
''',
                "cc",
            ),
        )
        for raw, dependency in cases:
            with self.subTest(dependency=dependency):
                violations = validate_document(self.parse(raw))
                self.assertEqual(len(violations), 1)
                self.assertIn(dependency, violations[0])


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
    elif len(sys.argv) == 2:
        try:
            validate_path(pathlib.Path(sys.argv[1]))
        except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
            raise SystemExit(str(error)) from None
    else:
        raise SystemExit("usage: cargo_dependency_pins.py <Cargo.toml> | --self-test")
