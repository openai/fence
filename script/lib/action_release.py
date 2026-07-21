#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request


SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAPPING_KEYS = {
    "schema_version",
    "repository",
    "version",
    "release_tag",
    "source_commit",
    "action_commit",
    "artifact_name",
    "artifact_sha256",
    "bundle_manifest_schema_version",
    "signer_workflow",
    "signer_digest",
}
GENERATED_FILES = {
    ("action/bin/fence", "added"),
    ("action/bundle-manifest.json", "added"),
}
REPOSITORY = "openai/fence"


def fail(message):
    raise ValueError(message)


def parse_semver(value):
    if not isinstance(value, str):
        fail("release version must be a string")
    match = SEMVER.fullmatch(value)
    if not match:
        fail(f"invalid release version: {value}")
    prerelease = None if match.group(4) is None else tuple(match.group(4).split("."))
    if prerelease and any(item.isdigit() and len(item) > 1 and item.startswith("0") for item in prerelease):
        fail(f"invalid numeric prerelease identifier: {value}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease)


def compare_semver(left, right):
    if left[:3] != right[:3]:
        return (left[:3] > right[:3]) - (left[:3] < right[:3])
    left_pre, right_pre = left[3], right[3]
    if left_pre is None or right_pre is None:
        return (left_pre is None) - (right_pre is None)
    for left_item, right_item in zip(left_pre, right_pre):
        if left_item == right_item:
            continue
        left_numeric = left_item.isdigit()
        right_numeric = right_item.isdigit()
        if left_numeric and right_numeric:
            return (int(left_item) > int(right_item)) - (int(left_item) < int(right_item))
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return (left_item > right_item) - (left_item < right_item)
    return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))


def release_channel(version):
    return "prerelease" if parse_semver(version)[3] is not None else "stable"


def package_manifest_identity(path):
    section = None
    values = {}
    for raw_line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section != "[package]":
            continue
        match = re.fullmatch(r'(name|version)\s*=\s*"([^"]+)"', line)
        if match:
            if match.group(1) in values:
                fail(f"duplicate Cargo.toml package {match.group(1)}")
            values[match.group(1)] = match.group(2)
    return values.get("name"), values.get("version")


def root_lock_identities(path):
    packages = []
    current = None
    for raw_line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {}
            continue
        if line.startswith("[") and line.endswith("]"):
            if current is not None:
                packages.append(current)
                current = None
            continue
        if current is None:
            continue
        match = re.fullmatch(r'(name|version|source)\s*=\s*"([^"]+)"', line)
        if match:
            if match.group(1) in current:
                fail(f"duplicate Cargo.lock package {match.group(1)}")
            current[match.group(1)] = match.group(2)
    if current is not None:
        packages.append(current)
    return packages


def validate_root_versions(cargo_path, lock_path):
    name, version = package_manifest_identity(cargo_path)
    if not isinstance(name, str) or not isinstance(version, str):
        fail("Cargo.toml package identity is incomplete")
    parse_semver(version)
    matches = [
        item
        for item in root_lock_identities(lock_path)
        if item.get("name") == name and item.get("version") == version and "source" not in item
    ]
    if len(matches) != 1:
        fail("root Cargo.lock package version does not match Cargo.toml")
    return name, version


def highest_published_release(pages):
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        fail("published release pagination response is malformed")
    published = []
    for page in pages:
        for release in page:
            if not isinstance(release, dict) or release.get("draft") is not False:
                continue
            tag = release.get("tag_name")
            if not isinstance(tag, str) or not tag.startswith("v"):
                continue
            try:
                parsed = parse_semver(tag[1:])
            except ValueError:
                continue
            published.append((parsed, tag))
    if not published:
        return None
    highest = published[0]
    for candidate in published[1:]:
        if compare_semver(candidate[0], highest[0]) > 0:
            highest = candidate
    return highest


def validate_release_order(version, pages):
    current = parse_semver(version)
    highest = highest_published_release(pages)
    if highest is None:
        return
    comparison = compare_semver(current, highest[0])
    if comparison < 0:
        fail(f"release version v{version} is older than published {highest[1]}")
    if comparison == 0 and highest[1] != f"v{version}":
        fail("release version collides with an existing semantic version")


def expected_mapping(repository, version, source_commit, action_commit, artifact_name, artifact_sha256):
    parse_semver(version)
    if not SHA1.fullmatch(source_commit):
        fail("release mapping source commit is invalid")
    if action_commit is not None and not SHA1.fullmatch(action_commit):
        fail("release mapping Action commit is invalid")
    if not SHA256.fullmatch(artifact_sha256):
        fail("release mapping artifact digest is invalid")
    if artifact_name != f"fence_v{version}_linux-amd64":
        fail("release mapping artifact name mismatch")
    expected = {
        "schema_version": 1,
        "repository": repository,
        "version": version,
        "release_tag": f"v{version}",
        "source_commit": source_commit,
        "artifact_name": artifact_name,
        "artifact_sha256": artifact_sha256,
        "bundle_manifest_schema_version": 4,
        "signer_workflow": f"{repository}/.github/workflows/release.yml",
        "signer_digest": source_commit,
    }
    if action_commit is not None:
        expected["action_commit"] = action_commit
    return expected


def validate_mapping(mapping, repository, version, source_commit, action_commit, artifact_name, artifact_sha256):
    if not isinstance(mapping, dict) or set(mapping) != MAPPING_KEYS:
        fail("release mapping schema mismatch")
    if not SHA1.fullmatch(str(mapping.get("action_commit", ""))):
        fail("release mapping Action commit is invalid")
    expected = expected_mapping(
        repository,
        version,
        source_commit,
        mapping["action_commit"] if action_commit is None else action_commit,
        artifact_name,
        artifact_sha256,
    )
    if mapping != expected:
        mismatches = sorted(key for key in MAPPING_KEYS if mapping.get(key) != expected.get(key))
        fail(f"release mapping mismatch: {', '.join(mismatches)}")
    return mapping["action_commit"]


def classify_release_state(state, repository, version, source_commit, artifact_name, artifact_sha256):
    if not isinstance(state, dict):
        fail("release state must be a JSON object")
    expected_state_keys = {
        "release_exists",
        "release_mapping",
        "tag_commit",
        "candidate_head",
        "draft_commit",
        "verification_succeeded",
        "verified_head",
    }
    if set(state) != expected_state_keys or not isinstance(state["release_exists"], bool):
        fail("release state schema mismatch")
    candidate_head = state["candidate_head"]
    draft_commit = state["draft_commit"]
    tag_commit = state["tag_commit"]
    verified_head = state["verified_head"]
    verification_succeeded = state["verification_succeeded"]
    if verification_succeeded is not None and not isinstance(verification_succeeded, bool):
        fail("release verification history must be boolean or null")
    for label, value in (
        ("candidate", candidate_head),
        ("draft", draft_commit),
        ("tag", tag_commit),
        ("verified", verified_head),
    ):
        if value is not None and not SHA1.fullmatch(value):
            fail(f"{label} release state commit is invalid")
    mapping = state["release_mapping"]
    if state["release_exists"]:
        if draft_commit is not None:
            fail("published release cannot also be a draft")
        if mapping is None:
            fail("existing release is missing action-release.json")
        action_commit = validate_mapping(
            mapping,
            repository,
            version,
            source_commit,
            None,
            artifact_name,
            artifact_sha256,
        )
        if tag_commit != action_commit:
            fail("existing release tag conflicts with its Action mapping")
        if candidate_head not in (None, action_commit):
            fail("existing candidate ref conflicts with the complete release")
        if verified_head not in (None, action_commit):
            fail("existing verification marker conflicts with the complete release")
        if candidate_head == action_commit and verified_head is None:
            if verification_succeeded is True:
                return {"state": "complete", "action_commit": action_commit}
            if verification_succeeded is False:
                return {"state": "withdrawn", "action_commit": action_commit}
            fail("existing candidate release verification history is indeterminate")
        return {"state": "complete", "action_commit": action_commit}
    if mapping is not None:
        fail("release mapping exists without a release")
    if verified_head is not None:
        fail("verification marker exists without a complete release")
    if verification_succeeded is not None:
        fail("release verification history exists without a complete release")
    if draft_commit is not None:
        if draft_commit == source_commit:
            fail("draft release points to the source commit instead of a distribution commit")
        if tag_commit not in (None, draft_commit):
            fail("release tag conflicts with the resumable draft")
        if candidate_head not in (None, draft_commit):
            fail("candidate ref conflicts with the resumable draft")
        return {"state": "draft", "action_commit": draft_commit}
    if tag_commit is not None:
        if tag_commit == source_commit:
            fail("release tag points to the source commit instead of a distribution commit")
        if candidate_head not in (None, tag_commit):
            fail("candidate ref conflicts with the resumable release tag")
        return {"state": "tag", "action_commit": tag_commit}
    if candidate_head is None:
        return {"state": "new", "action_commit": None}
    if candidate_head == source_commit:
        return {"state": "candidate-source", "action_commit": None}
    return {"state": "candidate", "action_commit": candidate_head}


def validate_distribution_commit(rest, graphql, source_commit, action_commit):
    if not SHA1.fullmatch(source_commit) or not SHA1.fullmatch(action_commit):
        fail("distribution commit identity is invalid")
    if not isinstance(rest, dict) or rest.get("sha") != action_commit:
        fail("distribution REST commit identity mismatch")
    if [parent.get("sha") for parent in rest.get("parents", [])] != [source_commit]:
        fail("distribution commit parent mismatch")
    files = {(item.get("filename"), item.get("status")) for item in rest.get("files", [])}
    if files != GENERATED_FILES:
        fail("distribution commit diff mismatch")
    verification = rest.get("commit", {}).get("verification", {})
    if verification.get("verified") is not True:
        fail("distribution commit REST signature is invalid")
    commit = graphql.get("data", {}).get("repository", {}).get("object", {}) if isinstance(graphql, dict) else {}
    signature = commit.get("signature") or {}
    if commit.get("oid") != action_commit:
        fail("distribution GraphQL commit identity mismatch")
    if signature.get("isValid") is not True or signature.get("wasSignedByGitHub") is not True:
        fail("distribution commit was not validly signed by GitHub")


def validate_draft_release(metadata, notes_path, asset_root, version, action_commit, release_channel_value):
    parse_semver(version)
    if not SHA1.fullmatch(action_commit):
        fail("draft release Action commit is invalid")
    if release_channel_value not in {"stable", "prerelease"}:
        fail("draft release channel is invalid")
    if not isinstance(metadata, dict) or metadata.get("draft") is not True:
        fail("resumable release is not a draft")
    version_tag = f"v{version}"
    if metadata.get("tag_name") != version_tag:
        fail("draft release tag mismatch")
    if metadata.get("target_commitish") != action_commit:
        fail("draft release target mismatch")
    if metadata.get("name") != version_tag:
        fail("draft release title mismatch")
    if metadata.get("prerelease") is not (release_channel_value == "prerelease"):
        fail("draft release channel mismatch")
    if metadata.get("immutable") is not False or metadata.get("published_at") is not None:
        fail("resumable draft has published release state")
    expected_body = pathlib.Path(notes_path).read_text(encoding="utf-8").rstrip("\n")
    if str(metadata.get("body", "")).rstrip("\n") != expected_body:
        fail("draft release notes mismatch")
    author = metadata.get("author") or {}
    if author.get("login") != "github-actions[bot]" or author.get("type") != "Bot":
        fail("draft release was not created by GitHub Actions")
    release_id = metadata.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        fail("draft release id is invalid")
    root = pathlib.Path(asset_root)
    expected_names = {
        f"fence_{version_tag}_linux-amd64",
        f"fence_{version_tag}_linux-amd64.tar.gz",
        "action-release.json",
        "checksums.txt",
    }
    expected_assets = {}
    for path in root.iterdir():
        if not path.is_file() or path.is_symlink() or path.name not in expected_names:
            fail("prepared release asset tree is invalid")
        expected_assets[path.name] = (
            path.stat().st_size,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    if set(expected_assets) != expected_names:
        fail("prepared release asset set is incomplete")
    assets = metadata.get("assets")
    if not isinstance(assets, list):
        fail("draft release assets are malformed")
    observed_names = set()
    for asset in assets:
        if not isinstance(asset, dict):
            fail("draft release assets are malformed")
        name = asset.get("name")
        if name in observed_names or name not in expected_assets:
            fail("draft release contains conflicting assets")
        observed_names.add(name)
        expected_size, expected_digest = expected_assets[name]
        if (
            asset.get("state") != "uploaded"
            or asset.get("size") != expected_size
            or asset.get("digest") != f"sha256:{expected_digest}"
        ):
            fail(f"draft release asset mismatch: {name}")
        uploader = asset.get("uploader") or {}
        if uploader.get("login") != "github-actions[bot]" or uploader.get("type") != "Bot":
            fail(f"draft release asset uploader mismatch: {name}")
    return release_id


def select_exact_release(pages, version_tag):
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        fail("release-state pagination response is malformed")
    matches = [
        release
        for page in pages
        for release in page
        if isinstance(release, dict) and release.get("tag_name") == version_tag
    ]
    if len(matches) > 1:
        fail("duplicate exact release records")
    if not matches:
        return "absent", None
    release = matches[0]
    if not isinstance(release.get("draft"), bool):
        fail("release-state response identity mismatch")
    return ("draft" if release["draft"] else "published"), release


def probe_github_release(repository, version_tag, token):
    if repository != REPOSITORY:
        fail("release-state repository is invalid")
    if not isinstance(version_tag, str) or not version_tag.startswith("v"):
        fail("release-state tag is invalid")
    parse_semver(version_tag[1:])
    if not isinstance(token, str) or not token:
        fail("release-state token is unavailable")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "fence-release-state",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    pages = []
    for page in range(1, 11):
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/releases?per_page=100&page={page}",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            fail(f"release-state probe failed with HTTP {error.code}")
        except (OSError, urllib.error.URLError) as error:
            fail(f"release-state probe was indeterminate: {error}")
        if len(body) > 4 * 1024 * 1024:
            fail("release-state response exceeded its fixed bound")
        try:
            releases = json.loads(body)
        except json.JSONDecodeError:
            fail("release-state response is not valid JSON")
        if not isinstance(releases, list):
            fail("release-state response is malformed")
        pages.append(releases)
        if len(releases) < 100:
            return select_exact_release(pages, version_tag)
    fail("release-state pagination exceeded its fixed bound")


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    state_parser = subparsers.add_parser("classify-state")
    state_parser.add_argument("--state", required=True)
    state_parser.add_argument("--repository", required=True)
    state_parser.add_argument("--version", required=True)
    state_parser.add_argument("--source-commit", required=True)
    state_parser.add_argument("--artifact-name", required=True)
    state_parser.add_argument("--artifact-sha256", required=True)

    mapping_parser = subparsers.add_parser("validate-mapping")
    mapping_parser.add_argument("--mapping", required=True)
    mapping_parser.add_argument("--repository", required=True)
    mapping_parser.add_argument("--version", required=True)
    mapping_parser.add_argument("--source-commit", required=True)
    mapping_parser.add_argument("--action-commit")
    mapping_parser.add_argument("--artifact-name", required=True)
    mapping_parser.add_argument("--artifact-sha256", required=True)

    commit_parser = subparsers.add_parser("verify-commit")
    commit_parser.add_argument("--rest", required=True)
    commit_parser.add_argument("--graphql", required=True)
    commit_parser.add_argument("--source-commit", required=True)
    commit_parser.add_argument("--action-commit", required=True)

    draft_parser = subparsers.add_parser("validate-draft")
    draft_parser.add_argument("--metadata", required=True)
    draft_parser.add_argument("--notes", required=True)
    draft_parser.add_argument("--asset-root", required=True)
    draft_parser.add_argument("--version", required=True)
    draft_parser.add_argument("--action-commit", required=True)
    draft_parser.add_argument("--release-channel", required=True)

    probe_parser = subparsers.add_parser("probe-release")
    probe_parser.add_argument("--repository", required=True)
    probe_parser.add_argument("--version-tag", required=True)
    probe_parser.add_argument("--output", required=True)

    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "classify-state":
            result = classify_release_state(
                load_json(arguments.state),
                arguments.repository,
                arguments.version,
                arguments.source_commit,
                arguments.artifact_name,
                arguments.artifact_sha256,
            )
            print(json.dumps(result, sort_keys=True))
        elif arguments.command == "validate-mapping":
            action_commit = validate_mapping(
                load_json(arguments.mapping),
                arguments.repository,
                arguments.version,
                arguments.source_commit,
                arguments.action_commit,
                arguments.artifact_name,
                arguments.artifact_sha256,
            )
            print(action_commit)
        elif arguments.command == "verify-commit":
            validate_distribution_commit(
                load_json(arguments.rest),
                load_json(arguments.graphql),
                arguments.source_commit,
                arguments.action_commit,
            )
        elif arguments.command == "validate-draft":
            release_id = validate_draft_release(
                load_json(arguments.metadata),
                arguments.notes,
                arguments.asset_root,
                arguments.version,
                arguments.action_commit,
                arguments.release_channel,
            )
            print(release_id)
        else:
            state, release = probe_github_release(
                arguments.repository,
                arguments.version_tag,
                os.environ.get("GH_TOKEN"),
            )
            output = pathlib.Path(arguments.output)
            if release is None:
                if output.exists():
                    fail("absent release-state output path already exists")
            else:
                output.write_text(json.dumps(release, sort_keys=True), encoding="utf-8")
            print(state)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
