"""Verify an immutable Fence release before advertising its consumer pin."""

import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.request

from action_release import REPOSITORY, SHA1, fail, release_channel, validate_distribution_commit


PENDING_NOTES = "Verification pending. Keep using the previous release."
READ_ATTEMPTS = 12


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        # Never carry the release token to another URL, or replay a PATCH.
        return None


def github(path, *, method="GET", data=None):
    url = f"https://api.github.com/{path}"
    headers = {
        "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    request = urllib.request.Request(url, json.dumps(data).encode() if data else None, headers, method=method)
    with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
        if method == "PATCH":
            return  # Promotion is confirmed by a fresh, separately validated GET.
        body = response.read(4 * 1024 * 1024 + 1)
    if len(body) > 4 * 1024 * 1024:
        fail("release metadata response exceeded its fixed bound")
    return json.loads(body)


def transient(error):
    if isinstance(error, urllib.error.HTTPError):
        return error.code in {404, 408, 429, 500, 502, 503, 504}
    return isinstance(getattr(error, "reason", error),
                      (TimeoutError, ConnectionResetError, http.client.IncompleteRead, http.client.RemoteDisconnected))


def read(path, *, validate=lambda value: value, **query):
    """Retry a transient read failure or an explicitly not-yet-visible result."""
    for attempt in range(READ_ATTEMPTS):
        try:
            result = validate(github(path, **query))
        except (OSError, http.client.HTTPException) as error:
            if not transient(error):
                raise
        else:
            if result is not None:
                return result
        if attempt + 1 < READ_ATTEMPTS:
            time.sleep(5)
    fail(f"timed out reading release metadata: {path}")


def verify_commit(source, action):
    owner, repo = REPOSITORY.split("/")
    query = """query($owner: String!, $repo: String!, $oid: GitObjectID!) {
      repository(owner: $owner, name: $repo) { object(oid: $oid) {
        ... on Commit { oid signature { isValid wasSignedByGitHub } }
      } } }"""
    rest = read(f"repos/{REPOSITORY}/commits/{action}")
    graphql = read("graphql", method="POST",
                   data={"query": query, "variables": {"owner": owner, "repo": repo, "oid": action}})
    # Invalid identity, tree, or signature is an integrity failure, not a retry.
    validate_distribution_commit(rest, graphql, source, action)


class Publication:
    def __init__(self, tag, source, action):
        self.prerelease = release_channel(tag.removeprefix("v")) == "prerelease"
        if not tag.startswith("v") or not SHA1.fullmatch(source) or not SHA1.fullmatch(action) or source == action:
            fail("invalid release adoption identity")
        self.tag, self.action = tag, action
        self.final_notes = (f"Release {tag}\n\nReviewed source commit: `{source}`\n"
                            f"Complete Action commit: `{action}`\n\n```yaml\n"
                            f"- uses: {REPOSITORY}@{action} # pin@{tag}\n```")
        self.base = f"repos/{REPOSITORY}/releases"

    def wait(self, *, release_id=None, existing=False, require_final=False):
        def validate(release):
            identity = release.get("id")
            if (type(identity) is not int or identity <= 0 or release_id not in (None, identity)
                    or release.get("tag_name") != self.tag or release.get("target_commitish") != self.action
                    or release.get("draft") is not False):
                fail("published release identity mismatch")
            notes = release.get("body", "").rstrip("\n")
            final = existing and notes == self.final_notes and release.get("prerelease") is self.prerelease
            pending = notes == PENDING_NOTES and release.get("prerelease") is True
            if not (final or pending):
                fail("published release channel or verification notes mismatch")
            immutable = release.get("immutable")
            if type(immutable) is not bool:
                fail("published release has no immutability status")
            if immutable and (final or not require_final):
                return identity, final
            return None

        path = release_id if release_id is not None else f"tags/{self.tag}"
        return read(f"{self.base}/{path}", validate=validate)

    def promote(self, release_id):
        # Check exact absence even on recovery after cleanup. An API failure is
        # never absence; a candidate can be the only record of withdrawal.
        for marker in ("release-candidate", "release-verified"):
            ref = f"heads/{marker}/{self.tag}"
            refs = read(f"repos/{REPOSITORY}/git/matching-refs/{ref}")
            if not isinstance(refs, list) or any(item["ref"] == f"refs/{ref}" for item in refs):
                fail(f"release not finalized: {ref} remains or could not be verified")
        _, finalized = self.wait(release_id=release_id, existing=True)
        if finalized:
            return  # Never re-promote an older release to latest on re-verification.
        update = {"body": self.final_notes, "prerelease": self.prerelease,
                  "make_latest": "false" if self.prerelease else "true"}
        try:
            github(f"{self.base}/{release_id}", method="PATCH", data=update)
        except (OSError, http.client.HTTPException) as error:
            if not transient(error):
                raise
        # Whether the response arrived or not, confirm the exact update by GET.
        # Never retry the mutation. A full workflow rerun can recover pending state.
        self.wait(release_id=release_id, existing=True, require_final=True)
        if not self.prerelease:
            read(f"{self.base}/latest", validate=lambda value: True if value["id"] == release_id else None)


def main(command):
    if command == "pending-notes":
        print(PENDING_NOTES)
        return
    source, action = os.environ["SOURCE_COMMIT"], os.environ["ACTION_COMMIT"]
    if command == "verify-commit":
        verify_commit(source, action)
        return
    publication = Publication(os.environ["VERSION_TAG"], source, action)
    if command == "verify":
        release_id, _ = publication.wait(existing=os.environ["EXISTING_RELEASE"] == "true")
        print(release_id)
    elif command == "promote":
        publication.promote(int(os.environ["VERIFIED_RELEASE_ID"]))
    else:
        fail(f"unknown release adoption command: {command}")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise SystemExit(str(error)) from None
