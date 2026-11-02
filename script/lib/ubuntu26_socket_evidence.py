"""Unprivileged hosted acceptance probes for the reviewed Ubuntu 26.04 sockets."""

import errno
import hashlib
import os
import platform
import pwd
import socket
import stat
import sys

SENTINELS = (
    ("SSH", "/run/ssh-unix-local/socket"),
    ("DNS", "/run/systemd/resolve/io.systemd.Resolve"),
    ("authorization", "/run/polkit/agent-helper.socket"),
)


def original_socket_identity(path):
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as info:
            (mount_id,) = [int(line.split()[1]) for line in info if line.startswith("mnt_id:")]
        identity = (mount_id, metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid, metadata.st_mode)
        return metadata, repr(identity).encode("ascii")
    finally:
        os.close(fd)


def check_sockets(mode):
    release = platform.freedesktop_os_release()
    if (release.get("ID"), release.get("VERSION_ID")) != ("ubuntu", "26.04"):
        if mode == "rollback":
            raise SystemExit("socket rollback evidence requires Ubuntu 26.04")
        return
    runner_uid = pwd.getpwnam("runner").pw_uid
    if os.geteuid() != runner_uid or runner_uid == 0:
        raise SystemExit("socket checks must run as the workflow user")
    digest = hashlib.sha256()
    for service, path in SENTINELS:
        try:
            if mode == "rollback":
                metadata, identity = original_socket_identity(path)
                if stat.S_IMODE(metadata.st_mode) != 0o666:
                    raise SystemExit(f"unexpected original {service} socket mode")
                digest.update(identity)
            else:
                metadata = os.lstat(path)
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid == runner_uid:
                raise SystemExit(f"unexpected {service} socket identity")
            if mode == "block":
                if stat.S_IMODE(metadata.st_mode) != 0o600:
                    raise SystemExit(f"block did not restrict the {service} socket permissions")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(1)
                    if client.connect_ex(path) != errno.EACCES:
                        raise SystemExit(f"block did not deny workflow connection to the {service} socket")
            elif not os.access(path, os.R_OK | os.W_OK, effective_ids=True):
                raise SystemExit(f"workflow access to the {service} socket was lost")
        except (OSError, ValueError):
            raise SystemExit(f"could not inspect the {service} socket") from None
    if mode == "rollback":
        print(digest.hexdigest())


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"audit", "block", "rollback"}:
        raise SystemExit("expected audit, block, or rollback")
    check_sockets(sys.argv[1])
