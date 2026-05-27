# Shared helpers for vendored release tools.

release_tools_zig_entries() {
  local file="$1"
  awk '
    function value(line) {
      sub(/^[^=]*= "/, "", line)
      sub(/"$/, "", line)
      return line
    }
    /^\[\[zig\]\]/ {
      if (in_zig && platform != "") {
        print platform "|" arch "|" os "|" version "|" url "|" path "|" sha256
      }
      in_zig = 1
      platform = arch = os = version = url = path = sha256 = ""
      next
    }
    /^\[/ {
      if (in_zig && platform != "") {
        print platform "|" arch "|" os "|" version "|" url "|" path "|" sha256
      }
      in_zig = 0
      next
    }
    in_zig && $1 == "platform" { platform = value($0) }
    in_zig && $1 == "arch" { arch = value($0) }
    in_zig && $1 == "os" { os = value($0) }
    in_zig && $1 == "version" { version = value($0) }
    in_zig && $1 == "url" { url = value($0) }
    in_zig && $1 == "path" { path = value($0) }
    in_zig && $1 == "sha256" { sha256 = value($0) }
    END {
      if (in_zig && platform != "") {
        print platform "|" arch "|" os "|" version "|" url "|" path "|" sha256
      }
    }
  ' "$file"
}

release_tools_cargo_zigbuild_entry() {
  local file="$1"
  awk '
    function value(line) {
      sub(/^[^=]*= "/, "", line)
      sub(/"$/, "", line)
      return line
    }
    /^\[cargo_zigbuild\]/ {
      in_cargo = 1
      next
    }
    /^\[/ {
      if (in_cargo) {
        in_cargo = 0
      }
      next
    }
    in_cargo && $1 == "version" { version = value($0) }
    in_cargo && $1 == "url" { url = value($0) }
    in_cargo && $1 == "crate_path" { crate_path = value($0) }
    in_cargo && $1 == "crate_sha256" { crate_sha256 = value($0) }
    END {
      print version "|" url "|" crate_path "|" crate_sha256
    }
  ' "$file"
}

release_tools_host_platform() {
  local os
  local arch
  local zig_os
  local zig_arch

  os="$(uname -s)"
  case "$os" in
    Darwin) zig_os="macos" ;;
    Linux) zig_os="linux" ;;
    *) die "unsupported OS: $os" ;;
  esac

  arch="$(uname -m)"
  case "$arch" in
    arm64|aarch64) zig_arch="aarch64" ;;
    x86_64) zig_arch="x86_64" ;;
    *) die "unsupported arch: $arch" ;;
  esac

  echo "${zig_os}|${zig_arch}|${zig_os}-${zig_arch}"
}

create_deterministic_targz() {
  local source_dir="$1"
  local dest="$2"
  local archive_root="$3"

  python3 - "$source_dir" "$dest" "$archive_root" <<'PY'
import gzip
import os
import shutil
import sys
import tarfile
from pathlib import Path

source = Path(sys.argv[1]).resolve()
dest = Path(sys.argv[2]).resolve()
archive_root = sys.argv[3].strip("/")

if not source.is_dir():
    raise SystemExit(f"source directory does not exist: {source}")
if not archive_root:
    raise SystemExit("archive root is required")

dest.parent.mkdir(parents=True, exist_ok=True)
plain_tar = dest.with_name(dest.name + ".tar.tmp")
gzip_tmp = dest.with_name(dest.name + ".tmp")

def normalized_info(path: Path, arcname: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(arcname)
    st = path.lstat()
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0

    if path.is_symlink():
        info.type = tarfile.SYMTYPE
        info.linkname = os.readlink(path)
        info.mode = 0o777
    elif path.is_dir():
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
    elif path.is_file():
        info.size = st.st_size
        info.mode = 0o755 if (st.st_mode & 0o111) else 0o644
    else:
        raise SystemExit(f"unsupported archive entry type: {path}")

    return info

paths = [source]
paths.extend(sorted(source.rglob("*"), key=lambda p: p.relative_to(source).as_posix()))

try:
    with tarfile.open(plain_tar, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in paths:
            rel = "" if path == source else path.relative_to(source).as_posix()
            arcname = archive_root if rel == "" else f"{archive_root}/{rel}"
            info = normalized_info(path, arcname)
            if path.is_file() and not path.is_symlink():
                with path.open("rb") as handle:
                    tar.addfile(info, handle)
            else:
                tar.addfile(info)

    with plain_tar.open("rb") as src, gzip_tmp.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            shutil.copyfileobj(src, gz)
    os.replace(gzip_tmp, dest)
finally:
    for tmp in (plain_tar, gzip_tmp):
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
PY
}
