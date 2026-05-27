# Shared Rust distribution lock helpers.

RUST_DIST_HOSTS=(
  "x86_64-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

RUST_DIST_TARGETS=(
  "x86_64-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

RUST_DIST_HOST_COMPONENTS=("rustc" "cargo" "rustfmt" "clippy" "llvm-tools-preview")

rust_dist_manifest_url() {
  local version="$1"
  echo "https://static.rust-lang.org/dist/channel-rust-${version}.toml"
}

rust_dist_csv() {
  local item
  local separator=""
  for item in "$@"; do
    printf '%s%s' "$separator" "$item"
    separator=","
  done
}

rust_dist_artifact_entries() {
  local file="$1"
  awk '
    function value(line) {
      sub(/^[^=]*= "/, "", line)
      sub(/"$/, "", line)
      return line
    }
    function print_entry() {
      if (in_artifact) {
        print kind "|" component "|" target "|" url "|" sha256
      }
    }
    /^\[\[artifacts\]\]/ {
      print_entry()
      in_artifact = 1
      kind = component = target = url = sha256 = ""
      next
    }
    /^\[/ {
      print_entry()
      in_artifact = 0
      next
    }
    in_artifact && $1 == "kind" { kind = value($0) }
    in_artifact && $1 == "component" { component = value($0) }
    in_artifact && $1 == "target" { target = value($0) }
    in_artifact && $1 == "url" { url = value($0) }
    in_artifact && $1 == "sha256" { sha256 = value($0) }
    END {
      print_entry()
    }
  ' "$file"
}

rust_dist_require_artifact() {
  local lockfile="$1"
  local kind="$2"
  local component="$3"
  local target="$4"

  if ! rust_dist_artifact_entries "$lockfile" | awk -F'|' -v kind="$kind" -v component="$component" -v target="$target" \
    '$1 == kind && $2 == component && $3 == target { found=1 } END { exit(found ? 0 : 1) }'; then
    die "missing Rust artifact lock entry: ${kind} ${component} ${target}"
  fi
}

rust_dist_generate_artifact_entries_from_manifest() {
  local manifest="$1"
  local version="$2"
  local hosts_csv="$3"
  local targets_csv="$4"

  python3 - "$manifest" "$version" "$hosts_csv" "$targets_csv" <<'PY'
import sys

manifest_path, version, hosts_csv, targets_csv = sys.argv[1:5]
hosts = [item for item in hosts_csv.split(",") if item]
targets = [item for item in targets_csv.split(",") if item]

targets_by_package = {}

with open(manifest_path, "r", encoding="utf-8") as handle:
    current = None
    for raw_line in handle:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").split(".")
            if len(section) >= 4 and section[0] == "pkg" and section[2] == "target":
                package_name = section[1]
                target_name = ".".join(section[3:])
                current = targets_by_package.setdefault(package_name, {}).setdefault(target_name, {})
            else:
                current = None
            continue
        if current is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value in ("true", "false"):
            value = value == "true"
        current[key] = value

component_packages = {
    "rustc": ("rustc",),
    "cargo": ("cargo",),
    "rust-std": ("rust-std",),
    "rustfmt": ("rustfmt", "rustfmt-preview"),
    "clippy": ("clippy", "clippy-preview"),
    "llvm-tools-preview": ("llvm-tools", "llvm-tools-preview"),
}


def package_for(component):
    for package_name in component_packages[component]:
        package = targets_by_package.get(package_name)
        if package:
            return package
    raise SystemExit(f"missing Rust package for component: {component}")


def artifact(component, target):
    package = package_for(component)
    target_info = package.get(target)
    if not target_info or target_info.get("available") is False:
        raise SystemExit(f"missing Rust artifact for {component} on {target}")
    url = target_info.get("xz_url") or target_info.get("url")
    sha256 = target_info.get("xz_hash") or target_info.get("hash")
    if not url or not sha256:
        raise SystemExit(f"missing URL/checksum for {component} on {target}")
    filename = url.rsplit("/", 1)[-1]
    if not filename.endswith(".tar.xz"):
        raise SystemExit(f"unexpected Rust artifact extension for {component} on {target}: {filename}")
    return url, sha256


for host in hosts:
    for component in ("rustc", "cargo", "rustfmt", "clippy", "llvm-tools-preview"):
        url, sha256 = artifact(component, host)
        print("|".join(("host", component, host, url, sha256)))

for target in targets:
    url, sha256 = artifact("rust-std", target)
    print("|".join(("target", "rust-std", target, url, sha256)))
PY
}

rust_dist_write_lockfile() {
  local file="$1"
  local version="$2"
  local manifest_url="$3"
  local manifest_sha256="$4"
  local artifacts_file="$5"
  local tmp_file="${file}.tmp"

  {
    echo "# Locked upstream Rust distribution inputs."
    echo "# Generated by script/vendor-rust."
    echo
    echo "[rust]"
    echo "version = \"$version\""
    echo "manifest_url = \"$manifest_url\""
    echo "manifest_sha256 = \"$manifest_sha256\""
    toml_array hosts "${RUST_DIST_HOSTS[@]}"
    toml_array targets "${RUST_DIST_TARGETS[@]}"
    toml_array host_components "${RUST_DIST_HOST_COMPONENTS[@]}"
    echo

    local first_artifact=true
    while IFS='|' read -r kind component target url sha256; do
      [[ -n "$kind" ]] || continue
      if [[ "$first_artifact" == "true" ]]; then
        first_artifact=false
      else
        echo
      fi
      echo "[[artifacts]]"
      echo "kind = \"$kind\""
      echo "component = \"$component\""
      echo "target = \"$target\""
      echo "url = \"$url\""
      echo "sha256 = \"$sha256\""
    done < "$artifacts_file"
  } > "$tmp_file"

  mv "$tmp_file" "$file"
}
