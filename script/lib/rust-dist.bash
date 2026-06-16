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

rust_dist_artifact_entry() {
  local lockfile="$1"
  local kind="$2"
  local component="$3"
  local target="$4"

  rust_dist_artifact_entries "$lockfile" | awk -F'|' \
    -v kind="$kind" -v component="$component" -v target="$target" '
      !found && $1 == kind && $2 == component && $3 == target {
        print $4 "|" $5
        found = 1
      }
      END { exit(found ? 0 : 1) }
    '
}

rust_dist_relative_url_path() {
  local url="$1"
  local path

  case "$url" in
    https://static.rust-lang.org/dist/*)
      path="${url#https://static.rust-lang.org/}"
      ;;
    *)
      die "unexpected Rust distribution URL"
      ;;
  esac

  case "$path" in
    *\?*|*\#*)
      die "Rust distribution URL must not contain a query or fragment"
      ;;
  esac
  reject_unsafe_relative_path "$path" "Rust distribution URL path"
  printf '%s\n' "$path"
}

rust_dist_fetch_verified() {
  local url="$1"
  local expected_sha256="$2"
  local mirror_root="$3"
  local relative_path
  local destination
  local actual_sha256

  if ! [[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    die "invalid locked Rust distribution checksum"
  fi

  relative_path="$(rust_dist_relative_url_path "$url")"
  destination="$mirror_root/$relative_path"
  if [[ ! -f "$destination" ]]; then
    fetch "$url" "$destination"
  fi

  actual_sha256="$(sha256_file "$destination")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    die "Rust distribution artifact checksum mismatch"
  fi
}

rust_dist_require_install_selection() {
  local lockfile="$1"
  local host="$2"
  local targets_csv="$3"
  local component
  local target
  local requested_targets=()

  if [[ -z "$host" || "$host" == "unknown" ]]; then
    die "unsupported Rust host"
  fi

  for component in "${RUST_DIST_HOST_COMPONENTS[@]}"; do
    rust_dist_require_artifact "$lockfile" host "$component" "$host"
  done
  rust_dist_require_artifact "$lockfile" target rust-std "$host"

  if [[ -n "$targets_csv" ]]; then
    IFS=',' read -r -a requested_targets <<< "$targets_csv"
    for target in "${requested_targets[@]}"; do
      [[ -n "$target" ]] || continue
      if [[ "$target" =~ [[:space:]] ]]; then
        die "Rust target contains whitespace"
      fi
      rust_dist_require_artifact "$lockfile" target rust-std "$target"
    done
  fi
}

rust_dist_prepare_verified_mirror() {
  local lockfile="$1"
  local host="$2"
  local targets_csv="$3"
  local mirror_root="$4"
  local component
  local target
  local artifact_entry
  local artifact_url
  local artifact_sha256
  local manifest_url
  local manifest_sha256
  local manifest_relative_path
  local manifest_path
  local seen_targets="|${host}|"
  local targets=("$host")
  local requested_targets=()

  rust_dist_require_install_selection "$lockfile" "$host" "$targets_csv"

  if [[ -n "$targets_csv" ]]; then
    IFS=',' read -r -a requested_targets <<< "$targets_csv"
    for target in "${requested_targets[@]}"; do
      [[ -n "$target" ]] || continue
      case "$seen_targets" in
        *"|${target}|"*) ;;
        *)
          targets+=("$target")
          seen_targets+="${target}|"
          ;;
      esac
    done
  fi

  manifest_url="$(toml_value "$lockfile" manifest_url)"
  manifest_sha256="$(toml_value "$lockfile" manifest_sha256)"
  rust_dist_fetch_verified "$manifest_url" "$manifest_sha256" "$mirror_root"
  manifest_relative_path="$(rust_dist_relative_url_path "$manifest_url")"
  manifest_path="$mirror_root/$manifest_relative_path"
  printf '%s  %s\n' "$manifest_sha256" "$(basename "$manifest_path")" > "${manifest_path}.sha256"

  for component in "${RUST_DIST_HOST_COMPONENTS[@]}"; do
    artifact_entry="$(rust_dist_artifact_entry "$lockfile" host "$component" "$host")"
    IFS='|' read -r artifact_url artifact_sha256 <<< "$artifact_entry"
    rust_dist_fetch_verified "$artifact_url" "$artifact_sha256" "$mirror_root"
  done

  for target in "${targets[@]}"; do
    artifact_entry="$(rust_dist_artifact_entry "$lockfile" target rust-std "$target")"
    IFS='|' read -r artifact_url artifact_sha256 <<< "$artifact_entry"
    rust_dist_fetch_verified "$artifact_url" "$artifact_sha256" "$mirror_root"
  done
}

rust_dist_install_from_verified_mirror() {
  local mirror_root="$1"
  local toolchain="$2"
  shift 2
  local port_file="${mirror_root}.port"
  local server_log="${mirror_root}.server.log"

  require_cmd python3

  if [[ -e "$port_file" ]]; then
    remove_generated_path "$port_file" "verified Rust distribution mirror port file"
  fi

  (
    python3 -I - "$mirror_root" "$port_file" >"$server_log" 2>&1 <<'PY' &
import functools
import http.server
import os
import sys

root, port_path = sys.argv[1:3]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass


handler = functools.partial(QuietHandler, directory=root)
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
descriptor = os.open(port_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    handle.write(f"{server.server_port}\n")
server.serve_forever()
PY
    local server_pid=$!
    cleanup_server() {
      kill "$server_pid" >/dev/null 2>&1 || true
      wait "$server_pid" >/dev/null 2>&1 || true
    }
    trap cleanup_server EXIT INT TERM

    local attempt
    for ((attempt = 0; attempt < 100; attempt++)); do
      if [[ -s "$port_file" ]]; then
        break
      fi
      if ! kill -0 "$server_pid" >/dev/null 2>&1; then
        die "verified Rust distribution mirror failed to start"
      fi
      sleep 0.05
    done
    if [[ ! -s "$port_file" ]]; then
      die "verified Rust distribution mirror did not become ready"
    fi

    local mirror_url="http://127.0.0.1:$(head -n1 "$port_file")"
    local rustup_environment=(
      env
      -u RUSTUP_DIST_ROOT
      -u RUSTUP_TOOLCHAIN
      -u RUSTUP_OFFLINE
      -u RUSTUP_LOG
      -u RUSTUP_TRACE_DIR
      -u RUSTUP_TOOLCHAIN_SOURCE
      -u RUSTUP_PERMIT_COPY_RENAME
      -u ALL_PROXY
      -u HTTPS_PROXY
      -u HTTP_PROXY
      -u all_proxy
      -u https_proxy
      -u http_proxy
      NO_PROXY="127.0.0.1,localhost"
      no_proxy="127.0.0.1,localhost"
      RUSTUP_DIST_SERVER="$mirror_url"
      RUSTUP_UPDATE_ROOT="$mirror_url/rustup"
      RUSTUP_AUTO_INSTALL=0
    )
    "${rustup_environment[@]}" rustup toolchain uninstall "$toolchain"
    "${rustup_environment[@]}" rustup "$@"
  )
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
