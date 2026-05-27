# Shared helpers for vendored test tools.

test_tools_cargo_llvm_cov_entries() {
  local file="$1"
  awk '
    function value(line) {
      sub(/^[^=]*= "/, "", line)
      sub(/"$/, "", line)
      return line
    }
    /^\[\[cargo_llvm_cov\]\]/ {
      if (in_tool && platform != "") {
        print platform "|" arch "|" os "|" target "|" version "|" url "|" path "|" sha256
      }
      in_tool = 1
      platform = arch = os = target = version = url = path = sha256 = ""
      next
    }
    /^\[/ {
      if (in_tool && platform != "") {
        print platform "|" arch "|" os "|" target "|" version "|" url "|" path "|" sha256
      }
      in_tool = 0
      next
    }
    in_tool && $1 == "platform" { platform = value($0) }
    in_tool && $1 == "arch" { arch = value($0) }
    in_tool && $1 == "os" { os = value($0) }
    in_tool && $1 == "target" { target = value($0) }
    in_tool && $1 == "version" { version = value($0) }
    in_tool && $1 == "url" { url = value($0) }
    in_tool && $1 == "path" { path = value($0) }
    in_tool && $1 == "sha256" { sha256 = value($0) }
    END {
      if (in_tool && platform != "") {
        print platform "|" arch "|" os "|" target "|" version "|" url "|" path "|" sha256
      }
    }
  ' "$file"
}

test_tools_host_platform() {
  local os
  local arch
  local tool_os
  local tool_arch
  local target

  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin) tool_os="macos" ;;
    Linux) tool_os="linux" ;;
    *) die "unsupported OS for cargo-llvm-cov artifact: $os" ;;
  esac

  case "$arch" in
    arm64|aarch64) tool_arch="aarch64" ;;
    x86_64) tool_arch="x86_64" ;;
    *) die "unsupported arch for cargo-llvm-cov artifact: $arch" ;;
  esac

  case "${tool_os}-${tool_arch}" in
    linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
    linux-aarch64) target="aarch64-unknown-linux-gnu" ;;
    macos-x86_64) target="x86_64-apple-darwin" ;;
    macos-aarch64) target="aarch64-apple-darwin" ;;
    *) die "unsupported cargo-llvm-cov platform: ${tool_os}-${tool_arch}" ;;
  esac

  echo "${tool_os}|${tool_arch}|${tool_os}-${tool_arch}|${target}"
}
