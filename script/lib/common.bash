# Shared Bash helpers for repo scripts.

sha256_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    sha256sum "$file" | awk '{print $1}'
  fi
}

sha256_stdin() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    sha256sum | awk '{print $1}'
  fi
}

fetch() {
  local url="$1"
  local dest="$2"

  mkdir -p "$(dirname "$dest")"
  curl -fsSL "$url" -o "$dest"
}

toml_value() {
  local file="$1"
  local key="$2"
  sed -n "s/^${key}[[:space:]]*=[[:space:]]*\"\([^\"]*\)\"/\\1/p" "$file" | head -n1
}

toml_array() {
  local name="$1"
  shift

  printf '%s = [' "$name"
  local separator=""
  local item
  for item in "$@"; do
    printf '%s"%s"' "$separator" "$item"
    separator=", "
  done
  printf ']\n'
}

reject_unsafe_relative_path() {
  local path="$1"
  local description="$2"

  case "$path" in
    ""|/*|../*|*/../*|*/..|..)
      die "${description} contains unsafe path: $path"
      ;;
  esac
}

validate_tar_entries() {
  local archive="$1"
  local compression_flag="$2"
  local entry

  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    case "$entry" in
      /*|../*|*/../*|*/..|..)
        die "unsafe archive entry in ${archive#$DIR/}: $entry"
        ;;
    esac
  done < <(tar -t"${compression_flag}"f "$archive")
}

archive_contains() {
  local archive="$1"
  local compression_flag="$2"
  local expected="$3"

  tar -t"${compression_flag}"f "$archive" | awk -v expected="$expected" '$0 == expected { found=1 } END { exit(found ? 0 : 1) }'
}

make_temp_dir() {
  local prefix="$1"
  local root="${2:-${TMPDIR:-/tmp}}"

  mkdir -p "$root"
  mktemp -d "${root}/${prefix}.XXXXXX"
}

generated_path_allowed() {
  local path="$1"

  case "$path" in
    "$DIR"/coverage|"$DIR"/coverage/*|"$DIR"/dist|"$DIR"/dist/*|"$DIR"/target/*|"$DIR"/vendor/cache|"$DIR"/vendor/release-tools|"$DIR"/vendor/test-tools)
      return 0
      ;;
  esac

  if [[ -n "${RUNNER_TEMP:-}" && "$path" == "$RUNNER_TEMP"/* ]]; then
    return 0
  fi
  if [[ -n "${TMPDIR:-}" && "$path" == "$TMPDIR"/* ]]; then
    return 0
  fi

  return 1
}

require_generated_path() {
  local path="$1"
  local description="$2"

  case "$path" in
    ""|/|"$DIR"|"${HOME:-__unset__}"|/tmp|/private/tmp|/var/tmp|"${RUNNER_TEMP:-__unset__}"|"${TMPDIR:-__unset__}")
      die "refusing to manage unsafe ${description}: ${path:-empty}"
      ;;
    ..|../*|*/..|*/../*)
      die "${description} must not contain .. path components: $path"
      ;;
  esac

  if ! generated_path_allowed "$path"; then
    die "${description} must stay under repo-generated paths, RUNNER_TEMP, or TMPDIR: $path"
  fi
}

remove_generated_path() {
  local path="$1"
  local description="$2"

  require_generated_path "$path" "$description"
  rm -rf "$path"
}

clear_generated_dir() {
  local path="$1"
  local description="$2"

  require_generated_path "$path" "$description"
  mkdir -p "$path"
  find "$path" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
}

rust_target_installed() {
  local target="$1"
  local sysroot

  sysroot="$(rustc --print sysroot 2>/dev/null || true)"
  if [[ -z "$sysroot" ]]; then
    return 1
  fi

  [[ -d "$sysroot/lib/rustlib/$target/lib" ]]
}

assert_tool_version() {
  local tool="$1"
  local expected_file="$2"
  local actual_version="$3"

  if [[ -f "$expected_file" ]]; then
    local expected
    expected="$(head -n1 "$expected_file" | tr -d '[:space:]')"
    if [[ -n "$expected" && "$actual_version" != "$expected" ]]; then
      die "${tool} version mismatch (expected ${expected}, found ${actual_version})"
    fi
  fi
}
