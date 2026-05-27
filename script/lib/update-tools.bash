# Shared helpers for online update-path Cargo tools.

update_tool_entries() {
  local lockfile="${1:-$UPDATE_TOOLS_LOCK}"
  awk '
    function value(line) {
      sub(/^[^=]*= "/, "", line)
      sub(/"$/, "", line)
      return line
    }
    function print_entry() {
      if (in_tool) {
        print name "|" binary "|" version "|" url "|" crate_sha256 "|" crate_lockfile_sha256
      }
    }
    /^\[\[tools\]\]/ {
      print_entry()
      in_tool = 1
      name = binary = version = url = crate_sha256 = crate_lockfile_sha256 = ""
      next
    }
    /^\[/ {
      print_entry()
      in_tool = 0
      next
    }
    in_tool && $1 == "name" { name = value($0) }
    in_tool && $1 == "binary" { binary = value($0) }
    in_tool && $1 == "version" { version = value($0) }
    in_tool && $1 == "url" { url = value($0) }
    in_tool && $1 == "crate_sha256" { crate_sha256 = value($0) }
    in_tool && $1 == "crate_lockfile_sha256" { crate_lockfile_sha256 = value($0) }
    END {
      print_entry()
    }
  ' "$lockfile"
}

update_tool_entry() {
  local requested="$1"
  local lockfile="${2:-$UPDATE_TOOLS_LOCK}"
  update_tool_entries "$lockfile" | awk -F'|' -v requested="$requested" '$1 == requested { print; exit }'
}

update_tool_require_entry() {
  local name="$1"
  if [[ -z "$(update_tool_entry "$name")" ]]; then
    die "missing update-tool lock entry: $name"
  fi
}

update_tool_expected_url() {
  local name="$1"
  local version="$2"
  echo "https://static.crates.io/crates/${name}/${name}-${version}.crate"
}

update_tool_validate_archive_paths() {
  local archive="$1"
  local name="$2"
  local path

  while IFS= read -r path; do
    case "$path" in
      ""|/*|../*|*/../*|*/..|..)
        die "${name} crate contains unsafe archive path: $path"
        ;;
    esac
  done < <(tar -tzf "$archive")
}

update_tool_extract_crate() {
  local name="$1"
  local version="$2"
  local crate_file="$3"
  local extract_dir="$4"
  local source_dir="$extract_dir/${name}-${version}"

  update_tool_validate_archive_paths "$crate_file" "$name"
  remove_generated_path "$extract_dir" "extracted update-tool directory"
  mkdir -p "$extract_dir"
  tar -xzf "$crate_file" -C "$extract_dir"

  if [[ ! -f "$source_dir/Cargo.toml" ]]; then
    die "${name} crate did not unpack to expected source directory"
  fi
  if [[ ! -f "$source_dir/Cargo.lock" ]]; then
    die "${name} crate does not include Cargo.lock"
  fi

  echo "$source_dir"
}

update_tool_verify_crate_sha256() {
  local name="$1"
  local crate_file="$2"
  local expected_sha256="$3"
  local actual_sha256

  actual_sha256="$(sha256_file "$crate_file")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    die "${name} crate checksum mismatch"
  fi
}

update_tool_verify_packaged_lockfile() {
  local name="$1"
  local source_dir="$2"
  local expected_sha256="$3"
  local actual_sha256

  actual_sha256="$(sha256_file "$source_dir/Cargo.lock")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    die "${name} packaged Cargo.lock checksum mismatch"
  fi
}

update_tool_fetch_locked_crate() {
  local name="$1"
  local version="$2"
  local url="$3"
  local expected_crate_sha256="$4"
  local expected_lockfile_sha256="$5"
  local tmp_root="$6"
  local crate_file="$tmp_root/${name}-${version}.crate"
  local extract_dir="$tmp_root/${name}-extract"
  local source_dir

  fetch "$url" "$crate_file"
  update_tool_verify_crate_sha256 "$name" "$crate_file" "$expected_crate_sha256"
  source_dir="$(update_tool_extract_crate "$name" "$version" "$crate_file" "$extract_dir")"
  update_tool_verify_packaged_lockfile "$name" "$source_dir" "$expected_lockfile_sha256"
  echo "$source_dir"
}

install_locked_update_tool() {
  local binary="$1"
  local crate="$2"
  local version_file="$3"
  local version_override="${4:-}"
  local expected="$version_override"

  if [[ -z "$expected" ]]; then
    expected="$(read_version_file "$version_file")"
  fi
  if [[ -z "$expected" ]]; then
    die "$(basename "$version_file") is required to pin ${crate}"
  fi

  local installed=""
  if command -v "$binary" >/dev/null 2>&1; then
    installed="$("$binary" --version 2>/dev/null | awk '{print $2}')"
  fi
  if [[ "$installed" == "$expected" ]]; then
    return
  fi

  local entry
  entry="$(update_tool_entry "$crate")"
  local locked_name locked_binary locked_version locked_url locked_crate_sha256 locked_crate_lockfile_sha256
  IFS='|' read -r locked_name locked_binary locked_version locked_url locked_crate_sha256 locked_crate_lockfile_sha256 <<< "$entry"
  if [[ -z "$locked_name" || -z "$locked_binary" || -z "$locked_version" || -z "$locked_url" || -z "$locked_crate_sha256" || -z "$locked_crate_lockfile_sha256" ]]; then
    die "${UPDATE_TOOLS_LOCK#$DIR/} is missing ${crate}"
  fi
  if [[ "$locked_binary" != "$binary" ]]; then
    die "${UPDATE_TOOLS_LOCK#$DIR/} binary mismatch for ${crate}"
  fi
  if [[ "$locked_version" != "$expected" ]]; then
    die "${UPDATE_TOOLS_LOCK#$DIR/} version mismatch for ${crate} (expected ${expected}, found ${locked_version})"
  fi

  local tool_tmp
  local source_dir
  tool_tmp="$(make_temp_dir "fence-${crate}")"
  source_dir="$(update_tool_fetch_locked_crate "$crate" "$expected" "$locked_url" "$locked_crate_sha256" "$locked_crate_lockfile_sha256" "$tool_tmp")"

  cargo install --locked --path "$source_dir" --force
  remove_generated_path "$tool_tmp" "temporary installed update-tool directory"

  installed="$("$binary" --version 2>/dev/null | awk '{print $2}')"
  if [[ "$installed" != "$expected" ]]; then
    die "${crate} version mismatch (expected ${expected}, found ${installed:-unknown})"
  fi
}
