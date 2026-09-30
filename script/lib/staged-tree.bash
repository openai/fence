# Helpers for publishing a fully prepared generated tree without exposing a partial refresh.

publish_staged_generated_tree() {
  local staged="$1"
  local destination="$2"
  local backup="$3"
  local description="$4"
  shift 4

  require_generated_path "$destination" "$description"
  require_generated_path "$backup" "$description backup"

  if [[ ! -d "$staged" || -L "$staged" ]]; then
    die "staged ${description} must be a real directory: $staged"
  fi
  if [[ -e "$backup" || -L "$backup" ]]; then
    die "staged ${description} backup path already exists: $backup"
  fi

  local had_previous=false
  if [[ -e "$destination" || -L "$destination" ]]; then
    mv "$destination" "$backup"
    had_previous=true
  fi

  if ! mv "$staged" "$destination"; then
    if [[ "$had_previous" == "true" ]]; then
      mv "$backup" "$destination" || true
    fi
    return 1
  fi

  if "$@"; then
    if [[ "$had_previous" == "true" ]]; then
      rm -rf "$backup"
    fi
    return 0
  else
    local status="$?"
    rm -rf "$destination"
    if [[ "$had_previous" == "true" ]]; then
      mv "$backup" "$destination" || return 1
    fi
    return "$status"
  fi
}
