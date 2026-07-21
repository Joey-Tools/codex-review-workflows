#!/bin/bash
set -euo pipefail

EXPECTED_SHA256="fcdf6d473ec5c6fa76488da0b115d147fe5e5fa576ed33710ecd3fd7186e0b46"
EXPECTED_SIZE=101728

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

path_exists() {
  [[ -e "$1" || -L "$1" ]]
}

require_no_acl() {
  local path="$1"
  local label="$2"
  local acl_listing

  if ! acl_listing="$(/bin/ls -lde "$path")"; then
    fail "could not inspect the ACL on $label"
  fi
  [[ "$acl_listing" != *$'\n'* ]] ||
    fail "$label must not have an extended ACL"
}

require_directory() {
  local path="$1"
  local label="$2"
  local metadata after uid gid mode device inode mode_number

  [[ -d "$path" && ! -L "$path" ]] || fail "unsafe directory: $path"
  metadata="$(/usr/bin/stat -f '%u:%g:%Lp:%d:%i' "$path")"
  IFS=: read -r uid gid mode device inode <<<"$metadata"
  [[ "$uid" == "$EXPECTED_UID" && "$gid" == "$EXPECTED_GID" ]] ||
    fail "$label must be owned by $EXPECTED_OWNER_DESCRIPTION"
  mode_number=$((8#$mode))
  (( (mode_number & 0022) == 0 && (mode_number & 0111) == 0111 )) ||
    fail "$label must not be group/world writable and must be traversable"
  require_no_acl "$path" "$label"
  after="$(/usr/bin/stat -f '%u:%g:%Lp:%d:%i' "$path")"
  [[ "$after" == "$metadata" ]] || fail "$label metadata changed during inspection"
}

require_test_root() {
  local path="$1"
  local metadata after uid gid mode device inode

  [[ -d "$path" && ! -L "$path" ]] || fail "test root must be a real directory"
  metadata="$(/usr/bin/stat -f '%u:%g:%Lp:%d:%i' "$path")"
  IFS=: read -r uid gid mode device inode <<<"$metadata"
  [[ "$uid" == "$EXPECTED_UID" && "$gid" == "$EXPECTED_GID" ]] ||
    fail "test root must be owned by the current user and group"
  [[ "$mode" == "700" ]] || fail "test root must have exact mode 0700"
  require_no_acl "$path" "test root"
  after="$(/usr/bin/stat -f '%u:%g:%Lp:%d:%i' "$path")"
  [[ "$after" == "$metadata" ]] || fail "test root metadata changed during inspection"
  TEST_ROOT_IDENTITY="$device:$inode"
}

create_directory() {
  local path="$1"
  local metadata after uid gid mode device inode

  if ! (umask 022; /bin/mkdir "$path") 2>/dev/null; then
    path_exists "$path" || fail "could not safely create directory: $path"
    require_directory "$path" "directory $path"
    return
  fi

  [[ -d "$path" && ! -L "$path" ]] || fail "new directory is unsafe: $path"
  metadata="$(/usr/bin/stat -f '%u:%g:%Lp:%d:%i' "$path")"
  IFS=: read -r uid gid mode device inode <<<"$metadata"
  [[ "$uid" == "$EXPECTED_UID" && "$gid" == "$EXPECTED_GID" && "$mode" == "755" ]] ||
    fail "new directory did not receive final metadata: $path"
  require_no_acl "$path" "new directory $path"
  after="$(/usr/bin/stat -f '%u:%g:%Lp:%d:%i' "$path")"
  [[ "$after" == "$metadata" ]] || fail "new directory metadata changed: $path"
  require_directory "$path" "directory $path"
}

require_private_staging_file() {
  local path="$1"
  local expected_size="$2"
  local metadata uid gid mode links device inode size

  [[ -f "$path" && ! -L "$path" ]] || fail "broker staging path is unsafe"
  metadata="$(/usr/bin/stat -f '%u:%g:%Lp:%l:%d:%i:%z' "$path")"
  IFS=: read -r uid gid mode links device inode size <<<"$metadata"
  [[ "$uid" == "$EXPECTED_UID" && "$gid" == "$EXPECTED_GID" ]] ||
    fail "broker staging file has an unsafe owner"
  [[ "$mode" == "600" && "$links" == "1" ]] ||
    fail "broker staging file must be private and single-link"
  [[ "$device:$inode" == "$TEMPORARY_IDENTITY" ]] ||
    fail "broker staging file identity changed"
  [[ "$size" == "$expected_size" ]] ||
    fail "broker artifact size does not match the installer"
  require_no_acl "$path" "broker staging file"
  [[ "$(/usr/bin/stat -f '%u:%g:%Lp:%l:%d:%i:%z' "$path")" == "$metadata" ]] ||
    fail "broker staging metadata changed during inspection"
}

require_final_file_metadata() {
  local path="$1"
  local label="$2"
  local metadata uid gid mode links device inode size

  [[ -f "$path" && ! -L "$path" ]] || fail "$label is not a regular file"
  metadata="$(/usr/bin/stat -f '%u:%g:%Lp:%l:%d:%i:%z' "$path")"
  IFS=: read -r uid gid mode links device inode size <<<"$metadata"
  [[ "$uid" == "$EXPECTED_UID" && "$gid" == "$EXPECTED_GID" ]] ||
    fail "$label has an unsafe owner"
  [[ "$mode" == "555" && "$links" == "1" && "$size" == "$EXPECTED_SIZE" ]] ||
    fail "$label metadata is unsafe"
  require_no_acl "$path" "$label"
  [[ "$(/usr/bin/stat -f '%u:%g:%Lp:%l:%d:%i:%z' "$path")" == "$metadata" ]] ||
    fail "$label metadata changed during inspection"
  FINAL_FILE_IDENTITY="$device:$inode"
}

require_expected_digest() {
  local path="$1"
  local label="$2"
  local digest_output digest

  digest_output="$(/usr/bin/shasum -a 256 "$path")"
  digest="${digest_output%% *}"
  [[ "$digest" == "$EXPECTED_SHA256" ]] ||
    fail "$label digest does not match the installer"
}

verify_private_staging_file() {
  local path="$1"
  local identity_before

  require_private_staging_file "$path" "$EXPECTED_SIZE"
  identity_before="$TEMPORARY_IDENTITY"
  require_expected_digest "$path" "broker artifact"
  /usr/bin/codesign --verify --strict --all-architectures --verbose=2 "$path"
  require_private_staging_file "$path" "$EXPECTED_SIZE"
  [[ "$TEMPORARY_IDENTITY" == "$identity_before" ]] ||
    fail "broker staging identity changed during verification"
}

verify_installed_file() {
  local path="$1"
  local identity_before

  require_final_file_metadata "$path" "installed broker"
  identity_before="$FINAL_FILE_IDENTITY"
  require_expected_digest "$path" "installed broker"
  /usr/bin/codesign --verify --strict --all-architectures --verbose=2 "$path"
  require_final_file_metadata "$path" "installed broker"
  [[ "$FINAL_FILE_IDENTITY" == "$identity_before" ]] ||
    fail "installed broker identity changed during verification"
}

cleanup_temporary() {
  local metadata uid links device inode

  [[ -n "$temporary" ]] || return 0
  if ! path_exists "$temporary"; then
    temporary=""
    return 0
  fi
  [[ -f "$temporary" && ! -L "$temporary" ]] || return 1
  metadata="$(/usr/bin/stat -f '%u:%l:%d:%i' "$temporary")" || return 1
  IFS=: read -r uid links device inode <<<"$metadata"
  [[ "$uid" == "$EXPECTED_UID" && "$links" == "1" ]] || return 1
  [[ -n "$TEMPORARY_IDENTITY" && "$device:$inode" == "$TEMPORARY_IDENTITY" ]] ||
    return 1
  /bin/rm -f "$temporary" || return 1
  if path_exists "$temporary"; then
    return 1
  fi
  temporary=""
}

cleanup_on_exit() {
  local status="$?"

  trap - EXIT HUP INT TERM
  if ! cleanup_temporary; then
    printf 'warning: refused to remove an unverified staging path: %s\n' \
      "$temporary" >&2
  fi
  exit "$status"
}

remove_temporary_or_fail() {
  cleanup_temporary || fail "could not safely remove the broker staging file"
}

install_payload() {
  local parent="$1"
  shift
  local component path destination temporary_metadata
  local temporary_uid temporary_mode temporary_links temporary_device temporary_inode

  umask 077
  for component in "$@"; do
    path="$parent/$component"
    create_directory "$path"
    parent="$path"
  done

  destination="$parent/security"
  temporary=""
  TEMPORARY_IDENTITY=""
  FINAL_FILE_IDENTITY=""
  trap cleanup_on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  temporary="$(/usr/bin/mktemp "$parent/.security.install.XXXXXX")" ||
    fail "could not create the broker staging file"
  [[ -f "$temporary" && ! -L "$temporary" ]] ||
    fail "new broker staging path is unsafe"
  temporary_metadata="$(/usr/bin/stat -f '%u:%Lp:%l:%d:%i' "$temporary")"
  IFS=: read -r temporary_uid temporary_mode temporary_links temporary_device temporary_inode \
    <<<"$temporary_metadata"
  [[ "$temporary_uid" == "$EUID" && "$temporary_mode" == "600" &&
    "$temporary_links" == "1" ]] ||
    fail "new broker staging file did not receive private metadata"
  TEMPORARY_IDENTITY="$temporary_device:$temporary_inode"

  /usr/sbin/chown "${EXPECTED_UID}:${EXPECTED_GID}" "$temporary"
  /bin/chmod -N "$temporary"
  /bin/chmod 0600 "$temporary"
  require_private_staging_file "$temporary" 0

  /usr/bin/head -c "$((EXPECTED_SIZE + 1))" > "$temporary"
  verify_private_staging_file "$temporary"

  if path_exists "$destination"; then
    verify_installed_file "$destination"
    remove_temporary_or_fail
    printf 'Claude Keychain broker already installed at %s\n' "$destination"
    exit 0
  fi

  /usr/sbin/chown "${EXPECTED_UID}:${EXPECTED_GID}" "$temporary"
  /bin/chmod -N "$temporary"
  /bin/chmod 0555 "$temporary"
  require_final_file_metadata "$temporary" "broker staging file"
  [[ "$FINAL_FILE_IDENTITY" == "$TEMPORARY_IDENTITY" ]] ||
    fail "broker staging identity changed before publication"

  /bin/mv -n "$temporary" "$destination"
  if path_exists "$temporary"; then
    verify_installed_file "$destination"
    remove_temporary_or_fail
    printf 'Claude Keychain broker already installed at %s\n' "$destination"
    exit 0
  fi
  temporary=""

  verify_installed_file "$destination"
  printf 'Installed Claude Keychain broker at %s\n' "$destination"
}

build_production_root_program() {
  local root_header root_functions

  builtin printf -v root_header \
    'set -euo pipefail\nEXPECTED_SHA256=%q\nEXPECTED_SIZE=%q\nEXPECTED_UID=0\nEXPECTED_GID=0\nEXPECTED_OWNER_DESCRIPTION=%q\ntemporary=%q\nTEMPORARY_IDENTITY=%q\nFINAL_FILE_IDENTITY=%q\n' \
    "$EXPECTED_SHA256" \
    "$EXPECTED_SIZE" \
    "root:wheel" \
    "" \
    "" \
    ""
  root_functions="$(builtin declare -f \
    fail \
    path_exists \
    require_no_acl \
    require_directory \
    create_directory \
    require_private_staging_file \
    require_final_file_metadata \
    require_expected_digest \
    verify_private_staging_file \
    verify_installed_file \
    cleanup_temporary \
    cleanup_on_exit \
    remove_temporary_or_fail \
    install_payload)"
  ROOT_PROGRAM="${root_header}${root_functions}"$'\n'
  ROOT_PROGRAM+='(( EUID == 0 )) || fail "production worker did not receive root"'$'\n'
  ROOT_PROGRAM+='require_directory "/" "directory /"'$'\n'
  ROOT_PROGRAM+='require_directory "/Library" "directory /Library"'$'\n'
  ROOT_PROGRAM+=$'install_payload "/Library" "Joey-Tools" "CodexReview" "brokers" "$EXPECTED_SHA256"\n'
}

run_production_install() {
  (( EUID != 0 )) ||
    fail "--install must start as a non-root user so root never opens this script"
  build_production_root_program

  exec /usr/bin/sudo \
    /usr/bin/env -i \
    HOME=/var/root \
    LANG=C \
    LC_ALL=C \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    TMPDIR=/private/tmp \
    /bin/bash -c "$ROOT_PROGRAM"
}

run_test_install() {
  local test_root="$1"
  local canonical_test_root
  local validated_test_root_identity

  (( EUID != 0 )) || fail "--test-root is forbidden when running as root"
  [[ "$test_root" == /* ]] || fail "--test-root requires an absolute path"
  case "$test_root" in
    / | /Library | /Library/*)
      fail "--test-root must not target a production path"
      ;;
  esac
  canonical_test_root="$(cd -P -- "$test_root" 2>/dev/null && pwd -P)" ||
    fail "test root is unavailable"
  [[ "$canonical_test_root" == "$test_root" ]] ||
    fail "test root must be a canonical path without symlink components"
  EXPECTED_UID="$(/usr/bin/id -u)"
  EXPECTED_GID="$(/usr/bin/id -g)"
  EXPECTED_OWNER_DESCRIPTION="the current user and group"
  require_test_root "$test_root"
  validated_test_root_identity="$TEST_ROOT_IDENTITY"
  cd -P -- "$test_root" 2>/dev/null || fail "test root changed before entry"
  require_test_root "."
  [[ "$TEST_ROOT_IDENTITY" == "$validated_test_root_identity" ]] ||
    fail "test root identity changed before installation"
  install_payload \
    "." \
    "Library" \
    "Joey-Tools" \
    "CodexReview" \
    "brokers" \
    "$EXPECTED_SHA256"
}

main() {
  [[ "$(/usr/bin/uname -s)" == "Darwin" ]] || fail "macOS is required"

  case "$#:${1-}" in
    1:--install)
      run_production_install
      ;;
    2:--test-root)
      run_test_install "$2"
      ;;
    *)
      fail "usage: $0 --install | $0 --test-root ABSOLUTE_PATH"
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
