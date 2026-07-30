#!/bin/bash
set -euo pipefail

DEPLOYMENT_TARGET="13.0"
IDENTIFIER="dev.openai.codex.claude-keychain-broker"
EXPECTED_SOURCE_SHA256="c7a08c6aa448a4e5b5d4972ca8a19393ccd311b8e1de0b28f6753387b13119b0"
EXPECTED_ARTIFACT_SHA256="fcdf6d473ec5c6fa76488da0b115d147fe5e5fa576ed33710ecd3fd7186e0b46"
EXPECTED_XCODE_VERSION="Xcode 26.6"
EXPECTED_XCODE_BUILD="Build version 17F113"
EXPECTED_SDK_VERSION="26.5"
EXPECTED_SDK_BUILD="25F70"
EXPECTED_CLANG_VERSION="Apple clang version 21.0.0 (clang-2100.1.1.101)"
EXPECTED_LD_PROJECT="PROJECT:ld-1267"
EXPECTED_CODESIGN_PROJECT="PROJECT:codesign-83.100.6"
EXPECTED_DEVELOPER_CLANG_SHA256="7def90dd8829726686213a747fc5bff1583df933dae5edc55d755479e0bfe00a"
EXPECTED_DEVELOPER_LD_SHA256="5897b275efd93b201b6df5832dd541262b3f20f290859ba78f2200a6a66ef38b"
EXPECTED_DEVELOPER_LIPO_SHA256="661f3514be6992bb66346e3e48d974fc0ce5b9be5eab55321eabf4818fb3bf28"
EXPECTED_DEVELOPER_VTOOL_SHA256="c87bf9bb62dc6a3c5d7faf5c5f8dabc94aba865161a3e08b9f1871150e938fe6"
EXPECTED_DEVELOPER_CODESIGN_ALLOCATE_SHA256="c56802d5bfdc2ee8b0e6e4358239f4de4c3b34814f71bee7a185100d78d6ad4b"
EXPECTED_DEVELOPER_CODESIGN_SHA256="214d455584d19abc0d74d02b9cbc7d3da6bdcb0596c235e6156dd9ed2f4e1ba7"
EXPECTED_HOSTED_CLANG_SHA256="d2e4bf622758eee1bf7267c060497fb2c41e098d37b0fca8be73898dc7e14eda"
EXPECTED_HOSTED_LD_SHA256="e412b9f2af31b1567a9eabc28f553a8f1cf34127e2107cb39c2694cf147571a4"
EXPECTED_HOSTED_LIPO_SHA256="d8ced1b847259d388ce48178e0a908a4be87dc3f8b1b3b2c997d2a8d6936f84d"
EXPECTED_HOSTED_VTOOL_SHA256="4fe292643e9c8c528148c5be41d8d22801a17ec1f2bdaf85665c25c5cc56e236"
EXPECTED_HOSTED_CODESIGN_ALLOCATE_SHA256="b22f65e9f3ac39e5d64a2b88b42d4b2571926f929fc8b6b57cfc10de6d0d16ac"
EXPECTED_HOSTED_CODESIGN_SHA256="214d455584d19abc0d74d02b9cbc7d3da6bdcb0596c235e6156dd9ed2f4e1ba7"
EXPECTED_HOSTED_LEGACY_CODESIGN_SHA256="06eacc36d43376972d3bca0a2137ea4efd6d0fe27de8a7af0e6b11d599e8f337"
EXPECTED_HOSTED_OS_VERSION="26.5.2"
EXPECTED_HOSTED_OS_BUILD="25F84"
EXPECTED_HOSTED_LEGACY_OS_VERSION="26.4"
EXPECTED_HOSTED_LEGACY_OS_BUILD="25E246"
DEFAULT_DEVELOPER_DIR="/Applications/Xcode-26.6.0.app/Contents/Developer"
HOSTED_RUNNER_DEVELOPER_DIR="/Applications/Xcode_26.6.app/Contents/Developer"
DEVELOPER_DIR="${DEVELOPER_DIR:-$DEFAULT_DEVELOPER_DIR}"
SCRIPT_DIR="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename -- "$0")"
SOURCE="$SCRIPT_DIR/review_runtime/claude_keychain_broker.c"
TRACKED_ARTIFACT="$SCRIPT_DIR/review_runtime/claude_keychain_broker"

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'Usage: %s --developer-check | --check\n' "$(basename -- "$0")" >&2
  exit 64
}

first_line() {
  local value="$1"
  printf '%s\n' "${value%%$'\n'*}"
}

require_digest() {
  local path="$1"
  local expected="$2"
  local label="$3"
  local output actual

  [[ -f "$path" && ! -L "$path" ]] ||
    fail "$label is not a real regular file: $path"
  output="$("${probe_environment[@]}" /usr/bin/shasum -a 256 "$path")"
  actual="${output%% *}"
  if [[ "$actual" != "$expected" ]]; then
    fail "$label digest does not match the reviewed pin (expected=$expected actual=$actual)"
  fi
  printf 'verified %s sha256=%s\n' "$label" "$actual"
}

require_artifact_pins() {
  require_digest "$SOURCE" "$EXPECTED_SOURCE_SHA256" "broker source"
  require_digest \
    "$TRACKED_ARTIFACT" \
    "$EXPECTED_ARTIFACT_SHA256" \
    "tracked broker artifact"
}

require_tool_digest() {
  require_digest "$1" "$2" "$3"
}

select_hosted_codesign_sha256() {
  local os_version os_build
  os_version="$("${probe_environment[@]}" /usr/bin/sw_vers -productVersion)"
  os_build="$("${probe_environment[@]}" /usr/bin/sw_vers -buildVersion)"
  case "$os_version:$os_build" in
    "$EXPECTED_HOSTED_OS_VERSION:$EXPECTED_HOSTED_OS_BUILD")
      printf '%s\n' "$EXPECTED_HOSTED_CODESIGN_SHA256"
      ;;
    "$EXPECTED_HOSTED_LEGACY_OS_VERSION:$EXPECTED_HOSTED_LEGACY_OS_BUILD")
      printf '%s\n' "$EXPECTED_HOSTED_LEGACY_CODESIGN_SHA256"
      ;;
    *)
      fail "hosted runner OS version/build is not reviewed: $os_version ($os_build)"
      ;;
  esac
}

initialize_expected_toolchain_paths() {
  toolchain_root="$DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin"
  clang="$toolchain_root/clang"
  ld="$toolchain_root/ld"
  lipo="$toolchain_root/lipo"
  vtool="$toolchain_root/vtool"
  codesign_allocate="$toolchain_root/codesign_allocate"
  sdk_root="$DEVELOPER_DIR/Platforms/MacOSX.platform/Developer/SDKs/MacOSX${EXPECTED_SDK_VERSION}.sdk"
}

initialize_expected_tool_digests() {
  if [[ "$mode" == "hosted-check" ]]; then
    expected_clang_sha256="$EXPECTED_HOSTED_CLANG_SHA256"
    expected_ld_sha256="$EXPECTED_HOSTED_LD_SHA256"
    expected_lipo_sha256="$EXPECTED_HOSTED_LIPO_SHA256"
    expected_vtool_sha256="$EXPECTED_HOSTED_VTOOL_SHA256"
    expected_codesign_allocate_sha256="$EXPECTED_HOSTED_CODESIGN_ALLOCATE_SHA256"
    expected_codesign_sha256="$(select_hosted_codesign_sha256)"
  else
    expected_clang_sha256="$EXPECTED_DEVELOPER_CLANG_SHA256"
    expected_ld_sha256="$EXPECTED_DEVELOPER_LD_SHA256"
    expected_lipo_sha256="$EXPECTED_DEVELOPER_LIPO_SHA256"
    expected_vtool_sha256="$EXPECTED_DEVELOPER_VTOOL_SHA256"
    expected_codesign_allocate_sha256="$EXPECTED_DEVELOPER_CODESIGN_ALLOCATE_SHA256"
    expected_codesign_sha256="$EXPECTED_DEVELOPER_CODESIGN_SHA256"
  fi
}

require_pinned_toolchain() {
  local xcode_version sdk_version sdk_build clang_version ld_version
  local codesign_version resolved_clang resolved_ld resolved_lipo resolved_vtool
  local resolved_codesign_allocate resolved_sdk_root

  [[ -d "$DEVELOPER_DIR" ]] || fail "pinned Xcode developer directory is unavailable"
  xcode_version="$("${probe_environment[@]}" /usr/bin/xcodebuild -version)"
  [[ "$xcode_version" == "$EXPECTED_XCODE_VERSION"$'\n'"$EXPECTED_XCODE_BUILD" ]] ||
    fail "broker checks require $EXPECTED_XCODE_VERSION ($EXPECTED_XCODE_BUILD)"
  sdk_version="$("${probe_environment[@]}" /usr/bin/xcrun \
    --toolchain XcodeDefault --sdk macosx --show-sdk-version)"
  [[ "$sdk_version" == "$EXPECTED_SDK_VERSION" ]] ||
    fail "broker checks require macOS SDK $EXPECTED_SDK_VERSION"
  sdk_build="$("${probe_environment[@]}" /usr/bin/xcrun \
    --toolchain XcodeDefault --sdk macosx --show-sdk-build-version)"
  [[ "$sdk_build" == "$EXPECTED_SDK_BUILD" ]] ||
    fail "broker checks require macOS SDK build $EXPECTED_SDK_BUILD"

  resolved_clang="$("${probe_environment[@]}" /usr/bin/xcrun \
    --toolchain XcodeDefault --sdk macosx --find clang)"
  resolved_ld="$("${probe_environment[@]}" /usr/bin/xcrun \
    --toolchain XcodeDefault --sdk macosx --find ld)"
  resolved_lipo="$("${probe_environment[@]}" /usr/bin/xcrun \
    --toolchain XcodeDefault --sdk macosx --find lipo)"
  resolved_vtool="$("${probe_environment[@]}" /usr/bin/xcrun \
    --toolchain XcodeDefault --sdk macosx --find vtool)"
  resolved_codesign_allocate="$("${probe_environment[@]}" /usr/bin/xcrun \
    --toolchain XcodeDefault --sdk macosx --find codesign_allocate)"
  resolved_sdk_root="$("${probe_environment[@]}" /usr/bin/xcrun \
    --toolchain XcodeDefault --sdk macosx --show-sdk-path)"
  [[ "$resolved_clang" == "$clang" && "$resolved_ld" == "$ld" &&
    "$resolved_lipo" == "$lipo" && "$resolved_vtool" == "$vtool" &&
    "$resolved_codesign_allocate" == "$codesign_allocate" ]] ||
    fail "resolved build tools do not belong to the pinned toolchain"
  [[ "$resolved_sdk_root" == "$sdk_root" ]] ||
    fail "resolved SDK path does not match the pinned SDK alias"

  clang_version="$("${probe_environment[@]}" "$clang" --version)"
  [[ "$(first_line "$clang_version")" == "$EXPECTED_CLANG_VERSION" ]] ||
    fail "broker checks require the pinned Apple clang"
  ld_version="$("${probe_environment[@]}" "$ld" -v 2>&1)"
  [[ "$(first_line "$ld_version")" == *"$EXPECTED_LD_PROJECT"* ]] ||
    fail "broker checks require the pinned Apple linker"
  codesign_version="$("${probe_environment[@]}" /usr/bin/what /usr/bin/codesign)"
  [[ "$codesign_version" == *"$EXPECTED_CODESIGN_PROJECT"* ]] ||
    fail "broker checks require the pinned codesign implementation"

  require_tool_digest "$clang" "$expected_clang_sha256" "clang"
  require_tool_digest "$ld" "$expected_ld_sha256" "ld"
  require_tool_digest "$lipo" "$expected_lipo_sha256" "lipo"
  require_tool_digest "$vtool" "$expected_vtool_sha256" "vtool"
  require_tool_digest \
    "$codesign_allocate" \
    "$expected_codesign_allocate_sha256" \
    "codesign_allocate"
  require_tool_digest \
    "/usr/bin/codesign" \
    "$expected_codesign_sha256" \
    "codesign"
}

require_hosted_runner_context() {
  # These assertions bind the required CI context; they are not a security boundary.
  [[ "${CI:-}" == "true" ]] || fail "--check requires CI=true"
  [[ "${GITHUB_ACTIONS:-}" == "true" ]] ||
    fail "--check requires GITHUB_ACTIONS=true"
  [[ "${RUNNER_OS:-}" == "macOS" ]] || fail "--check requires RUNNER_OS=macOS"
  [[ "$DEVELOPER_DIR" == "$HOSTED_RUNNER_DEVELOPER_DIR" ]] ||
    fail "--check requires DEVELOPER_DIR=$HOSTED_RUNNER_DEVELOPER_DIR"
}

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || fail "macOS is required"
[[ "$DEVELOPER_DIR" == /* && ! -L "$DEVELOPER_DIR" ]] ||
  fail "developer directory must be an absolute real directory"
[[ -f "$SCRIPT_PATH" && ! -L "$SCRIPT_PATH" ]] || fail "build script path is unsafe"

case "${1:-}" in
  --developer-check)
    [[ "$#" == 1 ]] || usage
    mode="developer-check"
    ;;
  --check)
    [[ "$#" == 1 ]] || usage
    mode="hosted-check"
    ;;
  *) usage ;;
esac

probe_environment=(
  /usr/bin/env
  -i
  "DEVELOPER_DIR=$DEVELOPER_DIR"
  "HOME=/var/empty"
  "LANG=C"
  "LC_ALL=C"
  "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
  "TZ=UTC"
)

initialize_expected_toolchain_paths
initialize_expected_tool_digests
if [[ "$mode" == "hosted-check" ]]; then
  require_hosted_runner_context
fi
require_artifact_pins
require_pinned_toolchain

temporary="$(/usr/bin/mktemp -d "$SCRIPT_DIR/.broker-build.XXXXXX")"
trap '/bin/rm -rf -- "$temporary"' EXIT
build_environment=(
  /usr/bin/env
  -i
  "CODESIGN_ALLOCATE=$codesign_allocate"
  "DEVELOPER_DIR=$DEVELOPER_DIR"
  "HOME=/var/empty"
  "LANG=C"
  "LC_ALL=C"
  "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
  "SOURCE_DATE_EPOCH=0"
  "TMPDIR=$temporary"
  "TZ=UTC"
  "ZERO_AR_DATE=1"
)
common_flags=(
  -mmacosx-version-min="$DEPLOYMENT_TARGET"
  -std=c11
  -Os
  -Wall
  -Wextra
  -Werror
  -fstack-protector-strong
  -D_FORTIFY_SOURCE=2
  "-Wl,-dead_strip"
)

for architecture in arm64 x86_64; do
  "${build_environment[@]}" "$clang" \
    -isysroot "$sdk_root" \
    -arch "$architecture" \
    "${common_flags[@]}" \
    "$SOURCE" \
    -o "$temporary/broker-$architecture"
done

"${build_environment[@]}" "$lipo" -create \
  "$temporary/broker-arm64" \
  "$temporary/broker-x86_64" \
  -output "$temporary/broker"
"${build_environment[@]}" /usr/bin/codesign --force --sign - --options runtime \
  --identifier "$IDENTIFIER" \
  "$temporary/broker"
"${build_environment[@]}" /usr/bin/codesign --verify --strict \
  --all-architectures --verbose=2 "$temporary/broker"

architectures="$("${build_environment[@]}" "$lipo" -archs "$temporary/broker")"
[[ "$architectures" == "x86_64 arm64" || "$architectures" == "arm64 x86_64" ]] ||
  fail "broker must contain exactly arm64 and x86_64 slices"
for architecture in arm64 x86_64; do
  build="$("${build_environment[@]}" "$vtool" -show-build \
    -arch "$architecture" "$temporary/broker")"
  [[ "$build" == *"platform MACOS"* && "$build" == *"minos $DEPLOYMENT_TARGET"* ]] ||
    fail "$architecture broker slice has an unexpected deployment target"
done

require_digest \
  "$temporary/broker" \
  "$EXPECTED_ARTIFACT_SHA256" \
  "rebuilt broker artifact"
"${build_environment[@]}" /usr/bin/cmp -s \
  "$temporary/broker" "$TRACKED_ARTIFACT" ||
  fail "tracked broker artifact is not byte-reproducible"

# Recheck every mutable input after the compiler and signer have exited.
if [[ "$mode" == "hosted-check" ]]; then
  require_hosted_runner_context
fi
require_artifact_pins
require_pinned_toolchain
if [[ "$mode" == "hosted-check" ]]; then
  printf 'Hosted-runner reproducibility/context check passed; context assertions are not a security boundary: %s\n' \
    "$TRACKED_ARTIFACT"
else
  printf 'Developer check reproduced the pinned broker bytes; use --check for the required hosted-runner context gate.\n'
fi

"${build_environment[@]}" /usr/bin/shasum -a 256 "$TRACKED_ARTIFACT"
for architecture in arm64 x86_64; do
  "${build_environment[@]}" /usr/bin/codesign -d \
    --arch "$architecture" --verbose=4 \
    "$TRACKED_ARTIFACT" 2>&1 |
    /usr/bin/awk '/^(CandidateCDHash sha256|Identifier=|Runtime Version=)/ { print }'
done
