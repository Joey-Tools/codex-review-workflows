from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import select
import shutil
import signal
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterable, Mapping, NoReturn, Sequence

from .claude_version_policy import (
    CLAUDE_GUARD_MANAGED_SESSION_MINIMUM_VERSION,
    ClaudeVersionPolicyError,
    parse_compatible_release_version,
)
from .common import (
    TRUSTED_PATH,
    ForwardedSignal,
    ForwardedSignalMaskOwner,
    ReviewError,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    _executable_candidate_identity,
    _is_process_control_flow_error,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    forwarded_signals,
    is_relative_to,
    resolve_git,
    restore_signal_mask,
    run_bounded_capture,
    strict_json_loads,
)
from .review_workspace import (
    WORKSPACE_SCHEMA_VERSION,
    PreparedWorkspace,
    RangeIncomplete,
    ReviewWorkspaceError,
    SourceAuthorityBindingError,
    _attach_workspace_teardown_failures,
    _attempt_workspace_descriptor_closes,
    _finish_forwarded_signal_mask,
    _partial_workspace_recovery_payload,
    _select_workspace_teardown_failure,
    build_source_authority_binding,
    canonical_source_authority_binding_bytes,
    cleanup_workspace,
    parse_canonical_source_authority_binding_bytes,
    prepare_workspace,
    recover_partial_workspace,
    retain_workspace_for_owner_exit_recovery,
    source_authority_common_marker_record,
    source_authority_control_record,
    source_authority_directory_record,
    source_authority_marker_record,
    validate_source_authority_binding,
    validate_workspace,
)

DEFAULT_TIMEOUT_SECONDS = 1_800.0
DEFAULT_STREAM_LIMIT_BYTES = 64 * 1024 * 1024
DEFAULT_PROMPT_LIMIT_BYTES = 256 * 1024
CLAUDE_PREFLIGHT_EVIDENCE_LIMIT_BYTES = 16 * 1024
CLAUDE_SOURCE_AUTHORITY_BINDING_LIMIT_BYTES = 32 * 1024
CLAUDE_BINARY_LIMIT_BYTES = 1024 * 1024 * 1024
CLAUDE_SESSION_ENV_IDENTITY_BINDING = "first-no-follow-open-after-exclusive-mkdir"
CLAUDE_SESSION_ENV_CREATION_ORIGIN_GUARANTEE = (
    "best-effort-122-bit-uuidv4-leaf-immediate-nofollow-open-"
    "cooperative-claude-control-directory-flock-same-uid-host-tcb"
)
CLAUDE_SESSION_ENV_NAMESPACE_EXCLUSIVITY_GUARANTEE = (
    "exclusive-advisory-claude-control-directory-flock-cooperative-same-uid-host-tcb"
)
CLAUDE_SESSION_ENV_CLEANUP_GUARANTEE = (
    "descriptor-custody-emptiness-revalidation-nonrecursive-rmdir-"
    "cooperative-claude-control-directory-flock-same-uid-host-tcb"
)
CLAUDE_SESSION_ENV_CLEANUP_OBSERVATION = "selected-name-absent-after-rmdir"
CLAUDE_DIRECT_ARGV_PROFILE = "named-direct-claude-argv-v3"
CLAUDE_DIRECT_ARGV_CONFORMANCE = "guard-constructed-exact-token-sequence"
CLAUDE_DIRECT_SETTINGS_SCHEMA = "named-direct-claude-settings-v1"
CLAUDE_DIRECT_ENVIRONMENT_PROFILE = "named-direct-claude-environment-v1"
CLAUDE_DIRECT_GIT_NULL_READ_EXCEPTION = pathlib.Path("/dev/null")
CLAUDE_DIRECT_READ_OVERLAP_EXCEPTIONS = frozenset(
    ((CLAUDE_DIRECT_GIT_NULL_READ_EXCEPTION, pathlib.Path("/dev")),)
)
CLAUDE_DIRECT_MODELS = ("claude-opus-4-8",)
CLAUDE_DIRECT_REQUIRED_OPTIONS = (
    "--print",
    "--input-format",
    "--model",
    "--effort",
    "--permission-mode",
    "--output-format",
    "--verbose",
    "--no-session-persistence",
    "--safe-mode",
    "--no-chrome",
    "--disable-slash-commands",
    "--strict-mcp-config",
    "--mcp-config",
    "--setting-sources",
    "--settings",
    "--tools",
    "--allowedTools",
    "--disallowedTools",
)
CLAUDE_DIRECT_EFFORT = "max"
CLAUDE_DIRECT_PERMISSION_MODE = "dontAsk"
CLAUDE_DIRECT_VISIBLE_TOOLS = "Read,Grep,Glob,Bash"
CLAUDE_DIRECT_ALLOWED_TOOLS = "Read(./**),Grep,Glob,Bash"
CLAUDE_DIRECT_DISALLOWED_TOOLS = "Edit,Write,NotebookEdit,WebFetch,WebSearch"
CLAUDE_DIRECT_PERMISSION_DENY_RULES = (
    "Edit",
    "Write",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
)
CLAUDE_DIRECT_PRIVATE_HOME_PATHS = (
    ".aws",
    ".claude",
    ".codex",
    ".config",
    ".copilot",
    ".gnupg",
    ".kube",
    ".ssh",
    ".git-credentials",
    ".netrc",
)
CLAUDE_DIRECT_SECRET_ENVIRONMENT_KEYS = (
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "ALL_PROXY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CURL_CA_BUNDLE",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GIT_SSL_CAINFO",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "NO_PROXY",
    "OPENAI_API_KEY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)
SANITIZED_GIT_ARGV_PREFIX_PROFILE = "sanitized-git-argv-prefix-v2"
SANITIZED_GIT_ARGV_PREFIX_CONFORMANCE = "exact-token-sequence"
SANITIZED_GIT_ARGV_PREFIX_ENCODING = "canonical-json-utf8-v1"
SANITIZED_GIT_ARGV_PREFIX_RECEIPT_SCHEMA_VERSION = (
    "sanitized-git-argv-prefix-receipt-v2"
)
SANITIZED_GIT_ARGV_PREFIX_RECEIPT_IDENTITY_ALGORITHM = (
    "sha256-canonical-json-utf8-v1-without-receipt-sha256"
)
SANITIZED_GIT_ARGV_PREFIX_RECEIPT_FILE_LIMIT_BYTES = 64 * 1024
_SANITIZED_GIT_VERSION_OUTPUT = re.compile(
    rb"git version ([0-9]+)\.([0-9]+)\.([0-9]+)"
    rb"(?: \(Apple Git-[0-9]+(?:\.[0-9]+)*\))?\n?\Z"
)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EXECUTABLE_IDENTITY_FIELDS = (
    "device",
    "inode",
    "file_type",
    "mode",
    "uid",
    "gid",
    "nlink",
    "size",
    "mtime_ns",
    "ctime_ns",
)
_WORKSPACE_VALIDATION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "command",
        "worktree",
        "base",
        "head",
        "object_format",
        "strategy",
        "source_shallow",
        "commit_count",
        "range_object_count",
        "range_object_sha256",
        "parent_support_object_count",
        "parent_support_object_sha256",
        "config_sha256",
        "shallow_bytes",
        "shallow_sha256",
        "symlink_count",
        "parent_identity",
        "workspace_identity",
        "git_identity",
        "objects_identity",
        "marker_sha256",
        "cleanup_token_sha256",
    }
)
_SANITIZED_GIT_ARGV_PREFIX_RECEIPT_FIELDS_WITHOUT_DIGEST = frozenset(
    {
        "schema_version",
        "status",
        "command",
        "prefix_profile",
        "sanitized_git_argv_prefix_conformance",
        "sanitized_git_argv_prefix",
        "sanitized_git_argv_prefix_encoding",
        "sanitized_git_argv_prefix_sha256",
        "git_executable",
        "git_executable_identity",
        "git_version",
        "git_version_stdout",
        "git_version_stdout_sha256",
        "worktree",
        "base",
        "head",
        "workspace_validation_receipt",
        "workspace_validation_receipt_encoding",
        "workspace_validation_receipt_sha256",
        "no_lazy_fetch_control",
        "receipt_identity_encoding",
        "receipt_identity_algorithm",
    }
)
GIT_OUTPUT_LIMIT_BYTES = 32 * 1024 * 1024
SYMLINK_TARGET_LIMIT_BYTES = 16 * 1024
SYMLINK_COUNT_LIMIT = 4_096
SYMLINK_BATCH_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024
SUBMODULE_ACTIVE_PATHSPEC_COUNT_LIMIT = 4_096
SUBMODULE_ACTIVE_PATHSPEC_ARGV_LIMIT_BYTES = 128 * 1024
MATERIALIZER_GIT_TIMEOUT_SECONDS = 120.0
MATERIALIZER_MINIMUM_GIT_VERSION = (2, 45, 0)
MATERIALIZER_BASE_REF = "refs/named-lane/base"
MATERIALIZER_HEAD_REF = "refs/named-lane/head"
MATERIALIZER_OBJECT_COUNT_LIMIT = 250_000
MATERIALIZER_PARENT_EDGE_COUNT_LIMIT = 250_000
MATERIALIZER_LOGICAL_OBJECT_BYTES_LIMIT = 2 * 1024 * 1024 * 1024
MATERIALIZER_CHECKOUT_ENTRY_COUNT_LIMIT = 100_000
MATERIALIZER_CHECKOUT_BLOB_BYTES_LIMIT = 2 * 1024 * 1024 * 1024
MATERIALIZER_CHECKOUT_PATH_BYTES_LIMIT = 64 * 1024 * 1024
MATERIALIZER_PACK_BYTES_LIMIT = 768 * 1024 * 1024
MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES = 1024 * 1024
FULL_OBJECT_ID = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
LOWER_FULL_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
LEGACY_SHORT_OBJECT_PREFIX = re.compile(r"[0-9a-f]{10}\Z")
LEGACY_PREFIX_RECEIPT_TIMEOUT_SECONDS = 120.0
LEGACY_PREFIX_RECEIPT_OUTPUT_LIMIT_BYTES = 1024
LEGACY_PREFIX_OBJECT_STORE_ENTRY_LIMIT = MATERIALIZER_OBJECT_COUNT_LIMIT
LEGACY_PREFIX_RECEIPT_SCHEMA_VERSION = "named-lane-legacy-short-prefix-receipts-v1"
CLAUDE_ENV_PASSTHROUGH_KEYS = (
    "ALL_PROXY",
    "COLORTERM",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TERM",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


class NamedLaneGuardError(ReviewError):
    """A named-lane safety or invocation precondition failed."""


def _validate_prefix_path(path: pathlib.Path, label: str) -> str:
    rendered = os.fspath(path)
    if not path.is_absolute():
        raise NamedLaneGuardError(f"{label} must be absolute")
    if any(character in rendered for character in ("\x00", "\n", "\r")):
        raise NamedLaneGuardError(f"{label} contains an unsupported control character")
    return rendered


def build_sanitized_git_argv_prefix(
    *,
    worktree: pathlib.Path,
    git_executable: pathlib.Path,
) -> tuple[str, ...]:
    """Build the exact local-Codex Git argv prefix profile."""

    rendered_worktree = _validate_prefix_path(worktree, "Codex review worktree")
    rendered_git = _validate_prefix_path(git_executable, "Codex review Git executable")
    rendered_ceiling = os.fspath(worktree.parent)
    if os.pathsep in rendered_ceiling:
        raise NamedLaneGuardError(
            "Codex review worktree parent cannot be encoded as a discovery ceiling"
        )
    return (
        "/usr/bin/env",
        "-i",
        f"PATH={TRUSTED_PATH}",
        "LANG=C",
        "LC_ALL=C",
        "GIT_ASKPASS=/usr/bin/false",
        "GIT_ATTR_NOSYSTEM=1",
        f"GIT_CEILING_DIRECTORIES={rendered_ceiling}",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_SYSTEM=/dev/null",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_GRAFT_FILE=/dev/null",
        "GIT_LITERAL_PATHSPECS=1",
        "GIT_NO_LAZY_FETCH=1",
        "GIT_TERMINAL_PROMPT=0",
        "GIT_NO_REPLACE_OBJECTS=1",
        "GIT_OPTIONAL_LOCKS=0",
        "PAGER=cat",
        "GIT_PAGER=cat",
        rendered_git,
        "--no-pager",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.checkStat=default",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.trustCtime=true",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "diff.external=",
        "-c",
        "color.ui=false",
        "-C",
        rendered_worktree,
    )


def validate_sanitized_git_argv_prefix(
    tokens: Sequence[str],
    *,
    worktree: pathlib.Path,
    git_executable: pathlib.Path,
) -> tuple[str, ...]:
    """Reject any token array that is not the exact selected v1 profile."""

    if isinstance(tokens, (str, bytes)):
        raise NamedLaneGuardError("sanitized Git argv prefix must be a token sequence")
    try:
        observed = tuple(tokens)
    except (TypeError, ValueError) as error:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix could not be read as a token sequence"
        ) from error
    if not all(type(token) is str for token in observed):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix contains a non-string token"
        )
    expected = build_sanitized_git_argv_prefix(
        worktree=worktree,
        git_executable=git_executable,
    )
    if observed != expected:
        raise NamedLaneGuardError(
            f"sanitized Git argv prefix does not conform to "
            f"{SANITIZED_GIT_ARGV_PREFIX_PROFILE}"
        )
    return observed


def _require_closed_mapping(
    value: object,
    expected_keys: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise NamedLaneGuardError(f"{label} must be an exact JSON object")
    if frozenset(value) != expected_keys:
        raise NamedLaneGuardError(f"{label} does not match its closed schema")
    return value


def _require_nonnegative_integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise NamedLaneGuardError(f"{label} must be a nonnegative JSON integer")
    return value


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise NamedLaneGuardError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _executable_identity_record(metadata: os.stat_result) -> dict[str, int]:
    return dict(
        zip(
            _EXECUTABLE_IDENTITY_FIELDS,
            _executable_candidate_identity(metadata),
            strict=True,
        )
    )


def _capture_prefix_git_executable_identity(
    git_executable: pathlib.Path,
) -> dict[str, object]:
    try:
        lexical = git_executable.lstat()
        resolved_path = git_executable.resolve(strict=True)
        target = git_executable.stat()
        resolved_target = resolved_path.stat()
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Codex review Git executable identity cannot be inspected"
        ) from error
    if (
        _executable_candidate_identity(target)
        != _executable_candidate_identity(resolved_target)
        or not stat.S_ISREG(target.st_mode)
        or not bool(target.st_mode & 0o111)
        or not os.access(git_executable, os.X_OK)
    ):
        raise NamedLaneGuardError(
            "Codex review Git executable identity is not a stable executable"
        )
    return {
        "lexical": _executable_identity_record(lexical),
        "resolved_path": str(resolved_path),
        "target": _executable_identity_record(target),
    }


def _validate_executable_identity_record(value: object) -> dict[str, object]:
    record = _require_closed_mapping(
        value,
        frozenset({"lexical", "resolved_path", "target"}),
        "Codex review Git executable identity",
    )
    resolved_path = record["resolved_path"]
    if (
        type(resolved_path) is not str
        or not pathlib.Path(resolved_path).is_absolute()
        or any(character in resolved_path for character in ("\x00", "\n", "\r"))
    ):
        raise NamedLaneGuardError(
            "Codex review Git resolved executable path is invalid"
        )
    for key in ("lexical", "target"):
        identity = _require_closed_mapping(
            record[key],
            frozenset(_EXECUTABLE_IDENTITY_FIELDS),
            f"Codex review Git executable {key} identity",
        )
        for field in _EXECUTABLE_IDENTITY_FIELDS:
            _require_nonnegative_integer(
                identity[field],
                f"Codex review Git executable {key}.{field}",
            )
        if identity["file_type"] != stat.S_IFMT(identity["mode"]):
            raise NamedLaneGuardError(
                f"Codex review Git executable {key} mode/type binding is invalid"
            )
    lexical = record["lexical"]
    target = record["target"]
    assert isinstance(lexical, dict)
    assert isinstance(target, dict)
    if lexical["file_type"] not in {stat.S_IFREG, stat.S_IFLNK}:
        raise NamedLaneGuardError("Codex review Git lexical executable type is invalid")
    if target["file_type"] != stat.S_IFREG or not bool(target["mode"] & 0o111):
        raise NamedLaneGuardError("Codex review Git target identity is not executable")
    return record


def _validate_workspace_validation_receipt(
    value: object,
    *,
    worktree: pathlib.Path,
    base: str,
    head: str,
) -> dict[str, object]:
    receipt = _require_closed_mapping(
        value,
        _WORKSPACE_VALIDATION_RECEIPT_FIELDS,
        "workspace validation receipt",
    )
    exact_values = {
        "schema_version": WORKSPACE_SCHEMA_VERSION,
        "status": "ok",
        "command": "validate-workspace",
        "worktree": str(worktree),
        "base": base,
        "head": head,
        "strategy": "exact-pack",
    }
    for key, expected in exact_values.items():
        if type(receipt[key]) is not type(expected) or receipt[key] != expected:
            raise NamedLaneGuardError(
                f"workspace validation receipt {key} does not match the frozen lane"
            )
    object_format = receipt["object_format"]
    if type(object_format) is not str or object_format not in {"sha1", "sha256"}:
        raise NamedLaneGuardError(
            "workspace validation receipt object_format is invalid"
        )
    expected_oid_length = 40 if object_format == "sha1" else 64
    if len(base) != expected_oid_length or len(head) != expected_oid_length:
        raise NamedLaneGuardError(
            "workspace validation receipt object format conflicts with its endpoints"
        )
    if type(receipt["source_shallow"]) is not bool:
        raise NamedLaneGuardError(
            "workspace validation receipt source_shallow must be a JSON boolean"
        )
    for key in (
        "commit_count",
        "range_object_count",
        "parent_support_object_count",
        "symlink_count",
    ):
        _require_nonnegative_integer(receipt[key], f"workspace receipt {key}")
    if receipt["commit_count"] == 0 or receipt["range_object_count"] == 0:
        raise NamedLaneGuardError(
            "workspace validation receipt cannot describe an empty frozen range closure"
        )
    for key in (
        "range_object_sha256",
        "parent_support_object_sha256",
        "config_sha256",
        "shallow_sha256",
        "marker_sha256",
        "cleanup_token_sha256",
    ):
        _require_sha256(receipt[key], f"workspace receipt {key}")
    if type(receipt["shallow_bytes"]) is not str:
        raise NamedLaneGuardError(
            "workspace validation receipt shallow_bytes must be a JSON string"
        )
    try:
        shallow_bytes = receipt["shallow_bytes"].encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise NamedLaneGuardError(
            "workspace validation receipt shallow_bytes must be ASCII"
        ) from error
    if receipt["shallow_sha256"] != hashlib.sha256(shallow_bytes).hexdigest():
        raise NamedLaneGuardError(
            "workspace validation receipt shallow digest is invalid"
        )
    for key in (
        "parent_identity",
        "workspace_identity",
        "git_identity",
        "objects_identity",
    ):
        identity = _require_closed_mapping(
            receipt[key],
            frozenset({"device", "inode", "uid"}),
            f"workspace receipt {key}",
        )
        for field in ("device", "inode", "uid"):
            _require_nonnegative_integer(
                identity[field], f"workspace receipt {key}.{field}"
            )
    return receipt


def _validated_prefix_git_version(
    git_executable: pathlib.Path,
    worktree: pathlib.Path,
    expected_identity: Mapping[str, object],
) -> tuple[str, str, str]:
    before = _capture_prefix_git_executable_identity(git_executable)
    if before != expected_identity:
        raise NamedLaneGuardError(
            "Codex review Git executable changed after workspace validation"
        )
    capture = None
    try:
        try:
            capture = run_bounded_capture(
                (str(git_executable), "--version"),
                cwd=worktree,
                env=_git_environment(),
                timeout_seconds=30.0,
                stdout_limit_bytes=1024,
                stderr_limit_bytes=1024,
            )
        except (
            ForwardedSignal,
            ReviewTimeoutError,
            ReviewOutputLimitError,
            ReviewOutputDrainError,
            ReviewProcessLeakError,
        ):
            raise
        except BaseException as error:
            if _is_process_control_flow_error(error):
                raise
            raise NamedLaneGuardError(
                "Codex review Git executable version could not be validated"
            ) from error
        stdout = bytes(capture.stdout)
        if capture.returncode != 0 or capture.stderr:
            raise NamedLaneGuardError(
                "Codex review Git executable version could not be validated"
            )
        match = _SANITIZED_GIT_VERSION_OUTPUT.fullmatch(stdout)
        if match is None:
            raise NamedLaneGuardError(
                "Codex review Git executable returned a malformed version"
            )
        version = tuple(int(component) for component in match.groups())
        if version < MATERIALIZER_MINIMUM_GIT_VERSION:
            raise NamedLaneGuardError(
                "Codex review workspace requires Git 2.45.0 or newer"
            )
        try:
            exact_stdout = stdout.decode("ascii")
        except UnicodeDecodeError as error:
            raise NamedLaneGuardError(
                "Codex review Git executable returned a non-ASCII version"
            ) from error
        normalized = exact_stdout.removesuffix("\n")
        stdout_sha256 = hashlib.sha256(stdout).hexdigest()
    finally:
        if capture is not None:
            capture.stdout[:] = b"\x00" * len(capture.stdout)
            capture.stderr[:] = b"\x00" * len(capture.stderr)
    after = _capture_prefix_git_executable_identity(git_executable)
    if after != before:
        raise NamedLaneGuardError(
            "Codex review Git executable changed during version validation"
        )
    return normalized, exact_stdout, stdout_sha256


def validate_sanitized_git_argv_prefix_receipt(
    value: object,
    *,
    worktree: pathlib.Path,
    base: str,
    head: str,
    git_executable: pathlib.Path,
) -> dict[str, object]:
    """Validate the closed composite prefix receipt without trusting prose."""

    rendered_worktree = _validate_prefix_path(worktree, "Codex review worktree")
    rendered_git = _validate_prefix_path(git_executable, "Codex review Git executable")
    if (
        LOWER_FULL_OBJECT_ID.fullmatch(base) is None
        or LOWER_FULL_OBJECT_ID.fullmatch(head) is None
    ):
        raise NamedLaneGuardError(
            "Codex review Git prefix endpoints must be full lowercase object IDs"
        )
    receipt = _require_closed_mapping(
        value,
        _SANITIZED_GIT_ARGV_PREFIX_RECEIPT_FIELDS_WITHOUT_DIGEST | {"receipt_sha256"},
        "sanitized Git argv prefix receipt",
    )
    exact_values = {
        "schema_version": SANITIZED_GIT_ARGV_PREFIX_RECEIPT_SCHEMA_VERSION,
        "status": "complete",
        "command": "codex-git-prefix",
        "prefix_profile": SANITIZED_GIT_ARGV_PREFIX_PROFILE,
        "sanitized_git_argv_prefix_conformance": (
            SANITIZED_GIT_ARGV_PREFIX_CONFORMANCE
        ),
        "sanitized_git_argv_prefix_encoding": SANITIZED_GIT_ARGV_PREFIX_ENCODING,
        "git_executable": rendered_git,
        "worktree": rendered_worktree,
        "base": base,
        "head": head,
        "workspace_validation_receipt_encoding": (SANITIZED_GIT_ARGV_PREFIX_ENCODING),
        "no_lazy_fetch_control": "GIT_NO_LAZY_FETCH=1",
        "receipt_identity_encoding": SANITIZED_GIT_ARGV_PREFIX_ENCODING,
        "receipt_identity_algorithm": (
            SANITIZED_GIT_ARGV_PREFIX_RECEIPT_IDENTITY_ALGORITHM
        ),
    }
    for key, expected in exact_values.items():
        if type(receipt[key]) is not type(expected) or receipt[key] != expected:
            raise NamedLaneGuardError(
                f"sanitized Git argv prefix receipt {key} is invalid"
            )
    tokens = receipt["sanitized_git_argv_prefix"]
    if type(tokens) is not list:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt tokens must be a JSON array"
        )
    validated_tokens = validate_sanitized_git_argv_prefix(
        tokens,
        worktree=worktree,
        git_executable=git_executable,
    )
    token_sha256 = hashlib.sha256(
        _canonical_json_bytes(list(validated_tokens))
    ).hexdigest()
    if receipt["sanitized_git_argv_prefix_sha256"] != token_sha256:
        raise NamedLaneGuardError("sanitized Git argv prefix digest is invalid")
    _validate_executable_identity_record(receipt["git_executable_identity"])
    git_version = receipt["git_version"]
    git_version_stdout = receipt["git_version_stdout"]
    if type(git_version) is not str or type(git_version_stdout) is not str:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix Git version fields must be JSON strings"
        )
    try:
        version_stdout_bytes = git_version_stdout.encode("ascii")
    except UnicodeEncodeError as error:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix Git version output must be ASCII"
        ) from error
    match = _SANITIZED_GIT_VERSION_OUTPUT.fullmatch(version_stdout_bytes)
    if (
        match is None
        or git_version != git_version_stdout.removesuffix("\n")
        or tuple(int(component) for component in match.groups())
        < MATERIALIZER_MINIMUM_GIT_VERSION
    ):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix Git version binding is invalid"
        )
    if (
        receipt["git_version_stdout_sha256"]
        != hashlib.sha256(version_stdout_bytes).hexdigest()
    ):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix Git version digest is invalid"
        )
    workspace_receipt = _validate_workspace_validation_receipt(
        receipt["workspace_validation_receipt"],
        worktree=worktree,
        base=base,
        head=head,
    )
    if (
        receipt["workspace_validation_receipt_sha256"]
        != hashlib.sha256(_canonical_json_bytes(workspace_receipt)).hexdigest()
    ):
        raise NamedLaneGuardError("workspace validation receipt digest is invalid")
    _require_sha256(
        receipt["receipt_sha256"], "sanitized Git argv prefix receipt identity"
    )
    receipt_without_digest = {
        key: receipt[key]
        for key in _SANITIZED_GIT_ARGV_PREFIX_RECEIPT_FIELDS_WITHOUT_DIGEST
    }
    if (
        receipt["receipt_sha256"]
        != hashlib.sha256(_canonical_json_bytes(receipt_without_digest)).hexdigest()
    ):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt identity is invalid"
        )
    selected_git = resolve_git()
    if selected_git != git_executable:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt Git path is no longer selected"
        )
    current_git_identity = _capture_prefix_git_executable_identity(selected_git)
    if receipt["git_executable_identity"] != current_git_identity:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt Git executable identity is stale"
        )
    current_version, current_stdout, current_stdout_sha256 = (
        _validated_prefix_git_version(
            selected_git,
            selected_git.parent,
            current_git_identity,
        )
    )
    if (
        receipt["git_version"] != current_version
        or receipt["git_version_stdout"] != current_stdout
        or receipt["git_version_stdout_sha256"] != current_stdout_sha256
    ):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt Git version evidence is stale"
        )
    current_workspace_receipt = _validate_workspace_validation_receipt(
        validate_workspace(worktree, base, head).receipt(),
        worktree=worktree,
        base=base,
        head=head,
    )
    if current_workspace_receipt != workspace_receipt:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix workspace validation receipt is stale"
        )
    if (
        resolve_git() != selected_git
        or _capture_prefix_git_executable_identity(selected_git) != current_git_identity
    ):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix Git executable changed during receipt validation"
        )
    return receipt


def _revalidate_prefix_receipt_publication_identities(
    receipt: Mapping[str, object],
    *,
    worktree: pathlib.Path,
    git_executable: pathlib.Path,
) -> None:
    if (
        resolve_git() != git_executable
        or _capture_prefix_git_executable_identity(git_executable)
        != receipt["git_executable_identity"]
    ):
        raise NamedLaneGuardError(
            "Codex review Git executable changed before prefix receipt publication"
        )
    workspace_receipt = receipt["workspace_validation_receipt"]
    assert isinstance(workspace_receipt, dict)
    try:
        parent = worktree.parent.lstat()
        root = worktree.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            "Codex review workspace changed before prefix receipt publication"
        ) from error
    expected_parent = workspace_receipt["parent_identity"]
    expected_root = workspace_receipt["workspace_identity"]
    assert isinstance(expected_parent, dict)
    assert isinstance(expected_root, dict)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(root.st_mode)
        or stat.S_ISLNK(root.st_mode)
        or (parent.st_dev, parent.st_ino, parent.st_uid)
        != (
            expected_parent["device"],
            expected_parent["inode"],
            expected_parent["uid"],
        )
        or (root.st_dev, root.st_ino, root.st_uid)
        != (
            expected_root["device"],
            expected_root["inode"],
            expected_root["uid"],
        )
    ):
        raise NamedLaneGuardError(
            "Codex review workspace identity changed before prefix receipt publication"
        )


def _prefix_receipt_parent_object_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _prefix_receipt_parent_access_policy(
    metadata: os.stat_result,
) -> tuple[int, int]:
    return metadata.st_uid, stat.S_IMODE(metadata.st_mode)


def _prefix_receipt_object_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _prefix_receipt_access_policy(
    metadata: os.stat_result,
) -> tuple[int, int, int, int]:
    return (
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
    )


def _prefix_receipt_content_signals(
    metadata: os.stat_result,
) -> tuple[int, int, int]:
    return metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _read_prefix_receipt_descriptor(descriptor: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt cannot be rewound"
        ) from error
    payload = bytearray()
    try:
        while len(payload) <= SANITIZED_GIT_ARGV_PREFIX_RECEIPT_FILE_LIMIT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    SANITIZED_GIT_ARGV_PREFIX_RECEIPT_FILE_LIMIT_BYTES
                    + 1
                    - len(payload),
                ),
            )
            if not chunk:
                break
            payload.extend(chunk)
    except OSError as error:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt cannot be read"
        ) from error
    if not payload or len(payload) > SANITIZED_GIT_ARGV_PREFIX_RECEIPT_FILE_LIMIT_BYTES:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt exceeded its byte limit"
        )
    return bytes(payload)


def _require_prefix_receipt_parent_policy(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt parent must be an owner-private directory"
        )


def _require_prefix_receipt_file_policy(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or bool(stat.S_IMODE(metadata.st_mode) & 0o022)
        or metadata.st_size <= 0
        or metadata.st_size > SANITIZED_GIT_ARGV_PREFIX_RECEIPT_FILE_LIMIT_BYTES
    ):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt must be a bounded owner-controlled single-link regular file"
        )


def _require_prefix_receipt_owner_private_acl(
    descriptor: int,
    *,
    label: str,
) -> None:
    """Reject non-owner Darwin ACL grants through a bound descriptor.

    UID, mode, and link count do not completely describe access policy on
    macOS.  The protected property is owner-private access: a deny entry may
    further restrict access, and an allow entry for the exact object owner is
    redundant, but an allow entry for any other or unrecognized principal
    grants access outside that property.  Linux and other POSIX platforms
    retain their existing mode-based semantics because their Darwin ACL
    inventory is empty.
    """

    if sys.platform != "darwin":
        return
    try:
        entries = _legacy_extended_acl_entries(
            descriptor,
            label=f"sanitized Git argv prefix receipt {label}",
        )
    except NamedLaneGuardError as error:
        raise NamedLaneGuardError(
            f"sanitized Git argv prefix receipt {label} extended ACL cannot be inspected"
        ) from error
    allow_qualifiers = _darwin_acl_allow_qualifiers(entries)
    if allow_qualifiers is None:
        raise NamedLaneGuardError(
            f"sanitized Git argv prefix receipt {label} has a non-owner extended ACL grant"
        )
    if not allow_qualifiers:
        return
    try:
        owner_uid = os.fstat(descriptor).st_uid
        owner_qualifier = _darwin_uid_acl_qualifier(
            owner_uid,
            label=f"sanitized Git argv prefix receipt {label} owner",
        )
        if len(owner_qualifier) != _DARWIN_ACL_QUALIFIER_BYTES:
            raise NamedLaneGuardError(
                f"sanitized Git argv prefix receipt {label} owner qualifier is malformed"
            )
    except (NamedLaneGuardError, OSError) as error:
        raise NamedLaneGuardError(
            f"sanitized Git argv prefix receipt {label} extended ACL cannot be inspected"
        ) from error
    if not _darwin_acl_entries_preserve_owner_private_access(
        entries,
        owner_qualifier=owner_qualifier,
    ):
        raise NamedLaneGuardError(
            f"sanitized Git argv prefix receipt {label} has a non-owner extended ACL grant"
        )


def _revalidate_open_prefix_receipt(
    *,
    receipt_path: pathlib.Path,
    parent_descriptor: int,
    receipt_descriptor: int,
    parent_identity: tuple[int, int, int],
    parent_policy: tuple[int, int],
    receipt_identity: tuple[int, int, int],
    receipt_policy: tuple[int, int, int, int],
    initial_signals: tuple[int, int, int],
    expected_payload: bytes,
) -> None:
    try:
        parent_descriptor_metadata = os.fstat(parent_descriptor)
        parent_path_metadata = receipt_path.parent.lstat()
        resolved_parent = receipt_path.parent.resolve(strict=True)
        receipt_descriptor_metadata = os.fstat(receipt_descriptor)
        receipt_path_metadata = os.stat(
            receipt_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt custody cannot be revalidated"
        ) from error
    for metadata in (parent_descriptor_metadata, parent_path_metadata):
        try:
            _require_prefix_receipt_parent_policy(metadata)
        except NamedLaneGuardError as error:
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt parent identity or access policy changed"
            ) from error
        if (
            _prefix_receipt_parent_object_identity(metadata) != parent_identity
            or _prefix_receipt_parent_access_policy(metadata) != parent_policy
        ):
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt parent identity or access policy changed"
            )
    if resolved_parent != receipt_path.parent:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt parent path changed"
        )
    _require_prefix_receipt_owner_private_acl(
        parent_descriptor,
        label="parent",
    )
    for metadata in (receipt_descriptor_metadata, receipt_path_metadata):
        try:
            _require_prefix_receipt_file_policy(metadata)
        except NamedLaneGuardError as error:
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt identity or access policy changed"
            ) from error
        if (
            _prefix_receipt_object_identity(metadata) != receipt_identity
            or _prefix_receipt_access_policy(metadata) != receipt_policy
        ):
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt identity or access policy changed"
            )
    _require_prefix_receipt_owner_private_acl(
        receipt_descriptor,
        label="file",
    )
    final_signals = _prefix_receipt_content_signals(receipt_descriptor_metadata)
    if (
        final_signals != initial_signals
        or _prefix_receipt_content_signals(receipt_path_metadata) != initial_signals
    ):
        # Metadata churn is only a re-read trigger. Exact bytes select whether
        # the protected content-stability property actually changed.
        if _read_prefix_receipt_descriptor(receipt_descriptor) != expected_payload:
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt content changed during validation"
            )
    elif _read_prefix_receipt_descriptor(receipt_descriptor) != expected_payload:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt content changed during validation"
        )


def validate_published_sanitized_git_argv_prefix_receipt(
    *,
    receipt_file: pathlib.Path,
    expected_receipt_sha256: str,
    worktree: pathlib.Path,
    base: str,
    head: str,
    git_executable: pathlib.Path,
) -> dict[str, object]:
    """Consume one published prefix receipt while retaining descriptor custody."""

    _validate_prefix_path(receipt_file, "sanitized Git argv prefix receipt file")
    _require_sha256(
        expected_receipt_sha256,
        "expected sanitized Git argv prefix receipt identity",
    )
    if is_relative_to(receipt_file, worktree):
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt file must stay outside the worktree"
        )
    if receipt_file.name in {"", ".", ".."}:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt file has no ordinary leaf name"
        )
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or directory_only is None or nonblocking is None:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt validation requires no-follow opens"
        )
    try:
        parent_before = receipt_file.parent.lstat()
        resolved_parent = receipt_file.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt parent cannot be inspected"
        ) from error
    _require_prefix_receipt_parent_policy(parent_before)
    if resolved_parent != receipt_file.parent:
        raise NamedLaneGuardError(
            "sanitized Git argv prefix receipt parent path traverses a symlink"
        )
    parent_identity = _prefix_receipt_parent_object_identity(parent_before)
    parent_policy = _prefix_receipt_parent_access_policy(parent_before)

    parent_descriptor: int | None = None
    receipt_descriptor: int | None = None
    result: dict[str, object] | None = None
    operation_error: BaseException | None = None
    try:
        parent_descriptor = os.open(
            receipt_file.parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | directory_only | nofollow,
        )
        parent_opened = os.fstat(parent_descriptor)
        _require_prefix_receipt_parent_policy(parent_opened)
        if (
            _prefix_receipt_parent_object_identity(parent_opened) != parent_identity
            or _prefix_receipt_parent_access_policy(parent_opened) != parent_policy
        ):
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt parent changed before opening"
            )
        _require_prefix_receipt_owner_private_acl(
            parent_descriptor,
            label="parent",
        )
        lexical = os.stat(
            receipt_file.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _require_prefix_receipt_file_policy(lexical)
        receipt_descriptor = os.open(
            receipt_file.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | nonblocking,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(receipt_descriptor)
        _require_prefix_receipt_file_policy(opened)
        receipt_identity = _prefix_receipt_object_identity(opened)
        receipt_policy = _prefix_receipt_access_policy(opened)
        initial_signals = _prefix_receipt_content_signals(opened)
        if (
            _prefix_receipt_object_identity(lexical) != receipt_identity
            or _prefix_receipt_access_policy(lexical) != receipt_policy
            or _prefix_receipt_content_signals(lexical) != initial_signals
        ):
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt changed before reading"
            )
        _require_prefix_receipt_owner_private_acl(
            receipt_descriptor,
            label="file",
        )
        payload = _read_prefix_receipt_descriptor(receipt_descriptor)
        if len(payload) != opened.st_size:
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt changed while reading"
            )
        try:
            receipt = strict_json_loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt is not strict UTF-8 JSON"
            ) from error
        if (
            type(receipt) is not dict
            or receipt.get("receipt_sha256") != expected_receipt_sha256
        ):
            raise NamedLaneGuardError(
                "sanitized Git argv prefix receipt does not match the retained expected identity"
            )
        validated = validate_sanitized_git_argv_prefix_receipt(
            receipt,
            worktree=worktree,
            base=base,
            head=head,
            git_executable=git_executable,
        )
        _revalidate_open_prefix_receipt(
            receipt_path=receipt_file,
            parent_descriptor=parent_descriptor,
            receipt_descriptor=receipt_descriptor,
            parent_identity=parent_identity,
            parent_policy=parent_policy,
            receipt_identity=receipt_identity,
            receipt_policy=receipt_policy,
            initial_signals=initial_signals,
            expected_payload=payload,
        )
        _revalidate_prefix_receipt_publication_identities(
            validated,
            worktree=worktree,
            git_executable=git_executable,
        )
        _revalidate_open_prefix_receipt(
            receipt_path=receipt_file,
            parent_descriptor=parent_descriptor,
            receipt_descriptor=receipt_descriptor,
            parent_identity=parent_identity,
            parent_policy=parent_policy,
            receipt_identity=receipt_identity,
            receipt_policy=receipt_policy,
            initial_signals=initial_signals,
            expected_payload=payload,
        )
        result = validated
    except BaseException as error:
        if isinstance(error, OSError):
            operation_error = NamedLaneGuardError(
                "sanitized Git argv prefix receipt cannot be opened safely"
            )
            operation_error.__cause__ = error
            operation_error.__suppress_context__ = True
        else:
            operation_error = error
    receipt_to_close = receipt_descriptor if receipt_descriptor is not None else -1
    parent_to_close = parent_descriptor if parent_descriptor is not None else -1
    receipt_descriptor = None
    parent_descriptor = None
    close_failures = _attempt_workspace_descriptor_closes(
        (
            (
                "sanitized Git argv prefix receipt descriptor close failed",
                receipt_to_close,
            ),
            (
                "sanitized Git argv prefix receipt parent descriptor close failed",
                parent_to_close,
            ),
        )
    )
    selected_error = operation_error
    if selected_error is not None:
        _attach_workspace_teardown_failures(selected_error, close_failures)
    else:
        selected_error = _select_workspace_teardown_failure(close_failures)
    if selected_error is not None:
        raise selected_error
    assert result is not None
    return result


def sanitized_git_argv_prefix_receipt(
    *,
    worktree: pathlib.Path,
    base: str,
    head: str,
    git_executable: pathlib.Path,
) -> dict[str, object]:
    """Revalidate a frozen workspace and return its composite prefix record."""

    _validate_prefix_path(worktree, "Codex review worktree")
    rendered_git = _validate_prefix_path(git_executable, "Codex review Git executable")
    if (
        LOWER_FULL_OBJECT_ID.fullmatch(base) is None
        or LOWER_FULL_OBJECT_ID.fullmatch(head) is None
    ):
        raise NamedLaneGuardError(
            "Codex review Git prefix endpoints must be full lowercase object IDs"
        )
    selected_git = resolve_git()
    if str(selected_git) != rendered_git:
        raise NamedLaneGuardError(
            "Codex review Git executable differs from the fixed trusted Git path"
        )
    git_identity = _capture_prefix_git_executable_identity(selected_git)
    git_version, git_version_stdout, git_version_stdout_sha256 = (
        _validated_prefix_git_version(
            selected_git,
            selected_git.parent,
            git_identity,
        )
    )
    validated = validate_workspace(worktree, base, head)
    canonical_worktree = validated.root
    workspace_receipt = _validate_workspace_validation_receipt(
        validated.receipt(),
        worktree=canonical_worktree,
        base=base,
        head=head,
    )
    if resolve_git() != selected_git:
        raise NamedLaneGuardError(
            "fixed trusted Git path changed during workspace validation"
        )
    if _capture_prefix_git_executable_identity(selected_git) != git_identity:
        raise NamedLaneGuardError(
            "Codex review Git executable changed during workspace validation"
        )
    tokens = validate_sanitized_git_argv_prefix(
        build_sanitized_git_argv_prefix(
            worktree=canonical_worktree,
            git_executable=selected_git,
        ),
        worktree=canonical_worktree,
        git_executable=selected_git,
    )
    encoded = _canonical_json_bytes(list(tokens))
    receipt: dict[str, object] = {
        "schema_version": SANITIZED_GIT_ARGV_PREFIX_RECEIPT_SCHEMA_VERSION,
        "status": "complete",
        "command": "codex-git-prefix",
        "prefix_profile": SANITIZED_GIT_ARGV_PREFIX_PROFILE,
        "sanitized_git_argv_prefix_conformance": (
            SANITIZED_GIT_ARGV_PREFIX_CONFORMANCE
        ),
        "sanitized_git_argv_prefix": list(tokens),
        "sanitized_git_argv_prefix_encoding": SANITIZED_GIT_ARGV_PREFIX_ENCODING,
        "sanitized_git_argv_prefix_sha256": hashlib.sha256(encoded).hexdigest(),
        "git_executable": str(selected_git),
        "git_executable_identity": git_identity,
        "git_version": git_version,
        "git_version_stdout": git_version_stdout,
        "git_version_stdout_sha256": git_version_stdout_sha256,
        "worktree": str(canonical_worktree),
        "base": base,
        "head": head,
        "workspace_validation_receipt": workspace_receipt,
        "workspace_validation_receipt_encoding": (SANITIZED_GIT_ARGV_PREFIX_ENCODING),
        "workspace_validation_receipt_sha256": hashlib.sha256(
            _canonical_json_bytes(workspace_receipt)
        ).hexdigest(),
        "no_lazy_fetch_control": "GIT_NO_LAZY_FETCH=1",
        "receipt_identity_encoding": SANITIZED_GIT_ARGV_PREFIX_ENCODING,
        "receipt_identity_algorithm": (
            SANITIZED_GIT_ARGV_PREFIX_RECEIPT_IDENTITY_ALGORITHM
        ),
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        _canonical_json_bytes(receipt)
    ).hexdigest()
    return validate_sanitized_git_argv_prefix_receipt(
        receipt,
        worktree=canonical_worktree,
        base=base,
        head=head,
        git_executable=selected_git,
    )


@dataclass(frozen=True)
class _SignalMaskRestoreOutcome:
    """Result of bounded terminal signal-mask restoration."""

    restored: bool
    failure_types: tuple[str, ...]
    direct_exact_mask_fallback: str


class _WorkspacePublicationRollbackError(ReviewWorkspaceError):
    """An unpublished workspace could not be removed after receipt failure."""

    def __init__(
        self,
        prepared: PreparedWorkspace,
        primary_error: BaseException,
        cleanup_error: BaseException,
        recovery_payload: Mapping[str, object],
    ) -> None:
        expected_parent = {
            "device": prepared.parent_identity[0],
            "inode": prepared.parent_identity[1],
            "uid": prepared.parent_identity[2],
        }
        expected_workspace = {
            "device": prepared.workspace_identity[0],
            "inode": prepared.workspace_identity[1],
            "uid": prepared.workspace_identity[2],
        }
        details: dict[str, object] = {
            "primary_reason": _workspace_publication_failure_reason(primary_error),
            "cleanup_reason": _workspace_publication_failure_reason(cleanup_error),
            "cleanup_token_sha256": prepared.cleanup_token_sha256,
            "parent_identity": expected_parent,
            "workspace_identity": expected_workspace,
            **dict(recovery_payload),
        }
        retained_path = _prepared_workspace_retained_path(
            prepared,
            cleanup_error,
        )
        if retained_path is not None:
            details["retained_path"] = retained_path
        else:
            details["expected_locator"] = {
                "parent": str(prepared.root.parent),
                "parent_identity": expected_parent,
                "leaf": prepared.root.name,
                "workspace_identity": expected_workspace,
            }
        super().__init__(
            "workspace-publication-rollback-incomplete",
            "workspace receipt publication failed and identity-bound cleanup did "
            "not complete",
            details=details,
        )


class _ControlObjectGuardError(NamedLaneGuardError):
    """A materialized control object failed with a stable machine reason."""

    _REASONS = frozenset(
        {
            "materialized-git-config-missing",
            "materialized-git-config-inspection-failure",
            "materialized-git-config-object-identity-mismatch",
            "materialized-git-config-content-mismatch",
            "materialized-git-config-access-policy-mismatch",
            "materialized-git-info-missing",
            "materialized-git-info-inspection-failure",
            "materialized-git-info-object-identity-mismatch",
            "materialized-git-info-content-mismatch",
            "materialized-git-info-access-policy-mismatch",
        }
    )

    def __init__(self, reason: str, message: str) -> None:
        if reason not in self._REASONS:
            raise ValueError("unknown materialized control-object reason")
        self.reason = reason
        super().__init__(message)


class LegacyPrefixReceiptInconclusive(ReviewError):
    """A legacy prefix was deterministically ineligible for a success receipt."""

    def __init__(self, reason: str) -> None:
        if reason not in {
            "legacy-prefix-is-current-head",
            "legacy-prefix-not-unique",
            "legacy-prefix-not-commit",
            "legacy-prefix-not-ancestor",
        }:
            raise ValueError("unknown legacy prefix receipt reason")
        self.reason = reason
        super().__init__(reason)


class _ClaudeLaunchSnapshotCleanupError(NamedLaneGuardError):
    """A launch snapshot remains after bounded process supervision."""

    def __init__(
        self,
        retained_path: pathlib.Path | None,
        process_reason: str,
        *,
        retained_parent_identity: tuple[int, int] | None = None,
        retained_leaf: str | None = None,
    ) -> None:
        if retained_path is None and (
            retained_parent_identity is None or retained_leaf is None
        ):
            raise ValueError(
                "descriptor-bound snapshot cleanup evidence requires parent "
                "identity and leaf"
            )
        self.retained_path = retained_path
        self.process_reason = process_reason
        self.retained_parent_identity = retained_parent_identity
        self.retained_leaf = retained_leaf
        detail = f"retained path: {retained_path}"
        if retained_path is None:
            assert retained_parent_identity is not None
            assert retained_leaf is not None
            detail = (
                "descriptor-bound retained locator: "
                f"parent device={retained_parent_identity[0]}, "
                f"inode={retained_parent_identity[1]}, leaf={retained_leaf}"
            )
        super().__init__(
            f"Claude launch snapshot cleanup failed after {process_reason}; {detail}"
        )


class _ClaudeSessionEnvCleanupError(NamedLaneGuardError):
    """A guard-bound Claude session environment directory remains."""

    def __init__(
        self,
        retained_path: pathlib.Path | None,
        process_reason: str,
        *,
        retained_parent_identity: tuple[int, int] | None = None,
        retained_leaf: str | None = None,
        retained_leaf_identity: tuple[int, int] | None = None,
        retained_for_quiescence: bool = False,
    ) -> None:
        if retained_path is None and (
            retained_parent_identity is None or retained_leaf is None
        ):
            raise ValueError(
                "descriptor-bound session environment cleanup evidence requires "
                "parent identity and leaf"
            )
        if retained_for_quiescence and (
            retained_parent_identity is None
            or retained_leaf is None
            or retained_leaf_identity is None
        ):
            raise ValueError(
                "unquiescent session environment evidence requires parent and "
                "leaf identities"
            )
        self.retained_path = retained_path
        self.process_reason = process_reason
        self.retained_parent_identity = retained_parent_identity
        self.retained_leaf = retained_leaf
        self.retained_leaf_identity = retained_leaf_identity
        self.retained_for_quiescence = retained_for_quiescence
        detail = f"retained path: {retained_path}"
        if retained_path is None:
            assert retained_parent_identity is not None
            assert retained_leaf is not None
            detail = (
                "descriptor-bound retained locator: "
                f"parent device={retained_parent_identity[0]}, "
                f"inode={retained_parent_identity[1]}, leaf={retained_leaf}"
            )
            if retained_leaf_identity is not None:
                detail += (
                    f", leaf device={retained_leaf_identity[0]}, "
                    f"inode={retained_leaf_identity[1]}"
                )
        failure = "cleanup failed"
        if retained_for_quiescence:
            failure = "was retained because process quiescence was not proven"
        super().__init__(
            f"Claude session environment {failure} after {process_reason}; {detail}"
        )


class _ClaudeSessionEnvCustodyError(NamedLaneGuardError):
    """The guard removed its leaf but the canonical parent binding drifted."""

    def __init__(
        self,
        session_id: str,
        process_reason: str,
        *,
        parent_identity: tuple[int, int],
        leaf_identity: tuple[int, int],
    ) -> None:
        self.session_id = session_id
        self.process_reason = process_reason
        self.parent_identity = parent_identity
        self.leaf_identity = leaf_identity
        self.cleanup_status = "removed"
        super().__init__(
            "Claude session environment canonical parent custody changed after "
            f"{process_reason}; guard leaf was removed"
        )


class _ClaudeControlCleanupError(NamedLaneGuardError):
    """Both guard-owned Claude control lifecycles failed after supervision."""

    def __init__(
        self,
        snapshot: _ClaudeLaunchSnapshotCleanupError,
        session_env: (_ClaudeSessionEnvCleanupError | _ClaudeSessionEnvCustodyError),
    ) -> None:
        self.snapshot = snapshot
        self.session_env = session_env
        super().__init__(
            "Claude launch snapshot and session environment lifecycles both failed"
        )


def _checkout_tree_output_limit(oid_length: int) -> int:
    return MATERIALIZER_CHECKOUT_PATH_BYTES_LIMIT + (
        MATERIALIZER_CHECKOUT_ENTRY_COUNT_LIMIT * (oid_length + 16)
    )


def _parent_graph_output_limit(commit_count: int, oid_length: int) -> int:
    if commit_count <= 0:
        raise NamedLaneGuardError("frozen commit count must be positive")
    if oid_length not in (40, 64):
        raise NamedLaneGuardError("frozen object ID width is unsupported")
    return (commit_count + MATERIALIZER_PARENT_EDGE_COUNT_LIMIT) * (oid_length + 1)


@dataclass(frozen=True)
class _ParentGraphCounts:
    commit_count: int
    parent_edge_count: int
    parent_graph_sha256: str


@dataclass(frozen=True)
class WorktreeValidation:
    root: pathlib.Path
    base_sha: str
    head_sha: str
    commit_count: int
    parent_edge_count: int
    parent_graph_sha256: str
    local_config_sha256: str
    symlink_count: int
    guidance_count: int


@dataclass(frozen=True)
class MaterializedWorktree:
    root: pathlib.Path
    base_sha: str
    head_sha: str
    commit_count: int
    parent_edge_count: int
    parent_graph_sha256: str
    local_config_sha256: str
    _parent: pathlib.Path
    _parent_identity: _DirectoryIdentity
    _root_identity: _DirectoryIdentity
    _handoff_signal_mask: set[signal.Signals] | None = None


@dataclass(frozen=True)
class _DirectoryIdentity:
    device: int
    inode: int
    owner: int


@dataclass(frozen=True)
class _LocalConfigBinding:
    device: int
    inode: int
    file_type: int
    owner: int
    group: int
    mode: int
    link_count: int
    size: int
    sha256: str


@dataclass(frozen=True)
class _GitInfoBinding:
    device: int
    inode: int
    file_type: int
    owner: int
    mode: int


@dataclass(frozen=True)
class _MaterializerSourceMarkerBinding:
    path: pathlib.Path
    expected_admin: pathlib.Path
    device: int
    inode: int
    file_type: int
    owner: int
    is_gitfile: bool


@dataclass(frozen=True)
class _MaterializerSourceStorage:
    marker: _MaterializerSourceMarkerBinding
    admin: pathlib.Path
    admin_identity: _DirectoryIdentity
    common: pathlib.Path
    common_identity: _DirectoryIdentity
    objects: pathlib.Path
    objects_identity: _DirectoryIdentity
    object_format: str


@dataclass(frozen=True)
class _LegacySourcePolicyBinding:
    path: pathlib.Path
    device: int
    inode: int
    file_type: int
    owner: int
    mode: int
    allowed_owners: tuple[int, ...]
    allow_deny_acl: bool


@dataclass(frozen=True)
class _LegacySourceContentBinding:
    path: pathlib.Path
    label: str
    size: int
    sha256: str


@dataclass(frozen=True)
class _LegacyPrefixSourceBinding:
    storage: _MaterializerSourceStorage
    policy_bindings: tuple[_LegacySourcePolicyBinding, ...]
    content_bindings: tuple[_LegacySourceContentBinding, ...]
    commondir_present: bool
    deadline_monotonic: float


@dataclass(frozen=True)
class _LegacyPrefixViewBinding:
    root: pathlib.Path
    root_identity: _DirectoryIdentity
    objects_identity: _DirectoryIdentity
    refs_identity: _DirectoryIdentity
    config_identity: tuple[int, int, int, int]
    head_identity: tuple[int, int, int, int]
    config_bytes: bytes
    head_bytes: bytes
    deadline_monotonic: float


@dataclass(frozen=True)
class _LegacyPrefixControlBinding:
    root: pathlib.Path
    root_identity: _DirectoryIdentity
    children: tuple[tuple[pathlib.Path, _DirectoryIdentity], ...]
    deadline_monotonic: float


@dataclass(frozen=True)
class LegacyPrefixReceiptResult:
    phase: str
    head_sha: str
    receipts: tuple[dict[str, object], ...]
    _handoff_signal_mask: set[signal.Signals] | None = None


@dataclass(frozen=True)
class _OutputTarget:
    path: pathlib.Path
    parent_fd: int
    parent_identity: tuple[int, int]


@dataclass(frozen=True)
class _PublishedOutput:
    target: _OutputTarget
    identity: tuple[int, int]


@dataclass(frozen=True)
class _ClaudeExecutableBinding:
    source_path: pathlib.Path
    selected_version: tuple[int, int, int]
    identity: Mapping[str, int]
    artifact_size: int
    artifact_checksum: str
    preflight_checksum: str


@dataclass(frozen=True)
class _ClaudeSourceControlFileBinding:
    path: pathlib.Path
    identity: _DirectoryIdentity
    file_type: int
    size: int
    sha256: str


@dataclass(frozen=True)
class _ClaudeSourceReadBoundaryBinding:
    source_worktree: pathlib.Path
    source_identity: _DirectoryIdentity
    marker: _MaterializerSourceMarkerBinding
    marker_content: _ClaudeSourceControlFileBinding | None
    back_pointer: _ClaudeSourceControlFileBinding | None
    admin: pathlib.Path
    admin_identity: _DirectoryIdentity
    commondir: _ClaudeSourceControlFileBinding | None
    common: pathlib.Path
    common_identity: _DirectoryIdentity
    objects: pathlib.Path
    objects_identity: _DirectoryIdentity
    object_info_identity: _DirectoryIdentity | None
    deny_roots: tuple[pathlib.Path, ...]


@dataclass(frozen=True)
class _ClaudeDirectArgvProfile:
    model: str
    worktree: pathlib.Path
    git_metadata: pathlib.Path
    account_home: pathlib.Path
    source_worktree: pathlib.Path
    source_read_deny_roots: tuple[pathlib.Path, ...]
    source_read_boundary: _ClaudeSourceReadBoundaryBinding
    source_authority_binding: Mapping[str, object]
    source_authority_binding_sha256: str
    preflight_result: pathlib.Path
    output_bindings: Mapping[str, object]
    environment_binding: Mapping[str, object]
    git_null_read_exception: Mapping[str, object]
    settings: Mapping[str, object]
    settings_json: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class _ClaudeLaunchSnapshot:
    path: pathlib.Path
    name: str
    identity: tuple[int, int]


@dataclass(frozen=True)
class _ClaudeDirectoryComponent:
    path: pathlib.Path
    device: int
    inode: int
    owner: int


@dataclass(frozen=True)
class _ClaudeSessionEnv:
    namespace_fd: int
    namespace_identity: tuple[int, int, int, int]
    parent_path: pathlib.Path
    parent_fd: int
    parent_identity: tuple[int, int]
    parent_components: tuple[_ClaudeDirectoryComponent, ...]
    session_id: str
    leaf_fd: int
    leaf_identity: tuple[int, int, int, int]


def _git_environment() -> dict[str, str]:
    environment = {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_GRAFT_FILE": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": TRUSTED_PATH,
    }
    return environment


def _git_capture(
    root: pathlib.Path,
    arguments: Iterable[str],
    *,
    output_limit_bytes: int = GIT_OUTPUT_LIMIT_BYTES,
    timeout_seconds: float = 30.0,
    allow_no_match: bool = False,
    neutralize_external_diff: bool = True,
    neutralize_fsmonitor: bool = True,
    stdin: bytearray | None = None,
) -> bytes:
    git = resolve_git()
    if not root.is_absolute() or os.pathsep in os.fspath(root.parent):
        raise NamedLaneGuardError(
            "Git worktree parent cannot be encoded as a discovery ceiling"
        )
    safety_config = [
        str(git),
        "--no-pager",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.checkStat=default",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "core.trustCtime=true",
    ]
    if neutralize_fsmonitor:
        safety_config.extend(("-c", "core.fsmonitor=false"))
    if neutralize_external_diff:
        safety_config.extend(("-c", "diff.external="))
    safety_config.extend(("-c", "color.ui=false", "-C", str(root)))
    command = (*safety_config, *tuple(arguments))
    environment = _git_environment()
    environment["GIT_CEILING_DIRECTORIES"] = str(root.parent)
    capture = run_bounded_capture(
        command,
        env=environment,
        stdin=stdin,
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=output_limit_bytes,
        stderr_limit_bytes=1024 * 1024,
    )
    try:
        no_match = (
            allow_no_match
            and capture.returncode == 1
            and not capture.stdout
            and not capture.stderr
        )
        if capture.returncode != 0 and not no_match:
            raise NamedLaneGuardError("bounded local Git preflight failed")
        return bytes(capture.stdout)
    finally:
        capture.stdout[:] = b"\x00" * len(capture.stdout)
        capture.stderr[:] = b"\x00" * len(capture.stderr)


def _current_user_id() -> int:
    get_effective_user_id = getattr(os, "geteuid", None)
    if get_effective_user_id is None:
        raise NamedLaneGuardError(
            "worktree materialization requires effective-user ownership checks"
        )
    return int(get_effective_user_id())


_DARWIN_ACL_EXTENDED_ALLOW = 1
_DARWIN_ACL_EXTENDED_DENY = 2
_DARWIN_ACL_QUALIFIER_BYTES = 16


def _legacy_extended_acl_entries(
    descriptor: int,
    *,
    label: str,
) -> tuple[tuple[int, bytes], ...]:
    """Return each Darwin ACL entry's access tag and principal UUID."""

    if sys.platform != "darwin":
        return ()
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        acl_get_fd_np = libc.acl_get_fd_np
        acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        acl_get_fd_np.restype = ctypes.c_void_p
        acl_get_entry = libc.acl_get_entry
        acl_get_entry.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        acl_get_entry.restype = ctypes.c_int
        acl_get_tag_type = libc.acl_get_tag_type
        acl_get_tag_type.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        acl_get_tag_type.restype = ctypes.c_int
        acl_get_qualifier = libc.acl_get_qualifier
        acl_get_qualifier.argtypes = [ctypes.c_void_p]
        acl_get_qualifier.restype = ctypes.c_void_p
        acl_free = libc.acl_free
        acl_free.argtypes = [ctypes.c_void_p]
        acl_free.restype = ctypes.c_int
    except (AttributeError, OSError) as error:
        raise NamedLaneGuardError(
            f"legacy prefix {label} extended ACL cannot be inspected"
        ) from error

    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, 0x00000100)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return ()
        raise NamedLaneGuardError(
            f"legacy prefix {label} extended ACL cannot be inspected"
        )
    entries: list[tuple[int, bytes]] = []
    try:
        entry_id = 0
        while True:
            entry = ctypes.c_void_p()
            ctypes.set_errno(0)
            entry_status = acl_get_entry(acl, entry_id, ctypes.byref(entry))
            entry_error = ctypes.get_errno()
            if entry_status == -1 and entry_error == errno.EINVAL:
                break
            if entry_status != 0 or not entry:
                raise NamedLaneGuardError(
                    f"legacy prefix {label} extended ACL cannot be inspected"
                )
            tag_type = ctypes.c_int()
            ctypes.set_errno(0)
            if acl_get_tag_type(entry, ctypes.byref(tag_type)) != 0:
                raise NamedLaneGuardError(
                    f"legacy prefix {label} extended ACL cannot be inspected"
                )
            ctypes.set_errno(0)
            qualifier = acl_get_qualifier(entry)
            if not qualifier:
                raise NamedLaneGuardError(
                    f"legacy prefix {label} extended ACL cannot be inspected"
                )
            try:
                qualifier_bytes = ctypes.string_at(
                    qualifier,
                    _DARWIN_ACL_QUALIFIER_BYTES,
                )
            finally:
                acl_free(qualifier)
            if len(qualifier_bytes) != _DARWIN_ACL_QUALIFIER_BYTES:
                raise NamedLaneGuardError(
                    f"legacy prefix {label} extended ACL cannot be inspected"
                )
            entries.append((int(tag_type.value), qualifier_bytes))
            entry_id = -1
    finally:
        acl_free(acl)
    return tuple(entries)


def _legacy_extended_acl_tag_types(
    descriptor: int,
    *,
    label: str,
) -> tuple[int, ...]:
    """Return every Darwin extended-ACL access tag from a bound descriptor."""

    return tuple(
        tag_type
        for tag_type, _qualifier in _legacy_extended_acl_entries(
            descriptor,
            label=label,
        )
    )


def _darwin_uid_acl_qualifier(uid: int, *, label: str) -> bytes:
    """Resolve one local UID to the UUID qualifier used by Darwin ACLs."""

    if sys.platform != "darwin":
        return b""
    if uid < 0 or uid > 0xFFFFFFFF:
        raise NamedLaneGuardError(
            f"legacy prefix {label} extended ACL owner cannot be resolved"
        )
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        mbr_uid_to_uuid = libc.mbr_uid_to_uuid
        qualifier_type = ctypes.c_ubyte * _DARWIN_ACL_QUALIFIER_BYTES
        mbr_uid_to_uuid.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte)]
        mbr_uid_to_uuid.restype = ctypes.c_int
    except (AttributeError, OSError) as error:
        raise NamedLaneGuardError(
            f"legacy prefix {label} extended ACL owner cannot be resolved"
        ) from error
    qualifier = qualifier_type()
    if mbr_uid_to_uuid(uid, qualifier) != 0:
        raise NamedLaneGuardError(
            f"legacy prefix {label} extended ACL owner cannot be resolved"
        )
    return bytes(qualifier)


def _darwin_acl_entries_preserve_owner_private_access(
    entries: Iterable[tuple[int, bytes]],
    *,
    owner_qualifier: bytes,
) -> bool:
    """Classify whether ACL entries preserve access by only the exact owner."""

    allow_qualifiers = _darwin_acl_allow_qualifiers(entries)
    if allow_qualifiers is None or not allow_qualifiers:
        return allow_qualifiers == ()
    if type(owner_qualifier) is not bytes:
        return False
    if len(owner_qualifier) != _DARWIN_ACL_QUALIFIER_BYTES:
        return False
    return all(qualifier == owner_qualifier for qualifier in allow_qualifiers)


def _darwin_acl_allow_qualifiers(
    entries: Iterable[tuple[int, bytes]],
) -> tuple[bytes, ...] | None:
    """Return valid allow principals, or ``None`` for an unsafe ACL shape."""

    allow_qualifiers: list[bytes] = []
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 2:
            return None
        tag_type, qualifier = entry
        if (
            type(tag_type) is not int
            or type(qualifier) is not bytes
            or len(qualifier) != _DARWIN_ACL_QUALIFIER_BYTES
        ):
            return None
        if tag_type == _DARWIN_ACL_EXTENDED_DENY:
            continue
        if tag_type != _DARWIN_ACL_EXTENDED_ALLOW:
            return None
        allow_qualifiers.append(qualifier)
    return tuple(allow_qualifiers)


def _require_no_legacy_extended_acl(descriptor: int, *, label: str) -> None:
    """Reject every Darwin extended ACL on a bound filesystem object.

    POSIX mode bits are an incomplete access-policy signal on macOS because an
    NFSv4-style extended ACL can grant another principal write or delete access
    while the ordinary mode remains owner-only.  The accepted ACL state is the
    singleton empty state, so every bind and revalidation can reject rather
    than serialize ACL entries into identity evidence.
    """

    if _legacy_extended_acl_tag_types(descriptor, label=label):
        raise NamedLaneGuardError(f"legacy prefix {label} has an extended ACL")


def _require_no_legacy_acl_allow_entry(descriptor: int, *, label: str) -> None:
    """Reject an ACL grant on a source ancestor while tolerating deny-only ACLs."""

    tag_types = _legacy_extended_acl_tag_types(descriptor, label=label)
    if any(tag_type != 2 for tag_type in tag_types):
        raise NamedLaneGuardError(f"legacy prefix {label} has an extended ACL grant")


def _legacy_custody_path_metadata(
    path: pathlib.Path,
    *,
    label: str,
    allowed_owners: tuple[int, ...],
    deadline_monotonic: float,
) -> os.stat_result:
    """Bind a real directory through a descriptor-relative chain from root."""

    if not path.is_absolute():
        raise NamedLaneGuardError(
            f"legacy prefix {label} custody path is not canonical"
        )
    try:
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            f"legacy prefix {label} custody path cannot be inspected"
        ) from error
    if resolved_path != path:
        raise NamedLaneGuardError(
            f"legacy prefix {label} custody path is not canonical"
        )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    current_path = pathlib.Path(path.anchor)
    try:
        _remaining_deadline_seconds(deadline_monotonic, label)
        descriptor = os.open(path.anchor, directory_flags)
        components = path.parts[1:]
        for component in (None, *components):
            _remaining_deadline_seconds(deadline_monotonic, label)
            if component is not None:
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=descriptor,
                )
                try:
                    lexical_metadata = os.stat(
                        component,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    opened_metadata = os.fstat(child_descriptor)
                except BaseException:
                    os.close(child_descriptor)
                    raise
                lexical_identity = (
                    lexical_metadata.st_dev,
                    lexical_metadata.st_ino,
                    stat.S_IFMT(lexical_metadata.st_mode),
                    lexical_metadata.st_uid,
                )
                opened_identity = (
                    opened_metadata.st_dev,
                    opened_metadata.st_ino,
                    stat.S_IFMT(opened_metadata.st_mode),
                    opened_metadata.st_uid,
                )
                if lexical_identity != opened_identity:
                    os.close(child_descriptor)
                    raise NamedLaneGuardError(
                        f"legacy prefix {label} custody edge changed"
                    )
                os.close(descriptor)
                descriptor = child_descriptor
                current_path /= component
            metadata = os.fstat(descriptor)
            mode = stat.S_IMODE(metadata.st_mode)
            sticky_root_custody = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in allowed_owners
            ):
                raise NamedLaneGuardError(
                    f"legacy prefix {label} custody access policy is unsafe"
                )
            if mode & 0o022 and not sticky_root_custody:
                raise NamedLaneGuardError(
                    f"legacy prefix {label} custody access policy is "
                    "group/world writable"
                )
            _require_no_legacy_acl_allow_entry(descriptor, label=label)
        if current_path != path:
            raise NamedLaneGuardError(f"legacy prefix {label} custody path changed")
        return os.fstat(descriptor)
    except NamedLaneGuardError:
        raise
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            f"legacy prefix {label} custody path cannot be inspected"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _legacy_policy_path_metadata(
    path: pathlib.Path,
    *,
    expect_directory: bool,
    label: str,
    allowed_owners: tuple[int, ...] | None = None,
    allow_deny_acl: bool = False,
    deadline_monotonic: float | None = None,
) -> os.stat_result:
    """Bind one real path object and reject unsafe Darwin ACL policy."""

    accepted_owners = allowed_owners or (_current_user_id(),)
    if allow_deny_acl:
        if not expect_directory:
            raise NamedLaneGuardError(
                f"legacy prefix {label} custody object must be a directory"
            )
        return _legacy_custody_path_metadata(
            path,
            label=label,
            allowed_owners=accepted_owners,
            deadline_monotonic=(
                deadline_monotonic if deadline_monotonic is not None else float("inf")
            ),
        )

    descriptor = -1
    expected_type = stat.S_IFDIR if expect_directory else stat.S_IFREG
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or nonblocking is None:
        raise NamedLaneGuardError(
            f"legacy prefix {label} requires no-follow nonblocking inspection"
        )
    try:
        lexical_metadata = path.lstat()
        resolved = path.resolve(strict=True)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nonblocking | no_follow
        if expect_directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        opened_metadata = os.fstat(descriptor)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            f"legacy prefix {label} access policy cannot be inspected"
        ) from error
    try:
        lexical_identity = (
            lexical_metadata.st_dev,
            lexical_metadata.st_ino,
            stat.S_IFMT(lexical_metadata.st_mode),
            lexical_metadata.st_uid,
            stat.S_IMODE(lexical_metadata.st_mode),
        )
        opened_identity = (
            opened_metadata.st_dev,
            opened_metadata.st_ino,
            stat.S_IFMT(opened_metadata.st_mode),
            opened_metadata.st_uid,
            stat.S_IMODE(opened_metadata.st_mode),
        )
        if (
            lexical_identity != opened_identity
            or stat.S_IFMT(opened_metadata.st_mode) != expected_type
            or stat.S_ISLNK(lexical_metadata.st_mode)
            or opened_metadata.st_uid not in accepted_owners
            or resolved != path
        ):
            raise NamedLaneGuardError(
                f"legacy prefix {label} identity or access policy is unsafe"
            )
        _require_no_legacy_extended_acl(descriptor, label=label)
        return opened_metadata
    finally:
        os.close(descriptor)


def _verify_legacy_prefix_parent(
    parent: pathlib.Path,
    expected: _DirectoryIdentity,
    deadline_monotonic: float | None = None,
) -> None:
    _legacy_custody_path_metadata(
        parent,
        label="temporary parent ancestor",
        allowed_owners=tuple(sorted({_current_user_id(), 0})),
        deadline_monotonic=(
            deadline_monotonic if deadline_monotonic is not None else float("inf")
        ),
    )
    _verify_materializer_parent(parent, expected)
    metadata = _legacy_policy_path_metadata(
        parent,
        expect_directory=True,
        label="temporary parent",
    )
    if (
        _directory_identity(metadata) != expected
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise NamedLaneGuardError(
            "legacy prefix temporary parent access policy changed"
        )


def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    return _DirectoryIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
    )


def _validate_materializer_parent(
    destination: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, _DirectoryIdentity]:
    if not destination.is_absolute():
        raise NamedLaneGuardError("materialized worktree path must be absolute")
    parent = destination.parent
    try:
        metadata = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materialized worktree parent is not accessible"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved_parent != parent
    ):
        raise NamedLaneGuardError(
            "materialized worktree parent must be an absolute real directory"
        )
    if metadata.st_uid != _current_user_id():
        raise NamedLaneGuardError(
            "materialized worktree parent must be owned by the current user"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise NamedLaneGuardError("materialized worktree parent must have mode 0700")
    if os.pathsep in os.fspath(resolved_parent):
        raise NamedLaneGuardError(
            "materialized worktree parent cannot be encoded as a Git discovery ceiling"
        )
    normalized = resolved_parent / destination.name
    if normalized != destination:
        raise NamedLaneGuardError(
            "materialized worktree path must not contain unresolved components"
        )
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized worktree destination cannot be inspected"
        ) from error
    else:
        raise NamedLaneGuardError(
            "materialized worktree destination must not already exist"
        )
    return normalized, resolved_parent, _directory_identity(metadata)


def _verify_materializer_parent(
    parent: pathlib.Path,
    expected: _DirectoryIdentity,
) -> None:
    try:
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materialized worktree parent changed during materialization"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != parent
        or metadata.st_uid != _current_user_id()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or _directory_identity(metadata) != expected
    ):
        raise NamedLaneGuardError(
            "materialized worktree parent changed during materialization"
        )


def _open_legacy_prefix_parent_descriptor(
    parent: pathlib.Path,
    expected: _DirectoryIdentity,
) -> int:
    descriptor = -1
    bound = False
    try:
        descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != _current_user_id()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or _directory_identity(metadata) != expected
        ):
            raise NamedLaneGuardError(
                "legacy prefix temporary parent descriptor is not bound safely"
            )
        _require_no_legacy_extended_acl(
            descriptor,
            label="temporary parent",
        )
        bound = True
        return descriptor
    except NamedLaneGuardError:
        raise
    except OSError as error:
        raise NamedLaneGuardError(
            "legacy prefix temporary parent descriptor cannot be opened"
        ) from error
    finally:
        if descriptor >= 0 and not bound:
            os.close(descriptor)


def _legacy_prefix_retained_evidence(
    *,
    label: str,
    path: pathlib.Path,
    expected_identity: _DirectoryIdentity | None,
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
    parent_fd: int,
) -> str:
    descriptor_bound = False
    try:
        descriptor_metadata = os.fstat(parent_fd)
        descriptor_bound = (
            stat.S_ISDIR(descriptor_metadata.st_mode)
            and descriptor_metadata.st_uid == _current_user_id()
            and _directory_identity(descriptor_metadata) == parent_identity
        )
    except OSError:
        descriptor_metadata = None
    if descriptor_bound and expected_identity is not None:
        try:
            _verify_materializer_parent(parent, parent_identity)
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except (NamedLaneGuardError, OSError, RuntimeError):
            pass
        else:
            if (
                stat.S_ISDIR(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and metadata.st_uid == _current_user_id()
                and resolved == path
                and path.parent == parent
                and _directory_identity(metadata) == expected_identity
            ):
                return f"retained legacy prefix {label} path: {path}"
    return (
        f"retained legacy prefix {label} locator: "
        f"parent device={parent_identity.device}, "
        f"inode={parent_identity.inode}, leaf={path.name}"
    )


def _cleanup_legacy_prefix_path(
    path: pathlib.Path,
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
    expected_identity: _DirectoryIdentity | None,
) -> pathlib.Path | None:
    retained = _cleanup_materializer_path(
        path,
        parent,
        parent_identity,
        expected_identity,
    )
    try:
        _verify_materializer_parent(parent, parent_identity)
    except NamedLaneGuardError:
        # Lexical absence after parent replacement does not prove that the
        # bound original parent's leaf was removed. Preserve descriptor-locator
        # evidence even when the generic lexical cleanup reported absence.
        return path
    return retained


def _resolve_materializer_source(
    source: pathlib.Path,
) -> tuple[pathlib.Path, _MaterializerSourceMarkerBinding]:
    if not source.is_absolute():
        raise NamedLaneGuardError("materializer source path must be absolute")
    try:
        metadata = source.lstat()
        resolved = source.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError("materializer source is not accessible") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NamedLaneGuardError("materializer source must be a real directory")
    if os.pathsep in os.fspath(resolved.parent):
        raise NamedLaneGuardError(
            "materializer source parent cannot be encoded as a Git discovery ceiling"
        )
    admin_marker = resolved / ".git"
    try:
        admin_metadata = admin_marker.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            "materializer source must name an exact Git worktree root"
        ) from error
    if (
        stat.S_ISLNK(admin_metadata.st_mode)
        or admin_metadata.st_uid != _current_user_id()
    ):
        raise NamedLaneGuardError(
            "materializer source must name an exact Git worktree root"
        )
    is_gitfile = stat.S_ISREG(admin_metadata.st_mode)
    if stat.S_ISDIR(admin_metadata.st_mode):
        try:
            expected_admin = admin_marker.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise NamedLaneGuardError(
                "materializer source Git admin directory cannot be resolved safely"
            ) from error
        if expected_admin != admin_marker:
            raise NamedLaneGuardError(
                "materializer source Git admin directory must be a real directory"
            )
    elif is_gitfile:
        expected_admin = _read_materializer_gitfile_admin(admin_marker, resolved)
        try:
            expected_metadata = expected_admin.lstat()
        except OSError as error:
            raise NamedLaneGuardError(
                "materializer source Git admin directory cannot be resolved safely"
            ) from error
        if (
            not stat.S_ISDIR(expected_metadata.st_mode)
            or stat.S_ISLNK(expected_metadata.st_mode)
            or expected_metadata.st_uid != _current_user_id()
        ):
            raise NamedLaneGuardError(
                "materializer source Git admin directory must be a real directory"
            )
    else:
        raise NamedLaneGuardError(
            "materializer source must name an exact Git worktree root"
        )
    binding = _MaterializerSourceMarkerBinding(
        path=admin_marker,
        expected_admin=expected_admin,
        device=admin_metadata.st_dev,
        inode=admin_metadata.st_ino,
        file_type=stat.S_IFMT(admin_metadata.st_mode),
        owner=admin_metadata.st_uid,
        is_gitfile=is_gitfile,
    )
    _verify_materializer_source_marker(binding, resolved)
    return resolved, binding


def _cleanup_materializer_path(
    path: pathlib.Path,
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
    expected_identity: _DirectoryIdentity | None,
) -> pathlib.Path | None:
    try:
        _verify_materializer_parent(parent, parent_identity)
    except NamedLaneGuardError:
        return path
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return path
    if expected_identity is None or _directory_identity(metadata) != expected_identity:
        return path
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != _current_user_id()
    ):
        return path
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return path
    if resolved != path or path.parent != parent:
        return path
    try:
        shutil.rmtree(path)
    except ForwardedSignal:
        raise
    # Ordinary cleanup failures must become exact retained-path evidence, while
    # control-flow BaseExceptions continue to propagate.
    except Exception:
        pass
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return path
    return path


def _make_materializer_control_directory(
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
) -> tuple[pathlib.Path, dict[str, pathlib.Path], _DirectoryIdentity]:
    _verify_materializer_parent(parent, parent_identity)
    control = pathlib.Path(
        tempfile.mkdtemp(prefix=".named-lane-materializer-", dir=parent)
    )
    control_identity: _DirectoryIdentity | None = None
    try:
        control_metadata = control.lstat()
        if (
            not stat.S_ISDIR(control_metadata.st_mode)
            or stat.S_ISLNK(control_metadata.st_mode)
            or control_metadata.st_uid != _current_user_id()
        ):
            raise NamedLaneGuardError(
                "materializer control directory must be current-user-owned"
            )
        control_identity = _directory_identity(control_metadata)
        os.chmod(control, 0o700, follow_symlinks=False)
        revalidated_control = control.lstat()
        if (
            _directory_identity(revalidated_control) != control_identity
            or stat.S_IMODE(revalidated_control.st_mode) != 0o700
        ):
            raise NamedLaneGuardError(
                "materializer control directory changed during setup"
            )
        directories: dict[str, pathlib.Path] = {}
        for name in ("home", "xdg", "hooks", "template", "tmp"):
            path = control / name
            path.mkdir(mode=0o700)
            path.chmod(0o700)
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != _current_user_id()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise NamedLaneGuardError(
                    "materializer control directories must be owner-only"
                )
            directories[name] = path
        if any(directories["template"].iterdir()):
            raise NamedLaneGuardError(
                "materializer Git template directory must start empty"
            )
        _verify_materializer_parent(parent, parent_identity)
        return control, directories, control_identity
    except BaseException as error:
        retained = _cleanup_materializer_path(
            control,
            parent,
            parent_identity,
            control_identity,
        )
        if retained is not None:
            raise NamedLaneGuardError(
                f"materializer control setup failed; retained control path: {retained}"
            ) from error
        raise


def _materializer_git_environment(
    directories: Mapping[str, pathlib.Path],
    destination_parent: pathlib.Path,
) -> dict[str, str]:
    environment = _git_environment()
    environment.update(
        {
            "GIT_CEILING_DIRECTORIES": str(destination_parent),
            "HOME": str(directories["home"]),
            "XDG_CONFIG_HOME": str(directories["xdg"]),
        }
    )
    return environment


def _validate_materializer_git_version(
    git: pathlib.Path,
    environment: Mapping[str, str],
    cwd: pathlib.Path,
    *,
    timeout_seconds: float = 30.0,
) -> None:
    capture = run_bounded_capture(
        (str(git), "--version"),
        cwd=cwd,
        env=dict(environment),
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=1024,
        stderr_limit_bytes=1024,
    )
    try:
        if capture.returncode != 0 or capture.stderr:
            raise NamedLaneGuardError("materializer Git version could not be validated")
        match = re.fullmatch(
            rb"git version ([0-9]+)\.([0-9]+)\.([0-9]+)"
            rb"(?: \(Apple Git-[0-9]+(?:\.[0-9]+)*\))?",
            bytes(capture.stdout).strip(),
        )
        if match is None:
            raise NamedLaneGuardError("materializer Git version could not be validated")
        version = tuple(int(component) for component in match.groups())
        if version < MATERIALIZER_MINIMUM_GIT_VERSION:
            raise NamedLaneGuardError(
                "worktree materialization requires Git 2.45.0 or newer"
            )
    finally:
        capture.stdout[:] = b"\x00" * len(capture.stdout)
        capture.stderr[:] = b"\x00" * len(capture.stderr)


def _materializer_git_prefix(
    git: pathlib.Path,
    hooks: pathlib.Path,
) -> tuple[str, ...]:
    return (
        str(git),
        "--no-pager",
        "-c",
        "advice.detachedHead=false",
        "-c",
        "color.ui=false",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.checkStat=default",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"core.excludesFile={os.devnull}",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.ignoreStat=false",
        "-c",
        f"core.hooksPath={hooks}",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "core.trustCtime=true",
        "-c",
        "credential.helper=",
        "-c",
        "diff.external=",
        "-c",
        "fetch.recurseSubmodules=false",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "submodule.recurse=false",
    )


def _materializer_git_capture(
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
    arguments: Sequence[str],
    *,
    root: pathlib.Path | None = None,
    allow_no_match: bool = False,
    stdin: bytearray | None = None,
    timeout_seconds: float = MATERIALIZER_GIT_TIMEOUT_SECONDS,
    output_limit_bytes: int = GIT_OUTPUT_LIMIT_BYTES,
) -> bytes:
    prefix = _materializer_git_prefix(git, hooks)
    command = (
        (*prefix, *arguments)
        if root is None
        else (*prefix, "-C", str(root), *arguments)
    )
    capture = run_bounded_capture(
        command,
        cwd=hooks.parent / "tmp",
        env=dict(environment),
        stdin=stdin,
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=output_limit_bytes,
        stderr_limit_bytes=1024 * 1024,
    )
    try:
        no_match = (
            allow_no_match
            and capture.returncode == 1
            and not capture.stdout
            and not capture.stderr
        )
        if capture.returncode != 0 and not no_match:
            command_name = arguments[0] if arguments else "command"
            raise NamedLaneGuardError(f"bounded materializer Git {command_name} failed")
        return bytes(capture.stdout)
    finally:
        capture.stdout[:] = b"\x00" * len(capture.stdout)
        capture.stderr[:] = b"\x00" * len(capture.stderr)


def _git_config_value_is_false(value: bytes | None) -> bool:
    return value is not None and value.strip().lower() in {
        b"0",
        b"false",
        b"no",
        b"off",
    }


def _require_control_properties_unchanged(
    label: str,
    reason_prefix: str,
    context: str,
    *,
    actual_identity: tuple[object, ...],
    expected_identity: tuple[object, ...],
    actual_content: tuple[object, ...] | None,
    expected_content: tuple[object, ...] | None,
    actual_access_policy: tuple[object, ...],
    expected_access_policy: tuple[object, ...],
) -> None:
    # Device/inode/type protect object identity. Ownership/mode/link count
    # protect the admitted access policy, while size/digest protect content.
    # The order gives simultaneous drift one deterministic machine reason.
    if actual_identity != expected_identity:
        raise _ControlObjectGuardError(
            f"{reason_prefix}-object-identity-mismatch",
            f"{label} identity changed {context}",
        )
    if actual_access_policy != expected_access_policy:
        raise _ControlObjectGuardError(
            f"{reason_prefix}-access-policy-mismatch",
            f"{label} access policy changed {context}",
        )
    if (
        actual_content is not None
        and expected_content is not None
        and actual_content != expected_content
    ):
        raise _ControlObjectGuardError(
            f"{reason_prefix}-content-mismatch",
            f"{label} content changed {context}",
        )


def _require_no_control_extended_acl(
    descriptor: int,
    *,
    label: str,
    reason_prefix: str,
) -> None:
    try:
        tag_types = _legacy_extended_acl_tag_types(descriptor, label=label)
    except NamedLaneGuardError as error:
        raise _ControlObjectGuardError(
            f"{reason_prefix}-inspection-failure",
            f"{label} extended ACL cannot be inspected",
        ) from error
    if tag_types:
        raise _ControlObjectGuardError(
            f"{reason_prefix}-access-policy-mismatch",
            f"{label} has an extended ACL",
        )


def _require_local_config_metadata_unchanged(
    actual: os.stat_result,
    expected: os.stat_result,
    *,
    context: str,
) -> None:
    _require_control_properties_unchanged(
        "materialized local Git config",
        "materialized-git-config",
        context,
        actual_identity=(
            actual.st_dev,
            actual.st_ino,
            stat.S_IFMT(actual.st_mode),
        ),
        expected_identity=(
            expected.st_dev,
            expected.st_ino,
            stat.S_IFMT(expected.st_mode),
        ),
        actual_content=(actual.st_size,),
        expected_content=(expected.st_size,),
        actual_access_policy=(
            actual.st_uid,
            actual.st_gid,
            stat.S_IMODE(actual.st_mode),
            actual.st_nlink,
        ),
        expected_access_policy=(
            expected.st_uid,
            expected.st_gid,
            stat.S_IMODE(expected.st_mode),
            expected.st_nlink,
        ),
    )


def _require_local_config_matches_binding(
    actual: os.stat_result,
    expected: _LocalConfigBinding,
    *,
    context: str,
) -> None:
    _require_control_properties_unchanged(
        "materialized local Git config",
        "materialized-git-config",
        context,
        actual_identity=(
            actual.st_dev,
            actual.st_ino,
            stat.S_IFMT(actual.st_mode),
        ),
        expected_identity=(expected.device, expected.inode, expected.file_type),
        actual_content=(actual.st_size,),
        expected_content=(expected.size,),
        actual_access_policy=(
            actual.st_uid,
            actual.st_gid,
            stat.S_IMODE(actual.st_mode),
            actual.st_nlink,
        ),
        expected_access_policy=(
            expected.owner,
            expected.group,
            expected.mode,
            expected.link_count,
        ),
    )


def _require_local_config_binding_unchanged(
    actual: _LocalConfigBinding,
    expected: _LocalConfigBinding,
    *,
    context: str,
) -> None:
    _require_control_properties_unchanged(
        "materialized local Git config",
        "materialized-git-config",
        context,
        actual_identity=(actual.device, actual.inode, actual.file_type),
        expected_identity=(expected.device, expected.inode, expected.file_type),
        actual_content=(actual.size, actual.sha256),
        expected_content=(expected.size, expected.sha256),
        actual_access_policy=(
            actual.owner,
            actual.group,
            actual.mode,
            actual.link_count,
        ),
        expected_access_policy=(
            expected.owner,
            expected.group,
            expected.mode,
            expected.link_count,
        ),
    )


def _read_local_config(
    path: pathlib.Path,
    *,
    expected: _LocalConfigBinding | None = None,
    expected_context: str = "during the protected window",
) -> tuple[_LocalConfigBinding, bytearray]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblocking is None:
        raise _ControlObjectGuardError(
            "materialized-git-config-inspection-failure",
            "materialized local Git config requires no-follow inspection",
        )
    descriptor = -1
    payload = bytearray()
    try:
        before = path.lstat()
        if expected is not None:
            _require_local_config_matches_binding(
                before,
                expected,
                context=expected_context,
            )
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_uid != _current_user_id()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise _ControlObjectGuardError(
                "materialized-git-config-access-policy-mismatch",
                "materialized local Git config has an unsafe access policy",
            )
        if before.st_size > MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES:
            raise _ControlObjectGuardError(
                "materialized-git-config-inspection-failure",
                "materialized local Git config is too large",
            )
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | nonblocking,
        )
        opened = os.fstat(descriptor)
        _require_local_config_metadata_unchanged(
            opened,
            before,
            context="during inspection",
        )
        _require_no_control_extended_acl(
            descriptor,
            label="materialized local Git config",
            reason_prefix="materialized-git-config",
        )
        while len(payload) <= MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    1 + MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES - len(payload),
                ),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES:
            raise _ControlObjectGuardError(
                "materialized-git-config-inspection-failure",
                "materialized local Git config is too large",
            )
        after_open = os.fstat(descriptor)
        _require_no_control_extended_acl(
            descriptor,
            label="materialized local Git config",
            reason_prefix="materialized-git-config",
        )
        after_path = path.lstat()
        _require_local_config_metadata_unchanged(
            after_open,
            opened,
            context="during inspection",
        )
        _require_local_config_metadata_unchanged(
            after_path,
            opened,
            context="during inspection",
        )
        if len(payload) != opened.st_size:
            raise _ControlObjectGuardError(
                "materialized-git-config-content-mismatch",
                "materialized local Git config content changed during inspection",
            )
        binding = _LocalConfigBinding(
            device=opened.st_dev,
            inode=opened.st_ino,
            file_type=stat.S_IFMT(opened.st_mode),
            owner=opened.st_uid,
            group=opened.st_gid,
            mode=stat.S_IMODE(opened.st_mode),
            link_count=opened.st_nlink,
            size=opened.st_size,
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        if expected is not None:
            _require_local_config_binding_unchanged(
                binding,
                expected,
                context=expected_context,
            )
        return binding, payload
    except NamedLaneGuardError:
        payload[:] = b"\x00" * len(payload)
        raise
    except FileNotFoundError as error:
        payload[:] = b"\x00" * len(payload)
        raise _ControlObjectGuardError(
            "materialized-git-config-missing",
            "materialized local Git config is missing",
        ) from error
    except OSError as error:
        payload[:] = b"\x00" * len(payload)
        raise _ControlObjectGuardError(
            "materialized-git-config-inspection-failure",
            "materialized local Git config cannot be inspected",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_direct_local_config(
    payload: bytearray,
    git: pathlib.Path,
    environment: Mapping[str, str],
    cwd: pathlib.Path,
) -> tuple[tuple[bytes, bytes | None], ...]:
    command = (
        str(git),
        "--no-pager",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.checkStat=default",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "core.trustCtime=true",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        "diff.external=",
        "-c",
        "color.ui=false",
        "config",
        "--file",
        "-",
        "--no-includes",
        "--null",
        "--list",
    )
    capture = None
    try:
        try:
            capture = run_bounded_capture(
                command,
                cwd=cwd,
                env=dict(environment),
                stdin=payload,
                timeout_seconds=MATERIALIZER_GIT_TIMEOUT_SECONDS,
                stdout_limit_bytes=4 * MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES,
                stderr_limit_bytes=1024 * 1024,
            )
        except (
            ReviewTimeoutError,
            ReviewOutputLimitError,
            ReviewOutputDrainError,
            ReviewProcessLeakError,
        ):
            raise
        except (ReviewError, OSError, ValueError) as error:
            raise _ControlObjectGuardError(
                "materialized-git-config-inspection-failure",
                "materialized direct local Git config cannot be parsed safely",
            ) from error
        if capture.returncode != 0 or capture.stderr:
            raise _ControlObjectGuardError(
                "materialized-git-config-inspection-failure",
                "materialized direct local Git config cannot be parsed safely",
            )
        try:
            return _parse_git_config_records(
                bytes(capture.stdout),
                label="materialized direct local Git config",
            )
        except (ReviewError, OSError, ValueError) as error:
            raise _ControlObjectGuardError(
                "materialized-git-config-inspection-failure",
                "materialized direct local Git config records are malformed",
            ) from error
    finally:
        if capture is not None:
            capture.stdout[:] = b"\x00" * len(capture.stdout)
            capture.stderr[:] = b"\x00" * len(capture.stderr)


def _audit_direct_local_config(
    path: pathlib.Path,
    git: pathlib.Path,
    environment: Mapping[str, str],
    cwd: pathlib.Path,
    *,
    expected: _LocalConfigBinding | None = None,
) -> tuple[_LocalConfigBinding, tuple[tuple[bytes, bytes | None], ...]]:
    binding, payload = _read_local_config(
        path,
        expected=expected,
        expected_context="during the protected window",
    )
    try:
        records = _parse_direct_local_config(payload, git, environment, cwd)
    finally:
        payload[:] = b"\x00" * len(payload)
    rechecked_binding, rechecked_payload = _read_local_config(
        path,
        expected=binding,
        expected_context="during direct audit",
    )
    try:
        _require_local_config_binding_unchanged(
            rechecked_binding,
            binding,
            context="during direct audit",
        )
    finally:
        rechecked_payload[:] = b"\x00" * len(rechecked_payload)
    configured_keys = frozenset(key for key, _value in records)
    _validate_git_config_includes(configured_keys)
    forbidden_stat_keys = {
        b"core.checkstat",
        b"core.ignorestat",
        b"core.trustctime",
    }
    if any(key.lower() in forbidden_stat_keys for key in configured_keys):
        raise NamedLaneGuardError(
            "direct core.checkStat, core.trustCtime, and core.ignoreStat settings "
            "are not allowed"
        )
    _validate_core_fsmonitor_config(records)
    _validate_executable_git_config(configured_keys)
    false_only_keys = {
        b"clone.recursesubmodules",
        b"fetch.recursesubmodules",
        b"submodule.recurse",
    }
    for key, value in records:
        lower_key = key.lower()
        if lower_key.startswith(b"credential."):
            raise NamedLaneGuardError(
                "materialized Git credential configuration is not allowed"
            )
        if lower_key == b"core.worktree":
            raise NamedLaneGuardError("materialized core.worktree is not allowed")
        if lower_key == b"core.bare" and not _git_config_value_is_false(value):
            raise NamedLaneGuardError("materialized core.bare must be disabled")
        if lower_key == b"core.hookspath":
            raise NamedLaneGuardError(
                "materialized direct core.hooksPath is not allowed"
            )
        if lower_key in {
            b"core.alternaterefscommand",
            b"core.askpass",
            b"core.gitproxy",
            b"core.sshcommand",
            b"ssh.command",
        }:
            raise NamedLaneGuardError(
                "materialized Git command configuration is not allowed"
            )
        if lower_key.startswith(b"core.sparse") or lower_key.startswith(
            b"index.sparse"
        ):
            raise NamedLaneGuardError(
                "materialized sparse checkout configuration is not allowed"
            )
        if (
            lower_key.startswith(b"extensions.")
            and lower_key != b"extensions.objectformat"
        ):
            raise NamedLaneGuardError(
                "unexpected materialized Git repository extension"
            )
        if lower_key in false_only_keys and not _git_config_value_is_false(value):
            raise NamedLaneGuardError(
                "materialized submodule recursion must be disabled"
            )
        if lower_key.startswith(b"url.") or lower_key.startswith(b"protocol."):
            raise NamedLaneGuardError(
                "materialized Git remote helper configuration is not allowed"
            )
        if lower_key.startswith((b"fsck.", b"fetch.fsck.", b"receive.fsck.")):
            raise NamedLaneGuardError(
                "materialized Git fsck policy overrides are not allowed"
            )
        if lower_key.startswith(b"remote."):
            raise NamedLaneGuardError(
                "unexpected materialized Git remote configuration"
            )
    return binding, records


def _audit_materialized_local_config(
    root: pathlib.Path,
    oid_length: int,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
    *,
    expected: _LocalConfigBinding | None = None,
) -> _LocalConfigBinding:
    binding, records = _audit_direct_local_config(
        root / ".git" / "config",
        git,
        environment,
        hooks.parent / "tmp",
        expected=expected,
    )

    object_formats: list[bytes] = []
    commit_graph_values: list[bytes] = []
    multi_pack_index_values: list[bytes] = []
    expected_hooks = os.fsencode(hooks)
    false_only_keys = frozenset(
        (
            b"clone.recursesubmodules",
            b"fetch.recursesubmodules",
            b"submodule.recurse",
        )
    )
    for key, value in records:
        lower_key = key.lower()
        if lower_key.startswith(b"alias."):
            raise NamedLaneGuardError(
                "materialized Git aliases are not allowed before checkout"
            )
        if lower_key.startswith(b"credential."):
            raise NamedLaneGuardError(
                "materialized Git credential helpers are not allowed before checkout"
            )
        if lower_key == b"core.worktree":
            raise NamedLaneGuardError(
                "materialized core.worktree is not allowed before checkout"
            )
        if lower_key == b"core.commitgraph":
            if not _git_config_value_is_false(value):
                raise NamedLaneGuardError(
                    "materialized core.commitGraph must be disabled before checkout"
                )
            assert value is not None
            commit_graph_values.append(value.strip().lower())
            continue
        if lower_key == b"core.multipackindex":
            if not _git_config_value_is_false(value):
                raise NamedLaneGuardError(
                    "materialized core.multiPackIndex must be disabled before checkout"
                )
            assert value is not None
            multi_pack_index_values.append(value.strip().lower())
            continue
        if lower_key == b"core.fsmonitor":
            if not _git_config_value_is_false(value):
                raise NamedLaneGuardError(
                    "materialized core.fsmonitor must be disabled before checkout"
                )
            continue
        if lower_key == b"core.hookspath":
            if value != expected_hooks:
                raise NamedLaneGuardError(
                    "materialized core.hooksPath is not the private hooks directory"
                )
            continue
        if lower_key == b"core.attributesfile" and value != os.fsencode(os.devnull):
            raise NamedLaneGuardError(
                "materialized core.attributesFile is not allowed before checkout"
            )
        if lower_key in {
            b"core.alternaterefscommand",
            b"core.askpass",
            b"core.gitproxy",
            b"core.sshcommand",
            b"ssh.command",
        }:
            raise NamedLaneGuardError(
                "materialized Git remote command configuration is not allowed"
            )
        if lower_key.startswith(b"core.sparse") or lower_key.startswith(
            b"index.sparse"
        ):
            raise NamedLaneGuardError(
                "materialized sparse checkout configuration is not allowed"
            )
        if lower_key.startswith(b"extensions."):
            if lower_key != b"extensions.objectformat":
                raise NamedLaneGuardError(
                    "unexpected materialized Git repository extension"
                )
            if value is None:
                raise NamedLaneGuardError(
                    "materialized Git object format must have a value"
                )
            object_formats.append(value.lower())
            continue
        executable_filter = _matches_named_driver_key(
            lower_key,
            b"filter.",
            frozenset((b"clean", b"process", b"smudge")),
        )
        executable_diff = lower_key == b"diff.external" or (
            _matches_named_driver_key(
                lower_key,
                b"diff.",
                frozenset((b"command", b"textconv")),
            )
        )
        if executable_filter or executable_diff:
            raise NamedLaneGuardError(
                "materialized executable Git filter or diff driver is not allowed"
            )
        if lower_key in false_only_keys and not _git_config_value_is_false(value):
            raise NamedLaneGuardError(
                "materialized submodule recursion must be disabled"
            )
        if (
            lower_key.startswith(b"submodule.")
            and lower_key.endswith(b".update")
            and (value is None or value.lstrip().startswith(b"!"))
        ):
            raise NamedLaneGuardError(
                "materialized executable submodule update command is not allowed"
            )
        if lower_key.startswith(b"url.") or lower_key.startswith(b"protocol."):
            raise NamedLaneGuardError(
                "materialized Git remote helper configuration is not allowed"
            )
        if lower_key.startswith((b"fsck.", b"fetch.fsck.", b"receive.fsck.")):
            raise NamedLaneGuardError(
                "materialized Git fsck policy overrides are not allowed"
            )
        if lower_key.startswith(b"remote."):
            raise NamedLaneGuardError(
                "unexpected materialized Git remote configuration"
            )

    if oid_length == 64:
        if object_formats != [b"sha256"]:
            raise NamedLaneGuardError(
                "materialized Git object format does not match frozen object IDs"
            )
    elif object_formats not in ([], [b"sha1"]):
        raise NamedLaneGuardError(
            "materialized Git object format does not match frozen object IDs"
        )
    if commit_graph_values != [b"false"]:
        raise NamedLaneGuardError(
            "materialized core.commitGraph must have one Git-false value"
        )
    if multi_pack_index_values != [b"false"]:
        raise NamedLaneGuardError(
            "materialized core.multiPackIndex must have one Git-false value"
        )
    return binding


def _read_materializer_control_file(
    path: pathlib.Path,
    *,
    label: str,
) -> bytearray:
    descriptor = -1
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != _current_user_id()
            or metadata.st_size > MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES
        ):
            raise NamedLaneGuardError(f"materializer source {label} is not safe")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        descriptor_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_metadata.st_mode)
            or descriptor_metadata.st_uid != _current_user_id()
            or descriptor_metadata.st_dev != metadata.st_dev
            or descriptor_metadata.st_ino != metadata.st_ino
            or descriptor_metadata.st_size != metadata.st_size
        ):
            raise NamedLaneGuardError(
                f"materializer source {label} changed during inspection"
            )
        payload = bytearray()
        while len(payload) <= MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    1 + MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES - len(payload),
                ),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES:
            payload[:] = b"\x00" * len(payload)
            raise NamedLaneGuardError(f"materializer source {label} is too large")
        final_metadata = os.fstat(descriptor)
        if (
            final_metadata.st_dev != descriptor_metadata.st_dev
            or final_metadata.st_ino != descriptor_metadata.st_ino
            or final_metadata.st_size != descriptor_metadata.st_size
        ):
            payload[:] = b"\x00" * len(payload)
            raise NamedLaneGuardError(
                f"materializer source {label} changed during inspection"
            )
        return payload
    except NamedLaneGuardError:
        raise
    except OSError as error:
        raise NamedLaneGuardError(
            f"materializer source {label} cannot be inspected"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _materializer_control_path(
    payload: bytes | bytearray,
    *,
    relative_to: pathlib.Path,
    label: str,
) -> pathlib.Path:
    stripped = bytes(payload).rstrip(b"\r\n")
    if not stripped or b"\0" in stripped or b"\n" in stripped or b"\r" in stripped:
        raise NamedLaneGuardError(f"materializer source {label} is malformed")
    candidate = pathlib.Path(os.fsdecode(stripped))
    if not candidate.is_absolute():
        candidate = relative_to / candidate
    try:
        return candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            f"materializer source {label} cannot be resolved safely"
        ) from error


def _read_materializer_gitfile_admin(
    marker: pathlib.Path,
    source: pathlib.Path,
) -> pathlib.Path:
    payload = _read_materializer_control_file(
        marker,
        label="Git admin marker",
    )
    try:
        stripped = bytes(payload).rstrip(b"\r\n")
        prefix = b"gitdir: "
        if (
            not stripped.startswith(prefix)
            or not stripped[len(prefix) :]
            or b"\0" in stripped
            or b"\n" in stripped
            or b"\r" in stripped
        ):
            raise NamedLaneGuardError("materializer source Git admin file is malformed")
        return _materializer_control_path(
            stripped[len(prefix) :],
            relative_to=source,
            label="Git admin marker",
        )
    finally:
        payload[:] = b"\x00" * len(payload)


def _verify_materializer_source_marker(
    binding: _MaterializerSourceMarkerBinding,
    source: pathlib.Path,
) -> None:
    try:
        metadata = binding.path.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            "materializer source Git admin marker cannot be inspected"
        ) from error
    current_identity = (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
    )
    expected_identity = (
        binding.device,
        binding.inode,
        binding.file_type,
        binding.owner,
    )
    if current_identity != expected_identity or stat.S_ISLNK(metadata.st_mode):
        raise NamedLaneGuardError(
            "materializer source Git admin marker changed during materialization"
        )
    if binding.is_gitfile:
        if not stat.S_ISREG(metadata.st_mode):
            raise NamedLaneGuardError(
                "materializer source Git admin marker changed during materialization"
            )
        current_admin = _read_materializer_gitfile_admin(binding.path, source)
        if current_admin != binding.expected_admin:
            raise NamedLaneGuardError(
                "materializer source Git admin marker changed during materialization"
            )
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise NamedLaneGuardError(
            "materializer source Git admin marker changed during materialization"
        )
    try:
        resolved = binding.path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materializer source Git admin marker cannot be resolved safely"
        ) from error
    if resolved != binding.expected_admin:
        raise NamedLaneGuardError(
            "materializer source Git admin marker changed during materialization"
        )


def _verify_materializer_source_back_pointer(
    marker: _MaterializerSourceMarkerBinding,
    admin: pathlib.Path,
) -> None:
    if not marker.is_gitfile:
        return
    gitdir_payload = _read_materializer_control_file(
        admin / "gitdir",
        label="Git admin back-pointer",
    )
    try:
        back_pointer = _materializer_control_path(
            gitdir_payload,
            relative_to=admin,
            label="Git admin back-pointer",
        )
    finally:
        gitdir_payload[:] = b"\x00" * len(gitdir_payload)
    if back_pointer != marker.path:
        raise NamedLaneGuardError(
            "materializer source Git admin directory does not match its exact marker"
        )


def _materializer_source_object_format_from_payload(
    config_payload: bytearray,
    oid_length: int,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
    *,
    timeout_seconds: float = MATERIALIZER_GIT_TIMEOUT_SECONDS,
) -> str:
    parsed = _materializer_git_capture(
        git,
        environment,
        hooks,
        ("config", "--file", "-", "--no-includes", "--null", "--list"),
        stdin=config_payload,
        timeout_seconds=timeout_seconds,
    )
    records = _parse_git_config_records(
        parsed,
        label="materializer source Git config",
    )
    if any(key.lower() == b"core.worktree" for key, _value in records):
        raise NamedLaneGuardError(
            "materializer source must name an exact Git worktree root"
        )
    if any(
        key.lower() == b"extensions.partialclone"
        or (key.lower().startswith(b"remote.") and key.lower().endswith(b".promisor"))
        for key, _value in records
    ):
        raise NamedLaneGuardError(
            "materializer source Git promisor configuration is not allowed"
        )
    repository_versions = [
        value
        for key, value in records
        if key.lower() == b"core.repositoryformatversion"
    ]
    object_formats = [
        value.lower() if value is not None else None
        for key, value in records
        if key.lower() == b"extensions.objectformat"
    ]
    if len(repository_versions) != 1 or repository_versions[0] not in {
        b"0",
        b"1",
    }:
        raise NamedLaneGuardError(
            "materializer source Git repository format is not supported"
        )
    expected = "sha256" if oid_length == 64 else "sha1"
    if expected == "sha256":
        valid = repository_versions == [b"1"] and object_formats == [b"sha256"]
    else:
        valid = object_formats in ([], [b"sha1"])
    if not valid:
        raise NamedLaneGuardError(
            "materializer source Git object format does not match frozen object IDs"
        )
    return expected


def _materializer_source_object_format(
    common: pathlib.Path,
    oid_length: int,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
    *,
    timeout_seconds: float = MATERIALIZER_GIT_TIMEOUT_SECONDS,
) -> str:
    try:
        config_payload = _read_materializer_control_file(
            common / "config",
            label="Git config",
        )
    except NamedLaneGuardError as error:
        raise NamedLaneGuardError(
            "materializer source must name an exact Git worktree root"
        ) from error
    try:
        return _materializer_source_object_format_from_payload(
            config_payload,
            oid_length,
            git,
            environment,
            hooks,
            timeout_seconds=timeout_seconds,
        )
    finally:
        config_payload[:] = b"\x00" * len(config_payload)


def _verify_materializer_source_storage(
    storage: _MaterializerSourceStorage,
) -> None:
    _verify_materializer_source_marker(storage.marker, storage.marker.path.parent)
    _verify_materializer_source_back_pointer(storage.marker, storage.admin)
    for path, expected, label in (
        (storage.admin, storage.admin_identity, "Git admin directory"),
        (storage.common, storage.common_identity, "Git common directory"),
        (storage.objects, storage.objects_identity, "Git object directory"),
    ):
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise NamedLaneGuardError(
                f"materializer source {label} cannot be inspected"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != _current_user_id()
            or resolved != path
            or _directory_identity(metadata) != expected
        ):
            raise NamedLaneGuardError(
                f"materializer source {label} changed during materialization"
            )

    info = storage.objects / "info"
    try:
        info_metadata = info.lstat()
        info_resolved = info.resolve(strict=True)
    except FileNotFoundError:
        info_metadata = None
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materializer source Git object-info storage cannot be inspected"
        ) from error
    if info_metadata is not None and (
        not stat.S_ISDIR(info_metadata.st_mode)
        or stat.S_ISLNK(info_metadata.st_mode)
        or info_metadata.st_uid != _current_user_id()
        or info_resolved != info
    ):
        raise NamedLaneGuardError(
            "materializer source Git object-info storage must be a real directory"
        )
    for candidate, label in (
        (info / "alternates", "alternates"),
        (info / "http-alternates", "HTTP alternates"),
        (storage.common / "shallow", "shallow repository state"),
        (storage.admin / "shallow", "per-worktree shallow repository state"),
    ):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise NamedLaneGuardError(
                f"materializer source Git {label} cannot be inspected"
            ) from error
        raise NamedLaneGuardError(f"materializer source Git {label} is not allowed")

    pack = storage.objects / "pack"
    try:
        pack_metadata = pack.lstat()
        pack_resolved = pack.resolve(strict=True)
    except FileNotFoundError:
        return
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materializer source Git pack storage cannot be inspected"
        ) from error
    if (
        not stat.S_ISDIR(pack_metadata.st_mode)
        or stat.S_ISLNK(pack_metadata.st_mode)
        or pack_metadata.st_uid != _current_user_id()
        or pack_resolved != pack
    ):
        raise NamedLaneGuardError(
            "materializer source Git pack storage must be a real directory"
        )
    try:
        with os.scandir(pack) as entries:
            for entry in entries:
                folded_name = entry.name.casefold()
                if folded_name.endswith(".promisor"):
                    raise NamedLaneGuardError(
                        "materializer source Git promisor state is not allowed"
                    )
                if folded_name.endswith(".bitmap"):
                    raise NamedLaneGuardError(
                        "materializer source Git bitmap cache is not allowed"
                    )
    except NamedLaneGuardError:
        raise
    except OSError as error:
        raise NamedLaneGuardError(
            "materializer source Git pack storage cannot be inspected"
        ) from error


def _validate_materializer_source_repository(
    source: pathlib.Path,
    marker_binding: _MaterializerSourceMarkerBinding,
    oid_length: int,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
    *,
    timeout_seconds: float = MATERIALIZER_GIT_TIMEOUT_SECONDS,
) -> _MaterializerSourceStorage:
    _verify_materializer_source_marker(marker_binding, source)
    marker = marker_binding.path
    expected_admin = marker_binding.expected_admin
    if marker_binding.is_gitfile:
        gitdir_payload = _read_materializer_control_file(
            expected_admin / "gitdir",
            label="Git admin back-pointer",
        )
        try:
            back_pointer = _materializer_control_path(
                gitdir_payload,
                relative_to=expected_admin,
                label="Git admin back-pointer",
            )
        finally:
            gitdir_payload[:] = b"\x00" * len(gitdir_payload)
        if back_pointer != marker:
            raise NamedLaneGuardError(
                "materializer source Git admin directory does not match its exact marker"
            )

    commondir = expected_admin / "commondir"
    try:
        commondir.lstat()
    except FileNotFoundError:
        common = expected_admin
    except OSError as error:
        raise NamedLaneGuardError(
            "materializer source Git common directory cannot be inspected"
        ) from error
    else:
        common_payload = _read_materializer_control_file(
            commondir,
            label="Git common-directory marker",
        )
        try:
            common = _materializer_control_path(
                common_payload,
                relative_to=expected_admin,
                label="Git common-directory marker",
            )
        finally:
            common_payload[:] = b"\x00" * len(common_payload)

    try:
        admin_metadata = expected_admin.lstat()
        common_metadata = common.lstat()
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materializer source Git control directories cannot be resolved safely"
        ) from error
    for path, metadata, label in (
        (expected_admin, admin_metadata, "admin"),
        (common, common_metadata, "common"),
    ):
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != _current_user_id()
            or path.resolve(strict=True) != path
        ):
            raise NamedLaneGuardError(
                f"materializer source Git {label} directory must be a real owned directory"
            )
    object_format = _materializer_source_object_format(
        common,
        oid_length,
        git,
        environment,
        hooks,
        timeout_seconds=timeout_seconds,
    )
    objects = common / "objects"
    try:
        objects_metadata = objects.lstat()
        objects_resolved = objects.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materializer source Git object storage cannot be resolved safely"
        ) from error
    if (
        not stat.S_ISDIR(objects_metadata.st_mode)
        or stat.S_ISLNK(objects_metadata.st_mode)
        or objects_metadata.st_uid != _current_user_id()
        or objects_resolved != objects
    ):
        raise NamedLaneGuardError(
            "materializer source Git object directory must be a real owned directory"
        )
    if os.pathsep in os.fspath(objects):
        raise NamedLaneGuardError(
            "materializer source Git object directory cannot be encoded as an alternate"
        )
    storage = _MaterializerSourceStorage(
        marker=marker_binding,
        admin=expected_admin,
        admin_identity=_directory_identity(admin_metadata),
        common=common,
        common_identity=_directory_identity(common_metadata),
        objects=objects,
        objects_identity=_directory_identity(objects_metadata),
        object_format=object_format,
    )
    _verify_materializer_source_storage(storage)
    return storage


def _bind_legacy_source_policy_path(
    path: pathlib.Path,
    *,
    expect_directory: bool,
    allowed_owners: tuple[int, ...] | None = None,
    allow_deny_acl: bool = False,
    deadline_monotonic: float,
) -> _LegacySourcePolicyBinding:
    _remaining_deadline_seconds(deadline_monotonic, "legacy prefix source policy")
    accepted_owners = allowed_owners or (_current_user_id(),)
    metadata = _legacy_policy_path_metadata(
        path,
        expect_directory=expect_directory,
        label="source path",
        allowed_owners=accepted_owners,
        allow_deny_acl=allow_deny_acl,
        deadline_monotonic=deadline_monotonic,
    )
    expected_type = stat.S_IFDIR if expect_directory else stat.S_IFREG
    if (
        stat.S_IFMT(metadata.st_mode) != expected_type
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid not in accepted_owners
    ):
        raise NamedLaneGuardError("legacy prefix source access policy is unsafe")
    mode = stat.S_IMODE(metadata.st_mode)
    sticky_root_custody = (
        allow_deny_acl and metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    )
    if mode & 0o022 and not sticky_root_custody:
        raise NamedLaneGuardError(
            "legacy prefix source access policy is group/world writable"
        )
    return _LegacySourcePolicyBinding(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        file_type=stat.S_IFMT(metadata.st_mode),
        owner=metadata.st_uid,
        mode=mode,
        allowed_owners=accepted_owners,
        allow_deny_acl=allow_deny_acl,
    )


def _verify_legacy_source_policy_path(
    binding: _LegacySourcePolicyBinding,
    deadline_monotonic: float,
) -> None:
    _remaining_deadline_seconds(deadline_monotonic, "legacy prefix source policy")
    metadata = _legacy_policy_path_metadata(
        binding.path,
        expect_directory=binding.file_type == stat.S_IFDIR,
        label="source path",
        allowed_owners=binding.allowed_owners,
        allow_deny_acl=binding.allow_deny_acl,
        deadline_monotonic=deadline_monotonic,
    )
    current = (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )
    expected = (
        binding.device,
        binding.inode,
        binding.file_type,
        binding.owner,
        binding.mode,
    )
    if current != expected or stat.S_ISLNK(metadata.st_mode):
        raise NamedLaneGuardError(
            "legacy prefix source identity or access policy changed"
        )
    sticky_root_custody = (
        binding.allow_deny_acl
        and binding.owner == 0
        and bool(binding.mode & stat.S_ISVTX)
    )
    if binding.mode & 0o022 and not sticky_root_custody:
        raise NamedLaneGuardError(
            "legacy prefix source access policy is group/world writable"
        )


def _verify_legacy_object_store_access_policy(
    storage: _MaterializerSourceStorage,
    deadline_monotonic: float,
) -> None:
    """Reject unsafe modes, extended ACLs, and special objects recursively.

    Prefix disambiguation observes the complete object-store namespace, not
    only the current head closure.  Stable access-policy admission therefore
    covers every filesystem entry that Git could consult.  Ordinary entry
    creation/removal remains child churn and is reevaluated at each query
    boundary; this scan is not a content snapshot or atomicity claim.
    """

    entry_count = 0
    pending = [storage.objects]
    while pending:
        _remaining_deadline_seconds(
            deadline_monotonic,
            "legacy prefix object-store policy inventory",
        )
        directory = pending.pop()
        directory_metadata = _legacy_policy_path_metadata(
            directory,
            expect_directory=True,
            label="source object-store directory",
        )
        if stat.S_IMODE(directory_metadata.st_mode) & 0o022:
            raise NamedLaneGuardError(
                "legacy prefix source object-store access policy is group/world writable"
            )
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entry_count += 1
                    if entry_count & 0xFF == 0:
                        _remaining_deadline_seconds(
                            deadline_monotonic,
                            "legacy prefix object-store policy inventory",
                        )
                    if entry_count > LEGACY_PREFIX_OBJECT_STORE_ENTRY_LIMIT:
                        raise NamedLaneGuardError(
                            "legacy prefix source object-store entry limit exceeded"
                        )
                    path = directory / entry.name
                    try:
                        metadata = path.lstat()
                    except OSError as error:
                        raise NamedLaneGuardError(
                            "legacy prefix source object-store entry cannot be inspected"
                        ) from error
                    file_type = stat.S_IFMT(metadata.st_mode)
                    if file_type == stat.S_IFDIR:
                        pending.append(path)
                        continue
                    if file_type != stat.S_IFREG:
                        raise NamedLaneGuardError(
                            "legacy prefix source object-store contains a special entry"
                        )
                    bound_metadata = _legacy_policy_path_metadata(
                        path,
                        expect_directory=False,
                        label="source object-store file",
                    )
                    if stat.S_IMODE(bound_metadata.st_mode) & 0o022:
                        raise NamedLaneGuardError(
                            "legacy prefix source object-store access policy is group/world writable"
                        )
        except NamedLaneGuardError:
            raise
        except OSError as error:
            raise NamedLaneGuardError(
                "legacy prefix source object-store inventory cannot be inspected"
            ) from error


def _legacy_source_content_binding(
    path: pathlib.Path,
    label: str,
    payload: bytes | bytearray,
) -> _LegacySourceContentBinding:
    return _LegacySourceContentBinding(
        path=path,
        label=label,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _read_legacy_source_content_binding(
    path: pathlib.Path,
    label: str,
) -> _LegacySourceContentBinding:
    payload = _read_materializer_control_file(path, label=label)
    try:
        return _legacy_source_content_binding(path, label, payload)
    finally:
        payload[:] = b"\x00" * len(payload)


def _bind_legacy_prefix_source(
    storage: _MaterializerSourceStorage,
    oid_length: int,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
    *,
    timeout_seconds: float,
    deadline_monotonic: float,
) -> _LegacyPrefixSourceBinding:
    _verify_materializer_source_storage(storage)
    config_payload = _read_materializer_control_file(
        storage.common / "config",
        label="Git config",
    )
    try:
        object_format = _materializer_source_object_format_from_payload(
            config_payload,
            oid_length,
            git,
            environment,
            hooks,
            timeout_seconds=timeout_seconds,
        )
        content_bindings = [
            _legacy_source_content_binding(
                storage.common / "config",
                "Git config",
                config_payload,
            )
        ]
    finally:
        config_payload[:] = b"\x00" * len(config_payload)
    if object_format != storage.object_format:
        raise NamedLaneGuardError(
            "legacy prefix source object format changed during setup"
        )
    policy_candidates: list[tuple[pathlib.Path, bool]] = [
        (storage.marker.path.parent, True),
        (storage.marker.path, not storage.marker.is_gitfile),
        (storage.admin, True),
        (storage.common, True),
        (storage.objects, True),
        (storage.common / "config", False),
    ]
    if storage.marker.is_gitfile:
        policy_candidates.append((storage.admin / "gitdir", False))
        content_bindings.extend(
            (
                _read_legacy_source_content_binding(
                    storage.marker.path,
                    "Git admin marker",
                ),
                _read_legacy_source_content_binding(
                    storage.admin / "gitdir",
                    "Git admin back-pointer",
                ),
            )
        )
    commondir = storage.admin / "commondir"
    try:
        commondir.lstat()
    except FileNotFoundError:
        commondir_present = False
    except OSError as error:
        raise NamedLaneGuardError(
            "legacy prefix source common-directory marker cannot be inspected"
        ) from error
    else:
        commondir_present = True
        policy_candidates.append((commondir, False))
        content_bindings.append(
            _read_legacy_source_content_binding(
                commondir,
                "Git common-directory marker",
            )
        )
    policy_bindings: list[_LegacySourcePolicyBinding] = []
    # Git receives absolute source paths. Bind every real ancestor that keeps
    # those paths in custody so another local UID cannot rename an unchecked
    # linked-worktree common directory between the point revalidations. Root-
    # owned ancestors are accepted; deny-only Darwin ACLs (for example the
    # standard home-directory delete denial) cannot grant mutation authority.
    custody_candidates: set[pathlib.Path] = set()
    for path, _expect_directory in policy_candidates:
        ancestor = path.parent
        while True:
            custody_candidates.add(ancestor)
            if ancestor.parent == ancestor:
                break
            ancestor = ancestor.parent
    custody_owners = tuple(sorted({_current_user_id(), 0}))
    custody_seen_paths: set[pathlib.Path] = set()
    for path in sorted(
        custody_candidates, key=lambda item: (len(item.parts), str(item))
    ):
        if path in custody_seen_paths:
            continue
        custody_seen_paths.add(path)
        policy_bindings.append(
            _bind_legacy_source_policy_path(
                path,
                expect_directory=True,
                allowed_owners=custody_owners,
                allow_deny_acl=True,
                deadline_monotonic=deadline_monotonic,
            )
        )
    strict_seen_paths: set[pathlib.Path] = set()
    for path, expect_directory in policy_candidates:
        if path in strict_seen_paths:
            continue
        strict_seen_paths.add(path)
        policy_bindings.append(
            _bind_legacy_source_policy_path(
                path,
                expect_directory=expect_directory,
                deadline_monotonic=deadline_monotonic,
            )
        )
    # Directory device/inode/type/owner protects object identity; regular-file
    # identity plus exact config/marker semantics protects the control inputs.
    # Mode is the separate access-policy signal. We intentionally ignore
    # mtime, ctime, nlink, directory size, and ordinary object child churn.
    binding = _LegacyPrefixSourceBinding(
        storage=storage,
        policy_bindings=tuple(policy_bindings),
        content_bindings=tuple(content_bindings),
        commondir_present=commondir_present,
        deadline_monotonic=deadline_monotonic,
    )
    _verify_legacy_object_store_access_policy(storage, deadline_monotonic)
    _verify_legacy_prefix_source(binding)
    return binding


def _verify_legacy_prefix_source(binding: _LegacyPrefixSourceBinding) -> None:
    storage = binding.storage
    _verify_materializer_source_storage(storage)
    for policy_binding in binding.policy_bindings:
        _verify_legacy_source_policy_path(
            policy_binding,
            binding.deadline_monotonic,
        )
    commondir = storage.admin / "commondir"
    try:
        commondir.lstat()
    except FileNotFoundError:
        if binding.commondir_present:
            raise NamedLaneGuardError(
                "legacy prefix source common-directory marker changed"
            )
    except OSError as error:
        raise NamedLaneGuardError(
            "legacy prefix source common-directory marker cannot be revalidated"
        ) from error
    else:
        if not binding.commondir_present:
            raise NamedLaneGuardError(
                "legacy prefix source common-directory marker changed"
            )
        commondir_payload = _read_materializer_control_file(
            commondir,
            label="Git common-directory marker",
        )
        try:
            current_common = _materializer_control_path(
                commondir_payload,
                relative_to=storage.admin,
                label="Git common-directory marker",
            )
        finally:
            commondir_payload[:] = b"\x00" * len(commondir_payload)
        if current_common != storage.common:
            raise NamedLaneGuardError(
                "legacy prefix source common-directory marker changed"
            )
    for content_binding in binding.content_bindings:
        payload = _read_materializer_control_file(
            content_binding.path,
            label=content_binding.label,
        )
        try:
            if (
                len(payload) != content_binding.size
                or hashlib.sha256(payload).hexdigest() != content_binding.sha256
            ):
                raise NamedLaneGuardError(
                    "legacy prefix source control content changed during "
                    "receipt generation"
                )
        finally:
            payload[:] = b"\x00" * len(payload)
    _verify_legacy_object_store_access_policy(
        storage,
        binding.deadline_monotonic,
    )
    _verify_materializer_source_storage(storage)


def _legacy_prefix_view_config(object_format: str) -> bytes:
    repository_version = "1" if object_format == "sha256" else "0"
    payload = (
        "[core]\n"
        f"\trepositoryformatversion = {repository_version}\n"
        "\tfilemode = true\n"
        "\tbare = true\n"
        "\tlogallrefupdates = false\n"
        "\tcommitGraph = false\n"
        "\tmultiPackIndex = false\n"
    )
    if object_format == "sha256":
        payload += "[extensions]\n\tobjectformat = sha256\n"
    return payload.encode("ascii")


def _legacy_prefix_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
    )


def _write_legacy_prefix_view_file(
    path: pathlib.Path, payload: bytes
) -> tuple[int, int, int, int]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        descriptor_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_metadata.st_mode)
            or descriptor_metadata.st_uid != _current_user_id()
            or stat.S_IMODE(descriptor_metadata.st_mode) != 0o600
            or descriptor_metadata.st_nlink != 1
            or descriptor_metadata.st_size != len(payload)
        ):
            raise NamedLaneGuardError(
                "legacy prefix Git view file could not be bound safely"
            )
        _require_no_legacy_extended_acl(
            descriptor,
            label="Git view file",
        )
        identity = _legacy_prefix_file_identity(descriptor_metadata)
    except NamedLaneGuardError:
        raise
    except OSError as error:
        raise NamedLaneGuardError(
            "legacy prefix Git view file could not be created safely"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        lexical_metadata = path.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            "legacy prefix Git view file could not be revalidated"
        ) from error
    if (
        _legacy_prefix_file_identity(lexical_metadata) != identity
        or stat.S_IMODE(lexical_metadata.st_mode) != 0o600
        or lexical_metadata.st_nlink != 1
    ):
        raise NamedLaneGuardError("legacy prefix Git view file changed during setup")
    return identity


def _make_legacy_prefix_view(
    root: pathlib.Path,
    root_identity: _DirectoryIdentity,
    object_format: str,
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
    deadline_monotonic: float,
) -> _LegacyPrefixViewBinding:
    _verify_legacy_prefix_parent(parent, parent_identity, deadline_monotonic)
    bound_root_metadata = _legacy_policy_path_metadata(
        root,
        expect_directory=True,
        label="Git view root",
    )
    if (
        _directory_identity(bound_root_metadata) != root_identity
        or stat.S_IMODE(bound_root_metadata.st_mode) != 0o700
    ):
        raise NamedLaneGuardError(
            "legacy prefix Git view root access policy changed during setup"
        )
    objects = root / "objects"
    refs = root / "refs"
    directory_identities: dict[str, _DirectoryIdentity] = {}
    for path in (objects, refs):
        try:
            path.mkdir(mode=0o700)
            path.chmod(0o700)
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise NamedLaneGuardError(
                "legacy prefix Git view directories could not be created safely"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != _current_user_id()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or resolved != path
        ):
            raise NamedLaneGuardError(
                "legacy prefix Git view directories are not owner-private"
            )
        bound_metadata = _legacy_policy_path_metadata(
            path,
            expect_directory=True,
            label="Git view directory",
        )
        if _directory_identity(bound_metadata) != _directory_identity(metadata):
            raise NamedLaneGuardError(
                "legacy prefix Git view directory changed during setup"
            )
        directory_identities[path.name] = _directory_identity(metadata)
    config_bytes = _legacy_prefix_view_config(object_format)
    head_bytes = b"ref: refs/heads/named-lane-empty\n"
    config_identity = _write_legacy_prefix_view_file(root / "config", config_bytes)
    head_identity = _write_legacy_prefix_view_file(root / "HEAD", head_bytes)
    binding = _LegacyPrefixViewBinding(
        root=root,
        root_identity=root_identity,
        objects_identity=directory_identities["objects"],
        refs_identity=directory_identities["refs"],
        config_identity=config_identity,
        head_identity=head_identity,
        config_bytes=config_bytes,
        head_bytes=head_bytes,
        deadline_monotonic=deadline_monotonic,
    )
    _verify_legacy_prefix_view(binding, parent, parent_identity)
    return binding


def _verify_legacy_prefix_view_file(
    path: pathlib.Path,
    expected_identity: tuple[int, int, int, int],
    expected_payload: bytes,
) -> None:
    payload = _read_materializer_control_file(
        path,
        label="legacy prefix Git view file",
    )
    try:
        metadata = _legacy_policy_path_metadata(
            path,
            expect_directory=False,
            label="Git view file",
        )
        if (
            _legacy_prefix_file_identity(metadata) != expected_identity
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or bytes(payload) != expected_payload
        ):
            raise NamedLaneGuardError(
                "legacy prefix Git view file changed during receipt generation"
            )
    except OSError as error:
        raise NamedLaneGuardError(
            "legacy prefix Git view file cannot be inspected"
        ) from error
    finally:
        payload[:] = b"\x00" * len(payload)


def _verify_legacy_prefix_view(
    binding: _LegacyPrefixViewBinding,
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
) -> None:
    # Root/objects/refs device+inode+type+owner protect view object identity;
    # exact 0700/0600 modes protect its owner-only access policy; no-follow,
    # single-link identity plus exact bytes protect config/HEAD content
    # stability. Directory timestamps and link counts are not mutation evidence.
    _verify_legacy_prefix_parent(
        parent,
        parent_identity,
        binding.deadline_monotonic,
    )
    root = binding.root
    try:
        root_metadata = _legacy_policy_path_metadata(
            root,
            expect_directory=True,
            label="Git view root",
        )
        root_resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "legacy prefix Git view cannot be inspected"
        ) from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != _current_user_id()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or root_resolved != root
        or root.parent != parent
        or _directory_identity(root_metadata) != binding.root_identity
    ):
        raise NamedLaneGuardError(
            "legacy prefix Git view changed during receipt generation"
        )
    try:
        root_entries = sorted(entry.name for entry in os.scandir(root))
    except OSError as error:
        raise NamedLaneGuardError(
            "legacy prefix Git view inventory cannot be inspected"
        ) from error
    if root_entries != ["HEAD", "config", "objects", "refs"]:
        raise NamedLaneGuardError(
            "legacy prefix Git view inventory changed during receipt generation"
        )
    for name, expected in (
        ("objects", binding.objects_identity),
        ("refs", binding.refs_identity),
    ):
        path = root / name
        try:
            metadata = _legacy_policy_path_metadata(
                path,
                expect_directory=True,
                label="Git view storage",
            )
            resolved = path.resolve(strict=True)
            entries = tuple(os.scandir(path))
        except (OSError, RuntimeError) as error:
            raise NamedLaneGuardError(
                "legacy prefix Git view storage cannot be inspected"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != _current_user_id()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or resolved != path
            or _directory_identity(metadata) != expected
            or entries
        ):
            raise NamedLaneGuardError(
                "legacy prefix Git view storage changed during receipt generation"
            )
    _verify_legacy_prefix_view_file(
        root / "config",
        binding.config_identity,
        binding.config_bytes,
    )
    _verify_legacy_prefix_view_file(
        root / "HEAD",
        binding.head_identity,
        binding.head_bytes,
    )
    _verify_legacy_prefix_parent(
        parent,
        parent_identity,
        binding.deadline_monotonic,
    )


def _bind_legacy_prefix_control(
    root: pathlib.Path,
    root_identity: _DirectoryIdentity,
    directories: Mapping[str, pathlib.Path],
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
    deadline_monotonic: float,
) -> _LegacyPrefixControlBinding:
    _verify_legacy_prefix_parent(parent, parent_identity, deadline_monotonic)
    root_metadata = _legacy_policy_path_metadata(
        root,
        expect_directory=True,
        label="control root",
    )
    if (
        _directory_identity(root_metadata) != root_identity
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise NamedLaneGuardError("legacy prefix control root access policy is unsafe")
    children: list[tuple[pathlib.Path, _DirectoryIdentity]] = []
    for name in ("home", "hooks", "template", "tmp", "xdg"):
        path = directories[name]
        try:
            metadata = _legacy_policy_path_metadata(
                path,
                expect_directory=True,
                label="control child",
            )
        except OSError as error:
            raise NamedLaneGuardError(
                "legacy prefix control directory cannot be bound"
            ) from error
        children.append((path, _directory_identity(metadata)))
    binding = _LegacyPrefixControlBinding(
        root=root,
        root_identity=root_identity,
        children=tuple(children),
        deadline_monotonic=deadline_monotonic,
    )
    _verify_legacy_prefix_control(binding, parent, parent_identity)
    return binding


def _verify_legacy_prefix_control(
    binding: _LegacyPrefixControlBinding,
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
) -> None:
    # Device/inode/type/owner bind the control hierarchy's object identity;
    # exact 0700 and empty fixed inventory bind its access policy and exclude
    # attacker-selected config, hooks, templates, and cwd content. Directory
    # mtime/ctime/nlink churn is not used as mutation evidence.
    _verify_legacy_prefix_parent(
        parent,
        parent_identity,
        binding.deadline_monotonic,
    )
    try:
        root_metadata = _legacy_policy_path_metadata(
            binding.root,
            expect_directory=True,
            label="control root",
        )
        root_resolved = binding.root.resolve(strict=True)
        with os.scandir(binding.root) as entries:
            root_entries = sorted(entry.name for entry in entries)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "legacy prefix control directory cannot be revalidated"
        ) from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != _current_user_id()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or root_resolved != binding.root
        or binding.root.parent != parent
        or _directory_identity(root_metadata) != binding.root_identity
        or root_entries != ["home", "hooks", "template", "tmp", "xdg"]
    ):
        raise NamedLaneGuardError(
            "legacy prefix control directory changed during receipt generation"
        )
    for path, expected_identity in binding.children:
        try:
            metadata = _legacy_policy_path_metadata(
                path,
                expect_directory=True,
                label="control child",
            )
            resolved = path.resolve(strict=True)
            with os.scandir(path) as entries:
                has_entries = next(entries, None) is not None
        except (OSError, RuntimeError) as error:
            raise NamedLaneGuardError(
                "legacy prefix control child cannot be revalidated"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != _current_user_id()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or resolved != path
            or path.parent != binding.root
            or _directory_identity(metadata) != expected_identity
            or has_entries
        ):
            raise NamedLaneGuardError(
                "legacy prefix control child changed during receipt generation"
            )
    _verify_legacy_prefix_parent(
        parent,
        parent_identity,
        binding.deadline_monotonic,
    )


def _legacy_prefix_git_environment(objects: pathlib.Path) -> dict[str, str]:
    return {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OBJECT_DIRECTORY": str(objects),
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": TRUSTED_PATH,
        "SSH_ASKPASS": "/usr/bin/false",
    }


def _legacy_prefix_git_prefix(
    git: pathlib.Path,
    view: pathlib.Path,
) -> tuple[str, ...]:
    return (
        str(git),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        f"--git-dir={view}",
    )


def _legacy_prefix_git_capture(
    git: pathlib.Path,
    environment: Mapping[str, str],
    cwd: pathlib.Path,
    view: _LegacyPrefixViewBinding,
    source: _LegacyPrefixSourceBinding,
    control: _LegacyPrefixControlBinding,
    parent: pathlib.Path,
    parent_identity: _DirectoryIdentity,
    arguments: Sequence[str],
    allowed_returncodes: frozenset[int],
    deadline_monotonic: float,
) -> tuple[int, bytes]:
    _verify_legacy_prefix_source(source)
    _verify_legacy_prefix_view(view, parent, parent_identity)
    _verify_legacy_prefix_control(control, parent, parent_identity)
    command = (*_legacy_prefix_git_prefix(git, view.root), *arguments)
    capture = None
    process_error: BaseException | None = None
    try:
        try:
            capture = run_bounded_capture(
                command,
                cwd=cwd,
                env=dict(environment),
                timeout_seconds=min(
                    30.0,
                    _remaining_deadline_seconds(
                        deadline_monotonic,
                        "legacy prefix receipt",
                    ),
                ),
                stdout_limit_bytes=LEGACY_PREFIX_RECEIPT_OUTPUT_LIMIT_BYTES,
                stderr_limit_bytes=LEGACY_PREFIX_RECEIPT_OUTPUT_LIMIT_BYTES,
            )
        except BaseException as error:
            process_error = error
        try:
            _verify_legacy_prefix_source(source)
            _verify_legacy_prefix_view(view, parent, parent_identity)
            _verify_legacy_prefix_control(control, parent, parent_identity)
        except BaseException as revalidation_error:
            if process_error is not None:
                raise revalidation_error from process_error
            raise
        if process_error is not None:
            raise process_error
        assert capture is not None
        if capture.stderr or capture.returncode not in allowed_returncodes:
            raise NamedLaneGuardError("legacy-prefix-git-process")
        return capture.returncode, bytes(capture.stdout)
    finally:
        if capture is not None:
            capture.stdout[:] = b"\x00" * len(capture.stdout)
            capture.stderr[:] = b"\x00" * len(capture.stderr)


def _parse_legacy_disambiguation(
    payload: bytes,
    raw_prefix: str,
    oid_length: int,
) -> str:
    if not payload or not payload.endswith(b"\n") or b"\r" in payload:
        raise LegacyPrefixReceiptInconclusive("legacy-prefix-not-unique")
    lines = payload[:-1].split(b"\n")
    if len(lines) != 1:
        raise LegacyPrefixReceiptInconclusive("legacy-prefix-not-unique")
    try:
        object_id = lines[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise LegacyPrefixReceiptInconclusive("legacy-prefix-not-unique") from error
    if (
        len(object_id) != oid_length
        or LOWER_FULL_OBJECT_ID.fullmatch(object_id) is None
        or not object_id.startswith(raw_prefix)
    ):
        raise LegacyPrefixReceiptInconclusive("legacy-prefix-not-unique")
    return object_id


def _parse_legacy_object_type(payload: bytes) -> str:
    if (
        not payload.endswith(b"\n")
        or payload.count(b"\n") != 1
        or b"\r" in payload
        or not payload[:-1]
    ):
        raise NamedLaneGuardError("legacy-prefix-git-output")
    try:
        object_type = payload[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise NamedLaneGuardError("legacy-prefix-git-output") from error
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", object_type) is None:
        raise NamedLaneGuardError("legacy-prefix-git-output")
    return object_type


def legacy_short_prefix_receipts(
    source: pathlib.Path,
    temporary_path: pathlib.Path,
    head_sha: str,
    phase: str,
    prefixes: Sequence[str],
    *,
    defer_signal_handoff: bool = False,
) -> LegacyPrefixReceiptResult:
    if LOWER_FULL_OBJECT_ID.fullmatch(head_sha) is None:
        raise NamedLaneGuardError(
            "legacy prefix receipt head must be a full lowercase Git object ID"
        )
    if phase not in {"initial", "final"}:
        raise NamedLaneGuardError("legacy prefix receipt phase is invalid")
    if len(prefixes) > 1_024:
        raise NamedLaneGuardError("legacy prefix receipt count limit exceeded")
    if any(LEGACY_SHORT_OBJECT_PREFIX.fullmatch(prefix) is None for prefix in prefixes):
        raise NamedLaneGuardError(
            "legacy prefix receipt prefixes must be exact lowercase 10-hex values"
        )
    if len(set(prefixes)) != len(prefixes):
        raise NamedLaneGuardError("legacy prefix receipt prefixes must be unique")
    sorted_prefixes = tuple(sorted(prefixes))

    deadline = time.monotonic() + LEGACY_PREFIX_RECEIPT_TIMEOUT_SECONDS
    frozen_head = head_sha
    _remaining_deadline_seconds(deadline, "legacy prefix receipt")
    resolved_source, source_marker = _resolve_materializer_source(source)
    _remaining_deadline_seconds(deadline, "legacy prefix receipt")
    view_path, parent, parent_identity = _validate_materializer_parent(temporary_path)
    git = resolve_git()
    _verify_legacy_prefix_parent(parent, parent_identity, deadline)
    parent_fd = _open_legacy_prefix_parent_descriptor(parent, parent_identity)
    control: pathlib.Path | None = None
    directories: dict[str, pathlib.Path] | None = None
    control_identity: _DirectoryIdentity | None = None
    control_binding: _LegacyPrefixControlBinding | None = None
    view_started = False
    view_identity: _DirectoryIdentity | None = None
    failure: BaseException | None = None
    result: LegacyPrefixReceiptResult | None = None
    cleanup_mask: set[signal.Signals] | None = None
    cleanup_acquisition_signal: ForwardedSignal | None = None
    try:
        control_setup_mask = block_forwarded_signals()
        if control_setup_mask is None:
            raise NamedLaneGuardError(
                "legacy prefix control setup requires main-thread signal masking"
            )
        try:
            control, directories, control_identity = (
                _make_materializer_control_directory(
                    parent,
                    parent_identity,
                )
            )
            control_binding = _bind_legacy_prefix_control(
                control,
                control_identity,
                directories,
                parent,
                parent_identity,
                deadline,
            )
            control_setup_signal = consume_pending_forwarded_signal()
            if control_setup_signal is not None:
                raise ForwardedSignal(control_setup_signal)
        except BaseException:
            if defer_signal_handoff:
                _restore_materializer_terminal_failure_mask(control_setup_mask)
            else:
                restore_signal_mask(control_setup_mask)
            raise
        else:
            restore_signal_mask(control_setup_mask)
        materializer_environment = _materializer_git_environment(
            directories,
            parent,
        )
        _validate_materializer_git_version(
            git,
            materializer_environment,
            directories["tmp"],
            timeout_seconds=min(
                30.0,
                _remaining_deadline_seconds(
                    deadline,
                    "legacy prefix receipt",
                ),
            ),
        )
        _verify_legacy_prefix_control(
            control_binding,
            parent,
            parent_identity,
        )
        source_storage = _validate_materializer_source_repository(
            resolved_source,
            source_marker,
            len(frozen_head),
            git,
            materializer_environment,
            directories["hooks"],
            timeout_seconds=_remaining_deadline_seconds(
                deadline,
                "legacy prefix receipt",
            ),
        )
        _verify_legacy_prefix_control(
            control_binding,
            parent,
            parent_identity,
        )
        source_binding = _bind_legacy_prefix_source(
            source_storage,
            len(frozen_head),
            git,
            materializer_environment,
            directories["hooks"],
            timeout_seconds=_remaining_deadline_seconds(
                deadline,
                "legacy prefix receipt",
            ),
            deadline_monotonic=deadline,
        )
        _verify_legacy_prefix_control(
            control_binding,
            parent,
            parent_identity,
        )
        view_setup_mask = block_forwarded_signals()
        if view_setup_mask is None:
            raise NamedLaneGuardError(
                "legacy prefix view setup requires main-thread signal masking"
            )
        try:
            _verify_legacy_prefix_parent(parent, parent_identity, deadline)
            view_path.mkdir(mode=0o700)
            view_started = True
            view_metadata = _legacy_policy_path_metadata(
                view_path,
                expect_directory=True,
                label="Git view root",
            )
            view_identity = _directory_identity(view_metadata)
            view_path.chmod(0o700)
            if (
                not stat.S_ISDIR(view_metadata.st_mode)
                or stat.S_ISLNK(view_metadata.st_mode)
                or view_metadata.st_uid != _current_user_id()
                or view_path.resolve(strict=True) != view_path
                or stat.S_IMODE(view_path.lstat().st_mode) != 0o700
                or _directory_identity(view_path.lstat()) != view_identity
            ):
                raise NamedLaneGuardError(
                    "legacy prefix Git view must be an owner-private real directory"
                )
            view_binding = _make_legacy_prefix_view(
                view_path,
                view_identity,
                source_storage.object_format,
                parent,
                parent_identity,
                deadline,
            )
            view_setup_signal = consume_pending_forwarded_signal()
            if view_setup_signal is not None:
                raise ForwardedSignal(view_setup_signal)
        except BaseException:
            if defer_signal_handoff:
                _restore_materializer_terminal_failure_mask(view_setup_mask)
            else:
                restore_signal_mask(view_setup_mask)
            raise
        else:
            restore_signal_mask(view_setup_mask)
        query_environment = _legacy_prefix_git_environment(source_storage.objects)
        head_returncode, head_type_payload = _legacy_prefix_git_capture(
            git,
            query_environment,
            directories["tmp"],
            view_binding,
            source_binding,
            control_binding,
            parent,
            parent_identity,
            ("cat-file", "-t", frozen_head),
            frozenset({0}),
            deadline,
        )
        if (
            head_returncode != 0
            or _parse_legacy_object_type(head_type_payload) != "commit"
        ):
            raise NamedLaneGuardError(
                "legacy prefix receipt head must name an exact commit"
            )
        completeness_returncode, completeness_payload = _legacy_prefix_git_capture(
            git,
            query_environment,
            directories["tmp"],
            view_binding,
            source_binding,
            control_binding,
            parent,
            parent_identity,
            (
                "rev-list",
                "--objects",
                "--missing=error",
                "--quiet",
                frozen_head,
                "--",
            ),
            frozenset({0}),
            deadline,
        )
        if completeness_returncode != 0 or completeness_payload:
            raise NamedLaneGuardError("legacy-prefix-git-output")
        if any(prefix == frozen_head[:10] for prefix in sorted_prefixes):
            raise LegacyPrefixReceiptInconclusive("legacy-prefix-is-current-head")

        receipts: list[dict[str, object]] = []
        for raw_prefix in sorted_prefixes:
            disambiguate_returncode, disambiguated_payload = _legacy_prefix_git_capture(
                git,
                query_environment,
                directories["tmp"],
                view_binding,
                source_binding,
                control_binding,
                parent,
                parent_identity,
                ("rev-parse", f"--disambiguate={raw_prefix}"),
                frozenset({0}),
                deadline,
            )
            resolved_object = _parse_legacy_disambiguation(
                disambiguated_payload,
                raw_prefix,
                len(frozen_head),
            )
            type_returncode, type_payload = _legacy_prefix_git_capture(
                git,
                query_environment,
                directories["tmp"],
                view_binding,
                source_binding,
                control_binding,
                parent,
                parent_identity,
                ("cat-file", "-t", resolved_object),
                frozenset({0}),
                deadline,
            )
            object_type = _parse_legacy_object_type(type_payload)
            if object_type != "commit":
                raise LegacyPrefixReceiptInconclusive("legacy-prefix-not-commit")
            ancestry_returncode, ancestry_payload = _legacy_prefix_git_capture(
                git,
                query_environment,
                directories["tmp"],
                view_binding,
                source_binding,
                control_binding,
                parent,
                parent_identity,
                (
                    "merge-base",
                    "--is-ancestor",
                    resolved_object,
                    frozen_head,
                ),
                frozenset({0, 1}),
                deadline,
            )
            if ancestry_payload:
                raise NamedLaneGuardError("legacy-prefix-git-output")
            if ancestry_returncode == 1:
                raise LegacyPrefixReceiptInconclusive("legacy-prefix-not-ancestor")
            # The full object ID binds the selected object; the exact type and
            # ancestry queries bind the semantics observed by these ordered
            # point queries. Source-container identity/access revalidation does
            # not freeze loose or packed object bytes: same-UID content or
            # prefix-inventory churn, intra-phase ABA, and ABA between
            # independent initial/final invocations remain outside the claim.
            receipts.append(
                {
                    "raw_prefix": raw_prefix,
                    "head": frozen_head,
                    "disambiguate_return_code": disambiguate_returncode,
                    "disambiguated_object_ids": [resolved_object],
                    "commit_object_check_return_code": type_returncode,
                    "object_type": object_type,
                    "ancestry_return_code": ancestry_returncode,
                }
            )
        _verify_legacy_prefix_source(source_binding)
        _verify_legacy_prefix_view(view_binding, parent, parent_identity)
        _verify_legacy_prefix_control(control_binding, parent, parent_identity)
        result = LegacyPrefixReceiptResult(
            phase=phase,
            head_sha=frozen_head,
            receipts=tuple(receipts),
        )
    except BaseException as error:
        failure = error
    finally:
        cleanup_mask, cleanup_acquisition_signal = _block_materializer_cleanup_signals()

    if cleanup_acquisition_signal is not None and failure is None:
        failure = cleanup_acquisition_signal
    if defer_signal_handoff and cleanup_mask is None and failure is None:
        failure = NamedLaneGuardError(
            "legacy prefix receipt handoff requires main-thread signal masking"
        )
    retained_view: pathlib.Path | None = None
    if view_started:
        retained_view = _cleanup_legacy_prefix_path(
            view_path,
            parent,
            parent_identity,
            view_identity,
        )
    retained_control: pathlib.Path | None = None
    if control is not None and control_identity is not None:
        retained_control = _cleanup_legacy_prefix_path(
            control,
            parent,
            parent_identity,
            control_identity,
        )
    pending_cleanup_signal = (
        consume_pending_forwarded_signal() if cleanup_mask is not None else None
    )
    if pending_cleanup_signal is not None and failure is None:
        failure = ForwardedSignal(pending_cleanup_signal)
    retained: list[str] = []
    if retained_view is not None:
        retained.append(
            _legacy_prefix_retained_evidence(
                label="temporary",
                path=retained_view,
                expected_identity=view_identity,
                parent=parent,
                parent_identity=parent_identity,
                parent_fd=parent_fd,
            )
        )
    if retained_control is not None:
        retained.append(
            _legacy_prefix_retained_evidence(
                label="control",
                path=retained_control,
                expected_identity=control_identity,
                parent=parent,
                parent_identity=parent_identity,
                parent_fd=parent_fd,
            )
        )
    with contextlib.suppress(OSError):
        os.close(parent_fd)
    if retained:
        detail = "; ".join(retained)
        terminal_failure = NamedLaneGuardError(detail)
        if defer_signal_handoff:
            _restore_materializer_terminal_failure_mask(cleanup_mask)
        else:
            restore_signal_mask(cleanup_mask)
        if failure is None:
            raise terminal_failure
        raise terminal_failure from failure
    if failure is not None:
        if defer_signal_handoff:
            _restore_materializer_terminal_failure_mask(cleanup_mask)
        else:
            restore_signal_mask(cleanup_mask)
        raise failure
    if control is None or directories is None or control_identity is None:
        if defer_signal_handoff:
            _restore_materializer_terminal_failure_mask(cleanup_mask)
        else:
            restore_signal_mask(cleanup_mask)
        raise NamedLaneGuardError("legacy prefix receipt setup was incomplete")
    assert result is not None
    if defer_signal_handoff:
        assert cleanup_mask is not None
        object.__setattr__(result, "_handoff_signal_mask", cleanup_mask)
    else:
        restore_signal_mask(cleanup_mask)
    return result


def _validate_materialized_admin_directory(
    root: pathlib.Path,
    *,
    expected_local_config: _LocalConfigBinding | None = None,
) -> pathlib.Path:
    git_directory = root / ".git"
    try:
        metadata = git_directory.lstat()
        resolved = git_directory.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materialized repository does not have a private Git directory"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != _current_user_id()
        or resolved != git_directory
    ):
        raise NamedLaneGuardError(
            "materialized repository does not have a private Git directory"
        )
    config = git_directory / "config"
    try:
        config_metadata = config.lstat()
    except FileNotFoundError as error:
        raise _ControlObjectGuardError(
            "materialized-git-config-missing",
            "materialized local Git config is missing",
        ) from error
    except OSError as error:
        raise _ControlObjectGuardError(
            "materialized-git-config-inspection-failure",
            "materialized local Git config cannot be inspected",
        ) from error
    if expected_local_config is not None:
        _require_local_config_matches_binding(
            config_metadata,
            expected_local_config,
            context="during the protected window",
        )
    if (
        not stat.S_ISREG(config_metadata.st_mode)
        or stat.S_ISLNK(config_metadata.st_mode)
        or config_metadata.st_uid != _current_user_id()
    ):
        raise _ControlObjectGuardError(
            "materialized-git-config-access-policy-mismatch",
            "materialized local Git config has an unsafe access policy",
        )
    commondir = git_directory / "commondir"
    try:
        commondir.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized Git commondir state cannot be inspected"
        ) from error
    else:
        raise NamedLaneGuardError("materialized Git commondir state is not allowed")
    worktree_config = git_directory / "config.worktree"
    try:
        worktree_config.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized per-worktree Git config cannot be inspected"
        ) from error
    else:
        raise NamedLaneGuardError("materialized per-worktree Git config is not allowed")
    return git_directory


def _git_info_binding(metadata: os.stat_result) -> _GitInfoBinding:
    return _GitInfoBinding(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        file_type=stat.S_IFMT(metadata.st_mode),
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _require_git_info_binding_unchanged(
    actual: _GitInfoBinding,
    expected: _GitInfoBinding,
    *,
    context: str,
) -> None:
    _require_control_properties_unchanged(
        "materialized Git info directory",
        "materialized-git-info",
        context,
        actual_identity=(actual.device, actual.inode, actual.file_type),
        expected_identity=(expected.device, expected.inode, expected.file_type),
        actual_content=None,
        expected_content=None,
        actual_access_policy=(actual.owner, actual.mode),
        expected_access_policy=(expected.owner, expected.mode),
    )


def _bind_materialized_git_info(
    git_directory: pathlib.Path,
    *,
    create: bool = False,
    expected: _GitInfoBinding | None = None,
) -> _GitInfoBinding:
    info = git_directory / "info"
    if create:
        try:
            info.mkdir(mode=0o700, exist_ok=True)
            os.chmod(info, 0o700, follow_symlinks=False)
        except (NotImplementedError, OSError) as error:
            raise NamedLaneGuardError(
                "materialized Git info directory cannot be made owner-private"
            ) from error
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if directory_flag is None or nofollow is None or nonblocking is None:
        raise NamedLaneGuardError(
            "materialized Git info directory requires no-follow inspection"
        )
    descriptor = -1
    try:
        before = info.lstat()
        before_binding = _git_info_binding(before)
        if expected is not None:
            _require_git_info_binding_unchanged(
                before_binding,
                expected,
                context="during the protected window",
            )
        resolved = info.resolve(strict=True)
        descriptor = os.open(
            info,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | directory_flag
            | nofollow
            | nonblocking,
        )
        opened = os.fstat(descriptor)
        opened_binding = _git_info_binding(opened)
        _require_git_info_binding_unchanged(
            opened_binding,
            before_binding,
            context="during inspection",
        )
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != _current_user_id()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or resolved != info
        ):
            raise _ControlObjectGuardError(
                "materialized-git-info-access-policy-mismatch",
                "materialized Git info directory must be an owner-private real directory",
            )
        _require_no_control_extended_acl(
            descriptor,
            label="materialized Git info directory",
            reason_prefix="materialized-git-info",
        )
        try:
            os.stat("grafts", dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise _ControlObjectGuardError(
                "materialized-git-info-inspection-failure",
                "materialized Git graft state cannot be inspected",
            ) from error
        else:
            raise _ControlObjectGuardError(
                "materialized-git-info-content-mismatch",
                "materialized Git graft state is not allowed",
            )
        final_opened = os.fstat(descriptor)
        final_path = info.lstat()
        _require_no_control_extended_acl(
            descriptor,
            label="materialized Git info directory",
            reason_prefix="materialized-git-info",
        )
        _require_git_info_binding_unchanged(
            _git_info_binding(final_opened),
            opened_binding,
            context="during inspection",
        )
        _require_git_info_binding_unchanged(
            _git_info_binding(final_path),
            opened_binding,
            context="during inspection",
        )
        if expected is not None:
            _require_git_info_binding_unchanged(
                opened_binding,
                expected,
                context="during the protected window",
            )
        # Child-entry churn changes timestamps, link count, and directory size
        # without changing custody. These are intentionally excluded; the
        # opened identity/access policy and graft absence are the properties.
        return opened_binding
    except NamedLaneGuardError:
        raise
    except FileNotFoundError as error:
        raise _ControlObjectGuardError(
            "materialized-git-info-missing",
            "materialized Git info directory is missing",
        ) from error
    except (OSError, RuntimeError) as error:
        raise _ControlObjectGuardError(
            "materialized-git-info-inspection-failure",
            "materialized Git info directory cannot be inspected",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_materialized_object_storage(
    git_directory: pathlib.Path,
    *,
    expected_shallow_boundary: str | None = None,
    remove_bitmaps: bool = False,
) -> None:
    objects = git_directory / "objects"
    try:
        objects_metadata = objects.lstat()
        objects_resolved = objects.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materialized Git object storage cannot be inspected"
        ) from error
    if (
        not stat.S_ISDIR(objects_metadata.st_mode)
        or stat.S_ISLNK(objects_metadata.st_mode)
        or objects_metadata.st_uid != _current_user_id()
        or objects_resolved != objects
    ):
        raise NamedLaneGuardError(
            "materialized Git object storage must be a real directory"
        )

    info = objects / "info"
    try:
        info_metadata = info.lstat()
        info_resolved = info.resolve(strict=True)
    except FileNotFoundError:
        info_metadata = None
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materialized Git object-info storage cannot be inspected"
        ) from error
    if info_metadata is not None and (
        not stat.S_ISDIR(info_metadata.st_mode)
        or stat.S_ISLNK(info_metadata.st_mode)
        or info_metadata.st_uid != _current_user_id()
        or info_resolved != info
    ):
        raise NamedLaneGuardError(
            "materialized Git object-info storage must be a real directory"
        )
    alternates = info / "alternates"
    http_alternates = info / "http-alternates"
    for candidate, label in (
        (alternates, "alternates"),
        (http_alternates, "HTTP alternates"),
    ):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise NamedLaneGuardError(
                f"materialized Git {label} cannot be inspected"
            ) from error
        raise NamedLaneGuardError(f"materialized Git {label} must be absent")

    shallow = git_directory / "shallow"
    if expected_shallow_boundary is None:
        try:
            shallow.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise NamedLaneGuardError(
                "materialized Git shallow repository state cannot be inspected"
            ) from error
        else:
            raise NamedLaneGuardError(
                "materialized Git shallow repository state is not allowed"
            )
    else:
        _materializer_verify_shallow_boundary(
            git_directory,
            expected_shallow_boundary,
        )

    sparse_checkout = git_directory / "info" / "sparse-checkout"
    try:
        sparse_checkout.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized Git sparse checkout state cannot be inspected"
        ) from error
    else:
        raise NamedLaneGuardError(
            "materialized Git sparse checkout state is not allowed"
        )

    pack = objects / "pack"
    try:
        pack_metadata = pack.lstat()
        pack_resolved = pack.resolve(strict=True)
    except FileNotFoundError:
        return
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materialized Git pack storage cannot be inspected"
        ) from error
    if (
        not stat.S_ISDIR(pack_metadata.st_mode)
        or stat.S_ISLNK(pack_metadata.st_mode)
        or pack_metadata.st_uid != _current_user_id()
        or pack_resolved != pack
    ):
        raise NamedLaneGuardError(
            "materialized Git pack storage must be a real directory"
        )
    pack_fd = -1
    try:
        pack_fd = os.open(
            pack,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        descriptor_metadata = os.fstat(pack_fd)
        if (
            not stat.S_ISDIR(descriptor_metadata.st_mode)
            or descriptor_metadata.st_uid != _current_user_id()
            or _directory_identity(descriptor_metadata)
            != _directory_identity(pack_metadata)
        ):
            raise NamedLaneGuardError(
                "materialized Git pack storage changed during inspection"
            )
        bitmaps: list[tuple[str, tuple[int, int, int, int]]] = []
        with os.scandir(pack_fd) as entries:
            for entry in entries:
                folded_name = entry.name.casefold()
                if folded_name.endswith(".promisor"):
                    raise NamedLaneGuardError(
                        "materialized Git promisor state is not allowed"
                    )
                if not folded_name.endswith(".bitmap"):
                    continue
                metadata = entry.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != _current_user_id()
                ):
                    raise NamedLaneGuardError(
                        "materialized Git bitmap cache must be an owned regular file"
                    )
                if not remove_bitmaps:
                    raise NamedLaneGuardError(
                        "materialized Git bitmap cache must be absent"
                    )
                bitmaps.append(
                    (
                        entry.name,
                        (
                            metadata.st_dev,
                            metadata.st_ino,
                            metadata.st_mode,
                            metadata.st_uid,
                        ),
                    )
                )
        for name, expected_identity in bitmaps:
            current = os.stat(name, dir_fd=pack_fd, follow_symlinks=False)
            current_identity = (
                current.st_dev,
                current.st_ino,
                current.st_mode,
                current.st_uid,
            )
            if current_identity != expected_identity:
                raise NamedLaneGuardError(
                    "materialized Git bitmap cache changed before removal"
                )
            os.unlink(name, dir_fd=pack_fd)
        with os.scandir(pack_fd) as entries:
            if any(entry.name.casefold().endswith(".bitmap") for entry in entries):
                raise NamedLaneGuardError(
                    "materialized Git bitmap cache must be absent"
                )
    except NamedLaneGuardError:
        raise
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized Git pack storage cannot be inspected"
        ) from error
    finally:
        if pack_fd >= 0:
            os.close(pack_fd)


def _materializer_verify_revision(
    root: pathlib.Path,
    revision: str,
    expected: str,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> None:
    actual = os.fsdecode(
        _materializer_git_capture(
            git,
            environment,
            hooks,
            ("rev-parse", "--verify", f"{revision}^{{commit}}"),
            root=root,
        )
    ).strip()
    if actual.lower() != expected.lower():
        raise NamedLaneGuardError(
            f"materialized {revision} does not match the frozen object ID"
        )


def _materializer_verify_complete_objects(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> None:
    _materializer_verify_revision(
        root,
        base_sha,
        base_sha,
        git,
        environment,
        hooks,
    )
    _materializer_verify_revision(
        root,
        head_sha,
        head_sha,
        git,
        environment,
        hooks,
    )
    _materializer_git_capture(
        git,
        environment,
        hooks,
        (
            "rev-list",
            "--objects",
            "--missing=error",
            "--quiet",
            base_sha,
            head_sha,
            "--",
        ),
        root=root,
    )


def _materializer_verify_object_integrity(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> None:
    _materializer_git_capture(
        git,
        environment,
        hooks,
        (
            "fsck",
            "--full",
            "--no-reflogs",
            "--no-dangling",
            "--no-progress",
            base_sha,
            head_sha,
        ),
        root=root,
        timeout_seconds=300.0,
    )


def _materializer_alternate_environment(
    environment: Mapping[str, str],
    storage: _MaterializerSourceStorage,
) -> dict[str, str]:
    alternate_environment = dict(environment)
    alternate_environment["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(storage.objects)
    return alternate_environment


def _materializer_review_commit_manifest(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> frozenset[bytes]:
    oid_length = len(head_sha)
    expected_base = base_sha.encode("ascii")

    def parse_manifest(payload: bytes, label: str) -> frozenset[bytes]:
        if payload and not payload.endswith(b"\n"):
            raise NamedLaneGuardError(f"{label} is malformed")
        range_commits = payload[:-1].split(b"\n") if payload else []
        expected_pattern = re.compile(
            rb"[0-9a-f]{" + str(oid_length).encode("ascii") + rb"}\Z"
        )
        if any(expected_pattern.fullmatch(commit) is None for commit in range_commits):
            raise NamedLaneGuardError(f"{label} is malformed")
        commits = frozenset((expected_base, *range_commits))
        if len(commits) != len(range_commits) + 1:
            raise NamedLaneGuardError(f"{label} contains duplicate commits")
        if len(commits) > MATERIALIZER_OBJECT_COUNT_LIMIT:
            raise NamedLaneGuardError(f"{label} exceeds the object-count limit")
        return commits

    merge_bases = _materializer_git_capture(
        git,
        environment,
        hooks,
        ("merge-base", "--all", base_sha, head_sha),
        root=root,
        allow_no_match=True,
        output_limit_bytes=2 * (oid_length + 1),
    )
    if merge_bases != expected_base + b"\n":
        raise NamedLaneGuardError(
            "frozen base must be the unique merge base of the frozen head"
        )

    manifest_output_limit = MATERIALIZER_OBJECT_COUNT_LIMIT * (oid_length + 1)
    try:
        raw_manifest = _materializer_git_capture(
            git,
            environment,
            hooks,
            (
                "rev-list",
                "--no-object-names",
                "--missing=error",
                head_sha,
                f"^{base_sha}",
                "--",
            ),
            root=root,
            output_limit_bytes=manifest_output_limit,
        )
    except ReviewOutputLimitError as error:
        raise NamedLaneGuardError(
            "materializer review commit manifest exceeds the object-count limit"
        ) from error
    review_commits = parse_manifest(
        raw_manifest,
        "materializer review commit manifest",
    )
    try:
        raw_ancestry = _materializer_git_capture(
            git,
            environment,
            hooks,
            (
                "rev-list",
                "--no-object-names",
                "--missing=error",
                "--ancestry-path",
                head_sha,
                f"^{base_sha}",
                "--",
            ),
            root=root,
            output_limit_bytes=manifest_output_limit,
        )
    except ReviewOutputLimitError as error:
        raise NamedLaneGuardError(
            "materializer ancestry-path commit manifest exceeds the object-count limit"
        ) from error
    ancestry_commits = parse_manifest(
        raw_ancestry,
        "materializer ancestry-path commit manifest",
    )
    if ancestry_commits != review_commits:
        raise NamedLaneGuardError(
            "materializer review graph cannot be represented by the sole shallow boundary"
        )
    return review_commits


def _parse_parent_graph(
    payload: bytes,
    expected_commits: frozenset[bytes],
    base_sha: bytes,
    oid_length: int,
    *,
    label: str,
    scope_mismatch_message: str,
) -> _ParentGraphCounts:
    if payload and not payload.endswith(b"\n"):
        raise NamedLaneGuardError(f"{label} is malformed")
    rows = payload[:-1].split(b"\n") if payload else []
    fields_by_row = [row.split(b" ") for row in rows]
    parent_edge_count = sum(max(0, len(fields) - 1) for fields in fields_by_row)
    if parent_edge_count > MATERIALIZER_PARENT_EDGE_COUNT_LIMIT:
        raise NamedLaneGuardError(
            "frozen commit parent graph exceeds the parent-edge budget"
        )
    oid_pattern = re.compile(rb"[0-9a-f]{" + str(oid_length).encode("ascii") + rb"}\Z")
    if any(
        not fields
        or any(oid_pattern.fullmatch(object_id) is None for object_id in fields)
        for fields in fields_by_row
    ):
        raise NamedLaneGuardError(f"{label} is malformed")
    parents_by_commit: dict[bytes, tuple[bytes, ...]] = {}
    for fields in fields_by_row:
        commit, *parents = fields
        if commit in parents_by_commit:
            raise NamedLaneGuardError(f"{label} contains duplicate commits")
        parents_by_commit[commit] = tuple(parents)
    if frozenset(parents_by_commit) != expected_commits:
        raise NamedLaneGuardError(scope_mismatch_message)
    if parents_by_commit.get(base_sha) != ():
        raise NamedLaneGuardError(
            "materialized frozen base is not the sole shallow boundary"
        )
    if any(
        parent not in expected_commits
        for commit, parents in parents_by_commit.items()
        if commit != base_sha
        for parent in parents
    ):
        raise NamedLaneGuardError("materialized commit parent escapes the frozen range")
    digest = hashlib.sha256()
    digest.update(b"named-lane-parent-graph-v1\0")
    digest.update(str(oid_length).encode("ascii"))
    digest.update(b"\0")
    for commit, parents in sorted(parents_by_commit.items()):
        digest.update(commit)
        digest.update(b"\0")
        for parent in parents:
            digest.update(parent)
            digest.update(b"\0")
        digest.update(b"\n")
    return _ParentGraphCounts(
        commit_count=len(expected_commits),
        parent_edge_count=parent_edge_count,
        parent_graph_sha256=digest.hexdigest(),
    )


def _materializer_parent_graph(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
    expected_commits: frozenset[bytes],
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> _ParentGraphCounts:
    output_limit = _parent_graph_output_limit(
        len(expected_commits),
        len(head_sha),
    )
    try:
        payload = _materializer_git_capture(
            git,
            environment,
            hooks,
            (
                "rev-list",
                "--parents",
                "--missing=error",
                head_sha,
                "--",
            ),
            root=root,
            output_limit_bytes=output_limit,
        )
    except ReviewOutputLimitError as error:
        raise NamedLaneGuardError(
            "frozen commit parent graph exceeds the parent-edge budget"
        ) from error
    return _parse_parent_graph(
        payload,
        expected_commits,
        base_sha.encode("ascii"),
        len(head_sha),
        label="materializer shallow parent traversal",
        scope_mismatch_message=(
            "materializer shallow commit closure does not match the frozen source range"
        ),
    )


def _materializer_shallow_boundary_payload(base_sha: str) -> bytes:
    return base_sha.encode("ascii") + b"\n"


def _materializer_verify_shallow_boundary(
    git_directory: pathlib.Path,
    base_sha: str,
) -> None:
    # Each point validation binds the opened object by device/inode/type/owner,
    # enforces the single-link owner-only access policy with mode/nlink, and
    # protects the range semantics with exact BASE-plus-LF content. Timestamps
    # are irrelevant to those properties. A safe same-content replacement
    # between complete validations is therefore harmless, while replacement
    # during a validation, content drift, or access-policy drift fails closed.
    path = git_directory / "shallow"
    expected_payload = _materializer_shallow_boundary_payload(base_sha)
    descriptor = -1
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != _current_user_id()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(expected_payload)
        ):
            raise NamedLaneGuardError("materialized Git shallow boundary is not safe")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        descriptor_metadata = os.fstat(descriptor)
        identity = (
            descriptor_metadata.st_dev,
            descriptor_metadata.st_ino,
            stat.S_IFMT(descriptor_metadata.st_mode),
            descriptor_metadata.st_uid,
        )
        if (
            identity
            != (
                metadata.st_dev,
                metadata.st_ino,
                stat.S_IFMT(metadata.st_mode),
                metadata.st_uid,
            )
            or stat.S_IMODE(descriptor_metadata.st_mode) != 0o600
            or descriptor_metadata.st_nlink != 1
            or descriptor_metadata.st_size != len(expected_payload)
        ):
            raise NamedLaneGuardError(
                "materialized Git shallow boundary changed during inspection"
            )
        payload = os.read(descriptor, len(expected_payload) + 1)
        final_descriptor_metadata = os.fstat(descriptor)
        if (
            payload != expected_payload
            or final_descriptor_metadata.st_dev != descriptor_metadata.st_dev
            or final_descriptor_metadata.st_ino != descriptor_metadata.st_ino
            or final_descriptor_metadata.st_mode != descriptor_metadata.st_mode
            or final_descriptor_metadata.st_uid != descriptor_metadata.st_uid
            or final_descriptor_metadata.st_nlink != descriptor_metadata.st_nlink
            or final_descriptor_metadata.st_size != descriptor_metadata.st_size
        ):
            raise NamedLaneGuardError(
                "materialized Git shallow boundary changed during inspection"
            )
    except NamedLaneGuardError:
        raise
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized Git shallow boundary cannot be inspected"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        final_metadata = path.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized Git shallow boundary cannot be revalidated"
        ) from error
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_mode != metadata.st_mode
        or final_metadata.st_uid != metadata.st_uid
        or final_metadata.st_nlink != metadata.st_nlink
        or final_metadata.st_size != metadata.st_size
    ):
        raise NamedLaneGuardError(
            "materialized Git shallow boundary changed during inspection"
        )


def _materializer_write_shallow_boundary(
    git_directory: pathlib.Path,
    base_sha: str,
) -> None:
    path = git_directory / "shallow"
    payload = _materializer_shallow_boundary_payload(base_sha)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized Git shallow boundary cannot be created safely"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _materializer_verify_shallow_boundary(git_directory, base_sha)


def _materializer_reachable_manifest(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
    expected_commits: frozenset[bytes],
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> tuple[bytearray, dict[bytes, tuple[bytes, int]]]:
    oid_length = len(head_sha)
    manifest_output_limit = MATERIALIZER_OBJECT_COUNT_LIMIT * (oid_length + 1)
    try:
        raw_manifest = _materializer_git_capture(
            git,
            environment,
            hooks,
            (
                "rev-list",
                "--objects",
                "--no-object-names",
                "--missing=error",
                base_sha,
                head_sha,
                "--",
            ),
            root=root,
            output_limit_bytes=manifest_output_limit,
        )
    except ReviewOutputLimitError as error:
        raise NamedLaneGuardError(
            "materializer reachable object manifest exceeds the object-count limit"
        ) from error
    if not raw_manifest or not raw_manifest.endswith(b"\n"):
        raise NamedLaneGuardError("materializer reachable object manifest is malformed")
    object_ids = raw_manifest[:-1].split(b"\n")
    if len(object_ids) > MATERIALIZER_OBJECT_COUNT_LIMIT:
        raise NamedLaneGuardError(
            "materializer reachable object manifest exceeds the object-count limit"
        )
    expected_pattern = re.compile(
        rb"[0-9a-f]{" + str(oid_length).encode("ascii") + rb"}\Z"
    )
    if any(expected_pattern.fullmatch(object_id) is None for object_id in object_ids):
        raise NamedLaneGuardError("materializer reachable object manifest is malformed")
    if len(set(object_ids)) != len(object_ids):
        raise NamedLaneGuardError(
            "materializer reachable object manifest contains duplicate objects"
        )
    manifest = bytearray(raw_manifest)
    metadata_input = bytearray(manifest)
    metadata_output_limit = MATERIALIZER_OBJECT_COUNT_LIMIT * (
        oid_length + 1 + len("commit") + 1 + 20 + 1
    )
    try:
        metadata_payload = _materializer_git_capture(
            git,
            environment,
            hooks,
            ("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"),
            root=root,
            stdin=metadata_input,
            output_limit_bytes=metadata_output_limit,
        )
    except ReviewOutputLimitError as error:
        manifest[:] = b"\x00" * len(manifest)
        raise NamedLaneGuardError(
            "materializer reachable object metadata exceeds its trusted limit"
        ) from error
    finally:
        metadata_input[:] = b"\x00" * len(metadata_input)
    if not metadata_payload.endswith(b"\n"):
        manifest[:] = b"\x00" * len(manifest)
        raise NamedLaneGuardError("materializer reachable object metadata is malformed")
    metadata: dict[bytes, tuple[bytes, int]] = {}
    logical_bytes = 0
    records = metadata_payload[:-1].split(b"\n")
    if len(records) != len(object_ids):
        manifest[:] = b"\x00" * len(manifest)
        raise NamedLaneGuardError(
            "materializer reachable object metadata is incomplete"
        )
    for expected_oid, record in zip(object_ids, records):
        fields = record.split(b" ")
        if len(fields) != 3 or fields[0] != expected_oid:
            manifest[:] = b"\x00" * len(manifest)
            raise NamedLaneGuardError(
                "materializer reachable object metadata is malformed"
            )
        object_type = fields[1]
        if object_type not in {b"blob", b"commit", b"tag", b"tree"}:
            manifest[:] = b"\x00" * len(manifest)
            raise NamedLaneGuardError(
                "materializer reachable object metadata has an unexpected type"
            )
        try:
            object_size = int(fields[2])
        except ValueError as error:
            manifest[:] = b"\x00" * len(manifest)
            raise NamedLaneGuardError(
                "materializer reachable object metadata has an invalid size"
            ) from error
        if object_size < 0:
            manifest[:] = b"\x00" * len(manifest)
            raise NamedLaneGuardError(
                "materializer reachable object metadata has an invalid size"
            )
        logical_bytes += object_size
        if logical_bytes > MATERIALIZER_LOGICAL_OBJECT_BYTES_LIMIT:
            manifest[:] = b"\x00" * len(manifest)
            raise NamedLaneGuardError(
                "materializer reachable objects exceed the logical-byte limit"
            )
        metadata[expected_oid] = (object_type, object_size)
    materialized_commits = frozenset(
        object_id
        for object_id, (object_type, _object_size) in metadata.items()
        if object_type == b"commit"
    )
    if materialized_commits != expected_commits:
        manifest[:] = b"\x00" * len(manifest)
        raise NamedLaneGuardError(
            "materializer shallow commit closure does not match the frozen source range"
        )
    return manifest, metadata


def _materializer_validate_checkout_manifest(
    root: pathlib.Path,
    head_sha: str,
    object_metadata: Mapping[bytes, tuple[bytes, int]],
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> None:
    oid_length = len(head_sha)
    output_limit = _checkout_tree_output_limit(oid_length)
    try:
        payload = _materializer_git_capture(
            git,
            environment,
            hooks,
            ("ls-tree", "-r", "-z", "--full-tree", head_sha),
            root=root,
            output_limit_bytes=output_limit,
        )
    except ReviewOutputLimitError as error:
        raise NamedLaneGuardError(
            "materializer head checkout manifest exceeds its trusted limits"
        ) from error
    entries = payload[:-1].split(b"\0") if payload else []
    if payload and not payload.endswith(b"\0"):
        raise NamedLaneGuardError("materializer head checkout manifest is malformed")
    if len(entries) > MATERIALIZER_CHECKOUT_ENTRY_COUNT_LIMIT:
        raise NamedLaneGuardError(
            "materializer head checkout exceeds the entry-count limit"
        )
    path_bytes = 0
    checkout_blob_bytes = 0
    oid_pattern = re.compile(rb"[0-9a-f]{" + str(oid_length).encode("ascii") + rb"}\Z")
    for entry in entries:
        header, separator, path = entry.partition(b"\t")
        fields = header.split(b" ")
        if (
            not separator
            or not path
            or len(fields) != 3
            or len(fields[0]) != 6
            or oid_pattern.fullmatch(fields[2]) is None
        ):
            raise NamedLaneGuardError(
                "materializer head checkout manifest is malformed"
            )
        path_bytes += len(path)
        if path_bytes > MATERIALIZER_CHECKOUT_PATH_BYTES_LIMIT:
            raise NamedLaneGuardError(
                "materializer head checkout exceeds the aggregate-path-byte limit"
            )
        if fields[1] == b"blob":
            metadata = object_metadata.get(fields[2])
            if metadata is None or metadata[0] != b"blob":
                raise NamedLaneGuardError(
                    "materializer head checkout references an unmanifested blob"
                )
            checkout_blob_bytes += metadata[1]
            if checkout_blob_bytes > MATERIALIZER_CHECKOUT_BLOB_BYTES_LIMIT:
                raise NamedLaneGuardError(
                    "materializer head checkout exceeds the blob-occurrence-byte limit"
                )
        elif fields[1] != b"commit":
            raise NamedLaneGuardError(
                "materializer head checkout manifest has an unexpected type"
            )


def _write_materializer_pack_zero_chunk(
    view: memoryview,
    offset: int,
    chunk_size: int,
    zeroes: bytes,
) -> None:
    view[offset : offset + chunk_size] = zeroes[:chunk_size]


def _zeroize_materializer_pack(
    payload: bytearray,
    *,
    primary_error: BaseException | None = None,
) -> None:
    """Wipe and clear a pack before propagating any cleanup-window signal."""

    cleanup_mask, acquisition_signal = _block_materializer_cleanup_signals()
    pending_signal: signal.Signals | None = None
    cleanup_error: BaseException | None = None
    try:
        if payload:
            zeroes = b"\x00" * min(len(payload), 64 * 1024)
            view = memoryview(payload)
            try:
                offset = 0
                while offset < len(view):
                    chunk_size = min(len(zeroes), len(view) - offset)
                    _write_materializer_pack_zero_chunk(
                        view,
                        offset,
                        chunk_size,
                        zeroes,
                    )
                    offset += chunk_size
            finally:
                view.release()
        payload.clear()
        if cleanup_mask is not None:
            pending_signal = consume_pending_forwarded_signal()
    except BaseException as error:
        cleanup_error = error
    try:
        restore_signal_mask(cleanup_mask)
    except BaseException as error:
        if cleanup_error is None:
            cleanup_error = error
    if cleanup_error is not None:
        if primary_error is not None and isinstance(cleanup_error, ForwardedSignal):
            return
        raise cleanup_error
    if primary_error is not None:
        return
    if acquisition_signal is not None:
        raise acquisition_signal
    if pending_signal is not None:
        raise ForwardedSignal(pending_signal)


@dataclass
class _MaterializerPackPayloadOwner:
    """Keep the pack reachable across the callee-return assignment boundary."""

    payload: bytearray | None = None

    def publish(self, payload: bytearray) -> None:
        if self.payload is not None:
            raise NamedLaneGuardError(
                "materializer pack payload ownership is ambiguous"
            )
        self.payload = payload

    def zeroize(self, *, primary_error: BaseException | None = None) -> None:
        payload = self.payload
        if payload is None:
            return
        try:
            _zeroize_materializer_pack(payload, primary_error=primary_error)
        finally:
            self.payload = None


def _materializer_pack_manifest(
    root: pathlib.Path,
    manifest: bytearray,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
    owner: _MaterializerPackPayloadOwner,
) -> None:
    command = (
        *_materializer_git_prefix(git, hooks),
        "-C",
        str(root),
        "pack-objects",
        "--stdout",
        "--quiet",
        "--delta-base-offset",
        "--no-use-bitmap-index",
        "--no-reuse-delta",
        "--no-reuse-object",
    )
    # The bounded runner temporarily manages forwarded signals itself, then
    # restores this caller-blocked mask before returning. That makes both its
    # return assignment and the caller-visible owner publication atomic with
    # respect to forwarded-signal delivery.
    handoff_mask, acquisition_signal = _block_materializer_cleanup_signals()
    if handoff_mask is None:
        raise NamedLaneGuardError(
            "materializer pack ownership handoff requires main-thread signal masking"
        )
    capture = None
    transferred = False
    handoff_pending_signal: signal.Signals | None = None
    handoff_restore_signal: signal.Signals | None = None
    try:
        if acquisition_signal is not None:
            raise acquisition_signal
        try:
            capture = run_bounded_capture(
                command,
                cwd=hooks.parent / "tmp",
                env=dict(environment),
                stdin=manifest,
                timeout_seconds=MATERIALIZER_GIT_TIMEOUT_SECONDS,
                stdout_limit_bytes=MATERIALIZER_PACK_BYTES_LIMIT,
                stderr_limit_bytes=1024 * 1024,
            )
        except ReviewOutputLimitError as error:
            raise NamedLaneGuardError(
                "materializer reachable pack exceeds the compressed-byte limit"
            ) from error
        if capture.returncode != 0:
            raise NamedLaneGuardError("bounded materializer Git pack-objects failed")
        owner.publish(capture.stdout)
        transferred = True
        handoff_pending_signal = consume_pending_forwarded_signal()
    finally:
        try:
            if capture is not None:
                if not transferred:
                    _zeroize_materializer_pack(
                        capture.stdout,
                        primary_error=sys.exc_info()[1],
                    )
                capture.stderr[:] = b"\x00" * len(capture.stderr)
            late_signal = consume_pending_forwarded_signal()
            if handoff_pending_signal is None:
                handoff_pending_signal = late_signal
        finally:
            restore_primary_error = sys.exc_info()[1]
            try:
                restore_signal_mask(handoff_mask)
            except ForwardedSignal as error:
                # The POSIX mask change completed before Python dispatched the
                # pending signal through the installed structured handler. A
                # restore-window signal must not replace an active capture or
                # cleanup failure.
                if restore_primary_error is None:
                    handoff_restore_signal = error.signum
    if handoff_pending_signal is None:
        handoff_pending_signal = handoff_restore_signal
    if handoff_pending_signal is not None:
        raise ForwardedSignal(handoff_pending_signal)


def _materializer_import_reachable_objects(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
    storage: _MaterializerSourceStorage,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> tuple[frozenset[bytes], _ParentGraphCounts]:
    _verify_materializer_source_storage(storage)
    alternate_environment = _materializer_alternate_environment(environment, storage)
    _materializer_verify_revision(
        root,
        base_sha,
        base_sha,
        git,
        alternate_environment,
        hooks,
    )
    _materializer_verify_revision(
        root,
        head_sha,
        head_sha,
        git,
        alternate_environment,
        hooks,
    )
    expected_commits = _materializer_review_commit_manifest(
        root,
        base_sha,
        head_sha,
        git,
        alternate_environment,
        hooks,
    )
    _materializer_write_shallow_boundary(root / ".git", base_sha)
    _validate_materialized_object_storage(
        root / ".git",
        expected_shallow_boundary=base_sha,
    )
    parent_graph = _materializer_parent_graph(
        root,
        base_sha,
        head_sha,
        expected_commits,
        git,
        alternate_environment,
        hooks,
    )
    manifest, metadata = _materializer_reachable_manifest(
        root,
        base_sha,
        head_sha,
        expected_commits,
        git,
        alternate_environment,
        hooks,
    )
    pack_owner = _MaterializerPackPayloadOwner()
    try:
        _materializer_validate_checkout_manifest(
            root,
            head_sha,
            metadata,
            git,
            alternate_environment,
            hooks,
        )
        _verify_materializer_source_storage(storage)
        _materializer_pack_manifest(
            root,
            manifest,
            git,
            alternate_environment,
            hooks,
            pack_owner,
        )
        pack_payload = pack_owner.payload
        if pack_payload is None:
            raise NamedLaneGuardError(
                "materializer pack payload ownership was not transferred"
            )
        _verify_materializer_source_storage(storage)
        if len(pack_payload) > MATERIALIZER_PACK_BYTES_LIMIT:
            raise NamedLaneGuardError(
                "materializer reachable pack exceeds the compressed-byte limit"
            )
        _materializer_git_capture(
            git,
            environment,
            hooks,
            (
                "index-pack",
                "--stdin",
                "--strict",
                f"--max-input-size={MATERIALIZER_PACK_BYTES_LIMIT}",
            ),
            root=root,
            stdin=pack_payload,
        )
        return frozenset(metadata), parent_graph
    finally:
        primary_error = sys.exc_info()[1]
        pack_owner.zeroize(primary_error=primary_error)
        manifest[:] = b"\x00" * len(manifest)


def _materializer_verify_exact_object_manifest(
    root: pathlib.Path,
    expected_objects: frozenset[bytes],
    oid_length: int,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> None:
    try:
        payload = _materializer_git_capture(
            git,
            environment,
            hooks,
            (
                "cat-file",
                "--batch-check=%(objectname)",
                "--batch-all-objects",
                "--unordered",
            ),
            root=root,
            output_limit_bytes=MATERIALIZER_OBJECT_COUNT_LIMIT * (oid_length + 1),
        )
    except ReviewOutputLimitError as error:
        raise NamedLaneGuardError(
            "materialized object inventory exceeds the object-count limit"
        ) from error
    if payload and not payload.endswith(b"\n"):
        raise NamedLaneGuardError("materialized object inventory is malformed")
    actual_objects = frozenset(payload[:-1].split(b"\n")) if payload else frozenset()
    if actual_objects != expected_objects:
        raise NamedLaneGuardError(
            "materialized object inventory does not match the frozen reachable closure"
        )


def _verify_materialized_root(
    root: pathlib.Path,
    expected_identity: _DirectoryIdentity,
) -> None:
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "materialized worktree changed during checkout"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != _current_user_id()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or resolved != root
        or _directory_identity(metadata) != expected_identity
    ):
        raise NamedLaneGuardError("materialized worktree changed during checkout")


def _block_materializer_cleanup_signals() -> tuple[
    set[signal.Signals] | None, ForwardedSignal | None
]:
    deferred: ForwardedSignal | None = None
    while True:
        try:
            return block_forwarded_signals(), deferred
        except ForwardedSignal as error:
            if deferred is None:
                deferred = error


def _restore_materializer_terminal_failure_mask(
    previous_mask: set[signal.Signals] | None,
) -> None:
    if previous_mask is None:
        restore_signal_mask(previous_mask)
        return
    terminal_signals: list[signal.Signals] = []

    def record_terminal_signal(signum: int, _frame: object) -> None:
        terminal_signals.append(signal.Signals(signum))

    # The caller has already frozen the terminal failure, including every
    # retained path. Keep later signals from replacing that evidence while the
    # enclosing structured-signal context regains control and restores the
    # original handlers.
    for forwarded in forwarded_signals():
        signal.signal(forwarded, record_terminal_signal)
    consume_pending_forwarded_signal()
    restore_signal_mask(previous_mask)


def materialize_worktree(
    source: pathlib.Path,
    worktree: pathlib.Path,
    base_sha: str,
    head_sha: str,
    *,
    defer_signal_handoff: bool = False,
) -> MaterializedWorktree:
    if FULL_OBJECT_ID.fullmatch(base_sha) is None:
        raise NamedLaneGuardError("frozen base must be a full Git object ID")
    if FULL_OBJECT_ID.fullmatch(head_sha) is None:
        raise NamedLaneGuardError("frozen head must be a full Git object ID")
    if len(base_sha) != len(head_sha):
        raise NamedLaneGuardError(
            "frozen base and head must use the same Git object format"
        )
    frozen_base = base_sha.lower()
    frozen_head = head_sha.lower()
    resolved_source, source_marker = _resolve_materializer_source(source)
    destination, parent, parent_identity = _validate_materializer_parent(worktree)
    git = resolve_git()
    control: pathlib.Path | None = None
    directories: dict[str, pathlib.Path] | None = None
    control_identity: _DirectoryIdentity | None = None
    environment: dict[str, str] | None = None
    destination_started = False
    result: MaterializedWorktree | None = None
    failure: BaseException | None = None
    destination_identity: _DirectoryIdentity | None = None
    local_config_binding: _LocalConfigBinding | None = None
    info_binding: _GitInfoBinding | None = None
    cleanup_mask: set[signal.Signals] | None = None
    cleanup_acquisition_signal: ForwardedSignal | None = None
    try:
        setup_mask = block_forwarded_signals()
        if setup_mask is None:
            raise NamedLaneGuardError(
                "materializer setup requires main-thread signal masking"
            )
        try:
            control, directories, control_identity = (
                _make_materializer_control_directory(
                    parent,
                    parent_identity,
                )
            )
            setup_signal = consume_pending_forwarded_signal()
            if setup_signal is not None:
                raise ForwardedSignal(setup_signal)
        except BaseException:
            if defer_signal_handoff:
                _restore_materializer_terminal_failure_mask(setup_mask)
            else:
                restore_signal_mask(setup_mask)
            raise
        else:
            restore_signal_mask(setup_mask)
        environment = _materializer_git_environment(directories, parent)
        _verify_materializer_parent(parent, parent_identity)
        _validate_materializer_git_version(
            git,
            environment,
            directories["tmp"],
        )
        source_storage = _validate_materializer_source_repository(
            resolved_source,
            source_marker,
            len(frozen_head),
            git,
            environment,
            directories["hooks"],
        )
        _verify_materializer_parent(parent, parent_identity)
        destination.mkdir(mode=0o700)
        destination_started = True
        try:
            initial_destination_metadata = destination.lstat()
            initial_destination_resolved = destination.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise NamedLaneGuardError(
                "materialized repository directory cannot be inspected safely"
            ) from error
        if (
            not stat.S_ISDIR(initial_destination_metadata.st_mode)
            or stat.S_ISLNK(initial_destination_metadata.st_mode)
            or initial_destination_metadata.st_uid != _current_user_id()
            or initial_destination_resolved != destination
        ):
            raise NamedLaneGuardError(
                "materialized repository directory must be a current-user-owned real directory"
            )
        initial_destination_identity = _directory_identity(initial_destination_metadata)
        try:
            os.chmod(destination, 0o700, follow_symlinks=False)
            destination_metadata = destination.lstat()
        except (NotImplementedError, OSError) as error:
            raise NamedLaneGuardError(
                "materialized repository directory cannot be made owner-only"
            ) from error
        destination_identity = _directory_identity(destination_metadata)
        if destination_identity != initial_destination_identity:
            raise NamedLaneGuardError(
                "materialized repository directory changed before initialization"
            )
        _verify_materialized_root(destination, destination_identity)
        _materializer_git_capture(
            git,
            environment,
            directories["hooks"],
            (
                "init",
                "--quiet",
                f"--object-format={source_storage.object_format}",
                f"--template={directories['template']}",
                "--initial-branch=named-lane-materializer",
                "--",
                str(destination),
            ),
        )
        _verify_materializer_parent(parent, parent_identity)
        _verify_materialized_root(destination, destination_identity)
        git_directory = _validate_materialized_admin_directory(destination)
        _materializer_git_capture(
            git,
            environment,
            directories["hooks"],
            (
                "config",
                "--file",
                str(git_directory / "config"),
                "--no-includes",
                "core.commitGraph",
                "false",
            ),
        )
        _materializer_git_capture(
            git,
            environment,
            directories["hooks"],
            (
                "config",
                "--file",
                str(git_directory / "config"),
                "--no-includes",
                "core.multiPackIndex",
                "false",
            ),
        )
        info_binding = _bind_materialized_git_info(
            git_directory,
            create=True,
        )
        local_config_binding = _audit_materialized_local_config(
            destination,
            len(frozen_head),
            git,
            environment,
            directories["hooks"],
        )
        _bind_materialized_git_info(git_directory, expected=info_binding)
        _validate_materialized_object_storage(git_directory)
        imported_objects, parent_graph = _materializer_import_reachable_objects(
            destination,
            frozen_base,
            frozen_head,
            source_storage,
            git,
            environment,
            directories["hooks"],
        )
        _validate_materialized_object_storage(
            git_directory,
            expected_shallow_boundary=frozen_base,
        )
        _materializer_verify_exact_object_manifest(
            destination,
            imported_objects,
            len(frozen_head),
            git,
            environment,
            directories["hooks"],
        )
        _materializer_verify_object_integrity(
            destination,
            frozen_base,
            frozen_head,
            git,
            environment,
            directories["hooks"],
        )
        _materializer_verify_complete_objects(
            destination,
            frozen_base,
            frozen_head,
            git,
            environment,
            directories["hooks"],
        )

        ref_transaction = bytearray(
            (
                "start\n"
                f"create {MATERIALIZER_BASE_REF} {frozen_base}\n"
                f"create {MATERIALIZER_HEAD_REF} {frozen_head}\n"
                "prepare\n"
                "commit\n"
            ).encode("ascii")
        )
        _materializer_git_capture(
            git,
            environment,
            directories["hooks"],
            ("update-ref", "--stdin"),
            root=destination,
            stdin=ref_transaction,
        )
        _audit_materialized_local_config(
            destination,
            len(frozen_head),
            git,
            environment,
            directories["hooks"],
            expected=local_config_binding,
        )
        _bind_materialized_git_info(git_directory, expected=info_binding)
        _validate_materialized_object_storage(
            git_directory,
            expected_shallow_boundary=frozen_base,
        )
        _materializer_verify_complete_objects(
            destination,
            frozen_base,
            frozen_head,
            git,
            environment,
            directories["hooks"],
        )
        _verify_materialized_root(destination, destination_identity)
        _materializer_git_capture(
            git,
            environment,
            directories["hooks"],
            (
                "checkout",
                "--detach",
                "--force",
                "--no-recurse-submodules",
                frozen_head,
                "--",
            ),
            root=destination,
        )
        _verify_materialized_root(destination, destination_identity)
        symbolic_head = _materializer_git_capture(
            git,
            environment,
            directories["hooks"],
            ("symbolic-ref", "--quiet", "HEAD"),
            root=destination,
            allow_no_match=True,
        )
        if symbolic_head:
            raise NamedLaneGuardError("materialized worktree HEAD must be detached")
        _materializer_verify_revision(
            destination,
            "HEAD",
            frozen_head,
            git,
            environment,
            directories["hooks"],
        )
        _materializer_verify_revision(
            destination,
            MATERIALIZER_BASE_REF,
            frozen_base,
            git,
            environment,
            directories["hooks"],
        )
        _materializer_verify_revision(
            destination,
            MATERIALIZER_HEAD_REF,
            frozen_head,
            git,
            environment,
            directories["hooks"],
        )
        _validate_materialized_object_storage(
            git_directory,
            expected_shallow_boundary=frozen_base,
        )
        _audit_materialized_local_config(
            destination,
            len(frozen_head),
            git,
            environment,
            directories["hooks"],
            expected=local_config_binding,
        )
        _bind_materialized_git_info(git_directory, expected=info_binding)
        if local_config_binding is None or info_binding is None:
            raise NamedLaneGuardError(
                "materialized control bindings were not established"
            )
        result = MaterializedWorktree(
            root=destination,
            base_sha=frozen_base,
            head_sha=frozen_head,
            commit_count=parent_graph.commit_count,
            parent_edge_count=parent_graph.parent_edge_count,
            parent_graph_sha256=parent_graph.parent_graph_sha256,
            local_config_sha256=local_config_binding.sha256,
            _parent=parent,
            _parent_identity=parent_identity,
            _root_identity=destination_identity,
        )
    except BaseException as error:
        failure = error
    finally:
        cleanup_mask, cleanup_acquisition_signal = _block_materializer_cleanup_signals()

    if cleanup_acquisition_signal is not None and failure is None:
        failure = cleanup_acquisition_signal
    if control is None or directories is None or control_identity is None:
        assert failure is not None
        if defer_signal_handoff:
            _restore_materializer_terminal_failure_mask(cleanup_mask)
        else:
            restore_signal_mask(cleanup_mask)
        raise failure
    if defer_signal_handoff and cleanup_mask is None and failure is None:
        failure = NamedLaneGuardError(
            "materializer receipt handoff requires main-thread signal masking"
        )
    retained_control = _cleanup_materializer_path(
        control,
        parent,
        parent_identity,
        control_identity,
    )
    pending_cleanup_signal = (
        consume_pending_forwarded_signal() if cleanup_mask is not None else None
    )
    if pending_cleanup_signal is not None and failure is None:
        failure = ForwardedSignal(pending_cleanup_signal)
    retained_worktree: pathlib.Path | None = None
    if failure is not None or retained_control is not None:
        if destination_started:
            retained_worktree = _cleanup_materializer_path(
                destination,
                parent,
                parent_identity,
                destination_identity,
            )
        late_cleanup_signal = (
            consume_pending_forwarded_signal() if cleanup_mask is not None else None
        )
        if late_cleanup_signal is not None and failure is None:
            failure = ForwardedSignal(late_cleanup_signal)
            if destination_started and retained_worktree is None:
                retained_worktree = _cleanup_materializer_path(
                    destination,
                    parent,
                    parent_identity,
                    destination_identity,
                )
        retained: list[str] = []
        if retained_worktree is not None:
            retained.append(f"retained materialized worktree: {retained_worktree}")
        if retained_control is not None:
            retained.append(f"retained materializer control path: {retained_control}")
        if retained:
            detail = "; ".join(retained)
            if failure is None:
                terminal_failure = NamedLaneGuardError(detail)
            else:
                terminal_failure = NamedLaneGuardError(f"{failure}; {detail}")
            if defer_signal_handoff:
                _restore_materializer_terminal_failure_mask(cleanup_mask)
            else:
                restore_signal_mask(cleanup_mask)
            if failure is None:
                raise terminal_failure
            raise terminal_failure from failure
        if failure is not None:
            if defer_signal_handoff:
                _restore_materializer_terminal_failure_mask(cleanup_mask)
            else:
                restore_signal_mask(cleanup_mask)
            raise failure

    assert result is not None
    if defer_signal_handoff:
        object.__setattr__(result, "_handoff_signal_mask", cleanup_mask)
    else:
        restore_signal_mask(cleanup_mask)
    return result


def _resolve_worktree_path(
    worktree: pathlib.Path,
) -> pathlib.Path:
    if not worktree.is_absolute():
        raise NamedLaneGuardError("worktree path must be absolute")
    lexical = worktree.absolute()
    try:
        metadata = lexical.lstat()
    except OSError as error:
        raise NamedLaneGuardError("worktree path is not accessible") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NamedLaneGuardError("worktree path must be a real directory")
    try:
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError("worktree path cannot be resolved safely") from error
    return resolved


def _verify_git_worktree_root(
    resolved: pathlib.Path,
    *,
    deadline_monotonic: float | None = None,
) -> None:
    git_timeout_seconds = 30.0
    if deadline_monotonic is not None:
        git_timeout_seconds = min(
            git_timeout_seconds,
            _remaining_deadline_seconds(
                deadline_monotonic,
                "Claude worktree Git resolution",
            ),
        )
    top_level = os.fsdecode(
        _git_capture(
            resolved,
            ("rev-parse", "--show-toplevel"),
            timeout_seconds=git_timeout_seconds,
        )
    ).strip()
    try:
        top_level_path = pathlib.Path(top_level).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Git worktree root cannot be resolved safely"
        ) from error
    if top_level_path != resolved:
        raise NamedLaneGuardError("worktree path must name the Git worktree root")


def _resolve_worktree_root(
    worktree: pathlib.Path,
    *,
    deadline_monotonic: float | None = None,
) -> pathlib.Path:
    resolved = _resolve_worktree_path(worktree)
    _verify_git_worktree_root(resolved, deadline_monotonic=deadline_monotonic)
    return resolved


def _parse_tree(
    payload: bytes,
) -> dict[pathlib.PurePosixPath, tuple[str, str, str]]:
    entries: dict[pathlib.PurePosixPath, tuple[str, str, str]] = {}
    for record in payload.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
        except (UnicodeDecodeError, ValueError) as error:
            raise NamedLaneGuardError("malformed frozen Git tree entry") from error
        path = pathlib.PurePosixPath(os.fsdecode(raw_path))
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise NamedLaneGuardError("frozen Git tree contains an unsafe path")
        if path in entries:
            raise NamedLaneGuardError("frozen Git tree contains a duplicate path")
        entries[path] = (mode, object_type, object_id)
    return entries


def _validate_index_flags(payload: bytes) -> None:
    valid_tags = frozenset(b"HSMRCK?hsmrck")
    for record in payload.split(b"\0"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" " or record[0] not in valid_tags:
            raise NamedLaneGuardError("malformed Git index flag record")
        tag = record[0:1]
        if tag == b"S" or tag.islower():
            raise NamedLaneGuardError(
                "Git index must not contain assume-unchanged or skip-worktree entries"
            )


def _validate_initialized_submodules(
    root: pathlib.Path,
    frozen_head: str,
    tree: Mapping[pathlib.PurePosixPath, tuple[str, str, str]],
    gitlinks: frozenset[pathlib.PurePosixPath],
    configured_keys: frozenset[bytes],
) -> None:
    gitmodules = tree.get(pathlib.PurePosixPath(".gitmodules"))
    if not gitlinks:
        return
    configured_names: dict[bytes, set[pathlib.PurePosixPath]] = {}
    if gitmodules is not None:
        mode, object_type, _object_id = gitmodules
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise NamedLaneGuardError("frozen .gitmodules must be a regular blob")
        definitions = _git_capture(
            root,
            (
                "config",
                "--no-includes",
                "--null",
                f"--blob={frozen_head}:.gitmodules",
                "--get-regexp",
                r"^submodule\..*\.path$",
            ),
            allow_no_match=True,
        )
        for key, raw_path in _parse_git_config_records(
            definitions,
            label="frozen submodule path",
        ):
            lower_key = key.lower()
            if (
                not lower_key.startswith(b"submodule.")
                or not lower_key.endswith(b".path")
                or raw_path is None
            ):
                raise NamedLaneGuardError("malformed frozen submodule path record")
            relative_path = pathlib.PurePosixPath(os.fsdecode(raw_path))
            if relative_path in gitlinks:
                name = key[len(b"submodule.") : -len(b".path")]
                configured_names.setdefault(name, set()).add(relative_path)

    effective_paths: dict[bytes, pathlib.PurePosixPath] = {}
    path_definitions = _git_capture(
        root,
        (
            "config",
            "--no-includes",
            "--null",
            "--get-regexp",
            r"^submodule\..*\.path$",
        ),
        allow_no_match=True,
    )
    for key, raw_path in _parse_git_config_records(
        path_definitions,
        label="effective submodule path",
    ):
        lower_key = key.lower()
        if not lower_key.startswith(b"submodule.") or not lower_key.endswith(b".path"):
            raise NamedLaneGuardError("malformed effective submodule path record")
        if raw_path is None:
            raise NamedLaneGuardError("malformed effective submodule path record")
        name = key[len(b"submodule.") : -len(b".path")]
        effective_paths[name] = pathlib.PurePosixPath(os.fsdecode(raw_path))
    for name, relative_path in effective_paths.items():
        if relative_path in gitlinks:
            configured_names.setdefault(name, set()).add(relative_path)

    configured_urls: set[bytes] = set()
    for key in configured_keys:
        if not key:
            continue
        lower_key = key.lower()
        if lower_key.startswith(b"submodule.") and lower_key.endswith(b".url"):
            name = key[len(b"submodule.") : -len(b".url")]
            configured_urls.add(name)
            named_path = pathlib.PurePosixPath(os.fsdecode(name))
            if named_path in gitlinks:
                configured_names.setdefault(name, set()).add(named_path)
        elif (
            lower_key != b"submodule.active"
            and lower_key.startswith(b"submodule.")
            and lower_key.endswith(b".active")
        ):
            name = key[len(b"submodule.") : -len(b".active")]
            named_path = pathlib.PurePosixPath(os.fsdecode(name))
            if named_path in gitlinks:
                configured_names.setdefault(name, set()).add(named_path)

    configured_active = _effective_tracked_submodule_active(
        root,
        configured_names.keys(),
    )

    globally_selected: set[pathlib.PurePosixPath] = set()
    for name, paths in configured_names.items():
        if name in configured_urls or configured_active.get(name) is True:
            raise NamedLaneGuardError(
                "tracked gitlinks must not be initialized as submodules"
            )
        if configured_active.get(name) is False:
            continue
        globally_selected.update(paths)

    configured_paths = frozenset(
        path for paths in configured_names.values() for path in paths
    )
    globally_selected.update(gitlinks.difference(configured_paths))

    if globally_selected:
        global_active = _effective_submodule_active_pathspecs(root)
        if _match_submodule_active_pathspecs(
            root,
            frozen_head,
            frozenset(globally_selected),
            global_active,
        ):
            raise NamedLaneGuardError(
                "tracked gitlinks must not be initialized as submodules"
            )


def _effective_tracked_submodule_active(
    root: pathlib.Path,
    names: Iterable[bytes],
) -> dict[bytes, bool]:
    tracked_names = tuple(sorted(set(names)))
    if not tracked_names:
        return {}
    escaped_names = tuple(_escape_posix_ere(name) for name in tracked_names)
    pattern = b"^submodule\\.(" + b"|".join(escaped_names) + b")\\.active$"
    if (
        len(tracked_names) > SUBMODULE_ACTIVE_PATHSPEC_COUNT_LIMIT
        or len(pattern) > SUBMODULE_ACTIVE_PATHSPEC_ARGV_LIMIT_BYTES
    ):
        raise NamedLaneGuardError("tracked submodule active keys are too large")
    active_definitions = _git_capture(
        root,
        (
            "config",
            "--no-includes",
            "--null",
            "--type=bool",
            "--get-regexp",
            os.fsdecode(pattern),
        ),
        allow_no_match=True,
    )
    configured_active: dict[bytes, bool] = {}
    for key, value in _parse_git_config_records(
        active_definitions,
        label="effective submodule active",
    ):
        lower_key = key.lower()
        if not lower_key.startswith(b"submodule.") or not lower_key.endswith(
            b".active"
        ):
            raise NamedLaneGuardError("malformed effective submodule active record")
        if value not in {b"true", b"false"}:
            raise NamedLaneGuardError("malformed effective submodule active boolean")
        configured_active[key[len(b"submodule.") : -len(b".active")]] = value == b"true"
    return configured_active


def _escape_posix_ere(value: bytes) -> bytes:
    special = b".^$*+?{}[]\\|()"
    return b"".join(
        b"\\" + bytes((character,)) if character in special else bytes((character,))
        for character in value
    )


def _parse_git_config_records(
    payload: bytes,
    *,
    label: str,
) -> tuple[tuple[bytes, bytes | None], ...]:
    if not payload:
        return ()
    if not payload.endswith(b"\0"):
        raise NamedLaneGuardError(f"malformed {label} record")
    records: list[tuple[bytes, bytes | None]] = []
    for record in payload[:-1].split(b"\0"):
        key, separator, value = record.partition(b"\n")
        if not key:
            raise NamedLaneGuardError(f"malformed {label} record")
        records.append((key, value if separator else None))
    return tuple(records)


def _effective_submodule_active_pathspecs(root: pathlib.Path) -> tuple[bytes, ...]:
    payload = _git_capture(
        root,
        (
            "config",
            "--no-includes",
            "--null",
            "--get-all",
            "submodule.active",
        ),
        allow_no_match=True,
    )
    if not payload:
        return ()
    if not payload.endswith(b"\0"):
        raise NamedLaneGuardError("malformed effective submodule active pathspec")
    return tuple(payload[:-1].split(b"\0"))


def _match_submodule_active_pathspecs(
    root: pathlib.Path,
    frozen_head: str,
    gitlinks: frozenset[pathlib.PurePosixPath],
    pathspecs: Sequence[bytes],
) -> frozenset[pathlib.PurePosixPath]:
    if not pathspecs:
        return frozenset()
    argv_size = sum(len(pathspec) + 8 for pathspec in pathspecs)
    if (
        len(pathspecs) > SUBMODULE_ACTIVE_PATHSPEC_COUNT_LIMIT
        or argv_size > SUBMODULE_ACTIVE_PATHSPEC_ARGV_LIMIT_BYTES
    ):
        raise NamedLaneGuardError("effective submodule active pathspecs are too large")
    payload = _git_capture(
        root,
        (
            "ls-files",
            "--cached",
            "--full-name",
            f"--with-tree={frozen_head}",
            "-z",
            "--",
            *(os.fsdecode(pathspec) for pathspec in pathspecs),
        ),
        output_limit_bytes=_checkout_tree_output_limit(len(frozen_head)),
    )
    matched = frozenset(
        pathlib.PurePosixPath(os.fsdecode(path))
        for path in payload.split(b"\0")
        if path
    )
    return gitlinks.intersection(matched)


def _validate_git_config_includes(configured_keys: frozenset[bytes]) -> None:
    for key in configured_keys:
        lower_key = key.lower()
        if lower_key == b"include.path" or (
            lower_key.startswith(b"includeif.") and lower_key.endswith(b".path")
        ):
            raise NamedLaneGuardError(
                "Git config include directives are not allowed before reviewer launch"
            )


def _validate_core_fsmonitor_config(
    records: Sequence[tuple[bytes, bytes | None]],
) -> None:
    message = "effective core.fsmonitor must be disabled before reviewer launch"
    values = [value for key, value in records if key.lower() == b"core.fsmonitor"]
    if any(
        value is None
        or (value.strip() != b"" and not _git_config_value_is_false(value))
        for value in values
    ):
        raise NamedLaneGuardError(message)


def _matches_named_driver_key(
    key: bytes,
    prefix: bytes,
    variables: frozenset[bytes],
) -> bool:
    if not key.startswith(prefix):
        return False
    _driver, separator, variable = key[len(prefix) :].rpartition(b".")
    return bool(separator) and variable in variables


def _validate_executable_git_config(configured_keys: frozenset[bytes]) -> None:
    for key in configured_keys:
        lower_key = key.lower()
        if lower_key.startswith(b"alias."):
            raise NamedLaneGuardError(
                "Git config aliases are not allowed before reviewer launch"
            )
        status_filter = _matches_named_driver_key(
            lower_key,
            b"filter.",
            frozenset((b"clean", b"process")),
        )
        reviewer_diff = lower_key == b"diff.external" or (
            _matches_named_driver_key(
                lower_key,
                b"diff.",
                frozenset((b"command", b"textconv")),
            )
        )
        if status_filter or reviewer_diff:
            raise NamedLaneGuardError(
                "executable Git filter or diff commands are not allowed"
            )


def _status_has_disallowed_changes(
    payload: bytes,
    safe_gitlinks: frozenset[pathlib.PurePosixPath],
) -> bool:
    for record in payload.split(b"\0"):
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise NamedLaneGuardError("malformed Git status record")
        path = pathlib.PurePosixPath(os.fsdecode(record[3:]))
        if record[0:2] == b" D" and path in safe_gitlinks:
            continue
        return True
    return False


def _relative_target_stays_inside(
    link_path: pathlib.PurePosixPath,
    target_text: str,
) -> bool:
    target = pathlib.PurePosixPath(target_text)
    if target.is_absolute():
        return False
    depth = len(link_path.parent.parts)
    for component in target.parts:
        if component == "..":
            if depth == 0:
                return False
            depth -= 1
        elif component not in {"", "."}:
            depth += 1
    return True


def _read_symlink_blobs(
    root: pathlib.Path,
    object_ids: Sequence[str],
) -> dict[str, str]:
    if len(object_ids) > SYMLINK_COUNT_LIMIT:
        raise NamedLaneGuardError("frozen Git tree contains too many symlinks")
    if not object_ids:
        return {}
    unique_object_ids = tuple(dict.fromkeys(object_ids))
    queries = bytearray(
        "".join(f"{object_id}\n" for object_id in unique_object_ids).encode("ascii")
    )
    payload = _git_capture(
        root,
        ("cat-file", "--batch"),
        output_limit_bytes=SYMLINK_BATCH_OUTPUT_LIMIT_BYTES,
        stdin=queries,
    )
    targets: dict[str, str] = {}
    cursor = 0
    for expected_object_id in unique_object_ids:
        header_end = payload.find(b"\n", cursor)
        if header_end < 0:
            raise NamedLaneGuardError("malformed Git symlink batch output")
        header = payload[cursor:header_end].split(b" ")
        if len(header) != 3:
            raise NamedLaneGuardError("malformed Git symlink batch header")
        raw_object_id, object_type, raw_size = header
        try:
            object_id = raw_object_id.decode("ascii")
            size = int(raw_size.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise NamedLaneGuardError("malformed Git symlink batch header") from error
        if (
            object_id != expected_object_id
            or object_type != b"blob"
            or size < 0
            or size > SYMLINK_TARGET_LIMIT_BYTES
        ):
            raise NamedLaneGuardError("frozen Git symlink target is invalid")
        target_start = header_end + 1
        target_end = target_start + size
        if target_end >= len(payload) or payload[target_end : target_end + 1] != b"\n":
            raise NamedLaneGuardError("malformed Git symlink batch payload")
        target = payload[target_start:target_end]
        if b"\0" in target:
            raise NamedLaneGuardError("frozen Git symlink target is invalid")
        targets[object_id] = os.fsdecode(target)
        cursor = target_end + 1
    if cursor != len(payload):
        raise NamedLaneGuardError("unexpected Git symlink batch output")
    return targets


def _validate_materialized_symlink(
    root: pathlib.Path,
    relative_path: pathlib.PurePosixPath,
    expected_target: str,
) -> None:
    candidate = root.joinpath(*relative_path.parts)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            f"tracked symlink is not materialized: {relative_path.as_posix()}"
        ) from error
    if not stat.S_ISLNK(metadata.st_mode):
        raise NamedLaneGuardError(
            f"tracked symlink is not materialized as a symlink: {relative_path.as_posix()}"
        )
    try:
        first_target = os.readlink(candidate)
    except OSError as error:
        raise NamedLaneGuardError(
            f"tracked symlink cannot be read safely: {relative_path.as_posix()}"
        ) from error
    if first_target != expected_target:
        raise NamedLaneGuardError(
            f"tracked symlink differs from the frozen tree: {relative_path.as_posix()}"
        )
    if not _relative_target_stays_inside(relative_path, first_target):
        raise NamedLaneGuardError(
            f"tracked symlink escapes the worktree lexically: {relative_path.as_posix()}"
        )
    try:
        resolved_once = (candidate.parent / first_target).resolve(strict=False)
        second_target = os.readlink(candidate)
        resolved_twice = (candidate.parent / second_target).resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            f"tracked symlink cannot be resolved safely: {relative_path.as_posix()}"
        ) from error
    if first_target != second_target or resolved_once != resolved_twice:
        raise NamedLaneGuardError(
            f"tracked symlink changed during validation: {relative_path.as_posix()}"
        )
    if not is_relative_to(resolved_once, root):
        raise NamedLaneGuardError(
            f"tracked symlink resolves outside the worktree: {relative_path.as_posix()}"
        )


def _validate_materialized_gitlink(
    root: pathlib.Path,
    relative_path: pathlib.PurePosixPath,
) -> str:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current_descriptor = -1
    try:
        current_descriptor = os.open(root, directory_flags)
        for component in relative_path.parts:
            try:
                next_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=current_descriptor,
                )
            except FileNotFoundError:
                return "absent"
            except OSError as error:
                raise NamedLaneGuardError(
                    "tracked gitlink must be absent or an empty real directory: "
                    f"{relative_path.as_posix()}"
                ) from error
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        if not stat.S_ISDIR(os.fstat(current_descriptor).st_mode):
            raise NamedLaneGuardError(
                "tracked gitlink must be absent or an empty real directory: "
                f"{relative_path.as_posix()}"
            )
        with os.scandir(current_descriptor) as entries:
            materialized = next(entries, None) is not None
    except OSError as error:
        raise NamedLaneGuardError(
            f"tracked gitlink cannot be inspected safely: {relative_path.as_posix()}"
        ) from error
    finally:
        if current_descriptor >= 0:
            os.close(current_descriptor)
    if materialized:
        raise NamedLaneGuardError(
            f"tracked gitlink must remain uninitialized: {relative_path.as_posix()}"
        )
    return "empty"


def _normalize_guidance_path(value: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise NamedLaneGuardError("guidance path must be repository-relative")
    return path


def _validate_guidance_file(
    root: pathlib.Path,
    relative_path: pathlib.PurePosixPath,
    entry: tuple[str, str, str] | None,
) -> None:
    if entry is None or entry[0] not in {"100644", "100755"} or entry[1] != "blob":
        raise NamedLaneGuardError(
            f"guidance must be a tracked regular file: {relative_path.as_posix()}"
        )
    candidate = root.joinpath(*relative_path.parts)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            f"guidance cannot be resolved safely: {relative_path.as_posix()}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NamedLaneGuardError(
            f"guidance must materialize as a regular file: {relative_path.as_posix()}"
        )
    if not is_relative_to(resolved, root):
        raise NamedLaneGuardError(
            f"guidance resolves outside the worktree: {relative_path.as_posix()}"
        )


def _validate_materialized_ref(
    root: pathlib.Path,
    ref_name: str,
    expected_sha: str,
) -> None:
    actual = _git_capture(
        root,
        ("show-ref", "--hash", "--verify", ref_name),
        output_limit_bytes=len(expected_sha) + 1,
    )
    if actual != expected_sha.encode("ascii") + b"\n":
        raise NamedLaneGuardError(
            f"materialized {ref_name} does not match the frozen object ID"
        )


def _parse_validator_commit_rows(
    payload: bytes,
    oid_length: int,
    *,
    label: str,
) -> tuple[tuple[bytes, ...], ...]:
    if payload and not payload.endswith(b"\n"):
        raise NamedLaneGuardError(f"{label} is malformed")
    rows = (
        tuple(line.split(b" ") for line in payload[:-1].split(b"\n")) if payload else ()
    )
    oid_pattern = re.compile(rb"[0-9a-f]{" + str(oid_length).encode("ascii") + rb"}\Z")
    if any(
        not row or any(oid_pattern.fullmatch(object_id) is None for object_id in row)
        for row in rows
    ):
        raise NamedLaneGuardError(f"{label} is malformed")
    if len(rows) > MATERIALIZER_OBJECT_COUNT_LIMIT:
        raise NamedLaneGuardError(f"{label} exceeds the object-count limit")
    return rows


def _revalidate_materialized_controls(
    root: pathlib.Path,
    git_directory: pathlib.Path,
    git: pathlib.Path,
    config_environment: Mapping[str, str],
    local_config_binding: _LocalConfigBinding,
    info_binding: _GitInfoBinding,
) -> None:
    current_git_directory = _validate_materialized_admin_directory(
        root,
        expected_local_config=local_config_binding,
    )
    if current_git_directory != git_directory:
        raise NamedLaneGuardError(
            "materialized Git admin directory changed during validation"
        )
    _audit_direct_local_config(
        current_git_directory / "config",
        git,
        config_environment,
        root.parent,
        expected=local_config_binding,
    )
    _bind_materialized_git_info(
        current_git_directory,
        expected=info_binding,
    )


def _validate_materialized_frozen_range(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
    git_directory: pathlib.Path,
    git: pathlib.Path,
    config_environment: Mapping[str, str],
    local_config_binding: _LocalConfigBinding,
    info_binding: _GitInfoBinding,
) -> _ParentGraphCounts:
    _validate_materialized_object_storage(
        git_directory,
        expected_shallow_boundary=base_sha,
    )
    _validate_materialized_ref(root, MATERIALIZER_BASE_REF, base_sha)
    _validate_materialized_ref(root, MATERIALIZER_HEAD_REF, head_sha)

    for revision, expected in ((base_sha, base_sha), (head_sha, head_sha)):
        actual = os.fsdecode(
            _git_capture(
                root,
                ("rev-parse", "--verify", f"{revision}^{{commit}}"),
                output_limit_bytes=len(expected) + 1,
            )
        ).strip()
        if actual != expected:
            raise NamedLaneGuardError(
                "materialized frozen endpoint is not the exact commit object"
            )

    merge_bases = _git_capture(
        root,
        ("merge-base", "--all", base_sha, head_sha),
        allow_no_match=True,
        output_limit_bytes=2 * (len(head_sha) + 1),
    )
    if merge_bases != base_sha.encode("ascii") + b"\n":
        raise NamedLaneGuardError(
            "frozen base must be the unique merge base of the frozen head"
        )

    commit_output_limit = MATERIALIZER_OBJECT_COUNT_LIMIT * (len(head_sha) + 1)
    range_rows = _parse_validator_commit_rows(
        _git_capture(
            root,
            (
                "rev-list",
                "--no-object-names",
                "--missing=error",
                "--ancestry-path",
                head_sha,
                f"^{base_sha}",
                "--",
            ),
            output_limit_bytes=commit_output_limit,
        ),
        len(head_sha),
        label="materialized frozen-range commit traversal",
    )
    if any(len(row) != 1 for row in range_rows):
        raise NamedLaneGuardError(
            "materialized frozen-range commit traversal is malformed"
        )
    expected_commits = frozenset(
        (base_sha.encode("ascii"), *(row[0] for row in range_rows))
    )
    if len(expected_commits) != len(range_rows) + 1:
        raise NamedLaneGuardError(
            "materialized frozen-range commit traversal contains duplicate commits"
        )
    if len(expected_commits) > MATERIALIZER_OBJECT_COUNT_LIMIT:
        raise NamedLaneGuardError(
            "materialized frozen-range commit traversal exceeds the object-count limit"
        )

    parent_output_limit = _parent_graph_output_limit(
        len(expected_commits),
        len(head_sha),
    )
    try:
        parent_payload = _git_capture(
            root,
            (
                "rev-list",
                "--parents",
                "--missing=error",
                head_sha,
                "--",
            ),
            output_limit_bytes=parent_output_limit,
        )
    except ReviewOutputLimitError as error:
        raise NamedLaneGuardError(
            "frozen commit parent graph exceeds the parent-edge budget"
        ) from error
    parent_graph = _parse_parent_graph(
        parent_payload,
        expected_commits,
        base_sha.encode("ascii"),
        len(head_sha),
        label="materialized shallow parent traversal",
        scope_mismatch_message=(
            "materialized shallow commit scope does not match the frozen range"
        ),
    )

    # Revalidate the range-bearing storage and refs after graph traversal so a
    # changed shallow boundary or endpoint cannot be handed to the first status.
    _revalidate_materialized_controls(
        root,
        git_directory,
        git,
        config_environment,
        local_config_binding,
        info_binding,
    )
    final_git_directory = _validate_materialized_admin_directory(
        root,
        expected_local_config=local_config_binding,
    )
    _validate_materialized_object_storage(
        final_git_directory,
        expected_shallow_boundary=base_sha,
    )
    _validate_materialized_ref(root, MATERIALIZER_BASE_REF, base_sha)
    _validate_materialized_ref(root, MATERIALIZER_HEAD_REF, head_sha)
    final_head = _git_capture(
        root,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        output_limit_bytes=len(head_sha) + 1,
    )
    if final_head != head_sha.encode("ascii") + b"\n":
        raise NamedLaneGuardError(
            "materialized HEAD changed during frozen-range validation"
        )
    return parent_graph


def validate_worktree(
    worktree: pathlib.Path,
    base_sha: str,
    head_sha: str,
    guidance_paths: Sequence[str] = (),
) -> WorktreeValidation:
    if FULL_OBJECT_ID.fullmatch(base_sha) is None:
        raise NamedLaneGuardError("frozen base must be a full Git object ID")
    if FULL_OBJECT_ID.fullmatch(head_sha) is None:
        raise NamedLaneGuardError("frozen head must be a full Git object ID")
    if len(base_sha) != len(head_sha):
        raise NamedLaneGuardError(
            "frozen base and head must use the same Git object format"
        )
    frozen_base = base_sha.lower()
    root = _resolve_worktree_path(worktree)
    git_directory = _validate_materialized_admin_directory(root)
    git = resolve_git()
    config_environment = _git_environment()
    config_environment["GIT_CEILING_DIRECTORIES"] = str(root.parent)
    local_config_binding, config_records = _audit_direct_local_config(
        git_directory / "config",
        git,
        config_environment,
        root.parent,
    )
    configured_keys = frozenset(key for key, _value in config_records)
    info_binding = _bind_materialized_git_info(git_directory)
    _verify_git_worktree_root(root)
    actual_head = os.fsdecode(
        _git_capture(root, ("rev-parse", "--verify", "HEAD^{commit}"))
    ).strip()
    frozen_head = os.fsdecode(
        _git_capture(root, ("rev-parse", "--verify", f"{head_sha}^{{commit}}"))
    ).strip()
    if not actual_head or actual_head != frozen_head:
        raise NamedLaneGuardError("worktree HEAD does not match the frozen head")
    if frozen_head != head_sha.lower():
        raise NamedLaneGuardError(
            "materialized frozen head is not the exact commit object"
        )
    parent_graph = _validate_materialized_frozen_range(
        root,
        frozen_base,
        frozen_head,
        git_directory,
        git,
        config_environment,
        local_config_binding,
        info_binding,
    )
    tree = _parse_tree(
        _git_capture(
            root,
            ("ls-tree", "-r", "-z", "--full-tree", frozen_head),
            output_limit_bytes=_checkout_tree_output_limit(len(frozen_head)),
        )
    )
    gitlinks = frozenset(path for path, entry in tree.items() if entry[0] == "160000")
    for path in gitlinks:
        mode, object_type, _object_id = tree[path]
        if mode != "160000" or object_type != "commit":
            raise NamedLaneGuardError("frozen Git gitlink entry has an invalid type")
    _validate_initialized_submodules(
        root,
        frozen_head,
        tree,
        gitlinks,
        configured_keys,
    )
    _validate_index_flags(
        _git_capture(
            root,
            ("ls-files", "--cached", "--full-name", "-v", "-z", "--"),
            output_limit_bytes=_checkout_tree_output_limit(len(frozen_head)),
        )
    )
    # Status may interpret a materialized gitfile and traverse outside the
    # worktree, so reject every populated gitlink before invoking it.
    gitlink_states = {
        path: _validate_materialized_gitlink(root, path) for path in gitlinks
    }
    absent_gitlinks = frozenset(
        path for path, state in gitlink_states.items() if state == "absent"
    )
    _revalidate_materialized_controls(
        root,
        git_directory,
        git,
        config_environment,
        local_config_binding,
        info_binding,
    )
    status = _git_capture(
        root,
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
            "--ignore-submodules=none",
            "--no-renames",
            "--",
        ),
        output_limit_bytes=_checkout_tree_output_limit(len(frozen_head)),
    )
    if _status_has_disallowed_changes(status, absent_gitlinks):
        raise NamedLaneGuardError("worktree must be clean before reviewer launch")
    symlinks = [path for path, entry in tree.items() if entry[0] == "120000"]
    symlink_targets = _read_symlink_blobs(
        root,
        [tree[path][2] for path in symlinks],
    )
    for path in symlinks:
        mode, object_type, object_id = tree[path]
        if mode != "120000" or object_type != "blob":
            raise NamedLaneGuardError("frozen Git symlink entry has an invalid type")
        _validate_materialized_symlink(
            root,
            path,
            symlink_targets[object_id],
        )
    guidance = {path for path in tree if path.name == "AGENTS.md"}
    guidance.update(_normalize_guidance_path(value) for value in guidance_paths)
    for path in sorted(guidance, key=lambda item: item.as_posix()):
        _validate_guidance_file(root, path, tree.get(path))
    _revalidate_materialized_controls(
        root,
        git_directory,
        git,
        config_environment,
        local_config_binding,
        info_binding,
    )
    return WorktreeValidation(
        root=root,
        base_sha=frozen_base,
        head_sha=frozen_head,
        commit_count=parent_graph.commit_count,
        parent_edge_count=parent_graph.parent_edge_count,
        parent_graph_sha256=parent_graph.parent_graph_sha256,
        local_config_sha256=local_config_binding.sha256,
        symlink_count=len(symlinks),
        guidance_count=len(guidance),
    )


def _validate_positive_finite(value: float, label: str) -> float:
    if not math.isfinite(value) or value <= 0:
        raise NamedLaneGuardError(f"{label} must be positive and finite")
    return value


def _validate_timeout_limit(value: float) -> float:
    timeout = _validate_positive_finite(float(value), "timeout")
    if timeout > DEFAULT_TIMEOUT_SECONDS:
        raise NamedLaneGuardError(
            f"timeout must not exceed {DEFAULT_TIMEOUT_SECONDS:g} seconds"
        )
    return timeout


def _validate_byte_limit(value: int, maximum: int, label: str) -> int:
    if value <= 0:
        raise NamedLaneGuardError(f"{label} must be positive")
    if value > maximum:
        raise NamedLaneGuardError(f"{label} must not exceed {maximum} bytes")
    return value


def _remaining_deadline_seconds(deadline: float, label: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReviewTimeoutError(f"{label} exceeded its monotonic deadline")
    return remaining


def _bounded_deadline(
    timeout_seconds: float,
    deadline_monotonic: float | None = None,
) -> float:
    timeout = _validate_timeout_limit(timeout_seconds)
    duration_deadline = time.monotonic() + timeout
    if deadline_monotonic is None:
        return duration_deadline
    absolute_deadline = _validate_positive_finite(
        float(deadline_monotonic),
        "deadline",
    )
    return min(duration_deadline, absolute_deadline)


def _read_control_prompt(
    stream: BinaryIO,
    limit_bytes: int,
    deadline: float,
) -> bytes:
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError) as error:
        raise NamedLaneGuardError(
            "Claude control prompt requires file-descriptor-backed stdin"
        ) from error
    payload = bytearray()
    while len(payload) <= limit_bytes:
        timeout = _remaining_deadline_seconds(
            deadline,
            "Claude control prompt read",
        )
        try:
            readable, _, _ = select.select((descriptor,), (), (), timeout)
        except InterruptedError:
            continue
        if not readable:
            raise ReviewTimeoutError(
                "Claude control prompt read exceeded its monotonic deadline"
            )
        try:
            chunk = os.read(
                descriptor,
                min(64 * 1024, limit_bytes + 1 - len(payload)),
            )
        except (BlockingIOError, InterruptedError):
            continue
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


@dataclass
class _StructuredSignalState:
    committed_returncode: int | None = None

    def commit(self, returncode: int) -> None:
        self.committed_returncode = returncode


@contextlib.contextmanager
def _structured_forwarded_signals() -> Iterable[_StructuredSignalState]:
    state = _StructuredSignalState()
    previous_handlers: dict[signal.Signals, object] = {}

    def raise_forwarded_signal(signum: int, _frame: object) -> None:
        raise ForwardedSignal(signal.Signals(signum))

    previous_mask = block_forwarded_signals()
    pending_signal: signal.Signals | None = None
    initial_mask_restored = False
    try:
        for forwarded in forwarded_signals():
            previous_handlers[forwarded] = signal.getsignal(forwarded)
            signal.signal(forwarded, raise_forwarded_signal)
        if previous_mask is not None:
            pending_signal = consume_pending_forwarded_signal()
        restore_signal_mask(previous_mask)
        initial_mask_restored = True
        if pending_signal is not None:
            raise ForwardedSignal(pending_signal)
        yield state
    finally:
        committed_returncode = state.committed_returncode
        if committed_returncode is not None:
            try:
                cleanup_mask = block_forwarded_signals()
                if cleanup_mask is not None:
                    consume_pending_forwarded_signal()
                restore_signal_mask(
                    cleanup_mask if initial_mask_restored else previous_mask
                )
                for forwarded, previous in previous_handlers.items():
                    signal.signal(forwarded, previous)
            except BaseException:
                _terminal_process_exit(committed_returncode)
        else:
            cleanup_mask = block_forwarded_signals()
            pending_cleanup_signal: signal.Signals | None = None
            try:
                for forwarded, previous in previous_handlers.items():
                    signal.signal(forwarded, previous)
                if cleanup_mask is not None:
                    pending_cleanup_signal = consume_pending_forwarded_signal()
            finally:
                restore_signal_mask(
                    cleanup_mask if initial_mask_restored else previous_mask
                )
            if pending_cleanup_signal is not None:
                raise ForwardedSignal(pending_cleanup_signal)


def _revalidate_output_parent(target: _OutputTarget) -> None:
    parent = target.path.parent
    try:
        descriptor_metadata = os.fstat(target.parent_fd)
        lexical_metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Claude output parent changed after validation"
        ) from error
    if (
        not stat.S_ISDIR(descriptor_metadata.st_mode)
        or not stat.S_ISDIR(lexical_metadata.st_mode)
        or stat.S_ISLNK(lexical_metadata.st_mode)
        or descriptor_metadata.st_uid != os.getuid()
        or lexical_metadata.st_uid != os.getuid()
        or stat.S_IMODE(descriptor_metadata.st_mode) != 0o700
        or stat.S_IMODE(lexical_metadata.st_mode) != 0o700
        or resolved != parent
        or _output_identity(descriptor_metadata) != target.parent_identity
        or _output_identity(lexical_metadata) != target.parent_identity
    ):
        raise NamedLaneGuardError("Claude output parent changed after validation")


def _output_parent_path_names_bound_directory(target: _OutputTarget) -> bool:
    parent = target.path.parent
    try:
        lexical_metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return (
        stat.S_ISDIR(lexical_metadata.st_mode)
        and not stat.S_ISLNK(lexical_metadata.st_mode)
        and resolved == parent
        and _output_identity(lexical_metadata) == target.parent_identity
    )


def _validate_output_path(path: pathlib.Path, worktree: pathlib.Path) -> _OutputTarget:
    if not path.is_absolute():
        raise NamedLaneGuardError("output paths must be absolute")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise NamedLaneGuardError(
            "Claude output path is not safely accessible"
        ) from error
    else:
        raise NamedLaneGuardError("Claude output path must not already exist")
    lexical_parent = path.parent
    try:
        parent_metadata = lexical_parent.lstat()
        parent_resolved = lexical_parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Claude output parent is not safely accessible"
        ) from error
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(
        parent_metadata.st_mode
    ):
        raise NamedLaneGuardError("Claude output parent must be a real directory")
    if parent_resolved != lexical_parent:
        raise NamedLaneGuardError("Claude output parent must not traverse a symlink")
    canonical = parent_resolved / path.name
    if is_relative_to(canonical, worktree):
        raise NamedLaneGuardError("Claude output paths must stay outside the worktree")
    if (
        parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        raise NamedLaneGuardError(
            "Claude output parent must be current-user-owned with mode 0700"
        )
    open_flags = os.O_RDONLY
    for flag_name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"):
        open_flags |= getattr(os, flag_name, 0)
    try:
        parent_fd = os.open(parent_resolved, open_flags)
    except OSError as error:
        raise NamedLaneGuardError(
            "Claude output parent cannot be opened safely"
        ) from error
    try:
        opened_metadata = os.fstat(parent_fd)
    except OSError as error:
        os.close(parent_fd)
        raise NamedLaneGuardError(
            "Claude output parent cannot be inspected safely"
        ) from error
    if (opened_metadata.st_dev, opened_metadata.st_ino) != (
        parent_metadata.st_dev,
        parent_metadata.st_ino,
    ) or (
        opened_metadata.st_uid != os.getuid()
        or stat.S_IMODE(opened_metadata.st_mode) != 0o700
    ):
        os.close(parent_fd)
        raise NamedLaneGuardError("Claude output parent changed during validation")
    target = _OutputTarget(
        path=canonical,
        parent_fd=parent_fd,
        parent_identity=_output_identity(opened_metadata),
    )
    try:
        _revalidate_output_parent(target)
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise NamedLaneGuardError(
                "Claude output path is not safely accessible"
            ) from error
        else:
            raise NamedLaneGuardError("Claude output path must not already exist")
    except Exception:
        os.close(parent_fd)
        raise
    return target


def _validate_node_extra_ca_certs(path: pathlib.Path) -> str:
    if not path.is_absolute():
        raise NamedLaneGuardError("Node extra CA path must be absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Node extra CA path is not safely accessible"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != path
    ):
        raise NamedLaneGuardError(
            "Node extra CA path must be an exact readable regular file"
        )
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise NamedLaneGuardError("Node extra CA validation requires O_NOFOLLOW")
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if nonblocking is None:
        raise NamedLaneGuardError("Node extra CA validation requires O_NONBLOCK")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | nonblocking,
        )
    except OSError as error:
        raise NamedLaneGuardError(
            "Node extra CA path must be an exact readable regular file"
        ) from error
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            "Node extra CA path changed during validation"
        ) from error
    finally:
        os.close(descriptor)

    def identity(value: os.stat_result) -> tuple[int, int, int, int]:
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid)

    if identity(metadata) != identity(opened) or identity(opened) != identity(after):
        raise NamedLaneGuardError("Node extra CA path changed during validation")
    return str(resolved)


def _claude_environment(
    worktree: pathlib.Path,
    inherit_node_extra_ca_certs: bool = False,
) -> dict[str, str]:
    if os.name != "posix":
        raise NamedLaneGuardError("named Claude lanes require a POSIX account")
    if os.getuid() != os.geteuid():
        raise NamedLaneGuardError(
            "named Claude lanes require matching real and effective users"
        )
    try:
        import pwd

        account = pwd.getpwuid(os.getuid())
    except (ImportError, KeyError, OSError) as error:
        raise NamedLaneGuardError(
            "current POSIX account cannot be resolved safely"
        ) from error
    environment = {
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CEILING_DIRECTORIES": str(worktree.parent),
        "GIT_GRAFT_FILE": os.devnull,
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": account.pw_dir,
        "LOGNAME": account.pw_name,
        "PAGER": "cat",
        "PATH": TRUSTED_PATH,
        "SHELL": account.pw_shell,
        "USER": account.pw_name,
    }
    for key in CLAUDE_ENV_PASSTHROUGH_KEYS:
        value = os.environ.get(key)
        if value is not None:
            environment[key] = value
    if inherit_node_extra_ca_certs:
        node_extra_ca_certs = os.environ.get("NODE_EXTRA_CA_CERTS")
        if not node_extra_ca_certs:
            raise NamedLaneGuardError(
                "explicit Node extra CA inheritance requires a configured path"
            )
        environment["NODE_EXTRA_CA_CERTS"] = _validate_node_extra_ca_certs(
            pathlib.Path(node_extra_ca_certs)
        )
    return environment


def _resolve_claude_isolation_directory(
    path: pathlib.Path,
    *,
    label: str,
) -> pathlib.Path:
    if not path.is_absolute():
        raise NamedLaneGuardError(f"{label} must be absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(f"{label} cannot be resolved safely") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != path
    ):
        raise NamedLaneGuardError(f"{label} must be a canonical real directory")
    return resolved


def _claude_direct_primary_source_guidance() -> str:
    return (
        "use an ordinary or linked worktree with canonical <common>/objects, "
        "a filesystem reflink/COW copy, or a clone made independent with "
        "--dissociate"
    )


def _claude_source_control_file_binding(
    path: pathlib.Path,
    *,
    label: str,
) -> tuple[_ClaudeSourceControlFileBinding, bytearray]:
    try:
        before = path.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            f"Claude source {label} cannot be inspected"
        ) from error
    payload = _read_materializer_control_file(path, label=label)
    try:
        after = path.lstat()
    except OSError as error:
        payload[:] = b"\x00" * len(payload)
        raise NamedLaneGuardError(
            f"Claude source {label} cannot be revalidated"
        ) from error

    def signature(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            metadata.st_uid,
            metadata.st_size,
        )

    if signature(before) != signature(after):
        payload[:] = b"\x00" * len(payload)
        raise NamedLaneGuardError(
            f"Claude source {label} changed during exact-content binding"
        )
    return (
        _ClaudeSourceControlFileBinding(
            path=path,
            identity=_directory_identity(after),
            file_type=stat.S_IFMT(after.st_mode),
            size=after.st_size,
            sha256=hashlib.sha256(payload).hexdigest(),
        ),
        payload,
    )


def _claude_linked_marker_content_bindings(
    marker: _MaterializerSourceMarkerBinding,
    source: pathlib.Path,
    admin: pathlib.Path,
) -> tuple[_ClaudeSourceControlFileBinding, _ClaudeSourceControlFileBinding]:
    marker_binding, marker_payload = _claude_source_control_file_binding(
        marker.path,
        label="Git admin marker",
    )
    try:
        stripped = bytes(marker_payload).rstrip(b"\r\n")
        prefix = b"gitdir: "
        if not stripped.startswith(prefix) or not stripped[len(prefix) :]:
            raise NamedLaneGuardError("Claude source Git admin marker is malformed")
        if (
            _materializer_control_path(
                stripped[len(prefix) :],
                relative_to=source,
                label="Git admin marker",
            )
            != admin
        ):
            raise NamedLaneGuardError(
                "Claude source Git admin marker does not match its bound admin"
            )
    finally:
        marker_payload[:] = b"\x00" * len(marker_payload)
    back_pointer, back_pointer_payload = _claude_source_control_file_binding(
        admin / "gitdir",
        label="Git admin back-pointer",
    )
    try:
        if (
            _materializer_control_path(
                back_pointer_payload,
                relative_to=admin,
                label="Git admin back-pointer",
            )
            != marker.path
        ):
            raise NamedLaneGuardError(
                "Claude source Git admin back-pointer does not match its marker"
            )
    finally:
        back_pointer_payload[:] = b"\x00" * len(back_pointer_payload)
    return marker_binding, back_pointer


def _claude_common_directory_binding(
    admin: pathlib.Path,
) -> tuple[_ClaudeSourceControlFileBinding | None, pathlib.Path]:
    marker_path = admin / "commondir"
    try:
        marker_path.lstat()
    except FileNotFoundError:
        return None, admin
    except OSError as error:
        raise NamedLaneGuardError(
            "Claude source Git common-directory marker cannot be inspected"
        ) from error
    binding, payload = _claude_source_control_file_binding(
        marker_path,
        label="Git common-directory marker",
    )
    try:
        common = _materializer_control_path(
            payload,
            relative_to=admin,
            label="Git common-directory marker",
        )
    finally:
        payload[:] = b"\x00" * len(payload)
    return binding, common


def _claude_source_object_info_identity(
    objects: pathlib.Path,
) -> _DirectoryIdentity | None:
    info = objects / "info"
    try:
        metadata = info.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise NamedLaneGuardError(
            "Claude source Git object-info storage cannot be inspected; "
            + _claude_direct_primary_source_guidance()
        ) from error
    try:
        resolved = info.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Claude source Git object-info storage must be a canonical real "
            "current-user directory; " + _claude_direct_primary_source_guidance()
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != _current_user_id()
        or resolved != info
    ):
        raise NamedLaneGuardError(
            "Claude source Git object-info storage must be a canonical real "
            "current-user directory; " + _claude_direct_primary_source_guidance()
        )
    return _directory_identity(metadata)


def _reject_claude_source_alternate_entries(objects: pathlib.Path) -> None:
    info = objects / "info"
    for candidate, label in (
        (info / "alternates", "local alternates"),
        (info / "http-alternates", "HTTP alternates"),
    ):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise NamedLaneGuardError(
                f"Claude source Git {label} state cannot be inspected; "
                + _claude_direct_primary_source_guidance()
            ) from error
        raise NamedLaneGuardError(
            f"Claude source Git {label} entry must be absent, regardless of "
            "its contents or file type; " + _claude_direct_primary_source_guidance()
        )


def _bind_claude_source_read_boundary(
    source_worktree: pathlib.Path,
) -> _ClaudeSourceReadBoundaryBinding:
    source = _resolve_claude_isolation_directory(
        source_worktree,
        label="Claude source worktree",
    )
    resolved_source, marker = _resolve_materializer_source(source)
    if resolved_source != source:
        raise NamedLaneGuardError(
            "Claude source worktree must be a canonical Git worktree root"
        )
    _verify_materializer_source_marker(marker, source)
    admin = marker.expected_admin
    _verify_materializer_source_back_pointer(marker, admin)
    commondir, common = _claude_common_directory_binding(admin)
    objects = common / "objects"
    path_metadata: dict[pathlib.Path, os.stat_result] = {}
    for path, label in (
        (source, "Claude source worktree"),
        (admin, "Claude source Git admin directory"),
        (common, "Claude source Git common directory"),
        (objects, "Claude source primary Git object directory"),
    ):
        resolved = _resolve_claude_isolation_directory(path, label=label)
        try:
            metadata = resolved.lstat()
        except OSError as error:
            raise NamedLaneGuardError(f"{label} cannot be inspected") from error
        if metadata.st_uid != _current_user_id():
            raise NamedLaneGuardError(f"{label} must be current-user-owned")
        path_metadata[path] = metadata
    marker_content: _ClaudeSourceControlFileBinding | None = None
    back_pointer: _ClaudeSourceControlFileBinding | None = None
    if marker.is_gitfile:
        marker_content, back_pointer = _claude_linked_marker_content_bindings(
            marker,
            source,
            admin,
        )
        if (
            marker_content.path != marker.path
            or marker_content.identity.device != marker.device
            or marker_content.identity.inode != marker.inode
            or marker_content.identity.owner != marker.owner
            or marker_content.file_type != marker.file_type
        ):
            raise NamedLaneGuardError(
                "Claude source Git marker identity changed during exact-content binding"
            )
    object_info_identity = _claude_source_object_info_identity(objects)
    _reject_claude_source_alternate_entries(objects)

    _verify_materializer_source_marker(marker, source)
    _verify_materializer_source_back_pointer(marker, admin)
    final_commondir, final_common = _claude_common_directory_binding(admin)
    if final_commondir != commondir or final_common != common:
        raise NamedLaneGuardError(
            "Claude source Git common-directory marker or authority changed during "
            "direct-primary source validation"
        )
    if marker.is_gitfile:
        final_marker_content, final_back_pointer = (
            _claude_linked_marker_content_bindings(marker, source, admin)
        )
        if final_marker_content != marker_content or final_back_pointer != back_pointer:
            raise NamedLaneGuardError(
                "Claude source Git marker or back-pointer content changed during "
                "direct-primary source validation"
            )
    for path, label in (
        (source, "Claude source worktree"),
        (admin, "Claude source Git admin directory"),
        (common, "Claude source Git common directory"),
        (objects, "Claude source primary Git object directory"),
    ):
        resolved = _resolve_claude_isolation_directory(path, label=label)
        try:
            final_metadata = resolved.lstat()
        except OSError as error:
            raise NamedLaneGuardError(f"{label} cannot be revalidated") from error
        if _directory_identity(final_metadata) != _directory_identity(
            path_metadata[path]
        ):
            raise NamedLaneGuardError(
                f"{label} changed during direct-primary source validation"
            )
    final_object_info_identity = _claude_source_object_info_identity(objects)
    _reject_claude_source_alternate_entries(objects)
    if final_object_info_identity != object_info_identity:
        raise NamedLaneGuardError(
            "Claude source Git object-info storage changed during direct-primary "
            "source validation"
        )
    roots = tuple(dict.fromkeys((source, admin, common)))
    return _ClaudeSourceReadBoundaryBinding(
        source_worktree=source,
        source_identity=_directory_identity(path_metadata[source]),
        marker=marker,
        marker_content=marker_content,
        back_pointer=back_pointer,
        admin=admin,
        admin_identity=_directory_identity(path_metadata[admin]),
        commondir=commondir,
        common=common,
        common_identity=_directory_identity(path_metadata[common]),
        objects=objects,
        objects_identity=_directory_identity(path_metadata[objects]),
        object_info_identity=object_info_identity,
        deny_roots=roots,
    )


def _resolve_claude_source_read_deny_roots(
    source_worktree: pathlib.Path,
) -> tuple[pathlib.Path, tuple[pathlib.Path, ...]]:
    binding = _bind_claude_source_read_boundary(source_worktree)
    return binding.source_worktree, binding.deny_roots


def _claude_source_identity_tuple(
    identity: _DirectoryIdentity,
) -> tuple[int, int, int]:
    return (identity.device, identity.inode, identity.owner)


def _claude_source_authority_binding_payload(
    binding: _ClaudeSourceReadBoundaryBinding,
) -> dict[str, object]:
    marker_content = binding.marker_content
    back_pointer = binding.back_pointer
    return build_source_authority_binding(
        source_worktree=source_authority_directory_record(
            binding.source_worktree,
            _claude_source_identity_tuple(binding.source_identity),
        ),
        git_marker=source_authority_marker_record(
            binding.marker.path,
            binding.marker.expected_admin,
            (
                binding.marker.device,
                binding.marker.inode,
                binding.marker.owner,
            ),
            file_type=binding.marker.file_type,
            kind="gitfile" if binding.marker.is_gitfile else "directory",
            size=None if marker_content is None else marker_content.size,
            sha256=None if marker_content is None else marker_content.sha256,
        ),
        linked_worktree_back_pointer=(
            None
            if back_pointer is None
            else source_authority_control_record(
                back_pointer.path,
                _claude_source_identity_tuple(back_pointer.identity),
                file_type=back_pointer.file_type,
                size=back_pointer.size,
                sha256=back_pointer.sha256,
            )
        ),
        git_common_directory_marker=(
            None
            if binding.commondir is None
            else source_authority_common_marker_record(
                source_authority_control_record(
                    binding.commondir.path,
                    _claude_source_identity_tuple(binding.commondir.identity),
                    file_type=binding.commondir.file_type,
                    size=binding.commondir.size,
                    sha256=binding.commondir.sha256,
                ),
                binding.common,
            )
        ),
        git_admin=source_authority_directory_record(
            binding.admin,
            _claude_source_identity_tuple(binding.admin_identity),
        ),
        git_common=source_authority_directory_record(
            binding.common,
            _claude_source_identity_tuple(binding.common_identity),
        ),
        primary_object_store=source_authority_directory_record(
            binding.objects,
            _claude_source_identity_tuple(binding.objects_identity),
        ),
        object_info_path=binding.objects / "info",
        object_info_identity=(
            None
            if binding.object_info_identity is None
            else _claude_source_identity_tuple(binding.object_info_identity)
        ),
    )


def _validate_parent_source_authority_binding(
    value: object,
    expected_sha256: object,
) -> tuple[dict[str, object], str]:
    try:
        return validate_source_authority_binding(value, expected_sha256)
    except SourceAuthorityBindingError as error:
        raise NamedLaneGuardError(str(error)) from error


def _parse_parent_source_authority_binding_json(
    value: str,
    expected_sha256: str,
) -> tuple[dict[str, object], str]:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise NamedLaneGuardError(
            "parent source-authority binding JSON is not valid UTF-8"
        ) from error
    if len(encoded) > CLAUDE_SOURCE_AUTHORITY_BINDING_LIMIT_BYTES:
        raise NamedLaneGuardError(
            "parent source-authority binding JSON exceeds its size bound"
        )
    try:
        return parse_canonical_source_authority_binding_bytes(
            encoded,
            expected_sha256,
        )
    except SourceAuthorityBindingError as error:
        raise NamedLaneGuardError(str(error)) from error


def _revalidate_claude_source_read_boundary(
    expected: _ClaudeSourceReadBoundaryBinding,
    parent_binding: Mapping[str, object],
    parent_binding_sha256: str,
) -> None:
    observed = _bind_claude_source_read_boundary(expected.source_worktree)
    observed_payload = _claude_source_authority_binding_payload(observed)
    if (
        observed != expected
        or observed_payload != parent_binding
        or not secrets.compare_digest(
            hashlib.sha256(
                canonical_source_authority_binding_bytes(observed_payload)
            ).hexdigest(),
            parent_binding_sha256,
        )
    ):
        raise NamedLaneGuardError(
            "Claude source direct-primary authority changed after initial "
            "binding; " + _claude_direct_primary_source_guidance()
        )


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _unique_rendered_paths(paths: Iterable[pathlib.Path]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for path in paths:
        rendered = str(path)
        if rendered not in seen:
            result.append(rendered)
            seen.add(rendered)
    return result


def _claude_git_null_read_exception_binding(
    path: pathlib.Path = CLAUDE_DIRECT_GIT_NULL_READ_EXCEPTION,
) -> dict[str, object]:
    if (
        os.name != "posix"
        or pathlib.Path(os.devnull) != CLAUDE_DIRECT_GIT_NULL_READ_EXCEPTION
        or path != CLAUDE_DIRECT_GIT_NULL_READ_EXCEPTION
    ):
        raise NamedLaneGuardError(
            "Claude Git null read exception must be exact canonical /dev/null"
        )
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblocking is None:
        raise NamedLaneGuardError(
            "Claude Git null read exception requires no-follow nonblocking open"
        )
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Claude Git null read exception cannot be resolved safely"
        ) from error
    if (
        resolved != CLAUDE_DIRECT_GIT_NULL_READ_EXCEPTION
        or stat.S_ISLNK(before.st_mode)
        or not stat.S_ISCHR(before.st_mode)
    ):
        raise NamedLaneGuardError(
            "Claude Git null read exception must be exact canonical /dev/null"
        )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | nonblocking,
        )
    except OSError as error:
        raise NamedLaneGuardError(
            "Claude Git null read exception must be a readable character device"
        ) from error
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as error:
        raise NamedLaneGuardError(
            "Claude Git null read exception changed during validation"
        ) from error
    finally:
        os.close(descriptor)

    def identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_rdev,
        )

    if (
        not stat.S_ISCHR(opened.st_mode)
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
    ):
        raise NamedLaneGuardError(
            "Claude Git null read exception changed during validation"
        )
    return {
        "path": str(path),
        "identity_binding": "canonical-no-follow-character-device",
        "identity": {
            "device": opened.st_dev,
            "inode": opened.st_ino,
            "file_type": stat.S_IFMT(opened.st_mode),
            "mode": stat.S_IMODE(opened.st_mode),
            "uid": opened.st_uid,
            "gid": opened.st_gid,
            "rdev": opened.st_rdev,
        },
    }


def _claude_output_profile_binding(target: _OutputTarget) -> dict[str, object]:
    _revalidate_output_parent(target)
    try:
        metadata = os.fstat(target.parent_fd)
    except OSError as error:
        raise NamedLaneGuardError(
            "Claude output parent cannot be inspected for the argv profile"
        ) from error
    return {
        "path": str(target.path),
        "parent": str(target.path.parent),
        "parent_identity": {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "file_type": stat.S_IFMT(metadata.st_mode),
            "uid": metadata.st_uid,
            "mode": stat.S_IMODE(metadata.st_mode),
        },
    }


def _claude_environment_profile_binding(
    child_environment: Mapping[str, str],
) -> dict[str, object]:
    environment = dict(child_environment)
    return {
        "profile": CLAUDE_DIRECT_ENVIRONMENT_PROFILE,
        "assurance": "guard-supplied-process-environment",
        "requested_keys": sorted(environment),
        "requested_environment_sha256": hashlib.sha256(
            _canonical_json_bytes(environment)
        ).hexdigest(),
        "present_passthrough_keys": sorted(
            set(environment).intersection(CLAUDE_ENV_PASSTHROUGH_KEYS)
        ),
        "node_extra_ca_certs_inherited": "NODE_EXTRA_CA_CERTS" in environment,
    }


def _claude_direct_required_options(
    version: tuple[int, int, int],
) -> tuple[str, ...]:
    if version < CLAUDE_GUARD_MANAGED_SESSION_MINIMUM_VERSION:
        return CLAUDE_DIRECT_REQUIRED_OPTIONS
    insertion = CLAUDE_DIRECT_REQUIRED_OPTIONS.index("--safe-mode")
    return (
        *CLAUDE_DIRECT_REQUIRED_OPTIONS[:insertion],
        "--session-id",
        *CLAUDE_DIRECT_REQUIRED_OPTIONS[insertion:],
    )


def _validate_claude_read_boundary_nonoverlap(
    *,
    allow_read: Sequence[pathlib.Path],
    deny_read: Sequence[pathlib.Path],
) -> None:
    for allowed in allow_read:
        for denied in deny_read:
            if (allowed, denied) in CLAUDE_DIRECT_READ_OVERLAP_EXCEPTIONS:
                continue
            if (
                allowed == denied
                or is_relative_to(allowed, denied)
                or is_relative_to(denied, allowed)
            ):
                raise NamedLaneGuardError(
                    "Claude allowRead and denyRead roots must not overlap"
                )


def _build_claude_direct_argv_profile(
    *,
    worktree: pathlib.Path,
    source_worktree: pathlib.Path,
    source_authority_binding: Mapping[str, object],
    source_authority_binding_sha256: str,
    preflight_result: pathlib.Path,
    stdout: _OutputTarget,
    stderr: _OutputTarget,
    child_environment: Mapping[str, str],
    model: str,
) -> _ClaudeDirectArgvProfile:
    if model not in CLAUDE_DIRECT_MODELS:
        raise NamedLaneGuardError(
            "Claude model must match the canonical named-direct model profile"
        )
    source_read_boundary = _bind_claude_source_read_boundary(source_worktree)
    observed_source_authority = _claude_source_authority_binding_payload(
        source_read_boundary
    )
    if (
        observed_source_authority != source_authority_binding
        or not secrets.compare_digest(
            hashlib.sha256(
                canonical_source_authority_binding_bytes(observed_source_authority)
            ).hexdigest(),
            source_authority_binding_sha256,
        )
    ):
        raise NamedLaneGuardError(
            "Claude source authority does not match the parent-owned "
            "prepare-workspace binding"
        )
    source = source_read_boundary.source_worktree
    source_read_deny_roots = source_read_boundary.deny_roots
    if (
        source == worktree
        or is_relative_to(source, worktree)
        or is_relative_to(worktree, source)
    ):
        raise NamedLaneGuardError(
            "Claude source and review worktrees must be independent"
        )
    git_metadata = _resolve_claude_isolation_directory(
        worktree / ".git",
        label="Claude review Git metadata",
    )
    if not is_relative_to(git_metadata, worktree):
        raise NamedLaneGuardError(
            "Claude review Git metadata must stay inside the review worktree"
        )
    home_value = child_environment.get("HOME")
    if type(home_value) is not str or not home_value:
        raise NamedLaneGuardError(
            "Claude account home is missing from the child profile"
        )
    home = _resolve_claude_isolation_directory(
        pathlib.Path(home_value),
        label="Claude account home",
    )
    private_home_paths = tuple(
        home / relative for relative in CLAUDE_DIRECT_PRIVATE_HOME_PATHS
    )
    git_null_read_exception = _claude_git_null_read_exception_binding()
    git_null_path = pathlib.Path(str(git_null_read_exception["path"]))
    deny_read = _unique_rendered_paths(
        (
            *private_home_paths,
            *source_read_deny_roots,
            preflight_result,
            stdout.path,
            stderr.path,
            pathlib.Path("/proc"),
            pathlib.Path("/dev"),
        )
    )
    allow_read_paths = (worktree, git_metadata, git_null_path)
    deny_read_paths = tuple(pathlib.Path(path) for path in deny_read)
    _validate_claude_read_boundary_nonoverlap(
        allow_read=allow_read_paths,
        deny_read=deny_read_paths,
    )
    settings: dict[str, object] = {
        "disableAllHooks": True,
        "disableBundledSkills": True,
        "permissions": {"deny": list(CLAUDE_DIRECT_PERMISSION_DENY_RULES)},
        "sandbox": {
            "allowUnsandboxedCommands": False,
            "autoAllowBashIfSandboxed": False,
            "credentials": {
                "envVars": [
                    {"mode": "deny", "name": key}
                    for key in CLAUDE_DIRECT_SECRET_ENVIRONMENT_KEYS
                ],
                "files": [
                    {"mode": "deny", "path": str(path)} for path in private_home_paths
                ],
            },
            "enabled": True,
            "enableWeakerNestedSandbox": False,
            "enableWeakerNetworkIsolation": False,
            "excludedCommands": [],
            "failIfUnavailable": True,
            "filesystem": {
                "allowRead": [str(path) for path in allow_read_paths],
                "denyRead": deny_read,
                "denyWrite": ["/"],
            },
            "network": {
                "allowAllUnixSockets": False,
                "allowLocalBinding": False,
                "allowUnixSockets": [],
                "allowedDomains": [],
            },
        },
    }
    settings_json = _canonical_json_bytes(settings).decode("utf-8")
    arguments = (
        "--print",
        "--input-format",
        "text",
        "--model",
        model,
        "--effort",
        CLAUDE_DIRECT_EFFORT,
        "--permission-mode",
        CLAUDE_DIRECT_PERMISSION_MODE,
        "--output-format",
        "stream-json",
        "--verbose",
        "--no-session-persistence",
        "--safe-mode",
        "--no-chrome",
        "--disable-slash-commands",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--setting-sources",
        "",
        "--settings",
        settings_json,
        "--tools",
        CLAUDE_DIRECT_VISIBLE_TOOLS,
        "--allowedTools",
        CLAUDE_DIRECT_ALLOWED_TOOLS,
        "--disallowedTools",
        CLAUDE_DIRECT_DISALLOWED_TOOLS,
    )
    if (
        tuple(
            argument
            for argument in arguments
            if argument in CLAUDE_DIRECT_REQUIRED_OPTIONS
        )
        != CLAUDE_DIRECT_REQUIRED_OPTIONS
    ):
        raise NamedLaneGuardError(
            "Claude guard-owned argv does not match its capability contract"
        )
    return _ClaudeDirectArgvProfile(
        model=model,
        worktree=worktree,
        git_metadata=git_metadata,
        account_home=home,
        source_worktree=source,
        source_read_deny_roots=source_read_deny_roots,
        source_read_boundary=source_read_boundary,
        source_authority_binding=source_authority_binding,
        source_authority_binding_sha256=source_authority_binding_sha256,
        preflight_result=preflight_result,
        output_bindings={
            "stdout": _claude_output_profile_binding(stdout),
            "stderr": _claude_output_profile_binding(stderr),
        },
        environment_binding=_claude_environment_profile_binding(child_environment),
        git_null_read_exception=git_null_read_exception,
        settings=settings,
        settings_json=settings_json,
        arguments=arguments,
    )


def _claude_direct_argv_profile_receipt(
    profile: _ClaudeDirectArgvProfile,
    *,
    effective_arguments: Sequence[str],
) -> dict[str, object]:
    _revalidate_claude_source_read_boundary(
        profile.source_read_boundary,
        profile.source_authority_binding,
        profile.source_authority_binding_sha256,
    )
    if _claude_git_null_read_exception_binding() != profile.git_null_read_exception:
        raise NamedLaneGuardError(
            "Claude Git null read exception changed before receipt generation"
        )
    payload: dict[str, object] = {
        "profile": CLAUDE_DIRECT_ARGV_PROFILE,
        "conformance": CLAUDE_DIRECT_ARGV_CONFORMANCE,
        "settings_schema": CLAUDE_DIRECT_SETTINGS_SCHEMA,
        "settings_assurance": "requested-configuration-only",
        "settings_parser_acceptance_attested": False,
        "managed_policy_residual": True,
        "native_sandbox_effectiveness_attested": False,
        "model": profile.model,
        "effort": CLAUDE_DIRECT_EFFORT,
        "worktree": str(profile.worktree),
        "review_git_metadata": str(profile.git_metadata),
        "account_home": str(profile.account_home),
        "source_worktree": str(profile.source_worktree),
        "source_worktree_binding": (
            "prepare-workspace-receipt-exact-digest-bound-authority-v1"
        ),
        "source_read_deny_roots": [
            str(path) for path in profile.source_read_deny_roots
        ],
        "source_authority_policy": "direct-primary-only",
        "source_authority_binding": json.loads(
            canonical_source_authority_binding_bytes(profile.source_authority_binding)
        ),
        "source_authority_binding_sha256": (profile.source_authority_binding_sha256),
        "source_primary_object_store": str(profile.source_read_boundary.objects),
        "source_primary_object_store_identity": {
            "device": profile.source_read_boundary.objects_identity.device,
            "inode": profile.source_read_boundary.objects_identity.inode,
            "uid": profile.source_read_boundary.objects_identity.owner,
        },
        "source_object_info_identity": (
            None
            if profile.source_read_boundary.object_info_identity is None
            else {
                "device": profile.source_read_boundary.object_info_identity.device,
                "inode": profile.source_read_boundary.object_info_identity.inode,
                "uid": profile.source_read_boundary.object_info_identity.owner,
            }
        ),
        "source_authority_revalidation": [
            "pre-spawn",
            "pre-terminal-acceptance",
        ],
        "preflight_result": str(profile.preflight_result),
        "output_bindings": profile.output_bindings,
        "environment_binding": profile.environment_binding,
        "git_null_read_exception": profile.git_null_read_exception,
        "settings": profile.settings,
        "settings_sha256": hashlib.sha256(
            profile.settings_json.encode("utf-8")
        ).hexdigest(),
        "guard_constructed_arguments": list(profile.arguments),
        "guard_constructed_arguments_sha256": hashlib.sha256(
            _canonical_json_bytes(list(profile.arguments))
        ).hexdigest(),
        "effective_arguments": list(effective_arguments),
        "effective_arguments_sha256": hashlib.sha256(
            _canonical_json_bytes(list(effective_arguments))
        ).hexdigest(),
    }
    payload["profile_sha256"] = hashlib.sha256(
        _canonical_json_bytes(payload)
    ).hexdigest()
    return payload


def _claude_directory_stat_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
    )


def _claude_session_directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if directory is None or nofollow is None or nonblocking is None:
        raise NamedLaneGuardError(
            "Claude session environment requires no-follow directory inspection"
        )
    return (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | directory | nofollow | nonblocking
    )


def _validate_claude_session_directory_policy(
    descriptor: int,
    metadata: os.stat_result,
    *,
    label: str,
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    current_user = _current_user_id()
    private_leaf = label == "leaf"
    owned_parent = label == "parent"
    sticky_root = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    owner_is_unsafe = (
        metadata.st_uid != current_user
        if private_leaf or owned_parent
        else metadata.st_uid not in {0, current_user}
    )
    mode_is_unsafe = (
        bool(mode & 0o077)
        if private_leaf
        else (
            bool(mode & 0o022)
            if owned_parent
            else bool(mode & 0o022) and not sticky_root
        )
    )
    if not stat.S_ISDIR(metadata.st_mode) or owner_is_unsafe or mode_is_unsafe:
        raise NamedLaneGuardError(
            f"Claude session environment {label} access policy is unsafe"
        )
    _require_no_legacy_acl_allow_entry(
        descriptor,
        label=f"Claude session environment {label}",
    )


def _open_claude_session_env_parent(
    home: pathlib.Path,
    *,
    create: bool = False,
    acquire_namespace_lock: bool = False,
) -> tuple[
    pathlib.Path,
    int,
    tuple[_ClaudeDirectoryComponent, ...],
    int | None,
]:
    if not home.is_absolute():
        raise NamedLaneGuardError("Claude account home must be absolute")
    parent = home / ".claude" / "session-env"
    try:
        resolution_target = parent if parent.exists() else parent.parent
        if resolution_target.resolve(strict=True) != resolution_target:
            raise NamedLaneGuardError(
                "Claude session environment parent must not traverse a symlink"
            )
    except NamedLaneGuardError:
        raise
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Claude session environment parent cannot be resolved safely"
        ) from error

    flags = _claude_session_directory_flags()
    descriptor = -1
    namespace_descriptor = -1
    keep_descriptor = False
    keep_namespace_descriptor = False
    components: list[_ClaudeDirectoryComponent] = []
    current_path = pathlib.Path(parent.anchor)
    try:
        descriptor = os.open(parent.anchor, flags)
        relative_components = parent.parts[1:]
        for component_index, component in enumerate((None, *relative_components)):
            if component is not None:
                final_component = component_index == len(relative_components)
                created = False
                try:
                    child_descriptor = os.open(
                        component,
                        flags,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not create or not final_component:
                        raise
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                        created = True
                    except FileExistsError:
                        pass
                    child_descriptor = os.open(
                        component,
                        flags,
                        dir_fd=descriptor,
                    )
                if created:
                    os.fchmod(child_descriptor, 0o700)
                try:
                    lexical = os.stat(
                        component,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    opened = os.fstat(child_descriptor)
                except BaseException:
                    os.close(child_descriptor)
                    raise
                if _claude_directory_stat_identity(
                    lexical
                ) != _claude_directory_stat_identity(opened):
                    os.close(child_descriptor)
                    raise NamedLaneGuardError(
                        "Claude session environment custody edge changed"
                    )
                os.close(descriptor)
                descriptor = child_descriptor
                current_path /= component
            metadata = os.fstat(descriptor)
            policy_label = (
                "parent"
                if component is not None and component_index == len(relative_components)
                else "ancestor"
            )
            _validate_claude_session_directory_policy(
                descriptor,
                metadata,
                label=policy_label,
            )
            components.append(
                _ClaudeDirectoryComponent(
                    path=current_path,
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    owner=metadata.st_uid,
                )
            )
            if acquire_namespace_lock and current_path == parent.parent:
                try:
                    namespace_descriptor = os.dup(descriptor)
                    os.set_inheritable(namespace_descriptor, False)
                    fcntl.flock(
                        namespace_descriptor,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                except BlockingIOError as error:
                    raise NamedLaneGuardError(
                        "Claude control directory namespace lease is already held"
                    ) from error
                except OSError as error:
                    raise NamedLaneGuardError(
                        "Claude control directory namespace lease is unavailable"
                    ) from error
                locked = os.fstat(namespace_descriptor)
                if _claude_directory_stat_identity(
                    locked
                ) != _claude_directory_stat_identity(metadata) or os.get_inheritable(
                    namespace_descriptor
                ):
                    raise NamedLaneGuardError(
                        "Claude control directory namespace lease changed"
                    )
                _validate_claude_session_directory_policy(
                    namespace_descriptor,
                    locked,
                    label="ancestor",
                )
        if current_path != parent:
            raise NamedLaneGuardError("Claude session environment custody path changed")
        if acquire_namespace_lock and namespace_descriptor < 0:
            raise NamedLaneGuardError(
                "Claude control directory namespace lease was not acquired"
            )
        keep_descriptor = True
        keep_namespace_descriptor = True
        return (
            parent,
            descriptor,
            tuple(components),
            namespace_descriptor if namespace_descriptor >= 0 else None,
        )
    except NamedLaneGuardError:
        raise
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Claude session environment parent cannot be inspected safely"
        ) from error
    finally:
        if descriptor >= 0 and not keep_descriptor:
            os.close(descriptor)
        if namespace_descriptor >= 0 and not keep_namespace_descriptor:
            os.close(namespace_descriptor)


def _revalidate_held_claude_namespace(session: _ClaudeSessionEnv) -> None:
    held = os.fstat(session.namespace_fd)
    if _claude_directory_stat_identity(held) != session.namespace_identity:
        raise NamedLaneGuardError("Claude control directory namespace identity changed")
    if os.get_inheritable(session.namespace_fd):
        raise NamedLaneGuardError(
            "Claude control directory namespace lease became inheritable"
        )
    _validate_claude_session_directory_policy(
        session.namespace_fd,
        held,
        label="ancestor",
    )


def _revalidate_held_claude_session_env_parent(session: _ClaudeSessionEnv) -> None:
    _revalidate_held_claude_namespace(session)
    held = os.fstat(session.parent_fd)
    expected = session.parent_components[-1]
    if _claude_directory_stat_identity(held) != (
        expected.device,
        expected.inode,
        stat.S_IFDIR,
        expected.owner,
    ):
        raise NamedLaneGuardError(
            "Claude session environment held parent identity changed"
        )
    _validate_claude_session_directory_policy(
        session.parent_fd,
        held,
        label="parent",
    )


def _revalidate_claude_session_env_parent(session: _ClaudeSessionEnv) -> None:
    _revalidate_held_claude_session_env_parent(session)
    parent_path, descriptor, components, namespace_descriptor = (
        _open_claude_session_env_parent(
            session.parent_path.parents[1],
            create=False,
        )
    )
    assert namespace_descriptor is None
    try:
        if (
            parent_path != session.parent_path
            or components != session.parent_components
        ):
            raise NamedLaneGuardError(
                "Claude session environment parent changed during launch"
            )
    finally:
        os.close(descriptor)


def _new_claude_session_id() -> str:
    value = bytearray(secrets.token_bytes(16))
    value[6] = (value[6] & 0x0F) | 0x40
    value[8] = (value[8] & 0x3F) | 0x80
    encoded = value.hex()
    return (
        f"{encoded[:8]}-{encoded[8:12]}-{encoded[12:16]}-"
        f"{encoded[16:20]}-{encoded[20:]}"
    )


def _prepare_claude_session_env(home: pathlib.Path) -> _ClaudeSessionEnv:
    parent_path, parent_fd, components, namespace_fd = _open_claude_session_env_parent(
        home,
        create=True,
        acquire_namespace_lock=True,
    )
    assert namespace_fd is not None
    session_id: str | None = None
    leaf_fd = -1
    session: _ClaudeSessionEnv | None = None
    try:
        for _attempt in range(16):
            candidate = _new_claude_session_id()
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            except OSError as error:
                raise NamedLaneGuardError(
                    "Claude session environment leaf cannot be created safely"
                ) from error
            session_id = candidate
            break
        if session_id is None:
            raise NamedLaneGuardError(
                "Claude session environment could not allocate a unique leaf"
            )
        try:
            leaf_fd = os.open(
                session_id,
                _claude_session_directory_flags(),
                dir_fd=parent_fd,
            )
            os.fchmod(leaf_fd, 0o700)
            lexical = os.stat(
                session_id,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            opened = os.fstat(leaf_fd)
        except BaseException as error:
            raise _ClaudeSessionEnvCleanupError(
                None,
                "prelaunch",
                retained_parent_identity=(
                    components[-1].device,
                    components[-1].inode,
                ),
                retained_leaf=session_id,
            ) from error
        identity = _claude_directory_stat_identity(opened)
        if (
            _claude_directory_stat_identity(lexical) != identity
            or identity[2] != stat.S_IFDIR
            or identity[3] != _current_user_id()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise _ClaudeSessionEnvCleanupError(
                None,
                "prelaunch",
                retained_parent_identity=(
                    components[-1].device,
                    components[-1].inode,
                ),
                retained_leaf=session_id,
            )
        session = _ClaudeSessionEnv(
            namespace_fd=namespace_fd,
            namespace_identity=(
                components[-2].device,
                components[-2].inode,
                stat.S_IFDIR,
                components[-2].owner,
            ),
            parent_path=parent_path,
            parent_fd=parent_fd,
            parent_identity=(components[-1].device, components[-1].inode),
            parent_components=components,
            session_id=session_id,
            leaf_fd=leaf_fd,
            leaf_identity=identity,
        )
        _validate_claude_session_directory_policy(
            leaf_fd,
            opened,
            label="leaf",
        )
        _revalidate_claude_session_env_parent(session)
        with os.scandir(leaf_fd) as entries:
            if next(entries, None) is not None:
                raise _ClaudeSessionEnvCleanupError(
                    parent_path / session_id,
                    "prelaunch",
                )
        return session
    except BaseException as error:
        if session is not None:
            try:
                _cleanup_claude_session_env(session)
            except BaseException as cleanup_error:
                retained = _claude_session_env_cleanup_error(session, "prelaunch")
                if leaf_fd >= 0:
                    os.close(leaf_fd)
                    leaf_fd = -1
                os.close(parent_fd)
                parent_fd = -1
                os.close(namespace_fd)
                namespace_fd = -1
                raise retained from cleanup_error
        elif session_id is not None and not isinstance(
            error,
            _ClaudeSessionEnvCleanupError,
        ):
            error = _ClaudeSessionEnvCleanupError(
                None,
                "prelaunch",
                retained_parent_identity=(
                    components[-1].device,
                    components[-1].inode,
                ),
                retained_leaf=session_id,
            )
        if leaf_fd >= 0:
            os.close(leaf_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        if namespace_fd >= 0:
            os.close(namespace_fd)
        raise error


def _revalidate_claude_session_env_leaf(
    session: _ClaudeSessionEnv,
    *,
    require_exact_mode: bool,
    require_lexical_parent: bool,
) -> None:
    def revalidate_binding() -> None:
        opened = os.fstat(session.leaf_fd)
        if _claude_directory_stat_identity(opened) != session.leaf_identity:
            raise NamedLaneGuardError(
                "Claude session environment leaf identity changed"
            )
        try:
            lexical = os.stat(
                session.session_id,
                dir_fd=session.parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise NamedLaneGuardError(
                "Claude session environment leaf is missing"
            ) from error
        if _claude_directory_stat_identity(lexical) != session.leaf_identity:
            raise NamedLaneGuardError("Claude session environment leaf was replaced")
        _validate_claude_session_directory_policy(
            session.leaf_fd,
            opened,
            label="leaf",
        )
        if require_exact_mode and stat.S_IMODE(opened.st_mode) != 0o700:
            raise NamedLaneGuardError(
                "Claude session environment leaf handoff mode changed"
            )

    revalidate_parent = (
        _revalidate_claude_session_env_parent
        if require_lexical_parent
        else _revalidate_held_claude_session_env_parent
    )
    revalidate_parent(session)
    revalidate_binding()
    with os.scandir(session.leaf_fd) as entries:
        if next(entries, None) is not None:
            raise NamedLaneGuardError("Claude session environment leaf is not empty")
    revalidate_binding()
    revalidate_parent(session)


def _cleanup_claude_session_env(session: _ClaudeSessionEnv) -> None:
    _revalidate_claude_session_env_leaf(
        session,
        require_exact_mode=False,
        require_lexical_parent=False,
    )
    final_lexical = os.stat(
        session.session_id,
        dir_fd=session.parent_fd,
        follow_symlinks=False,
    )
    if _claude_directory_stat_identity(final_lexical) != session.leaf_identity:
        raise NamedLaneGuardError(
            "Claude session environment leaf changed before removal"
        )
    os.rmdir(session.session_id, dir_fd=session.parent_fd)
    try:
        os.stat(
            session.session_id,
            dir_fd=session.parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise NamedLaneGuardError("Claude session environment leaf remains after cleanup")


def _claude_session_env_path_names_bound_directory(
    session: _ClaudeSessionEnv,
) -> bool:
    try:
        _revalidate_claude_session_env_parent(session)
        lexical = os.stat(
            session.session_id,
            dir_fd=session.parent_fd,
            follow_symlinks=False,
        )
    except (NamedLaneGuardError, OSError, RuntimeError):
        return False
    return _claude_directory_stat_identity(lexical) == session.leaf_identity


def _claude_session_env_cleanup_error(
    session: _ClaudeSessionEnv,
    process_reason: str,
    *,
    retained_for_quiescence: bool = False,
) -> _ClaudeSessionEnvCleanupError:
    retained_path = (
        session.parent_path / session.session_id
        if _claude_session_env_path_names_bound_directory(session)
        else None
    )
    return _ClaudeSessionEnvCleanupError(
        retained_path,
        process_reason,
        retained_parent_identity=session.parent_identity,
        retained_leaf=session.session_id,
        retained_leaf_identity=session.leaf_identity[:2],
        retained_for_quiescence=retained_for_quiescence,
    )


def _claude_session_env_custody_error(
    session: _ClaudeSessionEnv,
    process_reason: str,
) -> _ClaudeSessionEnvCustodyError:
    return _ClaudeSessionEnvCustodyError(
        session.session_id,
        process_reason,
        parent_identity=session.parent_identity,
        leaf_identity=session.leaf_identity[:2],
    )


def _open_private_temporary(
    target: _OutputTarget,
    *,
    readable: bool = False,
    prefix: str = ".named-lane-",
) -> tuple[int, str]:
    open_flags = (os.O_RDWR if readable else os.O_WRONLY) | os.O_CREAT | os.O_EXCL
    for flag_name in ("O_CLOEXEC", "O_NOFOLLOW"):
        open_flags |= getattr(os, flag_name, 0)
    for _attempt in range(16):
        name = f"{prefix}{secrets.token_hex(16)}"
        try:
            descriptor = os.open(
                name,
                open_flags,
                0o600,
                dir_fd=target.parent_fd,
            )
        except FileExistsError:
            continue
        except OSError as error:
            raise NamedLaneGuardError(
                "Claude output temporary file cannot be created safely"
            ) from error
        return descriptor, name
    raise NamedLaneGuardError("Claude output temporary name could not be reserved")


def _output_identity(metadata: os.stat_result) -> tuple[int, int]:
    return (metadata.st_dev, metadata.st_ino)


def _validate_published_output(output: _PublishedOutput) -> None:
    try:
        metadata = os.stat(
            output.target.path.name,
            dir_fd=output.target.parent_fd,
            follow_symlinks=False,
        )
    except OSError as error:
        raise NamedLaneGuardError("Claude output changed after publication") from error
    if _output_identity(metadata) != output.identity:
        raise NamedLaneGuardError("Claude output changed after publication")


def _unlink_output_if_observed_same(
    target: _OutputTarget,
    name: str,
    identity: tuple[int, int],
    *,
    label: str,
) -> None:
    # POSIX has no portable conditional unlink. The caller supplies a
    # lane-private 0700 directory and cooperatively excludes other same-UID
    # writers; this check preserves identity drift already visible here.
    try:
        metadata = os.stat(
            name,
            dir_fd=target.parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError as error:
        raise NamedLaneGuardError(
            f"{label} cannot be inspected before cleanup"
        ) from error
    if _output_identity(metadata) != identity:
        raise NamedLaneGuardError(f"{label} changed before cleanup")
    try:
        os.unlink(name, dir_fd=target.parent_fd)
    except FileNotFoundError:
        return
    except OSError as error:
        raise NamedLaneGuardError(f"{label} cannot be removed safely") from error


def _remove_private_output(output: _PublishedOutput) -> None:
    _unlink_output_if_observed_same(
        output.target,
        output.target.path.name,
        output.identity,
        label="Claude output",
    )


_CLAUDE_PREFLIGHT_FIELDS = frozenset(
    (
        "capability_contract",
        "classification",
        "compatible_version_range",
        "declared_version",
        "identity",
        "observed_version",
        "publisher_verification",
        "reason",
        "resolved_path",
        "selected_version",
        "source",
        "stream_contract",
    )
)
_CLAUDE_PREFLIGHT_IDENTITY_FIELDS = frozenset(
    (
        "device",
        "inode",
        "file_type",
        "mode",
        "nlink",
        "uid",
        "gid",
        "size",
        "mtime_ns",
        "ctime_ns",
    )
)
_CLAUDE_PUBLISHER_FIELDS = frozenset(
    (
        "artifact_size",
        "binary",
        "checksum",
        "manifest_url",
        "platform",
        "release_version",
        "signature_url",
        "signer_fingerprint",
    )
)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> object:
    raise ValueError("non-finite JSON number")


def _read_claude_preflight_evidence(
    path: pathlib.Path,
    *,
    worktree: pathlib.Path,
) -> tuple[dict[str, object], str]:
    if not path.is_absolute():
        raise NamedLaneGuardError("Claude preflight result path must be absolute")
    descriptor = -1
    try:
        parent_metadata = path.parent.lstat()
        canonical_parent = path.parent.resolve(strict=True)
        canonical_path = canonical_parent / path.name
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(parent_metadata.st_mode)
            or canonical_parent != path.parent
            or parent_metadata.st_uid != _current_user_id()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise NamedLaneGuardError(
                "Claude preflight result parent must be a private real directory"
            )
        if canonical_path == worktree or is_relative_to(canonical_path, worktree):
            raise NamedLaneGuardError(
                "Claude preflight result must stay outside the worktree"
            )
        before = canonical_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != _current_user_id()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size > CLAUDE_PREFLIGHT_EVIDENCE_LIMIT_BYTES
        ):
            raise NamedLaneGuardError(
                "Claude preflight result must be a private single-link regular file"
            )
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise NamedLaneGuardError(
                "Claude preflight result validation requires O_NOFOLLOW"
            )
        descriptor = os.open(
            canonical_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | nofollow,
        )
        opened_before = os.fstat(descriptor)
        payload = bytearray()
        while len(payload) <= CLAUDE_PREFLIGHT_EVIDENCE_LIMIT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    4096,
                    CLAUDE_PREFLIGHT_EVIDENCE_LIMIT_BYTES + 1 - len(payload),
                ),
            )
            if not chunk:
                break
            payload.extend(chunk)
        opened_after = os.fstat(descriptor)
        after = canonical_path.stat(follow_symlinks=False)
    except NamedLaneGuardError:
        raise
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError("Claude preflight result is unreadable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > CLAUDE_PREFLIGHT_EVIDENCE_LIMIT_BYTES:
        payload[:] = b"\x00" * len(payload)
        raise NamedLaneGuardError("Claude preflight result exceeds its size bound")

    def evidence_identity(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
        )

    if (
        len(
            {
                evidence_identity(metadata)
                for metadata in (before, opened_before, opened_after, after)
            }
        )
        != 1
    ):
        payload[:] = b"\x00" * len(payload)
        raise NamedLaneGuardError("Claude preflight result changed while reading")
    checksum = hashlib.sha256(payload).hexdigest()
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise NamedLaneGuardError(
            "Claude preflight result is not strict JSON"
        ) from error
    finally:
        payload[:] = b"\x00" * len(payload)
    if type(value) is not dict:
        raise NamedLaneGuardError("Claude preflight result must be a JSON object")
    return value, checksum


def _load_claude_executable_binding(
    preflight_result: pathlib.Path,
    *,
    worktree: pathlib.Path,
    command_path: pathlib.Path,
) -> _ClaudeExecutableBinding:
    evidence, preflight_checksum = _read_claude_preflight_evidence(
        preflight_result,
        worktree=worktree,
    )
    if frozenset(evidence) != _CLAUDE_PREFLIGHT_FIELDS:
        raise NamedLaneGuardError("Claude preflight result fields do not match")
    if (
        evidence.get("classification") != "accepted"
        or evidence.get("reason") != "compatible-version-selected"
    ):
        raise NamedLaneGuardError("Claude preflight result is not accepted")
    resolved_path = evidence.get("resolved_path")
    if type(resolved_path) is not str or pathlib.Path(resolved_path) != command_path:
        raise NamedLaneGuardError(
            "Claude command does not match the accepted preflight executable"
        )
    selected_version = evidence.get("selected_version")
    if (
        type(selected_version) is not str
        or not selected_version
        or evidence.get("declared_version") != selected_version
        or evidence.get("observed_version") != selected_version
    ):
        raise NamedLaneGuardError("Claude preflight version binding is invalid")
    try:
        parsed_version = parse_compatible_release_version(selected_version)
    except ClaudeVersionPolicyError as error:
        raise NamedLaneGuardError(
            "Claude preflight version binding is invalid"
        ) from error
    capability_contract = evidence.get("capability_contract")
    if (
        type(capability_contract) is not dict
        or frozenset(capability_contract) != {"required_options", "status"}
        or capability_contract.get("status") != "accepted"
        or capability_contract.get("required_options")
        != list(_claude_direct_required_options(parsed_version))
    ):
        raise NamedLaneGuardError(
            "Claude preflight capability contract does not match the closed argv profile"
        )
    identity = evidence.get("identity")
    if (
        type(identity) is not dict
        or frozenset(identity) != _CLAUDE_PREFLIGHT_IDENTITY_FIELDS
        or any(type(item) is not int or item < 0 for item in identity.values())
    ):
        raise NamedLaneGuardError("Claude preflight executable identity is invalid")
    publisher = evidence.get("publisher_verification")
    if type(publisher) is not dict or frozenset(publisher) != _CLAUDE_PUBLISHER_FIELDS:
        raise NamedLaneGuardError("Claude preflight publisher binding is invalid")
    artifact_size = publisher.get("artifact_size")
    artifact_checksum = publisher.get("checksum")
    if (
        type(artifact_size) is not int
        or artifact_size <= 0
        or artifact_size > CLAUDE_BINARY_LIMIT_BYTES
        or artifact_size != identity["size"]
        or type(artifact_checksum) is not str
        or _LOWER_SHA256.fullmatch(artifact_checksum) is None
        or publisher.get("release_version") != selected_version
        or identity["file_type"] != stat.S_IFREG
        or not identity["mode"] & 0o111
    ):
        raise NamedLaneGuardError("Claude preflight artifact binding is invalid")
    return _ClaudeExecutableBinding(
        source_path=command_path,
        selected_version=parsed_version,
        identity=dict(identity),
        artifact_size=artifact_size,
        artifact_checksum=artifact_checksum,
        preflight_checksum=preflight_checksum,
    )


def _executable_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "file_type": stat.S_IFMT(metadata.st_mode),
        "mode": metadata.st_mode,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "size": metadata.st_size,
    }


def _expected_executable_identity(
    binding: _ClaudeExecutableBinding,
) -> dict[str, int]:
    return {
        key: binding.identity[key]
        for key in ("device", "inode", "file_type", "mode", "uid", "gid", "size")
    }


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("short write while creating Claude launch snapshot")
        written += count


def _create_claude_launch_snapshot(
    binding: _ClaudeExecutableBinding,
    target: _OutputTarget,
    *,
    deadline_monotonic: float,
) -> _ClaudeLaunchSnapshot:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise NamedLaneGuardError("Claude executable binding requires O_NOFOLLOW")
    source_descriptor = -1
    snapshot_descriptor = -1
    snapshot_name: str | None = None
    snapshot_identity: tuple[int, int] | None = None
    expected_identity = _expected_executable_identity(binding)
    try:
        before = binding.source_path.lstat()
        if _executable_identity(before) != expected_identity:
            raise NamedLaneGuardError(
                "Claude executable changed after accepted preflight"
            )
        source_descriptor = os.open(
            binding.source_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | nofollow,
        )
        opened_before = os.fstat(source_descriptor)
        path_after_open = binding.source_path.lstat()
        if (
            _executable_identity(opened_before) != expected_identity
            or _executable_identity(path_after_open) != expected_identity
        ):
            raise NamedLaneGuardError(
                "Claude executable changed after accepted preflight"
            )
        _revalidate_output_parent(target)
        snapshot_descriptor, snapshot_name = _open_private_temporary(
            target,
            readable=True,
            prefix=".named-lane-launch-",
        )
        try:
            created = os.fstat(snapshot_descriptor)
        except OSError as error:
            raise NamedLaneGuardError(
                "Claude launch snapshot cannot be inspected safely"
            ) from error
        snapshot_identity = _output_identity(created)
        source_digest = hashlib.sha256()
        copied = 0
        while copied <= binding.artifact_size:
            _remaining_deadline_seconds(
                deadline_monotonic,
                "Claude executable snapshot",
            )
            chunk = os.read(
                source_descriptor,
                min(1024 * 1024, binding.artifact_size + 1 - copied),
            )
            if not chunk:
                break
            copied += len(chunk)
            if copied > binding.artifact_size:
                raise NamedLaneGuardError(
                    "Claude executable size changed during snapshot"
                )
            source_digest.update(chunk)
            _write_all(snapshot_descriptor, chunk)
        if copied != binding.artifact_size:
            raise NamedLaneGuardError("Claude executable size changed during snapshot")
        os.fchmod(snapshot_descriptor, 0o500)
        os.fsync(snapshot_descriptor)
        opened_after = os.fstat(source_descriptor)
        path_after_copy = binding.source_path.lstat()
        if (
            _executable_identity(opened_after) != expected_identity
            or _executable_identity(path_after_copy) != expected_identity
            or source_digest.hexdigest() != binding.artifact_checksum
        ):
            raise NamedLaneGuardError("Claude executable changed during launch binding")
        snapshot_metadata = os.fstat(snapshot_descriptor)
        if (
            not stat.S_ISREG(snapshot_metadata.st_mode)
            or snapshot_metadata.st_uid != _current_user_id()
            or snapshot_metadata.st_nlink != 1
            or stat.S_IMODE(snapshot_metadata.st_mode) != 0o500
            or snapshot_metadata.st_size != binding.artifact_size
        ):
            raise NamedLaneGuardError("Claude launch snapshot is not private and exact")
        os.lseek(snapshot_descriptor, 0, os.SEEK_SET)
        snapshot_digest = hashlib.sha256()
        verified = 0
        while verified < binding.artifact_size:
            _remaining_deadline_seconds(
                deadline_monotonic,
                "Claude executable snapshot",
            )
            chunk = os.read(
                snapshot_descriptor,
                min(1024 * 1024, binding.artifact_size - verified),
            )
            if not chunk:
                break
            verified += len(chunk)
            snapshot_digest.update(chunk)
        if (
            verified != binding.artifact_size
            or snapshot_digest.hexdigest() != binding.artifact_checksum
        ):
            raise NamedLaneGuardError(
                "Claude launch snapshot bytes do not match preflight"
            )
        snapshot_path = target.path.parent / snapshot_name
        current_snapshot = os.stat(
            snapshot_name,
            dir_fd=target.parent_fd,
            follow_symlinks=False,
        )
        if _output_identity(current_snapshot) != snapshot_identity:
            raise NamedLaneGuardError("Claude launch snapshot changed before handoff")
        return _ClaudeLaunchSnapshot(
            path=snapshot_path,
            name=snapshot_name,
            identity=snapshot_identity,
        )
    except BaseException as error:
        cleanup_error: BaseException | None = None
        if (
            snapshot_name is not None
            and snapshot_identity is None
            and snapshot_descriptor >= 0
        ):
            try:
                snapshot_identity = _output_identity(os.fstat(snapshot_descriptor))
            except OSError:
                raise NamedLaneGuardError(
                    "Claude launch snapshot cleanup cannot bind the retained path: "
                    f"{target.path.parent / snapshot_name}"
                ) from error
        if snapshot_name is not None and snapshot_identity is not None:
            try:
                _unlink_output_if_observed_same(
                    target,
                    snapshot_name,
                    snapshot_identity,
                    label="Claude launch snapshot",
                )
            except BaseException as candidate:
                cleanup_error = candidate
        if cleanup_error is not None:
            raise NamedLaneGuardError(
                "Claude launch snapshot cleanup failed; retained path: "
                f"{target.path.parent / snapshot_name}"
            ) from cleanup_error
        raise
    finally:
        for descriptor in (snapshot_descriptor, source_descriptor):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)


def _cleanup_claude_launch_snapshot(
    snapshot: _ClaudeLaunchSnapshot,
    target: _OutputTarget,
) -> None:
    _unlink_output_if_observed_same(
        target,
        snapshot.name,
        snapshot.identity,
        label="Claude launch snapshot",
    )


def _claude_launch_snapshot_cleanup_error(
    snapshot: _ClaudeLaunchSnapshot,
    target: _OutputTarget,
    process_reason: str,
) -> _ClaudeLaunchSnapshotCleanupError:
    retained_path = (
        snapshot.path if _output_parent_path_names_bound_directory(target) else None
    )
    return _ClaudeLaunchSnapshotCleanupError(
        retained_path,
        process_reason,
        retained_parent_identity=target.parent_identity,
        retained_leaf=snapshot.name,
    )


def _claude_process_failure_reason(error: BaseException | None) -> str:
    if error is None:
        return "complete"
    if isinstance(error, ForwardedSignal):
        return "forwarded-signal"
    if isinstance(error, ReviewTimeoutError):
        return "deadline"
    if isinstance(error, ReviewOutputLimitError):
        return "output-limit"
    if isinstance(error, ReviewOutputDrainError):
        return "output-drain"
    if isinstance(error, ReviewProcessLeakError):
        return "process-leak"
    return "process-error"


def _restore_claude_snapshot_signal_mask(
    previous_mask: set[signal.Signals],
) -> signal.Signals | None:
    failures: list[OSError] = []
    control_error: BaseException | None = None
    for _attempt in range(2):
        try:
            restore_signal_mask(previous_mask)
        except ForwardedSignal as error:
            # The POSIX mask change completed before Python dispatched the
            # pending signal through the installed structured handler.
            if control_error is not None:
                raise control_error.with_traceback(
                    control_error.__traceback__
                ) from error
            return error.signum
        except OSError as error:
            failures.append(error)
        except BaseException as error:
            if control_error is None:
                control_error = error
        else:
            if control_error is not None:
                cause = failures[-1] if failures else None
                if cause is not None:
                    raise control_error.with_traceback(
                        control_error.__traceback__
                    ) from cause
                raise control_error.with_traceback(control_error.__traceback__)
            return None
    if control_error is not None:
        cause = failures[-1] if failures else None
        if cause is not None:
            raise control_error.with_traceback(control_error.__traceback__) from cause
        raise control_error.with_traceback(control_error.__traceback__)
    raise NamedLaneGuardError(
        "Claude launch snapshot signal mask could not be restored"
    ) from failures[-1]


def _rollback_published_outputs(outputs: list[_PublishedOutput]) -> None:
    rollback = tuple(reversed(outputs))
    outputs.clear()
    errors: list[Exception] = []
    for output in rollback:
        try:
            _remove_private_output(output)
        except Exception as error:
            errors.append(error)
    if errors:
        raise NamedLaneGuardError(
            "Claude output rollback remained incomplete"
        ) from errors[0]


def _write_private_bytes(
    target: _OutputTarget,
    payload: bytes | bytearray,
) -> _PublishedOutput:
    descriptor, temporary_name = _open_private_temporary(target)
    identity: tuple[int, int] | None = None
    published: _PublishedOutput | None = None
    try:
        try:
            identity = _output_identity(os.fstat(descriptor))
        except OSError as inspection_error:
            try:
                identity = _output_identity(os.fstat(descriptor))
            except OSError as cleanup_probe_error:
                retained = target.path.parent / temporary_name
                raise NamedLaneGuardError(
                    "Claude output temporary cleanup remained incomplete; "
                    f"retained Claude output temporary path: {retained}"
                ) from cleanup_probe_error
            raise NamedLaneGuardError(
                "Claude output temporary file cannot be inspected safely"
            ) from inspection_error
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(
                temporary_name,
                target.path.name,
                src_dir_fd=target.parent_fd,
                dst_dir_fd=target.parent_fd,
                follow_symlinks=False,
            )
            published = _PublishedOutput(target=target, identity=identity)
            try:
                _validate_published_output(published)
            except Exception:
                try:
                    _remove_private_output(published)
                except Exception as rollback_error:
                    raise NamedLaneGuardError(
                        "Claude output publication rollback remained incomplete"
                    ) from rollback_error
                raise
        except FileExistsError as error:
            raise NamedLaneGuardError(
                "Claude output path appeared during write"
            ) from error
        except OSError as error:
            raise NamedLaneGuardError(
                "Claude output cannot be published safely"
            ) from error
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        try:
            if identity is not None:
                _unlink_output_if_observed_same(
                    target,
                    temporary_name,
                    identity,
                    label="Claude output temporary file",
                )
        except NamedLaneGuardError as cleanup_error:
            rollback_errors: list[Exception] = []
            if published is not None:
                try:
                    _remove_private_output(published)
                except Exception as error:
                    rollback_errors.append(error)
            if identity is not None:
                try:
                    _unlink_output_if_observed_same(
                        target,
                        temporary_name,
                        identity,
                        label="Claude output temporary file",
                    )
                except Exception as error:
                    rollback_errors.append(error)
            if rollback_errors:
                raise NamedLaneGuardError(
                    "Claude output cleanup or rollback remained incomplete"
                ) from rollback_errors[0]
            raise NamedLaneGuardError(
                "Claude output temporary cleanup failed"
            ) from cleanup_error
    assert published is not None
    return published


def run_claude(
    *,
    worktree: pathlib.Path,
    source_worktree: pathlib.Path,
    source_authority_binding: Mapping[str, object],
    source_authority_binding_sha256: str,
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    command: Sequence[str],
    preflight_result: pathlib.Path,
    prompt: bytes,
    model: str = CLAUDE_DIRECT_MODELS[0],
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    stream_limit_bytes: int = DEFAULT_STREAM_LIMIT_BYTES,
    inherit_node_extra_ca_certs: bool = False,
    deadline_monotonic: float | None = None,
    _receipt_emitter: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
    (
        parent_source_authority_binding,
        parent_source_authority_binding_sha256,
    ) = _validate_parent_source_authority_binding(
        source_authority_binding,
        source_authority_binding_sha256,
    )
    deadline = _bounded_deadline(timeout_seconds, deadline_monotonic)
    _remaining_deadline_seconds(deadline, "Claude named lane")
    stream_limit = _validate_byte_limit(
        stream_limit_bytes,
        DEFAULT_STREAM_LIMIT_BYTES,
        "stream limit",
    )
    if len(prompt) > DEFAULT_PROMPT_LIMIT_BYTES:
        raise NamedLaneGuardError(
            f"Claude control prompt must not exceed {DEFAULT_PROMPT_LIMIT_BYTES} bytes"
        )
    root = _resolve_worktree_root(
        worktree,
        deadline_monotonic=deadline,
    )
    if not command:
        raise NamedLaneGuardError("Claude command is required")
    if len(command) != 1:
        raise NamedLaneGuardError(
            "Claude arguments are owned by the named-lane guard; only the "
            "preflight-bound executable may follow --"
        )
    executable = pathlib.Path(command[0])
    if not executable.is_absolute():
        raise NamedLaneGuardError("Claude executable path must be absolute")
    binding = _load_claude_executable_binding(
        preflight_result,
        worktree=root,
        command_path=executable,
    )
    session_env_required = (
        binding.selected_version >= CLAUDE_GUARD_MANAGED_SESSION_MINIMUM_VERSION
    )
    child_environment = _claude_environment(
        root,
        inherit_node_extra_ca_certs,
    )
    stdout = _validate_output_path(stdout_path, root)
    try:
        stderr = _validate_output_path(stderr_path, root)
        try:
            if stdout.path == stderr.path:
                raise NamedLaneGuardError("stdout and stderr paths must differ")
            argv_profile = _build_claude_direct_argv_profile(
                worktree=root,
                source_worktree=source_worktree,
                source_authority_binding=parent_source_authority_binding,
                source_authority_binding_sha256=(
                    parent_source_authority_binding_sha256
                ),
                preflight_result=preflight_result,
                stdout=stdout,
                stderr=stderr,
                child_environment=child_environment,
                model=model,
            )
            snapshot_mask = block_forwarded_signals()
            if snapshot_mask is None:
                raise NamedLaneGuardError(
                    "Claude launch snapshot lifecycle requires main-thread signal masking"
                )
            snapshot: _ClaudeLaunchSnapshot | None = None
            session_env: _ClaudeSessionEnv | None = None
            capture = None
            process_error: BaseException | None = None
            process_supervision_started = False
            process_quiescence_proven = False
            session_cleanup_attempted = False
            session_cleanup_error: BaseException | None = None
            session_parent_custody_error: BaseException | None = None
            session_control_error: (
                _ClaudeSessionEnvCleanupError | _ClaudeSessionEnvCustodyError | None
            ) = None

            def mark_process_quiescent() -> None:
                nonlocal process_quiescence_proven
                process_quiescence_proven = True

            def finalize_session_env() -> None:
                nonlocal session_cleanup_attempted
                nonlocal session_cleanup_error
                nonlocal session_parent_custody_error
                if session_cleanup_attempted:
                    raise NamedLaneGuardError(
                        "Claude session environment finalization ran more than once"
                    )
                session_cleanup_attempted = True
                assert session_env is not None
                try:
                    _revalidate_claude_session_env_parent(session_env)
                except BaseException as error:
                    session_parent_custody_error = error
                try:
                    _cleanup_claude_session_env(session_env)
                except BaseException as error:
                    session_cleanup_error = error
                    return
                try:
                    _revalidate_claude_session_env_parent(session_env)
                except BaseException as error:
                    if session_parent_custody_error is None:
                        session_parent_custody_error = error

            try:
                if session_env_required:
                    session_env = _prepare_claude_session_env(
                        pathlib.Path(child_environment["HOME"])
                    )
                snapshot = _create_claude_launch_snapshot(
                    binding,
                    stdout,
                    deadline_monotonic=deadline,
                )
                snapshot_arguments = argv_profile.arguments
                if session_env is not None:
                    snapshot_arguments = (
                        "--session-id",
                        session_env.session_id,
                        *snapshot_arguments,
                    )
                snapshot_command = (str(snapshot.path), *snapshot_arguments)
                if session_env is not None:
                    _revalidate_claude_session_env_leaf(
                        session_env,
                        require_exact_mode=True,
                        require_lexical_parent=True,
                    )
                _revalidate_claude_source_read_boundary(
                    argv_profile.source_read_boundary,
                    argv_profile.source_authority_binding,
                    argv_profile.source_authority_binding_sha256,
                )
                restore_signal_mask(snapshot_mask)
                try:
                    process_timeout = _remaining_deadline_seconds(
                        deadline,
                        "Claude process supervision",
                    )
                    capture_options: dict[str, object] = {}
                    if session_env is not None:
                        capture_options["on_process_quiescent"] = mark_process_quiescent
                    process_supervision_started = True
                    capture = run_bounded_capture(
                        snapshot_command,
                        cwd=root,
                        env=child_environment,
                        stdin=bytearray(prompt),
                        timeout_seconds=process_timeout,
                        stdout_limit_bytes=stream_limit,
                        stderr_limit_bytes=stream_limit,
                        **capture_options,
                    )
                except BaseException as error:
                    process_error = error
            finally:
                lifecycle_error = (
                    process_error if process_error is not None else sys.exc_info()[1]
                )
                cleanup_error: BaseException | None = None
                if snapshot is not None or session_env is not None:
                    cleanup_mask_acquired = False
                    try:
                        if block_forwarded_signals() is None:
                            raise NamedLaneGuardError(
                                "Claude launch snapshot cleanup requires main-thread "
                                "signal masking"
                            )
                        cleanup_mask_acquired = True
                        if snapshot is not None:
                            _cleanup_claude_launch_snapshot(snapshot, stdout)
                    except BaseException as error:
                        cleanup_error = error
                    if session_env is not None:
                        try:
                            if (
                                process_supervision_started
                                and not process_quiescence_proven
                            ):
                                retained_reason = _claude_process_failure_reason(
                                    lifecycle_error
                                )
                                if retained_reason == "complete":
                                    retained_reason = "process-leak"
                                session_control_error = (
                                    _claude_session_env_cleanup_error(
                                        session_env,
                                        retained_reason,
                                        retained_for_quiescence=True,
                                    )
                                )
                                if lifecycle_error is None:
                                    lifecycle_error = ReviewProcessLeakError(
                                        "Claude process quiescence was not proven"
                                    )
                                session_control_error.__cause__ = lifecycle_error
                            elif not cleanup_mask_acquired:
                                session_control_error = (
                                    _claude_session_env_cleanup_error(
                                        session_env,
                                        "signal-mask-unavailable",
                                    )
                                )
                            else:
                                finalize_session_env()
                            if (
                                session_control_error is None
                                and session_cleanup_error is not None
                            ):
                                session_control_error = (
                                    _claude_session_env_cleanup_error(
                                        session_env,
                                        (
                                            "parent-custody"
                                            if session_parent_custody_error is not None
                                            else _claude_process_failure_reason(
                                                lifecycle_error
                                            )
                                        ),
                                    )
                                )
                                session_control_error.__cause__ = session_cleanup_error
                            elif (
                                session_control_error is None
                                and session_parent_custody_error is not None
                            ):
                                session_control_error = (
                                    _claude_session_env_custody_error(
                                        session_env,
                                        "parent-custody",
                                    )
                                )
                                session_control_error.__cause__ = (
                                    session_parent_custody_error
                                )
                        finally:
                            for descriptor in (
                                session_env.leaf_fd,
                                session_env.parent_fd,
                                session_env.namespace_fd,
                            ):
                                with contextlib.suppress(OSError):
                                    os.close(descriptor)
                    deferred_signal: signal.Signals | None = None
                    mask_restore_error: BaseException | None = None
                    try:
                        deferred_signal = _restore_claude_snapshot_signal_mask(
                            snapshot_mask
                        )
                    except BaseException as error:
                        mask_restore_error = error
                    if session_control_error is not None:
                        if capture is not None:
                            capture.stdout[:] = b"\x00" * len(capture.stdout)
                            capture.stderr[:] = b"\x00" * len(capture.stderr)
                        if (
                            mask_restore_error is not None
                            or deferred_signal is not None
                        ):
                            process_reason = (
                                "signal-mask-restore"
                                if mask_restore_error is not None
                                else "forwarded-signal"
                            )
                            if isinstance(
                                session_control_error,
                                _ClaudeSessionEnvCleanupError,
                            ):
                                if session_control_error.retained_for_quiescence:
                                    secondary_error = mask_restore_error
                                    if secondary_error is None:
                                        assert deferred_signal is not None
                                        secondary_error = ForwardedSignal(
                                            deferred_signal
                                        )
                                    prior_cause = session_control_error.__cause__
                                    if prior_cause is not None:
                                        with contextlib.suppress(Exception):
                                            secondary_error.__context__ = prior_cause
                                    session_control_error.__cause__ = secondary_error
                                else:
                                    session_control_error = _ClaudeSessionEnvCleanupError(
                                        session_control_error.retained_path,
                                        process_reason,
                                        retained_parent_identity=(
                                            session_control_error.retained_parent_identity
                                        ),
                                        retained_leaf=(
                                            session_control_error.retained_leaf
                                        ),
                                        retained_leaf_identity=(
                                            session_control_error.retained_leaf_identity
                                        ),
                                    )
                            else:
                                session_control_error = _ClaudeSessionEnvCustodyError(
                                    session_control_error.session_id,
                                    process_reason,
                                    parent_identity=(
                                        session_control_error.parent_identity
                                    ),
                                    leaf_identity=(session_control_error.leaf_identity),
                                )
                        if cleanup_error is not None and snapshot is not None:
                            cleanup_reason_error = lifecycle_error
                            if deferred_signal is not None:
                                cleanup_reason_error = ForwardedSignal(deferred_signal)
                            snapshot_cleanup_error = (
                                _claude_launch_snapshot_cleanup_error(
                                    snapshot,
                                    stdout,
                                    _claude_process_failure_reason(
                                        cleanup_reason_error
                                    ),
                                )
                            )
                            raise _ClaudeControlCleanupError(
                                snapshot_cleanup_error,
                                session_control_error,
                            )
                        raise session_control_error
                    if cleanup_error is not None:
                        if capture is not None:
                            capture.stdout[:] = b"\x00" * len(capture.stdout)
                            capture.stderr[:] = b"\x00" * len(capture.stderr)
                        cleanup_reason_error = lifecycle_error
                        if deferred_signal is not None:
                            cleanup_reason_error = ForwardedSignal(deferred_signal)
                        if mask_restore_error is not None:
                            cleanup_error = NamedLaneGuardError(
                                f"{cleanup_error}; {mask_restore_error}"
                            )
                        raise _claude_launch_snapshot_cleanup_error(
                            snapshot,
                            stdout,
                            _claude_process_failure_reason(cleanup_reason_error),
                        ) from cleanup_error
                    if mask_restore_error is not None:
                        if capture is not None:
                            capture.stdout[:] = b"\x00" * len(capture.stdout)
                            capture.stderr[:] = b"\x00" * len(capture.stderr)
                        raise mask_restore_error
                    if deferred_signal is not None:
                        if capture is not None:
                            capture.stdout[:] = b"\x00" * len(capture.stdout)
                            capture.stderr[:] = b"\x00" * len(capture.stderr)
                        raise ForwardedSignal(deferred_signal)
                else:
                    try:
                        deferred_signal = _restore_claude_snapshot_signal_mask(
                            snapshot_mask
                        )
                    except BaseException as mask_restore_error:
                        if isinstance(
                            lifecycle_error,
                            _ClaudeSessionEnvCleanupError,
                        ):
                            prior_link = lifecycle_error.__cause__
                            if prior_link is None:
                                prior_link = lifecycle_error.__context__
                            with contextlib.suppress(Exception):
                                mask_restore_error.__context__ = prior_link
                            raise lifecycle_error.with_traceback(
                                lifecycle_error.__traceback__
                            ) from mask_restore_error
                        raise
                    if deferred_signal is not None:
                        signal_error = ForwardedSignal(deferred_signal)
                        if isinstance(
                            lifecycle_error,
                            _ClaudeSessionEnvCleanupError,
                        ):
                            prior_link = lifecycle_error.__cause__
                            if prior_link is None:
                                prior_link = lifecycle_error.__context__
                            with contextlib.suppress(Exception):
                                signal_error.__context__ = prior_link
                            raise lifecycle_error.with_traceback(
                                lifecycle_error.__traceback__
                            ) from signal_error
                        raise signal_error
            if process_error is not None:
                raise process_error.with_traceback(process_error.__traceback__)
            if capture is None:
                raise NamedLaneGuardError(
                    "Claude process supervision did not return a complete capture"
                )
            try:
                publication_mask = block_forwarded_signals()
                if publication_mask is None:
                    raise NamedLaneGuardError(
                        "Claude output publication requires main-thread signal masking"
                    )
                published_outputs: list[_PublishedOutput] = []
                previous_handlers: dict[signal.Signals, object] = {}
                publication_phase = "publishing"
                deferred_signal: signal.Signals | None = None
                receipt_committed = False
                receipt_signals: list[signal.Signals] = []

                def defer_publication_signal(signum: int, _frame: object) -> None:
                    nonlocal deferred_signal, publication_phase
                    received = signal.Signals(signum)
                    if deferred_signal is None:
                        deferred_signal = received
                    if publication_phase == "publishing":
                        publication_phase = "interrupted"
                        raise ForwardedSignal(received)

                try:
                    for forwarded in forwarded_signals():
                        previous_handlers[forwarded] = signal.getsignal(forwarded)
                        signal.signal(forwarded, defer_publication_signal)
                    _revalidate_claude_source_read_boundary(
                        argv_profile.source_read_boundary,
                        argv_profile.source_authority_binding,
                        argv_profile.source_authority_binding_sha256,
                    )
                    _revalidate_output_parent(stdout)
                    _revalidate_output_parent(stderr)
                    published_outputs.append(
                        _write_private_bytes(stdout, capture.stdout)
                    )
                    published_outputs.append(
                        _write_private_bytes(stderr, capture.stderr)
                    )
                    _revalidate_output_parent(stdout)
                    _revalidate_output_parent(stderr)
                    for output in published_outputs:
                        _validate_published_output(output)
                    launch_binding: dict[str, object] = {
                        "mode": "verified-snapshot",
                        "preflight_sha256": binding.preflight_checksum,
                        "resolved_path": str(binding.source_path),
                        "identity": dict(_expected_executable_identity(binding)),
                        "artifact_sha256": binding.artifact_checksum,
                        "artifact_size": binding.artifact_size,
                        "argv_profile": _claude_direct_argv_profile_receipt(
                            argv_profile,
                            effective_arguments=snapshot_arguments,
                        ),
                    }
                    if session_env is not None:
                        launch_binding["session_id"] = session_env.session_id
                        launch_binding["session_env"] = {
                            "identity_binding": CLAUDE_SESSION_ENV_IDENTITY_BINDING,
                            "creation_origin_proven": False,
                            "creation_origin_guarantee": (
                                CLAUDE_SESSION_ENV_CREATION_ORIGIN_GUARANTEE
                            ),
                            "namespace_exclusivity_guarantee": (
                                CLAUDE_SESSION_ENV_NAMESPACE_EXCLUSIVITY_GUARANTEE
                            ),
                            "cleanup_guarantee": (CLAUDE_SESSION_ENV_CLEANUP_GUARANTEE),
                            "cleanup_observation": (
                                CLAUDE_SESSION_ENV_CLEANUP_OBSERVATION
                            ),
                            "namespace_identity": {
                                "device": session_env.namespace_identity[0],
                                "inode": session_env.namespace_identity[1],
                                "file_type": session_env.namespace_identity[2],
                                "uid": session_env.namespace_identity[3],
                            },
                            "parent_identity": {
                                "device": session_env.parent_identity[0],
                                "inode": session_env.parent_identity[1],
                                "file_type": stat.S_IFDIR,
                                "uid": session_env.parent_components[-1].owner,
                            },
                            "leaf_identity": {
                                "device": session_env.leaf_identity[0],
                                "inode": session_env.leaf_identity[1],
                                "file_type": session_env.leaf_identity[2],
                                "uid": session_env.leaf_identity[3],
                            },
                        }
                    result = {
                        "status": ("complete" if capture.returncode == 0 else "failed"),
                        "returncode": capture.returncode,
                        "stdout_path": str(stdout.path),
                        "stdout_bytes": len(capture.stdout),
                        "stderr_path": str(stderr.path),
                        "stderr_bytes": len(capture.stderr),
                        "launch_binding": launch_binding,
                    }
                    deferred_signal = consume_pending_forwarded_signal()
                    if deferred_signal is not None:
                        publication_phase = "interrupted"
                        raise ForwardedSignal(deferred_signal)
                    if _receipt_emitter is None:
                        restore_signal_mask(publication_mask)
                        publication_phase = "committed"
                    else:
                        _receipt_emitter(result)
                        deferred_signal = consume_pending_forwarded_signal()
                        if deferred_signal is not None:
                            publication_phase = "interrupted"
                            raise ForwardedSignal(deferred_signal)
                        # The successful pending-signal drain is the explicit
                        # commit point. Signals that arrive after it are
                        # post-terminal even though they remain masked until
                        # the commit-aware handlers are installed.
                        publication_phase = "committed"
                        receipt_committed = True
                        receipt_signals = _install_post_terminal_signal_handlers()
                        restore_signal_mask(publication_mask)
                except BaseException as publication_error:
                    publication_phase = "cleanup"
                    block_forwarded_signals()
                    cleanup_errors: list[BaseException] = []
                    try:
                        try:
                            _rollback_published_outputs(published_outputs)
                        except BaseException as error:
                            cleanup_errors.append(error)
                        late_signal = consume_pending_forwarded_signal()
                        if deferred_signal is None and receipt_signals:
                            deferred_signal = receipt_signals[0]
                        if deferred_signal is None:
                            deferred_signal = late_signal
                        for forwarded, previous in previous_handlers.items():
                            try:
                                signal.signal(forwarded, previous)
                            except BaseException as error:
                                cleanup_errors.append(error)
                    finally:
                        restore_signal_mask(publication_mask)
                    if cleanup_errors:
                        raise NamedLaneGuardError(
                            "Claude output signal rollback remained incomplete"
                        ) from cleanup_errors[0]
                    if deferred_signal is not None and not isinstance(
                        publication_error,
                        ForwardedSignal,
                    ):
                        raise ForwardedSignal(deferred_signal) from publication_error
                    raise
                else:
                    if receipt_committed:
                        return result
                    block_forwarded_signals()
                    handler_errors: list[BaseException] = []
                    try:
                        late_signal = consume_pending_forwarded_signal()
                        if deferred_signal is None:
                            deferred_signal = late_signal
                        for forwarded, previous in previous_handlers.items():
                            try:
                                signal.signal(forwarded, previous)
                            except BaseException as error:
                                handler_errors.append(error)
                    finally:
                        restore_signal_mask(publication_mask)
                    if handler_errors:
                        raise NamedLaneGuardError(
                            "Claude output signal handlers could not be restored"
                        ) from handler_errors[0]
                    if deferred_signal is not None:
                        raise ForwardedSignal(deferred_signal)
                    return result
            finally:
                capture.stdout[:] = b"\x00" * len(capture.stdout)
                capture.stderr[:] = b"\x00" * len(capture.stderr)
        finally:
            with contextlib.suppress(OSError):
                os.close(stderr.parent_fd)
    finally:
        with contextlib.suppress(OSError):
            os.close(stdout.parent_fd)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    prepare = subparsers.add_parser(
        "prepare-workspace",
        help="Create an independent clean workspace for a frozen committed range.",
    )
    prepare.add_argument("--source", required=True)
    prepare.add_argument("--worktree", required=True)
    prepare.add_argument("--base", required=True)
    prepare.add_argument("--head", required=True)

    validate = subparsers.add_parser(
        "validate-workspace",
        help="Revalidate an independent clean review workspace.",
    )
    validate.add_argument("--worktree", required=True)
    validate.add_argument("--base", required=True)
    validate.add_argument("--head", required=True)

    cleanup = subparsers.add_parser(
        "cleanup-workspace",
        help="Remove the exact identity-bound review workspace.",
    )
    cleanup.add_argument("--worktree", required=True)
    cleanup.add_argument("--token", required=True)

    recover = subparsers.add_parser(
        "recover-partial-workspace",
        help=(
            "Remove an identity-bound retained workspace after its exact process "
            "identity is absent."
        ),
    )
    recover.add_argument("--control-file", required=True)
    recover.add_argument("--control-sha256", required=True)

    codex_prefix = subparsers.add_parser(
        "codex-git-prefix",
        help="Generate the exact machine-validated local-Codex Git argv prefix.",
    )
    codex_prefix.add_argument("--worktree", required=True)
    codex_prefix.add_argument("--base", required=True)
    codex_prefix.add_argument("--head", required=True)
    codex_prefix.add_argument("--git-executable", required=True)

    validate_codex_prefix = subparsers.add_parser(
        "validate-codex-git-prefix-receipt",
        help=("Live-validate one already-published local-Codex Git prefix receipt."),
    )
    validate_codex_prefix.add_argument("--receipt-file", required=True)
    validate_codex_prefix.add_argument("--expected-receipt-sha256", required=True)
    validate_codex_prefix.add_argument("--worktree", required=True)
    validate_codex_prefix.add_argument("--base", required=True)
    validate_codex_prefix.add_argument("--head", required=True)
    validate_codex_prefix.add_argument("--git-executable", required=True)

    claude = subparsers.add_parser(
        "run-claude",
        help="Run an exact Claude executable under bounded process supervision.",
    )
    claude.add_argument("--worktree", required=True)
    claude.add_argument("--source-worktree", required=True)
    claude.add_argument("--source-authority-binding-json", required=True)
    claude.add_argument("--source-authority-binding-sha256", required=True)
    claude.add_argument("--preflight-result", required=True)
    claude.add_argument("--stdout-path", required=True)
    claude.add_argument("--stderr-path", required=True)
    claude.add_argument(
        "--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    claude.add_argument(
        "--stream-limit-bytes",
        type=int,
        default=DEFAULT_STREAM_LIMIT_BYTES,
    )
    claude.add_argument(
        "--prompt-limit-bytes",
        type=int,
        default=DEFAULT_PROMPT_LIMIT_BYTES,
    )
    claude.add_argument("--inherit-node-extra-ca-certs", action="store_true")
    claude.add_argument(
        "--model",
        choices=CLAUDE_DIRECT_MODELS,
        default=CLAUDE_DIRECT_MODELS[0],
    )
    claude.add_argument("claude_argv", nargs=argparse.REMAINDER)
    return parser


def _emit(payload: dict[str, object], *, stream: object | None = None) -> None:
    if stream is None:
        stream = sys.stdout
    print(json.dumps(payload, sort_keys=True), file=stream)


def _workspace_publication_failure_reason(error: BaseException) -> str:
    if isinstance(error, ForwardedSignal):
        return "forwarded-signal"
    if isinstance(error, ReviewWorkspaceError):
        return error.reason
    reason = str(error)
    return reason if reason else type(error).__name__


def _prepared_workspace_retained_path(
    prepared: PreparedWorkspace,
    cleanup_error: BaseException,
) -> str | None:
    candidates = [prepared.root]
    if isinstance(cleanup_error, ReviewWorkspaceError):
        retained = cleanup_error.details.get("retained_path")
        if isinstance(retained, str):
            candidate = pathlib.Path(retained)
            if candidate.is_absolute() and candidate.parent == prepared.root.parent:
                candidates.append(candidate)
    try:
        with os.scandir(prepared.root.parent) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096:
                    break
                candidate = prepared.root.parent / entry.name
                if candidate not in candidates:
                    candidates.append(candidate)
    except OSError:
        pass
    for candidate in candidates:
        parent_descriptor: int | None = None
        workspace_descriptor: int | None = None
        try:
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            parent_descriptor = os.open(candidate.parent, directory_flags)
            parent = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(parent.st_mode)
                or stat.S_IMODE(parent.st_mode) != 0o700
                or (parent.st_dev, parent.st_ino, parent.st_uid)
                != prepared.parent_identity
            ):
                continue
            workspace_descriptor = os.open(
                candidate.name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            workspace = os.fstat(workspace_descriptor)
            workspace_path = os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            parent_path = candidate.parent.stat(follow_symlinks=False)
            parent_final = os.fstat(parent_descriptor)
            workspace_final = os.fstat(workspace_descriptor)
            workspace_path_final = os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            parent_path_final = candidate.parent.stat(follow_symlinks=False)
            if (
                stat.S_ISDIR(workspace.st_mode)
                and stat.S_IMODE(workspace.st_mode) == 0o700
                and (workspace.st_dev, workspace.st_ino, workspace.st_uid)
                == prepared.workspace_identity
                and (workspace_path.st_dev, workspace_path.st_ino)
                == (workspace.st_dev, workspace.st_ino)
                and stat.S_IMODE(workspace_path.st_mode) == 0o700
                and (parent_path.st_dev, parent_path.st_ino, parent_path.st_uid)
                == prepared.parent_identity
                and stat.S_IMODE(parent_path.st_mode) == 0o700
                and (parent_final.st_dev, parent_final.st_ino, parent_final.st_uid)
                == prepared.parent_identity
                and stat.S_IMODE(parent_final.st_mode) == 0o700
                and (workspace_final.st_dev, workspace_final.st_ino)
                == (workspace.st_dev, workspace.st_ino)
                and (workspace_path_final.st_dev, workspace_path_final.st_ino)
                == (workspace.st_dev, workspace.st_ino)
                and workspace_path_final.st_uid == prepared.workspace_identity[2]
                and stat.S_IMODE(workspace_path_final.st_mode) == 0o700
                and (
                    parent_path_final.st_dev,
                    parent_path_final.st_ino,
                    parent_path_final.st_uid,
                )
                == prepared.parent_identity
                and stat.S_IMODE(parent_path_final.st_mode) == 0o700
            ):
                return str(candidate)
        except (OSError, ValueError):
            continue
        finally:
            if workspace_descriptor is not None:
                with contextlib.suppress(OSError):
                    os.close(workspace_descriptor)
            if parent_descriptor is not None:
                with contextlib.suppress(OSError):
                    os.close(parent_descriptor)
    return None


def _rollback_unpublished_workspace(
    prepared: PreparedWorkspace,
    primary_error: BaseException,
    handoff_owner: ForwardedSignalMaskOwner | None,
) -> None:
    try:
        cleaned = cleanup_workspace(
            prepared.root,
            prepared.cleanup_token,
            defer_signal_handoff=True,
        )
        nested_owner = cleaned._handoff_signal_mask
        if nested_owner is None or not nested_owner.active:
            raise NamedLaneGuardError(
                "workspace rollback cleanup did not retain signal-mask custody"
            )
        _finish_forwarded_signal_mask(
            nested_owner,
            primary_error=primary_error,
        )
    except BaseException as cleanup_error:
        retained_path = _prepared_workspace_retained_path(
            prepared,
            cleanup_error,
        )
        if retained_path is None:
            raise ReviewWorkspaceError(
                "workspace-publication-rollback-state-unavailable",
                "workspace receipt publication failed and rollback state could not be bound",
                details={
                    "primary_reason": _workspace_publication_failure_reason(
                        primary_error
                    ),
                    "cleanup_reason": _workspace_publication_failure_reason(
                        cleanup_error
                    ),
                    "parent_identity": {
                        "device": prepared.parent_identity[0],
                        "inode": prepared.parent_identity[1],
                        "uid": prepared.parent_identity[2],
                    },
                    "workspace_identity": {
                        "device": prepared.workspace_identity[0],
                        "inode": prepared.workspace_identity[1],
                        "uid": prepared.workspace_identity[2],
                    },
                },
            ) from cleanup_error
        try:
            recovery_payload = retain_workspace_for_owner_exit_recovery(
                pathlib.Path(retained_path),
                prepared.parent_identity,
                prepared.workspace_identity,
                primary_error=primary_error,
                signal_owner=handoff_owner,
            )
        except BaseException as recovery_error:
            recovery_payload = _partial_workspace_recovery_payload(recovery_error)
            if recovery_payload is not None:
                terminal_error = _WorkspacePublicationRollbackError(
                    prepared,
                    primary_error,
                    cleanup_error,
                    recovery_payload,
                )
                terminal_error.details["recovery_capability_reason"] = (
                    _workspace_publication_failure_reason(recovery_error)
                )
            else:
                terminal_error = ReviewWorkspaceError(
                    "workspace-publication-recovery-capability-unavailable",
                    "workspace rollback failed and an executable recovery capability could not be sealed",
                    details={
                        "primary_reason": _workspace_publication_failure_reason(
                            primary_error
                        ),
                        "cleanup_reason": _workspace_publication_failure_reason(
                            cleanup_error
                        ),
                        "recovery_reason": _workspace_publication_failure_reason(
                            recovery_error
                        ),
                        "retained_path": retained_path,
                        "parent_identity": {
                            "device": prepared.parent_identity[0],
                            "inode": prepared.parent_identity[1],
                            "uid": prepared.parent_identity[2],
                        },
                        "workspace_identity": {
                            "device": prepared.workspace_identity[0],
                            "inode": prepared.workspace_identity[1],
                            "uid": prepared.workspace_identity[2],
                        },
                    },
                )
            _attach_workspace_publication_owner(terminal_error, handoff_owner)
            raise terminal_error from recovery_error
        terminal_error = _WorkspacePublicationRollbackError(
            prepared,
            primary_error,
            cleanup_error,
            recovery_payload,
        )
        _attach_workspace_publication_owner(terminal_error, handoff_owner)
        raise terminal_error from cleanup_error
    if isinstance(primary_error, ForwardedSignal):
        terminal_error = primary_error
    else:
        terminal_error = ReviewWorkspaceError(
            "workspace-receipt-publication-failed",
            "workspace receipt publication failed after rollback completed",
            details={
                "publication_reason": _workspace_publication_failure_reason(
                    primary_error
                ),
                "rollback_status": "complete",
            },
        )
        terminal_error.__cause__ = primary_error
    _attach_workspace_publication_owner(terminal_error, handoff_owner)
    raise terminal_error


def _attach_workspace_publication_owner(
    error: BaseException,
    owner: ForwardedSignalMaskOwner | None,
) -> None:
    if owner is not None and owner.active:
        setattr(error, "_workspace_publication_signal_owner", owner)


def _workspace_publication_owner(
    error: BaseException,
) -> ForwardedSignalMaskOwner | None:
    owner = getattr(error, "_workspace_publication_signal_owner", None)
    if isinstance(owner, ForwardedSignalMaskOwner) and owner.active:
        return owner
    return None


def _acquire_workspace_publication_owner() -> tuple[
    ForwardedSignalMaskOwner,
    ForwardedSignal | None,
]:
    owner = ForwardedSignalMaskOwner()
    deferred: ForwardedSignal | None = None
    while True:
        try:
            block_forwarded_signals(signal_mask_owner=owner)
            return owner, deferred
        except ForwardedSignal as error:
            if deferred is None:
                deferred = error


def _direct_restore_workspace_signal_mask(
    previous_mask: set[signal.Signals] | None,
) -> None:
    if previous_mask is None:
        raise NamedLaneGuardError(
            "active workspace signal-mask owner has no exact previous mask"
        )
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _restore_workspace_publication_owner(
    owner: ForwardedSignalMaskOwner,
) -> _SignalMaskRestoreOutcome:
    failures: list[BaseException] = []
    for _attempt in range(2):
        if not owner.active:
            break
        try:
            owner.restore()
        except BaseException as error:
            failures.append(error)
    direct_fallback = "not-needed"
    if owner.active:
        try:
            _direct_restore_workspace_signal_mask(owner.previous_mask)
        except BaseException as error:
            failures.append(error)
            direct_fallback = "failed"
        else:
            owner.restore_attempted = True
            owner.active = False
            direct_fallback = "succeeded"
    return _SignalMaskRestoreOutcome(
        restored=not owner.active,
        failure_types=tuple(type(error).__name__ for error in failures),
        direct_exact_mask_fallback=direct_fallback,
    )


def _terminal_process_exit(returncode: int) -> NoReturn:
    os._exit(returncode)


def _finish_workspace_terminal_publication(
    owner: ForwardedSignalMaskOwner,
    signal_state: _StructuredSignalState,
    *,
    returncode: int,
) -> None:
    terminal_failure = False
    try:
        consume_pending_forwarded_signal()
        signal_state.commit(returncode)
    except BaseException:
        terminal_failure = True
    try:
        outcome = _restore_workspace_publication_owner(owner)
    except BaseException:
        terminal_failure = True
        outcome = _SignalMaskRestoreOutcome(
            restored=False,
            failure_types=("terminal-restore-internal-failure",),
            direct_exact_mask_fallback="failed",
        )
    if terminal_failure or not outcome.restored:
        _terminal_process_exit(returncode)


def _emit_prepared_workspace_receipt(
    prepared: PreparedWorkspace,
    signal_state: _StructuredSignalState,
) -> None:
    handoff_owner = prepared._handoff_signal_mask
    if handoff_owner is None or not handoff_owner.active:
        handoff_owner, acquisition_signal = _acquire_workspace_publication_owner()
        primary_error: BaseException
        if acquisition_signal is not None:
            primary_error = acquisition_signal
        else:
            primary_error = NamedLaneGuardError(
                "workspace receipt handoff does not own a signal mask"
            )
        _rollback_unpublished_workspace(
            prepared,
            primary_error,
            handoff_owner,
        )
    pending_before_receipt = consume_pending_forwarded_signal()
    if pending_before_receipt is not None:
        _rollback_unpublished_workspace(
            prepared,
            ForwardedSignal(pending_before_receipt),
            handoff_owner,
        )
    try:
        _install_post_terminal_signal_handlers()
        _emit(prepared.receipt())
        sys.stdout.flush()
    except BaseException as publication_error:
        _rollback_unpublished_workspace(
            prepared,
            publication_error,
            handoff_owner,
        )
    # A complete flush transfers cleanup-token custody to the caller. Signals
    # that arrived during publication are post-terminal and must not turn the
    # delivered success receipt into a false failure.
    _finish_workspace_terminal_publication(
        handoff_owner,
        signal_state,
        returncode=0,
    )


def _emit_workspace_terminal_receipt(
    payload: dict[str, object],
    signal_state: _StructuredSignalState,
    *,
    handoff_owner: ForwardedSignalMaskOwner | None = None,
) -> None:
    acquisition_signal: ForwardedSignal | None = None
    acquired_for_publication = False
    if handoff_owner is None or not handoff_owner.active:
        handoff_owner, acquisition_signal = _acquire_workspace_publication_owner()
        acquired_for_publication = True
        if not handoff_owner.active:
            raise NamedLaneGuardError(
                "workspace receipt publication requires main-thread signal masking"
            )
        if acquisition_signal is not None:
            _attach_workspace_publication_owner(acquisition_signal, handoff_owner)
            raise acquisition_signal
    try:
        if acquired_for_publication:
            pending_before_receipt = consume_pending_forwarded_signal()
            if pending_before_receipt is not None:
                raise ForwardedSignal(pending_before_receipt)
        _install_post_terminal_signal_handlers()
        _emit(payload)
        sys.stdout.flush()
    except BaseException as publication_error:
        _attach_workspace_publication_owner(publication_error, handoff_owner)
        raise
    _finish_workspace_terminal_publication(
        handoff_owner,
        signal_state,
        returncode=0,
    )


def _emit_claude_receipt(payload: dict[str, object]) -> None:
    _emit(payload)
    sys.stdout.flush()


def _install_post_terminal_signal_handlers() -> list[signal.Signals]:
    post_terminal_signals: list[signal.Signals] = []

    def record_post_terminal_signal(signum: int, _frame: object) -> None:
        post_terminal_signals.append(signal.Signals(signum))

    for forwarded in forwarded_signals():
        signal.signal(forwarded, record_post_terminal_signal)
    return post_terminal_signals


def _emit_structured_terminal_failure(
    payload: dict[str, object],
    signal_state: _StructuredSignalState,
    *,
    returncode: int,
    handoff_owner: ForwardedSignalMaskOwner | None = None,
) -> None:
    if handoff_owner is None or not handoff_owner.active:
        handoff_owner, _deferred_signal = _acquire_workspace_publication_owner()
    if not handoff_owner.active:
        raise NamedLaneGuardError(
            "terminal failure publication requires main-thread signal masking"
        )
    publication_error: BaseException | None = None
    try:
        _install_post_terminal_signal_handlers()
        _emit(payload, stream=sys.stderr)
        sys.stderr.flush()
        consume_pending_forwarded_signal()
        signal_state.commit(returncode)
    except BaseException as error:
        publication_error = error
    finally:
        outcome = _restore_workspace_publication_owner(handoff_owner)
        if not outcome.restored:
            _terminal_process_exit(returncode)
    if publication_error is not None:
        _terminal_process_exit(returncode)


def _workspace_command_failure(
    error: BaseException,
) -> tuple[int, dict[str, object]]:
    partial_recovery = _partial_workspace_recovery_payload(error) or {}
    if isinstance(error, RangeIncomplete):
        return 75, {**error.payload(), **partial_recovery}
    if isinstance(error, ReviewWorkspaceError):
        return 2, {**error.payload(), **partial_recovery}
    if isinstance(error, ForwardedSignal):
        return (
            128 + int(error.signum),
            {
                "status": "blocked-safety",
                "reason": "forwarded-signal",
                **partial_recovery,
            },
        )
    if isinstance(error, ReviewTimeoutError):
        reason = "deadline"
    elif isinstance(error, ReviewOutputLimitError):
        reason = "output-limit"
    elif isinstance(error, ReviewOutputDrainError):
        reason = "output-drain"
    elif isinstance(error, ReviewProcessLeakError):
        reason = "process-leak"
    else:
        reason = _machine_reason(error)
    return 2, {
        "status": "blocked-safety",
        "reason": reason,
        **partial_recovery,
    }


def _workspace_command_main(args: argparse.Namespace) -> int:
    with _structured_forwarded_signals() as signal_state:
        try:
            if args.command_name == "codex-git-prefix":
                worktree = pathlib.Path(args.worktree)
                git_executable = pathlib.Path(args.git_executable)
                receipt = sanitized_git_argv_prefix_receipt(
                    worktree=worktree,
                    base=args.base,
                    head=args.head,
                    git_executable=git_executable,
                )
                _revalidate_prefix_receipt_publication_identities(
                    receipt,
                    worktree=pathlib.Path(receipt["worktree"]),
                    git_executable=git_executable,
                )
                _emit_workspace_terminal_receipt(receipt, signal_state)
                return 0
            if args.command_name == "validate-codex-git-prefix-receipt":
                validation = validate_published_sanitized_git_argv_prefix_receipt(
                    receipt_file=pathlib.Path(args.receipt_file),
                    expected_receipt_sha256=args.expected_receipt_sha256,
                    worktree=pathlib.Path(args.worktree),
                    base=args.base,
                    head=args.head,
                    git_executable=pathlib.Path(args.git_executable),
                )
                _emit_workspace_terminal_receipt(validation, signal_state)
                return 0
            if args.command_name == "prepare-workspace":
                prepared = prepare_workspace(
                    pathlib.Path(args.source),
                    pathlib.Path(args.worktree),
                    args.base,
                    args.head,
                    defer_signal_handoff=True,
                )
                _emit_prepared_workspace_receipt(prepared, signal_state)
                return 0
            if args.command_name == "validate-workspace":
                validated = validate_workspace(
                    pathlib.Path(args.worktree),
                    args.base,
                    args.head,
                )
                _emit_workspace_terminal_receipt(
                    validated.receipt(),
                    signal_state,
                )
                return 0
            if args.command_name == "cleanup-workspace":
                cleaned = cleanup_workspace(
                    pathlib.Path(args.worktree),
                    args.token,
                    defer_signal_handoff=True,
                )
                if (
                    cleaned._handoff_signal_mask is None
                    or not cleaned._handoff_signal_mask.active
                ):
                    raise NamedLaneGuardError(
                        "cleanup workspace receipt handoff does not own a signal mask"
                    )
                _emit_workspace_terminal_receipt(
                    cleaned.receipt(),
                    signal_state,
                    handoff_owner=cleaned._handoff_signal_mask,
                )
                return 0
            if args.command_name == "recover-partial-workspace":
                cleaned = recover_partial_workspace(
                    pathlib.Path(args.control_file),
                    args.control_sha256,
                    defer_signal_handoff=True,
                )
                if (
                    cleaned._handoff_signal_mask is None
                    or not cleaned._handoff_signal_mask.active
                ):
                    raise NamedLaneGuardError(
                        "partial recovery receipt handoff does not own a signal mask"
                    )
                _emit_workspace_terminal_receipt(
                    cleaned.receipt(),
                    signal_state,
                    handoff_owner=cleaned._handoff_signal_mask,
                )
                return 0
            raise NamedLaneGuardError("unknown workspace command")
        except (
            ForwardedSignal,
            NamedLaneGuardError,
            RangeIncomplete,
            ReviewError,
            OSError,
            ValueError,
        ) as error:
            returncode, payload = _workspace_command_failure(error)
            _emit_structured_terminal_failure(
                payload,
                signal_state,
                returncode=returncode,
                handoff_owner=_workspace_publication_owner(error),
            )
            return returncode


def _machine_reason(error: BaseException) -> str:
    if isinstance(error, _ControlObjectGuardError):
        return error.reason
    return str(error)


def _materializer_failure_payload(
    error: BaseException,
) -> tuple[int, dict[str, object]]:
    if isinstance(error, ForwardedSignal):
        return (
            128 + int(error.signum),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )
    if isinstance(error, ReviewTimeoutError):
        reason = "deadline"
    elif isinstance(error, ReviewOutputLimitError):
        reason = "output-limit"
    elif isinstance(error, ReviewOutputDrainError):
        reason = "output-drain"
    elif isinstance(error, ReviewProcessLeakError):
        reason = "process-leak"
    else:
        reason = _machine_reason(error)
    return 2, {"status": "blocked-safety", "reason": reason}


def _emit_materialized_receipt(result: MaterializedWorktree) -> None:
    handoff_mask = result._handoff_signal_mask
    if handoff_mask is None:
        raise NamedLaneGuardError(
            "materializer receipt handoff does not own a signal mask"
        )
    try:
        pending_before_receipt = consume_pending_forwarded_signal()
        if pending_before_receipt is not None:
            raise ForwardedSignal(pending_before_receipt)
        _emit(
            {
                "status": "ok",
                "worktree": str(result.root),
                "base": result.base_sha,
                "head": result.head_sha,
                "commit_count": result.commit_count,
                "parent_edge_count": result.parent_edge_count,
                "parent_graph_sha256": result.parent_graph_sha256,
                "local_config_sha256": result.local_config_sha256,
            }
        )
        sys.stdout.flush()
    except BaseException as error:
        retained = _cleanup_materializer_path(
            result.root,
            result._parent,
            result._parent_identity,
            result._root_identity,
        )
        if retained is not None:
            terminal_failure: BaseException = NamedLaneGuardError(
                f"{error}; retained materialized worktree: {retained}"
            )
        else:
            terminal_failure = error
        _restore_materializer_terminal_failure_mask(handoff_mask)
        if retained is not None:
            raise terminal_failure from error
        raise terminal_failure
    # After the complete flushed receipt, replace the outer raising handlers
    # with commit-aware handlers before unblocking. The enclosing structured
    # context restores the original handlers on exit.
    _install_post_terminal_signal_handlers()
    consume_pending_forwarded_signal()
    restore_signal_mask(handoff_mask)


def _emit_legacy_prefix_receipt(result: LegacyPrefixReceiptResult) -> None:
    handoff_mask = result._handoff_signal_mask
    if handoff_mask is None:
        raise NamedLaneGuardError(
            "legacy prefix receipt handoff does not own a signal mask"
        )
    try:
        pending_before_receipt = consume_pending_forwarded_signal()
        if pending_before_receipt is not None:
            raise ForwardedSignal(pending_before_receipt)
        _emit(
            {
                "status": "ok",
                "schema_version": LEGACY_PREFIX_RECEIPT_SCHEMA_VERSION,
                "phase": result.phase,
                "head": result.head_sha,
                "temporary_cleanup_status": "complete",
                "receipts": list(result.receipts),
            }
        )
        sys.stdout.flush()
    except BaseException:
        _restore_materializer_terminal_failure_mask(handoff_mask)
        raise
    # The temporary view and its control directory are already proved absent.
    # Keep a signal concurrent with the complete flushed envelope from turning
    # that committed receipt into a false terminal failure.
    _install_post_terminal_signal_handlers()
    consume_pending_forwarded_signal()
    restore_signal_mask(handoff_mask)


def legacy_short_prefix_compatibility_main(
    source: pathlib.Path,
    temporary_path: pathlib.Path,
    head: str,
    phase: str,
    prefixes: Sequence[str],
) -> int:
    """Exercise the retained low-level receipt implementation without a CLI route."""
    try:
        with _structured_forwarded_signals() as signal_state:
            result = legacy_short_prefix_receipts(
                source,
                temporary_path,
                head,
                phase,
                prefixes,
                defer_signal_handoff=True,
            )
            _emit_legacy_prefix_receipt(result)
            signal_state.commit(0)
        return 0
    except LegacyPrefixReceiptInconclusive as error:
        _emit(
            {"status": "inconclusive", "reason": error.reason},
            stream=sys.stderr,
        )
        return 75
    except ForwardedSignal as error:
        _emit(
            {"status": "blocked-safety", "reason": "forwarded-signal"},
            stream=sys.stderr,
        )
        return 128 + int(error.signum)
    except ReviewTimeoutError:
        reason = "deadline"
    except ReviewOutputLimitError:
        reason = "output-limit"
    except ReviewOutputDrainError:
        reason = "output-drain"
    except ReviewProcessLeakError:
        reason = "process-leak"
    except (NamedLaneGuardError, ReviewError, OSError, ValueError) as error:
        reason = _machine_reason(error)
    _emit(
        {"status": "blocked-safety", "reason": reason},
        stream=sys.stderr,
    )
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    workspace_command = args.command_name in {
        "cleanup-workspace",
        "codex-git-prefix",
        "prepare-workspace",
        "recover-partial-workspace",
        "validate-codex-git-prefix-receipt",
        "validate-workspace",
    }
    safety_command = workspace_command
    if workspace_command:
        return _workspace_command_main(args)
    try:
        command = list(args.claude_argv)
        if command and command[0] == "--":
            command.pop(0)
        prompt_limit = _validate_byte_limit(
            args.prompt_limit_bytes,
            DEFAULT_PROMPT_LIMIT_BYTES,
            "prompt limit",
        )
        stream_limit = _validate_byte_limit(
            args.stream_limit_bytes,
            DEFAULT_STREAM_LIMIT_BYTES,
            "stream limit",
        )
        with _structured_forwarded_signals() as signal_state:
            (
                source_authority_binding,
                source_authority_binding_sha256,
            ) = _parse_parent_source_authority_binding_json(
                args.source_authority_binding_json,
                args.source_authority_binding_sha256,
            )
            timeout = _validate_timeout_limit(args.timeout_seconds)
            deadline = time.monotonic() + timeout
            prompt = _read_control_prompt(
                sys.stdin.buffer,
                prompt_limit,
                deadline,
            )
            if len(prompt) > prompt_limit:
                raise NamedLaneGuardError(
                    "Claude control prompt exceeded its bounded limit"
                )
            result = run_claude(
                worktree=pathlib.Path(args.worktree),
                source_worktree=pathlib.Path(args.source_worktree),
                source_authority_binding=source_authority_binding,
                source_authority_binding_sha256=(source_authority_binding_sha256),
                stdout_path=pathlib.Path(args.stdout_path),
                stderr_path=pathlib.Path(args.stderr_path),
                command=command,
                preflight_result=pathlib.Path(args.preflight_result),
                prompt=prompt,
                model=args.model,
                timeout_seconds=_remaining_deadline_seconds(
                    deadline,
                    "Claude named lane",
                ),
                stream_limit_bytes=stream_limit,
                inherit_node_extra_ca_certs=args.inherit_node_extra_ca_certs,
                deadline_monotonic=deadline,
                _receipt_emitter=_emit_claude_receipt,
            )
            returncode = 0 if result["status"] == "complete" else 1
            signal_state.commit(returncode)
            return returncode
    except _ClaudeControlCleanupError as error:
        snapshot = error.snapshot
        session_env = error.session_env
        snapshot_recovery: dict[str, object]
        if snapshot.retained_path is not None:
            snapshot_recovery = {"retained_path": str(snapshot.retained_path)}
        else:
            assert snapshot.retained_parent_identity is not None
            assert snapshot.retained_leaf is not None
            snapshot_recovery = {
                "retained_locator": {
                    "parent_device": snapshot.retained_parent_identity[0],
                    "parent_inode": snapshot.retained_parent_identity[1],
                    "leaf": snapshot.retained_leaf,
                }
            }
        session_recovery: dict[str, object]
        if isinstance(session_env, _ClaudeSessionEnvCustodyError):
            session_recovery = {
                "session_id": session_env.session_id,
                "cleanup_status": session_env.cleanup_status,
                "parent_identity": {
                    "device": session_env.parent_identity[0],
                    "inode": session_env.parent_identity[1],
                },
                "leaf_identity": {
                    "device": session_env.leaf_identity[0],
                    "inode": session_env.leaf_identity[1],
                },
            }
        elif session_env.retained_path is not None:
            session_recovery = {"retained_path": str(session_env.retained_path)}
            if session_env.retained_for_quiescence:
                assert session_env.retained_parent_identity is not None
                assert session_env.retained_leaf is not None
                assert session_env.retained_leaf_identity is not None
                session_recovery["retained_locator"] = {
                    "parent_device": session_env.retained_parent_identity[0],
                    "parent_inode": session_env.retained_parent_identity[1],
                    "leaf": session_env.retained_leaf,
                    "leaf_device": session_env.retained_leaf_identity[0],
                    "leaf_inode": session_env.retained_leaf_identity[1],
                }
        else:
            assert session_env.retained_parent_identity is not None
            assert session_env.retained_leaf is not None
            locator: dict[str, object] = {
                "parent_device": session_env.retained_parent_identity[0],
                "parent_inode": session_env.retained_parent_identity[1],
                "leaf": session_env.retained_leaf,
            }
            if session_env.retained_leaf_identity is not None:
                locator.update(
                    {
                        "leaf_device": session_env.retained_leaf_identity[0],
                        "leaf_inode": session_env.retained_leaf_identity[1],
                    }
                )
            session_recovery = {"retained_locator": locator}
        _emit(
            {
                "status": "inconclusive",
                "reason": (
                    "process-leak"
                    if isinstance(session_env, _ClaudeSessionEnvCleanupError)
                    and session_env.retained_for_quiescence
                    else "control-cleanup"
                ),
                "snapshot": {
                    "process_reason": snapshot.process_reason,
                    **snapshot_recovery,
                },
                "session_env": {
                    "process_reason": session_env.process_reason,
                    **session_recovery,
                },
            },
            stream=sys.stderr,
        )
        return 2
    except _ClaudeSessionEnvCustodyError as error:
        _emit(
            {
                "status": "inconclusive",
                "reason": "session-env-custody",
                "process_reason": error.process_reason,
                "session_id": error.session_id,
                "cleanup_status": error.cleanup_status,
                "parent_identity": {
                    "device": error.parent_identity[0],
                    "inode": error.parent_identity[1],
                },
                "leaf_identity": {
                    "device": error.leaf_identity[0],
                    "inode": error.leaf_identity[1],
                },
            },
            stream=sys.stderr,
        )
        return 2
    except _ClaudeSessionEnvCleanupError as error:
        payload: dict[str, object] = {
            "status": "inconclusive",
            "reason": (
                "process-leak"
                if error.retained_for_quiescence
                else "session-env-cleanup"
            ),
            "process_reason": error.process_reason,
        }
        if error.retained_path is not None:
            payload["retained_path"] = str(error.retained_path)
        if error.retained_path is None or error.retained_for_quiescence:
            assert error.retained_parent_identity is not None
            assert error.retained_leaf is not None
            retained_locator: dict[str, object] = {
                "parent_device": error.retained_parent_identity[0],
                "parent_inode": error.retained_parent_identity[1],
                "leaf": error.retained_leaf,
            }
            if error.retained_leaf_identity is not None:
                retained_locator.update(
                    {
                        "leaf_device": error.retained_leaf_identity[0],
                        "leaf_inode": error.retained_leaf_identity[1],
                    }
                )
            payload["retained_locator"] = retained_locator
        _emit(payload, stream=sys.stderr)
        return 2
    except _ClaudeLaunchSnapshotCleanupError as error:
        payload: dict[str, object] = {
            "status": "inconclusive",
            "reason": "snapshot-cleanup",
            "process_reason": error.process_reason,
        }
        if error.retained_path is not None:
            payload["retained_path"] = str(error.retained_path)
        else:
            assert error.retained_parent_identity is not None
            assert error.retained_leaf is not None
            payload["retained_locator"] = {
                "parent_device": error.retained_parent_identity[0],
                "parent_inode": error.retained_parent_identity[1],
                "leaf": error.retained_leaf,
            }
        _emit(payload, stream=sys.stderr)
        return 2
    except LegacyPrefixReceiptInconclusive as error:
        _emit(
            {"status": "inconclusive", "reason": error.reason},
            stream=sys.stderr,
        )
        return 75
    except RangeIncomplete as error:
        _emit(error.payload(), stream=sys.stderr)
        return 75
    except ReviewWorkspaceError as error:
        _emit(error.payload(), stream=sys.stderr)
        return 2
    except ForwardedSignal as error:
        status = "blocked-safety" if safety_command else "inconclusive"
        _emit(
            {"status": status, "reason": "forwarded-signal"},
            stream=sys.stderr,
        )
        return 128 + int(error.signum)
    except ReviewTimeoutError:
        status = "blocked-safety" if safety_command else "inconclusive"
        _emit(
            {"status": status, "reason": "deadline"},
            stream=sys.stderr,
        )
        return 2
    except ReviewOutputLimitError:
        status = "blocked-safety" if safety_command else "inconclusive"
        _emit(
            {"status": status, "reason": "output-limit"},
            stream=sys.stderr,
        )
        return 2
    except ReviewOutputDrainError:
        status = "blocked-safety" if safety_command else "inconclusive"
        _emit(
            {"status": status, "reason": "output-drain"},
            stream=sys.stderr,
        )
        return 2
    except ReviewProcessLeakError:
        status = "blocked-safety" if safety_command else "inconclusive"
        _emit(
            {"status": status, "reason": "process-leak"},
            stream=sys.stderr,
        )
        return 2
    except (NamedLaneGuardError, ReviewError, OSError, ValueError) as error:
        status = "blocked-safety" if safety_command else "inconclusive"
        _emit(
            {"status": status, "reason": _machine_reason(error)},
            stream=sys.stderr,
        )
        return 2
