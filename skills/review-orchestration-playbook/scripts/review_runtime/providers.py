from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import hmac
import importlib
import itertools
import json
import math
import os
import pathlib
import re
import secrets
import select
import socket
import socketserver
import ssl
import stat
import struct
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Iterator

from .claude_capabilities import (
    CLAUDE_REQUIRED_OPTIONS,
    ClaudeCapabilityError,
    ClaudeSafetyContractInvalid,
    ClaudeVersion,
    parse_claude_version,
    validate_claude_help,
)
from .claude_provenance import (
    CLAUDE_RELEASE_KEY_FINGERPRINT,
    ClaudeProvenanceDependencyUnavailable,
    ClaudeProvenanceInconclusive,
    ClaudeProvenanceInvalid,
    ClaudeProvenanceUnavailable,
    VerifiedClaudeExecutable,
    materialize_verified_executable,
    verify_claude_release,
)
from .claude_refresh_lock import (
    ClaudeRefreshLockError,
    ClaudeRefreshLockLease,
    ClaudeRefreshLockProtocol,
    ClaudeRefreshLockStale,
    certified_claude_refresh_lock_protocol,
    claude_refresh_lock,
)
from .claude_linux import (
    CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
    CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS,
    CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS,
    CLAUDE_LINUX_REVIEW_PERMISSION_MODE,
    CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS,
    LinuxCredentialInspectionInconclusive,
    LinuxCredentialStaleRefreshLock,
    LinuxCredentialUnavailable,
    LinuxCredentialUnsafe,
    LinuxHost,
    LinuxHostDependencyUnavailable,
    LinuxIsolationUnavailable,
    LinuxRuntimeError,
    LinuxRuntimeInspectionInconclusive,
    LinuxRuntimeUnsafe,
    LinuxUnsupportedHost,
    SandboxSpec,
    build_probe_command as build_claude_linux_probe_command,
    build_sandbox_command as build_claude_linux_sandbox_command,
    collect_runtime_libraries as collect_claude_linux_runtime_libraries,
    compile_launcher as compile_claude_linux_launcher,
    detect_host as detect_claude_linux_host,
    discover_native_toolchain as discover_claude_linux_toolchain,
    reject_wsl_windows_path as reject_claude_wsl_windows_path,
    reject_wsl_windows_paths as reject_claude_wsl_windows_paths,
    run_isolation_probe as run_claude_linux_isolation_probe,
    stage_claude_credentials,
    validate_claude_executable as validate_claude_linux_executable,
)
from .common import (
    Completed,
    ForwardedSignal,
    InvalidReviewerExecutable,
    RejectedReviewerCandidates,
    ReviewError,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    block_forwarded_signals,
    child_environment,
    is_relative_to,
    read_json,
    reviewer_executable_path,
    resolve_reviewer_executable,
    restore_signal_mask,
    run,
    run_bounded_capture,
    write_json,
    write_text_atomic,
)
from .workspace import (
    MAX_REVIEW_PROMPT_BYTES,
    ReviewWorkspace,
    encode_preflight_json,
    validate_external_workspace,
)


_CLAUDE_THREAD_LOCK_FACTORY = threading.Lock


CODEX_MODELS = ("gpt-5.6-sol", "gpt-5.5")
CODEX_REASONING_EFFORT = "xhigh"
CLAUDE_MODELS = ("claude-opus-4-8", "claude-opus-4-7")
# GitHub's supported-models matrix lists all pinned IDs for Copilot CLI. The
# shorter command-reference examples can lag product availability.
COPILOT_MODELS = ("claude-opus-4.8", "claude-opus-4.7")
CLAUDE_REASONING_EFFORT = "max"
COPILOT_REASONING_EFFORT = "max"
CLAUDE_LINUX_PROMPT_GUIDANCE = b"""
Linux/WSL2 runtime tool boundary:
- The sandbox working directory is `/workspace`.
- Read the primary diff at `/workspace/.codex-review/review.diff` using bounded Read windows.
- Only Read is available; do not request shell, Git, Grep, Glob, LSP, or other tools.
- Every Read `file_path` must be absolute and resolve beneath `/workspace`.
"""
CLAUDE_PROMPT_PATH_LEFT_BOUNDARIES = frozenset(b" \t\r\n=:'\"`([{<")
CLAUDE_PROMPT_PATH_RIGHT_BOUNDARIES = frozenset(b" \t\r\n,;:)'\"`]}>")
CLAUDE_PROMPT_PATH_QUOTES = frozenset(b"'\"`")
CLAUDE_PROMPT_DESCENDANT_LEFT_BOUNDARIES = frozenset(b"=:")
COPILOT_PERMISSION_HELP_FRAGMENTS = (
    "tool availability is controlled via the --available-tools and --excluded-tools options",
    "these filters decide which tools the model can see",
    "by default, file access is restricted to paths within the current working directory",
    "--disallow-temp-dir flag prevents automatic access",
    "denial rules always take precedence over allow rules, even --allow-all-tools",
)
CLAUDE_PROBE_SANDBOX = pathlib.Path("/usr/bin/sandbox-exec")
CLAUDE_PROBE_SANDBOX_PROFILE = "(version 1)(deny default)"
CLAUDE_PROBE_SYSTEM_READ_SUBPATHS = (
    pathlib.Path("/System/Library"),
    pathlib.Path("/usr/lib"),
    pathlib.Path("/usr/share"),
    pathlib.Path("/Library/Apple"),
    pathlib.Path("/private/var/db/dyld"),
    pathlib.Path("/private/var/db/timezone"),
)
CLAUDE_PROBE_SYSTEM_READ_LITERALS = (
    # Bun's standalone runtime enumerates the filesystem root during startup.
    # A literal filter permits that directory entry without allowing descendants.
    pathlib.Path("/"),
    pathlib.Path("/dev/null"),
    pathlib.Path("/dev/random"),
    pathlib.Path("/dev/urandom"),
    pathlib.Path("/etc/hosts"),
    pathlib.Path("/etc/localtime"),
    pathlib.Path("/etc/resolv.conf"),
    pathlib.Path("/private/etc/ssl/cert.pem"),
)
CLAUDE_PROBE_TIMEOUT_SECONDS = 20.0
CLAUDE_PROBE_OUTPUT_LIMIT_BYTES = 64 * 1024
CLAUDE_REVIEW_BASE_MACH_SERVICES = (
    "com.apple.cfprefsd.agent",
    "com.apple.cfprefsd.daemon",
    "com.apple.cfnetwork.cfnetworkagent",
    "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.trustd",
    "com.apple.trustd.agent",
)
CLAUDE_KEYCHAIN_BROKER_COMPILER = pathlib.Path("/usr/bin/clang")
CLAUDE_KEYCHAIN_CLIENT = pathlib.Path("/usr/bin/security")
CLAUDE_KEYCHAIN_BROKER_SOURCE = pathlib.Path(__file__).with_name(
    "claude_keychain_broker.c"
)
CLAUDE_KEYCHAIN_ACCOUNT = re.compile(r"^[A-Za-z0-9._-]+$")
CLAUDE_KEYCHAIN_SERVICE = "Claude Code-credentials"
CLAUDE_KEYCHAIN_BROKER_PORT_ENV = "CODEX_CLAUDE_KEYCHAIN_BROKER_PORT"
CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV = "CODEX_CLAUDE_KEYCHAIN_BROKER_CAPABILITY"
CLAUDE_KEYCHAIN_BROKER_CAPABILITY = re.compile(r"^[0-9a-f]{64}$")
CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES = 32
CLAUDE_KEYCHAIN_BROKER_TIMEOUT_SECONDS = 20.0
CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES = 64 * 1024
CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_SERVER_START_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_SERVER_POLL_INTERVAL_SECONDS = 0.05
CLAUDE_CREDENTIAL_UPDATE_LOCK_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES = 1024 * 1024
CLAUDE_KEYCHAIN_SECURITY_STDIN_LIMIT_BYTES = 4032
CLAUDE_MACOS_DUAL_CARRIER_KEYCHAIN_ATTEMPTS = 2
CLAUDE_CREDENTIAL_FILE_NAME = ".credentials.json"
CLAUDE_MACOS_RECOVERY_ENTRY_LIMIT = 64
CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX = (
    f".{CLAUDE_CREDENTIAL_FILE_NAME}.codex-"
)
CLAUDE_MACOS_RECOVERY_UPDATE_SUFFIX = ".tmp"
CLAUDE_MACOS_DURABLE_STAGE_GENERATION_WIDTH = 20
CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX = "claude-carrier-pending-"
CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX = "claude-carrier-durable-"
CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS = 8
CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES = (
    CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS
    * CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
)
CLAUDE_AUTH_LOGIN_ACTION = "Run `claude auth login`, then retry the review."
CLAUDE_API_KEY_ACTION = (
    "Unset or replace `ANTHROPIC_API_KEY`, then retry the review."
)
CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC = (
    "Claude credential refresh persistence also failed; the selected host "
    "credential source changed or could not be safely updated."
)
CLAUDE_REVIEW_TOOL_EXECUTABLE_CANDIDATES = (
    pathlib.Path("/opt/homebrew/bin/rg"),
    pathlib.Path("/usr/local/bin/rg"),
    pathlib.Path("/usr/bin/rg"),
)
CLAUDE_REVIEW_TOOL_LIBRARY_SUBPATH_CANDIDATES = (
    pathlib.Path("/opt/homebrew/opt/pcre2/lib"),
    pathlib.Path("/usr/local/opt/pcre2/lib"),
)
CLAUDE_LINUX_BOOTSTRAP_LIBRARY_ROOT_CANDIDATES = (
    pathlib.Path("/lib"),
    pathlib.Path("/lib64"),
    pathlib.Path("/usr/lib"),
    pathlib.Path("/usr/lib64"),
)
CLAUDE_TLS_REPLACEMENT_FILE_ENV_KEYS = (
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
)
CLAUDE_TLS_ADDITIVE_FILE_ENV_KEYS = ("NODE_EXTRA_CA_CERTS",)
CLAUDE_TLS_FILE_ENV_KEYS = (
    *CLAUDE_TLS_REPLACEMENT_FILE_ENV_KEYS,
    *CLAUDE_TLS_ADDITIVE_FILE_ENV_KEYS,
)
CLAUDE_TLS_DIR_ENV_KEYS = ("SSL_CERT_DIR",)
CLAUDE_CA_FILE_LIMIT_BYTES = 16 * 1024 * 1024
CLAUDE_CA_DIR_LIMIT_BYTES = 64 * 1024 * 1024
CLAUDE_CA_DIR_ENTRY_LIMIT = 4096
CLAUDE_CA_SYMLINK_LIMIT = 32
CLAUDE_CA_PATH_COMPONENT_LIMIT = 256
CLAUDE_CERTIFICATE_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
CLAUDE_PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN [^-\r\n]*PRIVATE KEY-----")
CLAUDE_PROXY_TARGETS = frozenset(
    {
        ("api.anthropic.com", 443),
        ("platform.claude.com", 443),
    }
)
CLAUDE_PROXY_HEADER_LIMIT_BYTES = 64 * 1024
CLAUDE_PROXY_CONNECT_TIMEOUT_SECONDS = 20.0
CLAUDE_PROXY_SERVER_START_TIMEOUT_SECONDS = 5.0
CLAUDE_PROXY_SERVER_POLL_INTERVAL_SECONDS = 0.05
CLAUDE_PROXY_SERVER_SHUTDOWN_TIMEOUT_SECONDS = 5.0
CLAUDE_REVIEW_FILE_DENY_RULES = (
    "Read(~/.aws/**)",
    "Read(~/.claude/**)",
    "Read(~/.codex/**)",
    "Read(~/.config/**)",
    "Read(~/.copilot/**)",
    "Read(~/.gnupg/**)",
    "Read(~/.kube/**)",
    "Read(~/.ssh/**)",
    "Read(~/.git-credentials)",
    "Read(~/.netrc)",
)
MACHO_MAGICS = frozenset(
    {
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
    }
)
COPILOT_PROBE_TIMEOUT_SECONDS = 20.0
COPILOT_PROBE_OUTPUT_LIMIT_BYTES = 64 * 1024
REVIEW_ATTEMPT_TIMEOUT_SECONDS = 30 * 60.0
REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024
COPILOT_JSONL_RECORD_LIMIT_BYTES = 4 * 1024 * 1024
LOW_LEVEL_HELPER_REVIEW_CONTRACT = "supplied-diff-no-git"
NAMED_LANE_ELIGIBLE = False
CLAUDE_EGRESS_CONSENTS = (
    "explicit-claude-review",
    "explicit-claude-with-copilot-fallback",
)
COPILOT_EGRESS_CONSENTS = ("explicit-claude-with-copilot-fallback",)
CODEX_ENV_KEYS = ("CODEX_HOME", "OPENAI_API_KEY")
CLAUDE_ENV_KEYS = ("ANTHROPIC_API_KEY", "NODE_EXTRA_CA_CERTS")
COPILOT_ENV_KEYS = (
    "COPILOT_GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
)

TRANSIENT_FAILURE_FRAGMENTS = (
    "at capacity",
    "capacity is temporarily",
    "overloaded",
    "rate limit",
    "rate_limit",
    "too many requests",
    "temporarily unavailable",
    "service unavailable",
    "gateway timeout",
    "timed out",
    "timeout",
    "connection reset",
    "connection refused",
    "network error",
    "status 429",
    "status 500",
    "status 502",
    "status 503",
    "status 504",
)

ENTITLEMENT_FAILURE_FRAGMENTS = (
    "not available for your account",
    "not available on your plan",
    "not available on your current plan",
    "not available with your current subscription",
    "not included in your plan",
    "not enabled for your account",
    "not enabled for this user",
    "not enabled for this organization",
    "not entitled",
    "user is not entitled",
    "does not have access to the model",
    "does not have access to this model",
    "don't have access to the model",
    "don't have access to this model",
    "do not have access to the model",
    "do not have access to this model",
    "account has no access to this model",
    "organization has no access to this model",
    "organisation has no access to this model",
    "model access is disabled",
    "model access has been disabled",
    "model is disabled by your organization",
    "model is disabled for your organization",
    "model is not allowed by your organization",
    "model is not enabled for your organization",
    "not in your organization's allowed models",
    "not in your organisation's allowed models",
    "model is not available to this account",
    "model is not available for this user",
    "not supported with your chatgpt account",
    "not supported when using codex with a chatgpt account",
    "unsupported model for this account",
    "model_not_enabled",
    "model_not_entitled",
)

STRUCTURED_ENTITLEMENT_CODES = (
    "model_access_denied",
    "model_not_enabled",
    "model_not_entitled",
    "model_permission_denied",
)
STRUCTURED_AUTH_CODES = (
    "authentication_error",
    "invalid_grant",
    "invalid_api_key",
    "invalid_token",
    "unauthorized",
)
STRUCTURED_AMBIGUOUS_MODEL_CODES = ("model_not_found", "not_found_error")

AUTH_FAILURE_FRAGMENTS = (
    "authentication failed",
    "not authenticated",
    "not logged in",
    "login required",
    "login expired",
    "please run /login",
    "claude auth login",
    "invalid api key",
    "invalid token",
    "oauth refresh failed",
    "failed to refresh oauth",
    "token refresh failed",
    "failed to refresh token",
    "unauthorized",
    "http 401",
    "status 401",
)
CODEX_ARG_TRANSPORT_NAME = re.compile(r"codex-arg0[A-Za-z0-9]+")
_UNRESOLVED_CLAUDE_REFRESH_LOCK_PROTOCOL = object()


class ClaudeProbeSandboxUnavailable(ReviewError):
    """The host does not provide the required Claude probe sandbox runtime."""


class ClaudeKeychainBrokerUnavailable(ReviewError):
    """The host cannot build the restricted Claude Keychain broker."""


class ClaudeKeychainCredentialUnavailable(ReviewError):
    """The local Claude credential is absent or cannot be used safely."""


class ClaudeCredentialUnsafe(ClaudeKeychainCredentialUnavailable):
    """A configured Claude credential source failed closed safety validation."""


class ClaudeCredentialInspectionInconclusive(ReviewError):
    """Credential I/O or a source race prevented a stable inspection."""


class ClaudeCredentialStaleRefreshLock(ClaudeCredentialInspectionInconclusive):
    """A stale shared refresh lock needs controlled operator recovery."""


class ClaudeCredentialPersistenceDiagnostic(Exception):
    """Visible Python 3.10 fallback for a secondary persistence failure."""


class ClaudeCredentialCleanupDiagnostic(Exception):
    """Visible Python 3.10 fallback for a secondary descriptor cleanup failure."""


def _is_claude_control_flow_error(error: BaseException) -> bool:
    return not isinstance(error, Exception) or isinstance(error, ForwardedSignal)


def _attach_claude_credential_cleanup_failure(
    primary: BaseException,
    _secondary: BaseException,
) -> None:
    note = "Claude credential operation also had a cleanup failure"
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        add_note(note)
        return
    diagnostic = ClaudeCredentialCleanupDiagnostic(note)
    if primary.__cause__ is not None:
        diagnostic.__cause__ = primary.__cause__
    elif primary.__context__ is not None:
        diagnostic.__context__ = primary.__context__
    primary.__cause__ = diagnostic


def _claude_visible_error_chain_contains(
    root: BaseException | None,
    candidate: BaseException,
) -> bool:
    current = root
    seen: set[int] = set()
    while current is not None and len(seen) < 32:
        if current is candidate:
            return True
        if id(current) in seen:
            break
        seen.add(id(current))
        if isinstance(current.__cause__, BaseException):
            current = current.__cause__
        elif (
            not current.__suppress_context__
            and isinstance(current.__context__, BaseException)
        ):
            current = current.__context__
        else:
            current = None
    return False


def _raise_or_attach_claude_credential_cleanup(
    primary: BaseException | None,
    cleanup_errors: list[BaseException],
    *,
    message: str,
) -> None:
    if not cleanup_errors:
        return
    cleanup_control_flow = next(
        (
            error
            for error in cleanup_errors
            if _is_claude_control_flow_error(error)
        ),
        None,
    )
    if primary is not None and _is_claude_control_flow_error(primary):
        selected = primary
    elif cleanup_control_flow is not None:
        selected = cleanup_control_flow
    elif primary is not None:
        selected = primary
    else:
        selected = ClaudeCredentialInspectionInconclusive(message)
        selected.__cause__ = cleanup_errors[0]
    for error in (primary, *cleanup_errors):
        if (
            error is None
            or error is selected
            or _claude_visible_error_chain_contains(selected, error)
        ):
            continue
        _attach_claude_credential_cleanup_failure(selected, error)
    if selected is not primary:
        raise selected


class ClaudeReviewToolUnavailable(ReviewError):
    """The host lacks a trusted local tool required by Claude Code."""


class ClaudeLoopbackUnavailable(ReviewError):
    """The host cannot bind a loopback service required by Claude Code."""


_CLAUDE_DETERMINISTIC_SOCKET_CAPABILITY_ERRNOS = frozenset(
    value
    for name in (
        "EACCES",
        "EPERM",
        "EAFNOSUPPORT",
        "EPFNOSUPPORT",
        "EPROTONOSUPPORT",
        "ESOCKTNOSUPPORT",
        "EOPNOTSUPP",
        "ENOTSUP",
        "ENOSYS",
    )
    if isinstance((value := getattr(errno, name, None)), int)
)
_CLAUDE_DETERMINISTIC_LOOPBACK_ERRNOS = (
    _CLAUDE_DETERMINISTIC_SOCKET_CAPABILITY_ERRNOS
    | frozenset(
        value
        for name in ("EADDRNOTAVAIL",)
        if isinstance((value := getattr(errno, name, None)), int)
    )
)


def _claude_loopback_bind_is_deterministically_unavailable(
    error: OSError,
) -> bool:
    return error.errno in _CLAUDE_DETERMINISTIC_LOOPBACK_ERRNOS


def _claude_unix_bind_is_deterministically_unavailable(
    error: OSError,
) -> bool:
    return error.errno in _CLAUDE_DETERMINISTIC_SOCKET_CAPABILITY_ERRNOS


class ClaudeExecutableUnavailable(ReviewError):
    """Automatic Claude discovery found only unsupported executables."""


class ClaudeExecutableInspectionInconclusive(ReviewError):
    """A Claude runtime file changed or became unreadable during inspection."""


class ClaudeProvenanceVerifierUnavailable(ReviewError):
    """The host lacks a trusted publisher-provenance verifier."""


class ClaudePublisherProvenanceInvalid(ReviewError):
    """The candidate failed deterministic publisher-provenance verification."""


class ClaudeSafeModeContractInvalid(ReviewError):
    """The candidate advertised ambiguous or unsafe safe-mode semantics."""


def _claude_linux_host() -> LinuxHost:
    host = detect_claude_linux_host()
    try:
        # Executable validation repeats this check, but doing it here gives WSL1
        # and native Windows a deterministic platform diagnostic before discovery.
        if not host.supported:
            raise LinuxUnsupportedHost(
                "WSL1 and native Windows cannot provide the required Linux sandbox"
            )
        return host
    except LinuxUnsupportedHost as error:
        raise ClaudeProbeSandboxUnavailable(str(error)) from error


def _is_claude_linux_host() -> bool:
    return sys.platform.startswith("linux")


def _is_claude_macos_host() -> bool:
    return sys.platform == "darwin"


def _claude_linux_bootstrap_library_roots() -> tuple[pathlib.Path, ...]:
    roots = tuple(
        path
        for path in CLAUDE_LINUX_BOOTSTRAP_LIBRARY_ROOT_CANDIDATES
        if path.is_dir()
    )
    if not roots:
        raise ClaudeProbeSandboxUnavailable(
            "Claude Linux bootstrap probe cannot find system library roots"
        )
    return roots


def _claude_linux_directory_identity(
    metadata: os.stat_result,
) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _create_or_validate_claude_runtime_directory(
    path: pathlib.Path,
    *,
    private: bool,
) -> pathlib.Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise ReviewError(
            f"cannot create Claude runtime directory {path}: {error}"
        ) from error
    try:
        before = path.lstat()
    except OSError as error:
        raise ReviewError(
            f"cannot inspect Claude runtime directory {path}: {error}"
        ) from error
    mode = stat.S_IMODE(before.st_mode)
    if not stat.S_ISDIR(before.st_mode):
        raise ReviewError(
            f"Claude runtime path must be a real directory: {path}"
        )
    if before.st_uid != os.geteuid():
        raise ReviewError(
            f"Claude runtime directory has an unexpected owner: {path}"
        )
    if (private and mode != 0o700) or (not private and mode & 0o022):
        requirement = "0700" if private else "not group- or world-writable"
        raise ReviewError(
            f"Claude runtime directory must be {requirement}: {path}"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReviewError(
            f"cannot open stable Claude runtime directory {path}: {error}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as error:
        raise ReviewError(
            f"Claude runtime directory changed during validation: {error}"
        ) from error
    finally:
        os.close(descriptor)
    if len(
        {
            _claude_linux_directory_identity(before),
            _claude_linux_directory_identity(opened),
            _claude_linux_directory_identity(after),
        }
    ) != 1:
        raise ReviewError("Claude runtime directory changed during validation")
    return path


def _sync_claude_credential_descriptor(descriptor: int) -> None:
    os.fsync(descriptor)
    if sys.platform != "darwin":
        return
    try:
        darwin_fcntl = importlib.import_module("fcntl")
    except ImportError as error:
        raise OSError(
            errno.ENOTSUP,
            "Darwin F_FULLFSYNC is unavailable for Claude credential durability",
        ) from error
    fullfsync = getattr(darwin_fcntl, "F_FULLFSYNC", None)
    if not isinstance(fullfsync, int):
        raise OSError(
            errno.ENOTSUP,
            "Darwin F_FULLFSYNC is unavailable for Claude credential durability",
        )
    darwin_fcntl.fcntl(descriptor, fullfsync)


def _fsync_claude_runtime_directory(
    path: pathlib.Path,
    *,
    label: str,
    require_current_user: bool = True,
) -> None:
    try:
        with _open_absolute_directory_chain_without_symlinks(path) as (
            descriptor,
            _identities,
        ):
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or (
                require_current_user and metadata.st_uid != os.geteuid()
            ):
                ownership = "current-user " if require_current_user else ""
                raise ClaudeCredentialInspectionInconclusive(
                    f"the {label} is not a stable {ownership}directory"
                )
            _sync_claude_credential_descriptor(descriptor)
    except OSError as error:
        failure = ClaudeCredentialInspectionInconclusive(
            f"cannot durably synchronize the {label}"
        )
        raise failure from error


@dataclass(frozen=True)
class Attempt:
    runtime: str
    requested_model: str
    effective_model: str | None
    requested_effort: str
    effective_effort: str | None
    returncode: int
    category: str
    final_text: str | None
    stdout_path: str
    stderr_path: str


@dataclass(frozen=True)
class Outcome:
    returncode: int
    final_text: str | None
    attempts: tuple[Attempt, ...]


def _merge_runtime_report(
    destination: dict[str, Any],
    updates: dict[str, Any],
) -> None:
    for key, value in updates.items():
        current = destination.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            _merge_runtime_report(current, value)
        else:
            destination[key] = value


def _update_claude_runtime_report(
    review: ReviewWorkspace,
    updates: dict[str, Any],
) -> None:
    path = review.container_dir / "claude-runtime.json"
    if not path.exists():
        return
    report = read_json(path)
    _merge_runtime_report(report, updates)
    write_json(path, report)


def _certified_claude_refresh_lock_protocol(
    review: ReviewWorkspace,
    executable: pathlib.Path,
) -> ClaudeRefreshLockProtocol:
    path = review.container_dir / "claude-runtime.json"
    try:
        report = read_json(path)
        version = report["version"]
        platform_key = report["platform"]
        checksum = report["sha256"]
        verified_executable = report["verified_executable"]
        publisher = report["publisher_provenance"]
    except (OSError, KeyError, TypeError, ValueError, ReviewError) as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude credential-lock protocol evidence is unavailable"
        ) from error
    if (
        report.get("schema") != 1
        or publisher != "anthropic-signed-manifest"
        or not isinstance(version, str)
        or not isinstance(platform_key, str)
        or not isinstance(checksum, str)
        or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
        or verified_executable != str(executable)
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude credential-lock protocol evidence does not match the verified "
            "runtime"
        )
    protocol = certified_claude_refresh_lock_protocol(
        version=version,
        platform_key=platform_key,
        checksum=checksum,
    )
    if protocol is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude credential-lock protocol is not certified for this signed "
            f"{version} {platform_key} artifact"
        )
    return protocol


def _native_macho_dependencies(
    path: pathlib.Path,
    *,
    label: str,
) -> tuple[pathlib.Path, ...]:
    candidates = (path.absolute(), path.resolve())
    resolved = candidates[-1]
    try:
        with resolved.open("rb") as handle:
            magic = handle.read(4)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect {label} executable: {error}"
        ) from error
    if magic not in MACHO_MAGICS or not os.access(resolved, os.X_OK):
        raise InvalidReviewerExecutable(
            f"{label} must be a native Mach-O executable, not a script or wrapper"
        )
    return tuple(dict.fromkeys(candidates))


def _claude_macos_platform_key(path: pathlib.Path) -> str:
    resolved = path.resolve()
    try:
        with resolved.open("rb") as handle:
            header = handle.read(8)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect Claude Code architecture: {error}"
        ) from error
    if len(header) < 8:
        raise InvalidReviewerExecutable(
            "Claude Code Mach-O header is truncated"
        )
    magic = header[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        byteorder = "little"
    elif magic == b"\xfe\xed\xfa\xcf":
        byteorder = "big"
    else:
        raise InvalidReviewerExecutable(
            "Claude Code must be a thin 64-bit Mach-O release artifact"
        )
    cpu_type = int.from_bytes(header[4:8], byteorder=byteorder, signed=False)
    if cpu_type == 0x0100000C:
        return "darwin-arm64"
    if cpu_type == 0x01000007:
        return "darwin-x64"
    raise InvalidReviewerExecutable(
        "Claude Code Mach-O architecture is not an official arm64 or x64 target"
    )


def _require_trusted_claude_release(
    path: pathlib.Path,
    *,
    version: str,
    platform_key: str,
    gpg_temp_root: pathlib.Path,
    gpg_temp_root_validator: Callable[[tuple[pathlib.Path, ...]], None] | None = None,
    cache_dir: pathlib.Path | None = None,
    snapshot_dir: pathlib.Path | None = None,
) -> VerifiedClaudeExecutable:
    try:
        verified = verify_claude_release(
            path,
            version=version,
            platform_key=platform_key,
            gpg_temp_root=gpg_temp_root,
            gpg_temp_root_validator=gpg_temp_root_validator,
            cache_dir=cache_dir,
        )
        return (
            materialize_verified_executable(verified, snapshot_dir)
            if snapshot_dir is not None
            else verified
        )
    except ClaudeProvenanceInvalid as error:
        raise ClaudePublisherProvenanceInvalid(str(error)) from error
    except ClaudeProvenanceInconclusive as error:
        raise ClaudeExecutableInspectionInconclusive(str(error)) from error
    except ClaudeProvenanceDependencyUnavailable as error:
        raise ClaudeProvenanceVerifierUnavailable(str(error)) from error
    except ClaudeProvenanceUnavailable as error:
        raise ClaudeExecutableInspectionInconclusive(str(error)) from error


def _claude_gpg_temp_root_validator(
    host: LinuxHost,
) -> Callable[[tuple[pathlib.Path, ...]], None]:
    def validate(paths: tuple[pathlib.Path, ...]) -> None:
        try:
            reject_claude_wsl_windows_paths(paths, host)
        except LinuxRuntimeUnsafe as error:
            raise ClaudeProvenanceInvalid(
                "trusted GPG temporary root must be on a Linux-native filesystem"
            ) from error
        except LinuxRuntimeError as error:
            raise ClaudeProvenanceInconclusive(
                "cannot prove the trusted GPG temporary root is Linux-native"
            ) from error

    return validate


def _claude_keychain_account() -> str:
    try:
        import pwd

        account = pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, OSError) as error:
        raise ReviewError(
            f"cannot resolve the Claude Keychain account: {error}"
        ) from error
    if not CLAUDE_KEYCHAIN_ACCOUNT.fullmatch(account):
        return "claude-code-user"
    return account


def _prepare_claude_keychain_broker(
    review: ReviewWorkspace,
    env: dict[str, str],
) -> dict[str, str]:
    result = dict(env)
    if result.get("ANTHROPIC_API_KEY"):
        return result
    if not CLAUDE_KEYCHAIN_CLIENT.is_file() or not os.access(
        CLAUDE_KEYCHAIN_CLIENT, os.X_OK
    ):
        raise ClaudeKeychainBrokerUnavailable(
            "Claude local-login review requires /usr/bin/security"
        )
    compiler = CLAUDE_KEYCHAIN_BROKER_COMPILER
    if not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise ClaudeKeychainBrokerUnavailable(
            "Claude local-login review requires /usr/bin/clang"
        )
    if not CLAUDE_KEYCHAIN_BROKER_SOURCE.is_file():
        raise ReviewError("Claude Keychain broker source is unavailable")
    home_raw = result.get("HOME")
    if not home_raw:
        raise ReviewError("Claude Keychain broker requires an isolated HOME")
    home = pathlib.Path(home_raw).resolve()
    if not is_relative_to(home, review.container_dir.resolve()):
        raise ReviewError("Claude Keychain broker requires a helper-owned HOME")
    broker_dir = review.container_dir.resolve() / "claude-runtime" / "keychain-broker"
    broker_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    broker = broker_dir / "security"
    broker.unlink(missing_ok=True)
    stdout_path = broker_dir / "build.stdout.log"
    stderr_path = broker_dir / "build.stderr.log"
    try:
        completed = run(
            (
                str(compiler),
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-deprecated-declarations",
                str(CLAUDE_KEYCHAIN_BROKER_SOURCE),
                "-o",
                str(broker),
            ),
            cwd=broker_dir,
            env=child_environment(container_dir=review.container_dir),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=CLAUDE_KEYCHAIN_BROKER_TIMEOUT_SECONDS,
            output_file_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
        )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot build the Claude Keychain broker: {error}"
        ) from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ClaudeExecutableInspectionInconclusive(
            "failed to build the Claude Keychain broker"
            + (f": {detail}" if detail else "")
        )
    broker.chmod(0o700)
    _native_macho_dependencies(broker, label="Claude Keychain broker")
    result["USER"] = _claude_keychain_account()
    result["PATH"] = os.pathsep.join(
        value for value in (str(broker_dir), result.get("PATH")) if value
    )
    return result


def _claude_pwd_home() -> pathlib.Path:
    try:
        import pwd

        raw_home = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, OSError) as error:
        raise ClaudeCredentialInspectionInconclusive(
            f"cannot resolve the current user's Claude credential home: {error}"
        ) from error
    home = pathlib.Path(raw_home)
    if not home.is_absolute() or home == pathlib.Path("/"):
        raise ClaudeCredentialUnsafe(
            "the current user's Claude credential home must be an absolute user directory"
        )
    return home


def _claude_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def _claude_credential_file_identity(
    metadata: os.stat_result,
) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass(frozen=True)
class _ClaudeCredentialFileSnapshot:
    home: pathlib.Path
    home_identity: tuple[int, ...]
    config_identity: tuple[int, ...]
    file_identity: tuple[int, ...]


@dataclass(frozen=True)
class _ClaudeMacOSCarrierSnapshot:
    keychain_digest: bytes | None
    file_digest: bytes | None
    file_snapshot: _ClaudeCredentialFileSnapshot | None
    keychain_refresh_digest: bytes | None = None
    file_refresh_digest: bytes | None = None


@dataclass(frozen=True)
class _ClaudeRetainedCredentialProof:
    artifact: pathlib.Path
    digest: bytes
    file_identity: tuple[int, ...]
    ancestor_identities: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class _ClaudeNoFollowArtifactSnapshot:
    ancestor_identities: tuple[tuple[int, ...], ...]
    leaf_identity: tuple[int, ...]
    leaf_complete_identity: tuple[int, ...]
    leaf_mode: int
    leaf_uid: int


@dataclass
class _ClaudeLocalCredential:
    source: str
    payload: bytearray
    expires_at_ms: float
    file_snapshot: _ClaudeCredentialFileSnapshot | None = None
    carrier_snapshot: _ClaudeMacOSCarrierSnapshot | None = None


def _claude_credential_digest(credential: bytes | bytearray) -> bytes:
    return hashlib.sha256(credential).digest()


def _claude_optional_credential_digest_matches(
    credential: bytearray | None,
    expected_digest: bytes | None,
) -> bool:
    if credential is None or expected_digest is None:
        return credential is None and expected_digest is None
    return hmac.compare_digest(
        _claude_credential_digest(credential),
        expected_digest,
    )


def _open_absolute_directory_without_symlinks(path: pathlib.Path) -> int:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ClaudeCredentialUnsafe(
            "Claude credential directory must be an absolute path without traversal"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = os.open("/", flags)
    primary_error: BaseException | None = None
    try:
        for component in path.parts[1:]:
            assert descriptor is not None
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            try:
                os.close(descriptor)
            except BaseException as error:
                # The close was attempted; never retry the same numeric fd. The
                # newly opened child still has independent cleanup ownership.
                descriptor = None
                cleanup_errors: list[BaseException] = []
                try:
                    os.close(next_descriptor)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                _raise_or_attach_claude_credential_cleanup(
                    error,
                    cleanup_errors,
                    message="cannot close Claude credential path descriptors safely",
                )
                raise
            descriptor = next_descriptor
        result = descriptor
        descriptor = None
        return result
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors = []
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        _raise_or_attach_claude_credential_cleanup(
            primary_error,
            cleanup_errors,
            message="cannot close the Claude credential path safely",
        )


@contextlib.contextmanager
def _open_absolute_directory_chain_without_symlinks(
    path: pathlib.Path,
) -> Iterator[tuple[int, tuple[tuple[int, ...], ...]]]:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ClaudeCredentialUnsafe(
            "Claude credential directory must be an absolute path without traversal"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    identities: list[tuple[int, ...]] = []
    components = path.parts[1:]
    pending_descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        pending_descriptor = root_descriptor = os.open("/", flags)
        descriptors.append(root_descriptor)
        pending_descriptor = None
        identities.append(
            _claude_linux_directory_identity(os.fstat(root_descriptor))
        )
        for component in components:
            parent_descriptor = descriptors[-1]
            before_metadata = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            pending_descriptor = next_descriptor = os.open(
                component,
                flags,
                dir_fd=parent_descriptor,
            )
            descriptors.append(next_descriptor)
            pending_descriptor = None
            opened_identity = _claude_linux_directory_identity(
                os.fstat(next_descriptor)
            )
            after_identity = _claude_linux_directory_identity(
                os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            )
            if (
                _claude_linux_directory_identity(before_metadata)
                != opened_identity
                or after_identity != opened_identity
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "a retained Claude artifact ancestor changed while opened"
                )
            identities.append(opened_identity)
        yield descriptors[-1], tuple(identities)
        if (
            _claude_linux_directory_identity(os.fstat(descriptors[0]))
            != identities[0]
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the retained Claude artifact root changed while inspected"
            )
        for index, component in enumerate(components, start=1):
            parent_descriptor = descriptors[index - 1]
            child_descriptor = descriptors[index]
            dirent_identity = _claude_linux_directory_identity(
                os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            )
            opened_identity = _claude_linux_directory_identity(
                os.fstat(child_descriptor)
            )
            if (
                dirent_identity != identities[index]
                or opened_identity != identities[index]
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "a retained Claude artifact ancestor changed during inspection"
                )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if (
            pending_descriptor is not None
            and pending_descriptor not in descriptors
        ):
            try:
                os.close(pending_descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        _raise_or_attach_claude_credential_cleanup(
            primary_error,
            cleanup_errors,
            message="cannot close the retained Claude artifact path safely",
        )


def _open_claude_credential_config_directory(
    home: pathlib.Path,
) -> tuple[int, int, tuple[int, ...], tuple[int, ...]] | None:
    owner_uid = os.getuid()
    try:
        home_descriptor: int | None = _open_absolute_directory_without_symlinks(
            home
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ClaudeCredentialUnsafe(
                "the current user's Claude credential home must not contain symlinks"
            ) from error
        raise ClaudeCredentialInspectionInconclusive(
            f"cannot safely open the current user's Claude credential home: {error}"
        ) from error
    config_descriptor: int | None = None
    try:
        assert home_descriptor is not None
        home_metadata = os.fstat(home_descriptor)
        if (
            not stat.S_ISDIR(home_metadata.st_mode)
            or home_metadata.st_uid != owner_uid
            or home_metadata.st_mode & 0o022
        ):
            raise ClaudeCredentialUnsafe(
                "the current user's Claude credential home is not a safe real directory"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            config_descriptor = os.open(".claude", flags, dir_fd=home_descriptor)
        except FileNotFoundError:
            owned_home_descriptor = home_descriptor
            home_descriptor = None
            cleanup_errors: list[BaseException] = []
            try:
                os.close(owned_home_descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
            _raise_or_attach_claude_credential_cleanup(
                None,
                cleanup_errors,
                message="cannot close the Claude credential home safely",
            )
            return None
        config_metadata = os.fstat(config_descriptor)
        if (
            not stat.S_ISDIR(config_metadata.st_mode)
            or config_metadata.st_uid != owner_uid
            or config_metadata.st_mode & 0o022
        ):
            raise ClaudeCredentialUnsafe(
                "the current user's .claude directory must be real, current-user-owned, "
                "and not group- or world-writable"
            )
        return (
            home_descriptor,
            config_descriptor,
            _claude_directory_identity(home_metadata),
            _claude_directory_identity(config_metadata),
        )
    except BaseException as error:
        cleanup_errors: list[BaseException] = []
        if config_descriptor is not None:
            try:
                os.close(config_descriptor)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if home_descriptor is not None:
            try:
                os.close(home_descriptor)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        _raise_or_attach_claude_credential_cleanup(
            error,
            cleanup_errors,
            message="cannot close the Claude credential directories safely",
        )
        if isinstance(error, OSError):
            if error.errno == errno.ELOOP:
                raise ClaudeCredentialUnsafe(
                    "the current user's .claude directory must not be a symlink"
                ) from error
            raise ClaudeCredentialInspectionInconclusive(
                "cannot inspect the current user's Claude credential directory: "
                f"{error}"
            ) from error
        raise


def _read_claude_credential_file_from_directory(
    config_descriptor: int,
    *,
    credential_name: str = CLAUDE_CREDENTIAL_FILE_NAME,
    expected_identity: tuple[int, ...] | None = None,
) -> tuple[bytearray, tuple[int, ...]] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(
            credential_name,
            flags,
            dir_fd=config_descriptor,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ClaudeCredentialUnsafe(
                "the Claude credential file must not be a symlink"
            ) from error
        raise ClaudeCredentialInspectionInconclusive(
            f"cannot safely open the Claude credential file: {error}"
        ) from error
    payload = bytearray()
    failure: BaseException | None = None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ClaudeCredentialUnsafe("the Claude credential file is not regular")
        if metadata.st_uid != os.getuid():
            raise ClaudeCredentialUnsafe(
                "the Claude credential file is not owned by the current user"
            )
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ClaudeCredentialUnsafe(
                "the Claude credential file mode must be exactly 0600"
            )
        if metadata.st_nlink != 1:
            raise ClaudeCredentialUnsafe(
                "the Claude credential file must have exactly one hard link"
            )
        if metadata.st_size <= 0 or metadata.st_size > CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES:
            raise ClaudeCredentialUnsafe(
                "the Claude credential file has an invalid bounded size"
            )
        initial_identity = _claude_credential_file_identity(metadata)
        if (
            expected_identity is not None
            and initial_identity != expected_identity
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the Claude credential file identity changed before readback"
            )
        while len(payload) <= CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES + 1 - len(payload),
                ),
            )
            if not chunk:
                break
            payload.extend(chunk)
        final_metadata = os.fstat(descriptor)
        if (
            len(payload) != metadata.st_size
            or len(payload) > CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
            or initial_identity
            != _claude_credential_file_identity(final_metadata)
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the Claude credential file changed while it was read"
            )
        return payload, initial_identity
    except OSError as error:
        failure = ClaudeCredentialInspectionInconclusive(
            f"cannot read the Claude credential file safely: {error}"
        )
        payload[:] = b"\x00" * len(payload)
        raise failure from error
    except BaseException as error:
        failure = error
        payload[:] = b"\x00" * len(payload)
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        try:
            os.close(descriptor)
        except BaseException as close_error:
            cleanup_errors.append(close_error)
            payload[:] = b"\x00" * len(payload)
        _raise_or_attach_claude_credential_cleanup(
            failure,
            cleanup_errors,
            message="cannot close the Claude credential file safely",
        )


def _read_claude_macos_file_credential(
    *,
    home: pathlib.Path | None = None,
) -> tuple[bytearray, _ClaudeCredentialFileSnapshot] | None:
    selected_home = _claude_pwd_home() if home is None else home
    opened = _open_claude_credential_config_directory(selected_home)
    if opened is None:
        return None
    home_descriptor, config_descriptor, home_identity, config_identity = opened
    payload_for_cleanup: bytearray | None = None
    primary_error: BaseException | None = None
    try:
        result = _read_claude_credential_file_from_directory(config_descriptor)
        if result is None:
            return None
        payload, file_identity = result
        payload_for_cleanup = payload
        try:
            if (
                _claude_directory_identity(os.fstat(home_descriptor)) != home_identity
                or _claude_directory_identity(os.fstat(config_descriptor))
                != config_identity
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "the Claude credential directory changed while it was read"
                )
            return payload, _ClaudeCredentialFileSnapshot(
                home=selected_home,
                home_identity=home_identity,
                config_identity=config_identity,
                file_identity=file_identity,
            )
        except OSError as error:
            payload[:] = b"\x00" * len(payload)
            raise ClaudeCredentialInspectionInconclusive(
                f"cannot revalidate the Claude credential directory: {error}"
            ) from error
        except BaseException:
            payload[:] = b"\x00" * len(payload)
            raise
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        for descriptor in (config_descriptor, home_descriptor):
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if payload_for_cleanup is not None:
                payload_for_cleanup[:] = b"\x00" * len(payload_for_cleanup)
            _raise_or_attach_claude_credential_cleanup(
                primary_error,
                cleanup_errors,
                message="cannot close the Claude credential directories safely",
            )


def _read_claude_keychain_credential(
    review: ReviewWorkspace,
) -> bytearray | None:
    client = CLAUDE_KEYCHAIN_CLIENT
    if not client.is_file() or not os.access(client, os.X_OK):
        raise ClaudeCredentialInspectionInconclusive(
            "Claude local-login review requires /usr/bin/security"
        )
    account = _claude_keychain_account()
    security_env = child_environment(container_dir=review.container_dir)
    security_env["USER"] = account
    try:
        completed = run_bounded_capture(
            (
                str(client),
                "find-generic-password",
                "-a",
                account,
                "-w",
                "-s",
                CLAUDE_KEYCHAIN_SERVICE,
            ),
            cwd=review.container_dir,
            env=security_env,
            timeout_seconds=CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS,
            stdout_limit_bytes=CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
            stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
        )
    except OSError as error:
        raise ClaudeCredentialInspectionInconclusive(
            f"Claude Keychain query failed: {error}"
        ) from error
    try:
        if completed.returncode == 44:
            return None
        if completed.returncode != 0:
            raise ClaudeCredentialInspectionInconclusive(
                "Claude Keychain query failed closed with status "
                f"{completed.returncode}"
            )
        credential = bytearray(completed.stdout)
        while credential and credential[-1] in b" \t\r\n":
            credential[-1] = 0
            credential.pop()
        leading = 0
        while leading < len(credential) and credential[leading] in b" \t\r\n":
            credential[leading] = 0
            leading += 1
        if leading:
            del credential[:leading]
        return credential
    finally:
        completed.stdout[:] = b"\x00" * len(completed.stdout)
        completed.stderr[:] = b"\x00" * len(completed.stderr)


def _claude_macos_carriers_match(
    review: ReviewWorkspace,
    expected: _ClaudeMacOSCarrierSnapshot,
) -> bool:
    keychain_credential: bytearray | None = None
    file_credential: bytearray | None = None
    try:
        keychain_credential = _read_claude_keychain_credential(review)
        file_result = _read_claude_macos_file_credential()
        current_file_snapshot: _ClaudeCredentialFileSnapshot | None = None
        if file_result is not None:
            file_credential, current_file_snapshot = file_result
        return (
            _claude_optional_credential_digest_matches(
                keychain_credential,
                expected.keychain_digest,
            )
            and _claude_optional_credential_digest_matches(
                file_credential,
                expected.file_digest,
            )
            and current_file_snapshot == expected.file_snapshot
        )
    finally:
        if keychain_credential is not None:
            keychain_credential[:] = b"\x00" * len(keychain_credential)
        if file_credential is not None:
            file_credential[:] = b"\x00" * len(file_credential)


def _read_claude_macos_carrier_snapshot(
    review: ReviewWorkspace,
) -> _ClaudeMacOSCarrierSnapshot:
    keychain_credential: bytearray | None = None
    file_credential: bytearray | None = None
    file_snapshot: _ClaudeCredentialFileSnapshot | None = None
    try:
        keychain_credential = _read_claude_keychain_credential(review)
        file_result = _read_claude_macos_file_credential()
        if file_result is not None:
            file_credential, file_snapshot = file_result
        return _ClaudeMacOSCarrierSnapshot(
            keychain_digest=(
                _claude_credential_digest(keychain_credential)
                if keychain_credential is not None
                else None
            ),
            file_digest=(
                _claude_credential_digest(file_credential)
                if file_credential is not None
                else None
            ),
            file_snapshot=file_snapshot,
            keychain_refresh_digest=(
                _claude_credential_refresh_digest(keychain_credential)
                if keychain_credential is not None
                else None
            ),
            file_refresh_digest=(
                _claude_credential_refresh_digest(file_credential)
                if file_credential is not None
                else None
            ),
        )
    finally:
        if keychain_credential is not None:
            keychain_credential[:] = b"\x00" * len(keychain_credential)
        if file_credential is not None:
            file_credential[:] = b"\x00" * len(file_credential)


def _validate_claude_local_credential(
    credential: bytes | bytearray,
    *,
    source: str,
    require_unexpired: bool = False,
) -> float:
    try:
        payload = json.loads(
            credential,
            parse_constant=_reject_nonstandard_json_constant,
            object_pairs_hook=_strict_json_object_from_pairs,
        )
        if not isinstance(payload, dict):
            raise TypeError("credential JSON is not an object")
        oauth = payload["claudeAiOauth"]
        if not isinstance(oauth, dict):
            raise TypeError("claudeAiOauth is not an object")
        access_token = oauth.get("accessToken")
        refresh_token = oauth.get("refreshToken")
        expires_at = oauth.get("expiresAt")
        if (
            not isinstance(access_token, str)
            or not access_token.strip()
            or not isinstance(refresh_token, str)
            or not refresh_token.strip()
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
        ):
            raise ValueError("required OAuth fields are absent")
        access_token.encode("utf-8")
        refresh_token.encode("utf-8")
        expires_at_ms = float(expires_at)
        if not math.isfinite(expires_at_ms):
            raise ValueError("credential expiry is not finite")
        if require_unexpired and expires_at_ms <= time.time() * 1000:
            raise ValueError("refreshed credential is already expired")
        return expires_at_ms
    except (
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        json.JSONDecodeError,
    ) as error:
        raise ClaudeCredentialUnsafe(
            f"Claude {source} credential is malformed"
        ) from error


def _claude_credential_refresh_digest(
    credential: bytes | bytearray,
) -> bytes:
    try:
        payload = json.loads(
            credential,
            parse_constant=_reject_nonstandard_json_constant,
            object_pairs_hook=_strict_json_object_from_pairs,
        )
        oauth = payload["claudeAiOauth"]
        refresh_token = oauth["refreshToken"]
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            raise ValueError("refresh token is absent")
        return hashlib.sha256(refresh_token.encode("utf-8")).digest()
    except (
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
        json.JSONDecodeError,
    ) as error:
        raise ClaudeCredentialUnsafe(
            "Claude credential refresh token is malformed"
        ) from error


def _claude_macos_carriers_share_refresh_token(
    snapshot: _ClaudeMacOSCarrierSnapshot,
) -> bool:
    return (
        snapshot.keychain_refresh_digest is not None
        and snapshot.file_refresh_digest is not None
        and hmac.compare_digest(
            snapshot.keychain_refresh_digest,
            snapshot.file_refresh_digest,
        )
    )


def _claude_keychain_update_script_prefix() -> bytes:
    account = _claude_keychain_account()
    return (
        f'add-generic-password -U -a "{account}" '
        f'-s "{CLAUDE_KEYCHAIN_SERVICE}" -X "'
    ).encode("ascii")


CLAUDE_KEYCHAIN_UPDATE_SCRIPT_SUFFIX = b'"\n'
CLAUDE_KEYCHAIN_HEX_DIGITS = b"0123456789abcdef"


def _claude_keychain_update_script(
    credential: bytes | bytearray,
) -> bytearray:
    prefix = _claude_keychain_update_script_prefix()
    suffix = CLAUDE_KEYCHAIN_UPDATE_SCRIPT_SUFFIX
    script = bytearray(len(prefix) + 2 * len(credential) + len(suffix))
    script[: len(prefix)] = prefix
    offset = len(prefix)
    for value in credential:
        script[offset] = CLAUDE_KEYCHAIN_HEX_DIGITS[value >> 4]
        script[offset + 1] = CLAUDE_KEYCHAIN_HEX_DIGITS[value & 0x0F]
        offset += 2
    script[offset:] = suffix
    return script


def _claude_keychain_credential_has_refresh_margin(
    credential: bytes | bytearray,
) -> bool:
    return (
        len(_claude_keychain_update_script_prefix())
        + 2 * len(credential)
        + len(CLAUDE_KEYCHAIN_UPDATE_SCRIPT_SUFFIX)
        <= CLAUDE_KEYCHAIN_SECURITY_STDIN_LIMIT_BYTES
    )


def _select_claude_macos_credential(
    review: ReviewWorkspace,
) -> _ClaudeLocalCredential:
    candidates: list[_ClaudeLocalCredential] = []
    keychain_credential: bytearray | None = None
    file_credential: bytearray | None = None
    keychain_digest: bytes | None = None
    file_digest: bytes | None = None
    keychain_refresh_digest: bytes | None = None
    file_refresh_digest: bytes | None = None
    observed_file_snapshot: _ClaudeCredentialFileSnapshot | None = None
    try:
        keychain_credential = _read_claude_keychain_credential(review)
        if keychain_credential is not None:
            expires_at_ms = _validate_claude_local_credential(
                keychain_credential,
                source="macOS Keychain",
            )
            keychain_digest = _claude_credential_digest(keychain_credential)
            keychain_refresh_digest = _claude_credential_refresh_digest(
                keychain_credential
            )
            candidates.append(
                _ClaudeLocalCredential(
                    source="macos-keychain",
                    payload=keychain_credential,
                    expires_at_ms=expires_at_ms,
                )
            )
            keychain_credential = None

        file_result = _read_claude_macos_file_credential()
        if file_result is not None:
            file_credential, file_snapshot = file_result
            expires_at_ms = _validate_claude_local_credential(
                file_credential,
                source="pwd-home file",
            )
            file_digest = _claude_credential_digest(file_credential)
            file_refresh_digest = _claude_credential_refresh_digest(file_credential)
            observed_file_snapshot = file_snapshot
            candidates.append(
                _ClaudeLocalCredential(
                    source="pwd-home-credential-file",
                    payload=file_credential,
                    expires_at_ms=expires_at_ms,
                    file_snapshot=file_snapshot,
                )
            )
            file_credential = None

        if not candidates:
            raise ClaudeKeychainCredentialUnavailable(
                "Claude local-login credential is unavailable in both macOS Keychain "
                "and the current user's pwd-home credential file"
            )
        selected = max(
            candidates,
            key=lambda candidate: (
                candidate.expires_at_ms,
                candidate.source == "macos-keychain",
            ),
        )
        carrier_snapshot = _ClaudeMacOSCarrierSnapshot(
            keychain_digest=keychain_digest,
            file_digest=file_digest,
            file_snapshot=observed_file_snapshot,
            keychain_refresh_digest=keychain_refresh_digest,
            file_refresh_digest=file_refresh_digest,
        )
        selected.carrier_snapshot = carrier_snapshot
        keychain_candidate = next(
            (
                candidate
                for candidate in candidates
                if candidate.source == "macos-keychain"
            ),
            None,
        )
        if (
            keychain_candidate is not None
            and (
                selected.source == "macos-keychain"
                or _claude_macos_carriers_share_refresh_token(carrier_snapshot)
            )
            and not _claude_keychain_credential_has_refresh_margin(
                selected.payload
            )
        ):
            raise ClaudeCredentialUnsafe(
                "Claude macOS Keychain credential is too large for safe refresh "
                "persistence without command-line exposure"
            )
        for candidate in candidates:
            if candidate is not selected:
                candidate.payload[:] = b"\x00" * len(candidate.payload)
        return selected
    except BaseException:
        if keychain_credential is not None:
            keychain_credential[:] = b"\x00" * len(keychain_credential)
        if file_credential is not None:
            file_credential[:] = b"\x00" * len(file_credential)
        for candidate in candidates:
            candidate.payload[:] = b"\x00" * len(candidate.payload)
        raise


@contextlib.contextmanager
def _claude_credential_update_lock(name: str) -> Iterator[None]:
    try:
        import fcntl
    except ImportError as error:
        raise ClaudeCredentialInspectionInconclusive(
            "Claude credential update locking is unavailable"
        ) from error

    if not re.fullmatch(r"[a-z-]+", name):
        raise ReviewError("Claude credential update lock name is invalid")
    path = pathlib.Path(f"/tmp/codex-claude-{name}-{os.getuid()}.lock")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot open the Claude credential update lock safely"
        ) from error
    locked = False
    primary_error: BaseException | None = None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ReviewError("Claude credential update lock is not private")
        deadline = time.monotonic() + CLAUDE_CREDENTIAL_UPDATE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ClaudeCredentialInspectionInconclusive(
                        "another isolated review is updating Claude credentials"
                    )
                time.sleep(0.05)
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if locked:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            os.close(descriptor)
        except BaseException as error:
            cleanup_errors.append(error)
        _raise_or_attach_claude_credential_cleanup(
            primary_error,
            cleanup_errors,
            message="cannot release the Claude credential update lock safely",
        )


def _claude_refresh_lock_config_directory() -> pathlib.Path:
    config_dir = _claude_pwd_home() / ".claude"
    try:
        os.mkdir(config_dir, 0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot prepare the current user's Claude refresh-lock directory"
        ) from error
    return config_dir


def _write_claude_keychain_credential(
    review: ReviewWorkspace,
    credential: bytearray,
    expected_credential: bytearray,
    carrier_snapshot: _ClaudeMacOSCarrierSnapshot,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    *,
    coordinated_refresh_lock: ClaudeRefreshLockLease | None = None,
    carriers_already_matched: bool = False,
) -> bool:
    try:
        _validate_claude_local_credential(
            credential,
            source="refreshed macOS Keychain",
        )
    except ClaudeCredentialUnsafe:
        return False
    if not _claude_keychain_credential_has_refresh_margin(credential):
        return False
    script = _claude_keychain_update_script(credential)
    account = _claude_keychain_account()
    security_env = child_environment(container_dir=review.container_dir)
    security_env["USER"] = account
    try:
        try:
            update_lock_context = (
                contextlib.nullcontext()
                if coordinated_refresh_lock is not None
                else _claude_credential_update_lock("keychain")
            )
            with update_lock_context:
                try:
                    refresh_lock_context = (
                        contextlib.nullcontext(coordinated_refresh_lock)
                        if coordinated_refresh_lock is not None
                        else claude_refresh_lock(
                            _claude_refresh_lock_config_directory(),
                            protocol=refresh_lock_protocol,
                        )
                    )
                    with refresh_lock_context as refresh_lock:
                        if (
                            not carriers_already_matched
                            and not _claude_macos_carriers_match(
                            review,
                            carrier_snapshot,
                            )
                        ):
                            return False
                        current = _read_claude_keychain_credential(review)
                        if current is None:
                            return False
                        try:
                            if not hmac.compare_digest(current, expected_credential):
                                return False
                        finally:
                            current[:] = b"\x00" * len(current)
                        refresh_lock.assert_held()
                        completed = run_bounded_capture(
                            (str(CLAUDE_KEYCHAIN_CLIENT), "-i"),
                            cwd=review.container_dir,
                            env=security_env,
                            stdin=script,
                            timeout_seconds=CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS,
                            stdout_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
                            stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
                        )
                except ClaudeRefreshLockStale as error:
                    raise ClaudeCredentialStaleRefreshLock(
                        "a stale Claude refresh lock requires controlled cleanup "
                        "after confirming that no Claude credential writer is active"
                    ) from error
                except ClaudeRefreshLockError as error:
                    raise ClaudeCredentialInspectionInconclusive(
                        "cannot coordinate Claude Keychain refresh writeback: "
                        f"{error}"
                    ) from error
        except ClaudeCredentialInspectionInconclusive:
            raise
        except (OSError, ReviewError):
            return False
        try:
            return completed.returncode == 0
        finally:
            completed.stdout[:] = b"\x00" * len(completed.stdout)
            completed.stderr[:] = b"\x00" * len(completed.stderr)
    finally:
        script[:] = b"\x00" * len(script)


def _write_all_to_descriptor(descriptor: int, payload: bytearray) -> None:
    offset = 0
    view = memoryview(payload)
    try:
        while offset < len(payload):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("short write while persisting Claude credential")
            offset += written
    finally:
        view.release()


def _write_claude_file_credential(
    review: ReviewWorkspace,
    credential: bytearray,
    expected_credential: bytearray,
    snapshot: _ClaudeCredentialFileSnapshot,
    carrier_snapshot: _ClaudeMacOSCarrierSnapshot,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    *,
    coordinated_refresh_lock: ClaudeRefreshLockLease | None = None,
    carriers_already_matched: bool = False,
) -> bool:
    try:
        _validate_claude_local_credential(
            credential,
            source="refreshed pwd-home file",
        )
    except ClaudeCredentialUnsafe:
        return False
    temporary_name = (
        f".{CLAUDE_CREDENTIAL_FILE_NAME}.codex-{secrets.token_hex(16)}.tmp"
    )
    temporary_created = False
    try:
        update_lock_context = (
            contextlib.nullcontext()
            if coordinated_refresh_lock is not None
            else _claude_credential_update_lock("credential-file")
        )
        with update_lock_context:
            try:
                refresh_lock_context = (
                    contextlib.nullcontext(coordinated_refresh_lock)
                    if coordinated_refresh_lock is not None
                    else claude_refresh_lock(
                        snapshot.home / ".claude",
                        protocol=refresh_lock_protocol,
                    )
                )
                with refresh_lock_context as refresh_lock:
                    if (
                        not carriers_already_matched
                        and not _claude_macos_carriers_match(
                        review,
                        carrier_snapshot,
                        )
                    ):
                        return False
                    opened = _open_claude_credential_config_directory(snapshot.home)
                    if opened is None:
                        return False
                    (
                        home_descriptor,
                        config_descriptor,
                        home_identity,
                        config_identity,
                    ) = opened
                    operation_error: BaseException | None = None
                    try:
                        if (
                            home_identity != snapshot.home_identity
                            or config_identity != snapshot.config_identity
                        ):
                            return False
                        current_result = _read_claude_credential_file_from_directory(
                            config_descriptor
                        )
                        if current_result is None:
                            return False
                        current, file_identity = current_result
                        try:
                            if (
                                file_identity != snapshot.file_identity
                                or not hmac.compare_digest(
                                    current,
                                    expected_credential,
                                )
                            ):
                                return False
                        finally:
                            current[:] = b"\x00" * len(current)
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
                            os,
                            "O_NOFOLLOW",
                            0,
                        )
                        temporary_descriptor = os.open(
                            temporary_name,
                            flags,
                            0o600,
                            dir_fd=config_descriptor,
                        )
                        temporary_created = True
                        temporary_operation_error: BaseException | None = None
                        try:
                            os.fchmod(temporary_descriptor, 0o600)
                            _write_all_to_descriptor(temporary_descriptor, credential)
                            _sync_claude_credential_descriptor(
                                temporary_descriptor
                            )
                            temporary_metadata = os.fstat(temporary_descriptor)
                            if (
                                not stat.S_ISREG(temporary_metadata.st_mode)
                                or temporary_metadata.st_uid != os.getuid()
                                or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
                                or temporary_metadata.st_nlink != 1
                                or temporary_metadata.st_size != len(credential)
                            ):
                                return False
                        except BaseException as error:
                            temporary_operation_error = error
                            raise
                        finally:
                            temporary_cleanup_errors: list[BaseException] = []
                            try:
                                os.close(temporary_descriptor)
                            except BaseException as error:
                                temporary_cleanup_errors.append(error)
                            _raise_or_attach_claude_credential_cleanup(
                                temporary_operation_error,
                                temporary_cleanup_errors,
                                message=(
                                    "cannot close the temporary Claude credential "
                                    "file safely"
                                ),
                            )
                        current_result = _read_claude_credential_file_from_directory(
                            config_descriptor
                        )
                        if current_result is None:
                            return False
                        current, current_identity = current_result
                        try:
                            if (
                                current_identity != snapshot.file_identity
                                or not hmac.compare_digest(
                                    current,
                                    expected_credential,
                                )
                            ):
                                return False
                        finally:
                            current[:] = b"\x00" * len(current)
                        refresh_lock.assert_held()
                        os.replace(
                            temporary_name,
                            CLAUDE_CREDENTIAL_FILE_NAME,
                            src_dir_fd=config_descriptor,
                            dst_dir_fd=config_descriptor,
                        )
                        temporary_created = False
                        _sync_claude_credential_descriptor(config_descriptor)
                        persisted = _read_claude_credential_file_from_directory(
                            config_descriptor
                        )
                        if persisted is None:
                            return False
                        persisted_payload, _persisted_identity = persisted
                        try:
                            return hmac.compare_digest(persisted_payload, credential)
                        finally:
                            persisted_payload[:] = b"\x00" * len(persisted_payload)
                    except BaseException as error:
                        operation_error = error
                        raise
                    finally:
                        cleanup_errors: list[BaseException] = []
                        if temporary_created:
                            try:
                                os.unlink(temporary_name, dir_fd=config_descriptor)
                            except FileNotFoundError:
                                pass
                            except BaseException as error:
                                cleanup_errors.append(error)
                        for descriptor in (config_descriptor, home_descriptor):
                            try:
                                os.close(descriptor)
                            except BaseException as error:
                                cleanup_errors.append(error)
                        _raise_or_attach_claude_credential_cleanup(
                            operation_error,
                            cleanup_errors,
                            message=(
                                "cannot clean up Claude credential-file writeback "
                                "safely"
                            ),
                        )
            except ClaudeRefreshLockStale as error:
                raise ClaudeCredentialStaleRefreshLock(
                    "a stale Claude refresh lock requires controlled cleanup after "
                    "confirming that no Claude credential writer is active"
                ) from error
            except ClaudeRefreshLockError as error:
                raise ClaudeCredentialInspectionInconclusive(
                    "cannot coordinate Claude credential-file refresh writeback: "
                    f"{error}"
                ) from error
    except ClaudeCredentialInspectionInconclusive:
        raise
    except (OSError, ReviewError):
        return False


@contextlib.contextmanager
def _claude_macos_carrier_coordination(
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
) -> Iterator[ClaudeRefreshLockLease]:
    try:
        with _claude_credential_update_lock("keychain"):
            with _claude_credential_update_lock("credential-file"):
                with claude_refresh_lock(
                    _claude_refresh_lock_config_directory(),
                    protocol=refresh_lock_protocol,
                ) as refresh_lock:
                    yield refresh_lock
    except ClaudeRefreshLockStale as error:
        raise ClaudeCredentialStaleRefreshLock(
            "a stale Claude refresh lock requires controlled cleanup after "
            "confirming that no Claude credential writer is active"
        ) from error
    except ClaudeRefreshLockError as error:
        raise ClaudeCredentialInspectionInconclusive(
            f"cannot coordinate Claude credential refresh writeback: {error}"
        ) from error


def _persist_claude_macos_refreshed_credential(
    review: ReviewWorkspace,
    selected: _ClaudeLocalCredential,
    refreshed: bytearray,
    expected_credential: bytearray,
    carrier_snapshot: _ClaudeMacOSCarrierSnapshot,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
) -> _ClaudeMacOSCarrierSnapshot | None:
    try:
        return _persist_claude_macos_refreshed_credential_impl(
            review,
            selected,
            refreshed,
            expected_credential,
            carrier_snapshot,
            refresh_lock_protocol,
        )
    except ClaudeCredentialUnsafe as error:
        raise ClaudeCredentialInspectionInconclusive(
            "Claude credential carriers became unsafe while refreshed credentials "
            "were being persisted"
        ) from error


def _claude_review_workspace_roots(
    review: ReviewWorkspace,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    source_root = review.source_root
    container_root = review.container_dir
    if (
        not source_root.is_absolute()
        or not container_root.is_absolute()
        or any(part in {".", ".."} for part in source_root.parts)
        or any(part in {".", ".."} for part in container_root.parts)
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the Claude review workspace paths are not canonical absolute paths"
        )
    review_root = source_root / ".codex-tmp"
    if (
        container_root.parent != review_root
        or not container_root.name.startswith("isolated-review-")
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the Claude review container is outside its private review root"
        )
    return source_root, review_root, container_root


def _claude_macos_recovery_root(review: ReviewWorkspace) -> pathlib.Path:
    _source_root, _review_root, container_root = (
        _claude_review_workspace_roots(review)
    )
    try:
        with _open_absolute_directory_chain_without_symlinks(container_root):
            pass
    except ClaudeCredentialInspectionInconclusive:
        raise
    except (OSError, RuntimeError, ValueError, ReviewError) as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot validate the macOS Claude recovery container path"
        ) from error
    runtime_parent = _create_or_validate_claude_runtime_directory(
        container_root / "claude-runtime",
        private=False,
    )
    return _create_or_validate_claude_runtime_directory(
        runtime_parent / "macos",
        private=True,
    )


def _retain_claude_macos_refreshed_credential(
    review: ReviewWorkspace,
    credential: bytearray,
    *,
    requested_carrier_root: pathlib.Path | None = None,
    credential_prevalidated: bool = False,
    durable_directories: bool = False,
) -> pathlib.Path:
    if not credential_prevalidated:
        _validate_claude_local_credential(
            credential,
            source="macOS recovery carrier",
        )
    credential_digest = _claude_credential_digest(credential)
    if durable_directories:
        source_root, review_root, container_root = (
            _claude_review_workspace_roots(review)
        )
        _fsync_claude_runtime_directory(
            source_root,
            label="Claude source repository root",
            require_current_user=False,
        )
        _fsync_claude_runtime_directory(
            review_root,
            label="Claude review workspace root",
        )
        _fsync_claude_runtime_directory(
            container_root,
            label="Claude review container",
        )
    recovery_root = _claude_macos_recovery_root(review)
    if durable_directories:
        _fsync_claude_runtime_directory(
            container_root / "claude-runtime",
            label="Claude runtime directory",
        )
    carrier_root: pathlib.Path | None = None
    config_dir: pathlib.Path | None = None
    payload_verified = False

    def mark_retention_failure(error: BaseException) -> None:
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        if carrier_root is None:
            return
        try:
            carrier_root.lstat()
        except OSError:
            return
        if payload_verified:
            setattr(
                error,
                "_codex_claude_retained_credential_carrier",
                str(carrier_root),
            )
            _mark_claude_macos_recovery_update_artifact(
                error,
                carrier_root / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                expected_digest=credential_digest,
            )
        else:
            _mark_claude_macos_recovery_cleanup_artifact(
                error,
                carrier_root,
            )

    try:
        if requested_carrier_root is None:
            carrier_root = pathlib.Path(
                tempfile.mkdtemp(
                    prefix="claude-carrier-",
                    dir=recovery_root,
                )
            )
        else:
            if (
                not requested_carrier_root.is_absolute()
                or requested_carrier_root.parent != recovery_root
                or not requested_carrier_root.name.startswith(
                    "claude-carrier-"
                )
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "the requested macOS Claude recovery carrier path is unsafe"
                )
            requested_carrier_root.mkdir(mode=0o700)
            carrier_root = requested_carrier_root
        _create_or_validate_claude_runtime_directory(
            carrier_root,
            private=True,
        )
        if durable_directories:
            _fsync_claude_runtime_directory(
                recovery_root,
                label="macOS Claude recovery root",
            )
        config_dir = carrier_root / "config"
        _create_or_validate_claude_runtime_directory(
            config_dir,
            private=True,
        )
        if durable_directories:
            _fsync_claude_runtime_directory(
                carrier_root,
                label="macOS Claude recovery carrier",
            )
    except (OSError, ReviewError) as error:
        failure = ClaudeCredentialInspectionInconclusive(
            "cannot create a private macOS Claude recovery carrier"
        )
        failure.__cause__ = error
        concurrent_candidate = None
        if (
            carrier_root is None
            and requested_carrier_root is not None
            and isinstance(error, FileExistsError)
        ):
            # Another recovery owner can win creation of the shared candidate.
            # Report that exact path even though this caller never owned it.
            concurrent_candidate = requested_carrier_root
        cleanup_errors: list[BaseException] = []
        for directory in (config_dir, carrier_root):
            if directory is None:
                continue
            try:
                directory.rmdir()
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        _raise_or_attach_claude_credential_cleanup(
            failure,
            cleanup_errors,
            message="cannot clean up an empty macOS Claude recovery carrier",
        )
        setattr(failure, "_codex_claude_refresh_persistence_failed", True)
        if concurrent_candidate is not None:
            try:
                concurrent_candidate.lstat()
            except OSError:
                pass
            else:
                _mark_claude_macos_recovery_cleanup_artifact(
                    failure,
                    concurrent_candidate,
                )
        elif carrier_root is not None:
            try:
                carrier_root.lstat()
            except FileNotFoundError:
                pass
            except OSError:
                _mark_claude_macos_recovery_cleanup_artifact(
                    failure,
                    carrier_root,
                )
            else:
                _mark_claude_macos_recovery_cleanup_artifact(
                    failure,
                    carrier_root,
                )
        raise failure

    assert carrier_root is not None
    assert config_dir is not None
    try:
        carrier_metadata = carrier_root.lstat()
        config_metadata = config_dir.lstat()
    except OSError as error:
        failure = ClaudeCredentialInspectionInconclusive(
            "cannot snapshot the private macOS Claude recovery carrier"
        )
        mark_retention_failure(failure)
        raise failure from error

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    file_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
        os,
        "O_NOFOLLOW",
        0,
    )
    config_descriptor: int | None = None
    credential_descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        config_descriptor = os.open(config_dir, directory_flags)
        opened_config_metadata = os.fstat(config_descriptor)
        prewrite_carrier_metadata = carrier_root.lstat()
        prewrite_config_metadata = config_dir.lstat()
        if (
            _claude_linux_directory_identity(carrier_metadata)
            != _claude_linux_directory_identity(prewrite_carrier_metadata)
            or len(
                {
                    _claude_linux_directory_identity(config_metadata),
                    _claude_linux_directory_identity(opened_config_metadata),
                    _claude_linux_directory_identity(prewrite_config_metadata),
                }
            )
            != 1
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery carrier moved before write"
            )
        credential_descriptor = os.open(
            CLAUDE_CREDENTIAL_FILE_NAME,
            file_flags,
            0o600,
            dir_fd=config_descriptor,
        )
        os.fchmod(credential_descriptor, 0o600)
        _write_all_to_descriptor(credential_descriptor, credential)
        _sync_claude_credential_descriptor(credential_descriptor)
        descriptor_metadata = os.fstat(credential_descriptor)
        path_metadata = os.stat(
            CLAUDE_CREDENTIAL_FILE_NAME,
            dir_fd=config_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(descriptor_metadata.st_mode)
            or descriptor_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(descriptor_metadata.st_mode) != 0o600
            or descriptor_metadata.st_nlink != 1
            or descriptor_metadata.st_size != len(credential)
            or _claude_credential_file_identity(descriptor_metadata)
            != _claude_credential_file_identity(path_metadata)
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery carrier changed while it was written"
            )
        _sync_claude_credential_descriptor(config_descriptor)
        recovered_result = _read_claude_credential_file_from_directory(
            config_descriptor
        )
        if recovered_result is None:
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery credential disappeared"
            )
        recovered, recovered_identity = recovered_result
        try:
            if (
                not hmac.compare_digest(recovered, credential)
                or _claude_credential_file_identity(
                    os.fstat(credential_descriptor)
                )
                != recovered_identity
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "the private macOS Claude recovery credential changed after write"
                )
        finally:
            recovered[:] = b"\x00" * len(recovered)
        current_carrier_metadata = carrier_root.lstat()
        current_config_metadata = config_dir.lstat()
        if (
            _claude_linux_directory_identity(carrier_metadata)
            != _claude_linux_directory_identity(current_carrier_metadata)
            or len(
                {
                    _claude_linux_directory_identity(config_metadata),
                    _claude_linux_directory_identity(opened_config_metadata),
                    _claude_linux_directory_identity(current_config_metadata),
                }
            )
            != 1
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery carrier moved while it was written"
            )
        payload_verified = True
    except BaseException as error:
        primary_error = error
        mark_retention_failure(error)
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        for descriptor in (credential_descriptor, config_descriptor):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            _raise_or_attach_claude_credential_cleanup(
                primary_error,
                cleanup_errors,
                message=(
                    "cannot close the private macOS Claude recovery carrier safely"
                ),
            )
        except BaseException as cleanup_error:
            mark_retention_failure(cleanup_error)
            raise
    return carrier_root


def _read_claude_macos_recovery_credential(
    review: ReviewWorkspace,
    carrier_root: pathlib.Path,
) -> bytearray:
    recovery_root = _claude_macos_recovery_root(review)
    if (
        not carrier_root.is_absolute()
        or carrier_root.parent != recovery_root
        or not carrier_root.name.startswith("claude-carrier-")
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the macOS Claude recovery carrier path is outside the private root"
        )
    config_dir = carrier_root / "config"
    try:
        carrier_metadata = carrier_root.lstat()
        config_metadata = config_dir.lstat()
        _create_or_validate_claude_runtime_directory(
            carrier_root,
            private=True,
        )
        _create_or_validate_claude_runtime_directory(
            config_dir,
            private=True,
        )
    except (OSError, ReviewError) as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot validate the private macOS Claude recovery carrier"
        ) from error
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    config_descriptor: int | None = None
    result: tuple[bytearray, tuple[int, ...]] | None = None
    payload: bytearray | None = None
    primary_error: BaseException | None = None
    try:
        config_descriptor = os.open(config_dir, flags)
        opened_config_metadata = os.fstat(config_descriptor)
        result = _read_claude_credential_file_from_directory(
            config_descriptor
        )
        if result is None:
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery credential is missing"
            )
        payload, _identity = result
        current_carrier_metadata = carrier_root.lstat()
        current_config_metadata = config_dir.lstat()
        if (
            _claude_linux_directory_identity(carrier_metadata)
            != _claude_linux_directory_identity(current_carrier_metadata)
            or len(
                {
                    _claude_linux_directory_identity(config_metadata),
                    _claude_linux_directory_identity(opened_config_metadata),
                    _claude_linux_directory_identity(current_config_metadata),
                }
            )
            != 1
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery carrier moved while read"
            )
        return payload
    except BaseException as error:
        primary_error = error
        payload_to_wipe = payload
        if payload_to_wipe is None and result is not None:
            payload_to_wipe = result[0]
        if payload_to_wipe is not None:
            payload_to_wipe[:] = b"\x00" * len(payload_to_wipe)
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if config_descriptor is not None:
            try:
                os.close(config_descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
                payload_to_wipe = payload
                if payload_to_wipe is None and result is not None:
                    payload_to_wipe = result[0]
                if payload_to_wipe is not None:
                    payload_to_wipe[:] = b"\x00" * len(payload_to_wipe)
        _raise_or_attach_claude_credential_cleanup(
            primary_error,
            cleanup_errors,
            message="cannot close the macOS Claude recovery carrier safely",
        )


def _commit_claude_macos_durable_stage(
    review: ReviewWorkspace,
    pending_carrier: pathlib.Path,
    acknowledged_carrier: pathlib.Path,
    credential: bytearray,
) -> pathlib.Path:
    credential_digest = _claude_credential_digest(credential)
    recovery_root = _claude_macos_recovery_root(review)
    if (
        pending_carrier.parent != recovery_root
        or acknowledged_carrier.parent != recovery_root
        or not pending_carrier.name.startswith(
            CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX
        )
        or not acknowledged_carrier.name.startswith(
            CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX
        )
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the macOS Claude durable-stage carrier path is unsafe"
        )

    def mark_stage_failure(
        error: BaseException,
        carrier: pathlib.Path,
        *,
        payload_verified: bool,
    ) -> None:
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        try:
            carrier.lstat()
        except OSError:
            return
        if payload_verified:
            setattr(
                error,
                "_codex_claude_retained_credential_carrier",
                str(carrier),
            )
            _mark_claude_macos_recovery_update_artifact(
                error,
                carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                expected_digest=credential_digest,
            )
        else:
            _mark_claude_macos_recovery_cleanup_artifact(error, carrier)

    pending_payload: bytearray | None = None
    pending_verified = False
    try:
        pending_payload = _read_claude_macos_recovery_credential(
            review,
            pending_carrier,
        )
        if not hmac.compare_digest(pending_payload, credential):
            raise ClaudeCredentialInspectionInconclusive(
                "the macOS Claude durable-stage credential changed before commit"
            )
        pending_verified = True
    except BaseException as error:
        mark_stage_failure(
            error,
            pending_carrier,
            payload_verified=False,
        )
        raise
    finally:
        if pending_payload is not None:
            pending_payload[:] = b"\x00" * len(pending_payload)

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    recovery_descriptor: int | None = None
    renamed = False
    committed_identity_verified = False
    primary_error: BaseException | None = None
    try:
        recovery_descriptor = os.open(recovery_root, flags)
        pending_metadata = os.stat(
            pending_carrier.name,
            dir_fd=recovery_descriptor,
            follow_symlinks=False,
        )
        try:
            os.stat(
                acknowledged_carrier.name,
                dir_fd=recovery_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise ClaudeCredentialInspectionInconclusive(
                "the macOS Claude durable-stage generation already exists"
            )
        os.rename(
            pending_carrier.name,
            acknowledged_carrier.name,
            src_dir_fd=recovery_descriptor,
            dst_dir_fd=recovery_descriptor,
        )
        renamed = True
        _sync_claude_credential_descriptor(recovery_descriptor)
        acknowledged_metadata = os.stat(
            acknowledged_carrier.name,
            dir_fd=recovery_descriptor,
            follow_symlinks=False,
        )
        if (
            _claude_linux_directory_identity(pending_metadata)
            != _claude_linux_directory_identity(acknowledged_metadata)
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the macOS Claude durable-stage carrier changed during commit"
            )
        committed_identity_verified = True
    except BaseException as error:
        primary_error = error
        retained_path = acknowledged_carrier if renamed else pending_carrier
        mark_stage_failure(
            error,
            retained_path,
            payload_verified=pending_verified,
        )
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if recovery_descriptor is not None:
            try:
                os.close(recovery_descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            _raise_or_attach_claude_credential_cleanup(
                primary_error,
                cleanup_errors,
                message=(
                    "cannot close the macOS Claude durable-stage root safely"
                ),
            )
        except BaseException as cleanup_error:
            retained_path = (
                acknowledged_carrier if renamed else pending_carrier
            )
            mark_stage_failure(
                cleanup_error,
                retained_path,
                payload_verified=pending_verified,
            )
            raise

    acknowledged_payload: bytearray | None = None
    post_commit_payload_mismatch = False
    try:
        acknowledged_payload = _read_claude_macos_recovery_credential(
            review,
            acknowledged_carrier,
        )
        if not hmac.compare_digest(acknowledged_payload, credential):
            post_commit_payload_mismatch = True
            raise ClaudeCredentialInspectionInconclusive(
                "the macOS Claude durable-stage credential changed after commit"
            )
    except BaseException as error:
        mark_stage_failure(
            error,
            acknowledged_carrier,
            payload_verified=(
                pending_verified
                and committed_identity_verified
                and not post_commit_payload_mismatch
            ),
        )
        raise
    finally:
        if acknowledged_payload is not None:
            acknowledged_payload[:] = b"\x00" * len(acknowledged_payload)
    return acknowledged_carrier


def _remove_claude_macos_recovery_carrier(
    review: ReviewWorkspace,
    carrier_root: pathlib.Path,
    expected_digest: bytes,
) -> None:
    recovery_root = _claude_macos_recovery_root(review)
    if (
        not carrier_root.is_absolute()
        or carrier_root.parent != recovery_root
        or not carrier_root.name.startswith("claude-carrier-")
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the macOS Claude recovery carrier path is unsafe"
        )
    config_dir = carrier_root / "config"
    credential_path = config_dir / CLAUDE_CREDENTIAL_FILE_NAME
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    recovery_descriptor: int | None = None
    carrier_descriptor: int | None = None
    config_descriptor: int | None = None
    credential_removed = False
    cleanup_scope = credential_path
    payload_verified = False
    primary_error: BaseException | None = None
    try:
        carrier_metadata = carrier_root.lstat()
        config_metadata = config_dir.lstat()
        recovery_descriptor = os.open(recovery_root, flags)
        carrier_descriptor = os.open(
            carrier_root.name,
            flags,
            dir_fd=recovery_descriptor,
        )
        config_descriptor = os.open(
            "config",
            flags,
            dir_fd=carrier_descriptor,
        )
        opened_carrier_metadata = os.fstat(carrier_descriptor)
        opened_config_metadata = os.fstat(config_descriptor)
        current_carrier_metadata = carrier_root.lstat()
        current_config_metadata = config_dir.lstat()
        if (
            len(
                {
                    _claude_linux_directory_identity(carrier_metadata),
                    _claude_linux_directory_identity(opened_carrier_metadata),
                    _claude_linux_directory_identity(current_carrier_metadata),
                }
            )
            != 1
            or len(
                {
                    _claude_linux_directory_identity(config_metadata),
                    _claude_linux_directory_identity(opened_config_metadata),
                    _claude_linux_directory_identity(current_config_metadata),
                }
            )
            != 1
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the durable macOS Claude recovery carrier moved before cleanup"
            )
        recovered_result = _read_claude_credential_file_from_directory(
            config_descriptor
        )
        if recovered_result is None:
            raise ClaudeCredentialInspectionInconclusive(
                "the durable macOS Claude recovery credential is missing"
            )
        recovered, _recovered_identity = recovered_result
        try:
            if not hmac.compare_digest(
                _claude_credential_digest(recovered),
                expected_digest,
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "the macOS Claude recovery credential changed before cleanup"
                )
        finally:
            recovered[:] = b"\x00" * len(recovered)
        current_credential_metadata = os.stat(
            CLAUDE_CREDENTIAL_FILE_NAME,
            dir_fd=config_descriptor,
            follow_symlinks=False,
        )
        if (
            _claude_credential_file_identity(current_credential_metadata)
            != _recovered_identity
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the durable macOS Claude recovery credential moved before cleanup"
            )
        payload_verified = True
        with os.scandir(config_descriptor) as directory_entries:
            entries = tuple(
                entry.name
                for entry in itertools.islice(
                    directory_entries,
                    CLAUDE_MACOS_RECOVERY_ENTRY_LIMIT + 1,
                )
            )
        if entries != (CLAUDE_CREDENTIAL_FILE_NAME,):
            raise ClaudeCredentialInspectionInconclusive(
                "the macOS Claude recovery carrier has unexpected cleanup entries"
            )
        os.unlink(
            CLAUDE_CREDENTIAL_FILE_NAME,
            dir_fd=config_descriptor,
        )
        credential_removed = True
        cleanup_scope = config_dir
        _sync_claude_credential_descriptor(config_descriptor)
        os.rmdir("config", dir_fd=carrier_descriptor)
        cleanup_scope = carrier_root
        _sync_claude_credential_descriptor(carrier_descriptor)
        os.rmdir(carrier_root.name, dir_fd=recovery_descriptor)
        cleanup_scope = recovery_root
        _sync_claude_credential_descriptor(recovery_descriptor)
    except BaseException as error:
        primary_error = error
    cleanup_errors: list[BaseException] = []
    for descriptor in (
        config_descriptor,
        carrier_descriptor,
        recovery_descriptor,
    ):
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except BaseException as error:
            cleanup_errors.append(error)
    if primary_error is None and cleanup_errors:
        primary_error = cleanup_errors.pop(0)
    if primary_error is not None:
        failure = (
            primary_error
            if _is_claude_control_flow_error(primary_error)
            else ClaudeCredentialInspectionInconclusive(
                "cannot remove the durable macOS Claude recovery carrier safely"
            )
        )
        if failure is not primary_error:
            failure.__cause__ = primary_error
        setattr(failure, "_codex_claude_refresh_persistence_failed", True)
        retained_credential_is_current = False
        if payload_verified and not credential_removed:
            try:
                retained_credential_is_current = (
                    _claude_macos_recovery_credential_matches_digest(
                        review,
                        carrier_root,
                        expected_digest,
                    )
                )
            except BaseException as verification_error:
                if _is_claude_control_flow_error(failure):
                    _attach_claude_credential_cleanup_failure(
                        failure,
                        verification_error,
                    )
                elif _is_claude_control_flow_error(verification_error):
                    _attach_claude_credential_cleanup_failure(
                        verification_error,
                        failure,
                    )
                    failure = verification_error
                    setattr(
                        failure,
                        "_codex_claude_refresh_persistence_failed",
                        True,
                    )
                else:
                    raise
        if retained_credential_is_current:
            setattr(
                failure,
                "_codex_claude_retained_credential_carrier",
                str(carrier_root),
            )
            _mark_claude_macos_recovery_update_artifact(
                failure,
                credential_path,
                expected_digest=expected_digest,
            )
        retained_cleanup_scope = (
            _existing_claude_macos_recovery_cleanup_scope(
                cleanup_scope,
                recovery_root,
            )
        )
        if retained_cleanup_scope is not None:
            _mark_claude_macos_recovery_cleanup_artifact(
                failure,
                retained_cleanup_scope,
            )
        _raise_or_attach_claude_credential_cleanup(
            failure,
            cleanup_errors,
            message="cannot close the durable macOS Claude recovery carrier safely",
        )
        raise failure


def _claude_macos_recovery_credential_matches_digest(
    review: ReviewWorkspace,
    carrier_root: pathlib.Path,
    expected_digest: bytes,
) -> bool:
    payload: bytearray | None = None
    try:
        payload = _read_claude_macos_recovery_credential(
            review,
            carrier_root,
        )
        return hmac.compare_digest(
            _claude_credential_digest(payload),
            expected_digest,
        )
    except BaseException as error:
        if _is_claude_control_flow_error(error):
            raise
        return False
    finally:
        if payload is not None:
            payload[:] = b"\x00" * len(payload)


def _existing_claude_macos_recovery_cleanup_scope(
    candidate: pathlib.Path,
    recovery_root: pathlib.Path,
) -> pathlib.Path | None:
    if candidate != recovery_root and recovery_root not in candidate.parents:
        return None
    current = candidate
    while True:
        try:
            current.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        else:
            return current
        if current == recovery_root:
            return None
        current = current.parent


def _claude_macos_recovery_update_artifacts(
    config_descriptor: int,
) -> tuple[str, ...]:
    with os.scandir(config_descriptor) as entries:
        names = [
            entry.name
            for entry in itertools.islice(
                entries,
                CLAUDE_MACOS_RECOVERY_ENTRY_LIMIT + 1,
            )
        ]
    if len(names) > CLAUDE_MACOS_RECOVERY_ENTRY_LIMIT:
        raise ClaudeCredentialInspectionInconclusive(
            "the private macOS Claude recovery carrier has too many entries"
        )
    artifacts: list[str] = []
    for name in sorted(names):
        if not (
            name.startswith(CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX)
            and name.endswith(CLAUDE_MACOS_RECOVERY_UPDATE_SUFFIX)
        ):
            continue
        try:
            metadata = os.stat(
                name,
                dir_fd=config_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ClaudeCredentialInspectionInconclusive(
                "cannot inspect a retained macOS Claude recovery update"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "a retained macOS Claude recovery update is unsafe"
            )
        artifacts.append(name)
    return tuple(artifacts)


def _capture_claude_retained_credential_proof(
    artifact: pathlib.Path,
    *,
    expected_digest: bytes,
) -> _ClaudeRetainedCredentialProof:
    if (
        not artifact.is_absolute()
        or not (
            artifact.name == CLAUDE_CREDENTIAL_FILE_NAME
            or (
                artifact.name.startswith(
                    CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX
                )
                and artifact.name.endswith(
                    CLAUDE_MACOS_RECOVERY_UPDATE_SUFFIX
                )
            )
        )
        or any(part in {".", ".."} for part in artifact.parts)
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the retained macOS Claude credential artifact path is unsafe"
        )
    if (
        not isinstance(expected_digest, bytes)
        or len(expected_digest) != hashlib.sha256().digest_size
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the retained macOS Claude credential source digest is invalid"
        )
    result: tuple[bytearray, tuple[int, ...]] | None = None
    payload: bytearray | None = None
    try:
        with _open_absolute_directory_chain_without_symlinks(
            artifact.parent
        ) as (parent_descriptor, ancestor_identities):
            result = _read_claude_credential_file_from_directory(
                parent_descriptor,
                credential_name=artifact.name,
            )
            if result is None:
                raise ClaudeCredentialInspectionInconclusive(
                    "the retained macOS Claude credential artifact is missing"
                )
            payload, file_identity = result
            final_identity = _claude_credential_file_identity(
                os.stat(
                    artifact.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            )
            if (
                final_identity != file_identity
                or not hmac.compare_digest(
                    _claude_credential_digest(payload),
                    expected_digest,
                )
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "the retained macOS Claude credential does not match its "
                    "authoritative source proof"
                )
            return _ClaudeRetainedCredentialProof(
                artifact=artifact,
                digest=expected_digest,
                file_identity=file_identity,
                ancestor_identities=ancestor_identities,
            )
    finally:
        payload_to_wipe = payload
        if payload_to_wipe is None and result is not None:
            payload_to_wipe = result[0]
        if payload_to_wipe is not None:
            payload_to_wipe[:] = b"\x00" * len(payload_to_wipe)


def _get_claude_retained_credential_proof(
    error: BaseException,
) -> _ClaudeRetainedCredentialProof | None:
    proof = getattr(
        error,
        "_codex_claude_retained_credential_proof",
        None,
    )
    if (
        not isinstance(proof, _ClaudeRetainedCredentialProof)
        or not isinstance(proof.artifact, pathlib.Path)
        or not proof.artifact.is_absolute()
        or any(part in {".", ".."} for part in proof.artifact.parts)
        or not isinstance(proof.digest, bytes)
        or len(proof.digest) != hashlib.sha256().digest_size
    ):
        return None
    return proof


def _clear_claude_retained_credential_proof(error: BaseException) -> None:
    with contextlib.suppress(AttributeError):
        delattr(error, "_codex_claude_retained_credential_proof")
    with contextlib.suppress(AttributeError):
        delattr(error, "_codex_claude_retained_credential_artifact")


def _set_claude_retained_credential_proof(
    error: BaseException,
    proof: _ClaudeRetainedCredentialProof,
) -> None:
    setattr(
        error,
        "_codex_claude_retained_credential_proof",
        proof,
    )
    setattr(
        error,
        "_codex_claude_retained_credential_artifact",
        str(proof.artifact),
    )


def _copy_claude_retained_credential_proof(
    source: BaseException,
    target: BaseException,
) -> bool:
    proof = _get_claude_retained_credential_proof(source)
    if proof is None:
        return False
    _set_claude_retained_credential_proof(target, proof)
    return True


def _mark_claude_macos_recovery_update_artifact(
    error: BaseException,
    artifact: pathlib.Path,
    *,
    expected_digest: bytes,
) -> None:
    try:
        proof = _capture_claude_retained_credential_proof(
            artifact,
            expected_digest=expected_digest,
        )
    except BaseException as proof_error:
        _clear_claude_retained_credential_proof(error)
        if _is_claude_control_flow_error(error):
            _attach_claude_credential_cleanup_failure(error, proof_error)
        elif _is_claude_control_flow_error(proof_error):
            _attach_claude_credential_cleanup_failure(proof_error, error)
            raise proof_error
        else:
            _attach_claude_credential_cleanup_failure(error, proof_error)
    else:
        _set_claude_retained_credential_proof(error, proof)
        add_note = getattr(error, "add_note", None)
        if callable(add_note):
            add_note(
                "A macOS Claude recovery credential update remains at "
                f"{artifact} for operator inspection."
            )


def _mark_claude_macos_recovery_cleanup_artifact(
    error: BaseException,
    artifact: pathlib.Path,
) -> None:
    setattr(
        error,
        "_codex_claude_retained_cleanup_artifact",
        str(artifact),
    )
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(
            "A non-current or incomplete macOS Claude recovery credential "
            f"artifact remains at {artifact} for controlled cleanup."
        )


def _replace_claude_macos_recovery_credential(
    review: ReviewWorkspace,
    carrier_root: pathlib.Path,
    credential: bytearray,
) -> None:
    _validate_claude_local_credential(
        credential,
        source="macOS recovery carrier update",
    )
    credential_digest = _claude_credential_digest(credential)
    recovery_root = _claude_macos_recovery_root(review)
    if (
        not carrier_root.is_absolute()
        or carrier_root.parent != recovery_root
        or not carrier_root.name.startswith("claude-carrier-")
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the macOS Claude recovery carrier path is outside the private root"
        )
    try:
        carrier_root.lstat()
        _create_or_validate_claude_runtime_directory(
            carrier_root,
            private=True,
        )
        config_dir = carrier_root / "config"
        config_dir.lstat()
        _create_or_validate_claude_runtime_directory(
            config_dir,
            private=True,
        )
        carrier_metadata = carrier_root.lstat()
        config_metadata = config_dir.lstat()
    except (OSError, ReviewError) as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot validate the private macOS Claude recovery carrier"
        ) from error

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    temporary_name = (
        f"{CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX}{secrets.token_hex(16)}"
        f"{CLAUDE_MACOS_RECOVERY_UPDATE_SUFFIX}"
    )
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    file_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
        os,
        "O_NOFOLLOW",
        0,
    )
    config_descriptor: int | None = None
    temporary_descriptor: int | None = None
    temporary_created = False
    temporary_complete = False
    temporary_identity: tuple[int, ...] | None = None
    stale_update_artifacts: tuple[str, ...] = ()
    retained_update_artifact: pathlib.Path | None = None
    retained_cleanup_artifact: pathlib.Path | None = None
    main_payload_verified = False
    primary_error: BaseException | None = None
    try:
        config_descriptor = os.open(config_dir, directory_flags)
        opened_config_metadata = os.fstat(config_descriptor)
        prewrite_carrier_metadata = carrier_root.lstat()
        prewrite_config_metadata = config_dir.lstat()
        if (
            _claude_linux_directory_identity(carrier_metadata)
            != _claude_linux_directory_identity(prewrite_carrier_metadata)
            or len(
                {
                    _claude_linux_directory_identity(config_metadata),
                    _claude_linux_directory_identity(opened_config_metadata),
                    _claude_linux_directory_identity(prewrite_config_metadata),
                }
            )
            != 1
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery carrier moved before update"
            )
        stale_update_artifacts = _claude_macos_recovery_update_artifacts(
            config_descriptor
        )
        try:
            current_metadata = os.stat(
                CLAUDE_CREDENTIAL_FILE_NAME,
                dir_fd=config_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            current_metadata = None
        if current_metadata is not None and (
            not stat.S_ISREG(current_metadata.st_mode)
            or current_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(current_metadata.st_mode) != 0o600
            or current_metadata.st_nlink != 1
            or current_metadata.st_size > CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the existing private macOS Claude recovery credential is unsafe"
            )
        temporary_descriptor = os.open(
            temporary_name,
            file_flags,
            0o600,
            dir_fd=config_descriptor,
        )
        temporary_created = True
        os.fchmod(temporary_descriptor, 0o600)
        _write_all_to_descriptor(temporary_descriptor, credential)
        _sync_claude_credential_descriptor(temporary_descriptor)
        temporary_metadata = os.fstat(temporary_descriptor)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
            or temporary_metadata.st_nlink != 1
            or temporary_metadata.st_size != len(credential)
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery update is unsafe"
            )
        temporary_identity = _claude_credential_file_identity(
            temporary_metadata
        )
        temporary_complete = True
        try:
            os.close(temporary_descriptor)
        except BaseException:
            raise
        finally:
            temporary_descriptor = None
        os.replace(
            temporary_name,
            CLAUDE_CREDENTIAL_FILE_NAME,
            src_dir_fd=config_descriptor,
            dst_dir_fd=config_descriptor,
        )
        temporary_created = False
        _sync_claude_credential_descriptor(config_descriptor)
        refreshed_result = _read_claude_credential_file_from_directory(
            config_descriptor
        )
        if refreshed_result is None:
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery update disappeared"
            )
        refreshed, _refreshed_identity = refreshed_result
        try:
            if not hmac.compare_digest(refreshed, credential):
                raise ClaudeCredentialInspectionInconclusive(
                    "the private macOS Claude recovery update changed after commit"
                )
        finally:
            refreshed[:] = b"\x00" * len(refreshed)
        current_carrier_metadata = carrier_root.lstat()
        current_config_metadata = config_dir.lstat()
        if (
            _claude_linux_directory_identity(carrier_metadata)
            != _claude_linux_directory_identity(current_carrier_metadata)
            or len(
                {
                    _claude_linux_directory_identity(config_metadata),
                    _claude_linux_directory_identity(opened_config_metadata),
                    _claude_linux_directory_identity(current_config_metadata),
                }
            )
            != 1
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the private macOS Claude recovery carrier moved during update"
            )
        main_payload_verified = True
        for artifact in stale_update_artifacts:
            try:
                os.unlink(artifact, dir_fd=config_descriptor)
            except BaseException as error:
                _mark_claude_macos_recovery_update_artifact(
                    error,
                    config_dir / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=credential_digest,
                )
                _mark_claude_macos_recovery_cleanup_artifact(
                    error,
                    config_dir / artifact,
                )
                raise
        if stale_update_artifacts:
            _sync_claude_credential_descriptor(config_descriptor)
    except BaseException as error:
        primary_error = error
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            str(carrier_root),
        )
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if temporary_descriptor is not None:
            try:
                os.close(temporary_descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
            temporary_descriptor = None
        if temporary_created and config_descriptor is not None:
            artifact = config_dir / temporary_name
            try:
                visible_temporary_metadata = os.stat(
                    temporary_name,
                    dir_fd=config_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                temporary_created = False
            except BaseException as error:
                retained_cleanup_artifact = artifact
                cleanup_errors.append(error)
            else:
                if temporary_complete and temporary_identity is not None:
                    retained_payload: bytearray | None = None
                    try:
                        if (
                            _claude_credential_file_identity(
                                visible_temporary_metadata
                            )
                            != temporary_identity
                        ):
                            raise ClaudeCredentialInspectionInconclusive(
                                "the private macOS Claude recovery update "
                                "identity changed before failure readback"
                            )
                        retained_result = (
                            _read_claude_credential_file_from_directory(
                                config_descriptor,
                                credential_name=temporary_name,
                                expected_identity=temporary_identity,
                            )
                        )
                        if retained_result is None:
                            temporary_created = False
                        else:
                            retained_payload, retained_identity = (
                                retained_result
                            )
                            try:
                                final_temporary_metadata = os.stat(
                                    temporary_name,
                                    dir_fd=config_descriptor,
                                    follow_symlinks=False,
                                )
                            except FileNotFoundError:
                                temporary_created = False
                            else:
                                if (
                                    retained_identity != temporary_identity
                                    or _claude_credential_file_identity(
                                        final_temporary_metadata
                                    )
                                    != temporary_identity
                                    or not hmac.compare_digest(
                                        retained_payload,
                                        credential,
                                    )
                                ):
                                    raise ClaudeCredentialInspectionInconclusive(
                                        "the private macOS Claude recovery "
                                        "update failed exact failure readback"
                                    )
                    except BaseException as error:
                        retained_cleanup_artifact = artifact
                        cleanup_errors.append(error)
                    else:
                        if retained_payload is not None and temporary_created:
                            retained_update_artifact = artifact
                    finally:
                        if retained_payload is not None:
                            retained_payload[:] = (
                                b"\x00" * len(retained_payload)
                            )
                else:
                    try:
                        os.unlink(temporary_name, dir_fd=config_descriptor)
                    except BaseException as error:
                        retained_cleanup_artifact = artifact
                        cleanup_errors.append(error)
                    else:
                        temporary_created = False
                        try:
                            _sync_claude_credential_descriptor(
                                config_descriptor
                            )
                        except BaseException as error:
                            cleanup_errors.append(error)
        current_credential_artifact = (
            config_dir / CLAUDE_CREDENTIAL_FILE_NAME
            if main_payload_verified
            else retained_update_artifact
        )
        if current_credential_artifact is not None and primary_error is not None:
            _mark_claude_macos_recovery_update_artifact(
                primary_error,
                current_credential_artifact,
                expected_digest=credential_digest,
            )
        if retained_cleanup_artifact is not None and primary_error is not None:
            _mark_claude_macos_recovery_cleanup_artifact(
                primary_error,
                retained_cleanup_artifact,
            )
        if config_descriptor is not None:
            try:
                os.close(config_descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
            config_descriptor = None
        try:
            _raise_or_attach_claude_credential_cleanup(
                primary_error,
                cleanup_errors,
                message=(
                    "cannot close the private macOS Claude recovery update safely"
                ),
            )
        except BaseException as cleanup_error:
            setattr(
                cleanup_error,
                "_codex_claude_retained_credential_carrier",
                str(carrier_root),
            )
            setattr(
                cleanup_error,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            if current_credential_artifact is not None:
                _mark_claude_macos_recovery_update_artifact(
                    cleanup_error,
                    current_credential_artifact,
                    expected_digest=credential_digest,
                )
            if retained_cleanup_artifact is not None:
                _mark_claude_macos_recovery_cleanup_artifact(
                    cleanup_error,
                    retained_cleanup_artifact,
                )
            raise


def _retained_claude_macos_credential_error(
    carrier_root: pathlib.Path,
    error: BaseException,
    *,
    expected_digest: bytes,
    artifact: pathlib.Path | None = None,
) -> ClaudeCredentialInspectionInconclusive:
    retained = ClaudeCredentialInspectionInconclusive(
        "Claude produced a structurally valid refreshed OAuth credential, but "
        "guarded host writeback was not proven; the private recovery carrier was "
        f"retained at {carrier_root}. Resume only after recovering or removing "
        "that carrier."
    )
    setattr(
        retained,
        "_codex_claude_retained_credential_carrier",
        str(carrier_root),
    )
    _mark_claude_macos_recovery_update_artifact(
        retained,
        artifact
        if artifact is not None
        else carrier_root / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
        expected_digest=expected_digest,
    )
    setattr(retained, "_codex_claude_refresh_persistence_failed", True)
    retained.__cause__ = error
    return retained


def _failed_claude_macos_recovery_error(
    persistence_error: BaseException,
    recovery_error: BaseException,
) -> ClaudeCredentialInspectionInconclusive:
    retained_carrier = getattr(
        recovery_error,
        "_codex_claude_retained_credential_carrier",
        None,
    )
    if not isinstance(retained_carrier, str):
        retained_carrier = getattr(
            persistence_error,
            "_codex_claude_retained_credential_carrier",
            None,
        )
    retained_proof_source: BaseException | None = None
    retained_artifact: str | None = None
    for proof_source in (recovery_error, persistence_error):
        proof = _get_claude_retained_credential_proof(proof_source)
        if proof is not None:
            retained_proof_source = proof_source
            retained_artifact = str(proof.artifact)
            retained_carrier = str(proof.artifact.parent.parent)
            break
    retained_cleanup_artifact = getattr(
        recovery_error,
        "_codex_claude_retained_cleanup_artifact",
        None,
    )
    if not isinstance(retained_cleanup_artifact, str):
        retained_cleanup_artifact = getattr(
            persistence_error,
            "_codex_claude_retained_cleanup_artifact",
            None,
        )
    message = (
        "Claude produced a structurally valid refreshed OAuth credential, but "
        "guarded host writeback was not proven and private recovery handling was "
        "incomplete; review is paused"
    )
    if isinstance(retained_carrier, str):
        message = (
            f"{message}; the private recovery carrier was retained at "
            f"{retained_carrier} for operator inspection"
        )
    if isinstance(retained_artifact, str):
        message = (
            f"{message}; the current recovery credential is at "
            f"{retained_artifact}"
        )
    if isinstance(retained_cleanup_artifact, str):
        message = (
            f"{message}; a stale credential artifact awaiting controlled cleanup "
            f"remains at {retained_cleanup_artifact}"
        )
    failed = ClaudeCredentialInspectionInconclusive(message)
    setattr(failed, "_codex_claude_refresh_persistence_failed", True)
    if isinstance(retained_carrier, str):
        setattr(
            failed,
            "_codex_claude_retained_credential_carrier",
            retained_carrier,
        )
    if retained_proof_source is not None:
        _copy_claude_retained_credential_proof(
            retained_proof_source,
            failed,
        )
    if isinstance(retained_cleanup_artifact, str):
        setattr(
            failed,
            "_codex_claude_retained_cleanup_artifact",
            retained_cleanup_artifact,
        )
    failed.__cause__ = recovery_error
    _attach_claude_credential_cleanup_failure(failed, persistence_error)
    return failed


def _persist_claude_macos_refreshed_credential_impl(
    review: ReviewWorkspace,
    selected: _ClaudeLocalCredential,
    refreshed: bytearray,
    expected_credential: bytearray,
    carrier_snapshot: _ClaudeMacOSCarrierSnapshot,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
) -> _ClaudeMacOSCarrierSnapshot | None:
    keychain_digest = carrier_snapshot.keychain_digest
    file_digest = carrier_snapshot.file_digest
    synchronize_both = _claude_macos_carriers_share_refresh_token(carrier_snapshot)
    write_keychain = selected.source == "macos-keychain" or synchronize_both
    write_file = selected.source == "pwd-home-credential-file" or synchronize_both
    file_snapshot = carrier_snapshot.file_snapshot
    if write_file and file_snapshot is None:
        return None
    selected_digest = (
        keychain_digest
        if selected.source == "macos-keychain"
        else file_digest
    )
    if (
        selected_digest is None
        or not hmac.compare_digest(
            _claude_credential_digest(expected_credential),
            selected_digest,
        )
    ):
        return None
    try:
        _validate_claude_local_credential(
            refreshed,
            source="broker refresh",
        )
    except ClaudeCredentialUnsafe:
        return None
    # Complete all pure validation before the first carrier is mutated. In
    # particular, a same-login file selection may also require a Keychain write.
    if write_keychain and not _claude_keychain_credential_has_refresh_margin(
        refreshed
    ):
        return None
    refreshed_digest = _claude_credential_digest(refreshed)

    with _claude_macos_carrier_coordination(
        refresh_lock_protocol,
    ) as refresh_lock:
        current_keychain: bytearray | None = None
        current_file: bytearray | None = None
        try:
            current_keychain = _read_claude_keychain_credential(review)
            current_file_result = _read_claude_macos_file_credential()
            current_file_snapshot: _ClaudeCredentialFileSnapshot | None = None
            if current_file_result is not None:
                current_file, current_file_snapshot = current_file_result
            if not (
                _claude_optional_credential_digest_matches(
                    current_keychain,
                    keychain_digest,
                )
                and _claude_optional_credential_digest_matches(
                    current_file,
                    file_digest,
                )
                and current_file_snapshot == file_snapshot
            ):
                return None
            # Write the file carrier first when one logical login is mirrored in
            # both stores; current Claude releases commonly treat it as active.
            if write_file:
                assert file_snapshot is not None
                assert current_file is not None
                if not _write_claude_file_credential(
                    review,
                    refreshed,
                    current_file,
                    file_snapshot,
                    carrier_snapshot,
                    refresh_lock_protocol,
                    coordinated_refresh_lock=refresh_lock,
                    carriers_already_matched=True,
                ):
                    return None
            if write_keychain:
                assert current_keychain is not None
                keychain_write_error: Exception | None = None
                for attempt_index in range(
                    CLAUDE_MACOS_DUAL_CARRIER_KEYCHAIN_ATTEMPTS
                ):
                    keychain_write_error = None
                    try:
                        keychain_written = _write_claude_keychain_credential(
                            review,
                            refreshed,
                            current_keychain,
                            carrier_snapshot,
                            refresh_lock_protocol,
                            coordinated_refresh_lock=refresh_lock,
                            carriers_already_matched=True,
                        )
                    except Exception as error:
                        if _is_claude_control_flow_error(error):
                            raise
                        keychain_write_error = error
                        keychain_written = False
                    if keychain_written:
                        break
                    refresh_lock.assert_held()
                    readback = _read_claude_macos_carrier_snapshot(review)
                    refresh_lock.assert_held()
                    keychain_is_refreshed = hmac.compare_digest(
                        readback.keychain_digest or b"",
                        refreshed_digest,
                    ) and readback.keychain_digest is not None
                    expected_file_digest = (
                        refreshed_digest if write_file else file_digest
                    )
                    file_is_expected = hmac.compare_digest(
                        readback.file_digest or b"",
                        expected_file_digest or b"",
                    ) and (readback.file_digest is None) == (
                        expected_file_digest is None
                    )
                    if keychain_is_refreshed and file_is_expected:
                        return readback
                    keychain_is_original = hmac.compare_digest(
                        readback.keychain_digest or b"",
                        keychain_digest or b"",
                    ) and (readback.keychain_digest is None) == (
                        keychain_digest is None
                    )
                    if not (keychain_is_original and file_is_expected):
                        raise ClaudeCredentialInspectionInconclusive(
                            "Claude credential carriers changed unexpectedly while "
                            "a refreshed Keychain credential was being reconciled"
                        ) from keychain_write_error
                    if (
                        attempt_index + 1
                        < CLAUDE_MACOS_DUAL_CARRIER_KEYCHAIN_ATTEMPTS
                    ):
                        continue
                    if write_file:
                        message = (
                            "Claude refreshed the pwd-home credential file, but the "
                            "matching Keychain carrier could not be synchronized "
                            "after a bounded retry; the refreshed file carrier was "
                            "preserved and review is paused to avoid discarding the "
                            "rotated login"
                        )
                    else:
                        message = (
                            "Claude refreshed its Keychain credential, but guarded "
                            "persistence could not be verified after a bounded retry; "
                            "review is paused to avoid losing the rotated login"
                        )
                    raise ClaudeCredentialInspectionInconclusive(
                        message
                    ) from keychain_write_error
            refresh_lock.assert_held()
            observed = _read_claude_macos_carrier_snapshot(review)
            expected_keychain_digest = (
                refreshed_digest if write_keychain else keychain_digest
            )
            expected_file_digest = refreshed_digest if write_file else file_digest
            if not (
                hmac.compare_digest(
                    observed.keychain_digest or b"",
                    expected_keychain_digest or b"",
                )
                and (observed.keychain_digest is None)
                == (expected_keychain_digest is None)
                and hmac.compare_digest(
                    observed.file_digest or b"",
                    expected_file_digest or b"",
                )
                and (observed.file_digest is None)
                == (expected_file_digest is None)
            ):
                return None
            return observed
        finally:
            if current_keychain is not None:
                current_keychain[:] = b"\x00" * len(current_keychain)
            if current_file is not None:
                current_file[:] = b"\x00" * len(current_file)


def _claude_macos_carrier_snapshot_is_current(
    review: ReviewWorkspace,
    carrier_snapshot: _ClaudeMacOSCarrierSnapshot,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
) -> bool:
    try:
        with _claude_macos_carrier_coordination(
            refresh_lock_protocol,
        ) as refresh_lock:
            matches = _claude_macos_carriers_match(review, carrier_snapshot)
            refresh_lock.assert_held()
            return matches
    except ClaudeCredentialUnsafe as error:
        raise ClaudeCredentialInspectionInconclusive(
            "Claude credential carriers became unsafe while the isolated runtime "
            "was active"
        ) from error


def _recv_exact(sock: socket.socket, length: int) -> bytearray | None:
    result = bytearray(length)
    view = memoryview(result)
    offset = 0
    try:
        while offset < length:
            received = sock.recv_into(view[offset:], length - offset)
            if received <= 0:
                result[:] = b"\x00" * len(result)
                return None
            offset += received
    except OSError:
        result[:] = b"\x00" * len(result)
        return None
    finally:
        view.release()
    return result


def _add_claude_persistence_note(
    error: BaseException,
    persistence_error: BaseException,
) -> None:
    setattr(error, "_codex_claude_refresh_persistence_failed", True)
    retained_carrier = getattr(
        persistence_error,
        "_codex_claude_retained_credential_carrier",
        None,
    )
    if isinstance(retained_carrier, str):
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            retained_carrier,
        )
    _copy_claude_retained_credential_proof(
        persistence_error,
        error,
    )
    retained_cleanup_artifact = getattr(
        persistence_error,
        "_codex_claude_retained_cleanup_artifact",
        None,
    )
    if isinstance(retained_cleanup_artifact, str):
        setattr(
            error,
            "_codex_claude_retained_cleanup_artifact",
            retained_cleanup_artifact,
        )
    note = (
        f"{CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC} "
        f"({type(persistence_error).__name__})"
    )
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(note)
        return
    diagnostic = ClaudeCredentialPersistenceDiagnostic(note)
    if error.__cause__ is not None:
        diagnostic.__cause__ = error.__cause__
    elif error.__context__ is not None:
        diagnostic.__context__ = error.__context__
    error.__cause__ = diagnostic


def _attach_claude_persistence_failure_preserving_control_flow(
    primary: BaseException,
    secondary: BaseException,
) -> BaseException:
    if _is_claude_control_flow_error(primary):
        _attach_claude_credential_cleanup_failure(primary, secondary)
        return primary
    if _is_claude_control_flow_error(secondary):
        _add_claude_persistence_note(secondary, primary)
        return secondary
    _attach_claude_credential_cleanup_failure(primary, secondary)
    return primary


def _claude_artifact_is_lexically_contained(
    candidate: pathlib.Path,
    container: pathlib.Path,
) -> bool:
    if (
        not candidate.is_absolute()
        or not container.is_absolute()
        or any(part in {".", ".."} for part in candidate.parts)
        or any(part in {".", ".."} for part in container.parts)
    ):
        return False
    try:
        candidate.relative_to(container)
    except ValueError:
        return False
    return True


def _claude_nofollow_artifact_snapshot(
    candidate: pathlib.Path,
) -> _ClaudeNoFollowArtifactSnapshot:
    with _open_absolute_directory_chain_without_symlinks(
        candidate.parent
    ) as (parent_descriptor, ancestor_identities):
        leaf_metadata = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        snapshot = _ClaudeNoFollowArtifactSnapshot(
            ancestor_identities=ancestor_identities,
            leaf_identity=_claude_cleanup_artifact_identity(leaf_metadata),
            leaf_complete_identity=_claude_credential_file_identity(
                leaf_metadata
            ),
            leaf_mode=leaf_metadata.st_mode,
            leaf_uid=leaf_metadata.st_uid,
        )
        final_leaf_metadata = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _claude_cleanup_artifact_identity(final_leaf_metadata)
            != snapshot.leaf_identity
            or _claude_credential_file_identity(final_leaf_metadata)
            != snapshot.leaf_complete_identity
        ):
            raise ClaudeCredentialInspectionInconclusive(
                "the retained Claude artifact changed during inspection"
            )
        return snapshot


def _claude_retained_credential_artifact_matches_proof(
    candidate: pathlib.Path,
    proof: _ClaudeRetainedCredentialProof,
) -> bool:
    if candidate != proof.artifact:
        return False
    result: tuple[bytearray, tuple[int, ...]] | None = None
    payload: bytearray | None = None
    try:
        with _open_absolute_directory_chain_without_symlinks(
            candidate.parent
        ) as (parent_descriptor, ancestor_identities):
            if ancestor_identities != proof.ancestor_identities:
                return False
            result = _read_claude_credential_file_from_directory(
                parent_descriptor,
                credential_name=candidate.name,
                expected_identity=proof.file_identity,
            )
            if result is None:
                return False
            payload, file_identity = result
            final_identity = _claude_credential_file_identity(
                os.stat(
                    candidate.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            )
            if (
                file_identity != proof.file_identity
                or final_identity != proof.file_identity
                or not hmac.compare_digest(
                    _claude_credential_digest(payload),
                    proof.digest,
                )
            ):
                return False
    finally:
        payload_to_wipe = payload
        if payload_to_wipe is None and result is not None:
            payload_to_wipe = result[0]
        if payload_to_wipe is not None:
            payload_to_wipe[:] = b"\x00" * len(payload_to_wipe)
    final_snapshot = _claude_nofollow_artifact_snapshot(candidate)
    return (
        final_snapshot.ancestor_identities == proof.ancestor_identities
        and final_snapshot.leaf_complete_identity == proof.file_identity
    )


def _validated_claude_retained_credential_carrier(
    review: ReviewWorkspace,
    error: BaseException,
) -> str | None:
    retained_candidate = getattr(
        error,
        "_codex_claude_retained_credential_carrier",
        None,
    )
    if not isinstance(retained_candidate, str):
        return None
    candidate_path = pathlib.Path(retained_candidate)
    if not _claude_artifact_is_lexically_contained(
        candidate_path,
        review.container_dir,
    ):
        return None
    try:
        initial = _claude_nofollow_artifact_snapshot(candidate_path)
        final = _claude_nofollow_artifact_snapshot(candidate_path)
    except ForwardedSignal:
        raise
    except (OSError, RuntimeError, ValueError, ReviewError):
        return None
    if (
        initial.ancestor_identities != final.ancestor_identities
        or initial.leaf_identity != final.leaf_identity
        or not stat.S_ISDIR(final.leaf_mode)
        or final.leaf_uid != os.geteuid()
        or stat.S_IMODE(final.leaf_mode) != 0o700
    ):
        return None
    return str(candidate_path)


def _validated_claude_retained_credential_artifact(
    review: ReviewWorkspace,
    error: BaseException,
) -> str | None:
    proof = _get_claude_retained_credential_proof(error)
    if proof is None:
        return None
    candidate_path = proof.artifact
    if not _claude_artifact_is_lexically_contained(
        candidate_path,
        review.container_dir,
    ):
        return None
    try:
        if not _claude_retained_credential_artifact_matches_proof(
            candidate_path,
            proof,
        ):
            return None
    except ForwardedSignal:
        raise
    except (OSError, RuntimeError, ValueError, ReviewError):
        return None
    return str(candidate_path)


def _validated_claude_retained_cleanup_artifact(
    review: ReviewWorkspace,
    error: BaseException,
) -> str | None:
    retained_candidate = getattr(
        error,
        "_codex_claude_retained_cleanup_artifact",
        None,
    )
    if not isinstance(retained_candidate, str):
        return None
    candidate_path = pathlib.Path(retained_candidate)
    if not _claude_artifact_is_lexically_contained(
        candidate_path,
        review.container_dir,
    ):
        return None
    try:
        initial = _claude_nofollow_artifact_snapshot(candidate_path)
        final = _claude_nofollow_artifact_snapshot(candidate_path)
    except ForwardedSignal:
        raise
    except (OSError, RuntimeError, ValueError, ReviewError):
        return None
    if (
        initial.ancestor_identities != final.ancestor_identities
        or initial.leaf_identity != final.leaf_identity
        or not (
            stat.S_ISDIR(final.leaf_mode)
            or stat.S_ISREG(final.leaf_mode)
        )
    ):
        return None
    return str(candidate_path)


def _claude_cleanup_artifact_identity(
    metadata: os.stat_result,
) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _record_claude_secondary_persistence_failure(
    review: ReviewWorkspace,
    error: BaseException,
) -> str | None:
    if not getattr(error, "_codex_claude_refresh_persistence_failed", False):
        return None
    retained_carrier = _validated_claude_retained_credential_carrier(
        review,
        error,
    )
    retained_artifact = _validated_claude_retained_credential_artifact(
        review,
        error,
    )
    retained_cleanup_artifact = _validated_claude_retained_cleanup_artifact(
        review,
        error,
    )
    authentication_report: dict[str, str] = {
        "refresh_persistence": "failed-after-attempt",
        "secondary_diagnostic": CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC,
    }
    if retained_carrier is not None:
        authentication_report["recovery_carrier"] = retained_carrier
    if retained_artifact is not None:
        authentication_report["recovery_artifact"] = retained_artifact
    if retained_cleanup_artifact is not None:
        authentication_report["recovery_cleanup_artifact"] = (
            retained_cleanup_artifact
        )
    diagnostic = CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC
    if retained_carrier is not None:
        diagnostic = (
            f"{diagnostic} Private recovery carrier retained at "
            f"{retained_carrier}."
        )
    if retained_artifact is not None:
        diagnostic = (
            f"{diagnostic} Recovery credential artifact retained at "
            f"{retained_artifact}."
        )
    if retained_cleanup_artifact is not None:
        diagnostic = (
            f"{diagnostic} Stale recovery credential artifact awaiting controlled "
            f"cleanup at {retained_cleanup_artifact}."
        )
    try:
        _update_claude_runtime_report(
            review,
            {
                "authentication": authentication_report
            },
        )
    except BaseException as report_error:
        if _is_claude_control_flow_error(report_error):
            setattr(
                report_error,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            if retained_carrier is not None:
                setattr(
                    report_error,
                    "_codex_claude_retained_credential_carrier",
                    retained_carrier,
                )
            if retained_artifact is not None:
                _copy_claude_retained_credential_proof(
                    error,
                    report_error,
                )
            if retained_cleanup_artifact is not None:
                setattr(
                    report_error,
                    "_codex_claude_retained_cleanup_artifact",
                    retained_cleanup_artifact,
                )
            _attach_claude_persistence_signal_detail(
                report_error,
                diagnostic,
            )
            raise
    _attach_claude_persistence_signal_detail(error, diagnostic)
    return diagnostic


def _attach_claude_persistence_signal_detail(
    error: BaseException,
    diagnostic: str | None,
) -> None:
    if not isinstance(error, ForwardedSignal) or diagnostic is None:
        return
    if error.detail is None:
        error.detail = diagnostic
    elif diagnostic not in error.detail:
        error.detail = f"{error.detail}; {diagnostic}"


def _propagate_claude_persistence_state(
    review: ReviewWorkspace,
    source: BaseException,
    target: BaseException,
) -> None:
    if not getattr(source, "_codex_claude_refresh_persistence_failed", False):
        return
    setattr(target, "_codex_claude_refresh_persistence_failed", True)
    retained_carrier = _validated_claude_retained_credential_carrier(
        review,
        source,
    )
    retained_artifact = _validated_claude_retained_credential_artifact(
        review,
        source,
    )
    retained_cleanup_artifact = _validated_claude_retained_cleanup_artifact(
        review,
        source,
    )
    diagnostic = CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC
    if retained_carrier is not None:
        setattr(
            target,
            "_codex_claude_retained_credential_carrier",
            retained_carrier,
        )
        diagnostic = (
            f"{diagnostic} Private recovery carrier retained at "
            f"{retained_carrier}."
        )
    if retained_artifact is not None:
        _copy_claude_retained_credential_proof(source, target)
        diagnostic = (
            f"{diagnostic} Recovery credential artifact retained at "
            f"{retained_artifact}."
        )
    if retained_cleanup_artifact is not None:
        setattr(
            target,
            "_codex_claude_retained_cleanup_artifact",
            retained_cleanup_artifact,
        )
        diagnostic = (
            f"{diagnostic} Stale recovery credential artifact awaiting controlled "
            f"cleanup at {retained_cleanup_artifact}."
        )
    _attach_claude_persistence_signal_detail(target, diagnostic)


def _claude_macos_runtime_io_inconclusive(
    review: ReviewWorkspace,
    error: OSError,
) -> ClaudeCredentialInspectionInconclusive:
    failure = ClaudeCredentialInspectionInconclusive(
        "Claude macOS credential runtime I/O was inconclusive"
    )
    _propagate_claude_persistence_state(review, error, failure)
    failure.__cause__ = error
    return failure


def _update_claude_runtime_report_preserving_persistence(
    review: ReviewWorkspace,
    report: dict[str, object],
    persistence_error: BaseException,
) -> None:
    try:
        _update_claude_runtime_report(review, report)
    except BaseException as report_error:
        _propagate_claude_persistence_state(
            review,
            persistence_error,
            report_error,
        )
        if _is_claude_control_flow_error(report_error):
            raise
        if not getattr(
            persistence_error,
            "_codex_claude_refresh_persistence_failed",
            False,
        ):
            raise
        retained_carrier = _validated_claude_retained_credential_carrier(
            review,
            persistence_error,
        )
        retained_artifact = _validated_claude_retained_credential_artifact(
            review,
            persistence_error,
        )
        retained_cleanup_artifact = _validated_claude_retained_cleanup_artifact(
            review,
            persistence_error,
        )
        message = "cannot update the Claude runtime report after refresh persistence failed"
        if retained_carrier is not None:
            message = (
                f"{message}; private recovery carrier retained at "
                f"{retained_carrier}"
            )
        if retained_artifact is not None:
            message = (
                f"{message}; recovery credential artifact retained at "
                f"{retained_artifact}"
            )
        if retained_cleanup_artifact is not None:
            message = (
                f"{message}; stale recovery credential artifact awaiting "
                f"controlled cleanup at {retained_cleanup_artifact}"
            )
        failure = ClaudeCredentialInspectionInconclusive(message)
        _propagate_claude_persistence_state(
            review,
            persistence_error,
            failure,
        )
        raise failure from report_error


class _ClaudeKeychainCredentialHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _ClaudeKeychainCredentialServer):
            return
        self.request.settimeout(2.0)
        raw_capability = _recv_exact(
            self.request,
            CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES,
        )
        if raw_capability is None:
            return
        authorized = hmac.compare_digest(raw_capability, server.capability)
        raw_capability[:] = b"\x00" * len(raw_capability)
        if not authorized:
            return
        operation = _recv_exact(self.request, 1)
        if operation == b"R":
            credential = server.take_initial_credential()
            try:
                self.request.sendall(struct.pack("!I", len(credential)))
                if credential:
                    self.request.sendall(credential)
            except OSError:
                return
            finally:
                credential[:] = b"\x00" * len(credential)
            return
        if operation != b"W":
            return
        raw_length = _recv_exact(self.request, 4)
        if raw_length is None:
            return
        length = struct.unpack("!I", raw_length)[0]
        if not 1 <= length <= CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES:
            return
        raw_credential = _recv_exact(self.request, length)
        if raw_credential is None:
            return
        updated_credential = raw_credential
        pending_generation: int | None = None
        try:
            pending_generation = server.stage_pending_update(
                updated_credential
            )
            if pending_generation is None:
                if server.pending_updates_closed():
                    self.request.sendall(b"\x01")
                return
            with server.update_lock:
                with server.credential_lock:
                    read_completed = server.consumed
                if (
                    not server.pending_update_is_current(
                        pending_generation
                    )
                    or not read_completed
                    or server.update_callback is None
                ):
                    success = False
                else:
                    success = server.update_callback(
                        updated_credential,
                        lambda publish: server.commit_pending_update(
                            pending_generation,
                            publish,
                        ),
                        lambda: server.claim_terminal_pending_update(
                            pending_generation
                        ),
                    )
                    if success:
                        server.updated = True
            self.request.sendall(b"\x00" if success else b"\x01")
        except OSError:
            return
        finally:
            if pending_generation is not None:
                server.clear_pending_update(pending_generation)
            updated_credential[:] = b"\x00" * len(updated_credential)


class _ClaudeKeychainCredentialServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        credential: bytearray | None,
        capability: bytes,
        update_callback: Callable[
            [
                bytearray,
                Callable[[Callable[[], bool]], bool],
                Callable[[], bool],
            ],
            bool,
        ]
        | None,
    ) -> None:
        super().__init__(("127.0.0.1", 0), _ClaudeKeychainCredentialHandler)
        self.credential = (
            bytearray(credential) if credential is not None else None
        )
        self.capability = capability
        self.credential_lock = threading.Lock()
        self.consumed = False
        self.update_callback = update_callback
        self.update_lock = threading.Lock()
        self.updated = False
        self._handler_condition = threading.Condition()
        self._handler_threads: set[threading.Thread] = set()
        self._handler_sockets: dict[threading.Thread, socket.socket] = {}
        self._handler_errors: list[BaseException] = []
        self._closing = False
        self._abandoned = threading.Event()
        self._pending_update_lock = threading.Lock()
        self._pending_update: tuple[int, bytearray] | None = None
        self._pending_generation = 0
        self._updates_closed = False
        self._serve_condition = threading.Condition()
        self._serving = False
        self._serve_stopped = False
        self._serve_error: BaseException | None = None

    def process_request(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        thread = threading.Thread(
            target=self.process_request_thread,
            args=(request, client_address),
            daemon=True,
            name="claude-review-keychain-handler",
        )
        with self._handler_condition:
            if self._closing:
                should_start = False
            else:
                self._handler_threads.add(thread)
                self._handler_sockets[thread] = request
                should_start = True
        if not should_start:
            self.shutdown_request(request)
            return
        try:
            thread.start()
        except BaseException:
            with self._handler_condition:
                self._handler_threads.discard(thread)
                self._handler_sockets.pop(thread, None)
                self._handler_condition.notify_all()
            self.shutdown_request(request)
            raise

    def process_request_thread(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        except BaseException as error:
            with self._handler_condition:
                self._handler_errors.append(error)
            raise
        finally:
            current = threading.current_thread()
            with self._handler_condition:
                self._handler_threads.discard(current)
                self._handler_sockets.pop(current, None)
                self._handler_condition.notify_all()

    def handle_error(
        self,
        _request: socket.socket,
        _client_address: tuple[str, int],
    ) -> None:
        error = sys.exc_info()[1]
        if error is None:
            return
        with self._handler_condition:
            self._handler_errors.append(error)

    def handler_errors(self) -> tuple[BaseException, ...]:
        with self._handler_condition:
            return tuple(self._handler_errors)

    def service_actions(self) -> None:
        with self._serve_condition:
            if not self._serving:
                self._serving = True
                self._serve_condition.notify_all()

    def record_serve_stopped(self, error: BaseException | None) -> None:
        with self._serve_condition:
            self._serve_stopped = True
            self._serve_error = error
            self._serve_condition.notify_all()

    def wait_until_serving(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._serve_condition:
            while not self._serving and not self._serve_stopped:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._serve_condition.wait(timeout=remaining)
            return self._serving and not self._serve_stopped

    def serve_error(self) -> BaseException | None:
        with self._serve_condition:
            return self._serve_error

    def wait_for_handlers(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._handler_condition:
            while self._handler_threads:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._handler_condition.wait(timeout=remaining)
            return not self._handler_threads

    def begin_closing(self) -> tuple[socket.socket, ...]:
        with self._handler_condition:
            self._closing = True
            return tuple(self._handler_sockets.values())

    def take_initial_credential(self) -> bytearray:
        with self.credential_lock:
            if (
                self._abandoned.is_set()
                or self.consumed
                or self.credential is None
            ):
                return bytearray()
            self.consumed = True
            credential = self.credential
            self.credential = None
            return credential

    def stage_pending_update(self, credential: bytearray) -> int | None:
        if self._abandoned.is_set():
            return None
        pending = bytearray(credential)
        previous: bytearray | None = None
        with self._pending_update_lock:
            if self._abandoned.is_set() or self._updates_closed:
                pending[:] = b"\x00" * len(pending)
                return None
            if self._pending_update is not None:
                _previous_generation, previous = self._pending_update
            self._pending_generation += 1
            generation = self._pending_generation
            self._pending_update = (generation, pending)
        if previous is not None:
            previous[:] = b"\x00" * len(previous)
        return generation

    def pending_updates_closed(self) -> bool:
        with self._pending_update_lock:
            return self._updates_closed

    def claim_terminal_pending_update(self, generation: int) -> bool:
        with self._pending_update_lock:
            if (
                self._abandoned.is_set()
                or self._updates_closed
                or self._pending_update is None
                or self._pending_update[0] != generation
            ):
                return False
            self._updates_closed = True
            return True

    def clear_pending_update(self, generation: int) -> None:
        pending: bytearray | None = None
        with self._pending_update_lock:
            if (
                self._pending_update is not None
                and self._pending_update[0] == generation
            ):
                _pending_generation, pending = self._pending_update
                self._pending_update = None
        if pending is not None:
            pending[:] = b"\x00" * len(pending)

    def pending_update_is_current(self, generation: int) -> bool:
        with self._pending_update_lock:
            return (
                not self._abandoned.is_set()
                and self._pending_update is not None
                and self._pending_update[0] == generation
            )

    def commit_pending_update(
        self,
        generation: int,
        publish: Callable[[], bool],
    ) -> bool:
        with self._pending_update_lock:
            if (
                self._abandoned.is_set()
                or self._pending_update is None
                or self._pending_update[0] != generation
            ):
                return False
            return publish()

    def close_pending_update_publication(self, timeout: float) -> bool:
        self._abandoned.set()
        acquired = self._pending_update_lock.acquire(
            timeout=max(0.0, timeout)
        )
        if not acquired:
            return False
        try:
            return True
        finally:
            self._pending_update_lock.release()

    def try_abandon_and_detach_pending_update(
        self,
        timeout: float | None,
    ) -> tuple[bool, bytearray | None]:
        self._abandoned.set()
        deadline = (
            None
            if timeout is None
            else time.monotonic() + max(0.0, timeout)
        )

        def acquire(lock: object) -> bool:
            acquire_lock = getattr(lock, "acquire")
            if deadline is None:
                acquire_lock()
                return True
            return bool(
                acquire_lock(timeout=max(0.0, deadline - time.monotonic()))
            )

        initial_credential: bytearray | None = None
        if not acquire(self.credential_lock):
            return False, None
        try:
            initial_credential = self.credential
            self.credential = None
        finally:
            self.credential_lock.release()
        if initial_credential is not None:
            initial_credential[:] = b"\x00" * len(initial_credential)
        if not acquire(self._pending_update_lock):
            return False, None
        try:
            if self._pending_update is None:
                return True, None
            _generation, pending = self._pending_update
            self._pending_update = None
            return True, pending
        finally:
            self._pending_update_lock.release()

    def abandon_and_detach_pending_update(self) -> bytearray | None:
        detached, pending = self.try_abandon_and_detach_pending_update(None)
        if not detached:
            raise AssertionError("unbounded pending-update detach did not finish")
        return pending

    def scrub_initial_credential(self) -> None:
        credential: bytearray | None = None
        with self.credential_lock:
            credential = self.credential
            self.credential = None
        if credential is not None:
            credential[:] = b"\x00" * len(credential)


@dataclass(frozen=True)
class _ClaudeKeychainServerShutdown:
    quiescent: bool
    pending_update: bytearray | None
    errors: tuple[BaseException, ...]
    abandonment_latched: bool = False
    pending_update_detached: bool = False


@dataclass(frozen=True)
class _ClaudeKeychainQuiescenceCallbacks:
    abandon: Callable[[], None]
    recover: Callable[[bytearray | None], BaseException | None]
    timeout_error: Callable[[], BaseException]
    timeout_fallback_error: BaseException | None = None
    fail_closed_error: Callable[[], BaseException] | None = None
    fail_closed_fallback_error: BaseException | None = None


class _ClaudeThreadEvent:
    def __init__(self) -> None:
        self._condition = threading.Condition(_CLAUDE_THREAD_LOCK_FACTORY())
        self._set = False

    def is_set(self) -> bool:
        with self._condition:
            return self._set

    def set(self) -> None:
        with self._condition:
            self._set = True
            self._condition.notify_all()

    def wait(self, timeout: float | None = None) -> bool:
        with self._condition:
            return self._condition.wait_for(lambda: self._set, timeout=timeout)


@dataclass
class _ClaudeMacOSDurableStage:
    pending_carrier: pathlib.Path
    committed_carrier: pathlib.Path
    credential_digest: bytes
    completed: _ClaudeThreadEvent
    terminal: bool = False
    committed: bool = False
    error: BaseException | None = None
    cleanup_after_completion: bool = False
    recovery_decided: _ClaudeThreadEvent = field(
        default_factory=_ClaudeThreadEvent
    )
    fallback_proven: bool = False
    handler_wait_expired: bool = False


@dataclass(frozen=True)
class _ClaudeRecoveryExpectation:
    carrier: pathlib.Path
    artifact: pathlib.Path
    digest: bytes


def _bounded_claude_keychain_abandonment(
    callback: Callable[[], None],
    timeout: float,
) -> tuple[bool, BaseException | None]:
    completed = threading.Event()
    errors: list[BaseException] = []

    def abandon() -> None:
        try:
            callback()
        except BaseException as error:
            errors.append(error)
        finally:
            completed.set()

    abandonment_thread = threading.Thread(
        target=abandon,
        daemon=True,
        name="claude-review-keychain-abandonment",
    )
    try:
        abandonment_thread.start()
    except BaseException as error:
        return False, error
    try:
        finished = completed.wait(timeout=max(0.0, timeout))
    except BaseException as error:
        return False, error
    if not finished:
        return (
            False,
            ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker runtime abandonment did not finish "
                "before the shutdown deadline"
            ),
        )
    if errors:
        return False, errors[0]
    return True, None


def _bounded_claude_keychain_fail_closed_error(
    callback: Callable[[], BaseException],
    timeout: float,
) -> tuple[BaseException | None, BaseException | None]:
    completed = threading.Event()
    results: list[BaseException] = []
    errors: list[BaseException] = []

    def capture() -> None:
        try:
            results.append(callback())
        except BaseException as error:
            errors.append(error)
        finally:
            completed.set()

    callback_thread = threading.Thread(
        target=capture,
        daemon=True,
        name="claude-review-keychain-fail-closed",
    )
    try:
        callback_thread.start()
    except BaseException as error:
        return None, error
    try:
        finished = completed.wait(timeout=max(0.0, timeout))
    except BaseException as error:
        return None, error
    if not finished:
        return (
            None,
            ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker fail-closed scope did not finish "
                "before the recovery deadline"
            ),
        )
    if errors:
        return None, errors[0]
    if not results:
        return (
            None,
            ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker fail-closed scope returned no error"
            ),
        )
    if not isinstance(results[0], BaseException):
        return (
            None,
            ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker fail-closed scope returned an "
                "invalid error"
            ),
        )
    return results[0], None


def _bounded_claude_keychain_server_shutdown(
    server: _ClaudeKeychainCredentialServer,
    serve_thread: threading.Thread,
    *,
    abandon_callback: Callable[[], None] | None = None,
) -> _ClaudeKeychainServerShutdown:
    deadline = (
        time.monotonic() + CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS
    )
    errors: list[BaseException] = []

    def remaining() -> float:
        return max(0.0, deadline - time.monotonic())

    def request_shutdown() -> None:
        try:
            server.shutdown()
        except BaseException as error:
            errors.append(error)

    def close_pending_publication() -> None:
        try:
            closed = server.close_pending_update_publication(remaining())
        except BaseException as error:
            errors.append(error)
            return
        if not closed:
            errors.append(
                ClaudeCredentialInspectionInconclusive(
                    "Claude Keychain broker pending-update publication did "
                    "not drain before the shutdown deadline"
                )
            )

    try:
        active_requests = server.begin_closing()
    except BaseException as error:
        errors.append(error)
        active_requests = ()
    for request in active_requests:
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        except BaseException as error:
            errors.append(error)
        try:
            request.close()
        except OSError:
            pass
        except BaseException as error:
            errors.append(error)

    shutdown_thread = threading.Thread(
        target=request_shutdown,
        daemon=True,
        name="claude-review-keychain-shutdown",
    )
    shutdown_started = False
    try:
        shutdown_thread.start()
        shutdown_started = True
    except BaseException as error:
        errors.append(error)
    if shutdown_started:
        try:
            shutdown_thread.join(timeout=remaining())
        except BaseException as error:
            errors.append(error)
    try:
        server.server_close()
    except BaseException as error:
        errors.append(error)
    try:
        serve_thread.join(timeout=remaining())
    except BaseException as error:
        errors.append(error)
    try:
        handlers_quiescent = server.wait_for_handlers(remaining())
    except BaseException as error:
        errors.append(error)
        handlers_quiescent = False
    shutdown_quiescent = (
        shutdown_started and not shutdown_thread.is_alive()
    )
    serve_quiescent = not serve_thread.is_alive()
    pending_update = None
    abandonment_latched = False
    pending_update_detached = False
    quiescent = (
        shutdown_quiescent and serve_quiescent and handlers_quiescent
    )
    serve_error = server.serve_error()
    if serve_error is not None:
        errors.append(serve_error)
    errors.extend(server.handler_errors())
    if not quiescent:
        close_pending_publication()
        if abandon_callback is not None:
            abandonment_latched, abandonment_error = (
                _bounded_claude_keychain_abandonment(
                    abandon_callback,
                    remaining(),
                )
            )
            if abandonment_error is not None:
                errors.append(abandonment_error)
        if abandon_callback is None or abandonment_latched:
            try:
                pending_update_detached, pending_update = (
                    server.try_abandon_and_detach_pending_update(remaining())
                )
            except BaseException as error:
                errors.append(error)
            if not pending_update_detached:
                errors.append(
                    ClaudeCredentialInspectionInconclusive(
                        "Claude Keychain broker pending update could not be "
                        "detached before the shutdown deadline"
                    )
                )
    return _ClaudeKeychainServerShutdown(
        quiescent=quiescent,
        pending_update=pending_update,
        errors=tuple(errors),
        abandonment_latched=abandonment_latched,
        pending_update_detached=pending_update_detached,
    )


def _bounded_claude_keychain_quiescence_recovery(
    callbacks: _ClaudeKeychainQuiescenceCallbacks,
    pending_update: bytearray | None,
    *,
    already_abandoned: bool = False,
) -> BaseException | None:
    deadline = time.monotonic() + CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS

    def remaining() -> float:
        return max(0.0, deadline - time.monotonic())

    def bounded_timeout_error() -> BaseException:
        captured, callback_error = (
            _bounded_claude_keychain_fail_closed_error(
                callbacks.timeout_error,
                min(
                    CLAUDE_KEYCHAIN_SERVER_POLL_INTERVAL_SECONDS,
                    max(0.0, CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS),
                ),
            )
        )
        failure = (
            captured
            or callbacks.timeout_fallback_error
            or ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker recovery timeout state could not be "
                "captured"
            )
        )
        if callback_error is not None and callback_error is not failure:
            failure = _attach_claude_persistence_failure_preserving_control_flow(
                failure,
                callback_error,
            )
        return failure

    if not already_abandoned:
        abandonment_latched, abandonment_error = (
            _bounded_claude_keychain_abandonment(
                callbacks.abandon,
                remaining(),
            )
        )
        if not abandonment_latched:
            if pending_update is not None:
                pending_update[:] = b"\x00" * len(pending_update)
            return abandonment_error or ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker runtime abandonment was not proven"
            )
    completed = threading.Event()
    result: list[BaseException | None] = []

    def recover() -> None:
        try:
            try:
                result.append(callbacks.recover(pending_update))
            except BaseException as error:
                result.append(error)
        finally:
            if pending_update is not None:
                pending_update[:] = b"\x00" * len(pending_update)
            completed.set()

    recovery_thread = threading.Thread(
        target=recover,
        daemon=True,
        name="claude-review-keychain-recovery",
    )
    try:
        recovery_thread.start()
    except BaseException as error:
        if pending_update is not None:
            pending_update[:] = b"\x00" * len(pending_update)
        timeout_error = bounded_timeout_error()
        _attach_claude_credential_cleanup_failure(timeout_error, error)
        return timeout_error
    try:
        recovery_completed = completed.wait(
            timeout=remaining()
        )
    except BaseException as error:
        timeout_error = bounded_timeout_error()
        if getattr(
            timeout_error,
            "_codex_claude_refresh_persistence_failed",
            False,
        ):
            _add_claude_persistence_note(error, timeout_error)
        else:
            _attach_claude_credential_cleanup_failure(error, timeout_error)
        return error
    if not recovery_completed:
        return bounded_timeout_error()
    return result[0] if result else None


@contextlib.contextmanager
def _claude_keychain_credential_server(
    credential: bytearray | None,
    capability: bytes,
    update_callback: Callable[
        [bytearray, Callable[[Callable[[], bool]], bool]],
        bool,
    ]
    | None = None,
    quiescence_callbacks: _ClaudeKeychainQuiescenceCallbacks | None = None,
) -> Iterator[int]:
    if len(capability) != CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES:
        raise ReviewError("Claude Keychain broker capability has an invalid length")
    try:
        server = _ClaudeKeychainCredentialServer(
            credential,
            capability,
            update_callback,
        )
    except OSError as error:
        failure_type = (
            ClaudeLoopbackUnavailable
            if _claude_loopback_bind_is_deterministically_unavailable(error)
            else ClaudeCredentialInspectionInconclusive
        )
        raise failure_type(
            f"Claude Keychain broker cannot bind loopback: {error}"
        ) from error
    serve_gate = threading.Event()
    serve_cancelled = threading.Event()

    def serve() -> None:
        serve_error: BaseException | None = None
        try:
            serve_gate.wait()
            if serve_cancelled.is_set():
                return
            server.serve_forever(
                poll_interval=CLAUDE_KEYCHAIN_SERVER_POLL_INTERVAL_SECONDS
            )
        except BaseException as error:
            serve_error = error
        finally:
            server.record_serve_stopped(serve_error)

    thread: threading.Thread | None = None
    thread_started = False
    serve_admitted = False
    runtime_exposed = False
    primary_error: BaseException | None = None
    try:
        try:
            thread = threading.Thread(
                target=serve,
                daemon=True,
                name="claude-review-keychain-broker",
            )
        except ForwardedSignal:
            raise
        except Exception as error:
            raise ClaudeCredentialInspectionInconclusive(
                f"Claude Keychain broker cannot construct its thread: {error}"
            ) from error
        try:
            thread.start()
            thread_started = True
        except ForwardedSignal:
            thread_started = _claude_thread_may_have_started(thread)
            raise
        except RuntimeError as error:
            thread_started = _claude_thread_may_have_started(thread)
            raise ClaudeCredentialInspectionInconclusive(
                f"Claude Keychain broker cannot start: {error}"
            ) from error
        serve_admitted = True
        serve_gate.set()
        if not server.wait_until_serving(
            CLAUDE_KEYCHAIN_SERVER_START_TIMEOUT_SECONDS
        ):
            failure = ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker did not enter its serve loop"
            )
            serve_error = server.serve_error()
            if serve_error is not None:
                failure.__cause__ = serve_error
            raise failure
        runtime_exposed = True
        yield int(server.server_address[1])
    except BaseException as error:
        primary_error = error
        raise
    finally:
        shutdown_errors: list[BaseException] = []
        if not serve_admitted:
            serve_cancelled.set()
        serve_gate.set()
        if thread is not None and not thread_started:
            thread_started = _claude_thread_may_have_started(thread)
        if thread_started and not serve_admitted and thread is not None:
            try:
                thread.join(
                    timeout=CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS
                )
            except BaseException as error:
                shutdown_errors.append(error)
            else:
                try:
                    thread_alive = thread.is_alive()
                except BaseException as error:
                    shutdown_errors.append(error)
                else:
                    if thread_alive:
                        shutdown_errors.append(
                            ClaudeCredentialInspectionInconclusive(
                                "Claude Keychain broker thread did not stop after "
                                "pre-serve cancellation"
                            )
                        )
                    else:
                        thread_started = False
        shutdown = _ClaudeKeychainServerShutdown(
            quiescent=True,
            pending_update=None,
            errors=(),
        )
        if thread_started and thread is not None:
            shutdown = _bounded_claude_keychain_server_shutdown(
                server,
                thread,
                abandon_callback=(
                    quiescence_callbacks.abandon
                    if runtime_exposed and quiescence_callbacks is not None
                    else None
                ),
            )
            shutdown_errors.extend(shutdown.errors)
        else:
            try:
                server.server_close()
            except BaseException as error:
                shutdown_errors.append(error)
        if shutdown.quiescent:
            try:
                server.scrub_initial_credential()
            except BaseException as error:
                shutdown_errors.append(error)
        if credential is not None:
            credential[:] = b"\x00" * len(credential)
        pending_update = shutdown.pending_update
        if not shutdown.quiescent:
            failure = ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker handler quiescence could not be proven "
                "before the shutdown deadline"
            )
            setattr(
                failure,
                "_codex_claude_keychain_handler_quiescence_unproven",
                True,
            )
            retention_error: BaseException | None = None
            fail_closed_scope_error: BaseException | None = None
            if runtime_exposed and quiescence_callbacks is not None:
                abandonment_latched = shutdown.abandonment_latched
                pending_update_detached = shutdown.pending_update_detached
                if not abandonment_latched:
                    fail_closed_error = (
                        quiescence_callbacks.fail_closed_error
                        or quiescence_callbacks.timeout_error
                    )
                    (
                        fail_closed_scope_error,
                        fail_closed_callback_error,
                    ) = _bounded_claude_keychain_fail_closed_error(
                        fail_closed_error,
                        CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS,
                    )
                    if fail_closed_scope_error is None:
                        fail_closed_scope_error = (
                            quiescence_callbacks.fail_closed_fallback_error
                        )
                    if fail_closed_callback_error is not None:
                        shutdown_errors.append(fail_closed_callback_error)
                    abandonment_latched, abandonment_error = (
                        _bounded_claude_keychain_abandonment(
                            quiescence_callbacks.abandon,
                            CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS,
                        )
                    )
                    if abandonment_error is not None:
                        error = abandonment_error
                        try:
                            publication_closed = (
                                server.close_pending_update_publication(0.0)
                            )
                        except BaseException as close_error:
                            shutdown_errors.append(close_error)
                        else:
                            if not publication_closed:
                                shutdown_errors.append(
                                    ClaudeCredentialInspectionInconclusive(
                                        "Claude Keychain broker pending-update "
                                        "publication did not drain after "
                                        "runtime abandonment failed"
                                    )
                                )
                        fail_closed_failure = (
                            fail_closed_scope_error
                            or fail_closed_callback_error
                            or ClaudeCredentialInspectionInconclusive(
                                "Claude Keychain broker fail-closed scope "
                                "could not be captured"
                            )
                        )
                        if fail_closed_failure is not None:
                            if _is_claude_control_flow_error(error):
                                _add_claude_persistence_note(
                                    error,
                                    fail_closed_failure,
                                )
                                retention_error = error
                            elif _is_claude_control_flow_error(
                                fail_closed_failure
                            ):
                                _add_claude_persistence_note(
                                    fail_closed_failure,
                                    error,
                                )
                                retention_error = fail_closed_failure
                            else:
                                _attach_claude_credential_cleanup_failure(
                                    fail_closed_failure,
                                    error,
                                )
                                retention_error = fail_closed_failure
                    if abandonment_latched:
                        try:
                            (
                                pending_update_detached,
                                pending_update,
                            ) = server.try_abandon_and_detach_pending_update(
                                CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS
                            )
                        except BaseException as error:
                            shutdown_errors.append(error)
                        if not pending_update_detached:
                            shutdown_errors.append(
                                ClaudeCredentialInspectionInconclusive(
                                    "Claude Keychain broker pending update "
                                    "could not be detached during bounded "
                                    "recovery"
                                )
                            )
                elif not pending_update_detached:
                    try:
                        (
                            pending_update_detached,
                            pending_update,
                        ) = server.try_abandon_and_detach_pending_update(
                            CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS
                        )
                    except BaseException as error:
                        shutdown_errors.append(error)
                    if not pending_update_detached:
                        shutdown_errors.append(
                            ClaudeCredentialInspectionInconclusive(
                                "Claude Keychain broker pending update could "
                                "not be detached during bounded recovery"
                            )
                        )
                if retention_error is None:
                    retention_error = (
                        _bounded_claude_keychain_quiescence_recovery(
                            quiescence_callbacks,
                            pending_update,
                            already_abandoned=abandonment_latched,
                        )
                    )
                if fail_closed_scope_error is not None:
                    if retention_error is None:
                        retention_error = fail_closed_scope_error
                    elif retention_error is not fail_closed_scope_error:
                        _add_claude_persistence_note(
                            retention_error,
                            fail_closed_scope_error,
                        )
                pending_update = None
            if pending_update is not None:
                pending_update[:] = b"\x00" * len(pending_update)
            if retention_error is not None:
                if getattr(
                    retention_error,
                    "_codex_claude_refresh_persistence_failed",
                    False,
                ):
                    _add_claude_persistence_note(failure, retention_error)
                else:
                    _attach_claude_credential_cleanup_failure(
                        failure,
                        retention_error,
                    )
            for error in shutdown_errors:
                _attach_claude_credential_cleanup_failure(failure, error)
            candidates = [failure, *shutdown_errors]
            if (
                retention_error is not None
                and _is_claude_control_flow_error(retention_error)
            ):
                candidates.append(retention_error)
            for candidate in (primary_error, *candidates):
                if candidate is None:
                    continue
                setattr(
                    candidate,
                    "_codex_claude_keychain_handler_quiescence_unproven",
                    True,
                )
                if getattr(
                    failure,
                    "_codex_claude_refresh_persistence_failed",
                    False,
                ):
                    _add_claude_persistence_note(candidate, failure)
                elif candidate is not failure:
                    add_note = getattr(candidate, "add_note", None)
                    if callable(add_note):
                        add_note(str(failure))
            if primary_error is None and not any(
                _is_claude_control_flow_error(candidate)
                for candidate in candidates
            ):
                raise failure
            _raise_or_attach_claude_credential_cleanup(
                primary_error,
                candidates,
                message=(
                    "cannot prove Claude Keychain broker handler quiescence"
                ),
            )
        if shutdown.quiescent:
            _raise_or_attach_claude_credential_cleanup(
                primary_error,
                shutdown_errors,
                message="cannot shut down the Claude Keychain broker safely",
            )


@contextlib.contextmanager
def _claude_keychain_runtime(
    review: ReviewWorkspace,
    env: dict[str, str],
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None,
) -> Iterator[dict[str, str]]:
    result = dict(env)
    if result.get("ANTHROPIC_API_KEY"):
        yield result
        return
    if refresh_lock_protocol is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude local-login credential-lock protocol is unavailable"
        )
    selected = _select_claude_macos_credential(review)
    expected_credential = bytearray(selected.payload)
    carrier_snapshot = selected.carrier_snapshot
    if carrier_snapshot is None:
        expected_credential[:] = b"\x00" * len(expected_credential)
        selected.payload[:] = b"\x00" * len(selected.payload)
        raise ReviewError("Claude macOS carrier snapshot is unavailable")
    try:
        fail_closed_recovery_root = _claude_macos_recovery_root(review)
    except BaseException as error:
        expected_credential[:] = b"\x00" * len(expected_credential)
        selected.payload[:] = b"\x00" * len(selected.payload)
        if _is_claude_control_flow_error(error):
            raise
        failure = ClaudeCredentialInspectionInconclusive(
            "the macOS Claude fail-closed recovery scope could not be "
            "initialized"
        )
        failure.__cause__ = error
        raise failure
    persistence_errors: list[BaseException] = []
    persisted_updates = 0
    runtime_state_lock = threading.Lock()
    runtime_abandon_requested = _ClaudeThreadEvent()
    staged_credential: bytearray | None = None
    durable_stage_session = secrets.token_bytes(16).hex()
    durable_stage_generation = 0
    durable_stage_reserved_generations = 0
    durable_stage_reserved_bytes = 0
    durable_stage_quota_exhausted_error: BaseException | None = None
    durable_stage_carriers: list[tuple[pathlib.Path, bytes]] = []
    durable_stage_inflight: _ClaudeMacOSDurableStage | None = None
    quiescence_durable_stage: _ClaudeMacOSDurableStage | None = None
    quiescence_recovery_candidate: pathlib.Path | None = None
    quiescence_recovery_replaces_existing = False
    quiescence_recovery_proven = False
    quiescence_recovery_expectation: _ClaudeRecoveryExpectation | None = None
    quiescence_recovery_timeout_failure: BaseException | None = None

    def runtime_is_abandoned() -> bool:
        return runtime_abandon_requested.is_set()

    def transfer_abandoned_stage_locked(
        stage: _ClaudeMacOSDurableStage,
    ) -> bool:
        nonlocal durable_stage_inflight
        nonlocal quiescence_durable_stage
        if (
            not runtime_is_abandoned()
            or durable_stage_inflight is not stage
        ):
            return False
        quiescence_durable_stage = stage
        durable_stage_inflight = None
        return True

    def new_recovery_candidate() -> pathlib.Path:
        return (
            review.container_dir
            / "claude-runtime"
            / "macos"
            / f"claude-carrier-{secrets.token_hex(16)}"
        )

    def recovery_expectation_from_error(
        error: BaseException,
        *candidate_carriers: pathlib.Path,
    ) -> _ClaudeRecoveryExpectation | None:
        proof = _get_claude_retained_credential_proof(error)
        if proof is None or proof.artifact.parent.name != "config":
            return None
        proof_carrier = proof.artifact.parent.parent
        if proof_carrier not in candidate_carriers:
            return None
        return _ClaudeRecoveryExpectation(
            proof_carrier,
            proof.artifact,
            proof.digest,
        )

    def published_recovery_claim_is_current(
        error: BaseException,
        expectation: _ClaudeRecoveryExpectation | None = None,
    ) -> bool:
        retained_value = getattr(
            error,
            "_codex_claude_retained_credential_carrier",
            None,
        )
        proof = _get_claude_retained_credential_proof(error)
        if not isinstance(retained_value, str) or proof is None:
            return False
        retained_carrier = pathlib.Path(retained_value)
        if (
            proof.artifact.parent.name != "config"
            or proof.artifact.parent.parent != retained_carrier
        ):
            return False
        if expectation is not None and (
            expectation.carrier != retained_carrier
            or expectation.artifact != proof.artifact
            or not hmac.compare_digest(expectation.digest, proof.digest)
        ):
            return False
        return (
            _validated_claude_retained_credential_artifact(
                review,
                error,
            )
            == str(proof.artifact)
        )

    def cleanup_late_durable_stage(
        stage: _ClaudeMacOSDurableStage,
    ) -> None:
        with runtime_state_lock:
            authoritative_expectation = quiescence_recovery_expectation
        try:
            _remove_claude_macos_recovery_carrier(
                review,
                stage.committed_carrier,
                stage.credential_digest,
            )
        except BaseException as cleanup_error:
            if authoritative_expectation is not None:
                setattr(
                    cleanup_error,
                    "_codex_claude_retained_credential_carrier",
                    str(authoritative_expectation.carrier),
                )
                _mark_claude_macos_recovery_update_artifact(
                    cleanup_error,
                    authoritative_expectation.artifact,
                    expected_digest=authoritative_expectation.digest,
                )
            with runtime_state_lock:
                if _is_claude_control_flow_error(cleanup_error):
                    persistence_errors.insert(0, cleanup_error)
                else:
                    persistence_errors.append(cleanup_error)
            raise
        else:
            with runtime_state_lock:
                durable_stage_carriers[:] = [
                    carrier
                    for carrier in durable_stage_carriers
                    if carrier[0] != stage.committed_carrier
                ]

    def stage_refreshed_credential(
        updated: bytearray,
        commit_pending: Callable[[Callable[[], bool]], bool] | None = None,
        claim_terminal: Callable[[], bool] | None = None,
    ) -> bool:
        nonlocal durable_stage_generation, staged_credential
        nonlocal durable_stage_reserved_generations
        nonlocal durable_stage_reserved_bytes
        nonlocal durable_stage_quota_exhausted_error
        nonlocal durable_stage_inflight
        nonlocal quiescence_recovery_candidate
        nonlocal quiescence_recovery_proven
        nonlocal quiescence_recovery_replaces_existing
        nonlocal quiescence_recovery_expectation
        previous: bytearray | None = None
        with runtime_state_lock:
            if runtime_is_abandoned():
                return False
            previous = staged_credential
            staged_credential = None
        if previous is not None:
            previous[:] = b"\x00" * len(previous)
        try:
            _validate_claude_local_credential(
                updated,
                source="broker refresh",
            )
        except ClaudeCredentialUnsafe as error:
            malformed = ClaudeCredentialInspectionInconclusive(
                "Claude produced a malformed refreshed OAuth credential"
            )
            malformed.__cause__ = error
            retained_entry: tuple[pathlib.Path, bytes] | None = None
            with runtime_state_lock:
                if not runtime_is_abandoned() and durable_stage_carriers:
                    retained_entry = durable_stage_carriers[-1]
            if retained_entry is not None:
                # A superseded generation is not accepted for host writeback,
                # but its synchronized carrier remains useful recovery evidence
                # if the newer payload fails.
                retained_carrier, retained_digest = retained_entry
                setattr(
                    malformed,
                    "_codex_claude_retained_credential_carrier",
                    str(retained_carrier),
                )
                _mark_claude_macos_recovery_update_artifact(
                    malformed,
                    retained_carrier
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=retained_digest,
                )
                setattr(
                    malformed,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
            with runtime_state_lock:
                if not runtime_is_abandoned():
                    persistence_errors.append(malformed)
            return False
        quota_failure: ClaudeCredentialInspectionInconclusive | None = None
        quota_retained_entry: tuple[pathlib.Path, bytes] | None = None
        terminal_generation = False
        generation: int | None = None
        requested_bytes = len(updated)
        with runtime_state_lock:
            if runtime_is_abandoned():
                return False
            if durable_stage_quota_exhausted_error is not None:
                return False
            normal_generation_limit = max(
                0,
                CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS - 1,
            )
            normal_byte_limit = max(
                0,
                CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES
                - CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES,
            )
            terminal_generation = (
                durable_stage_reserved_generations
                >= normal_generation_limit
                or durable_stage_reserved_bytes + requested_bytes
                > normal_byte_limit
            )
            if not terminal_generation:
                durable_stage_reserved_generations += 1
                durable_stage_reserved_bytes += requested_bytes
                durable_stage_generation += 1
                generation = durable_stage_generation
        if terminal_generation:
            try:
                terminal_claimed = (
                    True if claim_terminal is None else claim_terminal()
                )
            except BaseException as claim_error:
                if _is_claude_control_flow_error(claim_error):
                    raise
                claim_failure = ClaudeCredentialInspectionInconclusive(
                    "the terminal macOS Claude durable-stage generation "
                    "could not close later broker updates"
                )
                claim_failure.__cause__ = claim_error
                setattr(
                    claim_failure,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                with runtime_state_lock:
                    if durable_stage_carriers:
                        quota_retained_entry = durable_stage_carriers[-1]
                if quota_retained_entry is not None:
                    retained_carrier, retained_digest = quota_retained_entry
                    setattr(
                        claim_failure,
                        "_codex_claude_retained_credential_carrier",
                        str(retained_carrier),
                    )
                    _mark_claude_macos_recovery_update_artifact(
                        claim_failure,
                        retained_carrier
                        / "config"
                        / CLAUDE_CREDENTIAL_FILE_NAME,
                        expected_digest=retained_digest,
                    )
                with runtime_state_lock:
                    if not runtime_is_abandoned():
                        persistence_errors.append(claim_failure)
                return False
            if not terminal_claimed:
                return False
            with runtime_state_lock:
                if runtime_is_abandoned():
                    return False
                if durable_stage_quota_exhausted_error is not None:
                    return False
                exhausted = ClaudeCredentialInspectionInconclusive(
                    "the bounded macOS Claude durable-stage journal is full; "
                    "the terminal refreshed credential was retained for "
                    "recovery but not acknowledged"
                )
                setattr(
                    exhausted,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                durable_stage_quota_exhausted_error = exhausted
                quota_failure = exhausted
                if (
                    durable_stage_reserved_generations
                    < CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS
                    and durable_stage_reserved_bytes + requested_bytes
                    <= CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES
                ):
                    durable_stage_reserved_generations += 1
                    durable_stage_reserved_bytes += requested_bytes
                    durable_stage_generation += 1
                    generation = durable_stage_generation
                elif durable_stage_carriers:
                    quota_retained_entry = durable_stage_carriers[-1]
        if quota_failure is not None and generation is None:
            if quota_retained_entry is not None:
                retained_carrier, retained_digest = quota_retained_entry
                setattr(
                    quota_failure,
                    "_codex_claude_retained_credential_carrier",
                    str(retained_carrier),
                )
                _mark_claude_macos_recovery_update_artifact(
                    quota_failure,
                    retained_carrier
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=retained_digest,
                )
            with runtime_state_lock:
                persistence_errors.append(quota_failure)
            return False
        assert generation is not None
        try:
            recovery_root = _claude_macos_recovery_root(review)
            generation_text = str(generation).zfill(
                CLAUDE_MACOS_DURABLE_STAGE_GENERATION_WIDTH
            )
            pending_carrier = recovery_root / (
                f"{CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX}"
                f"{durable_stage_session}-{generation_text}"
            )
            acknowledged_carrier = recovery_root / (
                f"{CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX}"
                f"{durable_stage_session}-{generation_text}"
            )
            stage = _ClaudeMacOSDurableStage(
                pending_carrier=pending_carrier,
                committed_carrier=acknowledged_carrier,
                credential_digest=_claude_credential_digest(updated),
                completed=_ClaudeThreadEvent(),
                terminal=terminal_generation,
            )
            with runtime_state_lock:
                if runtime_is_abandoned():
                    return False
                durable_stage_inflight = stage
        except BaseException as setup_error:
            if _is_claude_control_flow_error(setup_error):
                setup_failure = setup_error
            else:
                setup_failure = ClaudeCredentialInspectionInconclusive(
                    "the macOS Claude durable recovery stage could not be "
                    "initialized"
                )
                setup_failure.__cause__ = setup_error
            setattr(
                setup_failure,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            with runtime_state_lock:
                previous_durable_entry = (
                    durable_stage_carriers[-1]
                    if durable_stage_carriers
                    else None
                )
            if previous_durable_entry is not None:
                previous_durable_carrier, previous_durable_digest = (
                    previous_durable_entry
                )
                setattr(
                    setup_failure,
                    "_codex_claude_retained_credential_carrier",
                    str(previous_durable_carrier),
                )
                _mark_claude_macos_recovery_update_artifact(
                    setup_failure,
                    previous_durable_carrier
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=previous_durable_digest,
                )
            with runtime_state_lock:
                persistence_errors.append(setup_failure)
            if _is_claude_control_flow_error(setup_error):
                raise
            return False
        committed_carrier: pathlib.Path | None = None
        staged: bytearray | None = None
        try:
            staged = bytearray(updated)
            _retain_claude_macos_refreshed_credential(
                review,
                updated,
                requested_carrier_root=pending_carrier,
                credential_prevalidated=True,
                durable_directories=True,
            )
            committed_carrier = _commit_claude_macos_durable_stage(
                review,
                pending_carrier,
                acknowledged_carrier,
                updated,
            )
            with runtime_state_lock:
                stage.committed = True
                durable_stage_carriers.append(
                    (committed_carrier, stage.credential_digest)
                )
                stage.completed.set()
                abandoned_after_commit = runtime_is_abandoned()
                cleanup_late_carrier = stage.cleanup_after_completion
                if abandoned_after_commit:
                    transfer_abandoned_stage_locked(stage)
        except BaseException as error:
            if staged is not None:
                staged[:] = b"\x00" * len(staged)
            if committed_carrier is not None:
                stage.committed = True
                setattr(
                    error,
                    "_codex_claude_retained_credential_carrier",
                    str(committed_carrier),
                )
                _mark_claude_macos_recovery_update_artifact(
                    error,
                    committed_carrier
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=stage.credential_digest,
                )
                setattr(
                    error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
            with runtime_state_lock:
                stage.error = error
                transferred_to_recovery = transfer_abandoned_stage_locked(
                    stage
                )
                if (
                    not transferred_to_recovery
                    and durable_stage_inflight is stage
                ):
                    durable_stage_inflight = None
            stage.completed.set()
            retained_candidate = getattr(
                error,
                "_codex_claude_retained_credential_carrier",
                None,
            )
            if isinstance(retained_candidate, str):
                retained_stage_path = pathlib.Path(retained_candidate)
                if retained_stage_path in (
                    pending_carrier,
                    acknowledged_carrier,
                ):
                    try:
                        retained_stage_path.lstat()
                    except OSError:
                        pass
                    else:
                        with runtime_state_lock:
                            if all(
                                carrier[0] != retained_stage_path
                                for carrier in durable_stage_carriers
                            ):
                                durable_stage_carriers.append(
                                    (
                                        retained_stage_path,
                                        stage.credential_digest,
                                    )
                                )
            if not isinstance(retained_candidate, str):
                cleanup_candidate: pathlib.Path | None = None
                for candidate in (acknowledged_carrier, pending_carrier):
                    try:
                        candidate.lstat()
                    except OSError:
                        continue
                    cleanup_candidate = candidate
                    break
                if cleanup_candidate is not None:
                    try:
                        _remove_claude_macos_recovery_carrier(
                            review,
                            cleanup_candidate,
                            stage.credential_digest,
                        )
                    except BaseException as cleanup_error:
                        cleanup_artifact = getattr(
                            cleanup_error,
                            "_codex_claude_retained_cleanup_artifact",
                            None,
                        )
                        if isinstance(cleanup_artifact, str):
                            setattr(
                                error,
                                "_codex_claude_retained_cleanup_artifact",
                                cleanup_artifact,
                            )
                        else:
                            _mark_claude_macos_recovery_cleanup_artifact(
                                error,
                                cleanup_candidate,
                            )
                        if _is_claude_control_flow_error(cleanup_error):
                            _add_claude_persistence_note(
                                cleanup_error,
                                error,
                            )
                            error = cleanup_error
                            with runtime_state_lock:
                                stage.error = error
                        else:
                            _attach_claude_credential_cleanup_failure(
                                error,
                                cleanup_error,
                            )
                    else:
                        for attribute in (
                            "_codex_claude_retained_credential_carrier",
                            "_codex_claude_retained_cleanup_artifact",
                        ):
                            value = getattr(error, attribute, None)
                            if not isinstance(value, str):
                                continue
                            with contextlib.suppress(ValueError):
                                pathlib.Path(value).relative_to(
                                    cleanup_candidate
                                )
                                delattr(error, attribute)
                        proof = _get_claude_retained_credential_proof(error)
                        if proof is not None:
                            with contextlib.suppress(ValueError):
                                proof.artifact.relative_to(cleanup_candidate)
                                _clear_claude_retained_credential_proof(error)
            if not isinstance(retained_candidate, str):
                with runtime_state_lock:
                    previous_durable_entry = (
                        durable_stage_carriers[-1]
                        if durable_stage_carriers
                        else None
                    )
                setattr(
                    error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                if previous_durable_entry is not None:
                    previous_durable_carrier, previous_durable_digest = (
                        previous_durable_entry
                    )
                    setattr(
                        error,
                        "_codex_claude_retained_credential_carrier",
                        str(previous_durable_carrier),
                    )
                    _mark_claude_macos_recovery_update_artifact(
                        error,
                        previous_durable_carrier
                        / "config"
                        / CLAUDE_CREDENTIAL_FILE_NAME,
                        expected_digest=previous_durable_digest,
                    )
            with runtime_state_lock:
                if not runtime_is_abandoned():
                    persistence_errors.append(error)
            if _is_claude_control_flow_error(error):
                raise
            return False
        assert staged is not None
        assert committed_carrier is not None

        if abandoned_after_commit:
            staged[:] = b"\x00" * len(staged)
            if cleanup_late_carrier:
                decision_ready = stage.recovery_decided.wait(
                    timeout=CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS
                )
                with runtime_state_lock:
                    if (
                        not decision_ready
                        and not stage.recovery_decided.is_set()
                    ):
                        stage.handler_wait_expired = True
                        return False
                    fallback_proven = stage.fallback_proven
                if fallback_proven:
                    try:
                        cleanup_late_durable_stage(stage)
                    except BaseException as cleanup_error:
                        if _is_claude_control_flow_error(cleanup_error):
                            raise
                else:
                    retained = _retained_claude_macos_credential_error(
                        committed_carrier,
                        ClaudeCredentialInspectionInconclusive(
                            "Claude Keychain recovery could not replace a "
                            "late durable generation"
                        ),
                        expected_digest=stage.credential_digest,
                    )
                    setattr(
                        retained,
                        "_codex_claude_keychain_handler_quiescence_unproven",
                        True,
                    )
                    with runtime_state_lock:
                        persistence_errors.append(retained)
            return False

        if terminal_generation:
            assert quota_failure is not None
            staged[:] = b"\x00" * len(staged)
            setattr(
                quota_failure,
                "_codex_claude_retained_credential_carrier",
                str(committed_carrier),
            )
            _mark_claude_macos_recovery_update_artifact(
                quota_failure,
                committed_carrier
                / "config"
                / CLAUDE_CREDENTIAL_FILE_NAME,
                expected_digest=stage.credential_digest,
            )
            with runtime_state_lock:
                terminal_abandoned = runtime_is_abandoned()
                if terminal_abandoned:
                    transfer_abandoned_stage_locked(stage)
                elif durable_stage_inflight is stage:
                    durable_stage_inflight = None
                if not terminal_abandoned:
                    persistence_errors.append(quota_failure)
            return False

        def publish_current_generation() -> bool:
            nonlocal durable_stage_inflight, staged_credential
            nonlocal quiescence_recovery_candidate
            nonlocal quiescence_recovery_proven
            nonlocal quiescence_recovery_replaces_existing
            nonlocal quiescence_recovery_expectation
            with runtime_state_lock:
                if runtime_is_abandoned():
                    return False
                staged_credential = staged
                quiescence_recovery_candidate = committed_carrier
                quiescence_recovery_replaces_existing = True
                quiescence_recovery_proven = True
                quiescence_recovery_expectation = _ClaudeRecoveryExpectation(
                    committed_carrier,
                    committed_carrier
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME,
                    stage.credential_digest,
                )
                if durable_stage_inflight is stage:
                    durable_stage_inflight = None
            return True

        try:
            if commit_pending is None:
                committed_current = publish_current_generation()
            else:
                committed_current = commit_pending(
                    publish_current_generation
                )
        except BaseException as publish_error:
            staged[:] = b"\x00" * len(staged)
            setattr(
                publish_error,
                "_codex_claude_retained_credential_carrier",
                str(committed_carrier),
            )
            _mark_claude_macos_recovery_update_artifact(
                publish_error,
                committed_carrier
                / "config"
                / CLAUDE_CREDENTIAL_FILE_NAME,
                expected_digest=stage.credential_digest,
            )
            setattr(
                publish_error,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            with runtime_state_lock:
                transferred_to_recovery = transfer_abandoned_stage_locked(
                    stage
                )
                if (
                    not transferred_to_recovery
                    and durable_stage_inflight is stage
                ):
                    durable_stage_inflight = None
                if _is_claude_control_flow_error(publish_error):
                    persistence_errors.insert(0, publish_error)
                else:
                    persistence_errors.append(publish_error)
            if _is_claude_control_flow_error(publish_error):
                raise
            return False
        if committed_current:
            return True
        staged[:] = b"\x00" * len(staged)
        with runtime_state_lock:
            transferred_to_recovery = transfer_abandoned_stage_locked(stage)
            if (
                not transferred_to_recovery
                and durable_stage_inflight is stage
            ):
                durable_stage_inflight = None
        return False

    def accept_refreshed_credential(updated: bytearray) -> bool:
        nonlocal carrier_snapshot, persisted_updates
        nonlocal quiescence_recovery_candidate
        nonlocal quiescence_recovery_replaces_existing
        nonlocal quiescence_recovery_proven
        nonlocal quiescence_recovery_expectation
        callback_expected_credential: bytearray | None = None
        updated_digest = _claude_credential_digest(updated)
        try:
            try:
                _validate_claude_local_credential(
                    updated,
                    source="broker refresh",
                )
            except ClaudeCredentialUnsafe as error:
                malformed = ClaudeCredentialInspectionInconclusive(
                    "Claude produced a malformed refreshed OAuth credential"
                )
                malformed.__cause__ = error
                with runtime_state_lock:
                    if not runtime_is_abandoned():
                        persistence_errors.append(malformed)
                return False
            with runtime_state_lock:
                if runtime_is_abandoned():
                    return False
                prior_error = (
                    persistence_errors[0] if persistence_errors else None
                )
                callback_carrier_snapshot = carrier_snapshot
                callback_expected_credential = bytearray(expected_credential)
            if prior_error is not None:
                callback_expected_credential[:] = (
                    b"\x00" * len(callback_expected_credential)
                )
                retained_candidate = getattr(
                    prior_error,
                    "_codex_claude_retained_credential_carrier",
                    None,
                )
                recovery_candidate = (
                    pathlib.Path(retained_candidate)
                    if isinstance(retained_candidate, str)
                    else new_recovery_candidate()
                )
                prior_expectation = recovery_expectation_from_error(
                    prior_error,
                    recovery_candidate,
                )
                with runtime_state_lock:
                    if runtime_is_abandoned():
                        return False
                    quiescence_recovery_candidate = recovery_candidate
                    quiescence_recovery_replaces_existing = isinstance(
                        retained_candidate,
                        str,
                    )
                    quiescence_recovery_proven = (
                        prior_expectation is not None
                    )
                    quiescence_recovery_expectation = prior_expectation
                try:
                    if isinstance(retained_candidate, str):
                        _replace_claude_macos_recovery_credential(
                            review,
                            pathlib.Path(retained_candidate),
                            updated,
                        )
                        retained_carrier = pathlib.Path(retained_candidate)
                    else:
                        retained_carrier = (
                            _retain_claude_macos_refreshed_credential(
                                review,
                                updated,
                                requested_carrier_root=recovery_candidate,
                            )
                        )
                except BaseException as recovery_error:
                    failed_recovery_expectation = (
                        recovery_expectation_from_error(
                            recovery_error,
                            recovery_candidate,
                        )
                    )
                    if _is_claude_control_flow_error(prior_error):
                        replacement_error = prior_error
                        deferred_persistence_note = recovery_error
                    elif _is_claude_control_flow_error(recovery_error):
                        _add_claude_persistence_note(
                            recovery_error,
                            prior_error,
                        )
                        replacement_error = recovery_error
                        deferred_persistence_note = None
                    else:
                        replacement_error = _failed_claude_macos_recovery_error(
                            prior_error,
                            recovery_error,
                        )
                        deferred_persistence_note = None
                    with runtime_state_lock:
                        if (
                            not runtime_is_abandoned()
                            and persistence_errors
                            and persistence_errors[0] is prior_error
                        ):
                            if (
                                quiescence_recovery_candidate
                                == recovery_candidate
                            ):
                                if failed_recovery_expectation is not None:
                                    quiescence_recovery_replaces_existing = True
                                    quiescence_recovery_proven = True
                                    quiescence_recovery_expectation = (
                                        failed_recovery_expectation
                                    )
                                else:
                                    quiescence_recovery_proven = False
                                    quiescence_recovery_expectation = None
                            if deferred_persistence_note is not None:
                                _add_claude_persistence_note(
                                    prior_error,
                                    deferred_persistence_note,
                                )
                            persistence_errors[0] = replacement_error
                    return False
                retained_error = _retained_claude_macos_credential_error(
                    retained_carrier,
                    prior_error,
                    expected_digest=updated_digest,
                )
                if _is_claude_control_flow_error(prior_error):
                    replacement_error = prior_error
                    deferred_persistence_note = retained_error
                else:
                    replacement_error = retained_error
                    deferred_persistence_note = None
                with runtime_state_lock:
                    if (
                        not runtime_is_abandoned()
                        and persistence_errors
                        and persistence_errors[0] is prior_error
                    ):
                        quiescence_recovery_candidate = retained_carrier
                        quiescence_recovery_replaces_existing = True
                        quiescence_recovery_proven = True
                        quiescence_recovery_expectation = (
                            _ClaudeRecoveryExpectation(
                                retained_carrier,
                                retained_carrier
                                / "config"
                                / CLAUDE_CREDENTIAL_FILE_NAME,
                                updated_digest,
                            )
                        )
                        if deferred_persistence_note is not None:
                            _add_claude_persistence_note(
                                prior_error,
                                deferred_persistence_note,
                            )
                        persistence_errors[0] = replacement_error
                return False
            if (
                (
                    selected.source == "macos-keychain"
                    or _claude_macos_carriers_share_refresh_token(
                        callback_carrier_snapshot
                    )
                )
                and not _claude_keychain_credential_has_refresh_margin(updated)
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "Claude refreshed its OAuth credential, but the result is too "
                    "large for safe Keychain persistence"
                )
            updated_snapshot = _persist_claude_macos_refreshed_credential(
                review,
                selected,
                updated,
                callback_expected_credential,
                callback_carrier_snapshot,
                refresh_lock_protocol,
            )
            if updated_snapshot is None:
                raise ClaudeCredentialInspectionInconclusive(
                    "Claude refreshed its OAuth credential, but the selected host "
                    "credential source changed or post-quiescence writeback could "
                    "not be verified"
                )
            with runtime_state_lock:
                if runtime_is_abandoned():
                    return False
                carrier_snapshot = updated_snapshot
                expected_credential[:] = updated
                persisted_updates += 1
                return True
        except BaseException as error:
            callback_recovery_candidate: pathlib.Path | None = None
            try:
                proposed_recovery_candidate = new_recovery_candidate()
                with runtime_state_lock:
                    if runtime_is_abandoned():
                        return False
                    if quiescence_recovery_candidate is None:
                        quiescence_recovery_candidate = (
                            proposed_recovery_candidate
                        )
                        quiescence_recovery_replaces_existing = False
                        quiescence_recovery_proven = False
                        quiescence_recovery_expectation = None
                    callback_recovery_candidate = (
                        quiescence_recovery_candidate
                    )
                    callback_replaces_existing = (
                        quiescence_recovery_replaces_existing
                    )
                assert callback_recovery_candidate is not None
                if callback_replaces_existing:
                    _replace_claude_macos_recovery_credential(
                        review,
                        callback_recovery_candidate,
                        updated,
                    )
                    retained_carrier = callback_recovery_candidate
                else:
                    retained_carrier = (
                        _retain_claude_macos_refreshed_credential(
                            review,
                            updated,
                            requested_carrier_root=(
                                callback_recovery_candidate
                            ),
                        )
                    )
            except BaseException as recovery_error:
                failed_recovery_expectation = (
                    recovery_expectation_from_error(
                        recovery_error,
                        callback_recovery_candidate,
                    )
                    if callback_recovery_candidate is not None
                    else None
                )
                if _is_claude_control_flow_error(error):
                    _add_claude_persistence_note(error, recovery_error)
                    persistence_error = error
                elif _is_claude_control_flow_error(recovery_error):
                    _add_claude_persistence_note(recovery_error, error)
                    persistence_error = recovery_error
                else:
                    persistence_error = _failed_claude_macos_recovery_error(
                        error,
                        recovery_error,
                    )
                recovered_carrier = False
            else:
                retained_error = _retained_claude_macos_credential_error(
                    retained_carrier,
                    error,
                    expected_digest=updated_digest,
                )
                if _is_claude_control_flow_error(error):
                    _add_claude_persistence_note(error, retained_error)
                    persistence_error = error
                else:
                    persistence_error = retained_error
                recovered_carrier = True
            with runtime_state_lock:
                if runtime_is_abandoned():
                    return False
                if recovered_carrier:
                    quiescence_recovery_candidate = retained_carrier
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    quiescence_recovery_expectation = (
                        _ClaudeRecoveryExpectation(
                            retained_carrier,
                            retained_carrier
                            / "config"
                            / CLAUDE_CREDENTIAL_FILE_NAME,
                            updated_digest,
                        )
                    )
                elif (
                    callback_recovery_candidate is not None
                    and quiescence_recovery_candidate
                    == callback_recovery_candidate
                ):
                    if failed_recovery_expectation is not None:
                        quiescence_recovery_replaces_existing = True
                        quiescence_recovery_proven = True
                        quiescence_recovery_expectation = (
                            failed_recovery_expectation
                        )
                    else:
                        quiescence_recovery_proven = False
                        quiescence_recovery_expectation = None
                if not persistence_errors:
                    persistence_errors.append(persistence_error)
                else:
                    prior_error = persistence_errors[0]
                    if _is_claude_control_flow_error(prior_error):
                        if persistence_error is not prior_error:
                            _add_claude_persistence_note(
                                prior_error,
                                persistence_error,
                            )
                    else:
                        if persistence_error is not prior_error:
                            _attach_claude_credential_cleanup_failure(
                                persistence_error,
                                prior_error,
                            )
                        persistence_errors[0] = persistence_error
            return False
        finally:
            if callback_expected_credential is not None:
                callback_expected_credential[:] = (
                    b"\x00" * len(callback_expected_credential)
                )

    def abandon_unquiescent_handler() -> None:
        runtime_abandon_requested.set()

    def recover_unquiescent_handler(
        updated: bytearray | None,
    ) -> BaseException | None:
        nonlocal durable_stage_inflight
        nonlocal staged_credential
        nonlocal quiescence_durable_stage
        nonlocal quiescence_recovery_candidate
        nonlocal quiescence_recovery_proven
        nonlocal quiescence_recovery_replaces_existing
        nonlocal quiescence_recovery_expectation
        nonlocal quiescence_recovery_timeout_failure
        with runtime_state_lock:
            if (
                quiescence_durable_stage is None
                and durable_stage_inflight is not None
                and runtime_is_abandoned()
            ):
                quiescence_durable_stage = durable_stage_inflight
                durable_stage_inflight = None
            recovery_candidate = quiescence_recovery_candidate
            replace_existing = quiescence_recovery_replaces_existing
            recovery_expectation = quiescence_recovery_expectation
            recovery_proven = (
                quiescence_recovery_proven
                and recovery_expectation is not None
                and recovery_expectation.carrier == recovery_candidate
            )
            inflight_stage = quiescence_durable_stage
            staged_fallback = staged_credential
            staged_credential = None
            recovery_scope_required = (
                bool(durable_stage_carriers) or inflight_stage is not None
            )
        recovery_payload = updated if updated is not None else staged_fallback
        quiescence_error = ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker stopped before refreshed credential "
            "writeback quiescence could be proven"
        )
        setattr(
            quiescence_error,
            "_codex_claude_keychain_handler_quiescence_unproven",
            True,
        )

        def ensure_recovery_scope(
            error: BaseException,
        ) -> BaseException:
            effective_scope_required = recovery_scope_required
            retained_value = getattr(
                error,
                "_codex_claude_retained_credential_carrier",
                None,
            )
            retained_proof = _get_claude_retained_credential_proof(error)
            current_claim_present = (
                isinstance(retained_value, str) or retained_proof is not None
            )
            if (
                current_claim_present
                and not published_recovery_claim_is_current(error)
            ):
                _clear_claude_retained_credential_proof(error)
                with contextlib.suppress(AttributeError):
                    delattr(
                        error,
                        "_codex_claude_retained_credential_carrier",
                    )
                effective_scope_required = True
            if not effective_scope_required:
                return error
            try:
                recovery_root = _claude_macos_recovery_root(review)
            except BaseException as root_error:
                error = (
                    _attach_claude_persistence_failure_preserving_control_flow(
                        error,
                        root_error,
                    )
                )
            else:
                _mark_claude_macos_recovery_cleanup_artifact(
                    error,
                    recovery_root,
                )
            return error

        cleanup_late_stage = False
        wait_for_inflight_stage = False
        if inflight_stage is not None:
            with runtime_state_lock:
                if (
                    inflight_stage.completed.is_set()
                    and inflight_stage.committed
                ):
                    recovery_candidate = inflight_stage.committed_carrier
                    replace_existing = True
                    recovery_proven = True
                    quiescence_recovery_candidate = recovery_candidate
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    recovery_expectation = _ClaudeRecoveryExpectation(
                        recovery_candidate,
                        recovery_candidate
                        / "config"
                        / CLAUDE_CREDENTIAL_FILE_NAME,
                        inflight_stage.credential_digest,
                    )
                    quiescence_recovery_expectation = recovery_expectation
                elif not inflight_stage.completed.is_set():
                    inflight_stage.cleanup_after_completion = True
                    cleanup_late_stage = True
                    wait_for_inflight_stage = recovery_payload is None
        if wait_for_inflight_stage and inflight_stage is not None:
            stage_finished = inflight_stage.completed.wait(
                timeout=CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS
            )
            if not stage_finished:
                with runtime_state_lock:
                    inflight_stage.fallback_proven = False
                    timeout_failure = quiescence_recovery_timeout_failure
                inflight_stage.recovery_decided.set()
                setattr(
                    quiescence_error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                persistence_error = quiescence_error
                if timeout_failure is not None:
                    _attach_claude_credential_cleanup_failure(
                        timeout_failure,
                        quiescence_error,
                    )
                    persistence_error = timeout_failure
                return ensure_recovery_scope(persistence_error)
            with runtime_state_lock:
                if inflight_stage.committed:
                    recovery_candidate = inflight_stage.committed_carrier
                    replace_existing = True
                    recovery_proven = True
                    recovery_expectation = _ClaudeRecoveryExpectation(
                        recovery_candidate,
                        recovery_candidate
                        / "config"
                        / CLAUDE_CREDENTIAL_FILE_NAME,
                        inflight_stage.credential_digest,
                    )
                    quiescence_recovery_candidate = recovery_candidate
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    quiescence_recovery_expectation = recovery_expectation
        if recovery_payload is None:
            inflight_error = (
                inflight_stage.error if inflight_stage is not None else None
            )
            inflight_expectation = (
                recovery_expectation_from_error(
                    inflight_error,
                    inflight_stage.pending_carrier,
                    inflight_stage.committed_carrier,
                )
                if inflight_stage is not None and inflight_error is not None
                else None
            )
            if (
                inflight_expectation is not None
                and inflight_expectation.digest
                != inflight_stage.credential_digest
            ):
                inflight_expectation = None
            if inflight_expectation is not None:
                with runtime_state_lock:
                    recovery_candidate = inflight_expectation.carrier
                    replace_existing = True
                    recovery_expectation = inflight_expectation
                    recovery_proven = True
                    quiescence_recovery_candidate = recovery_candidate
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    quiescence_recovery_expectation = recovery_expectation
            retained_inflight = (
                getattr(
                    inflight_error,
                    "_codex_claude_retained_credential_carrier",
                    None,
                )
                if inflight_error is not None
                else None
            )
            if inflight_expectation is not None:
                persistence_error = inflight_error
                assert persistence_error is not None
                setattr(
                    persistence_error,
                    "_codex_claude_retained_credential_carrier",
                    str(inflight_expectation.carrier),
                )
                setattr(
                    persistence_error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
            elif recovery_candidate is not None and recovery_proven:
                assert recovery_expectation is not None
                persistence_error = _retained_claude_macos_credential_error(
                    recovery_candidate,
                    quiescence_error,
                    expected_digest=recovery_expectation.digest,
                    artifact=recovery_expectation.artifact,
                )
            elif isinstance(retained_inflight, str):
                persistence_error = inflight_error
                assert persistence_error is not None
                setattr(
                    persistence_error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
            elif inflight_stage is not None:
                setattr(
                    quiescence_error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                if inflight_error is not None:
                    if _is_claude_control_flow_error(inflight_error):
                        _add_claude_persistence_note(
                            inflight_error,
                            quiescence_error,
                        )
                        persistence_error = inflight_error
                    else:
                        _attach_claude_credential_cleanup_failure(
                            quiescence_error,
                            inflight_error,
                        )
                        persistence_error = quiescence_error
                else:
                    persistence_error = quiescence_error
            else:
                if not recovery_scope_required:
                    return None
                setattr(
                    quiescence_error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                persistence_error = quiescence_error
            setattr(
                persistence_error,
                "_codex_claude_keychain_handler_quiescence_unproven",
                True,
            )
            if cleanup_late_stage and inflight_stage is not None:
                with runtime_state_lock:
                    inflight_stage.fallback_proven = False
                inflight_stage.recovery_decided.set()
            with runtime_state_lock:
                timeout_failure = quiescence_recovery_timeout_failure
                retained_proof = _get_claude_retained_credential_proof(
                    persistence_error
                )
                if timeout_failure is not None and retained_proof is not None:
                    setattr(
                        timeout_failure,
                        "_codex_claude_retained_credential_carrier",
                        str(retained_proof.artifact.parent.parent),
                    )
                    _copy_claude_retained_credential_proof(
                        persistence_error,
                        timeout_failure,
                    )
            if timeout_failure is not None:
                _attach_claude_credential_cleanup_failure(
                    timeout_failure,
                    persistence_error,
                )
                persistence_error = timeout_failure
            return ensure_recovery_scope(persistence_error)
        if recovery_candidate is None:
            try:
                recovery_candidate = new_recovery_candidate()
            except BaseException as candidate_error:
                if cleanup_late_stage and inflight_stage is not None:
                    with runtime_state_lock:
                        inflight_stage.fallback_proven = False
                    inflight_stage.recovery_decided.set()
                if staged_fallback is not None:
                    staged_fallback[:] = b"\x00" * len(staged_fallback)
                if _is_claude_control_flow_error(candidate_error):
                    _add_claude_persistence_note(
                        candidate_error,
                        quiescence_error,
                    )
                    return ensure_recovery_scope(candidate_error)
                failure = _failed_claude_macos_recovery_error(
                    quiescence_error,
                    candidate_error,
                )
                setattr(
                    failure,
                    "_codex_claude_keychain_handler_quiescence_unproven",
                    True,
                )
                return ensure_recovery_scope(failure)
            with runtime_state_lock:
                if quiescence_recovery_candidate is None:
                    quiescence_recovery_candidate = recovery_candidate
                    quiescence_recovery_replaces_existing = False
                    quiescence_recovery_proven = False
                    quiescence_recovery_expectation = None
                else:
                    recovery_candidate = quiescence_recovery_candidate
                    replace_existing = (
                        quiescence_recovery_replaces_existing
                    )
                    recovery_expectation = quiescence_recovery_expectation
                    recovery_proven = (
                        quiescence_recovery_proven
                        and recovery_expectation is not None
                        and recovery_expectation.carrier
                        == recovery_candidate
                    )
        recovery_succeeded = False
        recovery_payload_digest = _claude_credential_digest(
            recovery_payload
        )
        try:
            if replace_existing and recovery_proven:
                _replace_claude_macos_recovery_credential(
                    review,
                    recovery_candidate,
                    recovery_payload,
                )
                retained_carrier = recovery_candidate
            else:
                retained_carrier = _retain_claude_macos_refreshed_credential(
                    review,
                    recovery_payload,
                    requested_carrier_root=recovery_candidate,
                )
        except BaseException as recovery_error:
            if recovery_proven and not isinstance(
                getattr(
                    recovery_error,
                    "_codex_claude_retained_credential_carrier",
                    None,
                ),
                str,
            ):
                setattr(
                    recovery_error,
                    "_codex_claude_retained_credential_carrier",
                    str(recovery_candidate),
                )
                setattr(
                    recovery_error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                assert recovery_expectation is not None
                _mark_claude_macos_recovery_update_artifact(
                    recovery_error,
                    recovery_expectation.artifact,
                    expected_digest=recovery_expectation.digest,
                )
            failed_recovery_expectation = recovery_expectation_from_error(
                recovery_error,
                recovery_candidate,
            )
            if _is_claude_control_flow_error(recovery_error):
                _add_claude_persistence_note(
                    recovery_error,
                    quiescence_error,
                )
                persistence_error = recovery_error
            else:
                persistence_error = _failed_claude_macos_recovery_error(
                    quiescence_error,
                    recovery_error,
                )
            with runtime_state_lock:
                if failed_recovery_expectation is not None:
                    recovery_candidate = (
                        failed_recovery_expectation.carrier
                    )
                    replace_existing = True
                    recovery_expectation = failed_recovery_expectation
                    recovery_proven = True
                    quiescence_recovery_candidate = recovery_candidate
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    quiescence_recovery_expectation = recovery_expectation
                    recovery_succeeded = hmac.compare_digest(
                        failed_recovery_expectation.digest,
                        recovery_payload_digest,
                    )
                elif quiescence_recovery_candidate == recovery_candidate:
                    recovery_proven = False
                    recovery_expectation = None
                    quiescence_recovery_proven = False
                    quiescence_recovery_expectation = None
                timeout_failure = quiescence_recovery_timeout_failure
                recovery_timed_out = timeout_failure is not None
                if (
                    timeout_failure is not None
                    and failed_recovery_expectation is not None
                ):
                    setattr(
                        timeout_failure,
                        "_codex_claude_retained_credential_carrier",
                        str(failed_recovery_expectation.carrier),
                    )
                    _copy_claude_retained_credential_proof(
                        recovery_error,
                        timeout_failure,
                    )
            if recovery_timed_out and timeout_failure is not None:
                _attach_claude_credential_cleanup_failure(
                    timeout_failure,
                    persistence_error,
                )
                persistence_error = timeout_failure
        else:
            successful_expectation = _ClaudeRecoveryExpectation(
                retained_carrier,
                retained_carrier
                / "config"
                / CLAUDE_CREDENTIAL_FILE_NAME,
                recovery_payload_digest,
            )
            with runtime_state_lock:
                timeout_failure = quiescence_recovery_timeout_failure
                recovery_timed_out = timeout_failure is not None
                if (
                    not recovery_timed_out
                    or (replace_existing and recovery_proven)
                ):
                    quiescence_recovery_candidate = retained_carrier
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    quiescence_recovery_expectation = (
                        successful_expectation
                    )
            if (
                recovery_timed_out
                and timeout_failure is not None
                and replace_existing
                and recovery_proven
            ):
                setattr(
                    timeout_failure,
                    "_codex_claude_retained_credential_carrier",
                    str(retained_carrier),
                )
                _mark_claude_macos_recovery_update_artifact(
                    timeout_failure,
                    retained_carrier
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=recovery_payload_digest,
                )
            if (
                recovery_timed_out
                and not (replace_existing and recovery_proven)
            ):
                late_cleanup_error: BaseException | None = None
                try:
                    _remove_claude_macos_recovery_carrier(
                        review,
                        retained_carrier,
                        recovery_payload_digest,
                    )
                except BaseException as error:
                    late_cleanup_error = error
                if timeout_failure is None:
                    timeout_failure = ClaudeCredentialInspectionInconclusive(
                        "Claude Keychain broker recovery finished after its "
                        "shutdown deadline"
                    )
                    setattr(
                        timeout_failure,
                        "_codex_claude_refresh_persistence_failed",
                        True,
                    )
                if late_cleanup_error is not None:
                    for attribute in (
                        "_codex_claude_retained_credential_carrier",
                        "_codex_claude_retained_cleanup_artifact",
                    ):
                        value = getattr(late_cleanup_error, attribute, None)
                        if isinstance(value, str):
                            setattr(timeout_failure, attribute, value)
                    _copy_claude_retained_credential_proof(
                        late_cleanup_error,
                        timeout_failure,
                    )
                    _attach_claude_credential_cleanup_failure(
                        timeout_failure,
                        late_cleanup_error,
                    )
                persistence_error = timeout_failure
            else:
                recovery_succeeded = True
                persistence_error = (
                    timeout_failure
                    if recovery_timed_out and timeout_failure is not None
                    else _retained_claude_macos_credential_error(
                        retained_carrier,
                        quiescence_error,
                        expected_digest=recovery_payload_digest,
                    )
                )
        if cleanup_late_stage and inflight_stage is not None:
            with runtime_state_lock:
                inflight_stage.fallback_proven = recovery_succeeded
                cleanup_in_recovery = inflight_stage.handler_wait_expired
                inflight_stage.recovery_decided.set()
            if cleanup_in_recovery and recovery_succeeded:
                try:
                    cleanup_late_durable_stage(inflight_stage)
                except BaseException as cleanup_error:
                    if _is_claude_control_flow_error(cleanup_error):
                        _add_claude_persistence_note(
                            cleanup_error,
                            persistence_error,
                        )
                        persistence_error = cleanup_error
                    else:
                        _attach_claude_credential_cleanup_failure(
                            persistence_error,
                            cleanup_error,
                        )
        if (
            inflight_stage is not None
            and inflight_stage.error is not None
            and inflight_stage.error is not persistence_error
        ):
            if _is_claude_control_flow_error(inflight_stage.error):
                _add_claude_persistence_note(
                    inflight_stage.error,
                    persistence_error,
                )
                persistence_error = inflight_stage.error
            else:
                _attach_claude_credential_cleanup_failure(
                    persistence_error,
                    inflight_stage.error,
                )
        setattr(
            persistence_error,
            "_codex_claude_keychain_handler_quiescence_unproven",
            True,
        )
        if staged_fallback is not None:
            staged_fallback[:] = b"\x00" * len(staged_fallback)
        return ensure_recovery_scope(persistence_error)

    fail_closed_scope_failure = ClaudeCredentialInspectionInconclusive(
        "Claude Keychain broker runtime abandonment state could not be "
        "captured; pending publication was closed, and the private recovery "
        "scope requires operator inspection"
    )
    setattr(
        fail_closed_scope_failure,
        "_codex_claude_refresh_persistence_failed",
        True,
    )
    setattr(
        fail_closed_scope_failure,
        "_codex_claude_keychain_handler_quiescence_unproven",
        True,
    )
    _mark_claude_macos_recovery_cleanup_artifact(
        fail_closed_scope_failure,
        fail_closed_recovery_root,
    )

    def unquiescent_fail_closed_error() -> BaseException:
        runtime_abandon_requested.set()
        return fail_closed_scope_failure

    def new_recovery_timeout_scope_failure() -> BaseException:
        failure = ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker recovery did not finish before the "
            "shutdown deadline; a complete private recovery copy could not be "
            "proven"
        )
        setattr(failure, "_codex_claude_refresh_persistence_failed", True)
        setattr(
            failure,
            "_codex_claude_keychain_handler_quiescence_unproven",
            True,
        )
        setattr(
            failure,
            "_codex_claude_retained_cleanup_artifact",
            str(fail_closed_recovery_root),
        )
        return failure

    recovery_timeout_fallback_failure = new_recovery_timeout_scope_failure()

    def unquiescent_recovery_timeout_error() -> BaseException:
        nonlocal quiescence_recovery_timeout_failure
        runtime_abandon_requested.set()
        failure = new_recovery_timeout_scope_failure()
        recovery_candidate: pathlib.Path | None = None
        recovery_proven = False
        recovery_expectation: _ClaudeRecoveryExpectation | None = None
        recovery_cleanup_scope_required = True
        quiescence_recovery_timeout_failure = failure
        state_acquired = False
        try:
            state_acquired = runtime_state_lock.acquire(blocking=False)
            if state_acquired:
                recovery_candidate = quiescence_recovery_candidate
                recovery_expectation = quiescence_recovery_expectation
                recovery_proven = (
                    quiescence_recovery_proven
                    and recovery_expectation is not None
                    and recovery_expectation.carrier == recovery_candidate
                )
                inflight_stage = (
                    quiescence_durable_stage or durable_stage_inflight
                )
                unresolved_inflight_stage = (
                    inflight_stage is not None
                    and not inflight_stage.recovery_decided.is_set()
                )
                if unresolved_inflight_stage and inflight_stage.terminal:
                    recovery_candidate = None
                    recovery_expectation = None
                    recovery_proven = False
                recovery_cleanup_scope_required = (
                    bool(durable_stage_carriers)
                    or unresolved_inflight_stage
                )
        except BaseException as state_error:
            failure = (
                _attach_claude_persistence_failure_preserving_control_flow(
                    failure,
                    state_error,
                )
            )
        finally:
            if state_acquired:
                runtime_state_lock.release()
        if recovery_candidate is not None and recovery_proven:
            assert recovery_expectation is not None
            setattr(
                failure,
                "_codex_claude_retained_credential_carrier",
                str(recovery_candidate),
            )
            _mark_claude_macos_recovery_update_artifact(
                failure,
                recovery_expectation.artifact,
                expected_digest=recovery_expectation.digest,
            )
        published_current = (
            recovery_expectation is not None
            and published_recovery_claim_is_current(
                failure,
                recovery_expectation,
            )
        )
        if recovery_proven and not published_current:
            _clear_claude_retained_credential_proof(failure)
            with contextlib.suppress(AttributeError):
                delattr(
                    failure,
                    "_codex_claude_retained_credential_carrier",
                )
        if published_current and not recovery_cleanup_scope_required:
            with contextlib.suppress(AttributeError):
                delattr(
                    failure,
                    "_codex_claude_retained_cleanup_artifact",
                )
        else:
            _mark_claude_macos_recovery_cleanup_artifact(
                failure,
                fail_closed_recovery_root,
            )
        return failure

    capability = secrets.token_bytes(CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES)
    primary_error: BaseException | None = None
    try:
        with _claude_keychain_credential_server(
            selected.payload,
            capability,
            update_callback=stage_refreshed_credential,
            quiescence_callbacks=_ClaudeKeychainQuiescenceCallbacks(
                abandon=abandon_unquiescent_handler,
                recover=recover_unquiescent_handler,
                timeout_error=unquiescent_recovery_timeout_error,
                timeout_fallback_error=recovery_timeout_fallback_failure,
                fail_closed_error=unquiescent_fail_closed_error,
                fail_closed_fallback_error=fail_closed_scope_failure,
            ),
        ) as port:
            result[CLAUDE_KEYCHAIN_BROKER_PORT_ENV] = str(port)
            result[CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV] = capability.hex()
            _update_claude_runtime_report(
                review,
                {
                    "authentication": {
                        "source": selected.source,
                        "carrier": "one-shot-security-broker",
                        "status": "sandbox-auth-staged",
                        "refresh_persistence": (
                            "durable-recovery-before-ack"
                        ),
                    }
                },
            )
            yield result
    except BaseException as error:
        primary_error = error
        raise
    finally:
        persistence_error: BaseException | None = None
        staged_for_commit: bytearray | None = None
        durable_carriers_for_cleanup: tuple[
            tuple[pathlib.Path, bytes], ...
        ] = ()
        finalization_abandoned = bool(
            primary_error is not None
            and getattr(
                primary_error,
                "_codex_claude_keychain_handler_quiescence_unproven",
                False,
            )
        ) or runtime_is_abandoned()
        if not finalization_abandoned:
            errors_for_latest_reproof: tuple[BaseException, ...] = ()
            with runtime_state_lock:
                durable_carriers_for_cleanup = tuple(
                    durable_stage_carriers
                )
                if staged_credential is not None:
                    staged_for_commit = staged_credential
                    staged_credential = None
                if durable_carriers_for_cleanup and persistence_errors:
                    errors_for_latest_reproof = tuple(persistence_errors)
            if durable_carriers_for_cleanup and errors_for_latest_reproof:
                latest_durable_carrier, latest_durable_digest = (
                    durable_carriers_for_cleanup[-1]
                )
                latest_durable_artifact = (
                    latest_durable_carrier
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME
                )
                for existing_error in errors_for_latest_reproof:
                    retained_value = getattr(
                        existing_error,
                        "_codex_claude_retained_credential_carrier",
                        None,
                    )
                    existing_proof = _get_claude_retained_credential_proof(
                        existing_error
                    )
                    if (
                        not isinstance(retained_value, str)
                        or pathlib.Path(retained_value)
                        != latest_durable_carrier
                        or existing_proof is None
                        or existing_proof.artifact != latest_durable_artifact
                        or not hmac.compare_digest(
                            existing_proof.digest,
                            latest_durable_digest,
                        )
                    ):
                        setattr(
                            existing_error,
                            "_codex_claude_retained_credential_carrier",
                            str(latest_durable_carrier),
                        )
                        _mark_claude_macos_recovery_update_artifact(
                            existing_error,
                            latest_durable_artifact,
                            expected_digest=latest_durable_digest,
                        )
        if staged_for_commit is None and durable_carriers_for_cleanup:
            with runtime_state_lock:
                if persistence_errors:
                    cleanup_primary = persistence_errors[0]
                else:
                    cleanup_primary = None
            if cleanup_primary is None:
                created_cleanup_primary = (
                    _retained_claude_macos_credential_error(
                        durable_carriers_for_cleanup[-1][0],
                        ClaudeCredentialInspectionInconclusive(
                            "Claude durable-stage finalization did not retain "
                            "a host-writeback candidate"
                        ),
                        expected_digest=durable_carriers_for_cleanup[-1][1],
                    )
                )
                with runtime_state_lock:
                    if persistence_errors:
                        cleanup_primary = persistence_errors[0]
                    else:
                        cleanup_primary = created_cleanup_primary
                        persistence_errors.append(cleanup_primary)
            assert cleanup_primary is not None
            latest_durable_carrier, latest_durable_digest = (
                durable_carriers_for_cleanup[-1]
            )
            retained_value = getattr(
                cleanup_primary,
                "_codex_claude_retained_credential_carrier",
                None,
            )
            retained_path: pathlib.Path | None = None
            retained_digest: bytes | None = None
            retained_proof_is_current = False
            retained_proof = _get_claude_retained_credential_proof(
                cleanup_primary
            )
            if isinstance(retained_value, str) and retained_proof is not None:
                candidate_path = pathlib.Path(retained_value)
                expected_artifact = (
                    candidate_path
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME
                )
                if (
                    retained_proof.artifact == expected_artifact
                    and _validated_claude_retained_credential_artifact(
                        review,
                        cleanup_primary,
                    )
                    is not None
                ):
                    retained_path = candidate_path
                    retained_digest = retained_proof.digest
                    retained_proof_is_current = True
            if retained_path is None:
                _clear_claude_retained_credential_proof(cleanup_primary)
                retained_path = latest_durable_carrier
                retained_digest = latest_durable_digest
                setattr(
                    cleanup_primary,
                    "_codex_claude_retained_credential_carrier",
                    str(retained_path),
                )
                assert retained_digest is not None
                _mark_claude_macos_recovery_update_artifact(
                    cleanup_primary,
                    retained_path
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=retained_digest,
                )
                setattr(
                    cleanup_primary,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                retained_proof = _get_claude_retained_credential_proof(
                    cleanup_primary
                )
                expected_artifact = (
                    retained_path
                    / "config"
                    / CLAUDE_CREDENTIAL_FILE_NAME
                )
                retained_proof_is_current = (
                    retained_proof is not None
                    and retained_proof.artifact == expected_artifact
                    and hmac.compare_digest(
                        retained_proof.digest,
                        retained_digest,
                    )
                    and _validated_claude_retained_credential_artifact(
                        review,
                        cleanup_primary,
                    )
                    is not None
                )
            if not retained_proof_is_current:
                _clear_claude_retained_credential_proof(cleanup_primary)
                with contextlib.suppress(AttributeError):
                    delattr(
                        cleanup_primary,
                        "_codex_claude_retained_credential_carrier",
                    )
                try:
                    recovery_root = _claude_macos_recovery_root(review)
                except BaseException as root_error:
                    preferred_primary = (
                        _attach_claude_persistence_failure_preserving_control_flow(
                            cleanup_primary,
                            root_error,
                        )
                    )
                    if preferred_primary is not cleanup_primary:
                        with runtime_state_lock:
                            persistence_errors.insert(0, preferred_primary)
                        cleanup_primary = preferred_primary
                else:
                    _mark_claude_macos_recovery_cleanup_artifact(
                        cleanup_primary,
                        recovery_root,
                    )
            cleanup_failures: list[BaseException] = []
            cleanup_targets = (
                tuple(
                    carrier
                    for carrier in durable_carriers_for_cleanup
                    if carrier[0] != retained_path
                )
                if retained_proof_is_current
                else ()
            )
            cleanup_stopped_early = False
            for cleanup_index, (
                durable_carrier,
                durable_digest,
            ) in enumerate(cleanup_targets):
                try:
                    _remove_claude_macos_recovery_carrier(
                        review,
                        durable_carrier,
                        durable_digest,
                    )
                except BaseException as cleanup_error:
                    if not isinstance(
                        getattr(
                            cleanup_error,
                            "_codex_claude_retained_cleanup_artifact",
                            None,
                        ),
                        str,
                    ):
                        _mark_claude_macos_recovery_cleanup_artifact(
                            cleanup_error,
                            durable_carrier,
                        )
                    setattr(
                        cleanup_error,
                        "_codex_claude_retained_credential_carrier",
                        str(retained_path),
                    )
                    if not _copy_claude_retained_credential_proof(
                        cleanup_primary,
                        cleanup_error,
                    ):
                        assert retained_digest is not None
                        _mark_claude_macos_recovery_update_artifact(
                            cleanup_error,
                            retained_path
                            / "config"
                            / CLAUDE_CREDENTIAL_FILE_NAME,
                            expected_digest=retained_digest,
                        )
                    cleanup_failures.append(cleanup_error)
                    if _is_claude_control_flow_error(cleanup_error):
                        cleanup_stopped_early = (
                            cleanup_index + 1 < len(cleanup_targets)
                        )
                        break
                else:
                    with runtime_state_lock:
                        durable_stage_carriers[:] = [
                            carrier
                            for carrier in durable_stage_carriers
                            if carrier[0] != durable_carrier
                        ]
            if cleanup_failures:
                cleanup_paths = {
                    value
                    for cleanup_error in cleanup_failures
                    if isinstance(
                        value := getattr(
                            cleanup_error,
                            "_codex_claude_retained_cleanup_artifact",
                            None,
                        ),
                        str,
                    )
                }
                control_flow_cleanup = next(
                    (
                        cleanup_error
                        for cleanup_error in cleanup_failures
                        if _is_claude_control_flow_error(cleanup_error)
                    ),
                    None,
                )
                if len(cleanup_paths) == 1 and not cleanup_stopped_early:
                    setattr(
                        cleanup_primary,
                        "_codex_claude_retained_cleanup_artifact",
                        next(iter(cleanup_paths)),
                    )
                else:
                    try:
                        recovery_root = _claude_macos_recovery_root(review)
                    except BaseException as root_error:
                        root_primary = (
                            control_flow_cleanup or cleanup_primary
                        )
                        preferred_primary = (
                            _attach_claude_persistence_failure_preserving_control_flow(
                                root_primary,
                                root_error,
                            )
                        )
                        if (
                            control_flow_cleanup is None
                            and preferred_primary is not cleanup_primary
                        ):
                            control_flow_cleanup = preferred_primary
                    else:
                        _mark_claude_macos_recovery_cleanup_artifact(
                            cleanup_primary,
                            recovery_root,
                        )
                if control_flow_cleanup is not None:
                    _add_claude_persistence_note(
                        control_flow_cleanup,
                        cleanup_primary,
                    )
                    with runtime_state_lock:
                        persistence_errors.insert(0, control_flow_cleanup)
                else:
                    for cleanup_error in cleanup_failures:
                        _attach_claude_credential_cleanup_failure(
                            cleanup_primary,
                            cleanup_error,
                        )
        if staged_for_commit is not None:
            accepted = False
            persistence_control_flow = False
            stale_durable_cleanup_errors: list[BaseException] = []
            stale_durable_cleanup_targets = (
                durable_carriers_for_cleanup[:-1]
            )
            try:
                latest_carrier_verified = False
                latest_readback: bytearray | None = None
                verification_error: BaseException | None = None
                try:
                    if not durable_carriers_for_cleanup:
                        raise ClaudeCredentialInspectionInconclusive(
                            "the latest durable recovery carrier is missing "
                            "before host writeback"
                        )
                    latest_carrier, latest_digest = (
                        durable_carriers_for_cleanup[-1]
                    )
                    latest_readback = (
                        _read_claude_macos_recovery_credential(
                            review,
                            latest_carrier,
                        )
                    )
                    if (
                        not hmac.compare_digest(
                            _claude_credential_digest(latest_readback),
                            latest_digest,
                        )
                        or not hmac.compare_digest(
                            latest_readback,
                            staged_for_commit,
                        )
                    ):
                        raise ClaudeCredentialInspectionInconclusive(
                            "the latest durable recovery carrier no longer "
                            "matches the acknowledged Claude credential"
                        )
                    latest_carrier_verified = True
                except BaseException as error:
                    if _is_claude_control_flow_error(error):
                        verification_error = error
                    elif (
                        isinstance(
                            error,
                            ClaudeCredentialInspectionInconclusive,
                        )
                        and "latest durable recovery carrier" in str(error)
                    ):
                        verification_error = error
                    else:
                        verification_error = (
                            ClaudeCredentialInspectionInconclusive(
                                "cannot re-verify the latest durable recovery "
                                "carrier before host writeback"
                            )
                        )
                        verification_error.__cause__ = error
                finally:
                    if latest_readback is not None:
                        latest_readback[:] = b"\x00" * len(latest_readback)

                if verification_error is not None:
                    for error in (*persistence_errors, verification_error):
                        with contextlib.suppress(AttributeError):
                            delattr(
                                error,
                                "_codex_claude_retained_credential_carrier",
                            )
                        _clear_claude_retained_credential_proof(error)
                        setattr(
                            error,
                            "_codex_claude_refresh_persistence_failed",
                            True,
                        )
                    try:
                        recovery_root = _claude_macos_recovery_root(review)
                    except BaseException as root_error:
                        verification_error = (
                            _attach_claude_persistence_failure_preserving_control_flow(
                                verification_error,
                                root_error,
                            )
                        )
                    else:
                        _mark_claude_macos_recovery_cleanup_artifact(
                            verification_error,
                            recovery_root,
                        )
                        for error in persistence_errors:
                            _mark_claude_macos_recovery_cleanup_artifact(
                                error,
                                recovery_root,
                            )
                    existing_control_flow = next(
                        (
                            error
                            for error in persistence_errors
                            if _is_claude_control_flow_error(error)
                        ),
                        None,
                    )
                    with runtime_state_lock:
                        if (
                            existing_control_flow is not None
                            and not _is_claude_control_flow_error(
                                verification_error
                            )
                        ):
                            _attach_claude_credential_cleanup_failure(
                                existing_control_flow,
                                verification_error,
                            )
                            persistence_errors.remove(
                                existing_control_flow
                            )
                            persistence_errors.insert(
                                0,
                                existing_control_flow,
                            )
                        else:
                            persistence_errors.insert(
                                0,
                                verification_error,
                            )
                    persistence_control_flow = True

                if latest_carrier_verified:
                    for stale_index, (
                        durable_carrier,
                        durable_digest,
                    ) in enumerate(stale_durable_cleanup_targets):
                        try:
                            _remove_claude_macos_recovery_carrier(
                                review,
                                durable_carrier,
                                durable_digest,
                            )
                        except BaseException as error:
                            if _is_claude_control_flow_error(error):
                                cleanup_stopped_early = (
                                    stale_index + 1
                                    < len(stale_durable_cleanup_targets)
                                )
                                if cleanup_stopped_early:
                                    try:
                                        recovery_root = (
                                            _claude_macos_recovery_root(review)
                                        )
                                    except BaseException as root_error:
                                        error = (
                                            _attach_claude_persistence_failure_preserving_control_flow(
                                                error,
                                                root_error,
                                            )
                                        )
                                    else:
                                        _mark_claude_macos_recovery_cleanup_artifact(
                                            error,
                                            recovery_root,
                                        )
                                elif not isinstance(
                                    getattr(
                                        error,
                                        (
                                            "_codex_claude_retained_"
                                            "cleanup_artifact"
                                        ),
                                        None,
                                    ),
                                    str,
                                ):
                                    _mark_claude_macos_recovery_cleanup_artifact(
                                        error,
                                        durable_carrier,
                                    )
                                (
                                    latest_carrier,
                                    latest_digest,
                                ) = durable_carriers_for_cleanup[-1]
                                setattr(
                                    error,
                                    (
                                        "_codex_claude_retained_"
                                        "credential_carrier"
                                    ),
                                    str(latest_carrier),
                                )
                                _mark_claude_macos_recovery_update_artifact(
                                    error,
                                    latest_carrier
                                    / "config"
                                    / CLAUDE_CREDENTIAL_FILE_NAME,
                                    expected_digest=latest_digest,
                                )
                                setattr(
                                    error,
                                    "_codex_claude_refresh_persistence_failed",
                                    True,
                                )
                                with runtime_state_lock:
                                    persistence_errors.insert(0, error)
                                persistence_control_flow = True
                                break
                            stale_durable_cleanup_errors.append(error)
                if not persistence_control_flow:
                    try:
                        accepted = accept_refreshed_credential(
                            staged_for_commit
                        )
                    except BaseException as error:
                        with runtime_state_lock:
                            if _is_claude_control_flow_error(error):
                                persistence_errors.insert(0, error)
                                persistence_control_flow = True
                            else:
                                persistence_errors.append(error)
                if accepted and not persistence_control_flow:
                    for durable_carrier, durable_digest in (
                        durable_carriers_for_cleanup[-1:]
                    ):
                        try:
                            _remove_claude_macos_recovery_carrier(
                                review,
                                durable_carrier,
                                durable_digest,
                            )
                        except BaseException as error:
                            with contextlib.suppress(AttributeError):
                                delattr(
                                    error,
                                    (
                                        "_codex_claude_retained_"
                                        "credential_carrier"
                                    ),
                                )
                            _clear_claude_retained_credential_proof(error)
                            with runtime_state_lock:
                                if _is_claude_control_flow_error(error):
                                    persistence_errors.insert(0, error)
                                    persistence_control_flow = True
                                else:
                                    persistence_errors.append(error)
                            if persistence_control_flow:
                                break
                if stale_durable_cleanup_errors:
                    for cleanup_error in stale_durable_cleanup_errors:
                        with contextlib.suppress(AttributeError):
                            delattr(
                                cleanup_error,
                                "_codex_claude_retained_credential_carrier",
                            )
                        _clear_claude_retained_credential_proof(
                            cleanup_error
                        )
                    with runtime_state_lock:
                        persistence_errors.extend(
                            stale_durable_cleanup_errors
                        )
            finally:
                staged_for_commit[:] = b"\x00" * len(staged_for_commit)
        if finalization_abandoned:
            cleanup_error_snapshot: tuple[BaseException, ...] = ()
        else:
            with runtime_state_lock:
                cleanup_error_snapshot = tuple(persistence_errors)
        if cleanup_error_snapshot:
            actual_cleanup_paths: set[str] = set()
            for cleanup_error in cleanup_error_snapshot:
                cleanup_value = getattr(
                    cleanup_error,
                    "_codex_claude_retained_cleanup_artifact",
                    None,
                )
                if not isinstance(cleanup_value, str):
                    continue
                try:
                    pathlib.Path(cleanup_value).lstat()
                except OSError:
                    continue
                actual_cleanup_paths.add(cleanup_value)
            cleanup_primary = cleanup_error_snapshot[0]
            primary_cleanup_value = getattr(
                cleanup_primary,
                "_codex_claude_retained_cleanup_artifact",
                None,
            )
            if (
                isinstance(primary_cleanup_value, str)
                and primary_cleanup_value not in actual_cleanup_paths
            ):
                with contextlib.suppress(AttributeError):
                    delattr(
                        cleanup_primary,
                        "_codex_claude_retained_cleanup_artifact",
                    )
            if len(actual_cleanup_paths) == 1:
                if not isinstance(
                    getattr(
                        cleanup_primary,
                        "_codex_claude_retained_cleanup_artifact",
                        None,
                    ),
                    str,
                ):
                    setattr(
                        cleanup_primary,
                        "_codex_claude_retained_cleanup_artifact",
                        next(iter(actual_cleanup_paths)),
                    )
            elif len(actual_cleanup_paths) > 1:
                try:
                    recovery_root = _claude_macos_recovery_root(review)
                except BaseException as root_error:
                    preferred_primary = (
                        _attach_claude_persistence_failure_preserving_control_flow(
                            cleanup_primary,
                            root_error,
                        )
                    )
                    if preferred_primary is not cleanup_primary:
                        with runtime_state_lock:
                            persistence_errors.insert(0, preferred_primary)
                        cleanup_primary = preferred_primary
                else:
                    _mark_claude_macos_recovery_cleanup_artifact(
                        cleanup_primary,
                        recovery_root,
                    )
        if finalization_abandoned:
            final_persistence_errors: tuple[BaseException, ...] = ()
            final_carrier_snapshot = carrier_snapshot
            final_persisted_updates = 0
            final_runtime_abandoned = True
            final_recovery_candidate = None
            final_recovery_proven = False
            final_recovery_expectation = None
            remaining_staged_credential = None
        else:
            with runtime_state_lock:
                final_persistence_errors = tuple(persistence_errors)
                final_carrier_snapshot = carrier_snapshot
                final_persisted_updates = persisted_updates
                final_runtime_abandoned = runtime_is_abandoned()
                final_recovery_candidate = quiescence_recovery_candidate
                final_recovery_expectation = quiescence_recovery_expectation
                final_recovery_proven = (
                    quiescence_recovery_proven
                    and final_recovery_expectation is not None
                    and final_recovery_expectation.carrier
                    == final_recovery_candidate
                )
                remaining_staged_credential = staged_credential
                staged_credential = None
        try:
            try:
                if (
                    final_runtime_abandoned
                    and primary_error is not None
                    and getattr(
                        primary_error,
                        "_codex_claude_refresh_persistence_failed",
                        False,
                    )
                ):
                    abandonment_errors = (
                        primary_error,
                        *final_persistence_errors,
                    )
                    persistence_error = next(
                        (
                            error
                            for error in abandonment_errors
                            if _is_claude_control_flow_error(error)
                        ),
                        primary_error,
                    )
                    for secondary in abandonment_errors:
                        if secondary is persistence_error:
                            continue
                        if (
                            _get_claude_retained_credential_proof(
                                persistence_error
                            )
                            is None
                        ):
                            _copy_claude_retained_credential_proof(
                                secondary,
                                persistence_error,
                            )
                        secondary_cleanup_artifact = getattr(
                            secondary,
                            (
                                "_codex_claude_retained_"
                                "cleanup_artifact"
                            ),
                            None,
                        )
                        if (
                            isinstance(secondary_cleanup_artifact, str)
                            and not isinstance(
                                getattr(
                                    persistence_error,
                                    (
                                        "_codex_claude_retained_"
                                        "cleanup_artifact"
                                    ),
                                    None,
                                ),
                                str,
                            )
                        ):
                            setattr(
                                persistence_error,
                                (
                                    "_codex_claude_retained_"
                                    "cleanup_artifact"
                                ),
                                secondary_cleanup_artifact,
                            )
                        if (
                            not isinstance(
                                getattr(
                                    persistence_error,
                                    (
                                        "_codex_claude_retained_"
                                        "credential_carrier"
                                    ),
                                    None,
                                ),
                                str,
                            )
                            and isinstance(
                                getattr(
                                    secondary,
                                    (
                                        "_codex_claude_retained_"
                                        "credential_carrier"
                                    ),
                                    None,
                                ),
                                str,
                            )
                        ):
                            _add_claude_persistence_note(
                                persistence_error,
                                secondary,
                            )
                        else:
                            _attach_claude_credential_cleanup_failure(
                                persistence_error,
                                secondary,
                            )
                elif final_persistence_errors:
                    persistence_error = final_persistence_errors[0]
                    for secondary in final_persistence_errors[1:]:
                        _attach_claude_credential_cleanup_failure(
                            persistence_error,
                            secondary,
                        )
                elif final_runtime_abandoned:
                    persistence_error = (
                        ClaudeCredentialInspectionInconclusive(
                            "Claude Keychain broker handler quiescence could not "
                            "be proven before runtime cleanup"
                        )
                    )
                    setattr(
                        persistence_error,
                        (
                            "_codex_claude_keychain_handler_"
                            "quiescence_unproven"
                        ),
                        True,
                    )
                    if (
                        final_recovery_candidate is not None
                        and final_recovery_proven
                    ):
                        assert final_recovery_expectation is not None
                        setattr(
                            persistence_error,
                            "_codex_claude_retained_credential_carrier",
                            str(final_recovery_candidate),
                        )
                        _mark_claude_macos_recovery_update_artifact(
                            persistence_error,
                            final_recovery_expectation.artifact,
                            expected_digest=(
                                final_recovery_expectation.digest
                            ),
                        )
                        setattr(
                            persistence_error,
                            "_codex_claude_refresh_persistence_failed",
                            True,
                        )
                    _update_claude_runtime_report(
                        review,
                        {
                            "authentication": {
                                "refresh_persistence": (
                                    "broker-shutdown-inconclusive"
                                ),
                            }
                        },
                    )
                elif not _claude_macos_carrier_snapshot_is_current(
                    review,
                    final_carrier_snapshot,
                    refresh_lock_protocol,
                ):
                    raise ClaudeCredentialInspectionInconclusive(
                        "Claude credential carriers changed while the isolated "
                        "runtime was active"
                    )
                elif final_persisted_updates:
                    _update_claude_runtime_report(
                        review,
                        {
                            "authentication": {
                                "refresh_persistence": "guarded-writeback-persisted",
                            }
                        },
                    )
                else:
                    _update_claude_runtime_report(
                        review,
                        {
                            "authentication": {
                                "refresh_persistence": (
                                    "not-needed-host-snapshot-stable"
                                ),
                            }
                        },
                    )
            except BaseException as error:
                if persistence_error is None:
                    persistence_error = error
        finally:
            if remaining_staged_credential is not None:
                remaining_staged_credential[:] = (
                    b"\x00" * len(remaining_staged_credential)
                )
            expected_credential[:] = b"\x00" * len(expected_credential)
            selected.payload[:] = b"\x00" * len(selected.payload)
        if persistence_error is not None:
            if primary_error is not None:
                if (
                    not _is_claude_control_flow_error(primary_error)
                    and _is_claude_control_flow_error(persistence_error)
                ):
                    _attach_claude_credential_cleanup_failure(
                        persistence_error,
                        primary_error,
                    )
                    _record_claude_secondary_persistence_failure(
                        review,
                        persistence_error,
                    )
                    raise persistence_error
                if isinstance(primary_error, OSError):
                    active_io_error = primary_error
                    normalized_primary = (
                        _claude_macos_runtime_io_inconclusive(
                            review,
                            active_io_error,
                        )
                    )
                    if persistence_error is not active_io_error:
                        _add_claude_persistence_note(
                            normalized_primary,
                            persistence_error,
                        )
                    _record_claude_secondary_persistence_failure(
                        review,
                        normalized_primary,
                    )
                    raise normalized_primary
                if persistence_error is primary_error:
                    _record_claude_secondary_persistence_failure(
                        review,
                        primary_error,
                    )
                else:
                    _add_claude_persistence_note(
                        primary_error,
                        persistence_error,
                    )
                    _record_claude_secondary_persistence_failure(
                        review,
                        primary_error,
                    )
            else:
                if isinstance(persistence_error, OSError):
                    persistence_error = _claude_macos_runtime_io_inconclusive(
                        review,
                        persistence_error,
                    )
                _record_claude_secondary_persistence_failure(
                    review,
                    persistence_error,
                )
                raise persistence_error


def _extract_ca_certificates(data: bytes, *, source: str) -> bytes:
    if CLAUDE_PRIVATE_KEY_MARKER.search(data):
        raise ReviewError(f"Claude review CA source contains a private key: {source}")
    blocks = CLAUDE_CERTIFICATE_BLOCK.findall(data)
    if not blocks:
        raise ReviewError(f"Claude review CA source contains no PEM certificate: {source}")
    return b"\n".join(block.strip() for block in blocks) + b"\n"


def _ca_source_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_safe_ca_source_metadata(
    metadata: os.stat_result,
    *,
    source: str,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ReviewError(f"Claude review CA source is not a regular file: {source}")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ReviewError(f"Claude review CA source has an unsafe owner: {source}")
    if metadata.st_mode & 0o022:
        raise ReviewError(
            f"Claude review CA source is group- or world-writable: {source}"
        )


def _require_safe_ca_symlink_metadata(
    metadata: os.stat_result,
    *,
    source: str,
) -> None:
    if not stat.S_ISLNK(metadata.st_mode):
        raise ReviewError(f"Claude review CA directory entry is not a symlink: {source}")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ReviewError(
            f"Claude review CA directory symlink has an unsafe owner: {source}"
        )
    # POSIX ignores symlink permission bits. The stable link identity is checked
    # here; the target retains the regular-file owner and mode requirements.


def _require_safe_ca_directory_metadata(
    metadata: os.stat_result,
    *,
    source: str,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReviewError(f"Claude review CA path is not a directory: {source}")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ReviewError(f"Claude review CA directory has an unsafe owner: {source}")
    if metadata.st_mode & 0o022:
        raise ReviewError(
            f"Claude review CA directory is group- or world-writable: {source}"
        )


def _ca_nofollow_flags(*, directory: bool) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ReviewError("Claude review CA loading requires O_NOFOLLOW support")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if directory_flag is None:
            raise ReviewError("Claude review CA loading requires O_DIRECTORY support")
        flags |= directory_flag
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _open_stable_ca_directory(path: pathlib.Path, *, source: str) -> int:
    try:
        path_before = path.lstat()
    except ReviewError:
        raise
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open a stable Claude review CA directory {source}: {error}"
        ) from error
    if stat.S_ISLNK(path_before.st_mode):
        _require_safe_ca_symlink_metadata(path_before, source=source)
        try:
            target_before = os.readlink(path)
            link_after_read = path.lstat()
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot inspect a stable Claude review CA directory symlink "
                f"{source}: {error}"
            ) from error
        if _ca_source_metadata(path_before) != _ca_source_metadata(link_after_read):
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude review CA directory symlink changed while being opened: "
                f"{source}"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if directory_flag is None:
            raise ReviewError("Claude review CA loading requires O_DIRECTORY support")
        descriptor: int | None = None
        try:
            descriptor = os.open(path, flags | directory_flag)
            opened = os.fstat(descriptor)
            _require_safe_ca_directory_metadata(opened, source=source)
            followed_after = path.stat()
            link_before_final_read = path.lstat()
            target_after = os.readlink(path)
            link_after_final_read = path.lstat()
        except ReviewError:
            if descriptor is not None:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError as error:
            if descriptor is not None:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot validate a stable Claude review CA directory symlink "
                f"{source}: {error}"
            ) from error
        if (
            _ca_source_metadata(opened) != _ca_source_metadata(followed_after)
            or _ca_source_metadata(path_before)
            != _ca_source_metadata(link_before_final_read)
            or _ca_source_metadata(link_before_final_read)
            != _ca_source_metadata(link_after_final_read)
            or target_before != target_after
        ):
            assert descriptor is not None
            os.close(descriptor)
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude review CA directory symlink changed while being opened: "
                f"{source}"
            )
        assert descriptor is not None
        return descriptor

    _require_safe_ca_directory_metadata(path_before, source=source)
    try:
        descriptor = os.open(path, _ca_nofollow_flags(directory=True))
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open a stable Claude review CA directory {source}: {error}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        _require_safe_ca_directory_metadata(opened, source=source)
        path_after = path.lstat()
    except ReviewError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot validate a stable Claude review CA directory {source}: {error}"
        ) from error
    if (
        _ca_source_metadata(path_before) != _ca_source_metadata(opened)
        or _ca_source_metadata(opened) != _ca_source_metadata(path_after)
    ):
        os.close(descriptor)
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude review CA directory changed while being opened: {source}"
        )
    return descriptor


def _read_stable_ca_descriptor(
    descriptor: int,
    *,
    source: str,
    extract_certificates: bool = True,
) -> tuple[bytes, int, os.stat_result]:
    try:
        before = os.fstat(descriptor)
        _require_safe_ca_source_metadata(before, source=source)
        if before.st_size > CLAUDE_CA_FILE_LIMIT_BYTES:
            raise ReviewError(
                f"Claude review CA source exceeds the size limit: {source}"
            )
        payload = bytearray()
        while len(payload) <= CLAUDE_CA_FILE_LIMIT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    CLAUDE_CA_FILE_LIMIT_BYTES + 1 - len(payload),
                ),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot read a stable Claude review CA source {source}: {error}"
        ) from error
    if (
        _ca_source_metadata(before) != _ca_source_metadata(after)
        or len(payload) != before.st_size
    ):
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude review CA source changed while being read: {source}"
        )
    if len(payload) > CLAUDE_CA_FILE_LIMIT_BYTES:
        raise ReviewError(f"Claude review CA source exceeds the size limit: {source}")
    material = bytes(payload)
    if extract_certificates:
        material = _extract_ca_certificates(material, source=source)
    return material, len(payload), after


def _read_ca_source_with_size(
    path: pathlib.Path,
    *,
    source: str,
) -> tuple[bytes, int]:
    try:
        descriptor = os.open(path, _ca_nofollow_flags(directory=False))
    except OSError as error:
        try:
            metadata = path.lstat()
        except OSError:
            metadata = None
        if metadata is not None:
            _require_safe_ca_source_metadata(metadata, source=source)
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open a stable Claude review CA source {source}: {error}"
        ) from error
    try:
        material, source_size, after = _read_stable_ca_descriptor(
            descriptor,
            source=source,
        )
    finally:
        os.close(descriptor)
    try:
        path_after = path.lstat()
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude review CA source changed while being read: {source}"
        ) from error
    if (
        _ca_source_metadata(after) != _ca_source_metadata(path_after)
    ):
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude review CA source changed while being read: {source}"
        )
    return material, source_size


def _read_ca_source_at_with_size(
    directory_descriptor: int,
    name: str,
    *,
    source: str,
    extract_certificates: bool = True,
) -> tuple[bytes, int]:
    try:
        descriptor = os.open(
            name,
            _ca_nofollow_flags(directory=False),
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        try:
            metadata = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            metadata = None
        if metadata is not None:
            _require_safe_ca_source_metadata(metadata, source=source)
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open a stable Claude review CA source {source}: {error}"
        ) from error
    try:
        material, source_size, after = _read_stable_ca_descriptor(
            descriptor,
            source=source,
            extract_certificates=extract_certificates,
        )
    finally:
        os.close(descriptor)
    try:
        entry_after = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude review CA source changed while being read: {source}"
        ) from error
    if _ca_source_metadata(after) != _ca_source_metadata(entry_after):
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude review CA source changed while being read: {source}"
        )
    return material, source_size


def _read_ca_source(path: pathlib.Path, *, source: str) -> bytes:
    material, _size = _read_ca_source_with_size(path, source=source)
    return material


def _open_ca_directory_at(
    directory_descriptor: int,
    name: str,
    *,
    source: str,
) -> tuple[int, os.stat_result]:
    try:
        before = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        _require_safe_ca_directory_metadata(before, source=source)
        descriptor = os.open(
            name,
            _ca_nofollow_flags(directory=True),
            dir_fd=directory_descriptor,
        )
    except ReviewError:
        raise
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open a stable Claude review CA path directory {source}: {error}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        _require_safe_ca_directory_metadata(opened, source=source)
        after = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except ReviewError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot validate a stable Claude review CA path directory {source}: "
            f"{error}"
        ) from error
    if (
        _ca_source_metadata(before) != _ca_source_metadata(opened)
        or _ca_source_metadata(opened) != _ca_source_metadata(after)
    ):
        os.close(descriptor)
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude review CA path directory changed while being opened: {source}"
        )
    return descriptor, opened


def _ca_symlink_target_components(raw_target: str) -> tuple[bool, list[str]]:
    absolute = raw_target.startswith(os.sep)
    return absolute, [
        component
        for component in raw_target.split(os.sep)
        if component not in {"", "."}
    ]


def _revalidate_ca_symlink_path(
    directory_records: list[tuple[int, os.stat_result]],
    symlink_records: list[tuple[int, str, os.stat_result, str]],
    *,
    source: str,
) -> None:
    for parent_descriptor, name, expected, expected_target in symlink_records:
        try:
            before = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _require_safe_ca_symlink_metadata(before, source=source)
            target = os.readlink(name, dir_fd=parent_descriptor)
            after = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except ReviewError:
            raise
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude review CA directory symlink changed while being read: "
                f"{source}"
            ) from error
        if (
            _ca_source_metadata(expected) != _ca_source_metadata(before)
            or _ca_source_metadata(before) != _ca_source_metadata(after)
            or target != expected_target
        ):
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude review CA directory symlink changed while being read: "
                f"{source}"
            )
    for descriptor, expected in directory_records:
        try:
            current = os.fstat(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude review CA path directory changed while being read: {source}"
            ) from error
        if _ca_source_metadata(expected) != _ca_source_metadata(current):
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude review CA path directory changed while being read: {source}"
            )


def _read_ca_path_at_with_size(
    source_directory_descriptor: int,
    entry_name: str,
    *,
    source: str,
    extract_certificates: bool = True,
) -> tuple[bytes, int]:
    owned_descriptors: list[int] = []
    directory_records: list[tuple[int, os.stat_result]] = []
    symlink_records: list[tuple[int, str, os.stat_result, str]] = []
    seen_symlinks: set[tuple[int, int]] = set()
    symlink_count = 0
    component_count = 0
    try:
        current_directory = os.dup(source_directory_descriptor)
        owned_descriptors.append(current_directory)
        source_directory_metadata = os.fstat(current_directory)
        _require_safe_ca_directory_metadata(
            source_directory_metadata,
            source=source,
        )
        directory_records.append((current_directory, source_directory_metadata))
        _absolute, pending_components = _ca_symlink_target_components(entry_name)

        while pending_components:
            component = pending_components.pop(0)
            component_count += 1
            if component_count > CLAUDE_CA_PATH_COMPONENT_LIMIT:
                raise ReviewError(
                    f"Claude review CA symlink path has too many components: {source}"
                )
            if component == "..":
                parent_descriptor, parent_metadata = _open_ca_directory_at(
                    current_directory,
                    "..",
                    source=source,
                )
                owned_descriptors.append(parent_descriptor)
                directory_records.append((parent_descriptor, parent_metadata))
                current_directory = parent_descriptor
                continue

            try:
                entry_metadata = os.stat(
                    component,
                    dir_fd=current_directory,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    f"cannot inspect a stable Claude review CA symlink path "
                    f"{source}: {error}"
                ) from error

            if stat.S_ISLNK(entry_metadata.st_mode):
                _require_safe_ca_symlink_metadata(entry_metadata, source=source)
                try:
                    raw_target = os.readlink(
                        component,
                        dir_fd=current_directory,
                    )
                    link_after_read = os.stat(
                        component,
                        dir_fd=current_directory,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        f"cannot inspect a stable Claude review CA directory "
                        f"symlink {source}: {error}"
                    ) from error
                if _ca_source_metadata(entry_metadata) != _ca_source_metadata(
                    link_after_read
                ):
                    raise ClaudeExecutableInspectionInconclusive(
                        f"Claude review CA directory symlink changed while being "
                        f"read: {source}"
                    )
                link_identity = (entry_metadata.st_dev, entry_metadata.st_ino)
                if link_identity in seen_symlinks:
                    raise ReviewError(
                        f"Claude review CA directory symlink chain contains a loop: "
                        f"{source}"
                    )
                seen_symlinks.add(link_identity)
                symlink_count += 1
                if symlink_count > CLAUDE_CA_SYMLINK_LIMIT:
                    raise ReviewError(
                        f"Claude review CA directory symlink chain exceeds the "
                        f"depth limit: {source}"
                    )
                symlink_records.append(
                    (
                        current_directory,
                        component,
                        entry_metadata,
                        raw_target,
                    )
                )
                absolute, target_components = _ca_symlink_target_components(
                    raw_target
                )
                if len(target_components) + len(pending_components) > (
                    CLAUDE_CA_PATH_COMPONENT_LIMIT
                ):
                    raise ReviewError(
                        f"Claude review CA symlink path has too many components: "
                        f"{source}"
                    )
                if absolute:
                    root_descriptor = _open_stable_ca_directory(
                        pathlib.Path(os.sep),
                        source=source,
                    )
                    owned_descriptors.append(root_descriptor)
                    root_metadata = os.fstat(root_descriptor)
                    directory_records.append((root_descriptor, root_metadata))
                    current_directory = root_descriptor
                pending_components = target_components + pending_components
                continue

            if pending_components:
                if not stat.S_ISDIR(entry_metadata.st_mode):
                    raise ReviewError(
                        f"Claude review CA symlink path component is not a "
                        f"directory: {source}"
                    )
                next_directory, next_metadata = _open_ca_directory_at(
                    current_directory,
                    component,
                    source=source,
                )
                owned_descriptors.append(next_directory)
                directory_records.append((next_directory, next_metadata))
                current_directory = next_directory
                continue

            material, source_size = _read_ca_source_at_with_size(
                current_directory,
                component,
                source=source,
                extract_certificates=extract_certificates,
            )
            _revalidate_ca_symlink_path(
                directory_records,
                symlink_records,
                source=source,
            )
            return material, source_size

        raise ReviewError(
            f"Claude review CA symlink does not resolve to a regular file: {source}"
        )
    finally:
        for descriptor in reversed(owned_descriptors):
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _read_ca_path_from_parent_with_size(
    path: pathlib.Path,
    *,
    source: str,
    extract_certificates: bool = True,
) -> tuple[bytes, int]:
    source_directory = _open_stable_ca_directory(path.parent, source=source)
    try:
        return _read_ca_path_at_with_size(
            source_directory,
            path.name,
            source=source,
            extract_certificates=extract_certificates,
        )
    finally:
        os.close(source_directory)


def _read_absolute_ca_path_with_size(
    path: pathlib.Path,
    *,
    source: str,
    extract_certificates: bool = True,
) -> tuple[bytes, int]:
    if not path.is_absolute():
        raise ReviewError(f"Claude review requires an absolute CA path: {source}")
    root_directory = _open_stable_ca_directory(pathlib.Path(os.sep), source=source)
    try:
        return _read_ca_path_at_with_size(
            root_directory,
            str(path),
            source=source,
            extract_certificates=extract_certificates,
        )
    finally:
        os.close(root_directory)


def _bounded_ca_directory_names(
    directory_descriptor: int,
    limit: int,
    *,
    too_many_message: str,
) -> list[str]:
    with os.scandir(directory_descriptor) as entries:
        names = [
            entry.name
            for entry in itertools.islice(
                entries,
                limit + 1,
            )
        ]
    if len(names) > limit:
        raise ReviewError(too_many_message)
    return sorted(names)


def _read_ca_directory_entry_at_with_size(
    directory_descriptor: int,
    name: str,
    metadata: os.stat_result,
    *,
    source: str,
    extract_certificates: bool = True,
) -> tuple[bytes, int]:
    if stat.S_ISLNK(metadata.st_mode):
        return _read_ca_path_at_with_size(
            directory_descriptor,
            name,
            source=source,
            extract_certificates=extract_certificates,
        )
    return _read_ca_source_at_with_size(
        directory_descriptor,
        name,
        source=source,
        extract_certificates=extract_certificates,
    )


def _write_private_ca_file(path: pathlib.Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = pathlib.Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary_path.unlink()


def _validate_ca_file(path: pathlib.Path) -> None:
    try:
        ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError) as error:
        raise ReviewError(f"Claude review CA bundle is invalid: {path.name}") from error


def _prepare_claude_tls_environment(
    review: ReviewWorkspace,
    env: dict[str, str],
) -> dict[str, str]:
    result = dict(env)
    ca_root = review.container_dir / "claude-ca"
    ca_root.mkdir(mode=0o700, exist_ok=True)
    if ca_root.is_symlink() or not ca_root.is_dir():
        raise ReviewError("Claude review CA directory is not a real directory")
    for key in CLAUDE_TLS_FILE_ENV_KEYS:
        raw = result.get(key)
        if not raw:
            continue
        source_path = pathlib.Path(raw)
        if not source_path.is_absolute():
            raise ReviewError(f"Claude review requires valid absolute {key}")
        destination = ca_root / f"{key.lower()}.pem"
        _write_private_ca_file(
            destination,
            _read_ca_source(source_path, source=key),
        )
        _validate_ca_file(destination)
        result[key] = str(destination)

    for key in CLAUDE_TLS_DIR_ENV_KEYS:
        raw_entries = [entry for entry in result.get(key, "").split(os.pathsep) if entry]
        if not raw_entries:
            continue
        destination_root = pathlib.Path(
            tempfile.mkdtemp(prefix=f"{key.lower()}-", dir=ca_root)
        )
        prepared_dirs: list[pathlib.Path] = []
        total_size = 0
        entry_count = 0
        for index, raw in enumerate(raw_entries):
            source_dir = pathlib.Path(raw)
            if not source_dir.is_absolute():
                raise ReviewError(
                    f"Claude review requires valid absolute {key} entries"
                )
            destination_dir = destination_root / f"{index:04d}"
            destination_dir.mkdir(mode=0o700)
            copied = False
            source_directory = _open_stable_ca_directory(source_dir, source=key)
            try:
                directory_before = os.fstat(source_directory)
                remaining_entries = CLAUDE_CA_DIR_ENTRY_LIMIT - entry_count
                source_names = _bounded_ca_directory_names(
                    source_directory,
                    remaining_entries,
                    too_many_message=(
                        "Claude review CA directory has too many entries"
                    ),
                )
                entry_count += len(source_names)
                for source_name in source_names:
                    try:
                        entry_metadata = os.stat(
                            source_name,
                            dir_fd=source_directory,
                            follow_symlinks=False,
                        )
                    except OSError as error:
                        raise ClaudeExecutableInspectionInconclusive(
                            f"cannot inspect Claude review CA directory entry: "
                            f"{error}"
                        ) from error
                    if stat.S_ISDIR(entry_metadata.st_mode):
                        continue
                    raw_material, source_size = (
                        _read_ca_directory_entry_at_with_size(
                            source_directory,
                            source_name,
                            entry_metadata,
                            source=f"{key}:{source_name}",
                            extract_certificates=False,
                        )
                    )
                    total_size += source_size
                    if total_size > CLAUDE_CA_DIR_LIMIT_BYTES:
                        raise ReviewError(
                            "Claude review CA directory exceeds the size limit"
                        )
                    try:
                        material = _extract_ca_certificates(
                            raw_material,
                            source=f"{key}:{source_name}",
                        )
                    except ReviewError as error:
                        if "contains no PEM certificate" in str(error):
                            continue
                        raise
                    destination = destination_dir / source_name
                    _write_private_ca_file(destination, material)
                    _validate_ca_file(destination)
                    copied = True
                directory_after = os.fstat(source_directory)
                if _ca_source_metadata(directory_before) != _ca_source_metadata(
                    directory_after
                ):
                    raise ClaudeExecutableInspectionInconclusive(
                        "Claude review CA directory changed while being read"
                    )
            finally:
                os.close(source_directory)
            if copied:
                prepared_dirs.append(destination_dir)
            else:
                destination_dir.rmdir()
        if not prepared_dirs:
            raise ReviewError("Claude review CA directory contains no PEM certificates")
        result[key] = os.pathsep.join(str(path) for path in prepared_dirs)
    return result


def _read_proxy_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > CLAUDE_PROXY_HEADER_LIMIT_BYTES:
            raise ReviewError("Claude review proxy headers exceeded the size limit")
    return bytes(data)


def _upstream_proxy_url(
    env: dict[str, str],
    *,
    host: str,
    port: int,
) -> str | None:
    no_proxy = env.get("no_proxy") if "no_proxy" in env else env.get("NO_PROXY")
    if no_proxy and urllib.request.proxy_bypass_environment(
        f"{host}:{port}",
        {"no": no_proxy},
    ):
        return None
    for lowercase, uppercase in (
        ("https_proxy", "HTTPS_PROXY"),
        ("http_proxy", "HTTP_PROXY"),
        ("all_proxy", "ALL_PROXY"),
    ):
        if lowercase in env:
            value = env[lowercase]
        else:
            value = env.get(uppercase)
        if value:
            return value
    return None


def _proxy_ssl_context(env: dict[str, str]) -> ssl.SSLContext:
    cafile = next(
        (
            env[key]
            for key in (
                "SSL_CERT_FILE",
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
                "GIT_SSL_CAINFO",
            )
            if env.get(key)
        ),
        None,
    )
    context = ssl.create_default_context(cafile=cafile)
    for raw in env.get("SSL_CERT_DIR", "").split(os.pathsep):
        if raw:
            context.load_verify_locations(capath=raw)
    return context


def _parse_upstream_proxy_url(
    upstream_url: str,
) -> tuple[urllib.parse.SplitResult, int]:
    try:
        parsed = urllib.parse.urlsplit(upstream_url)
        hostname = parsed.hostname
        explicit_port = parsed.port
    except ValueError as error:
        raise ReviewError("Claude review upstream proxy URL is invalid") from error
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ReviewError(
            "Claude review proxy supports only HTTP(S) upstream proxies"
        )
    proxy_port = (
        explicit_port
        if explicit_port is not None
        else (443 if parsed.scheme == "https" else 80)
    )
    if not 1 <= proxy_port <= 65535:
        raise ReviewError("Claude review upstream proxy port is invalid")
    return parsed, proxy_port


def _open_proxy_target(
    host: str,
    port: int,
    *,
    env: dict[str, str],
) -> socket.socket:
    upstream_url = _upstream_proxy_url(env, host=host, port=port)
    if upstream_url is None:
        return socket.create_connection(
            (host, port),
            timeout=CLAUDE_PROXY_CONNECT_TIMEOUT_SECONDS,
        )
    parsed, proxy_port = _parse_upstream_proxy_url(upstream_url)
    connection = socket.create_connection(
        (parsed.hostname, proxy_port),
        timeout=CLAUDE_PROXY_CONNECT_TIMEOUT_SECONDS,
    )
    if parsed.scheme == "https":
        connection = _proxy_ssl_context(env).wrap_socket(
            connection,
            server_hostname=parsed.hostname,
        )
    headers = [
        f"CONNECT {host}:{port} HTTP/1.1",
        f"Host: {host}:{port}",
    ]
    if parsed.username is not None:
        username = urllib.parse.unquote(parsed.username)
        password = urllib.parse.unquote(parsed.password or "")
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    connection.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    response = _read_proxy_headers(connection)
    status_line = response.split(b"\r\n", 1)[0]
    if not re.fullmatch(rb"HTTP/1\.[01] 2\d\d(?: .*)?", status_line):
        connection.close()
        raise ReviewError("upstream proxy refused the Anthropic CONNECT request")
    return connection


def _parse_connect_target(authority: str) -> tuple[str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(f"//{authority}")
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if host is None or port is None:
        return None
    return host.lower().rstrip("."), port


def _tunnel_proxy_sockets(client: socket.socket, upstream: socket.socket) -> None:
    sockets = (client, upstream)
    for current in sockets:
        current.settimeout(None)
    while True:
        readable = tuple(
            current
            for current in sockets
            if isinstance(current, ssl.SSLSocket) and current.pending() > 0
        )
        if not readable:
            readable, _, _ = select.select(sockets, (), (), 1.0)
        for current in readable:
            data = current.recv(64 * 1024)
            if not data:
                return
            target = upstream if current is client else client
            target.sendall(data)


class _ClaudeProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        client.settimeout(CLAUDE_PROXY_CONNECT_TIMEOUT_SECONDS)
        upstream: socket.socket | None = None
        try:
            headers = _read_proxy_headers(client)
            request_line = headers.split(b"\r\n", 1)[0].decode(
                "ascii", errors="replace"
            )
            parts = request_line.split()
            target = (
                _parse_connect_target(parts[1])
                if len(parts) == 3 and parts[0].upper() == "CONNECT"
                else None
            )
            server = self.server
            if not isinstance(server, (_ClaudeProxyServer, _ClaudeUnixProxyServer)):
                raise ReviewError("invalid Claude review proxy server")
            if target not in server.allowed_targets:
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                return
            upstream = _open_proxy_target(*target, env=server.upstream_env)
            client.sendall(
                b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n"
            )
            _tunnel_proxy_sockets(client, upstream)
        except (OSError, ReviewError):
            with contextlib.suppress(OSError):
                client.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
                )
        finally:
            if upstream is not None:
                upstream.close()


def _claude_thread_may_have_started(thread: threading.Thread) -> bool:
    ident = thread.ident
    return isinstance(ident, int) and not isinstance(ident, bool)


class _ClaudeProxyServeState:
    def _initialize_serve_state(self) -> None:
        self._serve_condition = threading.Condition()
        self._serving = False
        self._serve_stopped = False
        self._serve_error: BaseException | None = None

    def service_actions(self) -> None:
        with self._serve_condition:
            if not self._serving:
                self._serving = True
                self._serve_condition.notify_all()

    def record_serve_stopped(self, error: BaseException | None) -> None:
        with self._serve_condition:
            self._serve_stopped = True
            self._serve_error = error
            self._serve_condition.notify_all()

    def wait_until_serving(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._serve_condition:
            while not self._serving and not self._serve_stopped:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._serve_condition.wait(timeout=remaining)
            return self._serving and not self._serve_stopped

    def is_serving(self) -> bool:
        with self._serve_condition:
            return self._serving and not self._serve_stopped

    def serve_error(self) -> BaseException | None:
        with self._serve_condition:
            return self._serve_error


class _ClaudeProxyServer(
    _ClaudeProxyServeState,
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(
        self,
        *,
        allowed_targets: frozenset[tuple[str, int]],
        upstream_env: dict[str, str],
    ) -> None:
        self.allowed_targets = allowed_targets
        self.upstream_env = dict(upstream_env)
        super().__init__(("127.0.0.1", 0), _ClaudeProxyHandler)
        self._initialize_serve_state()


class _ClaudeUnixProxyServer(
    _ClaudeProxyServeState,
    socketserver.ThreadingMixIn,
    socketserver.UnixStreamServer,
):
    daemon_threads = True

    def __init__(
        self,
        socket_path: pathlib.Path,
        *,
        allowed_targets: frozenset[tuple[str, int]],
        upstream_env: dict[str, str],
    ) -> None:
        self.allowed_targets = allowed_targets
        self.upstream_env = dict(upstream_env)
        super().__init__(str(socket_path), _ClaudeProxyHandler)
        self._initialize_serve_state()


def _shutdown_claude_proxy_server(
    server: _ClaudeProxyServeState,
    thread: threading.Thread | None,
    *,
    thread_started: bool,
    primary_error: BaseException | None,
    socket_path: pathlib.Path | None = None,
) -> None:
    cleanup_errors: list[BaseException] = []
    post_start_serve_error = False
    serving = False
    if thread_started:
        try:
            serving = server.is_serving()
        except BaseException as error:
            cleanup_errors.append(error)
    if serving:
        try:
            server.shutdown()  # type: ignore[attr-defined]
        except BaseException as error:
            cleanup_errors.append(error)
    try:
        server.server_close()  # type: ignore[attr-defined]
    except BaseException as error:
        cleanup_errors.append(error)
    if thread_started and thread is not None:
        thread_stopped = False
        try:
            thread.join(timeout=CLAUDE_PROXY_SERVER_SHUTDOWN_TIMEOUT_SECONDS)
        except BaseException as error:
            cleanup_errors.append(error)
        else:
            try:
                thread_alive = thread.is_alive()
            except BaseException as error:
                cleanup_errors.append(error)
            else:
                if thread_alive:
                    cleanup_errors.append(
                        ClaudeCredentialInspectionInconclusive(
                            "Claude CONNECT proxy thread did not stop before the "
                            "shutdown deadline"
                        )
                    )
                else:
                    thread_stopped = True
        if thread_stopped:
            try:
                serve_error = server.serve_error()
            except BaseException as error:
                cleanup_errors.append(error)
            else:
                if serve_error is not None and not (
                    _claude_visible_error_chain_contains(
                        primary_error,
                        serve_error,
                    )
                ):
                    cleanup_errors.insert(0, serve_error)
                    post_start_serve_error = True
    if socket_path is not None:
        try:
            socket_path.unlink(missing_ok=True)
        except BaseException as error:
            cleanup_errors.append(error)
    _raise_or_attach_claude_credential_cleanup(
        primary_error,
        cleanup_errors,
        message=(
            "Claude CONNECT proxy serve loop failed after startup"
            if post_start_serve_error
            else "cannot clean up the Claude CONNECT proxy safely"
        ),
    )


@contextlib.contextmanager
def _claude_connect_proxy(
    env: dict[str, str],
    *,
    allowed_targets: frozenset[tuple[str, int]] = CLAUDE_PROXY_TARGETS,
) -> Iterator[int]:
    for host, port in allowed_targets:
        upstream_url = _upstream_proxy_url(env, host=host, port=port)
        if upstream_url is not None:
            _parse_upstream_proxy_url(upstream_url)
    try:
        server = _ClaudeProxyServer(
            allowed_targets=allowed_targets,
            upstream_env=env,
        )
    except OSError as error:
        failure_type = (
            ClaudeLoopbackUnavailable
            if _claude_loopback_bind_is_deterministically_unavailable(error)
            else ClaudeCredentialInspectionInconclusive
        )
        raise failure_type(
            f"Claude CONNECT proxy cannot bind loopback: {error}"
        ) from error
    thread: threading.Thread | None = None
    thread_started = False
    serve_admitted = False
    serve_gate = threading.Event()
    serve_cancelled = threading.Event()
    primary_error: BaseException | None = None

    def serve() -> None:
        serve_error: BaseException | None = None
        try:
            serve_gate.wait()
            if serve_cancelled.is_set():
                return
            server.serve_forever(
                poll_interval=CLAUDE_PROXY_SERVER_POLL_INTERVAL_SECONDS
            )
        except BaseException as error:
            serve_error = error
        finally:
            server.record_serve_stopped(serve_error)

    try:
        try:
            thread = threading.Thread(
                target=serve,
                name="claude-review-connect-proxy",
                daemon=True,
            )
        except ForwardedSignal:
            raise
        except Exception as error:
            raise ClaudeCredentialInspectionInconclusive(
                f"Claude CONNECT proxy cannot construct its thread: {error}"
            ) from error
        try:
            thread.start()
            thread_started = True
        except ForwardedSignal:
            thread_started = _claude_thread_may_have_started(thread)
            raise
        except RuntimeError as error:
            thread_started = _claude_thread_may_have_started(thread)
            raise ClaudeCredentialInspectionInconclusive(
                f"Claude CONNECT proxy cannot start: {error}"
            ) from error
        serve_admitted = True
        serve_gate.set()
        if not server.wait_until_serving(
            CLAUDE_PROXY_SERVER_START_TIMEOUT_SECONDS
        ):
            failure = ClaudeCredentialInspectionInconclusive(
                "Claude CONNECT proxy did not enter its serve loop"
            )
            serve_error = server.serve_error()
            if serve_error is not None:
                failure.__cause__ = serve_error
            raise failure
        yield int(server.server_address[1])
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if not serve_admitted:
            serve_cancelled.set()
        serve_gate.set()
        if thread is not None and not thread_started:
            thread_started = _claude_thread_may_have_started(thread)
        _shutdown_claude_proxy_server(
            server,
            thread,
            thread_started=thread_started,
            primary_error=primary_error,
        )


@contextlib.contextmanager
def _claude_unix_connect_proxy(
    _review: ReviewWorkspace,
    env: dict[str, str],
    *,
    allowed_targets: frozenset[tuple[str, int]] = CLAUDE_PROXY_TARGETS,
) -> Iterator[pathlib.Path]:
    for host, port in allowed_targets:
        upstream_url = _upstream_proxy_url(env, host=host, port=port)
        if upstream_url is not None:
            _parse_upstream_proxy_url(upstream_url)
    with tempfile.TemporaryDirectory(
        prefix="codex-claude-proxy-",
        dir="/tmp",
    ) as raw_socket_dir:
        socket_dir = pathlib.Path(raw_socket_dir)
        try:
            socket_dir.chmod(0o700)
        except ForwardedSignal:
            raise
        except OSError as error:
            raise ClaudeCredentialInspectionInconclusive(
                "Claude CONNECT proxy cannot make its private Unix proxy "
                f"directory safe: {error}"
            ) from error
        socket_path = socket_dir / "p.sock"
        try:
            server = _ClaudeUnixProxyServer(
                socket_path,
                allowed_targets=allowed_targets,
                upstream_env=env,
            )
        except OSError as error:
            failure_type = (
                ClaudeLoopbackUnavailable
                if _claude_unix_bind_is_deterministically_unavailable(error)
                else ClaudeCredentialInspectionInconclusive
            )
            raise failure_type(
                f"Claude CONNECT proxy cannot bind a private Unix socket: {error}"
            ) from error
        try:
            socket_path.chmod(0o600)
        except OSError as error:
            failure = ClaudeCredentialInspectionInconclusive(
                "Claude CONNECT proxy cannot make its Unix socket private: "
                f"{error}"
            )
            failure.__cause__ = error
            cleanup_errors: list[BaseException] = []
            try:
                server.server_close()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            try:
                socket_path.unlink(missing_ok=True)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            _raise_or_attach_claude_credential_cleanup(
                failure,
                cleanup_errors,
                message="cannot clean up the failed Claude Unix CONNECT proxy",
            )
            raise failure
        thread: threading.Thread | None = None
        thread_started = False
        serve_admitted = False
        serve_gate = threading.Event()
        serve_cancelled = threading.Event()
        primary_error: BaseException | None = None

        def serve() -> None:
            serve_error: BaseException | None = None
            try:
                serve_gate.wait()
                if serve_cancelled.is_set():
                    return
                server.serve_forever(
                    poll_interval=CLAUDE_PROXY_SERVER_POLL_INTERVAL_SECONDS
                )
            except BaseException as error:
                serve_error = error
            finally:
                server.record_serve_stopped(serve_error)

        try:
            try:
                thread = threading.Thread(
                    target=serve,
                    name="claude-review-unix-connect-proxy",
                    daemon=True,
                )
            except ForwardedSignal:
                raise
            except Exception as error:
                raise ClaudeCredentialInspectionInconclusive(
                    "Claude Unix CONNECT proxy cannot construct its thread: "
                    f"{error}"
                ) from error
            try:
                thread.start()
                thread_started = True
            except ForwardedSignal:
                thread_started = _claude_thread_may_have_started(thread)
                raise
            except RuntimeError as error:
                thread_started = _claude_thread_may_have_started(thread)
                raise ClaudeCredentialInspectionInconclusive(
                    f"Claude Unix CONNECT proxy cannot start: {error}"
                ) from error
            serve_admitted = True
            serve_gate.set()
            if not server.wait_until_serving(
                CLAUDE_PROXY_SERVER_START_TIMEOUT_SECONDS
            ):
                failure = ClaudeCredentialInspectionInconclusive(
                    "Claude Unix CONNECT proxy did not enter its serve loop"
                )
                serve_error = server.serve_error()
                if serve_error is not None:
                    failure.__cause__ = serve_error
                raise failure
            yield socket_path.resolve(strict=True)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            if not serve_admitted:
                serve_cancelled.set()
            serve_gate.set()
            if thread is not None and not thread_started:
                thread_started = _claude_thread_may_have_started(thread)
            _shutdown_claude_proxy_server(
                server,
                thread,
                thread_started=thread_started,
                primary_error=primary_error,
                socket_path=socket_path,
            )


def _with_claude_proxy_environment(
    env: dict[str, str],
    port: int,
) -> dict[str, str]:
    result = dict(env)
    proxy_url = f"http://127.0.0.1:{port}"
    for key in (
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
    ):
        result[key] = proxy_url
    result["NO_PROXY"] = ""
    result["no_proxy"] = ""
    return result


def _review_environment(
    *,
    review: ReviewWorkspace,
    passthrough_keys: Iterable[str],
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    review_values = {
        "CODEX_ISOLATED_REVIEW_ROOT": str(review.workspace_root),
        "CODEX_ISOLATED_REVIEW_DIFF_FILE": str(review.diff_file),
        "CODEX_ISOLATED_REVIEW_PROMPT_FILE": str(review.prompt_file),
        "CODEX_ISOLATED_REVIEW_RANGE": f"{review.base_ref}..{review.head_ref}",
    }
    if extra:
        review_values.update(extra)
    return child_environment(
        container_dir=review.container_dir,
        passthrough_keys=passthrough_keys,
        extra=review_values,
    )


def _with_executable_path(
    env: dict[str, str],
    executable: pathlib.Path,
) -> dict[str, str]:
    result = dict(env)
    result["PATH"] = reviewer_executable_path(
        executable,
        base_path=result.get("PATH", ""),
    )
    return result


def _trusted_claude_ripgrep() -> pathlib.Path | None:
    if _is_claude_linux_host():
        try:
            return discover_claude_linux_toolchain(_claude_linux_host()).rg
        except (LinuxUnsupportedHost, LinuxIsolationUnavailable) as error:
            raise ClaudeReviewToolUnavailable(str(error)) from error
        except LinuxRuntimeInspectionInconclusive as error:
            raise ClaudeExecutableInspectionInconclusive(str(error)) from error
        except LinuxRuntimeUnsafe:
            raise
    for path in CLAUDE_REVIEW_TOOL_EXECUTABLE_CANDIDATES:
        if path.name != "rg" or not path.is_file() or not os.access(path, os.X_OK):
            continue
        try:
            _native_macho_dependencies(path, label="ripgrep")
        except InvalidReviewerExecutable:
            continue
        return path
    return None


def _with_claude_review_tool_path(
    review: ReviewWorkspace,
    env: dict[str, str],
) -> dict[str, str]:
    rg = _trusted_claude_ripgrep()
    if rg is None:
        raise ClaudeReviewToolUnavailable(
            "Claude Code Grep sandbox requires ripgrep in a trusted path"
        )
    if not _is_claude_linux_host():
        try:
            _native_macho_dependencies(rg, label="ripgrep")
        except InvalidReviewerExecutable as error:
            raise ClaudeReviewToolUnavailable(str(error)) from error
    entries: list[pathlib.Path] = []
    if not _is_claude_linux_host() and not env.get("ANTHROPIC_API_KEY"):
        broker_dir = (
            review.container_dir.resolve() / "claude-runtime" / "keychain-broker"
        )
        security = broker_dir / "security"
        if not security.is_file() or not os.access(security, os.X_OK):
            raise ReviewError(
                "Claude local-login sandbox requires the restricted Keychain broker"
            )
        entries.append(broker_dir)
    entries.append(rg.absolute().parent)
    result = dict(env)
    result["PATH"] = os.pathsep.join(
        dict.fromkeys(str(entry) for entry in entries)
    )
    return result


def _claude_linux_runtime_root(review: ReviewWorkspace) -> pathlib.Path:
    runtime_parent = _create_or_validate_claude_runtime_directory(
        review.container_dir.resolve(strict=True) / "claude-runtime",
        private=False,
    )
    root = runtime_parent / "linux"
    try:
        reject_claude_wsl_windows_path(root, _claude_linux_host())
    except LinuxRuntimeInspectionInconclusive as error:
        raise ClaudeExecutableInspectionInconclusive(str(error)) from error
    return _create_or_validate_claude_runtime_directory(root, private=True)


def _claude_linux_private_directory(
    review: ReviewWorkspace,
    name: str,
) -> pathlib.Path:
    path = _claude_linux_runtime_root(review) / name
    return _create_or_validate_claude_runtime_directory(path, private=True)


def _claude_linux_credential_source() -> pathlib.Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    if configured:
        config_dir = pathlib.Path(configured).expanduser()
        if not config_dir.is_absolute():
            raise ReviewError("CLAUDE_CONFIG_DIR must be absolute for Linux review")
    else:
        home = os.environ.get("HOME")
        if not home:
            raise ClaudeKeychainCredentialUnavailable(
                "Claude Linux local-login credential requires HOME"
            )
        config_dir = pathlib.Path(home).expanduser() / ".claude"
    source = config_dir / ".credentials.json"
    try:
        reject_claude_wsl_windows_path(source, _claude_linux_host())
    except LinuxRuntimeInspectionInconclusive as error:
        raise ClaudeExecutableInspectionInconclusive(str(error)) from error
    except LinuxRuntimeError as error:
        raise ReviewError(str(error)) from error
    return source


def _claude_linux_ca_bundle(
    review: ReviewWorkspace,
    env: dict[str, str],
) -> pathlib.Path:
    blocks: list[bytes] = []
    seen: set[bytes] = set()
    total_input = 0
    total_output = 0

    def add_material(material: bytes, source_size: int, *, source: str) -> None:
        nonlocal total_input, total_output
        total_input += source_size
        if total_input > CLAUDE_CA_DIR_LIMIT_BYTES:
            raise ReviewError("Claude Linux CA input exceeds the size limit")
        try:
            certificates = _extract_ca_certificates(material, source=source)
        except ReviewError as error:
            if "contains no PEM certificate" in str(error):
                return
            raise
        for block in CLAUDE_CERTIFICATE_BLOCK.findall(certificates):
            normalized = block.strip() + b"\n"
            if normalized in seen:
                continue
            total_output += len(normalized)
            if total_output > CLAUDE_CA_DIR_LIMIT_BYTES:
                raise ReviewError("Claude Linux CA material exceeds the size limit")
            seen.add(normalized)
            blocks.append(normalized)

    entry_count = 0

    def add_directory(directory: pathlib.Path, *, source: str) -> None:
        nonlocal entry_count
        directory_descriptor = _open_stable_ca_directory(
            directory,
            source=source,
        )
        try:
            directory_before = os.fstat(directory_descriptor)
            remaining_entries = CLAUDE_CA_DIR_ENTRY_LIMIT - entry_count
            entries = _bounded_ca_directory_names(
                directory_descriptor,
                remaining_entries,
                too_many_message=(
                    "Claude Linux CA directories have too many entries"
                ),
            )
            entry_count += len(entries)
            for entry in entries:
                try:
                    metadata = os.stat(
                        entry,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        f"cannot inspect Claude Linux CA directory entry: {error}"
                    ) from error
                if stat.S_ISDIR(metadata.st_mode):
                    continue
                material, source_size = _read_ca_directory_entry_at_with_size(
                    directory_descriptor,
                    entry,
                    metadata,
                    source=f"{source}:{entry}",
                    extract_certificates=False,
                )
                add_material(
                    material,
                    source_size,
                    source=f"{source}:{entry}",
                )
            directory_after = os.fstat(directory_descriptor)
            if _ca_source_metadata(directory_before) != _ca_source_metadata(
                directory_after
            ):
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude Linux CA directory changed while being read"
                )
        finally:
            os.close(directory_descriptor)

    def path_is_missing(error: BaseException) -> bool:
        cause: BaseException | None = error
        while cause is not None and not isinstance(cause, FileNotFoundError):
            cause = cause.__cause__
        return isinstance(cause, FileNotFoundError)

    replacement_configured = False
    for key in CLAUDE_TLS_REPLACEMENT_FILE_ENV_KEYS:
        raw = env.get(key)
        if not raw:
            continue
        replacement_configured = True
        source = pathlib.Path(raw)
        if not source.is_absolute():
            raise ReviewError(f"Claude Linux requires an absolute {key}")
        material, source_size = _read_ca_path_from_parent_with_size(
            source,
            source=key,
            extract_certificates=False,
        )
        add_material(material, source_size, source=key)
    for key in CLAUDE_TLS_DIR_ENV_KEYS:
        for raw in env.get(key, "").split(os.pathsep):
            if not raw:
                continue
            replacement_configured = True
            directory = pathlib.Path(raw)
            if not directory.is_absolute():
                raise ReviewError(f"Claude Linux requires absolute {key} entries")
            add_directory(directory, source=key)
    if not replacement_configured:
        defaults = ssl.get_default_verify_paths()
        for raw in dict.fromkeys(
            raw
            for raw in (
                defaults.cafile,
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/ssl/cert.pem",
                "/etc/pki/tls/certs/ca-bundle.crt",
            )
            if raw
        ):
            source = pathlib.Path(raw)
            if not source.is_absolute():
                continue
            try:
                material, source_size = _read_absolute_ca_path_with_size(
                    source,
                    source="Linux default CA bundle",
                    extract_certificates=False,
                )
            except ClaudeExecutableInspectionInconclusive as error:
                if path_is_missing(error):
                    continue
                raise
            add_material(
                material,
                source_size,
                source="Linux default CA bundle",
            )
        if defaults.capath:
            default_directory = pathlib.Path(defaults.capath)
            if default_directory.is_absolute():
                try:
                    add_directory(
                        default_directory,
                        source="Linux default CA directory",
                    )
                except ClaudeExecutableInspectionInconclusive as error:
                    if not path_is_missing(error):
                        raise
    for key in CLAUDE_TLS_ADDITIVE_FILE_ENV_KEYS:
        raw = env.get(key)
        if not raw:
            continue
        source = pathlib.Path(raw)
        if not source.is_absolute():
            raise ReviewError(f"Claude Linux requires an absolute {key}")
        material, source_size = _read_ca_path_from_parent_with_size(
            source,
            source=key,
            extract_certificates=False,
        )
        add_material(material, source_size, source=key)
    if not blocks:
        raise ClaudeProbeSandboxUnavailable(
            "Claude Linux review requires a usable PEM CA bundle"
        )
    destination = _claude_linux_private_directory(review, "ca") / "bundle.pem"
    _write_private_ca_file(destination, b"".join(blocks))
    _validate_ca_file(destination)
    return destination


def _claude_probe_command(
    executable: pathlib.Path,
    probe_cwd: pathlib.Path,
    *args: str,
) -> tuple[str, ...]:
    if _is_claude_linux_host():
        try:
            host = _claude_linux_host()
            info = validate_claude_linux_executable(executable, host)
            toolchain = discover_claude_linux_toolchain(host)
            return build_claude_linux_probe_command(
                host,
                toolchain,
                info.path,
                probe_cwd,
                (),
                args,
                library_roots=_claude_linux_bootstrap_library_roots(),
            )
        except (LinuxUnsupportedHost, LinuxIsolationUnavailable) as error:
            raise ClaudeProbeSandboxUnavailable(str(error)) from error
        except LinuxRuntimeInspectionInconclusive as error:
            raise ClaudeExecutableInspectionInconclusive(str(error)) from error
        except LinuxRuntimeUnsafe:
            raise
        except LinuxRuntimeError as error:
            raise InvalidReviewerExecutable(str(error)) from error
    if not CLAUDE_PROBE_SANDBOX.is_file() or not os.access(
        CLAUDE_PROBE_SANDBOX, os.X_OK
    ):
        raise ClaudeProbeSandboxUnavailable(
            "Claude Code review requires macOS sandbox-exec for preflight probes"
        )
    return (
        str(CLAUDE_PROBE_SANDBOX),
        "-p",
        _claude_probe_sandbox_profile(executable, probe_cwd),
        str(executable),
        "--safe-mode",
        *args,
    )


def _sandbox_path_filter(kind: str, path: pathlib.Path) -> str:
    return f"({kind} {json.dumps(str(path), ensure_ascii=False)})"


def _claude_probe_sandbox_profile(
    executable: pathlib.Path,
    probe_cwd: pathlib.Path,
) -> str:
    dependencies = _native_macho_dependencies(executable, label="Claude Code")
    host_home = pathlib.Path(
        os.environ.get("HOME", str(pathlib.Path.home()))
    ).expanduser().resolve()
    dependency_roots = {path.parent.resolve() for path in dependencies}
    if any(
        root == pathlib.Path("/") or root == host_home or root in host_home.parents
        for root in dependency_roots
    ):
        raise InvalidReviewerExecutable(
            "Claude Code executable or interpreter has an overly broad installation root"
        )
    read_subpaths = {
        probe_cwd.resolve(),
        *(path.resolve() for path in CLAUDE_PROBE_SYSTEM_READ_SUBPATHS),
        *dependency_roots,
    }
    read_files = {
        *(path.resolve() for path in CLAUDE_PROBE_SYSTEM_READ_LITERALS),
        *dependencies,
    }
    metadata_paths: set[pathlib.Path] = set()
    for path in {*read_files, *read_subpaths}:
        current = path
        while True:
            metadata_paths.add(current)
            if current.parent == current:
                break
            current = current.parent
    read_filters = "".join(
        [
            *(
                _sandbox_path_filter("literal", path)
                for path in sorted(read_files, key=str)
            ),
            *(
                _sandbox_path_filter("subpath", path)
                for path in sorted(read_subpaths, key=str)
            ),
        ]
    )
    metadata_filters = "".join(
        _sandbox_path_filter("literal", path)
        for path in sorted(metadata_paths, key=str)
    )
    exec_filters = "".join(
        [
            *(
                _sandbox_path_filter("literal", path)
                for path in sorted(dependencies, key=str)
            ),
            *(
                _sandbox_path_filter("subpath", path.parent.resolve())
                for path in sorted(dependencies, key=str)
            ),
        ]
    )
    return (
        CLAUDE_PROBE_SANDBOX_PROFILE
        + f"(allow file-read-metadata {metadata_filters})"
        + f"(allow file-read* {read_filters})"
        + f"(allow process-exec {exec_filters})"
        + "(allow sysctl-read)"
    )


def _claude_review_sandbox_profile(
    executable: pathlib.Path,
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    proxy_port: int,
) -> str:
    dependencies = _native_macho_dependencies(executable, label="Claude Code")
    home_raw = env.get("HOME")
    tmp_raw = env.get("TMPDIR")
    if not home_raw or not tmp_raw:
        raise ReviewError("Claude Code review sandbox requires HOME and TMPDIR")
    if not 1 <= proxy_port <= 65535:
        raise ReviewError("Claude Code review sandbox requires a valid proxy port")
    home = pathlib.Path(home_raw).resolve()
    tmp = pathlib.Path(tmp_raw).resolve()
    claude_tmp = pathlib.Path(env.get("CLAUDE_CODE_TMPDIR", tmp_raw)).resolve()
    container = review.container_dir.resolve()
    if (
        not is_relative_to(home, container)
        or not is_relative_to(tmp, container)
        or claude_tmp != tmp
    ):
        raise ReviewError(
            "Claude Code review sandbox requires helper-owned HOME and TMPDIR"
        )
    tls_files: set[pathlib.Path] = set()
    for key in CLAUDE_TLS_FILE_ENV_KEYS:
        raw = env.get(key)
        if not raw:
            continue
        path = pathlib.Path(raw)
        if not path.is_absolute() or not path.is_file():
            raise ReviewError(f"Claude Code review sandbox requires valid absolute {key}")
        resolved = path.resolve()
        if not is_relative_to(resolved, container):
            raise ReviewError(
                f"Claude Code review sandbox requires helper-owned {key}"
            )
        tls_files.update((path.absolute(), resolved))
    tls_dirs: set[pathlib.Path] = set()
    for key in CLAUDE_TLS_DIR_ENV_KEYS:
        for raw in env.get(key, "").split(os.pathsep):
            if not raw:
                continue
            path = pathlib.Path(raw)
            if not path.is_absolute() or not path.is_dir():
                raise ReviewError(
                    f"Claude Code review sandbox requires valid absolute {key} entries"
                )
            resolved = path.resolve()
            if not is_relative_to(resolved, container):
                raise ReviewError(
                    f"Claude Code review sandbox requires helper-owned {key} entries"
                )
            tls_dirs.update((path.absolute(), resolved))
    auth_executables: tuple[pathlib.Path, ...] = ()
    keychain_broker_port: int | None = None
    if not env.get("ANTHROPIC_API_KEY"):
        broker_dir = container / "claude-runtime" / "keychain-broker"
        security_candidate = next(
            (
                pathlib.Path(entry) / "security"
                for entry in env.get("PATH", "").split(os.pathsep)
                if entry
                and (pathlib.Path(entry) / "security").is_file()
                and os.access(pathlib.Path(entry) / "security", os.X_OK)
            ),
            None,
        )
        if (
            security_candidate is None
            or security_candidate.resolve() != (broker_dir / "security").resolve()
        ):
            raise ReviewError(
                "Claude local-login sandbox requires the restricted Keychain broker"
            )
        auth_executables = _native_macho_dependencies(
            broker_dir / "security",
            label="Claude Keychain broker",
        )
        if any(not is_relative_to(path.resolve(), container) for path in auth_executables):
            raise ReviewError("Claude Keychain broker must be helper-owned")
        try:
            keychain_broker_port = int(env[CLAUDE_KEYCHAIN_BROKER_PORT_ENV])
        except (KeyError, ValueError) as error:
            raise ReviewError(
                "Claude local-login sandbox requires a valid Keychain broker port"
            ) from error
        if not 1 <= keychain_broker_port <= 65535:
            raise ReviewError(
                "Claude local-login sandbox requires a valid Keychain broker port"
            )
        if not CLAUDE_KEYCHAIN_BROKER_CAPABILITY.fullmatch(
            env.get(CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV, "")
        ):
            raise ReviewError(
                "Claude local-login sandbox requires a valid Keychain broker capability"
            )
    rg_candidate = _trusted_claude_ripgrep()
    if rg_candidate is None:
        raise ClaudeReviewToolUnavailable(
            "Claude Code Grep sandbox requires ripgrep in a trusted path"
        )
    try:
        tool_executables = _native_macho_dependencies(rg_candidate, label="ripgrep")
    except InvalidReviewerExecutable as error:
        raise ClaudeReviewToolUnavailable(str(error)) from error
    tool_library_subpaths = {
        candidate
        for path in CLAUDE_REVIEW_TOOL_LIBRARY_SUBPATH_CANDIDATES
        if path.is_dir()
        for candidate in (path.absolute(), path.resolve())
    }
    read_subpaths = {
        home,
        tmp,
        review.workspace_root.resolve(),
        *(path.resolve() for path in CLAUDE_PROBE_SYSTEM_READ_SUBPATHS),
        *tool_library_subpaths,
        *tls_dirs,
    }
    read_files = {
        *(path.resolve() for path in CLAUDE_PROBE_SYSTEM_READ_LITERALS),
        *dependencies,
        *auth_executables,
        *tool_executables,
        *tls_files,
    }
    metadata_paths: set[pathlib.Path] = set()
    for path in {*read_files, *read_subpaths}:
        current = path
        while True:
            metadata_paths.add(current)
            if current.parent == current:
                break
            current = current.parent
    read_filters = "".join(
        [
            *(
                _sandbox_path_filter("literal", path)
                for path in sorted(read_files, key=str)
            ),
            *(
                _sandbox_path_filter("subpath", path)
                for path in sorted(read_subpaths, key=str)
            ),
        ]
    )
    metadata_filters = "".join(
        _sandbox_path_filter("literal", path)
        for path in sorted(metadata_paths, key=str)
    )
    exec_filters = "".join(
        _sandbox_path_filter("literal", path)
        for path in sorted(
            (*dependencies, *auth_executables, *tool_executables),
            key=str,
        )
    )
    write_filters = "".join(
        _sandbox_path_filter("subpath", path) for path in sorted((home, tmp), key=str)
    )
    mach_filters = "".join(
        f"(global-name {json.dumps(name)})"
        for name in CLAUDE_REVIEW_BASE_MACH_SERVICES
    )
    network_filters = f'(remote ip "localhost:{proxy_port}")'
    if keychain_broker_port is not None:
        network_filters += f'(remote ip "localhost:{keychain_broker_port}")'
    return (
        CLAUDE_PROBE_SANDBOX_PROFILE
        + f"(allow file-read-metadata {metadata_filters})"
        + f"(allow file-read* {read_filters})"
        + f"(allow file-write* {write_filters})"
        + f"(allow process-exec {exec_filters})"
        + "(allow process-fork)"
        + f"(allow mach-lookup {mach_filters})"
        + f"(allow network-outbound {network_filters})"
        + "(allow ipc-posix-shm-read*)"
        + "(allow sysctl-read)"
    )


def _claude_probe_cwd(env: dict[str, str]) -> pathlib.Path:
    raw_home = env.get("HOME")
    if not raw_home:
        raise ReviewError("Claude Code probe requires an isolated HOME")
    home = pathlib.Path(raw_home)
    if not home.is_absolute() or home.is_symlink() or not home.is_dir():
        raise ReviewError("Claude Code probe HOME must be an existing real directory")
    return home


def _claude_preflight_probe_environment(
    *,
    home: pathlib.Path,
    tmp: pathlib.Path,
) -> dict[str, str]:
    """Return a credential-free environment for executable preflight probes."""

    return {
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_SAFE_MODE": "1",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "TEMP": str(tmp),
        "TMP": str(tmp),
        "TMPDIR": str(tmp),
    }


def _run_claude_probe(
    executable: pathlib.Path,
    env: dict[str, str],
    *args: str,
) -> Completed:
    probe_cwd = _claude_probe_cwd(env)
    with tempfile.TemporaryDirectory(prefix=".claude-probe-", dir=probe_cwd) as raw:
        output_dir = pathlib.Path(raw)
        return run(
            _claude_probe_command(executable, probe_cwd, *args),
            cwd=probe_cwd,
            env=env,
            stdout_path=output_dir / "stdout.log",
            stderr_path=output_dir / "stderr.log",
            capture_limit_bytes=CLAUDE_PROBE_OUTPUT_LIMIT_BYTES,
            timeout_seconds=CLAUDE_PROBE_TIMEOUT_SECONDS,
            output_file_limit_bytes=CLAUDE_PROBE_OUTPUT_LIMIT_BYTES,
        )


def _require_claude_identity(
    executable: pathlib.Path,
    env: dict[str, str],
) -> ClaudeVersion:
    completed = _run_claude_probe(executable, env, "--version")
    output = (completed.stdout + b"\n" + completed.stderr).decode(
        "utf-8", errors="replace"
    )
    if completed.returncode != 0:
        raise InvalidReviewerExecutable(
            "sandboxed executable did not return a Claude Code release version"
        )
    try:
        return parse_claude_version(output)
    except ClaudeCapabilityError as error:
        raise InvalidReviewerExecutable(str(error)) from error


def _require_claude_safe_mode(
    executable: pathlib.Path,
    env: dict[str, str],
) -> None:
    completed = _run_claude_probe(executable, env, "--help")
    help_text = (completed.stdout + b"\n" + completed.stderr).decode(
        "utf-8", errors="replace"
    )
    if completed.returncode != 0:
        raise InvalidReviewerExecutable(
            "Claude Code help probe failed before capability validation"
        )
    try:
        validate_claude_help(help_text)
    except ClaudeSafetyContractInvalid as error:
        raise ClaudeSafeModeContractInvalid(str(error)) from error
    except ClaudeCapabilityError as error:
        raise InvalidReviewerExecutable(str(error)) from error


def classify_failure(stdout: bytes | str, stderr: bytes | str) -> str:
    def decode(value: bytes | str) -> str:
        return (
            value.decode("utf-8", errors="replace")
            if isinstance(value, bytes)
            else value
        )

    stdout_bytes = stdout.encode() if isinstance(stdout, str) else stdout
    structured_primary_error = _structured_error_text(stdout_bytes).lower()
    primary_message = f"{decode(stderr)}\n{structured_primary_error}".lower()
    if any(code in structured_primary_error for code in STRUCTURED_AUTH_CODES):
        return "auth"
    if any(fragment in primary_message for fragment in AUTH_FAILURE_FRAGMENTS):
        return "auth"
    if any(fragment in primary_message for fragment in TRANSIENT_FAILURE_FRAGMENTS):
        return "transient"
    if any(fragment in primary_message for fragment in ENTITLEMENT_FAILURE_FRAGMENTS):
        return "entitlement"
    if any(
        code in structured_primary_error for code in STRUCTURED_ENTITLEMENT_CODES
    ):
        return "entitlement"
    if (
        any(
            code in structured_primary_error
            for code in STRUCTURED_AMBIGUOUS_MODEL_CODES
        )
        and "model" in structured_primary_error
        and any(
            marker in structured_primary_error
            for marker in (
                "access",
                "account",
                "organization",
                "organisation",
                "plan",
                "entitled",
                "available",
            )
        )
    ):
        return "entitlement"
    return "other"


def _normalize_model(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _model_matches(requested: str, effective: str) -> bool:
    requested_normalized = _normalize_model(requested)
    effective_normalized = _normalize_model(effective)
    return effective_normalized == requested_normalized


def _json_objects(stdout: bytes) -> list[dict[str, Any]]:
    text = stdout.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    values: list[dict[str, Any]] = []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        values.append(parsed)
        return values
    for line in text.split("\n"):
        try:
            parsed_line = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed_line, dict):
            values.append(parsed_line)
    return values


def _strict_json_object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _strict_json_object(stdout: bytes) -> dict[str, Any] | None:
    try:
        text = stdout.decode("utf-8")
        parsed = json.loads(
            text,
            parse_constant=_reject_nonstandard_json_constant,
            object_pairs_hook=_strict_json_object_from_pairs,
        )
    except (UnicodeDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _strict_jsonl_objects(stdout: bytes) -> list[dict[str, Any]] | None:
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None
    objects: list[dict[str, Any]] = []
    for line in text.split("\n"):
        if not line.strip(" \t\r"):
            continue
        try:
            parsed = json.loads(
                line,
                parse_constant=_reject_nonstandard_json_constant,
                object_pairs_hook=_strict_json_object_from_pairs,
            )
        except ValueError:
            return None
        if not isinstance(parsed, dict):
            return None
        objects.append(parsed)
    return objects


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _error_payload_text(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, dict):
        result: list[str] = []
        for key in (
            "code",
            "type",
            "subtype",
            "status",
            "message",
            "reason",
            "detail",
            "error",
            "errors",
        ):
            if key in value:
                result.extend(_error_payload_text(value[key]))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_error_payload_text(item))
        return result
    return []


def _structured_error_item_text(
    item: dict[str, Any],
) -> str:
    messages: list[str] = []
    tokens = [
        value.lower()
        for key in ("type", "subtype", "status")
        if isinstance((value := item.get(key)), str)
    ]
    explicit_error = item.get("is_error") is True or any(
        token == "error"
        or token in {"failed", "failure", "error_during_execution"}
        or token.endswith(".failed")
        or token.endswith(".failure")
        or token.endswith(".error")
        or token.endswith("_error")
        or token.startswith("error_")
        for token in tokens
    )
    if not explicit_error:
        return ""
    messages.append(f"event {' '.join(tokens) or 'explicit error'}")
    for key in ("error", "errors", "message", "reason", "detail", "code"):
        if key in item:
            messages.extend(_error_payload_text(item[key]))
    api_error_status = item.get("api_error_status")
    if isinstance(api_error_status, (int, str)):
        messages.append(f"status {api_error_status}")
    return "\n".join(messages)


def _structured_error_text(
    stdout: bytes,
) -> str:
    return "\n".join(
        message
        for item in _json_objects(stdout)
        if (
            message := _structured_error_item_text(item)
        )
    )


def _parse_claude_output(
    stdout: bytes, *, requested_model: str | None = None
) -> tuple[str | None, str | None]:
    result = _strict_json_object(stdout)
    if result is None:
        return None, None
    if result.get("type") != "result":
        return None, None
    model_usage = result.get("modelUsage")
    if not isinstance(model_usage, dict) or not model_usage:
        return None, None
    if any(
        not isinstance(key, str)
        or not key
        or not isinstance(value, dict)
        for key, value in model_usage.items()
    ):
        return None, None
    candidates = list(model_usage)
    effective_model = None
    if requested_model is not None:
        effective_model = next(
            (
                candidate
                for candidate in candidates
                if _model_matches(requested_model, candidate)
            ),
            None,
        )
    if effective_model is None and candidates:
        effective_model = candidates[-1]
    if result.get("subtype") != "success" or result.get("is_error") is not False:
        return None, effective_model
    for key in ("error", "errors"):
        if key not in result:
            continue
        value = result[key]
        explicitly_empty = (
            value is None
            or (isinstance(value, str) and not value.strip())
            or (isinstance(value, (list, dict)) and not value)
        )
        if not explicitly_empty:
            return None, effective_model
    if "api_error_status" in result:
        value = result["api_error_status"]
        if value is not None and not (
            isinstance(value, str) and not value.strip()
        ):
            return None, effective_model
    final_text = result.get("result")
    if not isinstance(final_text, str) or not final_text.strip() or not candidates:
        return None, effective_model
    if _structured_error_text(stdout).strip():
        return None, effective_model
    return final_text, effective_model


def _copilot_item_model_evidence(
    item: dict[str, Any],
) -> tuple[bool, str | None]:
    event_type = item.get("type")
    if event_type == "session.start":
        model_key = "selectedModel"
    elif event_type in {"assistant.message", "assistant.usage"}:
        model_key = "model"
    else:
        return True, None
    data = item.get("data")
    if not isinstance(data, dict):
        return False, None
    if event_type != "session.start" and data.get("parentToolCallId"):
        return True, None
    if model_key not in data:
        return True, None
    candidate = data[model_key]
    if not isinstance(candidate, str) or not candidate:
        return False, None
    return True, candidate


def _parse_copilot_objects(
    objects: Iterable[dict[str, Any]],
    *,
    requested_model: str | None = None,
) -> tuple[str | None, str | None]:
    open_turn: dict[str, Any] | None = None
    completed_turn: tuple[int, dict[str, Any]] | None = None
    latest_session_model: str | None = None
    first_model: str | None = None
    evidence_conflict = False
    structured_error = False
    first_error_index: int | None = None
    last_error_index: int | None = None
    last_index = -1

    for index, item in enumerate(objects):
        last_index = index
        valid_model, candidate = _copilot_item_model_evidence(item)
        if not valid_model:
            return None, None
        if candidate is not None:
            if first_model is None:
                first_model = candidate
            elif not _model_matches(first_model, candidate):
                evidence_conflict = True
        if _structured_error_item_text(item):
            structured_error = True
            first_error_index = (
                index if first_error_index is None else first_error_index
            )
            last_error_index = index

        event_type = item.get("type")
        if event_type == "session.start":
            if open_turn is not None:
                return None, None
            latest_session_model = candidate
        if event_type in {"assistant.turn_start", "assistant.turn_end"}:
            data = item.get("data")
            if not isinstance(data, dict):
                return None, None
            turn_id = data.get("turnId")
            if not isinstance(turn_id, str) or not turn_id:
                return None, None
            if event_type == "assistant.turn_start":
                if open_turn is not None:
                    return None, None
                open_turn = {
                    "id": turn_id,
                    "start_index": index,
                    "message": None,
                    "session_model": latest_session_model,
                    "usage_model": None,
                }
                continue
            if open_turn is None or open_turn["id"] != turn_id:
                return None, None
            completed_turn = (
                index,
                {
                    "message": open_turn["message"],
                    "session_model": open_turn["session_model"],
                    "start_index": open_turn["start_index"],
                    "usage_model": open_turn["usage_model"],
                },
            )
            open_turn = None
            continue

        if open_turn is None:
            continue
        if event_type == "assistant.message":
            data = item["data"]
            if data.get("parentToolCallId"):
                continue
            open_turn["message"] = data
            open_turn["usage_model"] = None
        elif event_type == "assistant.usage":
            data = item["data"]
            if data.get("parentToolCallId") or open_turn["message"] is None:
                continue
            if candidate is not None and open_turn["usage_model"] is None:
                open_turn["usage_model"] = candidate

    if structured_error:
        assert first_error_index is not None and last_error_index is not None
        if open_turn is not None:
            if first_error_index <= open_turn["start_index"]:
                return None, None
        elif completed_turn is not None:
            terminal_index, turn = completed_turn
            if (
                terminal_index != last_index
                or first_error_index <= turn["start_index"]
                or last_error_index >= terminal_index
            ):
                return None, None
        else:
            return None, None
        if evidence_conflict:
            return None, None
        turn = open_turn if open_turn is not None else completed_turn[1]
        message = turn["message"]
        message_model = message.get("model") if isinstance(message, dict) else None
        effective_model = (
            turn["usage_model"] or message_model or turn["session_model"]
        )
        if not isinstance(effective_model, str) or not effective_model:
            return None, None
        return None, effective_model
    if (
        open_turn is not None
        or completed_turn is None
        or completed_turn[0] != last_index
        or evidence_conflict
    ):
        return None, None

    turn = completed_turn[1]
    data = turn["message"]
    if not isinstance(data, dict):
        return None, None
    tool_requests = data.get("toolRequests", [])
    if not isinstance(tool_requests, list) or tool_requests:
        return None, None
    content = data.get("content")
    if not isinstance(content, str) or not content.strip():
        return None, None
    usage_model = turn["usage_model"]
    message_model = data.get("model")
    model = usage_model or message_model or turn["session_model"]
    if not isinstance(model, str) or not model:
        return None, None
    if first_model is not None and not _model_matches(model, first_model):
        return None, None
    return content, model


def _parse_copilot_output(
    stdout: bytes, *, requested_model: str | None = None
) -> tuple[str | None, str | None]:
    objects = _strict_jsonl_objects(stdout)
    if objects is None:
        return None, None
    return _parse_copilot_objects(objects, requested_model=requested_model)


def _strict_jsonl_file_objects(path: pathlib.Path) -> Iterable[dict[str, Any]]:
    with path.open("rb") as handle:
        while raw_line := handle.readline(COPILOT_JSONL_RECORD_LIMIT_BYTES + 2):
            line = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
            if len(line) > COPILOT_JSONL_RECORD_LIMIT_BYTES:
                raise ValueError("Copilot JSONL record exceeds the bounded parser limit")
            if not line.strip(b" \t\r"):
                continue
            text = line.decode("utf-8")
            parsed = json.loads(
                text,
                parse_constant=_reject_nonstandard_json_constant,
                object_pairs_hook=_strict_json_object_from_pairs,
            )
            if not isinstance(parsed, dict):
                raise ValueError("Copilot JSONL record is not an object")
            yield parsed


def _parse_copilot_output_file(
    path: pathlib.Path,
    *,
    requested_model: str | None = None,
) -> tuple[str | None, str | None]:
    try:
        return _parse_copilot_objects(
            _strict_jsonl_file_objects(path),
            requested_model=requested_model,
        )
    except (OSError, UnicodeDecodeError, ValueError):
        return None, None


def _codex_thread_id(stdout: bytes) -> str | None:
    for item in _json_objects(stdout):
        if item.get("type") != "thread.started":
            continue
        thread_id = item.get("thread_id")
        if isinstance(thread_id, str) and thread_id:
            return thread_id
    return None


def _codex_session_metadata(
    stdout: bytes,
    env: dict[str, str],
    *,
    review_root: pathlib.Path,
) -> tuple[str | None, str | None, bool | None]:
    thread_id = _codex_thread_id(stdout)
    if thread_id is None:
        return None, None, None
    codex_home_value = env.get("CODEX_HOME")
    if codex_home_value:
        codex_home = pathlib.Path(codex_home_value).expanduser()
    else:
        home_value = env.get("HOME")
        if not home_value:
            return None, None, None
        codex_home = pathlib.Path(home_value).expanduser() / ".codex"
    sessions_root = codex_home / "sessions"
    try:
        candidates = sorted(
            sessions_root.glob(f"*/*/*/rollout-*-{thread_id}.jsonl"),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
    except OSError:
        return None, None, None
    for candidate in candidates:
        try:
            with candidate.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(item, dict) or item.get("type") != "turn_context":
                        continue
                    payload = item.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    model = payload.get("model")
                    effort = payload.get("effort")
                    return (
                        model if isinstance(model, str) and model else None,
                        effort if isinstance(effort, str) and effort else None,
                        _codex_permissions_match(
                            payload,
                            review_root=review_root,
                            codex_home=codex_home,
                        ),
                    )
        except OSError:
            continue
    return None, None, None


def _codex_permissions_match(
    payload: dict[str, Any],
    *,
    review_root: pathlib.Path,
    codex_home: pathlib.Path | None = None,
) -> bool:
    sandbox_policy = payload.get("sandbox_policy")
    permission_profile = payload.get("permission_profile")
    if (
        payload.get("approval_policy") != "never"
        or not isinstance(sandbox_policy, dict)
        or sandbox_policy.get("type") != "read-only"
        or not isinstance(permission_profile, dict)
        or permission_profile.get("type") != "managed"
        or permission_profile.get("network") != "restricted"
    ):
        return False
    filesystem = permission_profile.get("file_system")
    if (
        not isinstance(filesystem, dict)
        or filesystem.get("type") != "restricted"
        or filesystem.get("glob_scan_max_depth") != 8
    ):
        return False
    entries = filesystem.get("entries")
    if not isinstance(entries, list):
        return False

    expected_paths = {
        str(review_root.resolve()): "read",
        str((review_root / ".git").resolve()): "deny",
        str((review_root / ".codex").resolve()): "deny",
        str((review_root / ".agents").resolve()): "deny",
    }
    expected_globs = {
        str(review_root.resolve() / "*.env"): "deny",
        str(review_root.resolve() / "**/*.env"): "deny",
    }
    remaining_paths = dict(expected_paths)
    remaining_globs = dict(expected_globs)
    minimal_seen = False
    arg_transport_seen = False
    codex_arg_root = (
        (codex_home.expanduser().resolve() / "tmp/arg0")
        if codex_home is not None
        else None
    )
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("access"), str):
            return False
        path_value = entry.get("path")
        if not isinstance(path_value, dict):
            return False
        path_type = path_value.get("type")
        access = entry["access"]
        if path_type == "special":
            value = path_value.get("value")
            if (
                minimal_seen
                or access != "read"
                or value != {"kind": "minimal"}
            ):
                return False
            minimal_seen = True
            continue
        if path_type == "glob_pattern":
            pattern = path_value.get("pattern")
            if not isinstance(pattern, str) or remaining_globs.pop(pattern, None) != access:
                return False
            continue
        if path_type != "path":
            return False
        value = path_value.get("path")
        if not isinstance(value, str):
            return False
        expected_access = remaining_paths.pop(value, None)
        if expected_access == access:
            continue
        candidate = pathlib.Path(value).expanduser()
        if (
            codex_arg_root is not None
            and access == "read"
            and not arg_transport_seen
            and candidate.is_absolute()
            and candidate.parent == codex_arg_root
            and CODEX_ARG_TRANSPORT_NAME.fullmatch(candidate.name) is not None
        ):
            arg_transport_seen = True
            continue
        return False
    return minimal_seen and not remaining_paths and not remaining_globs


def _attempt_paths_without_io(
    review: ReviewWorkspace, index: int, runtime: str, model: str
) -> tuple[pathlib.Path, pathlib.Path]:
    safe_model = re.sub(r"[^A-Za-z0-9_.-]+", "-", model)
    prefix = review.container_dir / "attempts" / f"{index:02d}-{runtime}-{safe_model}"
    return pathlib.Path(f"{prefix}.stdout.log"), pathlib.Path(f"{prefix}.stderr.log")


def _attempt_paths(
    review: ReviewWorkspace, index: int, runtime: str, model: str
) -> tuple[pathlib.Path, pathlib.Path]:
    stdout_path, stderr_path = _attempt_paths_without_io(
        review,
        index,
        runtime,
        model,
    )
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    return stdout_path, stderr_path


def _append_attempt_diagnostic(path: pathlib.Path, message: str) -> None:
    with path.open("ab") as handle:
        if handle.tell():
            handle.write(b"\n")
        handle.write(message.rstrip().encode("utf-8", errors="replace") + b"\n")


def _claude_persistence_failed_attempt(
    *,
    review: ReviewWorkspace,
    index: int,
    model: str,
    completed: Completed,
    category: str = "blocked-authentication",
) -> Attempt:
    stdout_path, stderr_path = _attempt_paths_without_io(
        review,
        index,
        "claude",
        model,
    )
    try:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.touch(exist_ok=True)
        stderr_path.touch(exist_ok=True)
        _append_attempt_diagnostic(
            stderr_path,
            "Claude credential refresh persistence was not safely completed after "
            "the runtime attempt.",
        )
    except OSError:
        pass
    return Attempt(
        runtime="claude",
        requested_model=model,
        effective_model=None,
        requested_effort=CLAUDE_REASONING_EFFORT,
        effective_effort=None,
        returncode=completed.returncode,
        category=category,
        final_text=None,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )


def _claude_auth_rejection_after_credential_inspection(
    *,
    review: ReviewWorkspace,
    index: int,
    model: str,
    completed: Completed,
    inspection_error: BaseException,
) -> ClaudeKeychainCredentialUnavailable | None:
    if classify_failure(completed.stdout, completed.stderr) != "auth":
        return None
    failure = ClaudeKeychainCredentialUnavailable(
        "the restricted Claude runtime rejected the configured credential; "
        "post-attempt credential inspection was also inconclusive"
    )
    setattr(
        failure,
        "_codex_claude_persistence_attempt",
        _claude_persistence_failed_attempt(
            review=review,
            index=index,
            model=model,
            completed=completed,
            category="auth",
        ),
    )
    _propagate_claude_persistence_state(review, inspection_error, failure)
    _attach_claude_credential_cleanup_failure(failure, inspection_error)
    return failure


def _record_attempt(
    *,
    review: ReviewWorkspace,
    index: int,
    runtime: str,
    model: str,
    completed: Completed,
    final_text: str | None,
    effective_model: str | None,
    requested_effort: str,
    effective_effort: str | None,
    require_verified_model: bool = False,
    require_verified_effort: bool = False,
) -> Attempt:
    stdout_path, stderr_path = _attempt_paths(review, index, runtime, model)
    if not stdout_path.exists():
        stdout_path.write_bytes(completed.stdout)
    if not stderr_path.exists():
        stderr_path.write_bytes(completed.stderr)
    category = (
        "success"
        if completed.returncode == 0 and final_text
        else classify_failure(completed.stdout, completed.stderr)
    )
    attempt = Attempt(
        runtime=runtime,
        requested_model=model,
        effective_model=effective_model,
        requested_effort=requested_effort,
        effective_effort=effective_effort,
        returncode=completed.returncode,
        category=category,
        final_text=final_text,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )
    if attempt.category in {"success", "entitlement"} and (
        (require_verified_model and effective_model is None)
        or (require_verified_effort and effective_effort is None)
    ):
        detail = (
            "reviewer result did not expose required runtime verification "
            "metadata; refusing to accept the pinned lane result"
        )
        _append_attempt_diagnostic(stderr_path, detail)
        return replace(
            attempt,
            returncode=65,
            category="runtime-unverified",
            final_text=None,
        )
    if effective_model and not _model_matches(model, effective_model):
        mismatch = (
            f"requested model {model!r} was replaced by {effective_model!r}; "
            "refusing to infer an entitlement failure from silent model substitution"
        )
        _append_attempt_diagnostic(stderr_path, mismatch)
        attempt = replace(
            attempt,
            returncode=65,
            category="model-mismatch",
            final_text=None,
        )
    if effective_effort and effective_effort.lower() != requested_effort.lower():
        mismatch = (
            f"requested effort {requested_effort!r} was replaced by {effective_effort!r}; "
            "refusing to accept the pinned lane"
        )
        _append_attempt_diagnostic(stderr_path, mismatch)
        attempt = replace(
            attempt,
            returncode=65,
            category="effort-mismatch",
            final_text=None,
        )
    return attempt


def _codex_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
) -> Attempt:
    executable = resolve_reviewer_executable("codex")
    if executable is None:
        raise FileNotFoundError("codex is not available in a validated executable path")
    env = _with_executable_path(env, executable)
    attempt_final = review.container_dir / "attempts" / f"{index:02d}-codex-final.txt"
    attempt_final.parent.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = _attempt_paths(review, index, "codex", model)
    tool_home = review.container_dir / "tool-home"
    tool_home.mkdir(exist_ok=True)
    shell_values = {
        key: env[key]
        for key in (
            "CODEX_ISOLATED_REVIEW_DIFF_FILE",
            "CODEX_ISOLATED_REVIEW_PROMPT_FILE",
            "CODEX_ISOLATED_REVIEW_RANGE",
            "CODEX_ISOLATED_REVIEW_ROOT",
            "PATH",
            "TEMP",
            "TMP",
            "TMPDIR",
        )
        if key in env
    }
    shell_values["HOME"] = str(tool_home)
    shell_environment = (
        "shell_environment_policy.set={"
        + ",".join(
            f"{key}={json.dumps(value)}" for key, value in sorted(shell_values.items())
        )
        + "}"
    )
    permission_profile = (
        '{"filesystem"={"glob_scan_max_depth"=8,":minimal"="read",'
        '":workspace_roots"={"."="read",".git"="deny",'
        '".codex"="deny",".agents"="deny","*.env"="deny",'
        '"**/*.env"="deny"}'
        "}}"
    )
    prompt = review.prompt_file.read_bytes()
    completed = run(
        (
            str(executable),
            "-c",
            'approval_policy="never"',
            "-c",
            'default_permissions="isolated_review"',
            "-c",
            f"permissions.isolated_review={permission_profile}",
            "-c",
            'shell_environment_policy.inherit="none"',
            "-c",
            shell_environment,
            "-c",
            "project_doc_max_bytes=0",
            "-m",
            model,
            "-c",
            f'model_reasoning_effort="{CODEX_REASONING_EFFORT}"',
            "exec",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--json",
            "-o",
            str(attempt_final),
            "-",
        ),
        cwd=review.workspace_root,
        env=env,
        stdin=prompt,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
    )
    final_text = None
    if completed.returncode == 0 and attempt_final.is_file():
        final_text = (
            attempt_final.read_text(encoding="utf-8", errors="replace").strip() or None
        )
    effective_model, effective_effort, permissions_verified = _codex_session_metadata(
        completed.stdout,
        env,
        review_root=review.workspace_root,
    )
    attempt = _record_attempt(
        review=review,
        index=index,
        runtime="codex",
        model=model,
        completed=completed,
        final_text=final_text,
        effective_model=effective_model,
        requested_effort=CODEX_REASONING_EFFORT,
        effective_effort=effective_effort,
        require_verified_model=True,
        require_verified_effort=True,
    )
    if permissions_verified is False or (
        attempt.category == "success" and permissions_verified is None
    ):
        detail = (
            "effective Codex sandbox did not preserve the isolated review permission "
            "profile; refusing to accept a result from a legacy or managed sandbox override"
        )
        _append_attempt_diagnostic(stderr_path, detail)
        return replace(
            attempt,
            returncode=65,
            category="permission-mismatch",
            final_text=None,
        )
    return attempt


def _resolve_validated_claude_executable(
    *,
    review: ReviewWorkspace,
    env: dict[str, str],
) -> tuple[pathlib.Path | None, dict[str, str]]:
    linux_host = _claude_linux_host() if _is_claude_linux_host() else None
    if linux_host is not None:
        try:
            reject_claude_wsl_windows_path(
                review.container_dir,
                linux_host,
            )
        except LinuxRuntimeInspectionInconclusive as error:
            raise ClaudeExecutableInspectionInconclusive(str(error)) from error
    claude_home = review.container_dir / "claude-home"
    claude_home.mkdir(parents=True, exist_ok=True)
    prepared_env = dict(env)
    prepared_env["HOME"] = str(claude_home)
    claude_tmp = review.container_dir / "tmp"
    claude_tmp.mkdir(parents=True, exist_ok=True)
    prepared_env["TMPDIR"] = str(claude_tmp)
    prepared_env["TMP"] = str(claude_tmp)
    prepared_env["TEMP"] = str(claude_tmp)
    prepared_env["CLAUDE_CODE_TMPDIR"] = str(claude_tmp)
    gpg_runtime_parent = _create_or_validate_claude_runtime_directory(
        review.container_dir / "claude-runtime",
        private=True,
    )
    gpg_temp_root = _create_or_validate_claude_runtime_directory(
        gpg_runtime_parent / "gpg-tmp",
        private=True,
    )
    gpg_temp_root_validator = (
        _claude_gpg_temp_root_validator(linux_host)
        if linux_host is not None
        else None
    )
    prepared_env.pop("XDG_CONFIG_HOME", None)
    probe_home = review.container_dir / "claude-probe-home"
    probe_home.mkdir(parents=True, exist_ok=True)
    probe_home.chmod(0o700)
    runtime_reports: dict[str, dict[str, object]] = {}
    runtime_executables: dict[str, pathlib.Path] = {}

    def validate_candidate(candidate: pathlib.Path) -> None:
        if linux_host is not None:
            try:
                linux_info = validate_claude_linux_executable(
                    candidate,
                    linux_host,
                )
            except LinuxUnsupportedHost as error:
                raise ClaudeProbeSandboxUnavailable(str(error)) from error
            except LinuxRuntimeInspectionInconclusive as error:
                raise ClaudeExecutableInspectionInconclusive(str(error)) from error
            except LinuxRuntimeUnsafe:
                raise
            except LinuxRuntimeError as error:
                raise InvalidReviewerExecutable(str(error)) from error
            platform_key = linux_info.manifest_platform_key
        elif _is_claude_macos_host():
            _native_macho_dependencies(candidate, label="Claude Code")
            platform_key = _claude_macos_platform_key(candidate)
        else:
            raise ClaudeProbeSandboxUnavailable(
                "Claude Code secure review supports macOS, Linux, and WSL2 only; "
                "native Windows must run the helper inside WSL2"
            )
        candidate_env = _claude_preflight_probe_environment(
            home=probe_home,
            tmp=claude_tmp,
        )
        version = _require_claude_identity(candidate, candidate_env)
        verified = _require_trusted_claude_release(
            candidate,
            version=version.text,
            platform_key=platform_key,
            gpg_temp_root=gpg_temp_root,
            gpg_temp_root_validator=gpg_temp_root_validator,
            cache_dir=(
                review.container_dir / "claude-runtime" / "provenance-cache"
            ),
            snapshot_dir=(
                review.container_dir / "claude-runtime" / "verified-executables"
            ),
        )
        verified_executable = (
            verified.executable
            if isinstance(verified, VerifiedClaudeExecutable)
            else candidate
        )
        candidate_env = _claude_preflight_probe_environment(
            home=probe_home,
            tmp=claude_tmp,
        )
        _require_claude_safe_mode(verified_executable, candidate_env)
        runtime_executables[str(candidate.absolute())] = verified_executable
        if isinstance(verified, VerifiedClaudeExecutable):
            lock_protocol = certified_claude_refresh_lock_protocol(
                version=verified.artifact.version,
                platform_key=verified.artifact.platform_key,
                checksum=verified.artifact.checksum,
            )
            runtime_reports[str(candidate.absolute())] = {
                "schema": 1,
                "phase": "publisher-and-capabilities-verified",
                "version": version.text,
                "platform": platform_key,
                "source_executable": str(candidate.absolute()),
                "verified_executable": str(verified.executable),
                "publisher_provenance": "anthropic-signed-manifest",
                "release_key_fingerprint": CLAUDE_RELEASE_KEY_FINGERPRINT,
                "manifest_url": verified.manifest_url,
                "signature_url": verified.signature_url,
                "sha256": verified.artifact.checksum,
                "gpg_verifier": str(verified.gpg_path),
                "gpg_verifier_trust": "fixed-path-native-host-tool",
                "capabilities": {
                    "required_options": list(CLAUDE_REQUIRED_OPTIONS),
                    "safe_mode_semantics": "verified",
                    "credential_lock_protocol": (
                        lock_protocol.identifier
                        if lock_protocol is not None
                        else "unverified"
                    ),
                },
                "outer_sandbox": {
                    "implementation": (
                        "bubblewrap"
                        if _is_claude_linux_host()
                        else "sandbox-exec"
                    ),
                    "status": "pending-runtime-launch",
                },
                "authentication": {
                    "source": (
                        "api-key" if prepared_env.get("ANTHROPIC_API_KEY") else "pending"
                    ),
                    "carrier": (
                        "environment"
                        if prepared_env.get("ANTHROPIC_API_KEY")
                        else (
                            "writable-private-config-guarded-writeback"
                            if _is_claude_linux_host()
                            else "one-shot-security-broker"
                        )
                    ),
                    "status": "pending",
                },
            }

    try:
        executable = resolve_reviewer_executable(
            "claude", candidate_validator=validate_candidate
        )
    except RejectedReviewerCandidates as error:
        raise ClaudeExecutableUnavailable(str(error)) from error
    if executable is None:
        return None, prepared_env
    report = runtime_reports.get(str(executable.absolute()))
    if report is not None:
        write_json(review.container_dir / "claude-runtime.json", report)
    runtime_executable = runtime_executables.get(
        str(executable.absolute()),
        executable,
    )
    return runtime_executable, _with_executable_path(
        prepared_env,
        runtime_executable,
    )


@contextlib.contextmanager
def _claude_linux_review_runtime(
    review: ReviewWorkspace,
    executable: pathlib.Path,
    env: dict[str, str],
    arguments: tuple[str, ...],
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None = None,
    writer_started: Callable[[], bool] | None = None,
    writer_quiescent: Callable[[], bool] | None = None,
) -> Iterator[Any]:
    try:
        host = _claude_linux_host()
        claude_info = validate_claude_linux_executable(executable, host)
        toolchain = discover_claude_linux_toolchain(host)
    except (LinuxUnsupportedHost, LinuxIsolationUnavailable) as error:
        raise ClaudeProbeSandboxUnavailable(str(error)) from error
    except LinuxRuntimeInspectionInconclusive as error:
        raise ClaudeExecutableInspectionInconclusive(str(error)) from error
    root = _claude_linux_runtime_root(review)
    home = _claude_linux_private_directory(review, "home")
    temporary = _claude_linux_private_directory(review, "tmp")
    launcher_dir = _claude_linux_private_directory(review, "bin")
    try:
        launcher = compile_claude_linux_launcher(
            host,
            toolchain,
            launcher_dir / "claude-linux-launcher",
        )
    except LinuxIsolationUnavailable as error:
        raise ClaudeProbeSandboxUnavailable(str(error)) from error
    except LinuxRuntimeInspectionInconclusive as error:
        raise ClaudeExecutableInspectionInconclusive(str(error)) from error
    try:
        runtime_libraries = collect_claude_linux_runtime_libraries(
            host,
            (claude_info.path, launcher, toolchain.socat, toolchain.rg),
        )
    except LinuxHostDependencyUnavailable as error:
        raise ClaudeProbeSandboxUnavailable(str(error)) from error
    except LinuxRuntimeInspectionInconclusive as error:
        raise ClaudeExecutableInspectionInconclusive(str(error)) from error
    ca_bundle = _claude_linux_ca_bundle(review, env)
    with contextlib.ExitStack() as stack:
        auth_env: dict[str, str] = {}
        api_key = env.get("ANTHROPIC_API_KEY")
        if api_key:
            api_carrier = _create_or_validate_claude_runtime_directory(
                _claude_linux_private_directory(review, "api-carrier"),
                private=True,
            )
            config_dir = _create_or_validate_claude_runtime_directory(
                api_carrier / "config",
                private=True,
            )
            auth_env["ANTHROPIC_API_KEY"] = api_key
        else:
            if refresh_lock_protocol is None:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude local-login credential-lock protocol is unavailable"
                )
            source = _claude_linux_credential_source()
            staged = stack.enter_context(
                stage_claude_credentials(
                    source,
                    root,
                    required_validity_seconds=0.0,
                    refresh_lock_protocol=refresh_lock_protocol,
                    writer_started=writer_started,
                    writer_quiescent=writer_quiescent,
                )
            )
            config_dir = staged.config_dir
        proxy_socket = stack.enter_context(
            _claude_unix_connect_proxy(review, env)
        )
        spec = SandboxSpec(
            host=host,
            toolchain=toolchain,
            claude=claude_info.path,
            launcher=launcher,
            workspace=review.workspace_root,
            helper_root=root,
            helper_home=home,
            helper_tmp=temporary,
            config_dir=config_dir,
            proxy_socket=proxy_socket,
            runtime_libraries=runtime_libraries,
            ca_bundle=ca_bundle,
            node_extra_ca_certs_configured=bool(env.get("NODE_EXTRA_CA_CERTS")),
        )
        try:
            run_claude_linux_isolation_probe(
                spec,
                review.diff_file,
            )
        except LinuxIsolationUnavailable as error:
            raise ReviewError(
                f"Claude Linux isolation verification failed: {error}"
            ) from error
        except LinuxRuntimeInspectionInconclusive as error:
            raise ClaudeExecutableInspectionInconclusive(str(error)) from error
        _update_claude_runtime_report(
            review,
            {
                "phase": "runtime-ready",
                "outer_sandbox": {"status": "isolation-probe-verified"},
                "authentication": {
                    "source": "api-key" if api_key else "credential-file",
                    "carrier": (
                        "environment"
                        if api_key
                        else "writable-private-config-guarded-writeback"
                    ),
                    "status": "sandbox-auth-staged",
                },
            },
        )
        try:
            command = build_claude_linux_sandbox_command(
                spec,
                arguments,
                auth_env=auth_env,
            )
        except LinuxRuntimeInspectionInconclusive as error:
            raise ClaudeExecutableInspectionInconclusive(str(error)) from error
        yield command


def _claude_review_arguments(
    *,
    model: str,
    settings: str,
    linux: bool,
) -> tuple[str, ...]:
    permission_mode = (
        CLAUDE_LINUX_REVIEW_PERMISSION_MODE if linux else "default"
    )
    visible_tools = CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS if linux else "Read,Grep,Glob"
    allowed_tools = (
        CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS if linux else "Read(./**)"
    )
    disallowed_tools = (
        CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS
        if linux
        else "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch,Task"
    )
    return (
        "--print",
        "--model",
        model,
        "--effort",
        CLAUDE_REASONING_EFFORT,
        "--permission-mode",
        permission_mode,
        "--output-format",
        "json",
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
        settings,
        "--tools",
        visible_tools,
        "--allowedTools",
        allowed_tools,
        "--disallowedTools",
        disallowed_tools,
    )


def _claude_review_settings(*, linux: bool) -> str:
    deny_rules = list(CLAUDE_REVIEW_FILE_DENY_RULES)
    if linux:
        deny_rules.extend(CLAUDE_LINUX_FILE_TOOL_DENY_RULES)
    return json.dumps(
        {
            "disableAllHooks": True,
            "permissions": {"deny": deny_rules},
        },
        separators=(",", ":"),
    )


def _require_claude_linux_prompt_without_file_mentions(prompt: bytes) -> None:
    """Reject file mentions only in bytes sent through Claude's stdin parser.

    The frozen diff remains a separate Read-tool input and is intentionally not
    scanned here; literal ``@`` bytes in reviewed source never reach this parser.
    """
    if b"@" in prompt:
        raise ReviewError(
            "Claude Linux/WSL2 review supports releases whose file-mention "
            "boundary predates 2.1.208; ASCII @ file mentions are not allowed"
        )


def _replace_claude_prompt_host_path(
    prompt: bytes,
    *,
    source: bytes,
    target: bytes,
    label: str,
    allow_descendants: bool = False,
) -> bytes:
    chunks: list[bytes] = []
    cursor = 0
    while True:
        occurrence = prompt.find(source, cursor)
        if occurrence < 0:
            chunks.append(prompt[cursor:])
            return b"".join(chunks)
        end = occurrence + len(source)
        left_ok = occurrence == 0 or prompt[occurrence - 1] in (
            CLAUDE_PROMPT_PATH_LEFT_BOUNDARIES
        )
        right_ok = end == len(prompt) or prompt[end] in (
            CLAUDE_PROMPT_PATH_RIGHT_BOUNDARIES
        )
        if not right_ok and allow_descendants and prompt[end : end + 1] == b"/":
            preceding = prompt[occurrence - 1] if occurrence else None
            quote = (
                bytes((preceding,))
                if preceding in CLAUDE_PROMPT_PATH_QUOTES
                else b""
            )
            if quote:
                token_end = prompt.find(quote, end)
                right_ok = token_end >= 0 and b"\\" not in prompt[end:token_end]
            elif occurrence == 0 or preceding in (
                CLAUDE_PROMPT_DESCENDANT_LEFT_BOUNDARIES
            ):
                token_end = end
                while token_end < len(prompt):
                    current = prompt[token_end]
                    if current in CLAUDE_PROMPT_PATH_RIGHT_BOUNDARIES:
                        break
                    if current == ord(".") and (
                        token_end + 1 == len(prompt)
                        or prompt[token_end + 1]
                        in CLAUDE_PROMPT_PATH_RIGHT_BOUNDARIES
                    ):
                        break
                    token_end += 1
                right_ok = True
            else:
                token_end = end
                right_ok = False
            if right_ok:
                components = prompt[end:token_end].split(b"/")[1:]
                right_ok = bool(components) and all(
                    component not in {b"", b".", b".."}
                    and all(byte >= 0x20 and byte != 0x7F for byte in component)
                    for component in components
                )
        if not right_ok and prompt[end : end + 1] == b".":
            right_ok = end + 1 == len(prompt) or prompt[end + 1] in (
                CLAUDE_PROMPT_PATH_RIGHT_BOUNDARIES
            )
        if not left_ok or not right_ok:
            raise ReviewError(
                f"Claude review prompt contains an ambiguous host {label} path"
            )
        chunks.extend((prompt[cursor:occurrence], target))
        cursor = end


def _claude_review_prompt(
    review: ReviewWorkspace,
    prompt: bytes,
    *,
    linux: bool,
) -> bytes:
    workspace = str(review.workspace_root).encode("utf-8")
    diff_file = str(review.diff_file).encode("utf-8")
    target_workspace = b"/workspace" if linux else workspace
    target_diff = (
        b"/workspace/.codex-review/review.diff" if linux else diff_file
    )
    projected = prompt.replace(
        b"- Workspace: .\n",
        b"- Workspace: " + target_workspace + b"\n",
    ).replace(
        b"- Primary diff file: .codex-review/review.diff\n",
        b"- Primary diff file: " + target_diff + b"\n",
    )
    if linux:
        projected = _replace_claude_prompt_host_path(
            projected,
            source=diff_file,
            target=target_diff,
            label="diff-file",
        )
        projected = _replace_claude_prompt_host_path(
            projected,
            source=workspace,
            target=target_workspace,
            label="workspace",
            allow_descendants=True,
        )
        projected = projected.rstrip() + b"\n" + CLAUDE_LINUX_PROMPT_GUIDANCE
    if len(projected) > MAX_REVIEW_PROMPT_BYTES:
        raise ReviewError(
            "Claude projected review prompt exceeds the "
            f"{MAX_REVIEW_PROMPT_BYTES}-byte limit"
        )
    return projected


def _claude_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
    executable: pathlib.Path | None = None,
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None | object = (
        _UNRESOLVED_CLAUDE_REFRESH_LOCK_PROTOCOL
    ),
) -> Attempt:
    if executable is None:
        executable, env = _resolve_validated_claude_executable(
            review=review,
            env=env,
        )
    if executable is None:
        raise FileNotFoundError(
            "claude is not available in a validated executable path"
        )
    linux_host = _is_claude_linux_host()
    prompt = _claude_review_prompt(
        review,
        review.prompt_file.read_bytes(),
        linux=linux_host,
    )
    if linux_host:
        _require_claude_linux_prompt_without_file_mentions(prompt)
    env = _with_claude_review_tool_path(review, env)
    env = _prepare_claude_tls_environment(review, env)
    if env.get("ANTHROPIC_API_KEY"):
        selected_refresh_lock_protocol = None
    elif refresh_lock_protocol is _UNRESOLVED_CLAUDE_REFRESH_LOCK_PROTOCOL:
        selected_refresh_lock_protocol = _certified_claude_refresh_lock_protocol(
            review,
            executable,
        )
    elif isinstance(refresh_lock_protocol, ClaudeRefreshLockProtocol):
        selected_refresh_lock_protocol = refresh_lock_protocol
    else:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude local-login credential-lock protocol is unavailable"
        )
    if not linux_host:
        _update_claude_runtime_report(
            review,
            {
                "phase": "authentication-source-pending",
                "outer_sandbox": {"status": "pending-runtime-launch"},
                "authentication": {
                    "source": "api-key" if env.get("ANTHROPIC_API_KEY") else "pending",
                    "carrier": (
                        "environment"
                        if env.get("ANTHROPIC_API_KEY")
                        else "one-shot-security-broker"
                    ),
                    "status": (
                        "configured"
                        if env.get("ANTHROPIC_API_KEY")
                        else "pending-source-selection"
                    ),
                    "model": model,
                },
                "attempt": None,
            },
        )
    stdout_path, stderr_path = _attempt_paths(review, index, "claude", model)
    settings = _claude_review_settings(linux=linux_host)
    arguments = _claude_review_arguments(
        model=model,
        settings=settings,
        linux=linux_host,
    )
    completed: Completed | None = None
    if linux_host:
        writer_started = threading.Event()
        writer_quiescent = threading.Event()
        try:
            with _claude_linux_review_runtime(
                review,
                executable,
                env,
                arguments,
                selected_refresh_lock_protocol,
                writer_started=writer_started.is_set,
                writer_quiescent=writer_quiescent.is_set,
            ) as sandbox_command:
                completed = run(
                    sandbox_command.argv,
                    cwd=review.workspace_root,
                    env=sandbox_command.env,
                    stdin=prompt,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
                    output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
                    on_process_started=writer_started.set,
                )
                quiescence_mask = block_forwarded_signals()
                try:
                    writer_quiescent.set()
                finally:
                    restore_signal_mask(quiescence_mask)
        except LinuxCredentialInspectionInconclusive as error:
            _update_claude_runtime_report_preserving_persistence(
                review,
                {
                    "phase": "authentication-inspection-inconclusive",
                    "status": "inconclusive",
                    "outer_sandbox": {
                        "status": (
                            "isolation-probe-verified"
                            if completed is not None
                            else "pending-isolation-probe"
                        )
                    },
                    "authentication": {
                        "status": "inspection-inconclusive",
                        "model": model,
                        "failure_class": (
                            "stale-refresh-lock"
                            if isinstance(error, LinuxCredentialStaleRefreshLock)
                            else (
                                "refresh-persistence"
                                if completed is not None
                                else "credential-inspection"
                            )
                        ),
                    },
                    "attempt": (
                        {
                            "requested_model": model,
                            "effective_model": None,
                            "requested_effort": CLAUDE_REASONING_EFFORT,
                            "effective_effort": None,
                            "category": "inconclusive",
                            "returncode": completed.returncode,
                            "failure_class": (
                                "stale-refresh-lock"
                                if isinstance(
                                    error,
                                    LinuxCredentialStaleRefreshLock,
                                )
                                else "refresh-persistence"
                            ),
                        }
                        if completed is not None
                        else None
                    ),
                },
                error,
            )
            if completed is not None:
                authentication_error = (
                    _claude_auth_rejection_after_credential_inspection(
                        review=review,
                        index=index,
                        model=model,
                        completed=completed,
                        inspection_error=error,
                    )
                )
                if authentication_error is not None:
                    raise authentication_error from error
            translated_error = ClaudeCredentialInspectionInconclusive(
                f"Claude Linux credential inspection was inconclusive: {error}"
            )
            retained_carrier = getattr(
                error,
                "_codex_claude_retained_credential_carrier",
                None,
            )
            if isinstance(retained_carrier, str):
                setattr(
                    translated_error,
                    "_codex_claude_retained_credential_carrier",
                    retained_carrier,
                )
                setattr(
                    translated_error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
            if completed is not None:
                setattr(
                    translated_error,
                    "_codex_claude_persistence_attempt",
                    _claude_persistence_failed_attempt(
                        review=review,
                        index=index,
                        model=model,
                        completed=completed,
                        category="inconclusive",
                    ),
                )
            raise translated_error from error
        except (LinuxCredentialUnavailable, LinuxCredentialUnsafe) as error:
            persistence_failed = completed is not None
            _update_claude_runtime_report(
                review,
                {
                    "phase": "blocked-authentication",
                    "status": "blocked-authentication",
                    "category": "blocked-authentication",
                    "outer_sandbox": {
                        "status": (
                            "isolation-probe-verified"
                            if persistence_failed
                            else "pending-isolation-probe"
                        )
                    },
                    "authentication": {
                        "status": "blocked-authentication",
                        "category": "blocked-authentication",
                        "model": model,
                        "failure_class": (
                            "refresh-persistence"
                            if persistence_failed
                            else "credential-source"
                        ),
                    },
                    "attempt": (
                        {
                            "requested_model": model,
                            "effective_model": None,
                            "requested_effort": CLAUDE_REASONING_EFFORT,
                            "effective_effort": None,
                            "category": "blocked-authentication",
                            "returncode": completed.returncode,
                            "failure_class": "refresh-persistence",
                        }
                        if completed is not None
                        else None
                    ),
                },
            )
            translated_error: ClaudeKeychainCredentialUnavailable
            if isinstance(error, LinuxCredentialUnsafe):
                translated_error = ClaudeCredentialUnsafe(
                    f"Claude Linux local-login credential is unsafe: {error}"
                )
            else:
                translated_error = ClaudeKeychainCredentialUnavailable(str(error))
            if completed is not None:
                setattr(
                    translated_error,
                    "_codex_claude_persistence_attempt",
                    _claude_persistence_failed_attempt(
                        review=review,
                        index=index,
                        model=model,
                        completed=completed,
                    ),
                )
            raise translated_error from error
        except BaseException as error:
            _record_claude_secondary_persistence_failure(
                review,
                error,
            )
            raise
    else:
        runtime_started = False
        try:
            with contextlib.ExitStack() as stack:
                env = stack.enter_context(
                    _claude_keychain_runtime(
                        review,
                        env,
                        selected_refresh_lock_protocol,
                    )
                )
                proxy_port = stack.enter_context(_claude_connect_proxy(env))
                review_env = _with_claude_proxy_environment(env, proxy_port)
                sandbox_profile = _claude_review_sandbox_profile(
                    executable,
                    review,
                    review_env,
                    proxy_port=proxy_port,
                )
                _update_claude_runtime_report(
                    review,
                    {
                        "phase": "runtime-launching",
                        "outer_sandbox": {"status": "profile-generated"},
                        "authentication": {"status": "sandbox-auth-staged"},
                    },
                )
                runtime_started = True
                completed = run(
                    (
                        str(CLAUDE_PROBE_SANDBOX),
                        "-p",
                        sandbox_profile,
                        str(executable),
                        *arguments,
                    ),
                    cwd=review.workspace_root,
                    env=review_env,
                    stdin=prompt,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
                    output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
                )
        except ClaudeCredentialInspectionInconclusive as error:
            persistence_failed = completed is not None
            _update_claude_runtime_report_preserving_persistence(
                review,
                {
                    "phase": "authentication-inspection-inconclusive",
                    "status": "inconclusive",
                    "outer_sandbox": {
                        "status": (
                            "enforced-at-launch"
                            if runtime_started
                            else "pending-runtime-launch"
                        )
                    },
                    "authentication": {
                        "status": "inspection-inconclusive",
                        "model": model,
                        "failure_class": (
                            "stale-refresh-lock"
                            if isinstance(error, ClaudeCredentialStaleRefreshLock)
                            else (
                                "refresh-persistence"
                                if persistence_failed
                                else "credential-inspection"
                            )
                        ),
                    },
                    "attempt": (
                        {
                            "requested_model": model,
                            "effective_model": None,
                            "requested_effort": CLAUDE_REASONING_EFFORT,
                            "effective_effort": None,
                            "category": "inconclusive",
                            "returncode": completed.returncode,
                            "failure_class": (
                                "stale-refresh-lock"
                                if isinstance(
                                    error,
                                    ClaudeCredentialStaleRefreshLock,
                                )
                                else "refresh-persistence"
                            ),
                        }
                        if completed is not None
                        else None
                    ),
                },
                error,
            )
            if completed is not None:
                authentication_error = (
                    _claude_auth_rejection_after_credential_inspection(
                        review=review,
                        index=index,
                        model=model,
                        completed=completed,
                        inspection_error=error,
                    )
                )
                if authentication_error is not None:
                    raise authentication_error from error
                setattr(
                    error,
                    "_codex_claude_persistence_attempt",
                    _claude_persistence_failed_attempt(
                        review=review,
                        index=index,
                        model=model,
                        completed=completed,
                        category="inconclusive",
                    ),
                )
            raise
        except ClaudeKeychainCredentialUnavailable as error:
            persistence_failed = completed is not None
            _update_claude_runtime_report(
                review,
                {
                    "phase": "blocked-authentication",
                    "status": "blocked-authentication",
                    "category": "blocked-authentication",
                    "outer_sandbox": {
                        "status": (
                            "enforced-at-launch"
                            if runtime_started
                            else "pending-runtime-launch"
                        )
                    },
                    "authentication": {
                        "status": "blocked-authentication",
                        "category": "blocked-authentication",
                        "model": model,
                        "failure_class": (
                            "refresh-persistence"
                            if persistence_failed
                            else "credential-source"
                        ),
                    },
                    "attempt": (
                        {
                            "requested_model": model,
                            "effective_model": None,
                            "requested_effort": CLAUDE_REASONING_EFFORT,
                            "effective_effort": None,
                            "category": "blocked-authentication",
                            "returncode": completed.returncode,
                            "failure_class": "refresh-persistence",
                        }
                        if completed is not None
                        else None
                    ),
                },
            )
            if completed is not None:
                setattr(
                    error,
                    "_codex_claude_persistence_attempt",
                    _claude_persistence_failed_attempt(
                        review=review,
                        index=index,
                        model=model,
                        completed=completed,
                    ),
                )
            raise
        except (
            ClaudeKeychainBrokerUnavailable,
            ClaudeLoopbackUnavailable,
        ):
            _update_claude_runtime_report(
                review,
                {
                    "phase": "authentication-preflight-unavailable",
                    "outer_sandbox": {"status": "pending-runtime-launch"},
                    "authentication": {
                        "status": "runtime-unavailable",
                        "model": model,
                    },
                    "attempt": None,
                },
            )
            raise
    assert completed is not None
    final_text, effective_model = _parse_claude_output(
        completed.stdout, requested_model=model
    )
    attempt = _record_attempt(
        review=review,
        index=index,
        runtime="claude",
        model=model,
        completed=completed,
        final_text=final_text if completed.returncode == 0 else None,
        effective_model=effective_model,
        requested_effort=CLAUDE_REASONING_EFFORT,
        effective_effort=None,
        require_verified_model=True,
    )
    _update_claude_runtime_report(
        review,
        {
            "phase": "attempt-complete",
            "outer_sandbox": {
                "status": (
                    "isolation-probe-verified"
                    if _is_claude_linux_host()
                    else "enforced-at-launch"
                )
            },
            "attempt": {
                "requested_model": model,
                "effective_model": attempt.effective_model,
                "requested_effort": CLAUDE_REASONING_EFFORT,
                "effective_effort": attempt.effective_effort,
                "category": attempt.category,
                "returncode": attempt.returncode,
            },
        },
    )
    return attempt


def _copilot_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
) -> Attempt:
    executable = resolve_reviewer_executable("copilot")
    if executable is None:
        raise FileNotFoundError(
            "copilot is not available in a validated executable path"
        )
    env = _with_executable_path(env, executable)
    copilot_home = review.container_dir / "copilot-home"
    try:
        copilot_home.mkdir(mode=0o700, exist_ok=True)
    except OSError as error:
        raise ReviewError(f"cannot create isolated Copilot home: {error}") from error
    if copilot_home.is_symlink() or not copilot_home.is_dir():
        raise ReviewError("isolated Copilot home is not a real directory")
    env = dict(env)
    env["COPILOT_HOME"] = str(copilot_home)
    stdout_path, stderr_path = _attempt_paths(review, index, "copilot", model)
    permission_help = run(
        (str(executable), "help", "permissions"),
        env=env,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        capture_limit_bytes=COPILOT_PROBE_OUTPUT_LIMIT_BYTES,
        timeout_seconds=COPILOT_PROBE_TIMEOUT_SECONDS,
        output_file_limit_bytes=COPILOT_PROBE_OUTPUT_LIMIT_BYTES,
    )
    normalized_permission_help = " ".join(
        (permission_help.stdout + b"\n" + permission_help.stderr)
        .decode("utf-8", errors="replace")
        .lower()
        .split()
    )
    if permission_help.returncode != 0 or any(
        fragment not in normalized_permission_help
        for fragment in COPILOT_PERMISSION_HELP_FRAGMENTS
    ):
        raise ReviewError(
            "Copilot CLI did not expose the required cwd-only path verifier, "
            "temporary-directory denial, and deny-over-allow permission semantics"
        )
    command = [
        str(executable),
        "-C",
        str(review.workspace_root),
        "--prompt",
        review.prompt_file.read_text(encoding="utf-8"),
        "--model",
        model,
        "--reasoning-effort",
        COPILOT_REASONING_EFFORT,
        "--output-format",
        "json",
        "--mode",
        "plan",
        "--available-tools=view,glob,grep",
        "--allow-all-tools",
        "--deny-tool=write",
        "--deny-tool=shell",
        "--deny-tool=url",
        "--disallow-temp-dir",
        "--disable-builtin-mcps",
        "--no-bash-env",
        "--no-custom-instructions",
        "--no-experimental",
        "--no-remote",
        "--no-remote-export",
        "--no-color",
        "--no-ask-user",
        "--no-auto-update",
    ]
    sensitive_names = sorted(
        name
        for name in env
        if any(
            marker in name.upper()
            for marker in (
                "API_KEY",
                "CREDENTIAL",
                "PASSWORD",
                "PRIVATE_KEY",
                "SECRET",
                "TOKEN",
            )
        )
    )
    if sensitive_names:
        command.append(f"--secret-env-vars={','.join(sensitive_names)}")
    completed = run(
        command,
        cwd=review.workspace_root,
        env=env,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
    )
    final_text, effective_model = _parse_copilot_output_file(
        stdout_path, requested_model=model
    )
    return _record_attempt(
        review=review,
        index=index,
        runtime="copilot",
        model=model,
        completed=completed,
        final_text=final_text if completed.returncode == 0 else None,
        effective_model=effective_model,
        requested_effort=COPILOT_REASONING_EFFORT,
        effective_effort=None,
        require_verified_model=True,
    )


AttemptRunner = Callable[..., Attempt]

REVIEW_SUPERVISION_FAILURE_CLASSES: tuple[
    tuple[type[Exception], str], ...
] = (
    (ReviewTimeoutError, "timeout"),
    (ReviewOutputLimitError, "output-limit"),
    (ReviewOutputDrainError, "output-drain"),
    (ReviewProcessLeakError, "process-leak"),
)


def _review_supervision_failure_class(error: Exception) -> str:
    for error_type, failure_class in REVIEW_SUPERVISION_FAILURE_CLASSES:
        if isinstance(error, error_type):
            return failure_class
    return "supervision-inconclusive"


def _attempt_summary(attempt: Attempt) -> dict[str, Any]:
    return {
        "runtime": attempt.runtime,
        "requested_model": attempt.requested_model,
        "effective_model": attempt.effective_model,
        "requested_effort": attempt.requested_effort,
        "effective_effort": attempt.effective_effort,
        "returncode": attempt.returncode,
        "category": attempt.category,
        "final_available": bool(attempt.final_text),
        "stdout_path": attempt.stdout_path,
        "stderr_path": attempt.stderr_path,
    }


def _write_attempts(review: ReviewWorkspace, attempts: Iterable[Attempt]) -> None:
    write_json(
        review.container_dir / "attempts.json",
        [_attempt_summary(item) for item in attempts],
    )


def _finish(
    review: ReviewWorkspace, attempts: list[Attempt], final_text: str | None
) -> Outcome:
    _write_attempts(review, attempts)
    if final_text:
        write_text_atomic(
            review.container_dir / "final.txt", final_text.rstrip("\r\n") + "\n"
        )
        return Outcome(0, final_text, tuple(attempts))
    if attempts and attempts[-1].category == "transient":
        return Outcome(75, None, tuple(attempts))
    return Outcome(1, None, tuple(attempts))


def _finish_claude_auth_required(
    review: ReviewWorkspace,
    attempts: list[Attempt],
    detail: str,
    *,
    action: str = CLAUDE_AUTH_LOGIN_ACTION,
) -> Outcome:
    if attempts and attempts[-1].category == "auth":
        attempts[-1] = replace(
            attempts[-1],
            category="blocked-authentication",
        )
    failure_class = "auth"
    runtime_report_path = review.container_dir / "claude-runtime.json"
    if runtime_report_path.exists():
        current_report = read_json(runtime_report_path)
        current_authentication = current_report.get("authentication")
        if isinstance(current_authentication, dict) and isinstance(
            current_authentication.get("failure_class"),
            str,
        ):
            failure_class = current_authentication["failure_class"]
    _update_claude_runtime_report(
        review,
        {
            "phase": "blocked-authentication",
            "status": "blocked-authentication",
            "category": "blocked-authentication",
            "authentication": {
                "status": "blocked-authentication",
                "category": "blocked-authentication",
                "failure_class": failure_class,
            },
        },
    )
    write_text_atomic(
        review.container_dir / "runner-error.txt",
        f"Claude Code authentication requires user action: {detail}. "
        f"{action}\n",
    )
    _write_attempts(review, attempts)
    return Outcome(2, None, tuple(attempts))


def _run_model_chain(
    *,
    review: ReviewWorkspace,
    models: Iterable[str],
    runner: AttemptRunner,
    runtime: str,
    requested_effort: str,
    env: dict[str, str],
    attempts: list[Attempt],
) -> tuple[str, str | None]:
    for model in models:
        index = len(attempts) + 1
        try:
            attempt = runner(
                review=review,
                model=model,
                index=index,
                env=env,
            )
        except (
            ReviewTimeoutError,
            ReviewOutputDrainError,
            ReviewOutputLimitError,
            ReviewProcessLeakError,
        ) as error:
            stdout_path, stderr_path = _attempt_paths(review, index, runtime, model)
            stdout_path.touch(exist_ok=True)
            _append_attempt_diagnostic(stderr_path, f"review supervision failed: {error}")
            attempts.append(
                Attempt(
                    runtime=runtime,
                    requested_model=model,
                    effective_model=None,
                    requested_effort=requested_effort,
                    effective_effort=None,
                    returncode=75,
                    category="inconclusive",
                    final_text=None,
                    stdout_path=str(stdout_path),
                    stderr_path=str(stderr_path),
                )
            )
            _write_attempts(review, attempts)
            raise
        attempts.append(attempt)
        _write_attempts(review, attempts)
        if attempt.category == "success":
            return "success", attempt.final_text
        if attempt.category != "entitlement":
            return attempt.category, None
    return "entitlement", None


def run_review(
    *,
    review: ReviewWorkspace,
    reviewer: str,
    egress_consent: str | None = None,
) -> Outcome:
    if reviewer not in ("codex", "claude"):
        write_text_atomic(
            review.container_dir / "runner-error.txt", f"unknown reviewer: {reviewer}\n"
        )
        return Outcome(2, None, tuple())

    if reviewer == "claude":
        if egress_consent not in CLAUDE_EGRESS_CONSENTS:
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                "The low-level Claude helper requires an explicit egress-consent reason.\n",
            )
            return Outcome(2, None, tuple())
    elif egress_consent is not None:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "egress-consent is valid only for the low-level Claude helper.\n",
        )
        return Outcome(2, None, tuple())

    try:
        synthetic_evidence = validate_external_workspace(review) or {}
    except ReviewError as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            f"review egress workspace preflight failed: {error}\n",
        )
        return Outcome(2, None, tuple())

    preflight_evidence = {
        "review_range": f"{review.base_ref}..{review.head_ref}",
        "scope": "frozen tracked workspace, diff, and review prompt",
        "status": "sensitive-content and escaping-symlink checks passed",
    }
    preflight_evidence.update(synthetic_evidence)
    write_text_atomic(
        review.container_dir / "preflight.json",
        encode_preflight_json(preflight_evidence),
    )

    if reviewer == "claude":
        write_json(
            review.container_dir / "egress.json",
            {
                "consent": egress_consent,
                "reviewer": "low-level-helper",
                "requested_helper_reviewer": "claude",
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "review_range": f"{review.base_ref}..{review.head_ref}",
                "included": [
                    "tracked blobs materialized from the frozen head commit",
                    "the generated frozen diff",
                    "the review prompt and result",
                ],
                "excluded": [
                    "credential paths and high-confidence secrets blocked by preflight",
                    "untracked files",
                    "unrelated repositories",
                    "broad workspace or home-directory content",
                ],
                "preflight": "sensitive-content and escaping-symlink checks passed",
            },
        )

    attempts: list[Attempt] = []

    if reviewer == "codex":
        env = _review_environment(
            review=review,
            passthrough_keys=CODEX_ENV_KEYS,
        )
        try:
            _, final_text = _run_model_chain(
                review=review,
                models=CODEX_MODELS,
                runner=_codex_attempt,
                runtime="codex",
                requested_effort=CODEX_REASONING_EFFORT,
                env=env,
                attempts=attempts,
            )
        except FileNotFoundError as error:
            write_text_atomic(review.container_dir / "runner-error.txt", f"{error}\n")
            return Outcome(127, None, tuple())
        except (
            ReviewTimeoutError,
            ReviewOutputDrainError,
            ReviewOutputLimitError,
            ReviewProcessLeakError,
        ) as error:
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                f"Codex review was inconclusive: {error}\n",
            )
            _write_attempts(review, attempts)
            return Outcome(75, None, tuple(attempts))
        return _finish(review, attempts, final_text)

    claude_env = _review_environment(
        review=review,
        passthrough_keys=CLAUDE_ENV_KEYS,
        extra={
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_SAFE_MODE": "1",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        },
    )
    explicit_claude_override = bool(
        os.environ.get("CODEX_REVIEW_CLAUDE_PATH")
    )
    try:
        linux_host = _is_claude_linux_host()
        prompt = _claude_review_prompt(
            review,
            review.prompt_file.read_bytes(),
            linux=linux_host,
        )
        if linux_host:
            _require_claude_linux_prompt_without_file_mentions(
                prompt
            )
        claude_executable, claude_env = _resolve_validated_claude_executable(
            review=review,
            env=claude_env,
        )
        claude_available = claude_executable is not None
        if claude_available:
            if not _is_claude_linux_host():
                claude_env = _prepare_claude_keychain_broker(review, claude_env)
            claude_env = _with_claude_review_tool_path(review, claude_env)
    except ClaudeKeychainCredentialUnavailable as error:
        persistence_attempt = getattr(
            error,
            "_codex_claude_persistence_attempt",
            None,
        )
        if isinstance(persistence_attempt, Attempt):
            attempts.append(persistence_attempt)
        return _finish_claude_auth_required(review, attempts, str(error))
    except (
        ClaudeProbeSandboxUnavailable,
        ClaudeKeychainBrokerUnavailable,
        ClaudeReviewToolUnavailable,
        ClaudeLoopbackUnavailable,
        ClaudeExecutableUnavailable,
        ClaudeProvenanceVerifierUnavailable,
    ) as error:
        if explicit_claude_override and isinstance(
            error,
            (
                ClaudeExecutableUnavailable,
                ClaudeProbeSandboxUnavailable,
                ClaudeReviewToolUnavailable,
                ClaudeProvenanceVerifierUnavailable,
            ),
        ):
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                "Explicit CODEX_REVIEW_CLAUDE_PATH lacks a required secure "
                "runtime prerequisite; refusing Copilot fallback: "
                f"{error}\n",
            )
            _write_attempts(review, attempts)
            return Outcome(2, None, tuple(attempts))
        claude_available = False
        write_text_atomic(
            review.container_dir / "claude-skip.txt",
            f"Claude Code secure runtime is unavailable: {error}\n",
        )
    except (
        FileNotFoundError,
        ClaudeCredentialInspectionInconclusive,
        ClaudeExecutableInspectionInconclusive,
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewOutputLimitError,
        ReviewProcessLeakError,
    ) as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            f"Claude Code validation was inconclusive: {error}\n",
        )
        write_json(review.container_dir / "attempts.json", [])
        return Outcome(75, None, tuple(attempts))
    except ReviewError as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code executable validation failed; refusing Copilot fallback: "
            f"{error}\n",
        )
        write_json(review.container_dir / "attempts.json", [])
        return Outcome(2, None, tuple(attempts))
    if claude_available and claude_executable is not None:
        def run_claude_attempt_with_verified_executable(
            *,
            review: ReviewWorkspace,
            model: str,
            index: int,
            env: dict[str, str],
        ) -> Attempt:
            return _claude_attempt(
                review=review,
                model=model,
                index=index,
                env=env,
                executable=claude_executable,
            )

        try:
            category, final_text = _run_model_chain(
                review=review,
                models=CLAUDE_MODELS,
                runner=run_claude_attempt_with_verified_executable,
                runtime="claude",
                requested_effort=CLAUDE_REASONING_EFFORT,
                env=claude_env,
                attempts=attempts,
            )
        except (
            FileNotFoundError,
            ClaudeCredentialInspectionInconclusive,
            ClaudeExecutableInspectionInconclusive,
            ReviewTimeoutError,
            ReviewOutputDrainError,
            ReviewOutputLimitError,
            ReviewProcessLeakError,
        ) as error:
            persistence_attempt = getattr(
                error,
                "_codex_claude_persistence_attempt",
                None,
            )
            if isinstance(persistence_attempt, Attempt):
                attempts.append(persistence_attempt)
            persistence_diagnostic = _record_claude_secondary_persistence_failure(
                review,
                error,
            )
            if isinstance(
                error,
                (
                    ReviewTimeoutError,
                    ReviewOutputDrainError,
                    ReviewOutputLimitError,
                    ReviewProcessLeakError,
                ),
            ):
                _update_claude_runtime_report(
                    review,
                    {
                        "phase": "attempt-inconclusive",
                        "attempt": {
                            "category": "inconclusive",
                            "failure_class": _review_supervision_failure_class(error),
                        },
                    },
                )
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                f"Claude Code validation was inconclusive: {error}\n"
                + (
                    f"{persistence_diagnostic}\n"
                    if persistence_diagnostic is not None
                    else ""
                ),
            )
            _write_attempts(review, attempts)
            return Outcome(75, None, tuple(attempts))
        except ClaudeKeychainCredentialUnavailable as error:
            persistence_attempt = getattr(
                error,
                "_codex_claude_persistence_attempt",
                None,
            )
            if isinstance(persistence_attempt, Attempt):
                attempts.append(persistence_attempt)
            persistence_diagnostic = _record_claude_secondary_persistence_failure(
                review,
                error,
            )
            detail = str(error)
            if persistence_diagnostic is not None:
                detail = (
                    f"{detail.rstrip('.')}; "
                    f"{persistence_diagnostic.rstrip('.')}"
                )
            return _finish_claude_auth_required(review, attempts, detail)
        except (
            ClaudeKeychainBrokerUnavailable,
            ClaudeReviewToolUnavailable,
            ClaudeLoopbackUnavailable,
            ClaudeExecutableUnavailable,
            ClaudeProbeSandboxUnavailable,
            ClaudeProvenanceVerifierUnavailable,
        ) as error:
            if explicit_claude_override and isinstance(
                error,
                (
                    ClaudeExecutableUnavailable,
                    ClaudeProbeSandboxUnavailable,
                    ClaudeReviewToolUnavailable,
                    ClaudeProvenanceVerifierUnavailable,
                ),
            ):
                write_text_atomic(
                    review.container_dir / "runner-error.txt",
                    "Explicit CODEX_REVIEW_CLAUDE_PATH lacks a required secure "
                    "runtime prerequisite; refusing Copilot fallback: "
                    f"{error}\n",
                )
                _write_attempts(review, attempts)
                return Outcome(2, None, tuple(attempts))
            category = "unavailable"
            final_text = None
            write_text_atomic(
                review.container_dir / "claude-skip.txt",
                f"Claude Code local authentication became unavailable: {error}\n",
            )
        except ReviewError as error:
            persistence_diagnostic = _record_claude_secondary_persistence_failure(
                review,
                error,
            )
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                "Claude Code failed executable validation; "
                f"refusing Copilot fallback: {error}\n"
                + (
                    f"{persistence_diagnostic}\n"
                    if persistence_diagnostic is not None
                    else ""
                ),
            )
            _write_attempts(review, attempts)
            return Outcome(2, None, tuple(attempts))
        if final_text:
            return _finish(review, attempts, final_text)
        if category == "auth":
            return _finish_claude_auth_required(
                review,
                attempts,
                "the restricted Claude runtime rejected the configured credential",
                action=(
                    CLAUDE_API_KEY_ACTION
                    if claude_env.get("ANTHROPIC_API_KEY")
                    else CLAUDE_AUTH_LOGIN_ACTION
                ),
            )
        if category not in {"entitlement", "unavailable"}:
            return _finish(review, attempts, None)

    if egress_consent not in COPILOT_EGRESS_CONSENTS:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code was unavailable or lacked model entitlement. "
            "explicit-claude-review does not authorize GitHub Copilot; only "
            "explicit-claude-with-copilot-fallback authorizes the separately "
            "requested compatibility fallback.\n",
        )
        _write_attempts(review, attempts)
        return Outcome(2, None, tuple(attempts))

    try:
        copilot_available = resolve_reviewer_executable("copilot") is not None
    except ReviewError as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            f"Copilot CLI executable validation failed: {error}\n",
        )
        _write_attempts(review, attempts)
        return Outcome(2, None, tuple(attempts))
    if not copilot_available:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code was unavailable or lacked model entitlement, and "
            "Copilot CLI is unavailable.\n",
        )
        return _finish(review, attempts, None)
    copilot_env = _review_environment(
        review=review,
        passthrough_keys=COPILOT_ENV_KEYS,
    )
    try:
        _, final_text = _run_model_chain(
            review=review,
            models=COPILOT_MODELS,
            runner=_copilot_attempt,
            runtime="copilot",
            requested_effort=COPILOT_REASONING_EFFORT,
            env=copilot_env,
            attempts=attempts,
        )
    except (
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewOutputLimitError,
        ReviewProcessLeakError,
    ) as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            f"Copilot review was inconclusive: {error}\n",
        )
        _write_attempts(review, attempts)
        return Outcome(75, None, tuple(attempts))
    except (FileNotFoundError, ReviewError) as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            f"Copilot CLI became unavailable or failed executable validation: {error}\n",
        )
        _write_attempts(review, attempts)
        return Outcome(2, None, tuple(attempts))
    return _finish(review, attempts, final_text)
