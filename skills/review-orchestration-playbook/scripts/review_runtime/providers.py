from __future__ import annotations

import base64
import binascii
import contextlib
import errno
import hashlib
import hmac
import itertools
import json
import math
import os
import pathlib
import plistlib
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
from dataclasses import dataclass, replace
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
    CLAUDE_BINARY_MAX_BYTES,
    CLAUDE_RELEASE_KEY_FINGERPRINT,
    ClaudeProvenanceDependencyUnavailable,
    ClaudeProvenanceInconclusive,
    ClaudeProvenanceInvalid,
    ClaudeProvenanceUnavailable,
    VerifiedClaudeExecutable,
    materialize_verified_executable,
    verify_claude_release,
)
from .claude_linux import (
    CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
    CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS,
    CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS,
    CLAUDE_LINUX_REVIEW_PERMISSION_MODE,
    CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS,
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
    InvalidReviewerExecutable,
    RejectedReviewerCandidates,
    ReviewError,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    child_environment,
    is_relative_to,
    read_json,
    reviewer_executable_path,
    resolve_reviewer_executable,
    run,
    run_bounded_capture,
    strict_json_loads,
    write_json,
    write_text_atomic,
)
from .workspace import (
    MAX_REVIEW_PROMPT_BYTES,
    ReviewWorkspace,
    validate_external_workspace,
)


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
CLAUDE_KEYCHAIN_MACH_SERVICES = ("com.apple.securityd.xpc",)
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
CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES = 1024 * 1024
CLAUDE_KEYCHAIN_ITEM_NOT_FOUND_STATUS = 44
CLAUDE_AUTH_WARMUP_TIMEOUT_SECONDS = 120.0
CLAUDE_AUTH_EXPIRY_MARGIN_SECONDS = 120.0
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
CLAUDE_TLS_BYPASS_ENV_KEYS = (
    "NODE_OPTIONS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
)
CLAUDE_CA_FILE_LIMIT_BYTES = 16 * 1024 * 1024
CLAUDE_CA_DIR_LIMIT_BYTES = 64 * 1024 * 1024
CLAUDE_CA_DIR_ENTRY_LIMIT = 4096
CLAUDE_CA_SYMLINK_LIMIT = 32
CLAUDE_CA_PATH_COMPONENT_LIMIT = 256
CLAUDE_EXECUTABLE_HASH_CHUNK_BYTES = 1024 * 1024
CLAUDE_BUNDLED_CERTIFICATE_LIMIT_BYTES = 128 * 1024
CLAUDE_BUNDLED_ROOT_LIMIT = 512
CLAUDE_BUNDLED_ROOT_STORE_LIMIT_BYTES = 8 * 1024 * 1024
CLAUDE_BUNDLED_ROOT_STORE_TRAILER = (
    b"\x00NODE_EXTRA_CA_CERTS\x00"
    b"unified/../../../packages/bun-usockets/src/crypto/root_certs.cpp\x00"
    b"NODE_USE_SYSTEM_CA\x00"
)
CLAUDE_CERTIFICATE_SIGNATURE_DIGESTS = {
    bytes.fromhex("2a864886f70d010105"): "sha1",
    bytes.fromhex("2a864886f70d01010b"): "sha256",
    bytes.fromhex("2a864886f70d01010c"): "sha384",
    bytes.fromhex("2a864886f70d01010d"): "sha512",
    bytes.fromhex("2a8648ce3d040302"): "sha256",
    bytes.fromhex("2a8648ce3d040303"): "sha384",
    bytes.fromhex("2a8648ce3d040304"): "sha512",
}
CLAUDE_OPENSSL_CLIENT = pathlib.Path("/usr/bin/openssl")
CLAUDE_SYSTEM_CA_FILE = pathlib.Path("/private/etc/ssl/cert.pem")
CLAUDE_SYSTEM_KEYCHAIN = pathlib.Path("/Library/Keychains/System.keychain")
CLAUDE_SYSTEM_ROOT_KEYCHAIN = pathlib.Path(
    "/System/Library/Keychains/SystemRootCertificates.keychain"
)
CLAUDE_TRUST_CERTIFICATE_SOURCES = (
    ("default keychain search", ()),
    ("system keychain", (str(CLAUDE_SYSTEM_KEYCHAIN),)),
    ("system root keychain", (str(CLAUDE_SYSTEM_ROOT_KEYCHAIN),)),
)
CLAUDE_CA_BUNDLE_NAME = "trusted-ca-bundle.pem"
CLAUDE_CALLER_CA_SNAPSHOT_NAME = ".caller-ca-snapshot.pem"
CLAUDE_TRUST_POLICY_EVIDENCE_NAME = "claude-trust-policy.json"
CLAUDE_CERT_STORE_ENV = "CLAUDE_CODE_CERT_STORE"
CLAUDE_CERT_STORE = "bundled"
CLAUDE_TRUST_DOMAINS = (
    ("user", ()),
    ("admin", ("-d",)),
    ("system", ("-s",)),
)
CLAUDE_TRUST_NO_SETTINGS = (
    "SecTrustSettingsExport: No Trust Settings were found.",
    "SecTrustSettingsCreateExternalRepresentation: No Trust Settings were found.",
)
CLAUDE_TRUST_EXPORT_HELP_VARIANTS = (
    (
        "Usage: trust-settings-export [-s] [-d] settings_file",
        "-s Export system trust settings (default is user)",
        "-d Export admin trust settings (default is user)",
    ),
    (
        "Usage: trust-settings-export [-s] [-d] settings_file",
        "-s Export system Trust Settings; default is user.",
        "-d Export admin Trust Settings; default is user.",
    ),
)
CLAUDE_TRUST_EXPORT_UNAVAILABLE = (
    "SecTrustSettingsCreateExternalRepresentation: No keychain is available. "
    "You may need to restart your computer."
)
CLAUDE_TRUST_FINGERPRINT = re.compile(r"^[0-9A-Fa-f]{40}$")
CLAUDE_TRUST_RESULT_KEY = "kSecTrustSettingsResult"
CLAUDE_TRUST_RESULT_TRUST_ROOT = 1
CLAUDE_TRUST_RESULT_TRUST_AS_ROOT = 2
CLAUDE_TRUST_RESULT_DENY = 3
CLAUDE_TRUST_RESULTS = frozenset({1, 2, 3, 4})
CLAUDE_TRUST_UNCONSTRAINED_RESULTS = frozenset(
    {CLAUDE_TRUST_RESULT_TRUST_ROOT, CLAUDE_TRUST_RESULT_TRUST_AS_ROOT}
)
CLAUDE_CALLER_CA_INPUT_LIMIT_BYTES = 8 * 1024 * 1024
CLAUDE_CALLER_CA_SNAPSHOT_LIMIT_BYTES = CLAUDE_CALLER_CA_INPUT_LIMIT_BYTES + math.ceil(
    CLAUDE_CALLER_CA_INPUT_LIMIT_BYTES / 32
)
CLAUDE_CA_BUNDLE_INPUT_LIMIT_BYTES = (
    CLAUDE_CALLER_CA_INPUT_LIMIT_BYTES
    + CLAUDE_CA_FILE_LIMIT_BYTES * (2 + len(CLAUDE_TRUST_CERTIFICATE_SOURCES))
)
CLAUDE_CA_BUNDLE_LIMIT_BYTES = CLAUDE_CA_BUNDLE_INPUT_LIMIT_BYTES + math.ceil(
    CLAUDE_CA_BUNDLE_INPUT_LIMIT_BYTES / 32
)
CLAUDE_TRUST_SETTINGS_LIMIT_BYTES = 1024 * 1024
CLAUDE_TRUST_ENTRY_LIMIT = 4096
CLAUDE_ADDITIONAL_TRUST_ROOT_LIMIT = 256
CLAUDE_TRUST_ROOT_VERIFY_TOTAL_SECONDS = 30.0
CLAUDE_CERTIFICATE_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
CLAUDE_PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN [^-\r\n]*PRIVATE KEY-----")
CLAUDE_PROXY_TARGETS = frozenset({("api.anthropic.com", 443)})
CLAUDE_AUTH_PROXY_TARGETS = frozenset(
    {
        ("api.anthropic.com", 443),
        ("platform.claude.com", 443),
    }
)
CLAUDE_PROXY_HEADER_LIMIT_BYTES = 64 * 1024
CLAUDE_PROXY_CONNECT_TIMEOUT_SECONDS = 20.0
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
CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS = (
    REVIEW_ATTEMPT_TIMEOUT_SECONDS + CLAUDE_AUTH_EXPIRY_MARGIN_SECONDS
)
REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024
COPILOT_JSONL_RECORD_LIMIT_BYTES = 4 * 1024 * 1024
CLAUDE_EGRESS_CONSENTS = (
    "explicit-claude-review",
    "double-review",
    "triple-review",
)
COPILOT_EGRESS_CONSENTS = ("double-review", "triple-review")
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
STRUCTURED_AMBIGUOUS_MODEL_CODES = ("model_not_found", "not_found_error")

AUTH_FAILURE_FRAGMENTS = (
    "authentication failed",
    "not authenticated",
    "not logged in",
    "login required",
    "invalid api key",
    "invalid token",
    "unauthorized",
    "status 401",
)
CLAUDE_RESULT_AUTH_MESSAGES = frozenset(
    {
        "not logged in - please run /login",
        "not logged in - please run `/login`",
    }
)
CLAUDE_AUTH_WARMUP_SAFE_TYPES = frozenset({"result"})
CLAUDE_AUTH_WARMUP_SAFE_SUBTYPES = frozenset({"error_during_execution", "success"})
CLAUDE_AUTH_WARMUP_ERROR_FIELDS = frozenset(
    {
        "api_error_status",
        "code",
        "detail",
        "error",
        "errors",
        "message",
        "reason",
    }
)
CLAUDE_FAILURE_ENVELOPE_FIELDS = (
    frozenset(
        {
            "duration_api_ms",
            "duration_ms",
            "is_error",
            "modelUsage",
            "num_turns",
            "permission_denials",
            "result",
            "session_id",
            "subtype",
            "total_cost_usd",
            "type",
            "usage",
            "uuid",
        }
    )
    | CLAUDE_AUTH_WARMUP_ERROR_FIELDS
)
CLAUDE_ERROR_PAYLOAD_FIELDS = frozenset(
    {
        "code",
        "detail",
        "error",
        "errors",
        "message",
        "reason",
        "status",
        "subtype",
        "type",
    }
)
CLAUDE_MODEL_USAGE_FIELDS = frozenset(
    {
        "cacheCreationInputTokens",
        "cacheReadInputTokens",
        "contextWindow",
        "costUSD",
        "inputTokens",
        "maxOutputTokens",
        "outputTokens",
        "webSearchRequests",
    }
)
CLAUDE_USAGE_FIELDS = frozenset(
    {
        "cache_creation",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "input_tokens",
        "output_tokens",
        "server_tool_use",
        "service_tier",
    }
)
CLAUDE_USAGE_CACHE_CREATION_FIELDS = frozenset(
    {"ephemeral_1h_input_tokens", "ephemeral_5m_input_tokens"}
)
CLAUDE_USAGE_SERVER_TOOL_FIELDS = frozenset(
    {"web_fetch_requests", "web_search_requests"}
)
CLAUDE_FAILURE_METADATA_ITEM_LIMIT = 4096
CLAUDE_AUTH_WARMUP_RESULT_SIGNAL_TERMS = {
    "auth": (
        "api key",
        "authentication",
        "credential",
        "log in",
        "logged in",
        "login",
        "oauth",
        "sign in",
        "token",
        "unauthorized",
    ),
    "entitlement": (
        "account",
        "billing",
        "model is not available",
        "organization policy",
        "plan",
        "subscription",
    ),
    "transient": (
        "connection",
        "network",
        "overloaded",
        "rate limit",
        "temporarily",
        "timeout",
        "try again",
    ),
}
CODEX_ARG_TRANSPORT_NAME = re.compile(r"codex-arg0[A-Za-z0-9]+")


class ClaudeProbeSandboxUnavailable(ReviewError):
    """The host does not provide the required Claude probe sandbox runtime."""


class ClaudeKeychainBrokerUnavailable(ReviewError):
    """The host cannot build the restricted Claude Keychain broker."""


class ClaudeKeychainCredentialUnavailable(ReviewError):
    """Claude has no deterministic usable local-login credential."""


class ClaudeKeychainCredentialIntegrityError(ReviewError):
    """Claude credential contents or stable account binding failed inspection."""


class ClaudeKeychainCredentialRefreshRequired(ClaudeKeychainCredentialUnavailable):
    """The local Claude credential is valid but expires before the next attempt."""


class ClaudeAuthWarmupInconclusive(ReviewError):
    """Claude login refresh failed for a reason that must not trigger fallback."""


class ClaudeAuthWarmupEntitlement(ReviewError):
    """Claude login refresh proved that the requested model is not entitled."""

    def __init__(self, completed: Completed) -> None:
        super().__init__(
            "Claude authentication warmup reported a model entitlement denial"
        )
        self.completed = completed


class ClaudeReviewToolUnavailable(ReviewError):
    """The host lacks a trusted local tool required by Claude Code."""


class ClaudeLoopbackUnavailable(ReviewError):
    """The host cannot bind a loopback service required by Claude Code."""


class ClaudeExecutableUnavailable(ReviewError):
    """Automatic Claude discovery found only unsupported executables."""


class ClaudeExecutableInspectionInconclusive(ReviewError):
    """A Claude runtime file changed or became unreadable during inspection."""


class ClaudeTrustPolicyUnavailable(ReviewError):
    """Host trust policy is malformed or cannot be represented safely."""


class ClaudeTrustToolUnavailable(ClaudeReviewToolUnavailable):
    """The host cannot provide Apple's bounded trust export tooling."""


class ClaudeTrustCertificateInvalid(ReviewError):
    """An additional host trust certificate cannot be imported safely."""


class ClaudeCACertificateNotFound(ReviewError):
    """A bounded CA source contains no PEM certificate blocks."""


class ClaudeTrustSettingsDeny(ReviewError):
    """Host trust settings contain an explicit deny and require a hard stop."""


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
        path for path in CLAUDE_LINUX_BOOTSTRAP_LIBRARY_ROOT_CANDIDATES if path.is_dir()
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
        raise ReviewError(f"Claude Linux runtime path must be a real directory: {path}")
    if before.st_uid != os.geteuid():
        raise ReviewError(f"Claude runtime directory has an unexpected owner: {path}")
    if (private and mode != 0o700) or (not private and mode & 0o022):
        requirement = "0700" if private else "not group- or world-writable"
        raise ReviewError(f"Claude runtime directory must be {requirement}: {path}")
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
    if (
        len(
            {
                _claude_linux_directory_identity(before),
                _claude_linux_directory_identity(opened),
                _claude_linux_directory_identity(after),
            }
        )
        != 1
    ):
        raise ReviewError("Claude runtime directory changed during validation")
    return path


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
    reason: str | None = None


@dataclass(frozen=True)
class Outcome:
    returncode: int
    final_text: str | None
    attempts: tuple[Attempt, ...]


@dataclass(frozen=True)
class ClaudeExecutableTrustEvidence:
    executable_sha256: str
    bundled_root_certificates: bytes
    bundled_root_sha256_fingerprints: frozenset[bytes]

    @property
    def bundled_root_set_sha256(self) -> str:
        return hashlib.sha256(
            b"".join(sorted(self.bundled_root_sha256_fingerprints))
        ).hexdigest()


@dataclass(frozen=True)
class ClaudeTrustFingerprints:
    unconditional: tuple[str, ...]
    trust_as_root: tuple[str, ...]
    constrained: tuple[str, ...]


@dataclass(frozen=True)
class ClaudeSelectedTrustMaterial:
    certificates: bytes
    omitted_sha1_fingerprints: frozenset[str]


@dataclass(frozen=True)
class ClaudeTrustMaterial:
    certificates: bytes
    excluded_sha1_fingerprints: frozenset[str]
    evidence: dict[str, object]


@dataclass
class ClaudeTrustSessionState:
    caller_ca_snapshot_sha256: str | None = None


class _DuplicatePlistKey(ValueError):
    pass


class _UniquePlistDict(dict[Any, Any]):
    def __setitem__(self, key: Any, value: Any) -> None:
        if key in self:
            raise _DuplicatePlistKey
        super().__setitem__(key, value)


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
        raise InvalidReviewerExecutable("Claude Code Mach-O header is truncated")
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


def _canonical_ca_certificate(block: bytes, *, source: str) -> tuple[bytes, bytes]:
    lines = block.strip().splitlines()
    if len(lines) < 3:
        raise ReviewError(
            f"Claude review CA source contains an invalid certificate: {source}"
        )
    try:
        der = base64.b64decode(b"".join(lines[1:-1]), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ReviewError(
            f"Claude review CA source contains an invalid certificate: {source}"
        ) from error
    if not der:
        raise ReviewError(
            f"Claude review CA source contains an invalid certificate: {source}"
        )
    canonical = ssl.DER_cert_to_PEM_cert(der).encode("ascii")
    return der, canonical


def _der_tlv(
    data: bytes,
    offset: int,
    limit: int,
) -> tuple[int, int, int, int]:
    if offset < 0 or offset + 2 > limit or limit > len(data):
        raise ValueError("truncated DER element")
    tag = data[offset]
    first_length = data[offset + 1]
    cursor = offset + 2
    if first_length & 0x80:
        length_octets = first_length & 0x7F
        if (
            length_octets == 0
            or length_octets > 4
            or cursor + length_octets > limit
            or data[cursor] == 0
        ):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[cursor : cursor + length_octets], "big")
        if length < 0x80:
            raise ValueError("non-minimal DER length")
        cursor += length_octets
    else:
        length = first_length
    content_end = cursor + length
    if content_end > limit:
        raise ValueError("truncated DER content")
    return tag, cursor, content_end, content_end


def _require_unconditional_root_extensions(
    der: bytes,
    *,
    require_critical: bool = True,
    require_self_issued: bool = True,
) -> None:
    try:
        outer_tag, outer_start, outer_end, outer_next = _der_tlv(der, 0, len(der))
        if outer_tag != 0x30 or outer_next != len(der):
            raise ValueError("invalid certificate sequence")

        offset = outer_start
        tbs_tag, tbs_start, tbs_end, offset = _der_tlv(der, offset, outer_end)
        if tbs_tag != 0x30:
            raise ValueError("invalid TBSCertificate")
        signature_tag, _, _, offset = _der_tlv(der, offset, outer_end)
        signature_value_tag, _, _, offset = _der_tlv(der, offset, outer_end)
        if signature_tag != 0x30 or signature_value_tag != 0x03 or offset != outer_end:
            raise ValueError("invalid certificate signature")

        offset = tbs_start
        if offset < tbs_end and der[offset] == 0xA0:
            _, _, _, offset = _der_tlv(der, offset, tbs_end)
        for expected_tag in (0x02, 0x30):
            tag, _, _, offset = _der_tlv(der, offset, tbs_end)
            if tag != expected_tag:
                raise ValueError("invalid TBSCertificate field")

        issuer_offset = offset
        issuer_tag, _, _, offset = _der_tlv(der, offset, tbs_end)
        issuer = der[issuer_offset:offset]
        validity_tag, _, _, offset = _der_tlv(der, offset, tbs_end)
        subject_offset = offset
        subject_tag, _, _, offset = _der_tlv(der, offset, tbs_end)
        subject = der[subject_offset:offset]
        public_key_tag, _, _, offset = _der_tlv(der, offset, tbs_end)
        if (
            issuer_tag != 0x30
            or validity_tag != 0x30
            or subject_tag != 0x30
            or public_key_tag != 0x30
            or (require_self_issued and issuer != subject)
        ):
            raise ValueError("certificate is not an admissible trust anchor")

        extensions: tuple[int, int] | None = None
        while offset < tbs_end:
            tag, content_start, content_end, offset = _der_tlv(der, offset, tbs_end)
            if tag in (0x81, 0x82):
                continue
            if tag != 0xA3 or extensions is not None:
                raise ValueError("unsupported TBSCertificate field")
            extensions = (content_start, content_end)
        if extensions is None:
            raise ValueError("missing certificate extensions")

        extension_start, extension_end = extensions
        sequence_tag, sequence_start, sequence_end, sequence_next = _der_tlv(
            der,
            extension_start,
            extension_end,
        )
        if sequence_tag != 0x30 or sequence_next != extension_end:
            raise ValueError("invalid extension sequence")

        basic_constraints: tuple[bool, bytes] | None = None
        key_usage: tuple[bool, bytes] | None = None
        offset = sequence_start
        while offset < sequence_end:
            extension_tag, item_start, item_end, offset = _der_tlv(
                der,
                offset,
                sequence_end,
            )
            if extension_tag != 0x30:
                raise ValueError("invalid extension")
            item_offset = item_start
            oid_tag, oid_start, oid_end, item_offset = _der_tlv(
                der,
                item_offset,
                item_end,
            )
            if oid_tag != 0x06:
                raise ValueError("invalid extension identifier")
            critical = False
            if item_offset < item_end and der[item_offset] == 0x01:
                _, value_start, value_end, item_offset = _der_tlv(
                    der,
                    item_offset,
                    item_end,
                )
                if value_end - value_start != 1 or der[value_start] not in (0, 0xFF):
                    raise ValueError("invalid extension critical flag")
                critical = der[value_start] == 0xFF
            value_tag, value_start, value_end, item_offset = _der_tlv(
                der,
                item_offset,
                item_end,
            )
            if value_tag != 0x04 or item_offset != item_end:
                raise ValueError("invalid extension value")
            oid = der[oid_start:oid_end]
            value = der[value_start:value_end]
            if oid == b"\x55\x1d\x13":
                if basic_constraints is not None:
                    raise ValueError("duplicate basic constraints")
                basic_constraints = (critical, value)
            elif oid == b"\x55\x1d\x0f":
                if key_usage is not None:
                    raise ValueError("duplicate key usage")
                key_usage = (critical, value)

        if basic_constraints is None or (require_critical and not basic_constraints[0]):
            raise ValueError("missing critical basic constraints")
        basic = basic_constraints[1]
        tag, content_start, content_end, next_offset = _der_tlv(basic, 0, len(basic))
        if tag != 0x30 or next_offset != len(basic):
            raise ValueError("invalid basic constraints")
        tag, value_start, value_end, offset = _der_tlv(
            basic,
            content_start,
            content_end,
        )
        if (
            tag != 0x01
            or basic[value_start:value_end] != b"\xff"
            or (offset < content_end and basic[offset] != 0x02)
        ):
            raise ValueError("certificate is not a CA")
        if offset < content_end:
            _, _, _, offset = _der_tlv(basic, offset, content_end)
        if offset != content_end:
            raise ValueError("invalid basic constraints")

        if key_usage is None:
            if require_critical:
                raise ValueError("missing critical key usage")
        else:
            if require_critical and not key_usage[0]:
                raise ValueError("missing critical key usage")
            usage = key_usage[1]
            tag, value_start, value_end, next_offset = _der_tlv(
                usage,
                0,
                len(usage),
            )
            value = usage[value_start:value_end]
            if (
                tag != 0x03
                or next_offset != len(usage)
                or len(value) < 2
                or value[0] > 7
                or not (value[1] & 0x04)
                or (value[0] and value[-1] & ((1 << value[0]) - 1))
            ):
                raise ValueError("key usage does not permit certificate signing")
    except (IndexError, ValueError) as error:
        certificate_kind = (
            "strict self-signed CA root"
            if require_self_issued
            else "strict CA trust anchor"
        )
        raise ClaudeTrustCertificateInvalid(
            "Claude trust settings reference a certificate that is not a "
            f"{certificate_kind}"
        ) from error


def _verify_unconditional_trust_root(
    der: bytes,
    canonical: bytes,
    *,
    ca_root: pathlib.Path,
    timeout_seconds: float,
    allow_non_self_signed: bool = False,
) -> None:
    _require_unconditional_root_extensions(
        der,
        require_self_issued=not allow_non_self_signed,
    )
    if not CLAUDE_OPENSSL_CLIENT.is_file() or not os.access(
        CLAUDE_OPENSSL_CLIENT,
        os.X_OK,
    ):
        raise ClaudeTrustToolUnavailable(
            "Claude TLS root verification tooling is unavailable"
        )
    fd, temporary = tempfile.mkstemp(prefix=".trust-root-", suffix=".pem", dir=ca_root)
    certificate_path = pathlib.Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        _require_no_extended_acl(fd, label="Claude trust verification input")
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(canonical)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            verification_mode = (
                ("-partial_chain",)
                if allow_non_self_signed
                else ("-check_ss_sig",)
            )
            completed = run_bounded_capture(
                (
                    str(CLAUDE_OPENSSL_CLIENT),
                    "verify",
                    "-x509_strict",
                    *verification_mode,
                    "-purpose",
                    "any",
                    "-trusted",
                    certificate_path.name,
                    certificate_path.name,
                ),
                cwd=ca_root,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                timeout_seconds=timeout_seconds,
                stdout_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
                stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
            )
        except OSError as error:
            raise ClaudeTrustToolUnavailable(
                "Claude TLS root verification tooling became unavailable"
            ) from error
        try:
            if completed.returncode == 2:
                certificate_kind = (
                    "CA trust anchor"
                    if allow_non_self_signed
                    else "self-signed CA root"
                )
                raise ClaudeTrustCertificateInvalid(
                    "Claude trust settings reference a certificate that is not a "
                    f"currently valid {certificate_kind}"
                )
            if completed.returncode != 0:
                raise ClaudeTrustToolUnavailable(
                    "Claude TLS root verification tooling failed unexpectedly"
                )
        finally:
            completed.stdout[:] = b"\x00" * len(completed.stdout)
            completed.stderr[:] = b"\x00" * len(completed.stderr)
    finally:
        if fd >= 0:
            os.close(fd)
        certificate_path.unlink(missing_ok=True)


def _merge_ca_certificates(
    materials: Iterable[tuple[str, bytes]],
    *,
    excluded_sha1_fingerprints: Iterable[str] = (),
    allow_empty: bool = False,
    limit_bytes: int,
    label: str,
) -> bytes:
    if limit_bytes < 0:
        raise ValueError("CA merge byte limit must not be negative")
    merged = bytearray()
    try:
        seen: set[bytes] = set()
        excluded = {fingerprint.upper() for fingerprint in excluded_sha1_fingerprints}
        for source, data in materials:
            if not data and allow_empty:
                continue
            normalized = _extract_ca_certificates(data, source=source)
            for block in CLAUDE_CERTIFICATE_BLOCK.findall(normalized):
                der, canonical = _canonical_ca_certificate(block, source=source)
                sha1_fingerprint = (
                    hashlib.sha1(
                        der,
                        usedforsecurity=False,
                    )
                    .hexdigest()
                    .upper()
                )
                if sha1_fingerprint in excluded:
                    continue
                fingerprint = hashlib.sha256(der).digest()
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                if len(merged) + len(canonical) > limit_bytes:
                    raise ReviewError(f"{label} exceeds the size limit")
                merged.extend(canonical)
        if not merged and not allow_empty:
            raise ReviewError("Claude review CA bundle contains no PEM certificate")
        return bytes(merged)
    except MemoryError as error:
        raise ReviewError(f"{label} exceeded the bounded memory budget") from error


def _ca_sha256_fingerprints(data: bytes, *, source: str) -> frozenset[bytes]:
    normalized = _extract_ca_certificates(data, source=source)
    return frozenset(
        hashlib.sha256(_canonical_ca_certificate(block, source=source)[0]).digest()
        for block in CLAUDE_CERTIFICATE_BLOCK.findall(normalized)
    )


def _ca_fingerprint_pairs(data: bytes, *, source: str) -> dict[str, bytes]:
    normalized = _extract_ca_certificates(data, source=source)
    result: dict[str, bytes] = {}
    for block in CLAUDE_CERTIFICATE_BLOCK.findall(normalized):
        der, _canonical = _canonical_ca_certificate(block, source=source)
        result[hashlib.sha1(der, usedforsecurity=False).hexdigest().upper()] = (
            hashlib.sha256(der).digest()
        )
    return result


def _bundled_root_store_suffix(data: bytes) -> bytes:
    begin_marker = b"-----BEGIN CERTIFICATE-----"
    cursor = len(data)
    reversed_blocks: list[bytes] = []
    while cursor:
        begin = data.rfind(begin_marker, 0, cursor)
        if begin < 0:
            break
        block = data[begin:cursor]
        if (
            len(block) > CLAUDE_BUNDLED_CERTIFICATE_LIMIT_BYTES
            or CLAUDE_CERTIFICATE_BLOCK.fullmatch(block) is None
        ):
            break
        reversed_blocks.append(block)
        if len(reversed_blocks) > CLAUDE_BUNDLED_ROOT_LIMIT:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude executable bundled root count exceeds the inspection limit"
            )
        delimiter = begin - 1
        if delimiter >= 0 and data[delimiter] == 0:
            return b"\n".join(reversed(reversed_blocks))
        if delimiter < 0 or data[delimiter] != 0x0A:
            break
        cursor = delimiter
    raise ClaudeExecutableInspectionInconclusive(
        "Claude executable bundled root store has an invalid representation"
    )


def _certificate_self_signature_evidence(
    der: bytes,
) -> tuple[bytes, bytes, str]:
    try:
        outer_tag, outer_start, outer_end, outer_next = _der_tlv(der, 0, len(der))
        if outer_tag != 0x30 or outer_next != len(der):
            raise ValueError("invalid certificate sequence")
        tbs_offset = outer_start
        tbs_tag, tbs_start, tbs_end, tbs_next = _der_tlv(
            der,
            tbs_offset,
            outer_end,
        )
        algorithm_offset = tbs_next
        algorithm_tag, algorithm_start, algorithm_end, algorithm_next = _der_tlv(
            der,
            algorithm_offset,
            outer_end,
        )
        offset = algorithm_next
        signature_tag, signature_start, signature_end, offset = _der_tlv(
            der,
            offset,
            outer_end,
        )
        oid_tag, oid_start, oid_end, oid_next = _der_tlv(
            der,
            algorithm_start,
            algorithm_end,
        )
        tbs_cursor = tbs_start
        if tbs_cursor < tbs_end and der[tbs_cursor] == 0xA0:
            _, _, _, tbs_cursor = _der_tlv(der, tbs_cursor, tbs_end)
        _, _, _, tbs_cursor = _der_tlv(der, tbs_cursor, tbs_end)
        tbs_algorithm_offset = tbs_cursor
        tbs_algorithm_tag, _, _, tbs_cursor = _der_tlv(
            der,
            tbs_cursor,
            tbs_end,
        )
        if (
            tbs_tag != 0x30
            or tbs_algorithm_tag != 0x30
            or der[tbs_algorithm_offset:tbs_cursor]
            != der[algorithm_offset:algorithm_next]
            or algorithm_tag != 0x30
            or signature_tag != 0x03
            or offset != outer_end
            or oid_tag != 0x06
            or der[oid_next:algorithm_end] not in {b"", b"\x05\x00"}
            or signature_start >= signature_end
            or der[signature_start] != 0
        ):
            raise ValueError("invalid certificate signature encoding")
        digest = CLAUDE_CERTIFICATE_SIGNATURE_DIGESTS.get(der[oid_start:oid_end])
        if digest is None:
            raise ValueError("unsupported certificate signature algorithm")
        return (
            der[tbs_offset:tbs_next],
            der[signature_start + 1 : signature_end],
            digest,
        )
    except (IndexError, ValueError) as error:
        raise ClaudeTrustCertificateInvalid(
            "Claude executable bundled root has an invalid self-signature"
        ) from error


def _write_private_verification_file(path: pathlib.Path, data: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        _require_no_extended_acl(
            descriptor,
            label="Claude bundled root verification input",
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_bundled_root_self_signature(
    der: bytes,
    canonical: bytes,
    *,
    verification_root: pathlib.Path,
    index: int,
    timeout_seconds: float,
) -> None:
    try:
        metadata = CLAUDE_OPENSSL_CLIENT.lstat()
    except FileNotFoundError as error:
        raise ClaudeTrustToolUnavailable(
            "Claude bundled root verification tooling is unavailable"
        ) from error
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot inspect Claude bundled root verification tooling"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o6022
        or not os.access(CLAUDE_OPENSSL_CLIENT, os.X_OK)
    ):
        raise ClaudeTrustPolicyUnavailable(
            "Claude bundled root verification tooling has unsafe metadata"
        )
    tbs, signature, digest = _certificate_self_signature_evidence(der)
    prefix = f"root-{index:04d}"
    certificate_path = verification_root / f"{prefix}.pem"
    tbs_path = verification_root / f"{prefix}.tbs"
    signature_path = verification_root / f"{prefix}.sig"
    public_key_path = verification_root / f"{prefix}.pub"
    _write_private_verification_file(certificate_path, canonical)
    _write_private_verification_file(tbs_path, tbs)
    _write_private_verification_file(signature_path, signature)
    deadline = time.monotonic() + timeout_seconds

    def remaining_timeout() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReviewTimeoutError(
                "Claude bundled root verification exceeded its total timeout"
            )
        return remaining

    try:
        public_key = run_bounded_capture(
            (
                str(CLAUDE_OPENSSL_CLIENT),
                "x509",
                "-in",
                certificate_path.name,
                "-pubkey",
                "-noout",
            ),
            cwd=verification_root,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout_seconds=remaining_timeout(),
            stdout_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
            stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
        )
    except FileNotFoundError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude bundled root verification tooling changed before launch"
        ) from error
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude bundled root verification tooling could not be launched"
        ) from error
    try:
        public_key_bytes = bytes(public_key.stdout)
        if (
            public_key.returncode != 0
            or b"-----BEGIN PUBLIC KEY-----" not in public_key_bytes
            or b"PRIVATE KEY" in public_key_bytes
        ):
            raise ClaudeTrustCertificateInvalid(
                "Claude executable bundled root has an invalid public key"
            )
        _write_private_verification_file(public_key_path, public_key_bytes)
    finally:
        public_key.stdout[:] = b"\x00" * len(public_key.stdout)
        public_key.stderr[:] = b"\x00" * len(public_key.stderr)
    try:
        verified = run_bounded_capture(
            (
                str(CLAUDE_OPENSSL_CLIENT),
                "dgst",
                f"-{digest}",
                "-verify",
                public_key_path.name,
                "-signature",
                signature_path.name,
                tbs_path.name,
            ),
            cwd=verification_root,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout_seconds=remaining_timeout(),
            stdout_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
            stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
        )
    except FileNotFoundError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude bundled root verification tooling changed before launch"
        ) from error
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude bundled root verification tooling could not be launched"
        ) from error
    try:
        if verified.returncode == 1:
            raise ClaudeTrustCertificateInvalid(
                "Claude executable bundled root is not self-signed"
            )
        if verified.returncode != 0:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude bundled root verification tooling failed unexpectedly"
            )
    finally:
        verified.stdout[:] = b"\x00" * len(verified.stdout)
        verified.stderr[:] = b"\x00" * len(verified.stderr)


def _validated_bundled_root_certificates(
    data: bytes,
    *,
    executable: pathlib.Path,
    verify_self_signatures: bool = True,
) -> dict[bytes, bytes]:
    blocks = CLAUDE_CERTIFICATE_BLOCK.findall(data)
    if not blocks or len(blocks) > CLAUDE_BUNDLED_ROOT_LIMIT:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude executable bundled root store has an invalid certificate count"
        )
    deadline = time.monotonic() + CLAUDE_TRUST_ROOT_VERIFY_TOTAL_SECONDS
    certificates: dict[bytes, bytes] = {}
    verification_directory = (
        tempfile.TemporaryDirectory(
            prefix=".claude-bundled-roots-",
            dir=executable.parent,
        )
        if verify_self_signatures
        else contextlib.nullcontext(None)
    )
    with verification_directory as raw_verification_root:
        verification_root = (
            pathlib.Path(raw_verification_root)
            if raw_verification_root is not None
            else None
        )
        for index, block in enumerate(blocks):
            der, canonical = _canonical_ca_certificate(
                block,
                source="publisher-verified Claude bundled root store",
            )
            _require_unconditional_root_extensions(der, require_critical=False)
            if verify_self_signatures:
                assert verification_root is not None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ReviewTimeoutError(
                        "Claude bundled root verification exceeded its total timeout"
                    )
                _require_bundled_root_self_signature(
                    der,
                    canonical,
                    verification_root=verification_root,
                    index=index,
                    timeout_seconds=remaining,
                )
            fingerprint = hashlib.sha256(der).digest()
            existing = certificates.get(fingerprint)
            if existing is not None and existing != canonical:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude executable bundled roots contain a fingerprint collision"
                )
            certificates[fingerprint] = canonical
    return certificates


def _inspect_claude_executable_trust(
    path: pathlib.Path,
    *,
    expected_sha256: str | None = None,
    include_bundled_roots: bool,
    validate_bundled_roots: bool = True,
    required_mode: int | None = None,
) -> ClaudeExecutableTrustEvidence:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude executable snapshot validation requires O_NOFOLLOW"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | nofollow
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open Claude executable snapshot: {error}"
        ) from error
    digest = hashlib.sha256()
    root_store_search = bytearray()
    bundled_root_store: bytes | None = None

    def consume_root_store_search() -> None:
        nonlocal bundled_root_store
        while True:
            trailer = root_store_search.find(CLAUDE_BUNDLED_ROOT_STORE_TRAILER)
            if trailer < 0:
                break
            if bundled_root_store is not None:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude executable contains multiple bundled root stores"
                )
            bundled_root_store = _bundled_root_store_suffix(
                bytes(root_store_search[:trailer])
            )
            del root_store_search[: trailer + len(CLAUDE_BUNDLED_ROOT_STORE_TRAILER)]
        retained_limit = CLAUDE_BUNDLED_ROOT_STORE_LIMIT_BYTES + len(
            CLAUDE_BUNDLED_ROOT_STORE_TRAILER
        )
        if len(root_store_search) > retained_limit:
            del root_store_search[: len(root_store_search) - retained_limit]

    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or (
                required_mode is not None
                and stat.S_IMODE(before.st_mode) != required_mode
            )
            or before.st_size <= 0
            or before.st_size > CLAUDE_BINARY_MAX_BYTES
        ):
            raise ClaudeExecutableInspectionInconclusive(
                "Claude executable snapshot has unsafe file metadata"
            )
        total = 0
        while chunk := os.read(descriptor, CLAUDE_EXECUTABLE_HASH_CHUNK_BYTES):
            total += len(chunk)
            if total > CLAUDE_BINARY_MAX_BYTES:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude executable snapshot exceeds the inspection limit"
                )
            digest.update(chunk)
            if include_bundled_roots:
                root_store_search.extend(chunk)
                consume_root_store_search()
        after = os.fstat(descriptor)
        path_after = path.lstat()
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect Claude executable snapshot: {error}"
        ) from error
    finally:
        os.close(descriptor)
    if (
        _ca_source_metadata(before) != _ca_source_metadata(after)
        or _ca_source_metadata(after) != _ca_source_metadata(path_after)
        or total != before.st_size
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude executable snapshot changed during inspection"
        )
    actual_sha256 = digest.hexdigest()
    if expected_sha256 is not None and not hmac.compare_digest(
        actual_sha256,
        expected_sha256,
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude executable snapshot no longer matches signed provenance"
        )
    if include_bundled_roots and bundled_root_store is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude executable bundled root store is unavailable"
        )
    certificates_by_fingerprint = (
        _validated_bundled_root_certificates(
            bundled_root_store,
            executable=path,
            verify_self_signatures=validate_bundled_roots,
        )
        if bundled_root_store is not None
        else {}
    )
    fingerprints = frozenset(certificates_by_fingerprint)
    return ClaudeExecutableTrustEvidence(
        executable_sha256=actual_sha256,
        bundled_root_certificates=b"".join(
            certificates_by_fingerprint[fingerprint]
            for fingerprint in sorted(fingerprints)
        ),
        bundled_root_sha256_fingerprints=fingerprints,
    )


def _require_matching_claude_executable_snapshot(
    executable: pathlib.Path,
    expected: ClaudeExecutableTrustEvidence,
) -> None:
    current = _inspect_claude_executable_trust(
        executable,
        expected_sha256=expected.executable_sha256,
        include_bundled_roots=_is_claude_macos_host(),
        validate_bundled_roots=False,
        required_mode=0o500,
    )
    if current != expected:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude executable snapshot trust evidence changed"
        )


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
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ClaudeKeychainBrokerUnavailable(
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


def _read_claude_keychain_credential(
    review: ReviewWorkspace,
    *,
    account: str | None = None,
) -> bytearray | None:
    client = CLAUDE_KEYCHAIN_CLIENT
    if not client.is_file() or not os.access(client, os.X_OK):
        raise ClaudeKeychainBrokerUnavailable(
            "Claude local-login review requires /usr/bin/security"
        )
    account = account or _claude_keychain_account()
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
        raise ReviewError(f"Claude Keychain query failed: {error}") from error
    try:
        if completed.returncode == CLAUDE_KEYCHAIN_ITEM_NOT_FOUND_STATUS:
            return None
        if completed.returncode != 0:
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude Keychain query failed without a deterministic missing-item status"
            )
        if not completed.stdout.endswith(b"\n"):
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude Keychain output is missing its command terminator"
            )
        credential = bytearray(completed.stdout[:-1])
        if not credential:
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude Keychain returned an empty credential after a successful query"
            )
        return credential
    finally:
        completed.stdout[:] = b"\x00" * len(completed.stdout)
        completed.stderr[:] = b"\x00" * len(completed.stderr)


def _validate_fresh_claude_keychain_credential(
    credential: bytearray,
) -> None:
    try:
        payload = strict_json_loads(credential)
        if not isinstance(payload, dict):
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude local-login credential is malformed"
            )
        if "claudeAiOauth" not in payload or payload["claudeAiOauth"] is None:
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude local-login credential is malformed"
            )
        oauth = payload["claudeAiOauth"]
        if not isinstance(oauth, dict):
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude local-login credential is malformed"
            )
        access_token = oauth.get("accessToken")
        if access_token is None or (
            isinstance(access_token, str) and not access_token.strip()
        ):
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude local-login credential is malformed"
            )
        expires_at = oauth["expiresAt"]
        now = time.time()
        required_expiry = (now + CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS) * 1000
        maximum_expiry = (now + 7 * 24 * 60 * 60) * 1000
        if (
            not isinstance(access_token, str)
            or not access_token.strip()
            or not isinstance(expires_at, (int, float))
            or isinstance(expires_at, bool)
            or (isinstance(expires_at, float) and not math.isfinite(expires_at))
            or expires_at > maximum_expiry
        ):
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude local-login credential is malformed"
            )
        if expires_at <= required_expiry:
            raise ClaudeKeychainCredentialRefreshRequired(
                "Claude local-login access token cannot cover the current model "
                "attempt window"
            )
    except (
        ClaudeKeychainCredentialIntegrityError,
        ClaudeKeychainCredentialUnavailable,
    ):
        raise
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError) as error:
        raise ClaudeKeychainCredentialIntegrityError(
            "Claude local-login credential is malformed"
        ) from error


def _read_stable_claude_keychain_credential(
    review: ReviewWorkspace,
    *,
    env: dict[str, str] | None = None,
) -> bytearray:
    account = _claude_keychain_account()
    if env is not None and env.get("USER", account) != account:
        raise ClaudeKeychainCredentialIntegrityError(
            "Claude local-login account binding changed during review"
        )
    credential = _read_claude_keychain_credential(review, account=account)
    if credential is None:
        raise ClaudeKeychainCredentialRefreshRequired(
            "Claude local-login credential is unavailable and requires refresh"
        )
    comparison: bytearray | None = None
    try:
        comparison = _read_claude_keychain_credential(review, account=account)
        if comparison is None or not hmac.compare_digest(credential, comparison):
            raise ClaudeKeychainCredentialIntegrityError(
                "Claude local-login credential changed during stable validation"
            )
        _validate_fresh_claude_keychain_credential(credential)
        return credential
    except BaseException:
        credential[:] = b"\x00" * len(credential)
        raise
    finally:
        if comparison is not None:
            comparison[:] = b"\x00" * len(comparison)


def _require_fresh_claude_keychain_credential(
    review: ReviewWorkspace,
    *,
    env: dict[str, str] | None = None,
) -> None:
    credential = _read_stable_claude_keychain_credential(
        review,
        env=env,
    )
    try:
        _validate_fresh_claude_keychain_credential(credential)
    finally:
        credential[:] = b"\x00" * len(credential)


def _require_fresh_claude_keychain_credential_for_auth_preflight(
    review: ReviewWorkspace,
) -> None:
    try:
        _require_fresh_claude_keychain_credential(review)
    except (
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewOutputLimitError,
        ReviewProcessLeakError,
    ) as error:
        raise ClaudeAuthWarmupInconclusive(
            f"Claude authentication credential check was inconclusive: {error}"
        ) from error


def _recv_exact(sock: socket.socket, length: int) -> bytes | None:
    result = bytearray()
    try:
        while len(result) < length:
            chunk = sock.recv(length - len(result))
            if not chunk:
                return None
            result.extend(chunk)
    except OSError:
        return None
    return bytes(result)


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
        capability = bytearray(raw_capability)
        authorized = hmac.compare_digest(capability, server.capability)
        capability[:] = b"\x00" * len(capability)
        if not authorized:
            return
        operation = _recv_exact(self.request, 1)
        if operation != b"R":
            return
        credential = bytearray()
        with server.credential_lock:
            if not server.consumed and server.credential is not None:
                server.consumed = True
                credential = server.credential
                server.credential = None
        try:
            self.request.sendall(struct.pack("!I", len(credential)))
            if credential:
                self.request.sendall(credential)
        except OSError:
            return
        finally:
            credential[:] = b"\x00" * len(credential)


class _ClaudeKeychainCredentialServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False

    def __init__(
        self,
        credential: bytearray | None,
        capability: bytes,
    ) -> None:
        super().__init__(("127.0.0.1", 0), _ClaudeKeychainCredentialHandler)
        self.credential = credential
        self.capability = capability
        self.credential_lock = threading.Lock()
        self.consumed = False


@contextlib.contextmanager
def _claude_keychain_credential_server(
    credential: bytearray | None,
    capability: bytes,
) -> Iterator[int]:
    if len(capability) != CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES:
        raise ReviewError("Claude Keychain broker capability has an invalid length")
    try:
        server = _ClaudeKeychainCredentialServer(
            credential,
            capability,
        )
    except OSError as error:
        raise ClaudeLoopbackUnavailable(
            f"Claude Keychain broker cannot bind loopback: {error}"
        ) from error
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
        name="claude-review-keychain-broker",
    )
    thread_started = False
    try:
        try:
            thread.start()
            thread_started = True
        except RuntimeError as error:
            raise ClaudeLoopbackUnavailable(
                f"Claude Keychain broker cannot start: {error}"
            ) from error
        yield int(server.server_address[1])
    finally:
        if thread_started:
            server.shutdown()
        server.server_close()
        if thread_started:
            thread.join(timeout=5.0)
        if credential is not None:
            credential[:] = b"\x00" * len(credential)


@contextlib.contextmanager
def _claude_keychain_runtime(
    review: ReviewWorkspace,
    env: dict[str, str],
) -> Iterator[dict[str, str]]:
    result = dict(env)
    if result.get("ANTHROPIC_API_KEY"):
        yield result
        return
    credential = _read_stable_claude_keychain_credential(review, env=result)
    try:
        capability = secrets.token_bytes(CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES)
        with _claude_keychain_credential_server(
            credential,
            capability,
        ) as port:
            result[CLAUDE_KEYCHAIN_BROKER_PORT_ENV] = str(port)
            result[CLAUDE_KEYCHAIN_BROKER_CAPABILITY_ENV] = capability.hex()
            yield result
    finally:
        credential[:] = b"\x00" * len(credential)


def _extract_ca_certificates(data: bytes, *, source: str) -> bytes:
    if CLAUDE_PRIVATE_KEY_MARKER.search(data):
        raise ReviewError(f"Claude review CA source contains a private key: {source}")
    blocks = CLAUDE_CERTIFICATE_BLOCK.findall(data)
    if not blocks:
        raise ClaudeCACertificateNotFound(
            f"Claude review CA source contains no PEM certificate: {source}"
        )
    return b"\n".join(block.strip() for block in blocks) + b"\n"


def _require_no_extended_acl(descriptor: int, *, label: str) -> None:
    if not _is_claude_macos_host():
        return
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        acl_get_fd = libc.acl_get_fd
        acl_get_fd.argtypes = [ctypes.c_int]
        acl_get_fd.restype = ctypes.c_void_p
        acl_get_entry = libc.acl_get_entry
        acl_get_entry.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        acl_get_entry.restype = ctypes.c_int
        acl_free = libc.acl_free
        acl_free.argtypes = [ctypes.c_void_p]
        acl_free.restype = ctypes.c_int
    except (AttributeError, OSError) as error:
        raise ReviewError(f"cannot inspect {label} access controls") from error
    ctypes.set_errno(0)
    acl = acl_get_fd(descriptor)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise ReviewError(f"cannot inspect {label} access controls")
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        entry_status = acl_get_entry(acl, 0, ctypes.byref(entry))
        entry_errno = ctypes.get_errno()
        if entry_status == 0:
            raise ReviewError(f"{label} has an extended access control list")
        if entry_status != -1 or entry_errno != errno.EINVAL:
            raise ReviewError(f"cannot inspect {label} access controls")
    finally:
        acl_free(acl)


def _read_bounded_owner_file(
    path: pathlib.Path,
    *,
    source: str,
    limit_bytes: int,
    label: str,
    allow_empty: bool = False,
) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ReviewError(f"{label} requires O_NOFOLLOW support")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | nofollow
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect {label}: {source}"
        ) from error
    payload = bytearray()
    try:
        try:
            before = os.fstat(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot inspect {label}: {source}"
            ) from error
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & 0o077
        ):
            raise ReviewError(f"{label} has unsafe file metadata: {source}")
        _require_no_extended_acl(descriptor, label=label)
        if before.st_size > limit_bytes:
            raise ReviewError(f"{label} exceeds the size limit: {source}")
        while len(payload) <= limit_bytes:
            try:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, limit_bytes + 1 - len(payload)),
                )
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    f"cannot inspect {label}: {source}"
                ) from error
            if not chunk:
                break
            payload.extend(chunk)
        try:
            after = os.fstat(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot inspect {label}: {source}"
            ) from error
        try:
            path_after = path.lstat()
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"{label} changed while being read: {source}"
            ) from error
        if (
            _ca_source_metadata(before) != _ca_source_metadata(after)
            or _ca_source_metadata(after) != _ca_source_metadata(path_after)
            or len(payload) != before.st_size
        ):
            raise ClaudeExecutableInspectionInconclusive(
                f"{label} changed while being read: {source}"
            )
        if len(payload) > limit_bytes:
            raise ReviewError(f"{label} exceeds the size limit: {source}")
        if not payload and not allow_empty:
            raise ReviewError(f"{label} is empty: {source}")
        return bytes(payload)
    finally:
        payload[:] = b"\x00" * len(payload)
        os.close(descriptor)


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
    descriptor: int | None = None,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ReviewError(f"Claude review CA source is not a regular file: {source}")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ReviewError(f"Claude review CA source has an unsafe owner: {source}")
    if metadata.st_mode & 0o022:
        raise ReviewError(
            f"Claude review CA source is group- or world-writable: {source}"
        )
    if _is_claude_macos_host():
        if metadata.st_nlink != 1:
            raise ReviewError(
                f"Claude review CA source has an unsafe link count: {source}"
            )
        if metadata.st_uid == os.geteuid() and metadata.st_mode & 0o077:
            raise ReviewError(f"Claude review CA source is not owner-only: {source}")
        if descriptor is None:
            raise ReviewError(
                f"cannot inspect Claude review CA source access controls: {source}"
            )
        _require_no_extended_acl(descriptor, label="Claude review CA source")


def _require_safe_ca_symlink_metadata(
    metadata: os.stat_result,
    *,
    source: str,
) -> None:
    if not stat.S_ISLNK(metadata.st_mode):
        raise ReviewError(
            f"Claude review CA directory entry is not a symlink: {source}"
        )
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
        if _is_claude_macos_host():
            raise ReviewError(
                f"Claude review CA directory must not be a symlink: {source}"
            )
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
    if _ca_source_metadata(path_before) != _ca_source_metadata(
        opened
    ) or _ca_source_metadata(opened) != _ca_source_metadata(path_after):
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
        _require_safe_ca_source_metadata(
            before,
            source=source,
            descriptor=descriptor,
        )
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
    extract_certificates: bool = True,
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
            extract_certificates=extract_certificates,
        )
    finally:
        os.close(descriptor)
    try:
        path_after = path.lstat()
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude review CA source changed while being read: {source}"
        ) from error
    if _ca_source_metadata(after) != _ca_source_metadata(path_after):
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
    if _ca_source_metadata(before) != _ca_source_metadata(
        opened
    ) or _ca_source_metadata(opened) != _ca_source_metadata(after):
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
                f"Claude review CA directory symlink changed while being read: {source}"
            ) from error
        if (
            _ca_source_metadata(expected) != _ca_source_metadata(before)
            or _ca_source_metadata(before) != _ca_source_metadata(after)
            or target != expected_target
        ):
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude review CA directory symlink changed while being read: {source}"
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
                absolute, target_components = _ca_symlink_target_components(raw_target)
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
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
        ):
            raise ReviewError("cannot create a private Claude CA file")
        _require_no_extended_acl(fd, label="Claude generated CA file")
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            temporary_path.unlink()


def _validate_ca_file(path: pathlib.Path) -> None:
    try:
        ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError) as error:
        raise ReviewError(f"Claude review CA bundle is invalid: {path.name}") from error


def _classify_trust_fingerprints(
    data: bytes,
    *,
    domain: str,
) -> ClaudeTrustFingerprints:
    label = f"Claude {domain} trust settings"
    try:
        payload = plistlib.loads(data, dict_type=_UniquePlistDict)
    except (
        _DuplicatePlistKey,
        plistlib.InvalidFileException,
        ValueError,
        TypeError,
        OverflowError,
    ) as error:
        raise ClaudeTrustPolicyUnavailable(f"{label} are invalid") from error
    if not isinstance(payload, dict):
        raise ClaudeTrustPolicyUnavailable(f"{label} have an unsupported format")
    trust_list = payload.get("trustList")
    if not isinstance(trust_list, dict):
        raise ClaudeTrustPolicyUnavailable(f"{label} have an invalid trust list")

    # An exact deny remains authoritative even when another entry is malformed.
    for fingerprint, entry in trust_list.items():
        if (
            not isinstance(fingerprint, str)
            or not CLAUDE_TRUST_FINGERPRINT.fullmatch(fingerprint)
            or not isinstance(entry, dict)
        ):
            continue
        settings = entry.get("trustSettings")
        if not isinstance(settings, list):
            continue
        if any(
            isinstance(setting, dict)
            and type(setting.get(CLAUDE_TRUST_RESULT_KEY)) is int
            and setting[CLAUDE_TRUST_RESULT_KEY] == CLAUDE_TRUST_RESULT_DENY
            for setting in settings
        ):
            raise ClaudeTrustSettingsDeny(
                f"{label} contain an explicit deny entry; refusing native Claude review"
            )

    if type(payload.get("trustVersion")) is not int or payload["trustVersion"] != 1:
        raise ClaudeTrustPolicyUnavailable(f"{label} have an unsupported format")
    if len(trust_list) > CLAUDE_TRUST_ENTRY_LIMIT:
        raise ClaudeTrustPolicyUnavailable(f"{label} exceed the trust entry limit")
    unconditional: set[str] = set()
    trust_as_root: set[str] = set()
    constrained: set[str] = set()
    for fingerprint, entry in trust_list.items():
        if (
            not isinstance(fingerprint, str)
            or not CLAUDE_TRUST_FINGERPRINT.fullmatch(fingerprint)
            or not isinstance(entry, dict)
        ):
            raise ClaudeTrustPolicyUnavailable(f"{label} contain an invalid entry")
        normalized = fingerprint.upper()
        if "trustSettings" not in entry:
            unconditional.add(normalized)
            continue
        settings = entry["trustSettings"]
        if not isinstance(settings, list):
            raise ClaudeTrustPolicyUnavailable(f"{label} contain invalid constraints")
        if not settings:
            unconditional.add(normalized)
            continue
        has_unconditional_trust_root = False
        has_unconditional_trust_as_root = False
        for setting in settings:
            if not isinstance(setting, dict):
                raise ClaudeTrustPolicyUnavailable(
                    f"{label} contain invalid constraints"
                )
            if "result" in setting:
                raise ClaudeTrustPolicyUnavailable(
                    f"{label} contain ambiguous constraints"
                )
            if CLAUDE_TRUST_RESULT_KEY not in setting:
                continue
            result = setting[CLAUDE_TRUST_RESULT_KEY]
            if type(result) is not int or result not in CLAUDE_TRUST_RESULTS:
                raise ClaudeTrustPolicyUnavailable(
                    f"{label} contain invalid constraints"
                )
            if result in CLAUDE_TRUST_UNCONSTRAINED_RESULTS and set(setting) == {
                CLAUDE_TRUST_RESULT_KEY
            }:
                has_unconditional_trust_root = True
                if result == CLAUDE_TRUST_RESULT_TRUST_AS_ROOT:
                    has_unconditional_trust_as_root = True
        if has_unconditional_trust_root:
            unconditional.add(normalized)
            if has_unconditional_trust_as_root:
                trust_as_root.add(normalized)
        else:
            constrained.add(normalized)
    return ClaudeTrustFingerprints(
        unconditional=tuple(sorted(unconditional)),
        trust_as_root=tuple(sorted(trust_as_root)),
        constrained=tuple(sorted(constrained)),
    )


def _select_trust_certificates(
    materials: Iterable[tuple[str, bytes | bytearray]],
    fingerprints: Iterable[str],
    *,
    ca_root: pathlib.Path,
    trust_as_root_fingerprints: Iterable[str] = (),
) -> ClaudeSelectedTrustMaterial:
    requested = tuple(fingerprints)
    requested_set = set(requested)
    trust_as_root = set(trust_as_root_fingerprints)
    if not trust_as_root.issubset(requested_set):
        raise ValueError("TrustAsRoot fingerprints must be selected trust anchors")
    if len(requested) > CLAUDE_ADDITIONAL_TRUST_ROOT_LIMIT:
        raise ClaudeTrustPolicyUnavailable(
            "Claude additional trust roots exceed the verification limit"
        )
    certificates: dict[str, bytes] = {}
    for source, data in materials:
        if not data:
            continue
        normalized = _extract_ca_certificates(bytes(data), source=source)
        for block in CLAUDE_CERTIFICATE_BLOCK.findall(normalized):
            der, canonical = _canonical_ca_certificate(block, source=source)
            fingerprint = (
                hashlib.sha1(
                    der,
                    usedforsecurity=False,
                )
                .hexdigest()
                .upper()
            )
            existing = certificates.get(fingerprint)
            if existing is not None and existing != canonical:
                raise ClaudeTrustPolicyUnavailable(
                    "Claude trust certificates contain a fingerprint collision"
                )
            certificates[fingerprint] = canonical
    selected: list[bytes] = []
    omitted: set[str] = set()
    deadline = time.monotonic() + CLAUDE_TRUST_ROOT_VERIFY_TOTAL_SECONDS
    for fingerprint in requested:
        canonical = certificates.get(fingerprint)
        if canonical is None:
            omitted.add(fingerprint)
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReviewTimeoutError(
                "Claude additional trust root verification exceeded its deadline"
            )
        der, _ = _canonical_ca_certificate(
            canonical,
            source="Claude trust certificates",
        )
        try:
            _verify_unconditional_trust_root(
                der,
                canonical,
                ca_root=ca_root,
                timeout_seconds=min(CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS, remaining),
                allow_non_self_signed=fingerprint in trust_as_root,
            )
        except ClaudeTrustCertificateInvalid:
            omitted.add(fingerprint)
            continue
        selected.append(canonical)
    return ClaudeSelectedTrustMaterial(
        certificates=b"".join(selected),
        omitted_sha1_fingerprints=frozenset(omitted),
    )


def _is_no_trust_settings(detail: str) -> bool:
    lines = [line.strip() for line in detail.splitlines() if line.strip()]
    return any(
        lines in ([message], [f"security: {message}"])
        for message in CLAUDE_TRUST_NO_SETTINGS
    )


def _is_trust_export_unavailable(detail: str) -> bool:
    lines = [line.strip() for line in detail.splitlines() if line.strip()]
    return lines in (
        [CLAUDE_TRUST_EXPORT_UNAVAILABLE],
        [f"security: {CLAUDE_TRUST_EXPORT_UNAVAILABLE}"],
    )


def _require_claude_trust_export_tool(
    review: ReviewWorkspace,
    ca_root: pathlib.Path,
) -> tuple[pathlib.Path, dict[str, str]]:
    client = CLAUDE_KEYCHAIN_CLIENT
    if not client.is_file() or not os.access(client, os.X_OK):
        raise ClaudeTrustToolUnavailable(
            "Claude TLS setup requires Apple's security trust export tool"
        )
    security_env = child_environment(container_dir=review.container_dir)
    security_env.update({"LANG": "C", "LC_ALL": "C"})
    try:
        completed = run_bounded_capture(
            (str(client), "help", "trust-settings-export"),
            cwd=ca_root,
            env=security_env,
            timeout_seconds=CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS,
            stdout_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
            stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
        )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude TLS trust export tooling could not be inspected"
        ) from error
    try:
        detail = (bytes(completed.stdout) + b"\n" + bytes(completed.stderr)).decode(
            "utf-8",
            errors="replace",
        )
    finally:
        completed.stdout[:] = b"\x00" * len(completed.stdout)
        completed.stderr[:] = b"\x00" * len(completed.stderr)
    normalized_lines = tuple(
        normalized
        for line in detail.splitlines()
        if (normalized := " ".join(line.split()))
    )
    if (
        completed.returncode != 0
        or normalized_lines not in CLAUDE_TRUST_EXPORT_HELP_VARIANTS
    ):
        raise ClaudeTrustToolUnavailable(
            "Claude TLS trust export tooling is unavailable"
        )
    return client, security_env


def _new_claude_trust_policy_evidence(
    executable_evidence: ClaudeExecutableTrustEvidence,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "generation": secrets.token_hex(16),
        "policy": "require-publisher-verified-bundled-root-subset",
        "status": "checking",
        "executable_sha256": executable_evidence.executable_sha256,
        "bundled_root_count": len(executable_evidence.bundled_root_sha256_fingerprints),
        "bundled_root_set_sha256": executable_evidence.bundled_root_set_sha256,
        "bundled_root_resolution": "pending",
        "bundled_root_excluded_count": 0,
        "domains": [],
        "distinct_unconditional_count": 0,
        "distinct_constrained_omitted_count": 0,
        "additional_unconditional_candidate_count": 0,
        "additional_root_resolution": "not-started",
        "additional_unconditional_included_count": 0,
        "additional_unconditional_omitted_count": 0,
    }


def _write_claude_trust_policy_evidence(
    review: ReviewWorkspace,
    evidence: dict[str, object],
) -> None:
    write_json(
        review.container_dir / CLAUDE_TRUST_POLICY_EVIDENCE_NAME,
        evidence,
    )


def _terminalize_claude_trust_policy_evidence(
    review: ReviewWorkspace,
    evidence: dict[str, object],
    *,
    status: str,
    unresolved_resolution: str,
) -> None:
    evidence["status"] = status
    for key in ("bundled_root_resolution", "additional_root_resolution"):
        if evidence.get(key) in {"not-started", "pending"}:
            evidence[key] = unresolved_resolution
    _write_claude_trust_policy_evidence(review, evidence)


def _read_claude_trust_certificates(
    review: ReviewWorkspace,
    ca_root: pathlib.Path,
    *,
    evidence: dict[str, object],
) -> ClaudeTrustMaterial:
    try:
        material = _read_claude_trust_certificates_impl(
            review,
            ca_root,
            evidence=evidence,
        )
    except ClaudeTrustSettingsDeny:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="denied",
            unresolved_resolution="blocked",
        )
        raise
    except ClaudeTrustPolicyUnavailable:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
        )
        raise
    except ClaudeTrustToolUnavailable:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="unavailable",
            unresolved_resolution="unavailable",
        )
        raise
    except ClaudeExecutableInspectionInconclusive:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
        )
        raise
    except ReviewOutputLimitError as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
        )
        raise ClaudeTrustPolicyUnavailable(
            "Claude trust policy exceeds the inspection limit"
        ) from error
    except (
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewProcessLeakError,
    ):
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
        )
        raise
    except ReviewError:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
        )
        raise
    except BaseException:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
        )
        raise
    _write_claude_trust_policy_evidence(review, evidence)
    return material


def _read_claude_trust_certificates_impl(
    review: ReviewWorkspace,
    ca_root: pathlib.Path,
    *,
    evidence: dict[str, object],
) -> ClaudeTrustMaterial:
    client, security_env = _require_claude_trust_export_tool(review, ca_root)
    unconditional: set[str] = set()
    additional_unconditional: set[str] = set()
    additional_trust_as_root: set[str] = set()
    constrained: set[str] = set()
    domain_evidence: list[dict[str, object]] = []
    deferred_error: tuple[int, ReviewError] | None = None

    def defer_error(priority: int, error: ReviewError) -> None:
        nonlocal deferred_error
        if deferred_error is None or priority > deferred_error[0]:
            deferred_error = (priority, error)

    def refresh_counts() -> None:
        effective = additional_unconditional - constrained
        evidence.update(
            {
                "domains": list(domain_evidence),
                "distinct_unconditional_count": len(unconditional),
                "distinct_constrained_omitted_count": len(constrained),
                "additional_unconditional_candidate_count": len(effective),
            }
        )

    def record_domain_failure(domain: str, status: str) -> None:
        domain_evidence.append(
            {
                "domain": domain,
                "status": status,
                "unconditional_count": 0,
                "constrained_omitted_count": 0,
            }
        )
        refresh_counts()

    for domain, options in CLAUDE_TRUST_DOMAINS:
        trust_path = ca_root / f".{domain}-trust.plist"
        trust_path.unlink(missing_ok=True)
        try:
            try:
                completed = run_bounded_capture(
                    (
                        str(client),
                        "trust-settings-export",
                        *options,
                        str(trust_path),
                    ),
                    cwd=ca_root,
                    env=security_env,
                    timeout_seconds=CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS,
                    stdout_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
                    stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
                    regular_file_limit_bytes=CLAUDE_TRUST_SETTINGS_LIMIT_BYTES,
                    regular_file_limit_path=trust_path,
                )
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude TLS trust export tooling could not be inspected"
                ) from error
            try:
                detail = (
                    (bytes(completed.stdout) + bytes(completed.stderr))
                    .decode("utf-8", errors="replace")
                    .strip()
                )
                if completed.returncode != 0:
                    if not trust_path.exists() and _is_no_trust_settings(detail):
                        domain_evidence.append(
                            {
                                "domain": domain,
                                "status": "no-settings",
                                "unconditional_count": 0,
                                "constrained_omitted_count": 0,
                            }
                        )
                        refresh_counts()
                        continue
                    if not trust_path.exists() and _is_trust_export_unavailable(detail):
                        raise ClaudeTrustToolUnavailable(
                            "Claude TLS trust export tooling is unavailable"
                        )
                    raise ClaudeTrustPolicyUnavailable(
                        f"Claude {domain} trust export failed"
                    )
            finally:
                completed.stdout[:] = b"\x00" * len(completed.stdout)
                completed.stderr[:] = b"\x00" * len(completed.stderr)
            trust_data = _read_bounded_owner_file(
                trust_path,
                source=domain,
                limit_bytes=CLAUDE_TRUST_SETTINGS_LIMIT_BYTES,
                label="Claude trust export",
            )
            classified = _classify_trust_fingerprints(trust_data, domain=domain)
            unconditional.update(classified.unconditional)
            additional_unconditional.update(classified.unconditional)
            additional_trust_as_root.update(classified.trust_as_root)
            constrained.update(classified.constrained)
            domain_evidence.append(
                {
                    "domain": domain,
                    "status": "exported",
                    "unconditional_count": len(classified.unconditional),
                    "constrained_omitted_count": len(classified.constrained),
                }
            )
            refresh_counts()
        except ClaudeTrustSettingsDeny:
            domain_evidence.append(
                {
                    "domain": domain,
                    "status": "denied",
                    "unconditional_count": 0,
                    "constrained_omitted_count": 0,
                }
            )
            refresh_counts()
            raise
        except ClaudeTrustToolUnavailable as error:
            record_domain_failure(domain, "unavailable")
            defer_error(0, error)
        except ClaudeExecutableInspectionInconclusive as error:
            record_domain_failure(domain, "inconclusive")
            defer_error(1, error)
        except (
            ReviewTimeoutError,
            ReviewOutputDrainError,
            ReviewProcessLeakError,
        ) as error:
            record_domain_failure(domain, "inconclusive")
            defer_error(1, error)
        except ReviewOutputLimitError:
            record_domain_failure(domain, "blocked")
            defer_error(
                2,
                ClaudeTrustPolicyUnavailable(
                    f"Claude {domain} trust export exceeds the inspection limit"
                ),
            )
        except ReviewError as error:
            record_domain_failure(domain, "blocked")
            defer_error(2, error)
        finally:
            trust_path.unlink(missing_ok=True)

    if deferred_error is not None:
        raise deferred_error[1]
    effective_unconditional = additional_unconditional - constrained
    effective_trust_as_root = (
        additional_trust_as_root & effective_unconditional
    )
    evidence["additional_root_resolution"] = (
        "pending" if effective_unconditional else "not-required"
    )
    if not effective_unconditional:
        return ClaudeTrustMaterial(
            certificates=b"",
            excluded_sha1_fingerprints=frozenset(constrained),
            evidence=evidence,
        )

    completed_exports: list[tuple[str, Any]] = []
    try:
        for source, arguments in CLAUDE_TRUST_CERTIFICATE_SOURCES:
            try:
                completed = run_bounded_capture(
                    (
                        str(client),
                        "find-certificate",
                        "-a",
                        "-p",
                        *arguments,
                    ),
                    cwd=ca_root,
                    env=security_env,
                    timeout_seconds=CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS,
                    stdout_limit_bytes=CLAUDE_CA_FILE_LIMIT_BYTES,
                    stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
                )
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude trust certificate export tooling could not be inspected"
                ) from error
            completed_exports.append((source, completed))
            if completed.returncode != 0:
                raise ClaudeTrustToolUnavailable(
                    f"Claude {source} certificate export failed"
                )
        selected = _select_trust_certificates(
            ((source, completed.stdout) for source, completed in completed_exports),
            sorted(effective_unconditional),
            ca_root=ca_root,
            trust_as_root_fingerprints=sorted(effective_trust_as_root),
        )
        evidence["additional_root_resolution"] = "complete"
        evidence["additional_unconditional_included_count"] = len(
            effective_unconditional
        ) - len(selected.omitted_sha1_fingerprints)
        evidence["additional_unconditional_omitted_count"] = len(
            selected.omitted_sha1_fingerprints
        )
        return ClaudeTrustMaterial(
            certificates=selected.certificates,
            excluded_sha1_fingerprints=frozenset(
                constrained | selected.omitted_sha1_fingerprints
            ),
            evidence=evidence,
        )
    finally:
        for _source, completed in completed_exports:
            completed.stdout[:] = b"\x00" * len(completed.stdout)
            completed.stderr[:] = b"\x00" * len(completed.stderr)


def _prepare_claude_generic_tls_environment(
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
        raw_entries = [
            entry for entry in result.get(key, "").split(os.pathsep) if entry
        ]
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
                            f"cannot inspect Claude review CA directory entry: {error}"
                        ) from error
                    if stat.S_ISDIR(entry_metadata.st_mode):
                        continue
                    raw_material, source_size = _read_ca_directory_entry_at_with_size(
                        source_directory,
                        source_name,
                        entry_metadata,
                        source=f"{key}:{source_name}",
                        extract_certificates=False,
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
                    except ClaudeCACertificateNotFound:
                        continue
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


def _require_private_claude_ca_root(path: pathlib.Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise ReviewError("Claude CA workspace requires descriptor-safe directories")
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory_flag,
        )
    except OSError as error:
        raise ReviewError("Claude review CA directory is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or _ca_source_metadata(before) != _ca_source_metadata(opened)
            or _ca_source_metadata(opened) != _ca_source_metadata(after)
        ):
            raise ReviewError("Claude review CA directory has unsafe metadata")
        _require_no_extended_acl(descriptor, label="Claude review CA directory")
    finally:
        os.close(descriptor)


def _write_private_ca_snapshot(path: pathlib.Path, data: bytes) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except OSError as error:
        raise ReviewError("cannot create immutable caller CA snapshot") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
        ):
            raise ReviewError("caller CA snapshot has unsafe metadata")
        _require_no_extended_acl(descriptor, label="Claude caller CA snapshot")
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_claude_caller_ca_snapshot(path: pathlib.Path) -> bytes:
    data = _read_bounded_owner_file(
        path,
        source="caller CA snapshot",
        limit_bytes=CLAUDE_CALLER_CA_SNAPSHOT_LIMIT_BYTES,
        label="Claude caller CA snapshot",
        allow_empty=True,
    )
    return _extract_ca_certificates(data, source="caller CA snapshot") if data else b""


def _collect_claude_caller_ca_material(
    env: dict[str, str],
) -> list[tuple[str, bytes]]:
    materials: list[tuple[str, bytes]] = []
    aggregate_size = 0

    def charge_source(source_size: int) -> None:
        nonlocal aggregate_size
        aggregate_size += source_size
        if aggregate_size > CLAUDE_CALLER_CA_INPUT_LIMIT_BYTES:
            raise ReviewError("Claude caller CA material exceeds the aggregate limit")

    def append_material(source: str, material: bytes) -> None:
        materials.append((source, material))

    for key in CLAUDE_TLS_FILE_ENV_KEYS:
        raw = env.get(key)
        if not raw:
            continue
        source_path = pathlib.Path(raw)
        if not source_path.is_absolute():
            raise ReviewError(f"Claude review requires valid absolute {key}")
        raw_material, source_size = _read_ca_source_with_size(
            source_path,
            source=key,
            extract_certificates=False,
        )
        charge_source(source_size)
        material = _extract_ca_certificates(raw_material, source=key)
        append_material(key, material)

    directory_entry_count = 0
    configured_directory = False
    found_directory_certificate = False
    for key in CLAUDE_TLS_DIR_ENV_KEYS:
        raw_entries = [entry for entry in env.get(key, "").split(os.pathsep) if entry]
        configured_directory = configured_directory or bool(raw_entries)
        for raw in raw_entries:
            source_dir = pathlib.Path(raw)
            if not source_dir.is_absolute():
                raise ReviewError(
                    f"Claude review requires valid absolute {key} entries"
                )
            descriptor = _open_stable_ca_directory(source_dir, source=key)
            try:
                before = os.fstat(descriptor)
                names = _bounded_ca_directory_names(
                    descriptor,
                    CLAUDE_CA_DIR_ENTRY_LIMIT - directory_entry_count,
                    too_many_message="Claude review CA directory has too many entries",
                )
                directory_entry_count += len(names)
                for name in names:
                    metadata = os.stat(
                        name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    if stat.S_ISDIR(metadata.st_mode):
                        continue
                    if stat.S_ISLNK(metadata.st_mode):
                        raise ReviewError(
                            "Claude review CA directory must not contain symlinks"
                        )
                    raw_material, source_size = _read_ca_source_at_with_size(
                        descriptor,
                        name,
                        source=f"{key}:{name}",
                        extract_certificates=False,
                    )
                    charge_source(source_size)
                    try:
                        material = _extract_ca_certificates(
                            raw_material,
                            source=f"{key}:{name}",
                        )
                    except ClaudeCACertificateNotFound:
                        continue
                    append_material(f"{key}:{name}", material)
                    found_directory_certificate = True
                after = os.fstat(descriptor)
                if _ca_source_metadata(before) != _ca_source_metadata(after):
                    raise ClaudeExecutableInspectionInconclusive(
                        "Claude review CA directory changed while being read"
                    )
            finally:
                os.close(descriptor)
    if configured_directory and not found_directory_certificate:
        raise ReviewError("Claude review CA directory contains no PEM certificates")
    return materials


def _caller_ca_snapshot_material(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    trust_state: ClaudeTrustSessionState,
) -> bytes:
    snapshot = review.container_dir / "claude-ca" / CLAUDE_CALLER_CA_SNAPSHOT_NAME
    if snapshot.exists() or snapshot.is_symlink():
        material = _read_claude_caller_ca_snapshot(snapshot)
    else:
        source_materials = _collect_claude_caller_ca_material(env)
        material = _merge_ca_certificates(
            source_materials,
            allow_empty=True,
            limit_bytes=CLAUDE_CALLER_CA_SNAPSHOT_LIMIT_BYTES,
            label="Claude caller CA snapshot",
        )
        _write_private_ca_snapshot(snapshot, material)
        if _read_claude_caller_ca_snapshot(snapshot) != material:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude caller CA snapshot changed during creation"
            )
    digest = hashlib.sha256(material).hexdigest()
    if trust_state.caller_ca_snapshot_sha256 is None:
        trust_state.caller_ca_snapshot_sha256 = digest
    elif not hmac.compare_digest(trust_state.caller_ca_snapshot_sha256, digest):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude caller CA snapshot changed between attempts"
        )
    return material


def _prepare_claude_macos_tls_environment(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    executable_evidence: ClaudeExecutableTrustEvidence,
    trust_state: ClaudeTrustSessionState,
) -> dict[str, str]:
    evidence = _new_claude_trust_policy_evidence(executable_evidence)
    _write_claude_trust_policy_evidence(review, evidence)
    try:
        ca_root = review.container_dir / "claude-ca"
        _require_private_claude_ca_root(ca_root)
        bundled_certificates = executable_evidence.bundled_root_certificates
        bundled_fingerprints = executable_evidence.bundled_root_sha256_fingerprints
        actual_bundled_fingerprints = (
            _ca_sha256_fingerprints(
                bundled_certificates,
                source="publisher-verified Claude bundled roots",
            )
            if bundled_certificates
            else frozenset()
        )
        if actual_bundled_fingerprints != bundled_fingerprints:
            raise ClaudeTrustPolicyUnavailable(
                "Claude bundled root evidence does not match the signed snapshot"
            )
        trust_material = _read_claude_trust_certificates(
            review,
            ca_root,
            evidence=evidence,
        )
        system_certificates = _read_ca_source(
            CLAUDE_SYSTEM_CA_FILE,
            source="system CA bundle",
        )
        caller_certificates = _caller_ca_snapshot_material(
            review,
            env,
            trust_state=trust_state,
        )
        materials = [("system CA bundle", system_certificates)]
        if bundled_certificates:
            materials.append(
                ("publisher-verified Claude bundled roots", bundled_certificates)
            )
        if trust_material.certificates:
            materials.append(
                ("unconditional macOS trust roots", trust_material.certificates)
            )
        if caller_certificates:
            materials.append(("caller CA snapshot", caller_certificates))
        merged = _merge_ca_certificates(
            materials,
            excluded_sha1_fingerprints=trust_material.excluded_sha1_fingerprints,
            limit_bytes=CLAUDE_CA_BUNDLE_LIMIT_BYTES,
            label="Claude review CA bundle",
        )
        merged_fingerprints = _ca_sha256_fingerprints(
            merged,
            source="Claude review CA bundle",
        )
        bundled_pairs = (
            _ca_fingerprint_pairs(
                bundled_certificates,
                source="publisher-verified Claude bundled roots",
            )
            if bundled_certificates
            else {}
        )
        excluded_bundled = {
            sha256
            for sha1, sha256 in bundled_pairs.items()
            if sha1 in trust_material.excluded_sha1_fingerprints
        }
        expected_bundled = bundled_fingerprints - excluded_bundled
        actual_bundled = merged_fingerprints & bundled_fingerprints
        evidence["bundled_root_excluded_count"] = len(excluded_bundled)
        if actual_bundled != expected_bundled:
            raise ClaudeTrustPolicyUnavailable(
                "Claude merged CA bundle does not preserve the exact permitted "
                "bundled root set"
            )
        if excluded_bundled:
            raise ClaudeTrustPolicyUnavailable(
                "Claude bundled certificate store contains a policy-excluded root"
            )
        evidence["bundled_root_resolution"] = "complete"
        bundle = ca_root / CLAUDE_CA_BUNDLE_NAME
        _write_private_ca_file(bundle, merged)
        _validate_ca_file(bundle)
        result = dict(env)
        for key in CLAUDE_TLS_BYPASS_ENV_KEYS:
            result.pop(key, None)
        for key in CLAUDE_TLS_DIR_ENV_KEYS:
            result.pop(key, None)
        for key in CLAUDE_TLS_FILE_ENV_KEYS:
            result[key] = str(bundle)
        result[CLAUDE_CERT_STORE_ENV] = CLAUDE_CERT_STORE
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="complete",
            unresolved_resolution="complete",
        )
        return result
    except ClaudeTrustSettingsDeny:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="denied",
            unresolved_resolution="blocked",
        )
        raise
    except ClaudeTrustPolicyUnavailable:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
        )
        raise
    except ClaudeTrustToolUnavailable:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="unavailable",
            unresolved_resolution="unavailable",
        )
        raise
    except (
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewOutputLimitError,
        ReviewProcessLeakError,
        ClaudeExecutableInspectionInconclusive,
    ):
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
        )
        raise
    except ReviewError:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
        )
        raise
    except BaseException:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
        )
        raise


def _prepare_claude_tls_environment(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    executable_evidence: ClaudeExecutableTrustEvidence | None = None,
    trust_state: ClaudeTrustSessionState | None = None,
) -> dict[str, str]:
    if not _is_claude_macos_host():
        return _prepare_claude_generic_tls_environment(review, env)
    if executable_evidence is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude macOS TLS preparation requires signed executable root evidence"
        )
    return _prepare_claude_macos_tls_environment(
        review,
        env,
        executable_evidence=executable_evidence,
        trust_state=trust_state or ClaudeTrustSessionState(),
    )


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
        raise ReviewError("Claude review proxy supports only HTTP(S) upstream proxies")
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
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
        finally:
            if upstream is not None:
                upstream.close()


class _ClaudeProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
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


class _ClaudeUnixProxyServer(
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
        raise ClaudeLoopbackUnavailable(
            f"Claude CONNECT proxy cannot bind loopback: {error}"
        ) from error
    thread = threading.Thread(
        target=server.serve_forever,
        name="claude-review-connect-proxy",
        daemon=True,
    )
    thread_started = False
    try:
        try:
            thread.start()
            thread_started = True
        except RuntimeError as error:
            raise ClaudeLoopbackUnavailable(
                f"Claude CONNECT proxy cannot start: {error}"
            ) from error
        yield int(server.server_address[1])
    finally:
        if thread_started:
            server.shutdown()
        server.server_close()
        if thread_started:
            thread.join(timeout=5.0)


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
        socket_dir.chmod(0o700)
        socket_path = socket_dir / "p.sock"
        try:
            server = _ClaudeUnixProxyServer(
                socket_path,
                allowed_targets=allowed_targets,
                upstream_env=env,
            )
            socket_path.chmod(0o600)
        except OSError as error:
            raise ClaudeLoopbackUnavailable(
                f"Claude CONNECT proxy cannot bind a private Unix socket: {error}"
            ) from error
        thread = threading.Thread(
            target=server.serve_forever,
            name="claude-review-unix-connect-proxy",
            daemon=True,
        )
        thread_started = False
        try:
            try:
                thread.start()
                thread_started = True
            except RuntimeError as error:
                raise ClaudeLoopbackUnavailable(
                    f"Claude Unix CONNECT proxy cannot start: {error}"
                ) from error
            yield socket_path.resolve(strict=True)
        finally:
            if thread_started:
                server.shutdown()
            server.server_close()
            if thread_started:
                thread.join(timeout=5.0)
            socket_path.unlink(missing_ok=True)


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


def _run_claude_auth_warmup(
    review: ReviewWorkspace,
    executable: pathlib.Path,
    env: dict[str, str],
    model: str,
) -> Completed:
    rg = _trusted_claude_ripgrep()
    if rg is None:
        raise ClaudeReviewToolUnavailable(
            "Claude authentication warmup requires trusted ripgrep"
        )
    warmup_env = dict(env)
    warmup_env["PATH"] = os.pathsep.join(("/usr/bin", str(rg.absolute().parent)))
    settings = json.dumps(
        {"disableAllHooks": True},
        separators=(",", ":"),
    )
    with (
        _claude_connect_proxy(
            warmup_env,
            allowed_targets=CLAUDE_AUTH_PROXY_TARGETS,
        ) as proxy_port,
        tempfile.TemporaryDirectory(
            prefix="claude-auth-warmup-",
            dir=review.container_dir,
        ) as raw_output_dir,
    ):
        output_dir = pathlib.Path(raw_output_dir)
        proxied_env = _with_claude_proxy_environment(warmup_env, proxy_port)
        return run(
            (
                str(CLAUDE_PROBE_SANDBOX),
                "-p",
                _claude_review_sandbox_profile(
                    executable,
                    review,
                    proxied_env,
                    proxy_port=proxy_port,
                    allow_direct_keychain=True,
                    allow_workspace_read=False,
                ),
                str(executable),
                "--print",
                "--model",
                model,
                "--effort",
                CLAUDE_REASONING_EFFORT,
                "--permission-mode",
                "default",
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
                "",
                "--allowedTools",
                "Read(./__claude_auth_warmup_no_files__)",
                "--disallowedTools",
                "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch,Task",
            ),
            cwd=pathlib.Path(proxied_env["HOME"]),
            env=proxied_env,
            stdin=b"Reply with exactly OK.",
            stdout_path=output_dir / "stdout.log",
            stderr_path=output_dir / "stderr.log",
            timeout_seconds=CLAUDE_AUTH_WARMUP_TIMEOUT_SECONDS,
            output_file_limit_bytes=CLAUDE_PROBE_OUTPUT_LIMIT_BYTES,
        )


def _warm_claude_local_login(
    review: ReviewWorkspace,
    executable: pathlib.Path,
    env: dict[str, str],
    model: str,
) -> None:
    try:
        _require_fresh_claude_keychain_credential_for_auth_preflight(review)
        return
    except ClaudeKeychainCredentialUnavailable:
        pass
    try:
        warmup = _run_claude_auth_warmup(review, executable, env, model)
    except (
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewOutputLimitError,
        ReviewProcessLeakError,
    ) as error:
        raise ClaudeAuthWarmupInconclusive(
            f"Claude authentication warmup was inconclusive: {error}"
        ) from error
    credential_error: (
        ClaudeKeychainBrokerUnavailable | ClaudeKeychainCredentialUnavailable | None
    ) = None
    try:
        _require_fresh_claude_keychain_credential_for_auth_preflight(review)
    except (
        ClaudeKeychainBrokerUnavailable,
        ClaudeKeychainCredentialUnavailable,
    ) as error:
        credential_error = error
    category = classify_failure(warmup.stdout, warmup.stderr)
    warmup_result = _strict_json_object(warmup.stdout)
    output_shape = _claude_auth_warmup_output_shape(warmup.stdout)
    supported_success = (
        warmup.returncode == 0
        and output_shape.get("event_shape") == "supported-result-success"
    )
    supported_failure = (
        warmup.returncode != 0
        and warmup_result is not None
        and warmup_result.get("type") == "result"
        and warmup_result.get("subtype") in CLAUDE_AUTH_WARMUP_SAFE_SUBTYPES
        and warmup_result.get("is_error") is True
        and _claude_failure_metadata_is_supported(warmup_result)
    )
    verified_auth = supported_failure and _claude_supported_failure_category(
        warmup.stdout,
        stderr=warmup.stderr,
        requested_model=model,
    ) == "auth"
    if supported_success:
        category = "success"
    elif category in {"auth", "entitlement", "transient"} and not supported_failure:
        category = "inconclusive"
    elif category == "auth" and not verified_auth:
        category = "inconclusive"
    elif category == "other":
        category = "inconclusive"
    write_json(
        review.container_dir / "claude-auth-warmup.json",
        {
            "category": category,
            "output_shape": output_shape,
            "reason": (
                "supported-structural-success"
                if supported_success
                else "supported-structural-authentication"
                if verified_auth
                else f"supported-structural-{category}"
                if category in {"entitlement", "transient"}
                else "warmup-output-unverified"
            ),
            "returncode": warmup.returncode,
            "stderr_bytes": len(warmup.stderr),
            "stdout_bytes": len(warmup.stdout),
        },
    )
    if category == "transient":
        inconclusive = ClaudeAuthWarmupInconclusive(
            "Claude authentication warmup was inconclusive (transient)"
        )
        if credential_error is not None:
            raise inconclusive from credential_error
        raise inconclusive
    structured_entitlement = (
        category == "entitlement"
        and supported_failure
        and classify_failure(warmup.stdout, b"") == "entitlement"
    )
    if structured_entitlement:
        raise ClaudeAuthWarmupEntitlement(warmup)
    if verified_auth:
        if credential_error is not None:
            raise ClaudeKeychainCredentialUnavailable(
                "Claude authentication warmup could not obtain a fresh local "
                f"credential (returncode={warmup.returncode}, category=auth)"
            ) from credential_error
        raise ClaudeKeychainCredentialUnavailable(
            "Claude authentication warmup reported an authentication failure"
        )
    if supported_success:
        if credential_error is None:
            return
        if isinstance(credential_error, ClaudeKeychainBrokerUnavailable):
            raise credential_error
        raise ClaudeAuthWarmupInconclusive(
            "Claude authentication warmup did not produce a fresh credential "
            "(success)"
        ) from credential_error
    if credential_error is None:
        raise ClaudeAuthWarmupInconclusive(
            "Claude authentication warmup output was not a supported success "
            "envelope"
        )
    if isinstance(credential_error, ClaudeKeychainBrokerUnavailable):
        raise credential_error
    raise ClaudeAuthWarmupInconclusive(
        f"Claude authentication warmup did not produce a fresh credential ({category})"
    ) from credential_error


def _safe_claude_auth_warmup_enum(value: Any, allowed: frozenset[str]) -> str:
    if value is None:
        return "missing"
    if not isinstance(value, str):
        return "invalid"
    return value if value in allowed else "other"


def _nonnegative_json_number(value: Any) -> bool:
    if type(value) is int:
        return value >= 0
    return type(value) is float and math.isfinite(value) and value >= 0


def _claude_error_payload_is_supported(value: Any) -> bool:
    pending = [value]
    remaining = CLAUDE_FAILURE_METADATA_ITEM_LIMIT
    while pending:
        remaining -= 1
        if remaining < 0:
            return False
        item = pending.pop()
        if item is None or isinstance(item, str) or type(item) is int:
            continue
        if isinstance(item, list):
            pending.extend(item)
            continue
        if isinstance(item, dict):
            if not all(
                isinstance(key, str) and key in CLAUDE_ERROR_PAYLOAD_FIELDS
                for key in item
            ):
                return False
            pending.extend(item.values())
            continue
        return False
    return True


def _claude_model_usage_shape_is_supported(value: Any) -> bool:
    if not isinstance(value, dict) or len(value) > 256:
        return False
    for model, usage in value.items():
        if (
            not isinstance(model, str)
            or not model
            or not isinstance(usage, dict)
            or not set(usage) <= CLAUDE_MODEL_USAGE_FIELDS
        ):
            return False
        for key, metric in usage.items():
            if key == "costUSD":
                if not _nonnegative_json_number(metric):
                    return False
            elif type(metric) is not int or metric < 0:
                return False
    return True


def _claude_usage_shape_is_supported(value: Any) -> bool:
    if not isinstance(value, dict) or not set(value) <= CLAUDE_USAGE_FIELDS:
        return False
    for key, metric in value.items():
        if key == "service_tier":
            if not isinstance(metric, str) or not metric:
                return False
        elif key == "cache_creation":
            if (
                not isinstance(metric, dict)
                or not set(metric) <= CLAUDE_USAGE_CACHE_CREATION_FIELDS
                or any(type(item) is not int or item < 0 for item in metric.values())
            ):
                return False
        elif key == "server_tool_use":
            if (
                not isinstance(metric, dict)
                or not set(metric) <= CLAUDE_USAGE_SERVER_TOOL_FIELDS
                or any(type(item) is not int or item < 0 for item in metric.values())
            ):
                return False
        elif type(metric) is not int or metric < 0:
            return False
    return True


def _claude_failure_metadata_is_supported(result: dict[str, Any]) -> bool:
    if not set(result) <= CLAUDE_FAILURE_ENVELOPE_FIELDS:
        return False
    if "result" in result and not isinstance(result["result"], str):
        return False
    for key in ("duration_api_ms", "duration_ms", "num_turns"):
        if key in result and (type(result[key]) is not int or result[key] < 0):
            return False
    for key in ("session_id", "uuid"):
        if key in result and (not isinstance(result[key], str) or not result[key]):
            return False
    if "total_cost_usd" in result and not _nonnegative_json_number(
        result["total_cost_usd"]
    ):
        return False
    if "permission_denials" in result and result["permission_denials"] != []:
        return False
    if "usage" in result and not _claude_usage_shape_is_supported(result["usage"]):
        return False
    if "modelUsage" in result and not _claude_model_usage_shape_is_supported(
        result["modelUsage"]
    ):
        return False
    api_error_status = result.get("api_error_status")
    if "api_error_status" in result and not (
        api_error_status is None
        or (type(api_error_status) is int and 100 <= api_error_status <= 599)
    ):
        return False
    return all(
        _claude_error_payload_is_supported(result[key])
        for key in CLAUDE_AUTH_WARMUP_ERROR_FIELDS - {"api_error_status"}
        if key in result
    )


def _claude_auth_warmup_output_shape(stdout: bytes) -> dict[str, object]:
    result = _strict_json_object(stdout)
    if result is None:
        return {"json_shape": "invalid-or-non-object"}
    api_error_status = result.get("api_error_status")
    safe_api_error_status = (
        api_error_status
        if type(api_error_status) is int and 100 <= api_error_status <= 599
        else None
    )
    raw_result = result.get("result")
    normalized_result = (
        " ".join(raw_result.lower().split()) if isinstance(raw_result, str) else None
    )
    model_usage = result.get("modelUsage")
    model_usage_valid = _claude_model_usage_shape_is_supported(model_usage)
    safe_type = _safe_claude_auth_warmup_enum(
        result.get("type"),
        CLAUDE_AUTH_WARMUP_SAFE_TYPES,
    )
    safe_subtype = _safe_claude_auth_warmup_enum(
        result.get("subtype"),
        CLAUDE_AUTH_WARMUP_SAFE_SUBTYPES,
    )
    is_error = result["is_error"] if type(result.get("is_error")) is bool else None
    known_error_fields = sorted(
        key for key in CLAUDE_AUTH_WARMUP_ERROR_FIELDS if key in result
    )
    unknown_fields = set(result) - CLAUDE_FAILURE_ENVELOPE_FIELDS
    unknown_field_count = len(unknown_fields)
    known_error_payloads_empty = all(
        result[key] is None
        or (isinstance(result[key], str) and not result[key].strip())
        or (isinstance(result[key], (list, dict)) and not result[key])
        for key in known_error_fields
    )
    result_shape = (
        "missing"
        if "result" not in result
        else "string"
        if isinstance(raw_result, str)
        else "non-string"
    )
    supported_result_error = (
        safe_type == "result"
        and safe_subtype in {"success", "error_during_execution"}
        and is_error is True
        and result_shape == "string"
        and unknown_field_count == 0
        and _claude_failure_metadata_is_supported(result)
        and known_error_payloads_empty
    )
    supported_result_success = (
        safe_type == "result"
        and safe_subtype == "success"
        and is_error is False
        and raw_result == "OK"
        and unknown_field_count == 0
        and _claude_failure_metadata_is_supported(result)
        and known_error_payloads_empty
    )
    return {
        "api_error_status": safe_api_error_status,
        "api_error_status_present": "api_error_status" in result,
        "api_error_status_shape": (
            "missing"
            if "api_error_status" not in result
            else "null"
            if api_error_status is None
            else "status"
            if safe_api_error_status is not None
            else "invalid"
        ),
        "event_shape": (
            "supported-result-error"
            if supported_result_error
            else "supported-result-success"
            if supported_result_success
            else "unsupported"
        ),
        "is_error": is_error,
        "json_shape": "object",
        "known_error_fields_present": known_error_fields,
        "model_usage_entry_count": (
            min(len(model_usage), 256) if model_usage_valid else None
        ),
        "model_usage_present": "modelUsage" in result,
        "model_usage_shape": (
            "missing"
            if "modelUsage" not in result
            else "object"
            if model_usage_valid
            else "invalid"
        ),
        "result_matches_known_auth_message": (
            normalized_result in CLAUDE_RESULT_AUTH_MESSAGES
            if normalized_result is not None
            else False
        ),
        "result_signal_categories": (
            [
                category
                for category, terms in CLAUDE_AUTH_WARMUP_RESULT_SIGNAL_TERMS.items()
                if any(term in normalized_result for term in terms)
            ]
            if normalized_result is not None
            else []
        ),
        "result_shape": result_shape,
        "subtype": safe_subtype,
        "type": safe_type,
        "unknown_field_count": min(unknown_field_count, 256),
    }


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
    result["PATH"] = os.pathsep.join(dict.fromkeys(str(entry) for entry in entries))
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
        except ClaudeCACertificateNotFound:
            return
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
                too_many_message=("Claude Linux CA directories have too many entries"),
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
    host_home = (
        pathlib.Path(os.environ.get("HOME", str(pathlib.Path.home())))
        .expanduser()
        .resolve()
    )
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
    allow_direct_keychain: bool = False,
    allow_workspace_read: bool = True,
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
            raise ReviewError(
                f"Claude Code review sandbox requires valid absolute {key}"
            )
        resolved = path.resolve()
        if not is_relative_to(resolved, container):
            raise ReviewError(f"Claude Code review sandbox requires helper-owned {key}")
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
    if allow_direct_keychain:
        auth_executables = _native_macho_dependencies(
            CLAUDE_KEYCHAIN_CLIENT,
            label="Apple security client",
        )
    elif not env.get("ANTHROPIC_API_KEY"):
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
        if any(
            not is_relative_to(path.resolve(), container) for path in auth_executables
        ):
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
        *(path.resolve() for path in CLAUDE_PROBE_SYSTEM_READ_SUBPATHS),
        *tool_library_subpaths,
        *tls_dirs,
    }
    if allow_workspace_read:
        read_subpaths.add(review.workspace_root.resolve())
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
        for name in (
            *CLAUDE_REVIEW_BASE_MACH_SERVICES,
            *(CLAUDE_KEYCHAIN_MACH_SERVICES if allow_direct_keychain else ()),
        )
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


def _failure_evidence_categories(
    stdout: bytes | str,
    stderr: bytes | str,
) -> dict[str, str]:
    def decode(value: bytes | str) -> str:
        return (
            value.decode("utf-8", errors="replace")
            if isinstance(value, bytes)
            else value
        )

    stdout_bytes = stdout.encode() if isinstance(stdout, str) else stdout
    structured_error = _structured_error_text(stdout_bytes).lower()
    stderr_text = decode(stderr).lower()
    message = f"{stderr_text}\n{structured_error}"
    categories: dict[str, str] = {}
    if any(fragment in message for fragment in TRANSIENT_FAILURE_FRAGMENTS):
        source = (
            "structured"
            if any(
                fragment in structured_error for fragment in TRANSIENT_FAILURE_FRAGMENTS
            )
            else "stderr"
        )
        categories["transient"] = f"{source}-transient"
    if any(fragment in message for fragment in AUTH_FAILURE_FRAGMENTS):
        source = (
            "structured"
            if any(fragment in structured_error for fragment in AUTH_FAILURE_FRAGMENTS)
            else "stderr"
        )
        categories["auth"] = f"{source}-authentication"
    if any(fragment in message for fragment in ENTITLEMENT_FAILURE_FRAGMENTS):
        source = (
            "structured"
            if any(
                fragment in structured_error
                for fragment in ENTITLEMENT_FAILURE_FRAGMENTS
            )
            else "stderr"
        )
        categories["entitlement"] = f"{source}-entitlement"
    elif any(code in structured_error for code in STRUCTURED_ENTITLEMENT_CODES):
        categories["entitlement"] = "structured-entitlement-code"
    elif (
        any(code in structured_error for code in STRUCTURED_AMBIGUOUS_MODEL_CODES)
        and "model" in structured_error
        and any(
            marker in structured_error
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
        categories["entitlement"] = "structured-entitlement-context"
    return categories


def _classify_failure_evidence(
    stdout: bytes | str,
    stderr: bytes | str,
) -> tuple[str, str]:
    categories = _failure_evidence_categories(stdout, stderr)
    for category in ("transient", "auth", "entitlement"):
        if category in categories:
            return category, categories[category]
    return "other", "unclassified-failure"


def _copilot_model_discovery_network_failure(stderr: bytes | str) -> bool:
    raw = stderr.encode("utf-8") if isinstance(stderr, str) else stderr
    discovery_markers = (
        "failed to load models",
        "could not retrieve the list of available models",
    )
    network_markers = (
        "[enotfound]",
        "client error (connect)",
        "connection refused",
        "dns error",
        "failed to lookup address information",
        "name or service not known",
        "network error",
        "nodename nor servname provided",
    )
    detail = raw[:COPILOT_PROBE_OUTPUT_LIMIT_BYTES].decode(
        "utf-8",
        errors="replace",
    )
    for raw_line in detail.splitlines():
        line = " ".join(raw_line.lower().split())
        if any(marker in line for marker in discovery_markers) and any(
            marker in line for marker in network_markers
        ):
            return True
    return False


def classify_failure(stdout: bytes | str, stderr: bytes | str) -> str:
    category, _reason = _classify_failure_evidence(stdout, stderr)
    return category


def _claude_nonzero_failure_reason(stdout: bytes) -> str:
    if not stdout:
        return "nonzero-without-structured-diagnostic"
    result = _strict_json_object(stdout)
    if result is None:
        return "nonzero-invalid-strict-json"
    if result.get("type") != "result":
        return "nonzero-unsupported-event-type"
    subtype = result.get("subtype")
    if subtype not in CLAUDE_AUTH_WARMUP_SAFE_SUBTYPES:
        return "nonzero-unsupported-result-subtype"
    if type(result.get("is_error")) is not bool:
        return "nonzero-invalid-result-error-flag"
    _effective_model, model_evidence_consistent = _claude_model_usage_evidence(
        result,
        requested_model=None,
    )
    if not model_evidence_consistent:
        return "nonzero-malformed-model-usage"
    if result["is_error"] is False and subtype == "success":
        return "nonzero-success-envelope"
    if result["is_error"] is True:
        return "nonzero-unclassified-result-error"
    return "nonzero-contradictory-result-envelope"


def _claude_supported_failure_category(
    stdout: bytes,
    *,
    stderr: bytes = b"",
    requested_model: str,
) -> str | None:
    result = _strict_json_object(stdout)
    if (
        result is None
        or result.get("type") != "result"
        or result.get("subtype") not in CLAUDE_AUTH_WARMUP_SAFE_SUBTYPES
        or result.get("is_error") is not True
        or not _claude_failure_metadata_is_supported(result)
    ):
        return None
    effective_model, model_usage_valid = _claude_model_usage_evidence(
        result,
        requested_model=requested_model,
    )
    if not model_usage_valid:
        return None
    category, _reason = _classify_failure_evidence(stdout, stderr)
    evidence_categories = _failure_evidence_categories(stdout, stderr)
    if category in {"auth", "entitlement", "transient"} and set(
        evidence_categories
    ) != {category}:
        return None
    output_shape = _claude_auth_warmup_output_shape(stdout)
    result_signal_categories = output_shape.get("result_signal_categories")
    if category == "auth":
        if not (
            output_shape.get("event_shape") == "supported-result-error"
            and output_shape.get("result_matches_known_auth_message") is True
            and result_signal_categories == ["auth"]
        ):
            return None
    elif category in {"entitlement", "transient"} and result_signal_categories not in (
        [],
        [category],
    ):
        return None
    if category == "entitlement" and effective_model is None:
        return None
    return category if category in {"auth", "entitlement", "transient"} else None


def _normalize_model(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _model_matches(requested: str, effective: str) -> bool:
    requested_normalized = _normalize_model(requested)
    effective_normalized = _normalize_model(effective)
    return effective_normalized == requested_normalized


def _json_objects(stdout: bytes) -> list[dict[str, Any]]:
    try:
        text = stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        return []
    if not text:
        return []

    def parse_object(value: str) -> dict[str, Any] | None:
        try:
            parsed = strict_json_loads(value)
        except (UnicodeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None

    parsed = parse_object(text)
    if parsed is not None:
        return [parsed]

    values: list[dict[str, Any]] = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        parsed_line = parse_object(line)
        if parsed_line is None:
            return []
        values.append(parsed_line)
    return values


def _strict_json_object(stdout: bytes) -> dict[str, Any] | None:
    try:
        parsed = strict_json_loads(stdout)
    except (UnicodeError, ValueError):
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
            parsed = strict_json_loads(line)
        except (UnicodeError, ValueError):
            return None
        if not isinstance(parsed, dict):
            return None
        objects.append(parsed)
    return objects


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


def _structured_error_item_text(item: dict[str, Any]) -> str:
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
    payload_found = False
    for key in ("error", "errors", "message", "reason", "detail", "code"):
        if key in item:
            payload_messages = _error_payload_text(item[key])
            if payload_messages:
                payload_found = True
                messages.extend(payload_messages)
    api_error_status = item.get("api_error_status")
    if (
        isinstance(api_error_status, int) and not isinstance(api_error_status, bool)
    ) or (isinstance(api_error_status, str) and api_error_status.strip()):
        payload_found = True
        messages.append(f"status {api_error_status}")
    if (
        not payload_found
        and item.get("type") == "result"
        and isinstance(item.get("result"), str)
    ):
        normalized_result = " ".join(item["result"].lower().split())
        if normalized_result in CLAUDE_RESULT_AUTH_MESSAGES:
            messages.append("not logged in")
    return "\n".join(messages)


def _structured_error_text(stdout: bytes) -> str:
    return "\n".join(
        message
        for item in _json_objects(stdout)
        if (message := _structured_error_item_text(item))
    )


def _claude_model_usage_evidence(
    result: dict[str, Any],
    *,
    requested_model: str | None,
) -> tuple[str | None, bool]:
    if "modelUsage" not in result:
        return None, True
    model_usage = result["modelUsage"]
    if not isinstance(model_usage, dict) or not all(
        isinstance(key, str) and key and isinstance(value, dict)
        for key, value in model_usage.items()
    ):
        return None, False
    candidates = list(model_usage)
    if requested_model is not None:
        matching = next(
            (
                candidate
                for candidate in candidates
                if _model_matches(requested_model, candidate)
            ),
            None,
        )
        return matching or (candidates[-1] if candidates else None), True
    return (candidates[-1] if candidates else None), True


def _parse_claude_output_evidence(
    stdout: bytes, *, requested_model: str | None = None
) -> tuple[str | None, str | None, bool]:
    result = _strict_json_object(stdout)
    if result is None:
        return None, None, True
    if result.get("type") != "result":
        return None, None, True
    effective_model, model_evidence_consistent = _claude_model_usage_evidence(
        result,
        requested_model=requested_model,
    )
    if result.get("subtype") != "success" or result.get("is_error") is not False:
        return None, effective_model, model_evidence_consistent
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
            return None, effective_model, model_evidence_consistent
    if "api_error_status" in result:
        value = result["api_error_status"]
        if value is not None and not (isinstance(value, str) and not value.strip()):
            return None, effective_model, model_evidence_consistent
    final_text = result.get("result")
    if (
        not isinstance(final_text, str)
        or not final_text.strip()
        or effective_model is None
    ):
        return None, effective_model, model_evidence_consistent
    if _structured_error_text(stdout).strip():
        return None, effective_model, model_evidence_consistent
    return final_text, effective_model, model_evidence_consistent


def _parse_claude_output(
    stdout: bytes, *, requested_model: str | None = None
) -> tuple[str | None, str | None]:
    final_text, effective_model, _model_evidence_consistent = (
        _parse_claude_output_evidence(stdout, requested_model=requested_model)
    )
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
        effective_model = turn["usage_model"] or message_model or turn["session_model"]
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
                raise ValueError(
                    "Copilot JSONL record exceeds the bounded parser limit"
                )
            if not line.strip(b" \t\r"):
                continue
            text = line.decode("utf-8")
            parsed = strict_json_loads(text)
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
                        item = strict_json_loads(line)
                    except (UnicodeError, ValueError):
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
            if minimal_seen or access != "read" or value != {"kind": "minimal"}:
                return False
            minimal_seen = True
            continue
        if path_type == "glob_pattern":
            pattern = path_value.get("pattern")
            if (
                not isinstance(pattern, str)
                or remaining_globs.pop(pattern, None) != access
            ):
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


def _attempt_paths(
    review: ReviewWorkspace, index: int, runtime: str, model: str
) -> tuple[pathlib.Path, pathlib.Path]:
    safe_model = re.sub(r"[^A-Za-z0-9_.-]+", "-", model)
    prefix = review.container_dir / "attempts" / f"{index:02d}-{runtime}-{safe_model}"
    prefix.parent.mkdir(parents=True, exist_ok=True)
    return pathlib.Path(f"{prefix}.stdout.log"), pathlib.Path(f"{prefix}.stderr.log")


def _append_attempt_diagnostic(path: pathlib.Path, message: str) -> None:
    with path.open("ab") as handle:
        if handle.tell():
            handle.write(b"\n")
        handle.write(message.rstrip().encode("utf-8", errors="replace") + b"\n")


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
    model_evidence_consistent: bool = True,
) -> Attempt:
    if completed.returncode != 0:
        final_text = None
    stdout_path, stderr_path = _attempt_paths(review, index, runtime, model)
    if not stdout_path.exists():
        stdout_path.write_bytes(completed.stdout)
    if not stderr_path.exists():
        stderr_path.write_bytes(completed.stderr)
    if completed.returncode == 0 and final_text:
        category = "success"
        reason = None
    elif runtime == "copilot" and completed.returncode == 0:
        category = "inconclusive"
        reason = "zero-exit-without-verified-final"
    else:
        category, reason = _classify_failure_evidence(
            completed.stdout,
            completed.stderr,
        )
        if (
            runtime == "copilot"
            and completed.returncode != 0
            and category not in {"auth", "entitlement"}
            and _copilot_model_discovery_network_failure(completed.stderr)
        ):
            category = "transient"
            reason = "stderr-model-discovery-network"
            _append_attempt_diagnostic(
                stderr_path,
                "Copilot model discovery encountered a transient network failure",
            )
        if runtime == "claude":
            if category in {"auth", "entitlement", "transient"} and (
                _claude_supported_failure_category(
                    completed.stdout,
                    stderr=completed.stderr,
                    requested_model=model,
                )
                != category
            ):
                reason = f"unverified-{category}-failure-envelope"
                category = "inconclusive"
            elif completed.returncode != 0 and category == "other":
                category = "inconclusive"
                reason = _claude_nonzero_failure_reason(completed.stdout)
            elif completed.returncode == 0 and category == "other":
                result = _strict_json_object(completed.stdout)
                if (
                    result is not None
                    and result.get("type") == "result"
                    and (
                        result.get("subtype") != "success"
                        or result.get("is_error") is not False
                    )
                ):
                    category = "inconclusive"
                    reason = "zero-exit-unclassified-result-error"
            if category == "inconclusive":
                _append_attempt_diagnostic(
                    stderr_path,
                    f"Claude structured failure was inconclusive: {reason}",
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
        reason=reason,
    )
    if runtime == "claude" and not model_evidence_consistent:
        detail = (
            "Claude result exposed malformed modelUsage metadata; refusing to "
            "classify authentication, entitlement, or final output"
        )
        _append_attempt_diagnostic(stderr_path, detail)
        return replace(
            attempt,
            returncode=65,
            category="runtime-unverified",
            final_text=None,
            reason="malformed-model-usage",
        )
    if runtime == "claude" and completed.returncode == 0 and final_text is None:
        result = _strict_json_object(completed.stdout)
        if result is None or result.get("type") != "result":
            _append_attempt_diagnostic(
                stderr_path,
                "Claude successful process did not emit a supported strict result "
                "envelope",
            )
            return replace(
                attempt,
                returncode=65,
                category="runtime-unverified",
                final_text=None,
                reason="invalid-result-envelope",
            )
        if result.get("subtype") == "success" and result.get("is_error") is False:
            detail = (
                "Claude success result lacked verified requested-model evidence; "
                "refusing to accept final output"
            )
            _append_attempt_diagnostic(stderr_path, detail)
            return replace(
                attempt,
                returncode=65,
                category="runtime-unverified",
                final_text=None,
                reason="missing-requested-model-usage",
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
            reason="missing-runtime-verification-metadata",
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
            reason="effective-model-mismatch",
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
            reason="effective-effort-mismatch",
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
) -> tuple[
    pathlib.Path | None,
    dict[str, str],
    ClaudeExecutableTrustEvidence | None,
]:
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
        _claude_gpg_temp_root_validator(linux_host) if linux_host is not None else None
    )
    prepared_env.pop("XDG_CONFIG_HOME", None)
    probe_home = review.container_dir / "claude-probe-home"
    probe_home.mkdir(parents=True, exist_ok=True)
    probe_home.chmod(0o700)
    runtime_reports: dict[str, dict[str, object]] = {}
    runtime_executables: dict[str, pathlib.Path] = {}
    runtime_evidence: dict[str, ClaudeExecutableTrustEvidence] = {}

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
            cache_dir=(review.container_dir / "claude-runtime" / "provenance-cache"),
            snapshot_dir=(
                review.container_dir / "claude-runtime" / "verified-executables"
            ),
        )
        verified_executable = (
            verified.executable
            if isinstance(verified, VerifiedClaudeExecutable)
            else candidate
        )
        executable_evidence = _inspect_claude_executable_trust(
            verified_executable,
            expected_sha256=(
                verified.artifact.checksum
                if isinstance(verified, VerifiedClaudeExecutable)
                else None
            ),
            include_bundled_roots=_is_claude_macos_host(),
            required_mode=(
                0o500 if isinstance(verified, VerifiedClaudeExecutable) else None
            ),
        )
        candidate_env = _claude_preflight_probe_environment(
            home=probe_home,
            tmp=claude_tmp,
        )
        _require_claude_safe_mode(verified_executable, candidate_env)
        runtime_executables[str(candidate.absolute())] = verified_executable
        runtime_evidence[str(candidate.absolute())] = executable_evidence
        if isinstance(verified, VerifiedClaudeExecutable):
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
                "bundled_roots": {
                    "count": len(executable_evidence.bundled_root_sha256_fingerprints),
                    "set_sha256": executable_evidence.bundled_root_set_sha256,
                    "source": "publisher-verified-executable-snapshot",
                },
                "gpg_verifier": str(verified.gpg_path),
                "gpg_verifier_trust": "fixed-path-native-host-tool",
                "capabilities": {
                    "required_options": list(CLAUDE_REQUIRED_OPTIONS),
                    "safe_mode_semantics": "verified",
                },
                "outer_sandbox": {
                    "implementation": (
                        "bubblewrap" if _is_claude_linux_host() else "sandbox-exec"
                    ),
                    "status": "pending-runtime-launch",
                },
                "authentication": {
                    "backend": (
                        "api-key"
                        if prepared_env.get("ANTHROPIC_API_KEY")
                        else (
                            "private-file"
                            if _is_claude_linux_host()
                            else "keychain-broker"
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
        return None, prepared_env, None
    report = runtime_reports.get(str(executable.absolute()))
    if report is not None:
        write_json(review.container_dir / "claude-runtime.json", report)
    runtime_executable = runtime_executables.get(
        str(executable.absolute()),
        executable,
    )
    evidence = runtime_evidence.get(str(executable.absolute()))
    if evidence is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude executable snapshot evidence is unavailable"
        )
    return (
        runtime_executable,
        _with_executable_path(
            prepared_env,
            runtime_executable,
        ),
        evidence,
    )


@contextlib.contextmanager
def _claude_linux_review_runtime(
    review: ReviewWorkspace,
    executable: pathlib.Path,
    env: dict[str, str],
    arguments: tuple[str, ...],
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
            config_dir = _claude_linux_private_directory(review, "api-config")
            auth_env["ANTHROPIC_API_KEY"] = api_key
        else:
            source = _claude_linux_credential_source()
            try:
                staged = stack.enter_context(
                    stage_claude_credentials(
                        source,
                        root,
                        required_validity_seconds=(
                            CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS
                        ),
                    )
                )
            except LinuxCredentialUnavailable as error:
                raise ClaudeKeychainCredentialUnavailable(str(error)) from error
            except LinuxCredentialUnsafe as error:
                raise ReviewError(
                    f"Claude Linux local-login credential is unsafe: {error}"
                ) from error
            config_dir = staged.config_dir
        proxy_socket = stack.enter_context(_claude_unix_connect_proxy(review, env))
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
                "authentication": {"status": "sandbox-auth-staged"},
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
    permission_mode = CLAUDE_LINUX_REVIEW_PERMISSION_MODE if linux else "default"
    visible_tools = CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS if linux else "Read,Grep,Glob"
    allowed_tools = CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS if linux else "Read(./**)"
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
                bytes((preceding,)) if preceding in CLAUDE_PROMPT_PATH_QUOTES else b""
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
                        or prompt[token_end + 1] in CLAUDE_PROMPT_PATH_RIGHT_BOUNDARIES
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
    target_diff = b"/workspace/.codex-review/review.diff" if linux else diff_file
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
    executable_evidence: ClaudeExecutableTrustEvidence | None = None,
    trust_state: ClaudeTrustSessionState | None = None,
) -> Attempt:
    if executable is None:
        executable, env, executable_evidence = _resolve_validated_claude_executable(
            review=review,
            env=env,
        )
    elif executable_evidence is None:
        raise ClaudeExecutableInspectionInconclusive(
            "validated Claude executable snapshot evidence is unavailable"
        )
    if executable is None:
        raise FileNotFoundError(
            "claude is not available in a validated executable path"
        )
    assert executable_evidence is not None
    trust_state = trust_state or ClaudeTrustSessionState()
    _require_matching_claude_executable_snapshot(executable, executable_evidence)
    linux_host = _is_claude_linux_host()
    prompt = _claude_review_prompt(
        review,
        review.prompt_file.read_bytes(),
        linux=linux_host,
    )
    if linux_host:
        _require_claude_linux_prompt_without_file_mentions(prompt)
    stdout_path, stderr_path = _attempt_paths(review, index, "claude", model)
    settings = _claude_review_settings(linux=linux_host)
    arguments = _claude_review_arguments(
        model=model,
        settings=settings,
        linux=linux_host,
    )
    completed: Completed | None = None
    for credential_round in range(2):
        _require_matching_claude_executable_snapshot(
            executable,
            executable_evidence,
        )
        attempt_env = _with_claude_review_tool_path(review, env)
        attempt_env = _prepare_claude_tls_environment(
            review,
            attempt_env,
            executable_evidence=executable_evidence,
            trust_state=trust_state,
        )
        _require_matching_claude_executable_snapshot(
            executable,
            executable_evidence,
        )
        if not linux_host:
            if attempt_env.get("ANTHROPIC_API_KEY"):
                authentication_status = "configured"
            else:
                try:
                    _warm_claude_local_login(
                        review,
                        executable,
                        attempt_env,
                        model,
                    )
                except ClaudeAuthWarmupEntitlement as error:
                    (
                        _final_text,
                        effective_model,
                        model_evidence_consistent,
                    ) = _parse_claude_output_evidence(
                        error.completed.stdout,
                        requested_model=model,
                    )
                    attempt = _record_attempt(
                        review=review,
                        index=index,
                        runtime="claude",
                        model=model,
                        completed=error.completed,
                        final_text=None,
                        effective_model=effective_model,
                        requested_effort=CLAUDE_REASONING_EFFORT,
                        effective_effort=None,
                        require_verified_model=True,
                        model_evidence_consistent=model_evidence_consistent,
                    )
                    verified_entitlement = attempt.category == "entitlement"
                    _update_claude_runtime_report(
                        review,
                        {
                            "phase": "authentication-preflight-entitlement",
                            "outer_sandbox": {"status": "pending-runtime-launch"},
                            "authentication": {
                                "status": (
                                    "model-entitlement"
                                    if verified_entitlement
                                    else "model-entitlement-unverified"
                                ),
                                "model": model,
                                "validated_for_model": None,
                            },
                            "attempt": {
                                "requested_model": model,
                                "effective_model": attempt.effective_model,
                                "requested_effort": CLAUDE_REASONING_EFFORT,
                                "effective_effort": attempt.effective_effort,
                                "category": attempt.category,
                                "reason": attempt.reason,
                                "returncode": attempt.returncode,
                            },
                        },
                    )
                    return attempt
                except ClaudeAuthWarmupInconclusive:
                    _update_claude_runtime_report(
                        review,
                        {
                            "phase": "authentication-preflight-inconclusive",
                            "outer_sandbox": {"status": "pending-runtime-launch"},
                            "authentication": {
                                "status": "inconclusive",
                                "model": model,
                                "failure_class": "warmup",
                                "validated_for_model": None,
                            },
                            "attempt": None,
                        },
                    )
                    raise
                except (
                    ClaudeKeychainBrokerUnavailable,
                    ClaudeKeychainCredentialUnavailable,
                    ClaudeLoopbackUnavailable,
                ):
                    _update_claude_runtime_report(
                        review,
                        {
                            "phase": "authentication-preflight-unavailable",
                            "outer_sandbox": {"status": "pending-runtime-launch"},
                            "authentication": {
                                "status": "unavailable",
                                "model": model,
                                "validated_for_model": None,
                            },
                            "attempt": None,
                        },
                    )
                    raise
                authentication_status = "freshness-verified"
            _update_claude_runtime_report(
                review,
                {
                    "phase": "authentication-preflight-complete",
                    "outer_sandbox": {"status": "pending-runtime-launch"},
                    "authentication": {
                        "status": authentication_status,
                        "model": model,
                        "validated_for_model": model,
                    },
                    "attempt": None,
                },
            )
        if linux_host:
            _require_matching_claude_executable_snapshot(
                executable,
                executable_evidence,
            )
            with _claude_linux_review_runtime(
                review,
                executable,
                attempt_env,
                arguments,
            ) as sandbox_command:
                _require_matching_claude_executable_snapshot(
                    executable,
                    executable_evidence,
                )
                completed = run(
                    sandbox_command.argv,
                    cwd=review.workspace_root,
                    env=sandbox_command.env,
                    stdin=prompt,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
                    output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
                )
            break
        try:
            with contextlib.ExitStack() as stack:
                try:
                    runtime_env = stack.enter_context(
                        _claude_keychain_runtime(review, attempt_env)
                    )
                except (
                    ReviewTimeoutError,
                    ReviewOutputDrainError,
                    ReviewOutputLimitError,
                    ReviewProcessLeakError,
                ) as error:
                    raise ClaudeAuthWarmupInconclusive(
                        f"Claude final credential check was inconclusive: {error}"
                    ) from error
                proxy_port = stack.enter_context(_claude_connect_proxy(runtime_env))
                review_env = _with_claude_proxy_environment(
                    runtime_env,
                    proxy_port,
                )
                sandbox_profile = _claude_review_sandbox_profile(
                    executable,
                    review,
                    review_env,
                    proxy_port=proxy_port,
                )
                _require_matching_claude_executable_snapshot(
                    executable,
                    executable_evidence,
                )
                _update_claude_runtime_report(
                    review,
                    {
                        "phase": "runtime-launching",
                        "outer_sandbox": {"status": "profile-generated"},
                        "authentication": {"status": "sandbox-auth-staged"},
                    },
                )
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
            break
        except ClaudeKeychainCredentialRefreshRequired as error:
            if credential_round == 0:
                continue
            inconclusive = ClaudeAuthWarmupInconclusive(
                "Claude credential freshness expired during repeated "
                "final-attempt preflight"
            )
            _update_claude_runtime_report(
                review,
                {
                    "phase": "authentication-preflight-inconclusive",
                    "outer_sandbox": {"status": "pending-runtime-launch"},
                    "authentication": {
                        "status": "inconclusive",
                        "model": model,
                        "failure_class": "credential-read",
                        "validated_for_model": None,
                    },
                    "attempt": None,
                },
            )
            raise inconclusive from error
        except ClaudeAuthWarmupInconclusive:
            _update_claude_runtime_report(
                review,
                {
                    "phase": "authentication-preflight-inconclusive",
                    "outer_sandbox": {"status": "pending-runtime-launch"},
                    "authentication": {
                        "status": "inconclusive",
                        "model": model,
                        "failure_class": "credential-read",
                        "validated_for_model": None,
                    },
                    "attempt": None,
                },
            )
            raise
        except (
            ClaudeKeychainBrokerUnavailable,
            ClaudeKeychainCredentialUnavailable,
            ClaudeLoopbackUnavailable,
        ):
            _update_claude_runtime_report(
                review,
                {
                    "phase": "authentication-preflight-unavailable",
                    "outer_sandbox": {"status": "pending-runtime-launch"},
                    "authentication": {
                        "status": "unavailable",
                        "model": model,
                        "validated_for_model": None,
                    },
                    "attempt": None,
                },
            )
            raise
    if completed is None:
        raise ClaudeAuthWarmupInconclusive(
            "Claude final-attempt preflight did not complete"
        )
    final_text, effective_model, model_evidence_consistent = (
        _parse_claude_output_evidence(
            completed.stdout,
            requested_model=model,
        )
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
        model_evidence_consistent=model_evidence_consistent,
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
                "reason": attempt.reason,
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

REVIEW_SUPERVISION_FAILURE_CLASSES: tuple[tuple[type[Exception], str], ...] = (
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
        "reason": attempt.reason,
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
    if not attempts:
        return Outcome(1, None, tuple())
    if attempts[-1].category in {
        "inconclusive",
        "transient",
    }:
        return Outcome(75, None, tuple(attempts))
    return Outcome(1, None, tuple(attempts))


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
            _append_attempt_diagnostic(
                stderr_path, f"review supervision failed: {error}"
            )
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
                    reason=_review_supervision_failure_class(error),
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
                "Claude-family review requires an explicit egress-consent reason.\n",
            )
            return Outcome(2, None, tuple())
    elif egress_consent is not None:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "egress-consent is valid only for the Claude-family reviewer.\n",
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
    write_json(review.container_dir / "preflight.json", preflight_evidence)

    if reviewer == "claude":
        write_json(
            review.container_dir / "egress.json",
            {
                "consent": egress_consent,
                "reviewer": "claude-family",
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
    explicit_claude_override = bool(os.environ.get("CODEX_REVIEW_CLAUDE_PATH"))
    try:
        linux_host = _is_claude_linux_host()
        prompt = _claude_review_prompt(
            review,
            review.prompt_file.read_bytes(),
            linux=linux_host,
        )
        if linux_host:
            _require_claude_linux_prompt_without_file_mentions(prompt)
        (
            claude_executable,
            claude_env,
            claude_executable_evidence,
        ) = _resolve_validated_claude_executable(
            review=review,
            env=claude_env,
        )
        claude_available = claude_executable is not None
        if claude_available:
            if not _is_claude_linux_host():
                claude_env = _prepare_claude_keychain_broker(review, claude_env)
            claude_env = _with_claude_review_tool_path(review, claude_env)
            _update_claude_runtime_report(
                review,
                {
                    "phase": "attempt-preflight-ready",
                    "authentication": {
                        "status": (
                            "configured"
                            if claude_env.get("ANTHROPIC_API_KEY")
                            else "deferred-to-final-attempt"
                        )
                    },
                },
            )
    except (
        ClaudeProbeSandboxUnavailable,
        ClaudeKeychainBrokerUnavailable,
        ClaudeKeychainCredentialUnavailable,
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
        ClaudeAuthWarmupInconclusive,
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
    if (
        claude_available
        and claude_executable is not None
        and claude_executable_evidence is not None
    ):
        claude_trust_state = ClaudeTrustSessionState()

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
                executable_evidence=claude_executable_evidence,
                trust_state=claude_trust_state,
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
            ClaudeAuthWarmupInconclusive,
            ClaudeExecutableInspectionInconclusive,
            ReviewTimeoutError,
            ReviewOutputDrainError,
            ReviewOutputLimitError,
            ReviewProcessLeakError,
        ) as error:
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
                f"Claude Code validation was inconclusive: {error}\n",
            )
            _write_attempts(review, attempts)
            return Outcome(75, None, tuple(attempts))
        except (
            ClaudeKeychainBrokerUnavailable,
            ClaudeKeychainCredentialUnavailable,
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
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                "Claude Code failed executable validation; "
                f"refusing Copilot fallback: {error}\n",
            )
            _write_attempts(review, attempts)
            return Outcome(2, None, tuple(attempts))
        if final_text:
            return _finish(review, attempts, final_text)
        if category not in {"auth", "entitlement", "unavailable"}:
            return _finish(review, attempts, None)

    if egress_consent not in COPILOT_EGRESS_CONSENTS:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code was unavailable, lacked usable local/API authentication, "
            "or lacked model entitlement, but "
            "explicit-claude-review does not authorize GitHub Copilot fallback.\n",
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
            "Claude Code was unavailable, lacked usable local/API authentication, "
            "or lacked model entitlement, and Copilot CLI is unavailable.\n",
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
