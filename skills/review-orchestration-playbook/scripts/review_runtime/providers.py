from __future__ import annotations

import base64
import binascii
import contextlib
import ctypes
import datetime
import enum
import errno
import hashlib
import hmac
import importlib
import itertools
import json
import math
import os
import pathlib
import plistlib
import re
import secrets
import select
import signal
import socket
import socketserver
import ssl
import stat
import struct
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, BinaryIO, Callable, Iterable, Iterator, Mapping, TypeVar

from .claude_capabilities import (
    CLAUDE_REQUIRED_OPTIONS,
    ClaudeCapabilities,
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
from .claude_refresh_lock import (
    ClaudeRefreshLockError,
    ClaudeRefreshLockLease,
    ClaudeRefreshLockProtocol,
    ClaudeRefreshLockStale,
    attach_claude_refresh_lock_recovery as _attach_claude_refresh_lock_recovery_raw,
    certified_claude_refresh_lock_protocol,
    claude_refresh_lock,
    claude_refresh_lock_release_on_success,
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
    BoundedCapture,
    Completed,
    ForwardedSignal,
    InvalidReviewerExecutable,
    ProcessStartOwner,
    RejectedReviewerCandidates,
    ReviewError,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    atomic_write_redactions,
    child_environment,
    forwarded_signals,
    is_relative_to,
    output_redact_values,
    read_json,
    reviewer_executable_path,
    resolve_reviewer_executable,
    restore_signal_mask,
    run,
    run_bounded_capture,
    strict_json_loads,
    write_json,
    write_json_atomic_at,
    write_text_atomic,
    write_text_atomic_at,
)
from .workspace import (
    BoundReviewLock,
    MAX_REVIEW_PROMPT_BYTES,
    ReviewWorkspace,
    _review_root_for_source,
    build_preflight_evidence,
    encode_preflight_json,
    open_bound_review_lock,
    remove_private_review_artifacts,
    validate_external_workspace,
    write_bound_review_json,
    write_bound_runner_error,
)

_CaptureResult = TypeVar("_CaptureResult")


def _load_claude_stream_validator() -> Any:
    """Load and cache the sibling validator only when a Claude stream needs it."""
    try:
        return globals()["claude_stream_validator"]
    except KeyError:
        pass
    validator = importlib.import_module("validate_claude_stream")
    globals()["claude_stream_validator"] = validator
    return validator


def __getattr__(name: str) -> Any:
    if name == "claude_stream_validator":
        return _load_claude_stream_validator()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
CLAUDE_KEYCHAIN_CLIENT = pathlib.Path("/usr/bin/security")
CLAUDE_KEYCHAIN_BROKER_ARTIFACT = pathlib.Path(__file__).with_name(
    "claude_keychain_broker"
)
CLAUDE_KEYCHAIN_BROKER_ARTIFACT_SHA256 = (
    "fcdf6d473ec5c6fa76488da0b115d147fe5e5fa576ed33710ecd3fd7186e0b46"
)
CLAUDE_KEYCHAIN_BROKER_CDHASHES = frozenset(
    {
        bytes.fromhex("8af40bf4caf7e2398fb59182082ea57caa12ed9a"),
        bytes.fromhex("a5de7fbd8785b8baddb34da1d8477aa4f741efa0"),
    }
)
CLAUDE_KEYCHAIN_BROKER_INSTALL_ROOT = pathlib.Path(
    "/Library/Joey-Tools/CodexReview/brokers"
)
CLAUDE_KEYCHAIN_BROKER_INSTALL_PATH = (
    CLAUDE_KEYCHAIN_BROKER_INSTALL_ROOT
    / CLAUDE_KEYCHAIN_BROKER_ARTIFACT_SHA256
    / "security"
)
CLAUDE_KEYCHAIN_ACCOUNT = re.compile(r"^[A-Za-z0-9._-]+$")
CLAUDE_KEYCHAIN_SERVICE = "Claude Code-credentials"
CLAUDE_KEYCHAIN_BROKER_PORT_ENV = "CODEX_CLAUDE_KEYCHAIN_BROKER_PORT"
CLAUDE_KEYCHAIN_BROKER_EXECUTABLE_ENV = "CODEX_CLAUDE_KEYCHAIN_BROKER_EXECUTABLE"
CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET_ENV = (
    "CODEX_CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET"
)
CLAUDE_KEYCHAIN_BROKER_IDENTITY_DIRECTORY_ENV = (
    "CODEX_CLAUDE_KEYCHAIN_BROKER_IDENTITY_DIRECTORY"
)
CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES = 32
CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES = 64 * 1024
CLAUDE_KEYCHAIN_BROKER_ARTIFACT_LIMIT_BYTES = 1024 * 1024
CLAUDE_KEYCHAIN_BROKER_DIRECTORY_ATTEMPTS = 4
CLAUDE_KEYCHAIN_BROKER_DIRECTORY_PREFIX = "keychain-identity-"
CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET_NAME = "identity.sock"
CLAUDE_KEYCHAIN_BROKER_LOCAL_SOCKET_LEVEL = 0
CLAUDE_KEYCHAIN_BROKER_LOCAL_PEERPID = 2
CLAUDE_MACOS_CS_OPS_CDHASH = 5
CLAUDE_MACOS_CDHASH_BYTES = 20
CLAUDE_MACOS_PATH_BUFFER_BYTES = 1024
CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_SERVER_START_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_SERVER_POLL_INTERVAL_SECONDS = 0.05
CLAUDE_CREDENTIAL_UPDATE_LOCK_TIMEOUT_SECONDS = 5.0
CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES = 1024 * 1024
CLAUDE_KEYCHAIN_ITEM_NOT_FOUND_STATUS = 44
CLAUDE_KEYCHAIN_SECURITY_STDIN_LIMIT_BYTES = 4032
CLAUDE_MACOS_DUAL_CARRIER_KEYCHAIN_ATTEMPTS = 2
CLAUDE_CREDENTIAL_FILE_NAME = ".credentials.json"
CLAUDE_MACOS_RECOVERY_ENTRY_LIMIT = 64
CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX = f".{CLAUDE_CREDENTIAL_FILE_NAME}.codex-"
CLAUDE_MACOS_RECOVERY_UPDATE_SUFFIX = ".tmp"
CLAUDE_MACOS_DURABLE_STAGE_GENERATION_WIDTH = 20
CLAUDE_MACOS_DURABLE_STAGE_PENDING_PREFIX = "claude-carrier-pending-"
CLAUDE_MACOS_DURABLE_STAGE_COMMITTED_PREFIX = "claude-carrier-durable-"
CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS = 8
CLAUDE_MACOS_DURABLE_STAGE_MAX_BYTES = (
    CLAUDE_MACOS_DURABLE_STAGE_MAX_GENERATIONS * CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
)
CLAUDE_AUTH_LOGIN_ACTION = "Run `claude auth login`, then retry the review."
CLAUDE_API_KEY_ACTION = "Unset or replace `ANTHROPIC_API_KEY`, then retry the review."
CLAUDE_OAUTH_TOKEN_ACTION = (
    "Unset or replace `CLAUDE_CODE_OAUTH_TOKEN`, then retry the review."
)
CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC = (
    "Claude credential refresh persistence also failed; the selected host "
    "credential source changed or could not be safely updated."
)
CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC = (
    "Claude trust policy evidence also failed to persist"
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
CLAUDE_TLS_BYPASS_ENV_KEYS = (
    "NODE_OPTIONS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
)
CLAUDE_CA_FILE_LIMIT_BYTES = 16 * 1024 * 1024
CLAUDE_CA_DIR_LIMIT_BYTES = 64 * 1024 * 1024
CLAUDE_CA_DIR_ENTRY_LIMIT = 4096
CLAUDE_CA_SYMLINK_LIMIT = 32
CLAUDE_CA_PATH_COMPONENT_LIMIT = 256
CLAUDE_PROXY_CA_HASH_TIMEOUT_SECONDS = 20.0
CLAUDE_PROXY_CA_HASH_CERTIFICATE_LIMIT = 512
CLAUDE_PROXY_TLS_VERIFY_FLAGS = ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
CLAUDE_OPENSSL_CA_HASH_ENTRY_RE = re.compile(r"^([0-9a-f]{8})\.(0|[1-9][0-9]*)$")
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
CLAUDE_TRUST_FINGERPRINT = re.compile(r"^[0-9A-Fa-f]{40}$")
CLAUDE_ACL_TYPE_EXTENDED = 0x00000100
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
LOW_LEVEL_HELPER_REVIEW_CONTRACT = "supplied-diff-private-git"
NAMED_LANE_ELIGIBLE = False
CLAUDE_EGRESS_CONSENTS = (
    "explicit-claude-review",
    "explicit-claude-with-copilot-fallback",
)
COPILOT_EGRESS_CONSENTS = ("explicit-claude-with-copilot-fallback",)
CODEX_ENV_KEYS = ("CODEX_HOME", "OPENAI_API_KEY")
CLAUDE_EXPLICIT_AUTH_ENV_KEYS = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
)
CLAUDE_PROXY_URL_ENV_KEYS = (
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
)
CLAUDE_PROXY_USERINFO_SAFE_CHARACTERS = "!$%&'()*+,-._~"
CLAUDE_PROXY_IGNORED_URL_CONTROLS = str.maketrans("", "", "\t\n\r")
CLAUDE_PROXY_MINIMUM_STANDALONE_REDACTION_BYTES = 8
CLAUDE_ENV_KEYS = (*CLAUDE_EXPLICIT_AUTH_ENV_KEYS, "NODE_EXTRA_CA_CERTS")
CLAUDE_STREAM_ENTITLEMENT_REASONS = frozenset(
    (
        "terminal.model-entitlement-denial",
        "terminal.organization-policy-denial",
    )
)
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
CLAUDE_MODEL_ENTITLEMENT_TEXT_PATTERNS = (
    re.compile(
        r"\s*(?:error:\s*)?(?:(?:this|the|requested)\s+)?model\s+"
        r"(?:is|was)\s+not\s+"
        r"(?:available|enabled|allowed|included|supported|entitled)"
        r"(?:\s+(?:for|to|on|in|with|by)\s+"
        r"(?:(?:your|this|the)\s+)?"
        r"(?:(?:chatgpt\s+)?account(?:\s+plan)?|user|organization|organisation|plan|"
        r"current\s+plan|current\s+subscription))?\s*[.!]?\s*",
        re.I,
    ),
    re.compile(
        r"\s*(?:error:\s*)?(?:does not|do not|don't)\s+have access to\s+"
        r"(?:(?:this|the|requested)\s+)?model\s*[.!]?\s*",
        re.I,
    ),
    re.compile(
        r"\s*(?:error:\s*)?(?:account|user|organization|organisation)\s+"
        r"has no access to\s+(?:(?:this|the|requested)\s+)?model\s*[.!]?\s*",
        re.I,
    ),
    re.compile(
        r"\s*(?:error:\s*)?model access\s+"
        r"(?:(?:is|has been)\s+)?(?:denied|disabled)\s*[.!]?\s*",
        re.I,
    ),
    re.compile(
        r"\s*(?:error:\s*)?model\s+is\s+"
        r"(?:disabled|not allowed|not enabled)\s+(?:by|for)\s+"
        r"(?:your|this)\s+(?:organization|organisation)\s*[.!]?\s*",
        re.I,
    ),
    re.compile(
        r"\s*(?:error:\s*)?not in\s+(?:your|this)\s+"
        r"(?:organization|organisation)'s\s+allowed models\s*[.!]?\s*",
        re.I,
    ),
    re.compile(
        r"\s*(?:error:\s*)?unsupported model for\s+"
        r"(?:this|your|the) account\s*[.!]?\s*",
        re.I,
    ),
)
CLAUDE_ENTITLEMENT_NEUTRAL_TEXT_PATTERN = re.compile(
    r"\s*(?:error|request rejected)\s*",
    re.I,
)

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
_UNRESOLVED_CLAUDE_REFRESH_LOCK_PROTOCOL = object()


class ClaudeProbeSandboxUnavailable(ReviewError):
    """The host does not provide the required Claude probe sandbox runtime."""


class ClaudeKeychainBrokerUnavailable(ReviewError):
    """The host cannot build the restricted Claude Keychain broker."""


class ClaudeKeychainCredentialUnavailable(ReviewError):
    """The local Claude credential is absent or cannot be used safely."""


class ClaudeCredentialUnsafe(ClaudeKeychainCredentialUnavailable):
    """A configured Claude credential source failed closed safety validation."""


class ClaudeKeychainCredentialIntegrityError(ClaudeCredentialUnsafe):
    """Claude Keychain framing failed closed safety validation."""


class ClaudeCredentialInspectionInconclusive(ReviewError):
    """Credential I/O or a source race prevented a stable inspection."""


class ClaudeCredentialStaleRefreshLock(ClaudeCredentialInspectionInconclusive):
    """A stale shared refresh lock needs controlled operator recovery."""


class ClaudeCredentialPersistenceDiagnostic(Exception):
    """Visible Python 3.10 fallback for a secondary persistence failure."""


class ClaudeCredentialCleanupDiagnostic(Exception):
    """Visible Python 3.10 fallback for a secondary descriptor cleanup failure."""


class ClaudeCredentialCleanupControlFlowDiagnostic(BaseException):
    """Safe bounded placeholder for omitted BaseExceptionGroup children."""


def _is_claude_control_flow_error(error: BaseException) -> bool:
    return not isinstance(error, Exception) or isinstance(error, ForwardedSignal)


_CLAUDE_ERROR_GRAPH_NODE_BUDGET = 32
_CLAUDE_TIMEOUT_SEALED_SAFE_NOTE = (
    "Claude Keychain broker recovery timeout was finalized safely; later "
    "recovery diagnostics cannot replace the failure already delivered to "
    "the caller"
)
_CLAUDE_TIMEOUT_LATE_CONTROL_FLOW_NOTE = (
    "A control-flow failure occurred after the Claude recovery timeout was "
    "finalized; raw late details were hidden and the delivered failure root "
    "was retained"
)
_CLAUDE_TIMEOUT_LATE_ORDINARY_NOTE = (
    "An additional failure occurred after the Claude recovery timeout was "
    "finalized; raw late details were hidden and the delivered failure root "
    "was retained"
)


@dataclass
class _ClaudeTimeoutRootState:
    lock: Any
    fail_closed_root: pathlib.Path
    root: BaseException | None = None
    sealed: bool = False
    proof_revision: int = 0
    scope_required: bool = True


def _claude_timeout_root_state(
    error: BaseException,
) -> _ClaudeTimeoutRootState | None:
    state = getattr(error, "_codex_claude_timeout_root_state", None)
    if (
        not isinstance(state, _ClaudeTimeoutRootState)
        or not state.sealed
        or state.root is not error
    ):
        return None
    return state


def attach_claude_refresh_lock_recovery(
    error: BaseException,
    cleanup_error: BaseException,
) -> None:
    """Attach raw refresh-lock recovery only outside sealed timeout roots."""

    if (
        _claude_timeout_root_state(error) is not None
        or _claude_timeout_root_state(cleanup_error) is not None
    ):
        return
    _attach_claude_refresh_lock_recovery_raw(error, cleanup_error)


def _claude_exception_group_children(
    error: BaseException,
) -> tuple[BaseException, ...]:
    group_type = getattr(
        sys.modules["builtins"],
        "BaseExceptionGroup",
        None,
    )
    if not isinstance(group_type, type) or not isinstance(error, group_type):
        return ()
    children = getattr(error, "exceptions", ())
    if not isinstance(children, tuple):
        return ()
    return tuple(child for child in children if isinstance(child, BaseException))


def _claude_error_graph_contains(
    root: BaseException | None,
    candidate: BaseException,
) -> bool:
    pending = [(root, False)] if isinstance(root, BaseException) else []
    active: set[int] = set()
    complete: set[int] = set()
    while pending:
        current, exiting = pending.pop()
        identity = id(current)
        if exiting:
            active.discard(identity)
            complete.add(identity)
            continue
        if current is candidate:
            return True
        if identity in active:
            return True
        if identity in complete:
            continue
        if len(active) + len(complete) >= _CLAUDE_ERROR_GRAPH_NODE_BUDGET:
            return True
        active.add(identity)
        pending.append((current, True))
        for related in (
            current.__cause__,
            current.__context__,
            *_claude_exception_group_children(current),
        ):
            if isinstance(related, BaseException):
                pending.append((related, False))
    return False


def _claude_persistence_source_from_error_graph(
    root: BaseException,
) -> tuple[BaseException | None, bool]:
    pending = [(root, False)]
    active: set[int] = set()
    complete: set[int] = set()
    source: BaseException | None = None
    while pending:
        current, exiting = pending.pop()
        identity = id(current)
        if exiting:
            active.discard(identity)
            complete.add(identity)
            continue
        if identity in active:
            return None, False
        if identity in complete:
            continue
        if len(active) + len(complete) >= _CLAUDE_ERROR_GRAPH_NODE_BUDGET:
            return None, False
        if (
            current is not root
            and source is None
            and getattr(
                current,
                "_codex_claude_refresh_persistence_failed",
                False,
            )
        ):
            source = current
        active.add(identity)
        pending.append((current, True))
        for related in (
            current.__cause__,
            current.__context__,
            *_claude_exception_group_children(current),
        ):
            if isinstance(related, BaseException):
                pending.append((related, False))
    return source, True


def _claude_cleanup_error_without_primary_backlink(
    secondary: BaseException,
    primary: BaseException,
) -> BaseException:
    if not _claude_error_graph_contains(secondary, primary):
        return secondary
    if isinstance(secondary, ForwardedSignal):
        rendered: BaseException = ForwardedSignal(
            secondary.signum,
            detail=secondary.detail,
        )
    else:
        rendered = ClaudeCredentialCleanupDiagnostic(
            f"{type(secondary).__name__}: {secondary}"
        )
    if isinstance(
        secondary.__cause__, BaseException
    ) and not _claude_error_graph_contains(secondary.__cause__, primary):
        rendered.__cause__ = secondary.__cause__
    if (
        not secondary.__suppress_context__
        and isinstance(secondary.__context__, BaseException)
        and not _claude_error_graph_contains(secondary.__context__, primary)
    ):
        rendered.__context__ = secondary.__context__
        if rendered.__cause__ is None:
            rendered.__suppress_context__ = False
    if _claude_error_graph_contains(rendered, primary):
        rendered.__context__ = None
    if _claude_error_graph_contains(rendered, primary):
        rendered.__cause__ = None
    return rendered


def _claude_visible_error_chain_snapshot(
    root: BaseException,
) -> tuple[tuple[BaseException, ...], bool]:
    chain: list[BaseException] = []
    current = root
    seen: set[int] = set()
    while len(chain) < _CLAUDE_ERROR_GRAPH_NODE_BUDGET:
        identity = id(current)
        if identity in seen:
            return tuple(chain), False
        seen.add(identity)
        chain.append(current)
        if isinstance(current.__cause__, BaseException):
            current = current.__cause__
            continue
        if not current.__suppress_context__ and isinstance(
            current.__context__, BaseException
        ):
            current = current.__context__
            continue
        return tuple(chain), True
    return tuple(chain), False


def _claude_error_graph_snapshot(
    root: BaseException,
) -> tuple[tuple[BaseException, ...], bool]:
    pending = [(root, False)]
    active: set[int] = set()
    complete: set[int] = set()
    nodes: dict[int, BaseException] = {}
    while pending:
        current, exiting = pending.pop()
        identity = id(current)
        if exiting:
            active.discard(identity)
            complete.add(identity)
            continue
        if identity in active:
            return tuple(nodes.values()), False
        if identity in complete:
            continue
        if len(nodes) >= _CLAUDE_ERROR_GRAPH_NODE_BUDGET:
            return tuple(nodes.values()), False
        nodes[identity] = current
        active.add(identity)
        pending.append((current, True))
        cleanup_evidence = getattr(
            current,
            "_codex_claude_refresh_lock_cleanup_evidence",
            None,
        )
        for related in (
            current.__cause__,
            current.__context__,
            cleanup_evidence,
            *_claude_exception_group_children(current),
        ):
            if isinstance(related, BaseException):
                pending.append((related, False))
    return tuple(nodes.values()), True


def _claude_cleanup_chain_detail(
    cleanup: BaseException,
    *,
    stop_before: frozenset[int],
) -> tuple[str, bool]:
    visible, visible_complete = _claude_visible_error_chain_snapshot(cleanup)
    graph, graph_complete = _claude_error_graph_snapshot(cleanup)
    prefix: list[BaseException] = []
    stopped = False
    for error in visible:
        if id(error) in stop_before:
            stopped = True
            break
        prefix.append(error)
    recovery_unproven = (
        not visible_complete
        or not graph_complete
        or any(
            getattr(error, "_codex_claude_cleanup_graph_incomplete", False) is True
            for error in graph
        )
    )
    retained_descriptor_bound = any(
        getattr(
            error,
            "_codex_claude_refresh_lock_descriptor_bound",
            False,
        )
        is True
        for error in graph
    )
    detail_parts = [f"{type(error).__name__}: {error}" for error in prefix]
    if retained_descriptor_bound:
        detail_parts.append(
            "descriptor-bound refresh-lock recovery evidence is retained"
        )
    if recovery_unproven:
        detail_parts.append(
            "cleanup control-flow or descriptor-bound recovery evidence may "
            "be hidden beyond the safety limit"
        )
    detail = " -> ".join(detail_parts)
    if not visible_complete and not stopped:
        detail += "; additional cleanup links omitted after safety limit"
    return detail, retained_descriptor_bound or recovery_unproven


def _claude_cleanup_recovery_state(
    *roots: BaseException | None,
) -> tuple[bool, bool]:
    descriptor_bound = False
    recovery_incomplete = False
    for root in roots:
        if not isinstance(root, BaseException):
            continue
        graph, graph_complete = _claude_error_graph_snapshot(root)
        descriptor_bound = descriptor_bound or any(
            getattr(
                error,
                "_codex_claude_refresh_lock_descriptor_bound",
                False,
            )
            is True
            for error in graph
        )
        recovery_incomplete = (
            recovery_incomplete
            or not graph_complete
            or any(
                getattr(
                    error,
                    "_codex_claude_cleanup_graph_incomplete",
                    False,
                )
                is True
                for error in graph
            )
        )
    return descriptor_bound, recovery_incomplete


def _claude_sanitized_cleanup_wrapper(
    source: BaseException,
    *,
    role: str,
    descriptor_bound: bool,
    recovery_incomplete: bool,
) -> ClaudeCredentialCleanupDiagnostic:
    try:
        source_type = type(source).__name__
    except BaseException:
        source_type = "BaseException"
    if (
        not isinstance(source_type, str)
        or not source_type.isidentifier()
        or len(source_type) > 128
    ):
        source_type = "BaseException"
    detail_parts = [
        f"{role} type: {source_type}",
        "raw exception details hidden",
    ]
    if descriptor_bound:
        detail_parts.append(
            "descriptor-bound refresh-lock recovery evidence is retained"
        )
    if recovery_incomplete:
        detail_parts.append(
            "cleanup control-flow or descriptor-bound recovery evidence may "
            "be hidden beyond the safety limit"
        )
    wrapper = ClaudeCredentialCleanupDiagnostic("; ".join(detail_parts))
    setattr(
        wrapper,
        "_codex_claude_refresh_lock_descriptor_bound",
        True,
    )
    if recovery_incomplete:
        setattr(
            wrapper,
            "_codex_claude_cleanup_graph_incomplete",
            True,
        )
    return wrapper


def _sanitize_claude_cleanup_primary_root(
    primary: BaseException,
    *,
    note: str,
    recovery_incomplete: bool,
) -> None:
    if isinstance(primary, ForwardedSignal):
        primary.detail = note
        primary.args = (
            f"review orchestration received signal {int(primary.signum)}; {note}",
        )
    elif isinstance(primary, OSError):
        retained_errno = primary.errno
        primary.filename = None
        primary.filename2 = None
        primary.strerror = note
        if isinstance(retained_errno, int):
            primary.args = (retained_errno, note)
        else:
            primary.args = (note,)
    elif isinstance(primary, SystemExit):
        if primary.code is not None and not isinstance(primary.code, int):
            primary.code = 1
        primary.args = (note,)
    elif isinstance(primary, SyntaxError):
        primary.msg = note
        primary.filename = None
        primary.text = None
        primary.lineno = None
        primary.offset = None
        primary.end_lineno = None
        primary.end_offset = None
        primary.args = (note,)
    else:
        primary.args = (note,)
    primary.__notes__ = [note]
    primary.__traceback__ = None
    primary.__cause__ = None
    primary.__context__ = None
    primary.__suppress_context__ = True
    for attribute in (
        "_codex_claude_refresh_lock_cleanup_evidence",
        "_codex_claude_refresh_lock_paths",
    ):
        try:
            delattr(primary, attribute)
        except AttributeError:
            pass
    setattr(
        primary,
        "_codex_claude_refresh_lock_descriptor_bound",
        True,
    )
    if recovery_incomplete:
        setattr(
            primary,
            "_codex_claude_cleanup_graph_incomplete",
            True,
        )


def _safe_claude_cleanup_group_placeholder(
    *,
    preserve_control_flow: bool,
) -> BaseException:
    message = "additional structured exception details hidden after safety limit"
    if preserve_control_flow:
        placeholder: BaseException = ClaudeCredentialCleanupControlFlowDiagnostic(
            message
        )
    else:
        placeholder = ClaudeCredentialCleanupDiagnostic(message)
    setattr(
        placeholder,
        "_codex_claude_refresh_lock_descriptor_bound",
        True,
    )
    setattr(
        placeholder,
        "_codex_claude_cleanup_graph_incomplete",
        True,
    )
    return placeholder


def _safe_claude_cleanup_group_child(
    source: BaseException,
    *,
    note: str,
    descriptor_bound: bool,
    recovery_incomplete: bool,
    remaining: list[int],
) -> tuple[BaseException, bool]:
    if remaining[0] <= 0:
        raise AssertionError("structured exception node budget exhausted")
    children = _claude_exception_group_children(source)
    if children and remaining[0] == 1:
        remaining[0] = 0
        return (
            _safe_claude_cleanup_group_placeholder(
                preserve_control_flow=_is_claude_control_flow_error(source),
            ),
            False,
        )
    remaining[0] -= 1
    if children:
        exception_group_type = getattr(
            sys.modules["builtins"],
            "ExceptionGroup",
        )
        base_exception_group_type = getattr(
            sys.modules["builtins"],
            "BaseExceptionGroup",
        )
        ordinary_group = isinstance(source, exception_group_type)
        safe_children: list[BaseException] = []
        complete = True
        for index, child in enumerate(children):
            has_more_siblings = index + 1 < len(children)
            if remaining[0] == 1 and has_more_siblings:
                remaining[0] = 0
                safe_children.append(
                    _safe_claude_cleanup_group_placeholder(
                        preserve_control_flow=not ordinary_group,
                    )
                )
                complete = False
                break
            child_remaining = remaining
            available = remaining[0]
            if has_more_siblings:
                child_remaining = [available - 1]
            safe_child, child_complete = _safe_claude_cleanup_group_child(
                child,
                note=note,
                descriptor_bound=descriptor_bound,
                recovery_incomplete=recovery_incomplete,
                remaining=child_remaining,
            )
            safe_children.append(safe_child)
            complete = complete and child_complete
            if has_more_siblings:
                consumed = available - 1 - child_remaining[0]
                remaining[0] -= consumed
            if remaining[0] <= 0:
                complete = complete and not has_more_siblings
                break
        constructor = (
            exception_group_type if ordinary_group else base_exception_group_type
        )
        safe_group = constructor(note, safe_children)
        safe_group.__notes__ = [note]
        safe_group.__suppress_context__ = True
        setattr(
            safe_group,
            "_codex_claude_refresh_lock_descriptor_bound",
            True,
        )
        if recovery_incomplete or not complete:
            setattr(
                safe_group,
                "_codex_claude_cleanup_graph_incomplete",
                True,
            )
        return safe_group, complete
    if _is_claude_control_flow_error(source):
        _sanitize_claude_cleanup_primary_root(
            source,
            note=note,
            recovery_incomplete=recovery_incomplete,
        )
        return source, True
    return (
        _claude_sanitized_cleanup_wrapper(
            source,
            role="Structured exception child",
            descriptor_bound=descriptor_bound,
            recovery_incomplete=recovery_incomplete,
        ),
        True,
    )


def _safe_claude_cleanup_group_root(
    source: BaseException,
    *,
    note: str,
    descriptor_bound: bool,
    recovery_incomplete: bool,
) -> BaseException:
    safe_root, _complete = _safe_claude_cleanup_group_child(
        source,
        note=note,
        descriptor_bound=descriptor_bound,
        recovery_incomplete=recovery_incomplete,
        remaining=[_CLAUDE_ERROR_GRAPH_NODE_BUDGET],
    )
    return safe_root


def _merge_claude_sealed_timeout_failure_locked(
    primary: BaseException,
    secondary: BaseException,
    state: _ClaudeTimeoutRootState,
) -> BaseException:
    if not state.sealed or state.root is not primary:
        raise AssertionError("Claude sealed timeout root state changed")
    proof = _get_claude_retained_credential_proof(secondary)
    if proof is None:
        proof = _get_claude_retained_credential_proof(primary)
    late_control_flow = _is_claude_control_flow_error(secondary)
    count_attribute = (
        "_codex_claude_timeout_late_control_flow_count"
        if late_control_flow
        else "_codex_claude_timeout_late_ordinary_count"
    )
    prior_count = getattr(primary, count_attribute, 0)
    if not isinstance(prior_count, int) or prior_count < 0:
        prior_count = 0
    setattr(primary, count_attribute, min(prior_count + 1, sys.maxsize))
    if _claude_exception_group_children(primary):
        primary.__cause__ = None
        primary.__context__ = None
        primary.__suppress_context__ = True
        primary.__traceback__ = None
        primary.__notes__ = [_CLAUDE_TIMEOUT_SEALED_SAFE_NOTE]
    else:
        _sanitize_claude_cleanup_primary_root(
            primary,
            note=_CLAUDE_TIMEOUT_SEALED_SAFE_NOTE,
            recovery_incomplete=True,
        )
    for attribute in (
        "_codex_claude_refresh_lock_cleanup_evidence",
        "_codex_claude_refresh_lock_paths",
    ):
        with contextlib.suppress(AttributeError):
            delattr(primary, attribute)
    _clear_claude_retained_credential_proof(primary)
    with contextlib.suppress(AttributeError):
        delattr(primary, "_codex_claude_retained_credential_carrier")
    if proof is not None:
        _set_claude_retained_credential_proof(primary, proof)
        setattr(
            primary,
            "_codex_claude_retained_credential_carrier",
            str(proof.artifact.parent.parent),
        )
    setattr(
        primary,
        "_codex_claude_retained_cleanup_artifact",
        str(state.fail_closed_root),
    )
    control_flow_count = getattr(
        primary,
        "_codex_claude_timeout_late_control_flow_count",
        0,
    )
    ordinary_count = getattr(
        primary,
        "_codex_claude_timeout_late_ordinary_count",
        0,
    )
    safe_notes = [_CLAUDE_TIMEOUT_SEALED_SAFE_NOTE]
    if isinstance(control_flow_count, int) and control_flow_count > 0:
        safe_notes.append(_CLAUDE_TIMEOUT_LATE_CONTROL_FLOW_NOTE)
    if isinstance(ordinary_count, int) and ordinary_count > 0:
        safe_notes.append(_CLAUDE_TIMEOUT_LATE_ORDINARY_NOTE)
    primary.__notes__ = safe_notes
    setattr(primary, "_codex_claude_cleanup_graph_incomplete", True)
    setattr(primary, "_codex_claude_refresh_persistence_failed", True)
    setattr(
        primary,
        "_codex_claude_keychain_handler_quiescence_unproven",
        True,
    )
    setattr(primary, "_codex_claude_timeout_root_sealed_safe", True)
    setattr(primary, "_codex_claude_timeout_root_state", state)
    state.scope_required = True
    state.proof_revision += 1
    return primary


def _merge_claude_sealed_timeout_failure(
    primary: BaseException,
    secondary: BaseException,
) -> BaseException:
    state = _claude_timeout_root_state(primary)
    if state is None:
        raise AssertionError("Claude sealed timeout root state is unavailable")
    with state.lock:
        return _merge_claude_sealed_timeout_failure_locked(
            primary,
            secondary,
            state,
        )


def _attach_claude_credential_cleanup_failure(
    primary: BaseException,
    secondary: BaseException,
) -> BaseException:
    if _claude_timeout_root_state(primary) is not None:
        return _merge_claude_sealed_timeout_failure(primary, secondary)
    if _claude_timeout_root_state(secondary) is not None:
        return _merge_claude_sealed_timeout_failure(secondary, primary)
    note = "Claude credential operation also had a cleanup failure"
    existing_link: BaseException | None = None
    if isinstance(primary.__cause__, BaseException):
        existing_link = primary.__cause__
    elif not primary.__suppress_context__ and isinstance(
        primary.__context__, BaseException
    ):
        existing_link = primary.__context__
    descriptor_bound, recovery_incomplete = _claude_cleanup_recovery_state(
        primary,
        secondary,
    )
    add_note = getattr(primary, "add_note", None)
    if not descriptor_bound and not recovery_incomplete and callable(add_note):
        add_note(note)
        return primary
    if descriptor_bound:
        note = (
            f"{note}; Claude refresh-lock cleanup is inconclusive; "
            "descriptor-bound lock directories may remain, but no "
            "authoritative pathname is available. Pause and independently "
            "identify the retained directory tree after confirming that no "
            "Claude credential writer is active."
        )
    elif recovery_incomplete:
        note = (
            f"{note}; Claude refresh-lock recovery evidence is incomplete; "
            "helper-owned lock state may remain, but no authoritative "
            "pathname is safe to publish. Pause and independently identify "
            "the retained directory tree after confirming that no Claude "
            "credential writer is active."
        )
    else:
        recovery_paths = getattr(
            primary,
            "_codex_claude_refresh_lock_paths",
            None,
        )
        if (
            isinstance(recovery_paths, tuple)
            and recovery_paths
            and all(isinstance(path, str) and path for path in recovery_paths)
        ):
            note = (
                f"{note}; Claude refresh-lock cleanup is inconclusive; "
                "helper-owned lock paths may remain at "
                f"{', '.join(recovery_paths)}. Pause and confirm that no Claude "
                "credential writer is active before controlled cleanup."
            )
    diagnostic = ClaudeCredentialCleanupDiagnostic(note)
    if descriptor_bound or recovery_incomplete:
        cleanup_wrapper = _claude_sanitized_cleanup_wrapper(
            secondary,
            role="Cleanup exception",
            descriptor_bound=descriptor_bound,
            recovery_incomplete=recovery_incomplete,
        )
        setattr(
            diagnostic,
            "_codex_claude_refresh_lock_descriptor_bound",
            True,
        )
        if recovery_incomplete:
            setattr(
                diagnostic,
                "_codex_claude_cleanup_graph_incomplete",
                True,
            )
        if existing_link is not None:
            cleanup_wrapper.__cause__ = _claude_sanitized_cleanup_wrapper(
                existing_link,
                role="Selected existing exception",
                descriptor_bound=descriptor_bound,
                recovery_incomplete=recovery_incomplete,
            )
        diagnostic.__cause__ = cleanup_wrapper
        if _claude_exception_group_children(primary):
            primary = _safe_claude_cleanup_group_root(
                primary,
                note=note,
                descriptor_bound=descriptor_bound,
                recovery_incomplete=recovery_incomplete,
            )
        else:
            _sanitize_claude_cleanup_primary_root(
                primary,
                note=note,
                recovery_incomplete=recovery_incomplete,
            )
    else:
        stop_before = {id(primary)}
        if existing_link is not None:
            existing_visible, _existing_complete = _claude_visible_error_chain_snapshot(
                existing_link
            )
            stop_before.update(id(error) for error in existing_visible)
        cleanup_detail, cleanup_descriptor_bound = _claude_cleanup_chain_detail(
            secondary,
            stop_before=frozenset(stop_before),
        )
        if cleanup_detail:
            diagnostic.args = (f"{note}; cleanup detail: {cleanup_detail}",)
        if cleanup_descriptor_bound:
            setattr(
                diagnostic,
                "_codex_claude_refresh_lock_descriptor_bound",
                True,
            )
        diagnostic.__cause__ = existing_link
    primary.__cause__ = diagnostic
    return primary


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
        elif not current.__suppress_context__ and isinstance(
            current.__context__, BaseException
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
    sealed = next(
        (
            error
            for error in (primary, *cleanup_errors)
            if error is not None and _claude_timeout_root_state(error) is not None
        ),
        None,
    )
    if sealed is not None:
        for error in (primary, *cleanup_errors):
            if error is None or error is sealed:
                continue
            sealed = _merge_claude_sealed_timeout_failure(sealed, error)
        raise sealed
    cleanup_control_flow = next(
        (error for error in cleanup_errors if _is_claude_control_flow_error(error)),
        None,
    )
    selected_from_cleanup = False
    if primary is not None and _is_claude_control_flow_error(primary):
        selected = primary
    elif cleanup_control_flow is not None:
        selected = cleanup_control_flow
        selected_from_cleanup = True
    elif primary is not None:
        selected = primary
    else:
        selected = ClaudeCredentialInspectionInconclusive(message)
        first_descriptor_bound, first_recovery_incomplete = (
            _claude_cleanup_recovery_state(cleanup_errors[0])
        )
        if not first_descriptor_bound and not first_recovery_incomplete:
            selected.__cause__ = cleanup_errors[0]
    attached_any = False
    for error in (primary, *cleanup_errors):
        if (
            error is None
            or error is selected
            or _claude_visible_error_chain_contains(selected, error)
        ):
            continue
        selected = _attach_claude_credential_cleanup_failure(selected, error)
        attached_any = True
    if selected_from_cleanup and not attached_any:
        descriptor_bound, recovery_incomplete = _claude_cleanup_recovery_state(selected)
        if descriptor_bound or recovery_incomplete:
            if descriptor_bound:
                note = (
                    "Claude credential operation also had a cleanup failure; "
                    "Claude refresh-lock cleanup is inconclusive; descriptor-bound "
                    "lock directories may remain, but no authoritative pathname "
                    "is available. Pause and independently identify the retained "
                    "directory tree after confirming that no Claude credential "
                    "writer is active."
                )
            else:
                note = (
                    "Claude credential operation also had a cleanup failure; "
                    "Claude refresh-lock recovery evidence is incomplete; "
                    "helper-owned lock state may remain, but no authoritative "
                    "pathname is safe to publish. Pause and independently identify "
                    "the retained directory tree after confirming that no Claude "
                    "credential writer is active."
                )
            if _claude_exception_group_children(selected):
                selected = _safe_claude_cleanup_group_root(
                    selected,
                    note=note,
                    descriptor_bound=descriptor_bound,
                    recovery_incomplete=recovery_incomplete,
                )
            else:
                _sanitize_claude_cleanup_primary_root(
                    selected,
                    note=note,
                    recovery_incomplete=recovery_incomplete,
                )
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


class ClaudeTrustEvidenceWriteDiagnostic(Exception):
    """Sanitized fallback for a secondary trust-evidence write failure."""

    def __init__(self, message: str, *, original_suppress_context: bool) -> None:
        super().__init__(message)
        self.original_suppress_context = original_suppress_context


def _attach_claude_trust_evidence_write_failure(primary: BaseException) -> None:
    marker = "_codex_claude_trust_evidence_write_failed"
    if getattr(primary, marker, False):
        return
    setattr(primary, marker, True)
    note = CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        add_note(note)
        return
    diagnostic = ClaudeTrustEvidenceWriteDiagnostic(
        note,
        original_suppress_context=primary.__suppress_context__,
    )
    if primary.__cause__ is not None:
        diagnostic.__cause__ = primary.__cause__
    elif primary.__context__ is not None:
        diagnostic.__context__ = primary.__context__
    primary.__cause__ = diagnostic


def _clear_claude_trust_evidence_write_failure(primary: BaseException) -> None:
    marker = "_codex_claude_trust_evidence_write_failed"
    if hasattr(primary, marker):
        delattr(primary, marker)
    notes = getattr(primary, "__notes__", None)
    if isinstance(notes, list):
        notes[:] = [
            note for note in notes if note != CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC
        ]
    diagnostic = primary.__cause__
    if isinstance(diagnostic, ClaudeTrustEvidenceWriteDiagnostic) and (
        diagnostic.args == (CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC,)
    ):
        primary.__cause__ = diagnostic.__cause__
        primary.__suppress_context__ = diagnostic.original_suppress_context


def _claude_trust_evidence_write_diagnostic(
    error: BaseException,
) -> str | None:
    pending = [error]
    seen: set[int] = set()
    marker_found = False
    while pending and len(seen) < 32:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if getattr(
            current,
            "_codex_claude_trust_evidence_write_failed",
            False,
        ):
            marker_found = True
        notes = getattr(current, "__notes__", ())
        if isinstance(notes, (list, tuple)) and any(
            note == CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC for note in notes
        ):
            return CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC
        if isinstance(current, ClaudeTrustEvidenceWriteDiagnostic) and current.args == (
            CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC,
        ):
            return CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC
        for related in (current.__cause__, current.__context__):
            if isinstance(related, BaseException):
                pending.append(related)
    return CLAUDE_TRUST_EVIDENCE_WRITE_DIAGNOSTIC if marker_found else None


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


def _validate_claude_runtime_directory_descriptor(
    path: pathlib.Path,
    descriptor: int,
    *,
    private: bool,
) -> None:
    try:
        before = path.lstat()
        opened = os.fstat(descriptor)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
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
    if _claude_linux_directory_identity(before) != _claude_linux_directory_identity(
        opened
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude runtime directory changed during validation"
        )
    _require_no_extended_acl(descriptor, label="Claude runtime directory")
    try:
        after = path.lstat()
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"Claude runtime directory changed during validation: {error}"
        ) from error
    if _claude_linux_directory_identity(opened) != _claude_linux_directory_identity(
        after
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude runtime directory changed during validation"
        )


def _require_existing_claude_runtime_directory(
    path: pathlib.Path,
    *,
    private: bool,
) -> pathlib.Path:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ReviewError(
                f"Claude Linux runtime path must be a real directory: {path}"
            ) from error
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open stable Claude runtime directory {path}: {error}"
        ) from error
    try:
        _validate_claude_runtime_directory_descriptor(
            path,
            descriptor,
            private=private,
        )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    else:
        try:
            os.close(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close stable Claude runtime directory {path}: {error}"
            ) from error
    return path


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
    return _require_existing_claude_runtime_directory(path, private=private)


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
    trust_root: tuple[str, ...] = ()


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
    caller_ca_source_snapshot_sha256: tuple[tuple[str, int, str, str], ...] | None = (
        None
    )
    final_ca_bundle_sha256: str | None = None
    proxy_tls_env: dict[str, str] | None = None
    proxy_ssl_context: ssl.SSLContext | None = None
    proxy_tls_snapshot_sha256: tuple[tuple[str, int, str, str], ...] | None = None


class _DuplicatePlistKey(ValueError):
    pass


class _UniquePlistDict(dict[Any, Any]):
    def __setitem__(self, key: Any, value: Any) -> None:
        if key in self:
            raise _DuplicatePlistKey
        super().__setitem__(key, value)


def _bound_metadata_state(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_bound_directory_at(parent_descriptor: int, name: str, *, label: str) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ReviewError(f"cannot securely open bound {label}: {error}") from error
    for metadata in (before, opened, after):
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise ReviewError(f"bound {label} is not a directory")
        if metadata.st_uid != os.geteuid():
            os.close(descriptor)
            raise ReviewError(f"bound {label} has an unexpected owner")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            os.close(descriptor)
            raise ReviewError(f"bound {label} must not be group or other writable")
    if len({_bound_metadata_state(item) for item in (before, opened, after)}) != 1:
        os.close(descriptor)
        raise ReviewError(f"bound {label} changed while opening")
    return descriptor


def _ensure_bound_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
) -> int:
    created = False
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        created = True
    except FileExistsError:
        pass
    except OSError as error:
        raise ReviewError(f"cannot create bound {label}: {error}") from error
    if created:
        try:
            # mkdir mode is masked by the process umask. This name was just
            # created below the already-bound owner-private container, before
            # any reviewer starts; the no-follow open and identity checks
            # immediately below remain authoritative.
            os.chmod(name, 0o700, dir_fd=parent_descriptor)
        except OSError as error:
            raise ReviewError(
                f"cannot protect newly created bound {label}: {error}"
            ) from error
    descriptor = _open_bound_directory_at(
        parent_descriptor,
        name,
        label=label,
    )
    try:
        os.fchmod(descriptor, 0o700)
    except OSError as error:
        os.close(descriptor)
        raise ReviewError(f"cannot protect bound {label}: {error}") from error
    return descriptor


def _open_bound_prompt_at(control_descriptor: int) -> tuple[int, tuple[int, ...]]:
    name = "review.prompt"
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=control_descriptor, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=control_descriptor)
        opened = os.fstat(descriptor)
        after = os.stat(name, dir_fd=control_descriptor, follow_symlinks=False)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ReviewError(
            f"cannot securely open bound review prompt: {error}"
        ) from error
    for metadata in (before, opened, after):
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(descriptor)
            raise ReviewError("bound review prompt is not a regular file with one link")
        if metadata.st_uid != os.geteuid():
            os.close(descriptor)
            raise ReviewError("bound review prompt has an unexpected owner")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            os.close(descriptor)
            raise ReviewError("bound review prompt must not be group or other writable")
    states = {_bound_metadata_state(item) for item in (before, opened, after)}
    if len(states) != 1:
        os.close(descriptor)
        raise ReviewError("bound review prompt changed while opening")
    return descriptor, states.pop()


def _close_launch_descriptor(descriptor: int) -> None:
    os.close(descriptor)


def _directory_descriptor_path(descriptor: int, *, label: str) -> pathlib.Path:
    try:
        if sys.platform == "darwin":
            darwin_fcntl = importlib.import_module("fcntl")
            get_path = getattr(darwin_fcntl, "F_GETPATH")
            raw_path = darwin_fcntl.fcntl(descriptor, get_path, b"\0" * 1024)
            path = pathlib.Path(os.fsdecode(raw_path.split(b"\0", 1)[0]))
        else:
            path = pathlib.Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        opened = os.fstat(descriptor)
        current = path.lstat()
    except (AttributeError, ImportError, OSError) as error:
        raise ReviewError(f"cannot resolve bound {label} path: {error}") from error
    if not path.is_absolute() or not stat.S_ISDIR(current.st_mode):
        raise ReviewError(f"bound {label} path is not an absolute directory")
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise ReviewError(f"bound {label} path changed while resolving")
    return path


@dataclass
class ReviewLaunchBinding:
    container: BoundReviewLock
    workspace_descriptor: int
    attempts_descriptor: int
    prompt_descriptor: int
    prompt_state: tuple[int, ...]
    prompt: bytes | None = None

    @property
    def container_descriptor(self) -> int:
        return self.container.fileno()

    def freeze_prompt(self, expected_path: pathlib.Path | None = None) -> bytes:
        try:
            path_before = expected_path.lstat() if expected_path is not None else None
            os.lseek(self.prompt_descriptor, 0, os.SEEK_SET)
            payload = bytearray()
            while len(payload) <= MAX_REVIEW_PROMPT_BYTES:
                chunk = os.read(
                    self.prompt_descriptor,
                    min(64 * 1024, MAX_REVIEW_PROMPT_BYTES + 1 - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
            final = os.fstat(self.prompt_descriptor)
            path_after = expected_path.lstat() if expected_path is not None else None
        except OSError as error:
            raise ReviewError(f"cannot freeze bound review prompt: {error}") from error
        if len(payload) > MAX_REVIEW_PROMPT_BYTES:
            raise ReviewError(
                f"bound review prompt exceeds the {MAX_REVIEW_PROMPT_BYTES}-byte limit"
            )
        if _bound_metadata_state(final) != self.prompt_state:
            raise ReviewError("bound review prompt changed while freezing")
        if path_before is not None and path_after is not None:
            path_states = {
                _bound_metadata_state(path_before),
                _bound_metadata_state(path_after),
                self.prompt_state,
            }
            if len(path_states) != 1:
                raise ReviewError(
                    "bound review prompt does not match the preflight path"
                )
        self.prompt = bytes(payload)
        return self.prompt

    def require_workspace_path(self, expected: pathlib.Path) -> pathlib.Path:
        before = os.fstat(self.workspace_descriptor)
        actual = _directory_descriptor_path(
            self.workspace_descriptor,
            label="review workspace",
        )
        try:
            expected_metadata = expected.lstat()
            after = os.fstat(self.workspace_descriptor)
        except OSError as error:
            raise ReviewError(
                f"cannot verify bound review workspace path: {error}"
            ) from error
        if actual != expected or not stat.S_ISDIR(expected_metadata.st_mode):
            raise ReviewError("bound review workspace path was replaced")
        identities = {
            (metadata.st_dev, metadata.st_ino)
            for metadata in (before, expected_metadata, after)
        }
        if len(identities) != 1:
            raise ReviewError("bound review workspace path changed during launch")
        return actual

    def open_attempt_file(self, name: str) -> BinaryIO:
        return self._open_attempt_file(name, create=True)

    def open_existing_attempt_file(self, name: str) -> BinaryIO:
        return self._open_attempt_file(name, create=False)

    def _open_attempt_file(self, name: str, *, create: bool) -> BinaryIO:
        if not name or pathlib.PurePath(name).name != name or name in {".", ".."}:
            raise ReviewError("bound attempt log name is invalid")
        flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        descriptor: int | None = None
        created = False
        try:
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=self.attempts_descriptor,
            )
            if create:
                created = True
                os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            current = os.stat(
                name,
                dir_fd=self.attempts_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            if created:
                try:
                    os.unlink(name, dir_fd=self.attempts_descriptor)
                except OSError:
                    pass
            action = "create" if create else "open"
            raise ReviewError(f"cannot {action} bound attempt log: {error}") from error
        for metadata in (opened, current):
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(descriptor)
                raise ReviewError(
                    "bound attempt log is not a regular file with one link"
                )
            if metadata.st_uid != os.geteuid():
                os.close(descriptor)
                raise ReviewError("bound attempt log has an unexpected owner")
            if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                os.close(descriptor)
                raise ReviewError("bound attempt log must be owner-only")
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            os.close(descriptor)
            raise ReviewError("bound attempt log changed while opening")
        return os.fdopen(descriptor, "w+b" if create else "r+b")

    def runtime_review(self, review: ReviewWorkspace) -> ReviewWorkspace:
        container = _directory_descriptor_path(
            self.container_descriptor,
            label="review container",
        )
        workspace = _directory_descriptor_path(
            self.workspace_descriptor,
            label="review workspace",
        )
        try:
            workspace.relative_to(container)
        except ValueError as error:
            raise ReviewError("bound review workspace escaped its container") from error
        if container == review.container_dir and workspace == review.workspace_root:
            return review
        control = workspace / ".codex-review"
        return replace(
            review,
            container_dir=container,
            workspace_root=workspace,
            diff_file=control / "review.diff",
            prompt_file=control / "review.prompt",
        )

    def close(self) -> None:
        first_error: OSError | None = None
        for descriptor in (
            self.prompt_descriptor,
            self.attempts_descriptor,
            self.workspace_descriptor,
        ):
            try:
                os.close(descriptor)
            except OSError as error:
                if first_error is None:
                    first_error = error
        try:
            self.container.close()
        except OSError as error:
            if first_error is None:
                first_error = error
        if first_error is not None:
            raise first_error

    def __enter__(self) -> ReviewLaunchBinding:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _open_review_launch_binding(review: ReviewWorkspace) -> ReviewLaunchBinding:
    container, lock_error = open_bound_review_lock(
        review.container_dir,
        expected=review.private_cleanup,
        name="cleanup.lock",
    )
    if lock_error or container is None:
        raise ReviewError(
            "cannot bind prepared review container"
            + (f": {lock_error}" if lock_error else "")
        )
    workspace_descriptor: int | None = None
    attempts_descriptor: int | None = None
    control_descriptor: int | None = None
    prompt_descriptor: int | None = None
    transferred = False
    try:
        workspace_descriptor = _open_bound_directory_at(
            container.fileno(),
            "workspace",
            label="review workspace",
        )
        attempts_descriptor = _ensure_bound_directory_at(
            container.fileno(),
            "attempts",
            label="review attempts directory",
        )
        control_descriptor = _open_bound_directory_at(
            workspace_descriptor,
            ".codex-review",
            label="review control directory",
        )
        prompt_descriptor, prompt_state = _open_bound_prompt_at(control_descriptor)
        descriptor_to_close = control_descriptor
        control_descriptor = None
        try:
            _close_launch_descriptor(descriptor_to_close)
        except OSError as error:
            raise ReviewError(
                f"cannot close bound review control directory: {error}"
            ) from error
        binding = ReviewLaunchBinding(
            container=container,
            workspace_descriptor=workspace_descriptor,
            attempts_descriptor=attempts_descriptor,
            prompt_descriptor=prompt_descriptor,
            prompt_state=prompt_state,
        )
        workspace_descriptor = None
        attempts_descriptor = None
        prompt_descriptor = None
        transferred = True
        return binding
    finally:
        cleanup_errors: list[OSError] = []
        for descriptor in (
            control_descriptor,
            prompt_descriptor,
            attempts_descriptor,
            workspace_descriptor,
        ):
            if descriptor is None:
                continue
            try:
                _close_launch_descriptor(descriptor)
            except OSError as error:
                cleanup_errors.append(error)
        if not transferred:
            try:
                container.close()
            except OSError as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            cleanup_error = ReviewError(
                "cannot close review launch binding descriptors: "
                + "; ".join(str(error) for error in cleanup_errors)
            )
            active_error = sys.exc_info()[1]
            if active_error is None:
                raise cleanup_error
            add_note = getattr(active_error, "add_note", None)
            if callable(add_note):
                add_note(str(cleanup_error))
            else:  # pragma: no cover - Python 3.10 compatibility
                raise cleanup_error from active_error


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


def _update_claude_sealed_persistence_report(
    review: ReviewWorkspace,
) -> None:
    path = review.container_dir / "claude-runtime.json"
    if not path.exists():
        return
    report = read_json(path)
    authentication = report.get("authentication")
    if not isinstance(authentication, dict):
        authentication = {}
        report["authentication"] = authentication
    for key in (
        "recovery_carrier",
        "recovery_artifact",
        "recovery_cleanup_artifact",
    ):
        authentication.pop(key, None)
    authentication.update(
        {
            "refresh_persistence": "failed-after-attempt",
            "secondary_diagnostic": CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC,
        }
    )
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
            metadata = os.fstat(handle.fileno())
            magic = handle.read(4)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect {label} executable: {error}"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & 0o111
        or magic not in MACHO_MAGICS
    ):
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


def _der_certificate_time(tag: int, value: bytes) -> datetime.datetime:
    if not value.endswith(b"Z"):
        raise ValueError("certificate time is not UTC")
    digits = value[:-1]
    if not digits.isdigit():
        raise ValueError("certificate time is not numeric")
    if tag == 0x17 and len(digits) == 12:
        year = int(digits[:2])
        year += 2000 if year < 50 else 1900
        offset = 2
    elif tag == 0x18 and len(digits) == 14:
        year = int(digits[:4])
        offset = 4
    else:
        raise ValueError("certificate time has an unsupported encoding")
    return datetime.datetime(
        year,
        int(digits[offset : offset + 2]),
        int(digits[offset + 2 : offset + 4]),
        int(digits[offset + 4 : offset + 6]),
        int(digits[offset + 6 : offset + 8]),
        int(digits[offset + 8 : offset + 10]),
        tzinfo=datetime.timezone.utc,
    )


def _canonical_x509_name(name: bytes) -> tuple[tuple[object, ...], bool]:
    string_decoders: dict[int, tuple[str, str]] = {
        0x0C: ("utf-8", "strict"),
        0x13: ("ascii", "strict"),
        0x1C: ("utf-32-be", "strict"),
        0x1E: ("utf-16-be", "strict"),
    }
    name_tag, name_start, name_end, name_next = _der_tlv(name, 0, len(name))
    if name_tag != 0x30 or name_next != len(name):
        raise ValueError("invalid X.509 name")
    complete = True
    rdns: list[tuple[object, ...]] = []
    rdn_offset = name_start
    while rdn_offset < name_end:
        rdn_tag, rdn_start, rdn_end, rdn_offset = _der_tlv(
            name,
            rdn_offset,
            name_end,
        )
        if rdn_tag != 0x31:
            raise ValueError("invalid X.509 relative distinguished name")
        attributes: list[tuple[bytes, object]] = []
        attribute_offset = rdn_start
        while attribute_offset < rdn_end:
            attribute_tag, attribute_start, attribute_end, attribute_offset = _der_tlv(
                name, attribute_offset, rdn_end
            )
            if attribute_tag != 0x30:
                raise ValueError("invalid X.509 name attribute")
            oid_tag, oid_start, oid_end, value_offset = _der_tlv(
                name,
                attribute_start,
                attribute_end,
            )
            if oid_tag != 0x06:
                raise ValueError("invalid X.509 name attribute identifier")
            value_tag, value_start, value_end, value_next = _der_tlv(
                name,
                value_offset,
                attribute_end,
            )
            if value_next != attribute_end:
                raise ValueError("invalid X.509 name attribute value")
            raw_value = name[value_start:value_end]
            decoder = string_decoders.get(value_tag)
            if decoder is None:
                complete = False
                normalized_value: object = (value_tag, raw_value)
            else:
                try:
                    text = raw_value.decode(*decoder)
                except UnicodeError as error:
                    raise ValueError("invalid X.509 name string") from error
                # Full RFC 4518 mapping is intentionally not reimplemented here.
                # Only printable ASCII is complete enough to prove inequality.
                if any(
                    ord(character) < 0x20 or ord(character) > 0x7E for character in text
                ):
                    complete = False
                normalized_value = " ".join(
                    unicodedata.normalize("NFKC", text).casefold().split()
                )
            attributes.append((name[oid_start:oid_end], normalized_value))
        rdns.append(
            tuple(sorted(attributes, key=lambda item: (item[0], repr(item[1]))))
        )
    return tuple(rdns), complete


def _require_unconditional_root_extensions(
    der: bytes,
    *,
    require_critical: bool = True,
    require_self_issued: bool = True,
    require_non_self_issued: bool = False,
) -> None:
    if require_self_issued and require_non_self_issued:
        raise ValueError("certificate cannot require both issuer relationships")
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
        if offset >= tbs_end or der[offset] != 0xA0:
            raise ValueError("certificate does not declare X.509 v3")
        _, version_start, version_end, offset = _der_tlv(der, offset, tbs_end)
        version_tag, value_start, value_end, version_next = _der_tlv(
            der,
            version_start,
            version_end,
        )
        if (
            version_tag != 0x02
            or der[value_start:value_end] != b"\x02"
            or version_next != version_end
        ):
            raise ValueError("certificate does not declare X.509 v3")
        for expected_tag in (0x02, 0x30):
            tag, _, _, offset = _der_tlv(der, offset, tbs_end)
            if tag != expected_tag:
                raise ValueError("invalid TBSCertificate field")

        issuer_offset = offset
        issuer_tag, _, _, offset = _der_tlv(der, offset, tbs_end)
        issuer = der[issuer_offset:offset]
        validity_tag, validity_start, validity_end, offset = _der_tlv(
            der,
            offset,
            tbs_end,
        )
        subject_offset = offset
        subject_tag, _, _, offset = _der_tlv(der, offset, tbs_end)
        subject = der[subject_offset:offset]
        public_key_tag, _, _, offset = _der_tlv(der, offset, tbs_end)
        issuer_name, issuer_name_complete = _canonical_x509_name(issuer)
        subject_name, subject_name_complete = _canonical_x509_name(subject)
        names_semantically_equal = issuer == subject or (
            issuer_name_complete
            and subject_name_complete
            and issuer_name == subject_name
        )
        names_provably_different = (
            issuer_name_complete
            and subject_name_complete
            and issuer_name != subject_name
        )
        if (
            issuer_tag != 0x30
            or validity_tag != 0x30
            or subject_tag != 0x30
            or public_key_tag != 0x30
            or (require_self_issued and not names_semantically_equal)
            or (require_non_self_issued and not names_provably_different)
        ):
            raise ValueError("certificate is not an admissible trust anchor")

        validity_offset = validity_start
        not_before_tag, not_before_start, not_before_end, validity_offset = _der_tlv(
            der,
            validity_offset,
            validity_end,
        )
        not_after_tag, not_after_start, not_after_end, validity_offset = _der_tlv(
            der,
            validity_offset,
            validity_end,
        )
        if validity_offset != validity_end:
            raise ValueError("certificate validity has trailing data")
        not_before = _der_certificate_time(
            not_before_tag,
            der[not_before_start:not_before_end],
        )
        not_after = _der_certificate_time(
            not_after_tag,
            der[not_after_start:not_after_end],
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        if not_before > not_after or not_before > now or now > not_after:
            raise ValueError("certificate is not currently valid")

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


def _consume_sensitive_bounded_capture(
    command: tuple[str, ...],
    *,
    cwd: pathlib.Path,
    deadline: float,
    consume: Callable[[BoundedCapture], _CaptureResult],
) -> _CaptureResult:
    previous_mask = block_forwarded_signals()
    completed: BoundedCapture | None = None
    try:
        completed = run_bounded_capture(
            command,
            cwd=cwd,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            deadline=deadline,
            stdout_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
            stderr_limit_bytes=CLAUDE_KEYCHAIN_BROKER_OUTPUT_LIMIT_BYTES,
        )
        return consume(completed)
    finally:
        if completed is not None:
            completed.zeroize()
        restore_signal_mask(previous_mask)


def _verify_unconditional_trust_root(
    der: bytes,
    canonical: bytes,
    *,
    ca_root: pathlib.Path,
    timeout_seconds: float | None = None,
    deadline: float | None = None,
    allow_non_self_signed: bool = False,
) -> None:
    if (timeout_seconds is None) == (deadline is None):
        raise ValueError("exactly one trust-root timeout form is required")
    if deadline is None:
        assert timeout_seconds is not None
        deadline = time.monotonic() + max(0.0, timeout_seconds)

    def remaining_timeout() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReviewTimeoutError(
                "Claude TLS root verification exceeded its total timeout"
            )
        return remaining

    _require_unconditional_root_extensions(
        der,
        require_self_issued=not allow_non_self_signed,
        require_non_self_issued=allow_non_self_signed,
    )
    try:
        openssl_metadata = CLAUDE_OPENSSL_CLIENT.stat()
    except FileNotFoundError as error:
        raise ClaudeTrustToolUnavailable(
            "Claude TLS root verification tooling is unavailable"
        ) from error
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot inspect Claude TLS root verification tooling"
        ) from error
    if not stat.S_ISREG(openssl_metadata.st_mode) or not (
        openssl_metadata.st_mode & 0o111
    ):
        raise ClaudeTrustToolUnavailable(
            "Claude TLS root verification tooling is unavailable"
        )
    try:
        fd, temporary = tempfile.mkstemp(
            prefix=".trust-root-",
            suffix=".pem",
            dir=ca_root,
        )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot prepare Claude trust verification input"
        ) from error
    certificate_path = pathlib.Path(temporary)
    try:
        try:
            os.fchmod(fd, 0o600)
            _require_no_extended_acl(fd, label="Claude trust verification input")
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(canonical)
                handle.flush()
                os.fsync(handle.fileno())
        except ReviewError:
            raise
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot prepare Claude trust verification input"
            ) from error

        try:
            use_partial_chain = False
            if allow_non_self_signed:
                remaining_timeout()

                def inspect_capabilities(capabilities: BoundedCapture) -> bool:
                    remaining_timeout()
                    if capabilities.returncode not in (0, 1):
                        raise ClaudeExecutableInspectionInconclusive(
                            "Claude TLS root verification capability probe was "
                            "inconclusive"
                        )

                    def contains(value: bytes) -> bool:
                        return (
                            value in capabilities.stdout or value in capabilities.stderr
                        )

                    if not contains(b"-trusted") or not contains(b"-x509_strict"):
                        raise ClaudeTrustToolUnavailable(
                            "Claude TLS root verification tooling lacks required "
                            "capabilities"
                        )
                    return contains(b"-partial_chain")

                use_partial_chain = _consume_sensitive_bounded_capture(
                    (str(CLAUDE_OPENSSL_CLIENT), "verify", "-help"),
                    cwd=ca_root,
                    deadline=deadline,
                    consume=inspect_capabilities,
                )

            if allow_non_self_signed and not use_partial_chain:
                verification_command = (
                    str(CLAUDE_OPENSSL_CLIENT),
                    "x509",
                    "-in",
                    certificate_path.name,
                    "-pubkey",
                    "-noout",
                )
                invalid_returncode: int | None = None
            else:
                verification_mode = (
                    ("-partial_chain",) if allow_non_self_signed else ("-check_ss_sig",)
                )
                verification_command = (
                    str(CLAUDE_OPENSSL_CLIENT),
                    "verify",
                    "-x509_strict",
                    *verification_mode,
                    "-purpose",
                    "any",
                    "-trusted",
                    certificate_path.name,
                    certificate_path.name,
                )
                invalid_returncode = 2
            remaining_timeout()

            def validate_verification(completed: BoundedCapture) -> None:
                remaining_timeout()
                public_key_invalid = (
                    allow_non_self_signed
                    and not use_partial_chain
                    and b"-----BEGIN PUBLIC KEY-----" not in completed.stdout
                )
                if (
                    invalid_returncode is not None
                    and completed.returncode == invalid_returncode
                ):
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
                    raise ClaudeExecutableInspectionInconclusive(
                        "Claude TLS root verification failed inconclusively"
                    )
                if public_key_invalid:
                    raise ClaudeTrustCertificateInvalid(
                        "Claude trust settings reference a certificate that is not a "
                        "currently valid CA trust anchor"
                    )

            _consume_sensitive_bounded_capture(
                verification_command,
                cwd=ca_root,
                deadline=deadline,
                consume=validate_verification,
            )
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude TLS root verification launch was inconclusive"
            ) from error
    finally:
        active_error = sys.exc_info()[0] is not None
        cleanup_error: OSError | None = None
        if fd >= 0:
            try:
                os.close(fd)
            except OSError as error:
                cleanup_error = error
        try:
            certificate_path.unlink(missing_ok=True)
        except OSError as error:
            cleanup_error = cleanup_error or error
        if cleanup_error is not None and not active_error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot clean up Claude trust verification input"
            ) from cleanup_error


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


def _write_private_verification_file(
    path: pathlib.Path,
    data: bytes | bytearray,
) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot create Claude bundled root verification input"
        ) from error
    published = False
    try:
        _require_no_extended_acl(
            descriptor,
            label="Claude bundled root verification input",
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        published = True
    except ReviewError:
        raise
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot write Claude bundled root verification input"
        ) from error
    finally:
        active_error = sys.exc_info()[0] is not None
        cleanup_error: OSError | None = None
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_error = error
        if not published:
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None and not active_error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot clean up Claude bundled root verification input"
            ) from cleanup_error


def _require_bundled_root_deadline(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReviewTimeoutError(
            "Claude bundled root verification exceeded its total timeout"
        )
    return remaining


def _run_with_bundled_root_deadline(
    deadline: float,
    operation: Callable[[], Any],
) -> Any:
    _require_bundled_root_deadline(deadline)
    try:
        result = operation()
    except (ForwardedSignal, ReviewTimeoutError):
        raise
    except Exception:
        _require_bundled_root_deadline(deadline)
        raise
    _require_bundled_root_deadline(deadline)
    return result


def _zeroize_bounded_capture(completed: BoundedCapture) -> None:
    completed.zeroize()


def _run_bundled_root_openssl(
    command: tuple[str, ...],
    *,
    verification_root: pathlib.Path,
    deadline: float,
    consume: Callable[[BoundedCapture], _CaptureResult],
) -> _CaptureResult:
    try:
        _require_bundled_root_deadline(deadline)
        return _consume_sensitive_bounded_capture(
            command,
            cwd=verification_root,
            deadline=deadline,
            consume=lambda completed: _run_with_bundled_root_deadline(
                deadline,
                lambda: consume(completed),
            ),
        )
    except (ForwardedSignal, ReviewTimeoutError):
        raise
    except FileNotFoundError as error:
        _require_bundled_root_deadline(deadline)
        raise ClaudeExecutableInspectionInconclusive(
            "Claude bundled root verification tooling changed before launch"
        ) from error
    except OSError as error:
        _require_bundled_root_deadline(deadline)
        raise ClaudeExecutableInspectionInconclusive(
            "Claude bundled root verification tooling could not be launched"
        ) from error
    except Exception:
        _require_bundled_root_deadline(deadline)
        raise


def _require_bundled_root_self_signature(
    der: bytes,
    canonical: bytes,
    *,
    verification_root: pathlib.Path,
    index: int,
    deadline: float,
) -> None:
    try:
        metadata = _run_with_bundled_root_deadline(
            deadline,
            CLAUDE_OPENSSL_CLIENT.lstat,
        )
    except FileNotFoundError as error:
        raise ClaudeTrustToolUnavailable(
            "Claude bundled root verification tooling is unavailable"
        ) from error
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot inspect Claude bundled root verification tooling"
        ) from error
    openssl_accessible = _run_with_bundled_root_deadline(
        deadline,
        lambda: os.access(CLAUDE_OPENSSL_CLIENT, os.X_OK),
    )
    unsafe_metadata = _run_with_bundled_root_deadline(
        deadline,
        lambda: (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o6022
            or not openssl_accessible
        ),
    )
    if unsafe_metadata:
        raise ClaudeTrustPolicyUnavailable(
            "Claude bundled root verification tooling has unsafe metadata"
        )
    tbs, signature, digest = _run_with_bundled_root_deadline(
        deadline,
        lambda: _certificate_self_signature_evidence(der),
    )
    prefix = f"root-{index:04d}"
    certificate_path = verification_root / f"{prefix}.pem"
    tbs_path = verification_root / f"{prefix}.tbs"
    signature_path = verification_root / f"{prefix}.sig"
    public_key_path = verification_root / f"{prefix}.pub"
    for path, payload in (
        (certificate_path, canonical),
        (tbs_path, tbs),
        (signature_path, signature),
    ):
        _run_with_bundled_root_deadline(
            deadline,
            lambda path=path, payload=payload: _write_private_verification_file(
                path,
                payload,
            ),
        )

    def validate_and_write_public_key(public_key: BoundedCapture) -> None:
        def validate_and_write() -> None:
            if (
                public_key.returncode != 0
                or b"-----BEGIN PUBLIC KEY-----" not in public_key.stdout
                or b"PRIVATE KEY" in public_key.stdout
            ):
                raise ClaudeTrustCertificateInvalid(
                    "Claude executable bundled root has an invalid public key"
                )
            _write_private_verification_file(public_key_path, public_key.stdout)

        _run_with_bundled_root_deadline(deadline, validate_and_write)

    _run_bundled_root_openssl(
        (
            str(CLAUDE_OPENSSL_CLIENT),
            "x509",
            "-in",
            certificate_path.name,
            "-pubkey",
            "-noout",
        ),
        verification_root=verification_root,
        deadline=deadline,
        consume=validate_and_write_public_key,
    )
    _require_bundled_root_deadline(deadline)

    def validate_self_signature(verified: BoundedCapture) -> None:
        def validate() -> None:
            if verified.returncode == 1:
                raise ClaudeTrustCertificateInvalid(
                    "Claude executable bundled root is not self-signed"
                )
            if verified.returncode != 0:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude bundled root verification tooling failed unexpectedly"
                )

        _run_with_bundled_root_deadline(deadline, validate)

    _run_bundled_root_openssl(
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
        verification_root=verification_root,
        deadline=deadline,
        consume=validate_self_signature,
    )
    _require_bundled_root_deadline(deadline)


def _validated_bundled_root_certificates(
    data: bytes,
    *,
    executable: pathlib.Path,
    verify_self_signatures: bool = True,
) -> dict[bytes, bytes]:
    deadline = time.monotonic() + CLAUDE_TRUST_ROOT_VERIFY_TOTAL_SECONDS
    try:
        blocks = CLAUDE_CERTIFICATE_BLOCK.findall(data)
        _require_bundled_root_deadline(deadline)
        if not blocks or len(blocks) > CLAUDE_BUNDLED_ROOT_LIMIT:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude executable bundled root store has an invalid certificate count"
            )
        certificates: dict[bytes, bytes] = {}
        verification_directory = _run_with_bundled_root_deadline(
            deadline,
            lambda: (
                _bundled_root_verification_directory(executable)
                if verify_self_signatures
                else contextlib.nullcontext(None)
            ),
        )
        with verification_directory as verification_root:
            _require_bundled_root_deadline(deadline)
            for index, block in enumerate(blocks):
                der, canonical = _run_with_bundled_root_deadline(
                    deadline,
                    lambda block=block: _canonical_ca_certificate(
                        block,
                        source="publisher-verified Claude bundled root store",
                    ),
                )
                _run_with_bundled_root_deadline(
                    deadline,
                    lambda: _require_unconditional_root_extensions(
                        der,
                        require_critical=False,
                    ),
                )
                if verify_self_signatures:
                    assert verification_root is not None
                    _run_with_bundled_root_deadline(
                        deadline,
                        lambda: _require_bundled_root_self_signature(
                            der,
                            canonical,
                            verification_root=verification_root,
                            index=index,
                            deadline=deadline,
                        ),
                    )
                fingerprint = _run_with_bundled_root_deadline(
                    deadline,
                    lambda: hashlib.sha256(der).digest(),
                )
                existing = _run_with_bundled_root_deadline(
                    deadline,
                    lambda: certificates.get(fingerprint),
                )
                collision = _run_with_bundled_root_deadline(
                    deadline,
                    lambda: existing is not None and existing != canonical,
                )
                if collision:
                    raise ClaudeExecutableInspectionInconclusive(
                        "Claude executable bundled roots contain a fingerprint collision"
                    )
                _run_with_bundled_root_deadline(
                    deadline,
                    lambda: certificates.__setitem__(fingerprint, canonical),
                )
            _require_bundled_root_deadline(deadline)
        _require_bundled_root_deadline(deadline)
    except (ForwardedSignal, ReviewTimeoutError):
        raise
    except Exception:
        _require_bundled_root_deadline(deadline)
        raise
    _require_bundled_root_deadline(deadline)
    return certificates


@contextlib.contextmanager
def _bundled_root_verification_directory(
    executable: pathlib.Path,
) -> Iterator[pathlib.Path]:
    try:
        directory = tempfile.TemporaryDirectory(
            prefix=".claude-bundled-roots-",
            dir=executable.parent,
        )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot create Claude bundled root verification directory"
        ) from error
    try:
        verification_root = pathlib.Path(directory.__enter__())
    except OSError as error:
        active_error = sys.exc_info()
        try:
            directory.__exit__(*active_error)
        except (ForwardedSignal, KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            pass
        raise ClaudeExecutableInspectionInconclusive(
            "cannot enter Claude bundled root verification directory"
        ) from error
    try:
        yield verification_root
    except BaseException:
        active_error = sys.exc_info()
        try:
            directory.__exit__(*active_error)
        except (ForwardedSignal, KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            pass
        raise
    else:
        try:
            directory.__exit__(None, None, None)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot clean up Claude bundled root verification directory"
            ) from error


@contextlib.contextmanager
def _open_private_claude_snapshot_parent(
    path: pathlib.Path,
    *,
    container_dir: pathlib.Path,
) -> Iterator[int]:
    container = container_dir.expanduser().absolute()
    executable = path.expanduser().absolute()
    if container != pathlib.Path(
        os.path.normpath(container)
    ) or executable != pathlib.Path(os.path.normpath(executable)):
        raise ReviewError(
            "Claude executable snapshot paths must be lexically normalized"
        )
    review_root = container.parent
    try:
        relative_parent = executable.parent.relative_to(container)
    except ValueError as error:
        raise ReviewError(
            "Claude executable snapshot is outside the private review container"
        ) from error
    if len(relative_parent.parts) > 8:
        raise ReviewError(
            "Claude executable snapshot directory chain exceeds its depth limit"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    try:
        try:
            review_root_descriptor = os.open(review_root, flags)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ReviewError(
                    "Claude executable snapshot review root must be a real directory"
                ) from error
            raise ClaudeExecutableInspectionInconclusive(
                "cannot open the Claude review root for snapshot validation"
            ) from error
        descriptors.append(review_root_descriptor)
        try:
            _validate_claude_runtime_directory_descriptor(
                review_root,
                review_root_descriptor,
                private=False,
            )
            container_descriptor = os.open(
                container.name,
                flags,
                dir_fd=review_root_descriptor,
            )
            descriptors.append(container_descriptor)
            _validate_claude_runtime_directory_descriptor(
                container,
                container_descriptor,
                private=True,
            )
            current = container
            for component in relative_parent.parts:
                descriptor = os.open(component, flags, dir_fd=descriptors[-1])
                descriptors.append(descriptor)
                current /= component
                _validate_claude_runtime_directory_descriptor(
                    current,
                    descriptor,
                    private=True,
                )
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ReviewError(
                    "Claude executable snapshot path must use real directories"
                ) from error
            raise ClaudeExecutableInspectionInconclusive(
                "cannot inspect the Claude executable snapshot directory chain"
            ) from error
        yield descriptors[-1]
    except BaseException:
        for descriptor in reversed(descriptors):
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise
    else:
        close_error: OSError | None = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                close_error = close_error or error
        if close_error is not None:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot close the Claude snapshot directory chain"
            ) from close_error


def _inspect_claude_executable_trust(
    path: pathlib.Path,
    *,
    container_dir: pathlib.Path,
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

    with _open_private_claude_snapshot_parent(
        path,
        container_dir=container_dir,
    ) as parent_descriptor:
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ReviewError(
                    "Claude executable snapshot must be a real file"
                ) from error
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot open Claude executable snapshot: {error}"
            ) from error
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
                raise ReviewError("Claude executable snapshot has unsafe file metadata")
            _require_no_extended_acl(
                descriptor,
                label="Claude executable snapshot",
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
            path_after = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot inspect Claude executable snapshot: {error}"
            ) from error
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            raise
        else:
            try:
                os.close(descriptor)
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    f"cannot close Claude executable snapshot: {error}"
                ) from error
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
    *,
    container_dir: pathlib.Path,
) -> None:
    current = _inspect_claude_executable_trust(
        executable,
        container_dir=container_dir,
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


def _require_claude_keychain_executable(
    path: pathlib.Path,
    *,
    requirement: str,
) -> None:
    try:
        metadata = path.stat()
    except FileNotFoundError as error:
        raise ClaudeKeychainBrokerUnavailable(requirement) from error
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect required Claude Keychain executable {path}: {error}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise ClaudeKeychainBrokerUnavailable(requirement)
    try:
        executable = os.access(path, os.X_OK)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot check required Claude Keychain executable {path}: {error}"
        ) from error
    if not executable:
        raise ClaudeExecutableInspectionInconclusive(
            f"required Claude Keychain executable is not accessible: {path}"
        )


def _claude_keychain_identity_directory_name() -> str:
    try:
        token = os.urandom(16)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot allocate a Claude Keychain broker directory identity"
        ) from error
    if len(token) != 16:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude Keychain broker directory identity is incomplete"
        )
    return CLAUDE_KEYCHAIN_BROKER_DIRECTORY_PREFIX + token.hex()


@contextlib.contextmanager
def _open_or_create_claude_keychain_identity_directory(
    review: ReviewWorkspace,
) -> Iterator[tuple[pathlib.Path, int]]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude Keychain broker preparation requires O_NOFOLLOW"
        )
    container = review.container_dir.expanduser().absolute()
    if container != pathlib.Path(os.path.normpath(container)):
        raise ReviewError("Claude Keychain broker container path is not normalized")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | nofollow
    ancestors = contextlib.ExitStack()
    try:
        container_descriptor, _ancestor_identities = ancestors.enter_context(
            _open_absolute_directory_chain_without_symlinks(container)
        )
    except OSError as error:
        ancestors.close()
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ReviewError(
                "Claude Keychain broker container path must use real directories"
            ) from error
        raise ClaudeExecutableInspectionInconclusive(
            "cannot inspect the Claude Keychain broker container path"
        ) from error
    with ancestors:
        _validate_claude_runtime_directory_descriptor(
            container,
            container_descriptor,
            private=True,
        )
        descriptors: list[int] = []
        current = container
        try:
            try:
                os.mkdir("claude-runtime", 0o700, dir_fd=container_descriptor)
            except FileExistsError:
                pass
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    f"cannot create the Claude Keychain runtime directory: {error}"
                ) from error
            try:
                runtime_descriptor = os.open(
                    "claude-runtime",
                    flags,
                    dir_fd=container_descriptor,
                )
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ReviewError(
                        "Claude Keychain broker path must use real directories"
                    ) from error
                raise ClaudeExecutableInspectionInconclusive(
                    "cannot open the Claude Keychain runtime directory"
                ) from error
            descriptors.append(runtime_descriptor)
            current /= "claude-runtime"
            _validate_claude_runtime_directory_descriptor(
                current,
                runtime_descriptor,
                private=True,
            )
            broker_name: str | None = None
            for _attempt in range(CLAUDE_KEYCHAIN_BROKER_DIRECTORY_ATTEMPTS):
                candidate = _claude_keychain_identity_directory_name()
                try:
                    os.mkdir(candidate, 0o700, dir_fd=runtime_descriptor)
                except FileExistsError:
                    continue
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        f"cannot create the Claude Keychain broker directory: {error}"
                    ) from error
                broker_name = candidate
                break
            if broker_name is None:
                raise ClaudeExecutableInspectionInconclusive(
                    "cannot allocate a unique Claude Keychain broker directory"
                )
            try:
                broker_descriptor = os.open(
                    broker_name,
                    flags,
                    dir_fd=runtime_descriptor,
                )
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ReviewError(
                        "Claude Keychain broker path must use real directories"
                    ) from error
                raise ClaudeExecutableInspectionInconclusive(
                    "cannot open the Claude Keychain broker directory"
                ) from error
            descriptors.append(broker_descriptor)
            current /= broker_name
            _validate_claude_runtime_directory_descriptor(
                current,
                broker_descriptor,
                private=True,
            )
            yield current, broker_descriptor
        except BaseException:
            for descriptor in reversed(descriptors):
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise
        else:
            close_error: OSError | None = None
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError as error:
                    close_error = close_error or error
            if close_error is not None:
                raise ClaudeExecutableInspectionInconclusive(
                    "cannot close the Claude Keychain broker directory chain"
                ) from close_error


def _read_verified_claude_keychain_broker(
    path: pathlib.Path,
    *,
    require_root_owned: bool = False,
) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude Keychain broker verification requires O_NOFOLLOW"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise ClaudeKeychainBrokerUnavailable(
            "Claude Keychain broker is not installed"
        ) from error
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ReviewError("Claude Keychain broker must be a real file") from error
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open the Claude Keychain broker artifact: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if require_root_owned:
            metadata_safe = (
                before.st_uid == 0
                and before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o555
            )
        else:
            metadata_safe = (
                before.st_uid in {0, os.geteuid()}
                and not stat.S_IMODE(before.st_mode) & 0o022
            )
        if (
            not stat.S_ISREG(before.st_mode)
            or not metadata_safe
            or before.st_nlink != 1
            or not 0 < before.st_size <= CLAUDE_KEYCHAIN_BROKER_ARTIFACT_LIMIT_BYTES
        ):
            raise ReviewError("Claude Keychain broker artifact has unsafe metadata")
        _require_no_extended_acl(
            descriptor,
            label="Claude Keychain broker artifact",
        )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude Keychain broker artifact was truncated while read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ClaudeExecutableInspectionInconclusive(
                "Claude Keychain broker artifact grew while read"
            )
        after = os.fstat(descriptor)
        dirent = os.stat(path, follow_symlinks=False)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or dirent.st_dev != before.st_dev
            or dirent.st_ino != before.st_ino
            or not stat.S_ISREG(dirent.st_mode)
        ):
            raise ClaudeExecutableInspectionInconclusive(
                "Claude Keychain broker artifact changed while verified"
            )
        payload = b"".join(chunks)
        if (
            hashlib.sha256(payload).hexdigest()
            != CLAUDE_KEYCHAIN_BROKER_ARTIFACT_SHA256
        ):
            raise ReviewError("Claude Keychain broker artifact digest is invalid")
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    else:
        try:
            os.close(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot close the Claude Keychain broker artifact"
            ) from error
    return payload


def _validate_root_owned_claude_keychain_broker_directory(
    path: pathlib.Path,
    descriptor: int,
) -> None:
    try:
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect installed Claude Keychain broker ancestor {path}"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReviewError(
            "installed Claude Keychain broker ancestors must be root-owned and "
            "not group- or world-writable"
        )
    _require_no_extended_acl(
        descriptor,
        label=f"installed Claude Keychain broker ancestor {path}",
    )


def _require_installed_claude_keychain_broker() -> None:
    broker = CLAUDE_KEYCHAIN_BROKER_INSTALL_PATH
    try:
        with _open_absolute_directory_chain_without_symlinks(
            broker.parent,
            descriptor_validator=(
                _validate_root_owned_claude_keychain_broker_directory
            ),
        ):
            _read_verified_claude_keychain_broker(
                broker,
                require_root_owned=True,
            )
            _native_macho_dependencies(
                broker,
                label="installed Claude Keychain broker",
            )
    except FileNotFoundError as error:
        raise ClaudeKeychainBrokerUnavailable(
            "Claude Keychain broker is not installed"
        ) from error
    except ClaudeCredentialUnsafe as error:
        raise ReviewError(
            "installed Claude Keychain broker path must not contain symlinks"
        ) from error


def _darwin_volume_inode_path(metadata: os.stat_result) -> pathlib.Path:
    if sys.platform != "darwin":
        raise ClaudeExecutableInspectionInconclusive(
            "Claude Keychain broker volume identities require macOS"
        )
    result = pathlib.Path("/.vol") / str(metadata.st_dev) / str(metadata.st_ino)
    try:
        resolved = os.stat(result, follow_symlinks=False)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot resolve the Claude Keychain broker volume identity"
        ) from error
    if (resolved.st_dev, resolved.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude Keychain broker volume identity does not match its directory"
        )
    return result


def _claude_macos_descriptor_path(descriptor: int) -> pathlib.Path:
    try:
        darwin_fcntl = importlib.import_module("fcntl")
        getpath = darwin_fcntl.F_GETPATH
        raw = darwin_fcntl.fcntl(
            descriptor,
            getpath,
            b"\x00" * CLAUDE_MACOS_PATH_BUFFER_BYTES,
        )
    except (AttributeError, ImportError, OSError) as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot resolve the Claude Keychain broker identity directory"
        ) from error
    if not isinstance(raw, bytes):
        raise ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker identity directory resolution is invalid"
        )
    encoded = raw.split(b"\x00", 1)[0]
    if not encoded:
        raise ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker identity directory resolution is empty"
        )
    path = pathlib.Path(os.fsdecode(encoded))
    if not path.is_absolute():
        raise ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker identity directory resolution is not absolute"
        )
    return path


def _require_claude_keychain_identity_directory(path: pathlib.Path) -> pathlib.Path:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_descriptor = os.open(path, flags)
    except OSError as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot inspect the Claude Keychain broker identity directory"
        ) from error
    try:
        _validate_claude_runtime_directory_descriptor(
            path,
            directory_descriptor,
            private=True,
        )
        canonical_path = _claude_macos_descriptor_path(directory_descriptor)
        descriptor_metadata = os.fstat(directory_descriptor)
        canonical_metadata = os.stat(canonical_path, follow_symlinks=False)
        if (
            canonical_metadata.st_dev,
            canonical_metadata.st_ino,
        ) != (
            descriptor_metadata.st_dev,
            descriptor_metadata.st_ino,
        ) or not stat.S_ISDIR(canonical_metadata.st_mode):
            raise ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker identity directory changed while resolved"
            )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(directory_descriptor)
        raise
    else:
        try:
            os.close(directory_descriptor)
        except OSError as error:
            raise ClaudeCredentialInspectionInconclusive(
                "cannot close the Claude Keychain broker identity directory"
            ) from error
    return canonical_path


def _require_claude_keychain_identity_socket(path: pathlib.Path) -> pathlib.Path:
    canonical_directory = _require_claude_keychain_identity_directory(path.parent)
    canonical_path = canonical_directory / path.name
    try:
        metadata = os.stat(path, follow_symlinks=False)
        canonical_metadata = os.stat(canonical_path, follow_symlinks=False)
    except OSError as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot inspect the Claude Keychain broker identity socket"
        ) from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not stat.S_ISSOCK(canonical_metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (canonical_metadata.st_dev, canonical_metadata.st_ino)
    ):
        raise ReviewError(
            "Claude local-login sandbox requires a valid Keychain broker "
            "identity socket"
        )
    return canonical_path


def _allocate_claude_keychain_identity_directory(
    review: ReviewWorkspace,
) -> pathlib.Path:
    with _open_or_create_claude_keychain_identity_directory(review) as (
        identity_dir,
        identity_directory_descriptor,
    ):
        _validate_claude_runtime_directory_descriptor(
            identity_dir,
            identity_directory_descriptor,
            private=True,
        )
        identity_directory_metadata = os.fstat(identity_directory_descriptor)
        return _darwin_volume_inode_path(identity_directory_metadata)


def _prepare_claude_keychain_broker(
    review: ReviewWorkspace,
    env: dict[str, str],
) -> dict[str, str]:
    result = dict(env)
    if _claude_uses_explicit_auth(result):
        return result
    _require_claude_keychain_executable(
        CLAUDE_KEYCHAIN_CLIENT,
        requirement="Claude local-login review requires /usr/bin/security",
    )
    home_raw = result.get("HOME")
    if not home_raw:
        raise ReviewError("Claude Keychain broker requires an isolated HOME")
    home = pathlib.Path(home_raw).resolve()
    if not is_relative_to(home, review.container_dir.resolve()):
        raise ReviewError("Claude Keychain broker requires a helper-owned HOME")
    _require_installed_claude_keychain_broker()
    result["USER"] = _claude_keychain_account()
    result[CLAUDE_KEYCHAIN_BROKER_EXECUTABLE_ENV] = str(
        CLAUDE_KEYCHAIN_BROKER_INSTALL_PATH
    )
    result.pop(CLAUDE_KEYCHAIN_BROKER_IDENTITY_DIRECTORY_ENV, None)
    result.pop(CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET_ENV, None)
    result.pop(CLAUDE_KEYCHAIN_BROKER_PORT_ENV, None)
    result["PATH"] = os.pathsep.join(
        value
        for value in (
            str(CLAUDE_KEYCHAIN_BROKER_INSTALL_PATH.parent),
            result.get("PATH"),
        )
        if value
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
    *,
    descriptor_validator: Callable[[pathlib.Path, int], None] | None = None,
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
        identities.append(_claude_linux_directory_identity(os.fstat(root_descriptor)))
        if descriptor_validator is not None:
            descriptor_validator(pathlib.Path("/"), root_descriptor)
        current = pathlib.Path("/")
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
                _claude_linux_directory_identity(before_metadata) != opened_identity
                or after_identity != opened_identity
            ):
                raise ClaudeCredentialInspectionInconclusive(
                    "a retained Claude artifact ancestor changed while opened"
                )
            identities.append(opened_identity)
            current /= component
            if descriptor_validator is not None:
                descriptor_validator(current, next_descriptor)
        yield descriptors[-1], tuple(identities)
        if _claude_linux_directory_identity(os.fstat(descriptors[0])) != identities[0]:
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
        if pending_descriptor is not None and pending_descriptor not in descriptors:
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
        home_descriptor: int | None = _open_absolute_directory_without_symlinks(home)
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
        if (
            metadata.st_size <= 0
            or metadata.st_size > CLAUDE_KEYCHAIN_CREDENTIAL_LIMIT_BYTES
        ):
            raise ClaudeCredentialUnsafe(
                "the Claude credential file has an invalid bounded size"
            )
        initial_identity = _claude_credential_file_identity(metadata)
        if expected_identity is not None and initial_identity != expected_identity:
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
            or initial_identity != _claude_credential_file_identity(final_metadata)
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
    *,
    account: str | None = None,
) -> bytearray | None:
    client = CLAUDE_KEYCHAIN_CLIENT
    if not client.is_file() or not os.access(client, os.X_OK):
        raise ClaudeCredentialInspectionInconclusive(
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
        raise ClaudeCredentialInspectionInconclusive(
            f"Claude Keychain query failed: {error}"
        ) from error
    try:
        if completed.returncode == CLAUDE_KEYCHAIN_ITEM_NOT_FOUND_STATUS:
            return None
        if completed.returncode != 0:
            raise ClaudeCredentialInspectionInconclusive(
                "Claude Keychain query failed without a deterministic missing-item "
                "status"
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
        payload = strict_json_loads(credential)
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
        payload = strict_json_loads(credential)
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
        f'add-generic-password -U -a "{account}" -s "{CLAUDE_KEYCHAIN_SERVICE}" -X "'
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
            and not _claude_keychain_credential_has_refresh_margin(selected.payload)
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
    descriptor: int | None = None
    created = False
    try:
        try:
            descriptor = os.open(path, flags | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            descriptor = os.open(path, flags & ~os.O_CREAT)
        if created:
            os.fchmod(descriptor, 0o600)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise ClaudeCredentialInspectionInconclusive(
            "cannot open the Claude credential update lock safely"
        ) from error
    assert descriptor is not None
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
                        f"cannot coordinate Claude Keychain refresh writeback: {error}"
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
    temporary_name = f".{CLAUDE_CREDENTIAL_FILE_NAME}.codex-{secrets.token_hex(16)}.tmp"
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
                            _sync_claude_credential_descriptor(temporary_descriptor)
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


def _claude_macos_refresh_lock_coordination_failure(
    error: ClaudeRefreshLockError,
) -> ClaudeCredentialInspectionInconclusive:
    if isinstance(error, ClaudeRefreshLockStale):
        return ClaudeCredentialStaleRefreshLock(
            "a stale Claude refresh lock requires controlled cleanup after "
            "confirming that no Claude credential writer is active"
        )
    return ClaudeCredentialInspectionInconclusive(
        f"cannot coordinate Claude credential refresh writeback: {error}"
    )


@contextlib.contextmanager
def _claude_macos_carrier_coordination(
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    *,
    require_explicit_context_release: bool = False,
) -> Iterator[ClaudeRefreshLockLease]:
    try:
        with _claude_credential_update_lock("keychain"):
            with _claude_credential_update_lock("credential-file"):
                signal_mask_owner = _ClaudeSignalMaskOwner()
                first_restore_error: BaseException | None = None
                coordination_error: BaseException | None = None
                try:
                    refresh_lock_start_mask = block_forwarded_signals(
                        signal_mask_owner=signal_mask_owner,
                    )
                    if not signal_mask_owner.owns_previous_signal_mask(
                        refresh_lock_start_mask
                    ):
                        signal_mask_owner.publish_previous_signal_mask(
                            refresh_lock_start_mask
                        )
                    refresh_lock_context = (
                        claude_refresh_lock_release_on_success(
                            _claude_refresh_lock_config_directory(),
                            protocol=refresh_lock_protocol,
                        )
                        if require_explicit_context_release
                        else claude_refresh_lock(
                            _claude_refresh_lock_config_directory(),
                            protocol=refresh_lock_protocol,
                        )
                    )
                    with refresh_lock_context as coordinated_refresh_lock:
                        try:
                            signal_mask_owner.restore_previous_signal_mask()
                        except BaseException as restore_error:
                            first_restore_error = restore_error
                            raise
                        yield coordinated_refresh_lock
                except BaseException as error:
                    coordination_error = error
                    raise
                finally:
                    if first_restore_error is None:
                        restore_error = _restore_claude_signal_mask_owner_bounded(
                            signal_mask_owner
                        )
                        if restore_error is not None:
                            selected_error = _select_claude_thread_start_related_error(
                                coordination_error,
                                restore_error,
                            )
                            assert selected_error is not None
                            raise selected_error
                    else:
                        try:
                            signal_mask_owner.restore_previous_signal_mask()
                        except BaseException as retry_error:
                            selected_error = _select_claude_thread_start_related_error(
                                first_restore_error,
                                retry_error,
                            )
                            if (
                                coordination_error is not None
                                and coordination_error is not selected_error
                            ):
                                selected_error = (
                                    _select_claude_thread_start_related_error(
                                        coordination_error,
                                        selected_error,
                                    )
                                )
                            assert selected_error is not None
                            if selected_error is retry_error:
                                raise
                            raise selected_error
    except ClaudeRefreshLockError as error:
        raise _claude_macos_refresh_lock_coordination_failure(error) from error


def _persist_claude_macos_refreshed_credential(
    review: ReviewWorkspace,
    selected: _ClaudeLocalCredential,
    refreshed: bytearray,
    expected_credential: bytearray,
    carrier_snapshot: _ClaudeMacOSCarrierSnapshot,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    *,
    coordinated_refresh_lock: ClaudeRefreshLockLease | None = None,
) -> _ClaudeMacOSCarrierSnapshot | None:
    try:
        return _persist_claude_macos_refreshed_credential_impl(
            review,
            selected,
            refreshed,
            expected_credential,
            carrier_snapshot,
            refresh_lock_protocol,
            coordinated_refresh_lock=coordinated_refresh_lock,
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
    try:
        canonical_source = source_root.resolve(strict=True)
        canonical_container = container_root.resolve(strict=True)
        review_root = _review_root_for_source(canonical_source)
    except (OSError, RuntimeError, ValueError, ReviewError) as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot validate the external Claude review workspace roots"
        ) from error
    if source_root != canonical_source or container_root != canonical_container:
        raise ClaudeCredentialInspectionInconclusive(
            "the Claude review workspace paths are not canonical absolute paths"
        )
    if container_root.parent != review_root or not container_root.name.startswith(
        "isolated-review-"
    ):
        raise ClaudeCredentialInspectionInconclusive(
            "the Claude review container is outside its private review root"
        )
    return source_root, review_root, container_root


def _claude_macos_recovery_root(review: ReviewWorkspace) -> pathlib.Path:
    _source_root, _review_root, container_root = _claude_review_workspace_roots(review)
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
        _source_root, review_root, container_root = _claude_review_workspace_roots(
            review
        )
        _fsync_claude_runtime_directory(
            review_root.parent,
            label="Claude review namespace root",
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

    def mark_retention_failure(error: BaseException) -> BaseException:
        if carrier_root is None:
            setattr(error, "_codex_claude_refresh_persistence_failed", True)
            return error
        try:
            carrier_root.lstat()
        except OSError:
            setattr(error, "_codex_claude_refresh_persistence_failed", True)
            return error
        if payload_verified:
            setattr(
                error,
                "_codex_claude_retained_credential_carrier",
                str(carrier_root),
            )
            error = _mark_claude_macos_recovery_update_artifact(
                error,
                carrier_root / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                expected_digest=credential_digest,
            )
        else:
            _mark_claude_macos_recovery_cleanup_artifact(
                error,
                carrier_root,
            )
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        return error

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
                or not requested_carrier_root.name.startswith("claude-carrier-")
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
                or _claude_credential_file_identity(os.fstat(credential_descriptor))
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
        primary_error = mark_retention_failure(error)
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
            primary_error = mark_retention_failure(cleanup_error)
    if primary_error is not None:
        raise primary_error
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
        result = _read_claude_credential_file_from_directory(config_descriptor)
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
    ) -> BaseException:
        try:
            carrier.lstat()
        except OSError:
            setattr(error, "_codex_claude_refresh_persistence_failed", True)
            return error
        if payload_verified:
            setattr(
                error,
                "_codex_claude_retained_credential_carrier",
                str(carrier),
            )
            error = _mark_claude_macos_recovery_update_artifact(
                error,
                carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                expected_digest=credential_digest,
            )
        else:
            _mark_claude_macos_recovery_cleanup_artifact(error, carrier)
        setattr(error, "_codex_claude_refresh_persistence_failed", True)
        return error

    pending_payload: bytearray | None = None
    pending_verified = False
    pending_error: BaseException | None = None
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
        pending_error = mark_stage_failure(
            error,
            pending_carrier,
            payload_verified=False,
        )
    finally:
        if pending_payload is not None:
            pending_payload[:] = b"\x00" * len(pending_payload)
    if pending_error is not None:
        raise pending_error

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
        if _claude_linux_directory_identity(
            pending_metadata
        ) != _claude_linux_directory_identity(acknowledged_metadata):
            raise ClaudeCredentialInspectionInconclusive(
                "the macOS Claude durable-stage carrier changed during commit"
            )
        committed_identity_verified = True
    except BaseException as error:
        retained_path = acknowledged_carrier if renamed else pending_carrier
        primary_error = mark_stage_failure(
            error,
            retained_path,
            payload_verified=pending_verified,
        )
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
                message=("cannot close the macOS Claude durable-stage root safely"),
            )
        except BaseException as cleanup_error:
            retained_path = acknowledged_carrier if renamed else pending_carrier
            primary_error = mark_stage_failure(
                cleanup_error,
                retained_path,
                payload_verified=pending_verified,
            )
    if primary_error is not None:
        raise primary_error

    acknowledged_payload: bytearray | None = None
    post_commit_payload_mismatch = False
    post_commit_error: BaseException | None = None
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
        post_commit_error = mark_stage_failure(
            error,
            acknowledged_carrier,
            payload_verified=(
                pending_verified
                and committed_identity_verified
                and not post_commit_payload_mismatch
            ),
        )
    finally:
        if acknowledged_payload is not None:
            acknowledged_payload[:] = b"\x00" * len(acknowledged_payload)
    if post_commit_error is not None:
        raise post_commit_error
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
                    failure = _attach_claude_credential_cleanup_failure(
                        failure,
                        verification_error,
                    )
                elif _is_claude_control_flow_error(verification_error):
                    failure = _attach_claude_credential_cleanup_failure(
                        verification_error,
                        failure,
                    )
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
            failure = _mark_claude_macos_recovery_update_artifact(
                failure,
                credential_path,
                expected_digest=expected_digest,
            )
        retained_cleanup_scope = _existing_claude_macos_recovery_cleanup_scope(
            cleanup_scope,
            recovery_root,
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
                artifact.name.startswith(CLAUDE_MACOS_RECOVERY_UPDATE_PREFIX)
                and artifact.name.endswith(CLAUDE_MACOS_RECOVERY_UPDATE_SUFFIX)
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
        with _open_absolute_directory_chain_without_symlinks(artifact.parent) as (
            parent_descriptor,
            ancestor_identities,
        ):
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
            if final_identity != file_identity or not hmac.compare_digest(
                _claude_credential_digest(payload),
                expected_digest,
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
) -> BaseException:
    try:
        proof = _capture_claude_retained_credential_proof(
            artifact,
            expected_digest=expected_digest,
        )
    except BaseException as proof_error:
        _clear_claude_retained_credential_proof(error)
        if _is_claude_control_flow_error(error):
            error = _attach_claude_credential_cleanup_failure(
                error,
                proof_error,
            )
        elif _is_claude_control_flow_error(proof_error):
            raise _attach_claude_credential_cleanup_failure(
                proof_error,
                error,
            )
        else:
            error = _attach_claude_credential_cleanup_failure(
                error,
                proof_error,
            )
    else:
        _set_claude_retained_credential_proof(error, proof)
        add_note = getattr(error, "add_note", None)
        if callable(add_note):
            add_note(
                "A macOS Claude recovery credential update remains at "
                f"{artifact} for operator inspection."
            )
    return error


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
    stale_cleanup_failure: BaseException | None = None
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
        temporary_identity = _claude_credential_file_identity(temporary_metadata)
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
                stale_cleanup_failure = _mark_claude_macos_recovery_update_artifact(
                    error,
                    config_dir / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=credential_digest,
                )
                _mark_claude_macos_recovery_cleanup_artifact(
                    stale_cleanup_failure,
                    config_dir / artifact,
                )
                break
        if stale_cleanup_failure is not None:
            raise stale_cleanup_failure
        if stale_update_artifacts:
            _sync_claude_credential_descriptor(config_descriptor)
    except BaseException as error:
        primary_error = error
        setattr(
            primary_error,
            "_codex_claude_retained_credential_carrier",
            str(carrier_root),
        )
        setattr(
            primary_error,
            "_codex_claude_refresh_persistence_failed",
            True,
        )
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
                            _claude_credential_file_identity(visible_temporary_metadata)
                            != temporary_identity
                        ):
                            raise ClaudeCredentialInspectionInconclusive(
                                "the private macOS Claude recovery update "
                                "identity changed before failure readback"
                            )
                        retained_result = _read_claude_credential_file_from_directory(
                            config_descriptor,
                            credential_name=temporary_name,
                            expected_identity=temporary_identity,
                        )
                        if retained_result is None:
                            temporary_created = False
                        else:
                            retained_payload, retained_identity = retained_result
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
                            retained_payload[:] = b"\x00" * len(retained_payload)
                else:
                    try:
                        os.unlink(temporary_name, dir_fd=config_descriptor)
                    except BaseException as error:
                        retained_cleanup_artifact = artifact
                        cleanup_errors.append(error)
                    else:
                        temporary_created = False
                        try:
                            _sync_claude_credential_descriptor(config_descriptor)
                        except BaseException as error:
                            cleanup_errors.append(error)
        current_credential_artifact = (
            config_dir / CLAUDE_CREDENTIAL_FILE_NAME
            if main_payload_verified
            else retained_update_artifact
        )
        if current_credential_artifact is not None and primary_error is not None:
            primary_error = _mark_claude_macos_recovery_update_artifact(
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
                cleanup_error = _mark_claude_macos_recovery_update_artifact(
                    cleanup_error,
                    current_credential_artifact,
                    expected_digest=credential_digest,
                )
            if retained_cleanup_artifact is not None:
                _mark_claude_macos_recovery_cleanup_artifact(
                    cleanup_error,
                    retained_cleanup_artifact,
                )
            setattr(
                cleanup_error,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            primary_error = cleanup_error
    if primary_error is not None:
        raise primary_error


def _retained_claude_macos_credential_error(
    carrier_root: pathlib.Path,
    error: BaseException,
    *,
    expected_digest: bytes,
    artifact: pathlib.Path | None = None,
) -> BaseException:
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
    descriptor_bound, recovery_incomplete = _claude_cleanup_recovery_state(error)
    if _is_claude_control_flow_error(error):
        retained = _attach_claude_credential_cleanup_failure(error, retained)
    elif not descriptor_bound and not recovery_incomplete:
        retained.__cause__ = error
    else:
        retained = _attach_claude_credential_cleanup_failure(retained, error)
    setattr(
        retained,
        "_codex_claude_retained_credential_carrier",
        str(carrier_root),
    )
    retained = _mark_claude_macos_recovery_update_artifact(
        retained,
        artifact
        if artifact is not None
        else carrier_root / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
        expected_digest=expected_digest,
    )
    setattr(retained, "_codex_claude_refresh_persistence_failed", True)
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
            f"{message}; the current recovery credential is at {retained_artifact}"
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
    return _attach_claude_credential_cleanup_failure(
        failed,
        persistence_error,
    )


def _persist_claude_macos_refreshed_credential_impl(
    review: ReviewWorkspace,
    selected: _ClaudeLocalCredential,
    refreshed: bytearray,
    expected_credential: bytearray,
    carrier_snapshot: _ClaudeMacOSCarrierSnapshot,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    *,
    coordinated_refresh_lock: ClaudeRefreshLockLease | None = None,
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
        keychain_digest if selected.source == "macos-keychain" else file_digest
    )
    if selected_digest is None or not hmac.compare_digest(
        _claude_credential_digest(expected_credential),
        selected_digest,
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
    if write_keychain and not _claude_keychain_credential_has_refresh_margin(refreshed):
        return None
    refreshed_digest = _claude_credential_digest(refreshed)

    coordination = (
        contextlib.nullcontext(coordinated_refresh_lock)
        if coordinated_refresh_lock is not None
        else _claude_macos_carrier_coordination(refresh_lock_protocol)
    )
    with coordination as refresh_lock:
        assert refresh_lock is not None
        refresh_lock.assert_held()
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
                for attempt_index in range(CLAUDE_MACOS_DUAL_CARRIER_KEYCHAIN_ATTEMPTS):
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
                    keychain_is_refreshed = (
                        hmac.compare_digest(
                            readback.keychain_digest or b"",
                            refreshed_digest,
                        )
                        and readback.keychain_digest is not None
                    )
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
                    if attempt_index + 1 < CLAUDE_MACOS_DUAL_CARRIER_KEYCHAIN_ATTEMPTS:
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
                and (observed.file_digest is None) == (expected_file_digest is None)
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
    *,
    coordinated_refresh_lock: ClaudeRefreshLockLease | None = None,
) -> bool:
    try:
        coordination = (
            contextlib.nullcontext(coordinated_refresh_lock)
            if coordinated_refresh_lock is not None
            else _claude_macos_carrier_coordination(refresh_lock_protocol)
        )
        with coordination as refresh_lock:
            assert refresh_lock is not None
            refresh_lock.assert_held()
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
    if error is persistence_error:
        return
    if _claude_timeout_root_state(error) is not None:
        _merge_claude_sealed_timeout_failure(error, persistence_error)
        return
    if _claude_timeout_root_state(persistence_error) is not None:
        raise AssertionError(
            "Claude sealed timeout persistence source requires a state-aware selector"
        )
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
        f"{CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC} ({type(persistence_error).__name__})"
    )
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(note)
        return
    diagnostic = ClaudeCredentialPersistenceDiagnostic(note)
    if error.__cause__ is not None:
        diagnostic.__cause__ = error.__cause__
    elif not error.__suppress_context__ and error.__context__ is not None:
        diagnostic.__context__ = error.__context__
    error.__cause__ = diagnostic


def _attach_claude_persistence_failure_preserving_control_flow(
    primary: BaseException,
    secondary: BaseException,
) -> BaseException:
    if _claude_timeout_root_state(primary) is not None:
        return _merge_claude_sealed_timeout_failure(primary, secondary)
    if _claude_timeout_root_state(secondary) is not None:
        return _merge_claude_sealed_timeout_failure(secondary, primary)
    if _is_claude_control_flow_error(primary):
        return _attach_claude_credential_cleanup_failure(primary, secondary)
    if _is_claude_control_flow_error(secondary):
        _add_claude_persistence_note(secondary, primary)
        return secondary
    return _attach_claude_credential_cleanup_failure(primary, secondary)


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
    with _open_absolute_directory_chain_without_symlinks(candidate.parent) as (
        parent_descriptor,
        ancestor_identities,
    ):
        leaf_metadata = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        snapshot = _ClaudeNoFollowArtifactSnapshot(
            ancestor_identities=ancestor_identities,
            leaf_identity=_claude_cleanup_artifact_identity(leaf_metadata),
            leaf_complete_identity=_claude_credential_file_identity(leaf_metadata),
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
        with _open_absolute_directory_chain_without_symlinks(candidate.parent) as (
            parent_descriptor,
            ancestor_identities,
        ):
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
        or not (stat.S_ISDIR(final.leaf_mode) or stat.S_ISREG(final.leaf_mode))
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
    timeout_state = _claude_timeout_root_state(error)
    if timeout_state is not None:
        with timeout_state.lock:
            try:
                _update_claude_sealed_persistence_report(review)
            except BaseException:
                pass
        return CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC
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
        authentication_report["recovery_cleanup_artifact"] = retained_cleanup_artifact
    diagnostic = CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC
    if retained_carrier is not None:
        diagnostic = (
            f"{diagnostic} Private recovery carrier retained at {retained_carrier}."
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
            {"authentication": authentication_report},
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
    if (
        _claude_timeout_root_state(error) is not None
        or not isinstance(error, ForwardedSignal)
        or diagnostic is None
    ):
        return
    if error.detail is None:
        error.detail = diagnostic
    elif diagnostic not in error.detail:
        error.detail = f"{error.detail}; {diagnostic}"


def _propagate_claude_persistence_state(
    review: ReviewWorkspace,
    source: BaseException,
    target: BaseException,
) -> BaseException:
    if source is target or _claude_timeout_root_state(source) is not None:
        return source
    if _claude_timeout_root_state(target) is not None:
        return target
    if not getattr(source, "_codex_claude_refresh_persistence_failed", False):
        return target
    setattr(target, "_codex_claude_refresh_persistence_failed", True)
    diagnostic = CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC
    try:
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
    except BaseException as validation_error:
        _attach_claude_persistence_signal_detail(target, diagnostic)
        setattr(
            validation_error,
            "_codex_claude_refresh_persistence_failed",
            True,
        )
        _attach_claude_persistence_signal_detail(
            validation_error,
            diagnostic,
        )
        raise
    if retained_carrier is not None:
        setattr(
            target,
            "_codex_claude_retained_credential_carrier",
            retained_carrier,
        )
        diagnostic = (
            f"{diagnostic} Private recovery carrier retained at {retained_carrier}."
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
    return target


def _claude_macos_runtime_io_inconclusive(
    review: ReviewWorkspace,
    error: OSError,
) -> BaseException:
    failure = ClaudeCredentialInspectionInconclusive(
        "Claude macOS credential runtime I/O was inconclusive"
    )
    effective_failure = _propagate_claude_persistence_state(
        review,
        error,
        failure,
    )
    if effective_failure is not failure:
        return effective_failure
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
        effective_error = _propagate_claude_persistence_state(
            review,
            persistence_error,
            report_error,
        )
        if effective_error is persistence_error:
            return
        if _claude_timeout_root_state(effective_error) is not None:
            raise
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
        message = (
            "cannot update the Claude runtime report after refresh persistence failed"
        )
        if retained_carrier is not None:
            message = (
                f"{message}; private recovery carrier retained at {retained_carrier}"
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
        effective_failure = _propagate_claude_persistence_state(
            review,
            persistence_error,
            failure,
        )
        if effective_failure is not failure:
            raise effective_failure
        raise failure from report_error


def _claude_macos_process_cdhash(process_id: int) -> bytes | None:
    if sys.platform != "darwin":
        raise ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker process identity requires macOS"
        )
    if process_id <= 0:
        return None
    library = ctypes.CDLL(None, use_errno=True)
    try:
        csops = library.csops
    except AttributeError as error:
        raise ClaudeCredentialInspectionInconclusive(
            "macOS csops is unavailable for Claude Keychain broker identity"
        ) from error
    csops.argtypes = (
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_size_t,
    )
    csops.restype = ctypes.c_int
    code_hash = (ctypes.c_ubyte * CLAUDE_MACOS_CDHASH_BYTES)()
    ctypes.set_errno(0)
    result = csops(
        process_id,
        CLAUDE_MACOS_CS_OPS_CDHASH,
        ctypes.byref(code_hash),
        ctypes.sizeof(code_hash),
    )
    if result == 0:
        return bytes(code_hash)
    error_number = ctypes.get_errno() or errno.EIO
    if error_number == errno.ESRCH:
        return None
    raise ClaudeCredentialInspectionInconclusive(
        "cannot inspect the running Claude Keychain broker code identity"
    ) from OSError(error_number, os.strerror(error_number))


def _claude_keychain_peer_process_id(connection: socket.socket) -> int | None:
    if sys.platform != "darwin":
        raise ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker peer credentials require macOS"
        )
    peer_pid = connection.getsockopt(
        CLAUDE_KEYCHAIN_BROKER_LOCAL_SOCKET_LEVEL,
        CLAUDE_KEYCHAIN_BROKER_LOCAL_PEERPID,
    )
    if not isinstance(peer_pid, int) or peer_pid <= 0:
        return None
    library = ctypes.CDLL(None, use_errno=True)
    try:
        getpeereid = library.getpeereid
    except AttributeError as error:
        raise ClaudeCredentialInspectionInconclusive(
            "macOS getpeereid is unavailable for Claude Keychain broker identity"
        ) from error
    getpeereid.argtypes = (
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    )
    getpeereid.restype = ctypes.c_int
    peer_uid = ctypes.c_uint()
    peer_gid = ctypes.c_uint()
    ctypes.set_errno(0)
    if (
        getpeereid(
            connection.fileno(),
            ctypes.byref(peer_uid),
            ctypes.byref(peer_gid),
        )
        != 0
    ):
        error_number = ctypes.get_errno() or errno.EIO
        raise ClaudeCredentialInspectionInconclusive(
            "cannot inspect the Claude Keychain broker peer credentials"
        ) from OSError(error_number, os.strerror(error_number))
    if peer_uid.value != os.geteuid() or peer_gid.value != os.getegid():
        return None
    return peer_pid


class _ClaudeKeychainIdentityHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _ClaudeKeychainIdentityServer):
            return
        self.request.settimeout(2.0)
        try:
            peer_pid = _claude_keychain_peer_process_id(self.request)
            if peer_pid is None:
                return
            if not server.credential_server.authorize_identity_peer(peer_pid):
                return
            self.request.sendall(server.credential_server.capability)
        except (BrokenPipeError, ConnectionError, TimeoutError):
            return
        except BaseException as error:
            server.credential_server.record_handler_error(error)


class _ClaudeKeychainIdentityServer(socketserver.UnixStreamServer):
    allow_reuse_address = False

    def __init__(
        self,
        socket_path: pathlib.Path,
        credential_server: _ClaudeKeychainCredentialServer,
    ) -> None:
        self.credential_server = credential_server
        self._serve_condition = threading.Condition()
        self._serving = False
        self._serve_stopped = False
        self._serve_error: BaseException | None = None
        super().__init__(str(socket_path), _ClaudeKeychainIdentityHandler)

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
            with contextlib.suppress(OSError):
                self.request.sendall(b"\x01")
            return
        try:
            self.request.sendall(b"\x00")
        except OSError:
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
        observed_generation: int | None = None
        if server.write_observed_callback is not None:
            observed_generation = server.write_observed_callback()
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
            pending_generation = server.stage_pending_update(updated_credential)
            if pending_generation is None:
                if server.pending_updates_closed():
                    self.request.sendall(b"\x01")
                return
            with server.update_lock:
                with server.credential_lock:
                    read_completed = server.consumed
                if (
                    not server.pending_update_is_current(pending_generation)
                    or not read_completed
                    or server.update_callback is None
                ):
                    success = False
                else:
                    callback_args = (
                        updated_credential,
                        lambda publish: server.commit_pending_update(
                            pending_generation,
                            publish,
                        ),
                        lambda: server.claim_terminal_pending_update(
                            pending_generation
                        ),
                    )
                    if observed_generation is None:
                        success = server.update_callback(*callback_args)
                    else:
                        success = server.update_callback(
                            *callback_args,
                            observed_generation,
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


@dataclass(frozen=True)
class _ClaudeRuntimeProcessBinding:
    process_id: int
    session_id: int
    process_group: int


def _inspect_claude_runtime_process(process_id: int) -> _ClaudeRuntimeProcessBinding:
    if process_id <= 0:
        raise ReviewError("Claude Keychain broker runtime process is invalid")
    try:
        session_id = os.getsid(process_id)
        process_group = os.getpgid(process_id)
    except OSError as error:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot inspect the Claude Keychain broker runtime process"
        ) from error
    if session_id != process_id or process_group != process_id:
        raise ReviewError(
            "Claude Keychain broker runtime must start as its own session"
        )
    return _ClaudeRuntimeProcessBinding(
        process_id=process_id,
        session_id=session_id,
        process_group=process_group,
    )


class _ClaudeSignalMaskOwnerState(enum.Enum):
    UNPUBLISHED = "unpublished"
    OUTER = "outer"
    RESTORE_ATTEMPTED = "restore-attempted"


@dataclass
class _ClaudeSignalMaskOwner:
    previous_signal_mask: set[Any] | None = None
    signal_mask_owner_state: _ClaudeSignalMaskOwnerState = (
        _ClaudeSignalMaskOwnerState.UNPUBLISHED
    )

    @property
    def signal_mask_owner_active(self) -> bool:
        return self.signal_mask_owner_state is _ClaudeSignalMaskOwnerState.OUTER

    def publish_previous_signal_mask(
        self,
        previous_signal_mask: set[signal.Signals] | None,
    ) -> None:
        self.previous_signal_mask = previous_signal_mask
        self.signal_mask_owner_state = _ClaudeSignalMaskOwnerState.OUTER

    def owns_previous_signal_mask(
        self,
        previous_signal_mask: set[signal.Signals] | None,
    ) -> bool:
        return (
            self.signal_mask_owner_active
            and self.previous_signal_mask is previous_signal_mask
        )

    def restore_previous_signal_mask(self) -> None:
        if not self.signal_mask_owner_active:
            return
        restore_signal_mask(self.previous_signal_mask)
        self.signal_mask_owner_state = _ClaudeSignalMaskOwnerState.RESTORE_ATTEMPTED


@dataclass
class _ClaudeMacOSTerminalHandoff(_ClaudeSignalMaskOwner):
    abandonment_attempted: bool = False
    recovery_source: BaseException | None = None
    persistence_source: BaseException | None = None


@dataclass(frozen=True)
class _ClaudeSignalMaskAcquisition:
    previous_mask: set[signal.Signals] | None
    error: BaseException | None


class _ClaudeThreadStartState(enum.Enum):
    NOT_STARTED = "not-started"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class _ClaudeThreadStartOutcome:
    state: _ClaudeThreadStartState
    error: BaseException | None

    @property
    def started(self) -> bool:
        return self.state is _ClaudeThreadStartState.CONFIRMED

    @property
    def may_have_started(self) -> bool:
        return self.state is not _ClaudeThreadStartState.NOT_STARTED


@dataclass
class _ClaudeThreadStartOwner:
    snapshot: _ClaudeThreadStartOutcome = field(
        default_factory=lambda: _ClaudeThreadStartOutcome(
            state=_ClaudeThreadStartState.NOT_STARTED,
            error=None,
        )
    )


def _select_claude_thread_start_related_error(
    earlier_error: BaseException | None,
    later_error: BaseException | None,
) -> BaseException | None:
    if earlier_error is None:
        return later_error
    if later_error is None:
        return earlier_error
    selected = earlier_error
    try:
        _raise_or_attach_claude_credential_cleanup(
            earlier_error,
            [later_error],
            message="Claude worker thread startup or cleanup failed",
        )
    except BaseException as selected_error:
        selected = selected_error
    if _claude_timeout_root_state(selected) is not None:
        return selected
    for related_error in (earlier_error, later_error):
        if related_error is selected or _claude_visible_error_chain_contains(
            selected, related_error
        ):
            continue
        rendered = _claude_cleanup_error_without_primary_backlink(
            related_error,
            selected,
        )
        if selected.__cause__ is None:
            selected.__cause__ = rendered
            continue
        diagnostic = ClaudeCredentialCleanupDiagnostic(
            "Claude worker thread startup or cleanup also failed: "
            f"{type(rendered).__name__}: {rendered}"
        )
        diagnostic.__cause__ = selected.__cause__
        diagnostic.__context__ = rendered
        diagnostic.__suppress_context__ = False
        selected.__cause__ = diagnostic
    return selected


def _restore_claude_signal_mask_owner_bounded(
    signal_mask_owner: _ClaudeSignalMaskOwner,
) -> BaseException | None:
    selected_error: BaseException | None = None
    for _attempt in range(2):
        try:
            signal_mask_owner.restore_previous_signal_mask()
        except BaseException as restore_error:
            selected_error = _select_claude_thread_start_related_error(
                selected_error,
                restore_error,
            )
            continue
        break
    return selected_error


def _acquire_claude_forwarded_signal_mask(
    *,
    main_thread_only: bool,
    signal_mask_owner: _ClaudeSignalMaskOwner | None = None,
) -> _ClaudeSignalMaskAcquisition:
    if main_thread_only and threading.current_thread() is not threading.main_thread():
        return _ClaudeSignalMaskAcquisition(
            previous_mask=None,
            error=ClaudeCredentialInspectionInconclusive(
                "cannot establish the Claude forwarded-signal handoff outside "
                "the main thread"
            ),
        )
    if os.name != "posix" or not hasattr(signal, "pthread_sigmask"):
        return _ClaudeSignalMaskAcquisition(previous_mask=None, error=None)

    try:
        queried_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    except BaseException as query_error:
        return _ClaudeSignalMaskAcquisition(
            previous_mask=None,
            error=query_error,
        )

    previous_mask = queried_mask
    try:
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            forwarded_signals(),
        )
        if signal_mask_owner is not None:
            signal_mask_owner.publish_previous_signal_mask(previous_mask)
    except BaseException as block_error:
        restore_error: BaseException | None = None
        if signal_mask_owner is None or not signal_mask_owner.owns_previous_signal_mask(
            previous_mask
        ):
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException as error:
                restore_error = error
        return _ClaudeSignalMaskAcquisition(
            previous_mask=None,
            error=_select_claude_thread_start_related_error(
                block_error,
                restore_error,
            ),
        )
    return _ClaudeSignalMaskAcquisition(
        previous_mask=previous_mask,
        error=None,
    )


def block_forwarded_signals(
    *,
    signal_mask_owner: _ClaudeSignalMaskOwner | None = None,
) -> set[signal.Signals]:
    acquisition = _acquire_claude_forwarded_signal_mask(
        main_thread_only=True,
        signal_mask_owner=signal_mask_owner,
    )
    if acquisition.error is not None:
        raise acquisition.error
    if acquisition.previous_mask is None:
        raise ClaudeCredentialInspectionInconclusive(
            "cannot establish the Claude forwarded-signal handoff on this platform"
        )
    return acquisition.previous_mask


def _start_claude_thread_inheriting_forwarded_signal_mask(
    thread: threading.Thread,
    *,
    thread_start_owner: _ClaudeThreadStartOwner | None = None,
) -> _ClaudeThreadStartOutcome:
    if thread_start_owner is None:
        thread_start_owner = _ClaudeThreadStartOwner()
    signal_mask_owner = _ClaudeSignalMaskOwner()
    state = _ClaudeThreadStartState.NOT_STARTED
    outcome_error: BaseException | None = None
    outcome_state: _ClaudeThreadStartState | None = None
    raised_error: BaseException | None = None
    restore_error: BaseException | None = None
    try:
        acquisition = _acquire_claude_forwarded_signal_mask(
            main_thread_only=False,
            signal_mask_owner=signal_mask_owner,
        )
        if acquisition.error is not None:
            outcome_error = acquisition.error
            thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
                state=_ClaudeThreadStartState.NOT_STARTED,
                error=outcome_error,
            )
        else:
            if (
                acquisition.previous_mask is not None
                and not signal_mask_owner.owns_previous_signal_mask(
                    acquisition.previous_mask
                )
            ):
                signal_mask_owner.publish_previous_signal_mask(
                    acquisition.previous_mask
                )
            state = _ClaudeThreadStartState.UNKNOWN
            thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
                state=state,
                error=None,
            )
            try:
                thread.start()
            except BaseException as error:
                outcome_error = error
                thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
                    state=state,
                    error=outcome_error,
                )
            else:
                state = _ClaudeThreadStartState.CONFIRMED
                thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
                    state=state,
                    error=None,
                )
        outcome_state = state
    except BaseException as processing_error:
        conservative_state = (
            _ClaudeThreadStartState.NOT_STARTED
            if state is _ClaudeThreadStartState.NOT_STARTED
            else _ClaudeThreadStartState.UNKNOWN
        )
        thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
            state=conservative_state,
            error=processing_error,
        )
        if state is _ClaudeThreadStartState.NOT_STARTED and outcome_error is None:
            raised_error = processing_error
        else:
            outcome_error = _select_claude_thread_start_related_error(
                outcome_error,
                processing_error,
            )
            thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
                state=conservative_state,
                error=outcome_error,
            )
    finally:
        restore_error = _restore_claude_signal_mask_owner_bounded(signal_mask_owner)
        if restore_error is not None:
            conservative_state = (
                _ClaudeThreadStartState.NOT_STARTED
                if state is _ClaudeThreadStartState.NOT_STARTED
                else _ClaudeThreadStartState.UNKNOWN
            )
            thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
                state=conservative_state,
                error=restore_error,
            )
            prior_error = raised_error or outcome_error
            if (
                prior_error is not None
                and restore_error.__cause__ is None
                and not _claude_error_graph_contains(
                    prior_error,
                    restore_error,
                )
            ):
                restore_error.__cause__ = prior_error

    if raised_error is not None:
        selected_error = _select_claude_thread_start_related_error(
            raised_error,
            restore_error,
        )
        assert selected_error is not None
        thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
            state=_ClaudeThreadStartState.NOT_STARTED,
            error=selected_error,
        )
        raise selected_error
    final_state = state if outcome_state is None else outcome_state
    selected_error = _select_claude_thread_start_related_error(
        outcome_error,
        restore_error,
    )
    conservative_state = (
        _ClaudeThreadStartState.NOT_STARTED
        if final_state is _ClaudeThreadStartState.NOT_STARTED
        else _ClaudeThreadStartState.UNKNOWN
    )
    thread_start_owner.snapshot = _ClaudeThreadStartOutcome(
        state=conservative_state,
        error=selected_error,
    )
    outcome = _ClaudeThreadStartOutcome(
        state=final_state,
        error=selected_error,
    )
    thread_start_owner.snapshot = outcome
    return outcome


def _bounded_claude_thread_quiescence(
    thread: threading.Thread,
    state: _ClaudeThreadStartState,
    timeout: float,
) -> tuple[bool, BaseException | None]:
    if state is _ClaudeThreadStartState.NOT_STARTED:
        return True, None
    deadline = time.monotonic() + max(0.0, timeout)
    if state is _ClaudeThreadStartState.UNKNOWN:
        started_event = getattr(thread, "_started", None)
        if not isinstance(started_event, threading.Event):
            return False, None
        try:
            published = started_event.wait(
                timeout=max(0.0, deadline - time.monotonic())
            )
        except BaseException as error:
            return False, error
        if not published:
            return False, None
    try:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    except BaseException as error:
        return False, error
    try:
        return not thread.is_alive(), None
    except BaseException as error:
        return False, error


class _ClaudeKeychainCredentialServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        credential: bytearray | None,
        capability: bytes,
        allowed_broker_cdhashes: frozenset[bytes],
        update_callback: Callable[..., bool] | None,
        write_observed_callback: Callable[[], int | None] | None = None,
    ) -> None:
        if not allowed_broker_cdhashes or any(
            len(code_hash) != CLAUDE_MACOS_CDHASH_BYTES
            for code_hash in allowed_broker_cdhashes
        ):
            raise ReviewError("Claude Keychain broker code identities are unavailable")
        self.credential: bytearray | None = None
        try:
            super().__init__(("127.0.0.1", 0), _ClaudeKeychainCredentialHandler)
            self.credential = bytearray(credential) if credential is not None else None
            self.capability = capability
            self.credential_lock = threading.Lock()
            self.consumed = False
            self.update_callback = update_callback
            self.write_observed_callback = write_observed_callback
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
            self._runtime_session_lock = threading.Lock()
            self._runtime_session_id: int | None = None
            self.allowed_broker_cdhashes = allowed_broker_cdhashes
        except BaseException:
            if self.credential is not None:
                self.credential[:] = b"\x00" * len(self.credential)
            with contextlib.suppress(BaseException):
                self.server_close()
            raise

    def bind_runtime_process(self, binding: _ClaudeRuntimeProcessBinding) -> None:
        if (
            binding.process_id <= 0
            or binding.session_id != binding.process_id
            or binding.process_group != binding.process_id
        ):
            raise ReviewError(
                "Claude Keychain broker runtime must start as its own session"
            )
        if not self._runtime_session_lock.acquire(blocking=False):
            raise ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker runtime binding is busy"
            )
        try:
            if self._runtime_session_id is not None:
                raise ReviewError(
                    "Claude Keychain broker runtime process was already bound"
                )
            self._runtime_session_id = binding.process_id
        finally:
            self._runtime_session_lock.release()

    def authorize_identity_peer(self, process_id: int) -> bool:
        with self._runtime_session_lock:
            expected_session = self._runtime_session_id
        if expected_session is None:
            return False
        try:
            session_before = os.getsid(process_id)
            process_group_before = os.getpgid(process_id)
        except ProcessLookupError:
            return False
        except OSError as error:
            raise ClaudeCredentialInspectionInconclusive(
                "cannot inspect the Claude Keychain broker peer session"
            ) from error
        if (
            session_before != expected_session
            or process_group_before != expected_session
        ):
            return False
        code_hash = _claude_macos_process_cdhash(process_id)
        if code_hash is None or not any(
            hmac.compare_digest(code_hash, expected)
            for expected in self.allowed_broker_cdhashes
        ):
            return False
        try:
            return (
                os.getsid(process_id) == expected_session
                and os.getpgid(process_id) == expected_session
            )
        except ProcessLookupError:
            return False
        except OSError as error:
            raise ClaudeCredentialInspectionInconclusive(
                "cannot revalidate the Claude Keychain broker peer session"
            ) from error

    def record_handler_error(self, error: BaseException) -> None:
        with self._handler_condition:
            self._handler_errors.append(error)

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
        thread_start_owner = _ClaudeThreadStartOwner()
        start_completed = False
        start_interruption: BaseException | None = None
        cleanup_required = False
        try:
            try:
                _start_claude_thread_inheriting_forwarded_signal_mask(
                    thread,
                    thread_start_owner=thread_start_owner,
                )
                start_completed = True
            except BaseException as error:
                start_interruption = error
            finally:
                try:
                    start_snapshot = thread_start_owner.snapshot
                    cleanup_required = (
                        not start_completed or start_snapshot.error is not None
                    )
                finally:
                    if (
                        not start_completed
                        or thread_start_owner.snapshot.error is not None
                    ):
                        if not thread_start_owner.snapshot.may_have_started:
                            with self._handler_condition:
                                self._handler_threads.discard(thread)
                                self._handler_sockets.pop(thread, None)
                                self._handler_condition.notify_all()
                        self.shutdown_request(request)
        except BaseException as error:
            start_interruption = error
        start_snapshot = thread_start_owner.snapshot
        if cleanup_required or start_interruption is not None:
            selected_error = _select_claude_thread_start_related_error(
                start_snapshot.error,
                start_interruption,
            )
            assert selected_error is not None
            raise selected_error

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
            if self._abandoned.is_set() or self.consumed or self.credential is None:
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
        acquired = self._pending_update_lock.acquire(timeout=max(0.0, timeout))
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
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)

        def acquire(lock: object) -> bool:
            acquire_lock = getattr(lock, "acquire")
            if deadline is None:
                acquire_lock()
                return True
            return bool(acquire_lock(timeout=max(0.0, deadline - time.monotonic())))

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
    write_observed: Callable[[], int | None] | None = None


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
    recovery_decided: _ClaudeThreadEvent = field(default_factory=_ClaudeThreadEvent)
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
    thread_start_owner = _ClaudeThreadStartOwner()
    start_interruption: BaseException | None = None
    finished = False
    wait_error: BaseException | None = None
    cleanup_required = False
    try:
        try:
            _start_claude_thread_inheriting_forwarded_signal_mask(
                abandonment_thread,
                thread_start_owner=thread_start_owner,
            )
        except BaseException as error:
            start_interruption = error
        finally:
            try:
                start_snapshot = thread_start_owner.snapshot
                cleanup_required = start_snapshot.may_have_started
            finally:
                if cleanup_required or thread_start_owner.snapshot.may_have_started:
                    try:
                        finished = completed.wait(timeout=max(0.0, timeout))
                    except BaseException as error:
                        wait_error = error
    except BaseException as error:
        start_interruption = error
    start_snapshot = thread_start_owner.snapshot
    if not start_snapshot.may_have_started and (
        start_snapshot.error is not None or start_interruption is not None
    ):
        selected = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        assert selected is not None
        return False, selected
    if wait_error is not None:
        selected = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        selected = _select_claude_thread_start_related_error(
            selected,
            wait_error,
        )
        assert selected is not None
        return False, selected
    if not finished:
        timeout_error = ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker runtime abandonment did not finish "
            "before the shutdown deadline"
        )
        selected = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        selected = _select_claude_thread_start_related_error(
            selected,
            timeout_error,
        )
        assert selected is not None
        return False, selected
    selected_error = _select_claude_thread_start_related_error(
        start_snapshot.error,
        start_interruption,
    )
    for error in errors:
        selected_error = _select_claude_thread_start_related_error(
            selected_error,
            error,
        )
    if selected_error is not None:
        return False, selected_error
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
    thread_start_owner = _ClaudeThreadStartOwner()
    start_interruption: BaseException | None = None
    finished = False
    wait_error: BaseException | None = None
    cleanup_required = False
    try:
        try:
            _start_claude_thread_inheriting_forwarded_signal_mask(
                callback_thread,
                thread_start_owner=thread_start_owner,
            )
        except BaseException as error:
            start_interruption = error
        finally:
            try:
                start_snapshot = thread_start_owner.snapshot
                cleanup_required = start_snapshot.may_have_started
            finally:
                if cleanup_required or thread_start_owner.snapshot.may_have_started:
                    try:
                        finished = completed.wait(timeout=max(0.0, timeout))
                    except BaseException as error:
                        wait_error = error
    except BaseException as error:
        start_interruption = error
    start_snapshot = thread_start_owner.snapshot
    if not start_snapshot.may_have_started and (
        start_snapshot.error is not None or start_interruption is not None
    ):
        selected = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        assert selected is not None
        return None, selected
    if wait_error is not None:
        selected = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        selected = _select_claude_thread_start_related_error(
            selected,
            wait_error,
        )
        assert selected is not None
        return None, selected
    if not finished:
        timeout_error = ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker fail-closed scope did not finish "
            "before the recovery deadline"
        )
        selected = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        selected = _select_claude_thread_start_related_error(
            selected,
            timeout_error,
        )
        assert selected is not None
        return None, selected
    selected_error = _select_claude_thread_start_related_error(
        start_snapshot.error,
        start_interruption,
    )
    for error in errors:
        selected_error = _select_claude_thread_start_related_error(
            selected_error,
            error,
        )
    if selected_error is not None:
        return None, selected_error
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
                "Claude Keychain broker fail-closed scope returned an invalid error"
            ),
        )
    return results[0], None


def _bounded_claude_keychain_server_shutdown(
    server: _ClaudeKeychainCredentialServer,
    serve_thread: threading.Thread,
    *,
    serve_thread_state: _ClaudeThreadStartState = (_ClaudeThreadStartState.CONFIRMED),
    abandon_callback: Callable[[], None] | None = None,
) -> _ClaudeKeychainServerShutdown:
    deadline = time.monotonic() + CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS
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
    thread_start_owner = _ClaudeThreadStartOwner()
    start_interruption: BaseException | None = None
    shutdown_quiescent = False
    quiescence_error: BaseException | None = None
    server_close_error: BaseException | None = None
    cleanup_required = False
    try:
        try:
            _start_claude_thread_inheriting_forwarded_signal_mask(
                shutdown_thread,
                thread_start_owner=thread_start_owner,
            )
        except BaseException as error:
            start_interruption = error
        finally:
            try:
                start_snapshot = thread_start_owner.snapshot
                cleanup_required = start_snapshot.may_have_started
            finally:
                try:
                    if cleanup_required or thread_start_owner.snapshot.may_have_started:
                        shutdown_quiescent, quiescence_error = (
                            _bounded_claude_thread_quiescence(
                                shutdown_thread,
                                thread_start_owner.snapshot.state,
                                remaining(),
                            )
                        )
                finally:
                    try:
                        server.server_close()
                    except BaseException as error:
                        server_close_error = error
    except BaseException as error:
        start_interruption = error
    start_snapshot = thread_start_owner.snapshot
    start_error = _select_claude_thread_start_related_error(
        start_snapshot.error,
        start_interruption,
    )
    if start_error is not None:
        errors.append(start_error)
    if quiescence_error is not None:
        errors.append(quiescence_error)
    if server_close_error is not None:
        errors.append(server_close_error)
    serve_quiescent, serve_quiescence_error = _bounded_claude_thread_quiescence(
        serve_thread,
        serve_thread_state,
        remaining(),
    )
    if serve_quiescence_error is not None:
        errors.append(serve_quiescence_error)
    try:
        handlers_quiescent = server.wait_for_handlers(remaining())
    except BaseException as error:
        errors.append(error)
        handlers_quiescent = False
    pending_update = None
    abandonment_latched = False
    pending_update_detached = False
    quiescent = shutdown_quiescent and serve_quiescent and handlers_quiescent
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
        captured, callback_error = _bounded_claude_keychain_fail_closed_error(
            callbacks.timeout_error,
            min(
                CLAUDE_KEYCHAIN_SERVER_POLL_INTERVAL_SECONDS,
                max(0.0, CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS),
            ),
        )
        failure = (
            captured
            or callbacks.timeout_fallback_error
            or ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker recovery timeout state could not be captured"
            )
        )
        if callback_error is not None and callback_error is not failure:
            failure = _attach_claude_persistence_failure_preserving_control_flow(
                failure,
                callback_error,
            )
        return failure

    if not already_abandoned:
        abandonment_latched, abandonment_error = _bounded_claude_keychain_abandonment(
            callbacks.abandon,
            remaining(),
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
    thread_start_owner = _ClaudeThreadStartOwner()
    start_interruption: BaseException | None = None
    recovery_completed = False
    wait_error: BaseException | None = None
    cleanup_required = False
    try:
        try:
            _start_claude_thread_inheriting_forwarded_signal_mask(
                recovery_thread,
                thread_start_owner=thread_start_owner,
            )
        except BaseException as error:
            start_interruption = error
        finally:
            try:
                start_snapshot = thread_start_owner.snapshot
                cleanup_required = start_snapshot.may_have_started
            finally:
                if cleanup_required or thread_start_owner.snapshot.may_have_started:
                    try:
                        recovery_completed = completed.wait(timeout=remaining())
                    except BaseException as error:
                        wait_error = error
    except BaseException as error:
        start_interruption = error
    start_snapshot = thread_start_owner.snapshot
    if not start_snapshot.may_have_started and (
        start_snapshot.error is not None or start_interruption is not None
    ):
        if pending_update is not None:
            pending_update[:] = b"\x00" * len(pending_update)
        timeout_error = bounded_timeout_error()
        start_error = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        assert start_error is not None
        timeout_error = _attach_claude_credential_cleanup_failure(
            timeout_error,
            start_error,
        )
        return timeout_error
    if wait_error is not None:
        timeout_error = bounded_timeout_error()
        selected = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        selected = _select_claude_thread_start_related_error(
            selected,
            wait_error,
        )
        assert selected is not None
        if getattr(
            timeout_error,
            "_codex_claude_refresh_persistence_failed",
            False,
        ):
            selected = _attach_claude_persistence_failure_preserving_control_flow(
                timeout_error,
                selected,
            )
        else:
            selected = _attach_claude_credential_cleanup_failure(
                selected,
                timeout_error,
            )
        return selected
    if not recovery_completed:
        selected = _select_claude_thread_start_related_error(
            start_snapshot.error,
            start_interruption,
        )
        return _select_claude_thread_start_related_error(
            selected,
            bounded_timeout_error(),
        )
    recovery_error = result[0] if result else None
    selected = _select_claude_thread_start_related_error(
        start_snapshot.error,
        start_interruption,
    )
    return _select_claude_thread_start_related_error(
        selected,
        recovery_error,
    )


@dataclass(frozen=True)
class _ClaudeKeychainBrokerEndpoint:
    port: int
    identity_socket: pathlib.Path
    prepare_runtime_process: Callable[[int], _ClaudeRuntimeProcessBinding]
    bind_runtime_process: Callable[[_ClaudeRuntimeProcessBinding], None]


class _ClaudeKeychainRuntimeEnvironment(dict[str, str]):
    def __init__(
        self,
        values: dict[str, str],
        prepare_runtime_process: Callable[[int], _ClaudeRuntimeProcessBinding],
        bind_runtime_process: Callable[[_ClaudeRuntimeProcessBinding], None],
    ) -> None:
        super().__init__(values)
        self.prepare_runtime_process = prepare_runtime_process
        self.bind_runtime_process = bind_runtime_process


@dataclass(frozen=True)
class _ClaudeKeychainIdentityRuntime:
    server: _ClaudeKeychainIdentityServer
    thread: threading.Thread
    socket_path: pathlib.Path
    socket_identity: tuple[int, int]


def _verify_claude_keychain_identity_socket_for_cleanup(
    socket_path: pathlib.Path,
    socket_identity: tuple[int, int],
    *,
    missing_is_error: bool,
) -> BaseException | None:
    try:
        current = os.stat(socket_path, follow_symlinks=False)
    except FileNotFoundError:
        if not missing_is_error:
            return None
        return ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker identity socket disappeared during cleanup"
        )
    except OSError as error:
        failure = ClaudeCredentialInspectionInconclusive(
            "cannot inspect the Claude Keychain broker identity socket during cleanup"
        )
        failure.__cause__ = error
        return failure
    if (current.st_dev, current.st_ino) != socket_identity or not stat.S_ISSOCK(
        current.st_mode
    ):
        return ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker identity socket changed during cleanup"
        )
    return None


def _close_unstarted_claude_keychain_identity_server(
    server: _ClaudeKeychainIdentityServer,
    socket_path: pathlib.Path,
    socket_identity: tuple[int, int],
) -> tuple[BaseException, ...]:
    errors: list[BaseException] = []
    try:
        server.server_close()
    except BaseException as error:
        errors.append(error)
    cleanup_error = _verify_claude_keychain_identity_socket_for_cleanup(
        socket_path,
        socket_identity,
        missing_is_error=False,
    )
    if cleanup_error is not None:
        errors.append(cleanup_error)
    return tuple(errors)


def _raise_claude_identity_cleanup_control_flow(
    primary: BaseException | None,
    cleanup_errors: tuple[BaseException, ...] | list[BaseException],
) -> None:
    selected = (
        primary
        if primary is not None and _is_claude_control_flow_error(primary)
        else next(
            (error for error in cleanup_errors if _is_claude_control_flow_error(error)),
            None,
        )
    )
    if selected is None:
        return
    for error in (primary, *cleanup_errors):
        if error is None or error is selected:
            continue
        _attach_claude_credential_cleanup_failure(selected, error)
    raise selected


def _start_claude_keychain_identity_server(
    credential_server: _ClaudeKeychainCredentialServer,
    socket_path: pathlib.Path,
) -> _ClaudeKeychainIdentityRuntime:
    startup_deadline = time.monotonic() + CLAUDE_KEYCHAIN_SERVER_START_TIMEOUT_SECONDS
    if not socket_path.is_absolute() or socket_path.name != (
        CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET_NAME
    ):
        raise ReviewError("Claude Keychain broker identity socket path is invalid")
    _require_claude_keychain_identity_directory(socket_path.parent)
    try:
        identity_server = _ClaudeKeychainIdentityServer(
            socket_path,
            credential_server,
        )
    except OSError as error:
        raise ClaudeCredentialInspectionInconclusive(
            f"Claude Keychain broker cannot bind its identity socket: {error}"
        ) from error
    socket_identity: tuple[int, int] | None = None
    try:
        initial_metadata = os.stat(socket_path, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(initial_metadata.st_mode)
            or initial_metadata.st_uid != os.geteuid()
        ):
            raise ReviewError(
                "Claude Keychain broker identity endpoint must be a socket"
            )
        socket_identity = (initial_metadata.st_dev, initial_metadata.st_ino)
        os.chmod(socket_path, 0o600, follow_symlinks=False)
        socket_metadata = os.stat(socket_path, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(socket_metadata.st_mode)
            or socket_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(socket_metadata.st_mode) != 0o600
            or (socket_metadata.st_dev, socket_metadata.st_ino) != socket_identity
        ):
            raise ReviewError(
                "Claude Keychain broker identity endpoint must be a socket"
            )
    except BaseException as error:
        if socket_identity is not None:
            cleanup_errors = _close_unstarted_claude_keychain_identity_server(
                identity_server,
                socket_path,
                socket_identity,
            )
        else:
            cleanup_errors = ()
            try:
                identity_server.server_close()
            except BaseException as cleanup_error:
                cleanup_errors = (cleanup_error,)
        _raise_claude_identity_cleanup_control_flow(error, cleanup_errors)
        if isinstance(error, ReviewError):
            for cleanup_error in cleanup_errors:
                _attach_claude_credential_cleanup_failure(error, cleanup_error)
            raise
        failure = ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker cannot secure its identity endpoint"
        )
        for cleanup_error in cleanup_errors:
            _attach_claude_credential_cleanup_failure(failure, cleanup_error)
        raise failure from error

    def serve() -> None:
        serve_error: BaseException | None = None
        try:
            identity_server.serve_forever(
                poll_interval=CLAUDE_KEYCHAIN_SERVER_POLL_INTERVAL_SECONDS
            )
        except BaseException as error:
            serve_error = error
        finally:
            identity_server.record_serve_stopped(serve_error)

    try:
        thread = threading.Thread(
            target=serve,
            daemon=True,
            name="claude-review-keychain-identity",
        )
    except BaseException as error:
        cleanup_errors = _close_unstarted_claude_keychain_identity_server(
            identity_server,
            socket_path,
            socket_identity,
        )
        _raise_claude_identity_cleanup_control_flow(error, cleanup_errors)
        failure = ClaudeCredentialInspectionInconclusive(
            f"Claude Keychain broker identity service cannot construct: {error}"
        )
        for cleanup_error in cleanup_errors:
            _attach_claude_credential_cleanup_failure(failure, cleanup_error)
        raise failure from error
    thread_start_owner = _ClaudeThreadStartOwner()
    start_interruption: BaseException | None = None
    try:
        _start_claude_thread_inheriting_forwarded_signal_mask(
            thread,
            thread_start_owner=thread_start_owner,
        )
    except BaseException as error:
        start_interruption = error
    start_snapshot = thread_start_owner.snapshot
    start_error = _select_claude_thread_start_related_error(
        start_snapshot.error,
        start_interruption,
    )
    if start_error is not None:
        cleanup_errors: list[BaseException] = []
        if start_snapshot.may_have_started:
            cleanup_errors.extend(
                _stop_claude_keychain_identity_server(
                    _ClaudeKeychainIdentityRuntime(
                        server=identity_server,
                        thread=thread,
                        socket_path=socket_path,
                        socket_identity=socket_identity,
                    ),
                    deadline=startup_deadline,
                )
            )
        else:
            cleanup_errors.extend(
                _close_unstarted_claude_keychain_identity_server(
                    identity_server,
                    socket_path,
                    socket_identity,
                )
            )
        _raise_claude_identity_cleanup_control_flow(start_error, cleanup_errors)
        failure = ClaudeCredentialInspectionInconclusive(
            f"Claude Keychain broker identity service cannot start: {start_error}"
        )
        for cleanup_error in cleanup_errors:
            _attach_claude_credential_cleanup_failure(failure, cleanup_error)
        raise failure from start_error
    runtime = _ClaudeKeychainIdentityRuntime(
        server=identity_server,
        thread=thread,
        socket_path=socket_path,
        socket_identity=socket_identity,
    )
    try:
        entered_serve_loop = identity_server.wait_until_serving(
            max(0.0, startup_deadline - time.monotonic())
        )
    except BaseException as error:
        cleanup_errors = _stop_claude_keychain_identity_server(
            runtime,
            deadline=startup_deadline,
        )
        _raise_claude_identity_cleanup_control_flow(error, cleanup_errors)
        failure = ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker identity service startup could not be observed"
        )
        for cleanup_error in cleanup_errors:
            _attach_claude_credential_cleanup_failure(failure, cleanup_error)
        raise failure from error
    if not entered_serve_loop or time.monotonic() > startup_deadline:
        failure = ClaudeCredentialInspectionInconclusive(
            "Claude Keychain broker identity service did not enter its serve loop "
            "before its startup deadline"
        )
        cleanup_errors = _stop_claude_keychain_identity_server(
            runtime,
            deadline=startup_deadline,
        )
        _raise_claude_identity_cleanup_control_flow(None, cleanup_errors)
        for cleanup_error in cleanup_errors:
            _attach_claude_credential_cleanup_failure(failure, cleanup_error)
        serve_error = identity_server.serve_error()
        if serve_error is not None:
            failure.__cause__ = serve_error
        raise failure
    return runtime


def _stop_claude_keychain_identity_server(
    runtime: _ClaudeKeychainIdentityRuntime,
    *,
    deadline: float | None = None,
) -> tuple[BaseException, ...]:
    if deadline is None:
        deadline = time.monotonic() + CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS
    errors: list[BaseException] = []

    def remaining() -> float:
        return max(0.0, deadline - time.monotonic())

    def request_shutdown() -> None:
        try:
            runtime.server.shutdown()
        except BaseException as error:
            errors.append(error)

    shutdown_thread: threading.Thread | None = None
    thread_start_owner = _ClaudeThreadStartOwner()
    shutdown_start_interruption: BaseException | None = None
    try:
        shutdown_thread = threading.Thread(
            target=request_shutdown,
            daemon=True,
            name="claude-review-keychain-identity-shutdown",
        )
        _start_claude_thread_inheriting_forwarded_signal_mask(
            shutdown_thread,
            thread_start_owner=thread_start_owner,
        )
    except BaseException as error:
        shutdown_start_interruption = error
    shutdown_start_snapshot = thread_start_owner.snapshot
    shutdown_start_error = _select_claude_thread_start_related_error(
        shutdown_start_snapshot.error,
        shutdown_start_interruption,
    )
    if shutdown_start_error is not None:
        errors.append(shutdown_start_error)
    if shutdown_thread is not None and shutdown_start_snapshot.may_have_started:
        shutdown_stopped, shutdown_error = _bounded_claude_thread_quiescence(
            shutdown_thread,
            shutdown_start_snapshot.state,
            remaining(),
        )
        if shutdown_error is not None:
            errors.append(shutdown_error)
    else:
        shutdown_stopped = False
    try:
        runtime.server.server_close()
    except BaseException as error:
        errors.append(error)
    try:
        runtime.thread.join(timeout=remaining())
    except BaseException as error:
        errors.append(error)
    serve_stopped = False
    try:
        serve_stopped = not runtime.thread.is_alive()
    except BaseException as error:
        errors.append(error)
    if not shutdown_stopped or not serve_stopped:
        errors.append(
            ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker identity service did not stop"
            )
        )
    try:
        serve_error = runtime.server.serve_error()
    except BaseException as error:
        errors.append(error)
    else:
        if serve_error is not None:
            errors.append(serve_error)
    cleanup_error = _verify_claude_keychain_identity_socket_for_cleanup(
        runtime.socket_path,
        runtime.socket_identity,
        missing_is_error=True,
    )
    if cleanup_error is not None:
        errors.append(cleanup_error)
    return tuple(errors)


@contextlib.contextmanager
def _claude_keychain_credential_server(
    credential: bytearray | None,
    capability: bytes,
    *,
    identity_socket: pathlib.Path,
    allowed_broker_cdhashes: frozenset[bytes] = CLAUDE_KEYCHAIN_BROKER_CDHASHES,
    update_callback: Callable[..., bool] | None = None,
    quiescence_callbacks: _ClaudeKeychainQuiescenceCallbacks | None = None,
) -> Iterator[_ClaudeKeychainBrokerEndpoint]:
    if len(capability) != CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES:
        if credential is not None:
            credential[:] = b"\x00" * len(credential)
        raise ReviewError("Claude Keychain broker capability has an invalid length")
    try:
        server = _ClaudeKeychainCredentialServer(
            credential,
            capability,
            allowed_broker_cdhashes,
            update_callback,
            (
                quiescence_callbacks.write_observed
                if quiescence_callbacks is not None
                else None
            ),
        )
    except BaseException as error:
        if credential is not None:
            credential[:] = b"\x00" * len(credential)
        if isinstance(error, OSError):
            failure_type = (
                ClaudeLoopbackUnavailable
                if _claude_loopback_bind_is_deterministically_unavailable(error)
                else ClaudeCredentialInspectionInconclusive
            )
            raise failure_type(
                f"Claude Keychain broker cannot bind loopback: {error}"
            ) from error
        raise
    try:
        identity_runtime = _start_claude_keychain_identity_server(
            server,
            identity_socket,
        )
    except BaseException as error:
        try:
            server.server_close()
        except BaseException as cleanup_error:
            _attach_claude_credential_cleanup_failure(error, cleanup_error)
        try:
            server.scrub_initial_credential()
        except BaseException as cleanup_error:
            _attach_claude_credential_cleanup_failure(error, cleanup_error)
        if credential is not None:
            credential[:] = b"\x00" * len(credential)
        raise
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
    thread_start_state = _ClaudeThreadStartState.NOT_STARTED
    thread_start_error: BaseException | None = None
    thread_start_owner = _ClaudeThreadStartOwner()
    serve_admitted = False
    runtime_exposed = False
    primary_error: BaseException | None = None
    try:
        serve_cancelled.set()
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
            _start_claude_thread_inheriting_forwarded_signal_mask(
                thread,
                thread_start_owner=thread_start_owner,
            )
            start_snapshot = thread_start_owner.snapshot
            if start_snapshot.error is not None:
                raise start_snapshot.error
        except ForwardedSignal:
            raise
        except Exception as error:
            raise ClaudeCredentialInspectionInconclusive(
                f"Claude Keychain broker cannot start: {error}"
            ) from error
        serve_cancelled.clear()
        serve_admitted = True
        serve_gate.set()
        if not server.wait_until_serving(CLAUDE_KEYCHAIN_SERVER_START_TIMEOUT_SECONDS):
            failure = ClaudeCredentialInspectionInconclusive(
                "Claude Keychain broker did not enter its serve loop"
            )
            serve_error = server.serve_error()
            if serve_error is not None:
                failure.__cause__ = serve_error
            raise failure
        runtime_exposed = True
        yield _ClaudeKeychainBrokerEndpoint(
            port=int(server.server_address[1]),
            identity_socket=identity_socket,
            prepare_runtime_process=_inspect_claude_runtime_process,
            bind_runtime_process=server.bind_runtime_process,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        shutdown_errors: list[BaseException] = []
        start_handoff_error: BaseException | None = None
        try:
            try:
                final_start_snapshot = thread_start_owner.snapshot
                thread_start_state = final_start_snapshot.state
                thread_start_error = final_start_snapshot.error
            finally:
                try:
                    if not serve_admitted:
                        serve_cancelled.set()
                finally:
                    serve_gate.set()
        except BaseException as error:
            start_handoff_error = error
        try:
            shutdown_errors.extend(
                _stop_claude_keychain_identity_server(identity_runtime)
            )
        except BaseException as error:
            shutdown_errors.append(error)
        snapshot_refresh_error: BaseException | None = None
        shutdown = _ClaudeKeychainServerShutdown(
            quiescent=True,
            pending_update=None,
            errors=(),
        )
        try:
            final_start_snapshot = thread_start_owner.snapshot
            thread_start_state = final_start_snapshot.state
            thread_start_error = final_start_snapshot.error
        except BaseException as error:
            snapshot_refresh_error = error
        finally:
            pre_serve_quiescence_unproven = False
            if (
                thread is not None
                and thread_start_state is not _ClaudeThreadStartState.NOT_STARTED
                and not serve_admitted
            ):
                stopped, quiescence_error = _bounded_claude_thread_quiescence(
                    thread,
                    thread_start_state,
                    CLAUDE_KEYCHAIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS,
                )
                if quiescence_error is not None:
                    shutdown_errors.append(quiescence_error)
                if stopped:
                    thread_start_state = _ClaudeThreadStartState.NOT_STARTED
                else:
                    pre_serve_quiescence_unproven = True
                    shutdown_errors.append(
                        ClaudeCredentialInspectionInconclusive(
                            "Claude Keychain broker thread did not publish "
                            "startup and stop after pre-serve cancellation"
                        )
                    )
            shutdown = _ClaudeKeychainServerShutdown(
                quiescent=not pre_serve_quiescence_unproven,
                pending_update=None,
                errors=(),
            )
            if serve_admitted and thread is not None:
                try:
                    shutdown = _bounded_claude_keychain_server_shutdown(
                        server,
                        thread,
                        serve_thread_state=thread_start_state,
                        abandon_callback=(
                            quiescence_callbacks.abandon
                            if runtime_exposed and quiescence_callbacks is not None
                            else None
                        ),
                    )
                except BaseException as error:
                    shutdown_errors.append(error)
                    shutdown = _ClaudeKeychainServerShutdown(
                        quiescent=False,
                        pending_update=None,
                        errors=(),
                    )
                else:
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
        start_cleanup_error = _select_claude_thread_start_related_error(
            thread_start_error,
            start_handoff_error,
        )
        start_cleanup_error = _select_claude_thread_start_related_error(
            start_cleanup_error,
            snapshot_refresh_error,
        )
        if start_cleanup_error is not None and not _claude_visible_error_chain_contains(
            primary_error,
            start_cleanup_error,
        ):
            shutdown_errors.insert(0, start_cleanup_error)
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
                                retention_error = _attach_claude_persistence_failure_preserving_control_flow(
                                    fail_closed_failure,
                                    error,
                                )
                            elif _is_claude_control_flow_error(fail_closed_failure):
                                retention_error = _attach_claude_persistence_failure_preserving_control_flow(
                                    error,
                                    fail_closed_failure,
                                )
                            else:
                                fail_closed_failure = (
                                    _attach_claude_credential_cleanup_failure(
                                        fail_closed_failure,
                                        error,
                                    )
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
                    retention_error = _bounded_claude_keychain_quiescence_recovery(
                        quiescence_callbacks,
                        pending_update,
                        already_abandoned=abandonment_latched,
                    )
                if fail_closed_scope_error is not None:
                    if retention_error is None:
                        retention_error = fail_closed_scope_error
                    elif retention_error is not fail_closed_scope_error:
                        if (
                            _claude_timeout_root_state(retention_error) is not None
                            or _claude_timeout_root_state(fail_closed_scope_error)
                            is not None
                        ):
                            retention_error = _attach_claude_persistence_failure_preserving_control_flow(
                                retention_error,
                                fail_closed_scope_error,
                            )
                        else:
                            _add_claude_persistence_note(
                                retention_error,
                                fail_closed_scope_error,
                            )
                pending_update = None
            if pending_update is not None:
                pending_update[:] = b"\x00" * len(pending_update)
            if retention_error is not None:
                if _claude_timeout_root_state(retention_error) is not None:
                    failure = _attach_claude_credential_cleanup_failure(
                        retention_error,
                        failure,
                    )
                elif getattr(
                    retention_error,
                    "_codex_claude_refresh_persistence_failed",
                    False,
                ):
                    _add_claude_persistence_note(failure, retention_error)
                else:
                    failure = _attach_claude_credential_cleanup_failure(
                        failure,
                        retention_error,
                    )
            for error in shutdown_errors:
                failure = _attach_claude_credential_cleanup_failure(
                    failure,
                    error,
                )
            if _claude_timeout_root_state(failure) is not None:
                candidates = [failure]
            else:
                candidates = [failure, *shutdown_errors]
            if (
                retention_error is not None
                and _is_claude_control_flow_error(retention_error)
                and all(retention_error is not candidate for candidate in candidates)
            ):
                candidates.append(retention_error)
            if _claude_timeout_root_state(failure) is None:
                for candidate in (primary_error, *candidates):
                    if candidate is None:
                        continue
                    if _claude_timeout_root_state(candidate) is not None:
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
                _is_claude_control_flow_error(candidate) for candidate in candidates
            ):
                raise failure
            _raise_or_attach_claude_credential_cleanup(
                primary_error,
                candidates,
                message=("cannot prove Claude Keychain broker handler quiescence"),
            )
        if shutdown.quiescent:
            _raise_or_attach_claude_credential_cleanup(
                primary_error,
                shutdown_errors,
                message="cannot shut down the Claude Keychain broker safely",
            )


@dataclass
class _ClaudeMacOSRefreshTransaction:
    process_started: Callable[[], bool] | None = None
    process_quiescent: Callable[[], bool] | None = None
    _generation_lock: Any = field(
        default_factory=_CLAUDE_THREAD_LOCK_FACTORY,
        init=False,
        repr=False,
    )
    _latest_observed_generation: int = field(default=0, init=False)
    _host_commit_generation: int = field(default=0, init=False)
    _final_carrier_snapshot_generation: int | None = field(
        default=None,
        init=False,
    )

    def observe_refresh(self) -> int:
        with self._generation_lock:
            self._latest_observed_generation += 1
            return self._latest_observed_generation

    def mark_host_commit_verified(self, generation: int) -> None:
        with self._generation_lock:
            self._host_commit_generation = max(
                self._host_commit_generation,
                generation,
            )

    def publish_if_latest_observed(
        self,
        generation: int,
        publish: Callable[[], bool],
    ) -> bool:
        with self._generation_lock:
            if generation != self._latest_observed_generation:
                return False
            return publish()

    def generation_is_latest_observed(self, generation: int) -> bool:
        with self._generation_lock:
            return generation == self._latest_observed_generation

    def refresh_generations(self) -> tuple[int, int]:
        with self._generation_lock:
            return (
                self._latest_observed_generation,
                self._host_commit_generation,
            )

    def mark_final_carrier_snapshot_verified(self) -> None:
        with self._generation_lock:
            self._final_carrier_snapshot_generation = self._latest_observed_generation

    def final_carrier_snapshot_is_verified(self) -> bool:
        with self._generation_lock:
            return (
                self._final_carrier_snapshot_generation is not None
                and self._final_carrier_snapshot_generation
                == self._latest_observed_generation
            )

    def refresh_was_observed(self) -> bool:
        observed_generation, _committed_generation = self.refresh_generations()
        return observed_generation > 0


def _claude_macos_final_carrier_snapshot_is_current(
    review: ReviewWorkspace,
    snapshot: _ClaudeMacOSCarrierSnapshot,
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    transaction: _ClaudeMacOSRefreshTransaction,
    *,
    coordinated_refresh_lock: ClaudeRefreshLockLease,
) -> bool:
    is_current = _claude_macos_carrier_snapshot_is_current(
        review,
        snapshot,
        refresh_lock_protocol,
        coordinated_refresh_lock=coordinated_refresh_lock,
    )
    if is_current:
        transaction.mark_final_carrier_snapshot_verified()
    return is_current


def _claude_macos_refresh_transaction_abandonment_reason(
    review: ReviewWorkspace,
    transaction: _ClaudeMacOSRefreshTransaction,
    error: BaseException | None,
) -> str | None:
    if error is not None and getattr(
        error,
        "_codex_claude_keychain_handler_quiescence_unproven",
        False,
    ):
        return "Keychain broker handler quiescence was not proven"
    retained_cleanup_artifact_declared = error is not None and isinstance(
        getattr(
            error,
            "_codex_claude_retained_cleanup_artifact",
            None,
        ),
        str,
    )
    if retained_cleanup_artifact_declared:
        assert error is not None
        if _validated_claude_retained_cleanup_artifact(review, error) is None:
            return "durable Claude recovery cleanup identity could not be proven"
        return "durable Claude recovery cleanup remained incomplete"
    if transaction.process_started is None:
        return "reviewer process-start state was not tracked"
    try:
        process_started = bool(transaction.process_started())
    except Exception as error:
        if _is_claude_control_flow_error(error):
            raise
        return "reviewer process-start state could not be inspected"
    if process_started:
        if transaction.process_quiescent is None:
            return "reviewer process quiescence was not tracked"
        try:
            process_quiescent = bool(transaction.process_quiescent())
        except Exception as error:
            if _is_claude_control_flow_error(error):
                raise
            return "reviewer process-quiescence state could not be inspected"
        if not process_quiescent:
            return "reviewer process quiescence was not proven"
    observed_generation, committed_generation = transaction.refresh_generations()
    if observed_generation != committed_generation:
        return (
            "the latest observed Claude credential write was not verified "
            "in host carriers"
        )
    if (
        process_started or observed_generation > 0
    ) and not transaction.final_carrier_snapshot_is_verified():
        return "the final Claude credential carrier snapshot was not verified"
    return None


@dataclass(frozen=True)
class _ClaudeMacOSRefreshAbandonmentOutcome:
    error: BaseException
    propagate: bool


def _abandon_claude_macos_refresh_transaction(
    refresh_lock: ClaudeRefreshLockLease,
    reason: str,
    primary_error: BaseException,
) -> _ClaudeMacOSRefreshAbandonmentOutcome:
    try:
        cleanup_error = refresh_lock.abandon(reason)
    except BaseException as error:
        if _is_claude_control_flow_error(error) and not _is_claude_control_flow_error(
            primary_error
        ):
            attach_claude_refresh_lock_recovery(error, primary_error)
            return _ClaudeMacOSRefreshAbandonmentOutcome(
                error=_attach_claude_credential_cleanup_failure(
                    error,
                    primary_error,
                ),
                propagate=True,
            )
        attach_claude_refresh_lock_recovery(primary_error, error)
        return _ClaudeMacOSRefreshAbandonmentOutcome(
            error=_attach_claude_credential_cleanup_failure(
                primary_error,
                error,
            ),
            propagate=False,
        )
    attach_claude_refresh_lock_recovery(primary_error, cleanup_error)
    return _ClaudeMacOSRefreshAbandonmentOutcome(
        error=_attach_claude_credential_cleanup_failure(
            primary_error,
            cleanup_error,
        ),
        propagate=False,
    )


class _ClaudeMacOSPartialPendingSignalWait(Exception):
    def __init__(
        self,
        first_signal: signal.Signals,
        wait_error: BaseException,
    ) -> None:
        super().__init__("later owned pending-signal wait failed")
        self.first_signal = first_signal
        self.wait_error = wait_error


def _select_claude_macos_terminal_handoff_error(
    primary_error: BaseException | None,
    handoff_errors: list[BaseException],
) -> BaseException | None:
    try:
        _raise_or_attach_claude_credential_cleanup(
            primary_error,
            handoff_errors,
            message=(
                "cannot restore forwarded signals after settling the Claude "
                "refresh transaction"
            ),
        )
    except BaseException as selected:
        return selected
    return primary_error


def _begin_claude_macos_terminal_handoff(
    review: ReviewWorkspace,
    refresh_lock: ClaudeRefreshLockLease,
    primary_error: BaseException | None,
    handoff: _ClaudeMacOSTerminalHandoff | None = None,
) -> _ClaudeMacOSTerminalHandoff:
    if handoff is None:
        handoff = _ClaudeMacOSTerminalHandoff(
            persistence_source=primary_error,
        )
    else:
        handoff.persistence_source = primary_error
    deferred_error: BaseException | None = None
    try:
        previous_signal_mask = block_forwarded_signals(
            signal_mask_owner=handoff,
        )
    except BaseException as mask_error:
        selected = (
            mask_error
            if primary_error is None
            else _select_claude_macos_terminal_handoff_error(
                primary_error,
                [mask_error],
            )
        )
        assert selected is not None
        reason = (
            "Claude refresh transaction terminal signal handoff could not be "
            "established"
        )
        _attach_claude_persistence_signal_detail(selected, reason)
        handoff.abandonment_attempted = True
        handoff.recovery_source = selected
        try:
            abandonment = _abandon_claude_macos_refresh_transaction(
                refresh_lock,
                reason,
                selected,
            )
            selected = abandonment.error
            handoff.recovery_source = selected
        except BaseException as abandonment_error:
            binding_errors = _bind_claude_macos_terminal_handoff_recovery(
                review,
                handoff,
                abandonment_error,
                abandonment_error,
            )
            selected_abandonment_error = _select_claude_macos_terminal_handoff_error(
                abandonment_error,
                binding_errors,
            )
            assert selected_abandonment_error is not None
            deferred_error = selected_abandonment_error
        else:
            if primary_error is not None and selected is not primary_error:
                try:
                    selected = _propagate_claude_persistence_state(
                        review,
                        primary_error,
                        selected,
                    )
                except BaseException as validation_error:
                    attach_claude_refresh_lock_recovery(
                        validation_error,
                        selected,
                    )
                    selected = _select_claude_macos_terminal_handoff_error(
                        selected,
                        [validation_error],
                    )
                    assert selected is not None
                    attach_claude_refresh_lock_recovery(
                        selected,
                        validation_error,
                    )
            deferred_error = selected
    if deferred_error is not None:
        raise deferred_error
    if not handoff.owns_previous_signal_mask(previous_signal_mask):
        handoff.publish_previous_signal_mask(previous_signal_mask)
    return handoff


def _settle_claude_macos_refresh_transaction(
    review: ReviewWorkspace,
    transaction: _ClaudeMacOSRefreshTransaction,
    refresh_lock: ClaudeRefreshLockLease,
    primary_error: BaseException | None,
    handoff: _ClaudeMacOSTerminalHandoff,
) -> BaseException | None:
    terminal_error = primary_error
    deferred_terminal_error: BaseException | None = None
    try:
        abandonment_reason = _claude_macos_refresh_transaction_abandonment_reason(
            review,
            transaction,
            primary_error,
        )
        if abandonment_reason is not None and terminal_error is None:
            failure = ClaudeCredentialInspectionInconclusive(
                "Claude local-login refresh transaction ended without a "
                "safe terminal state"
            )
            if transaction.refresh_was_observed():
                setattr(
                    failure,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
            terminal_error = failure
    except BaseException as inspection_error:
        retained_cleanup_artifact_declared = primary_error is not None and isinstance(
            getattr(
                primary_error,
                "_codex_claude_retained_cleanup_artifact",
                None,
            ),
            str,
        )
        inspection_reason = (
            "durable Claude recovery cleanup identity could not be proven"
            if retained_cleanup_artifact_declared
            else ("Claude refresh transaction terminal state could not be inspected")
        )
        terminal_error = (
            inspection_error
            if primary_error is None
            else _attach_claude_persistence_failure_preserving_control_flow(
                primary_error,
                inspection_error,
            )
        )
        _attach_claude_persistence_signal_detail(
            terminal_error,
            inspection_reason,
        )
        handoff.abandonment_attempted = True
        handoff.recovery_source = terminal_error
        if handoff.persistence_source is None and getattr(
            terminal_error,
            "_codex_claude_refresh_persistence_failed",
            False,
        ):
            handoff.persistence_source = terminal_error
        try:
            abandonment = _abandon_claude_macos_refresh_transaction(
                refresh_lock,
                inspection_reason,
                terminal_error,
            )
            terminal_error = abandonment.error
            handoff.recovery_source = terminal_error
        except BaseException as abandonment_error:
            handoff.recovery_source = abandonment_error
            raise
        if terminal_error is primary_error and not abandonment.propagate:
            return terminal_error
        deferred_terminal_error = terminal_error

    if deferred_terminal_error is not None:
        raise deferred_terminal_error

    if abandonment_reason is None:
        return None
    assert terminal_error is not None
    handoff.abandonment_attempted = True
    handoff.recovery_source = terminal_error
    if handoff.persistence_source is None and getattr(
        terminal_error,
        "_codex_claude_refresh_persistence_failed",
        False,
    ):
        handoff.persistence_source = terminal_error
    try:
        abandonment = _abandon_claude_macos_refresh_transaction(
            refresh_lock,
            abandonment_reason,
            terminal_error,
        )
        terminal_error = abandonment.error
        handoff.recovery_source = terminal_error
    except BaseException as abandonment_error:
        handoff.recovery_source = abandonment_error
        raise
    if abandonment.propagate:
        raise terminal_error
    return terminal_error


def _bind_claude_macos_terminal_handoff_recovery(
    review: ReviewWorkspace,
    handoff: _ClaudeMacOSTerminalHandoff,
    error: BaseException,
    primary_error: BaseException | None,
) -> list[BaseException]:
    if not handoff.abandonment_attempted:
        return []
    validation_errors: list[BaseException] = []
    observed_sources: set[int] = set()
    for recovery_source in (
        primary_error,
        handoff.recovery_source,
        handoff.persistence_source,
    ):
        if (
            recovery_source is None
            or recovery_source is error
            or id(recovery_source) in observed_sources
        ):
            continue
        observed_sources.add(id(recovery_source))
        attach_claude_refresh_lock_recovery(error, recovery_source)
        if getattr(
            recovery_source,
            "_codex_claude_refresh_persistence_failed",
            False,
        ):
            try:
                effective_error = _propagate_claude_persistence_state(
                    review,
                    recovery_source,
                    error,
                )
                if effective_error is not error and all(
                    effective_error is not candidate for candidate in validation_errors
                ):
                    validation_errors.append(effective_error)
            except BaseException as validation_error:
                attach_claude_refresh_lock_recovery(
                    validation_error,
                    recovery_source,
                )
                validation_errors.append(validation_error)
    return validation_errors


def _consume_claude_macos_owned_pending_forwarded_signal(
    previous_signal_mask: set[Any] | None,
) -> signal.Signals | None:
    if (
        previous_signal_mask is None
        or not hasattr(signal, "sigpending")
        or not hasattr(signal, "sigwait")
    ):
        return None
    owned_signals = set(forwarded_signals()).difference(previous_signal_mask)
    pending = set(signal.sigpending()).intersection(owned_signals)
    if not pending:
        return None
    ordered = sorted(pending, key=int)
    first_consumed: signal.Signals | None = None
    for pending_signal in ordered:
        try:
            signal.sigwait({pending_signal})
        except BaseException as wait_error:
            if first_consumed is None:
                raise
            raise _ClaudeMacOSPartialPendingSignalWait(
                first_consumed,
                wait_error,
            ) from wait_error
        if first_consumed is None:
            first_consumed = pending_signal
    return first_consumed


def _complete_claude_macos_terminal_handoff(
    review: ReviewWorkspace,
    handoff: _ClaudeMacOSTerminalHandoff,
    primary_error: BaseException | None,
) -> None:
    if handoff.signal_mask_owner_state is _ClaudeSignalMaskOwnerState.UNPUBLISHED:
        handoff.publish_previous_signal_mask(handoff.previous_signal_mask)
    handoff_errors: list[BaseException] = []
    if handoff.previous_signal_mask is not None:
        try:
            pending_signal = _consume_claude_macos_owned_pending_forwarded_signal(
                handoff.previous_signal_mask
            )
            if pending_signal is not None:
                handoff_errors.append(ForwardedSignal(pending_signal))
        except _ClaudeMacOSPartialPendingSignalWait as partial:
            handoff_errors.append(ForwardedSignal(partial.first_signal))
            handoff_errors.append(partial.wait_error)
        except BaseException as error:
            handoff_errors.append(error)
    binding_errors: list[BaseException] = []
    for handoff_error in tuple(handoff_errors):
        binding_errors.extend(
            _bind_claude_macos_terminal_handoff_recovery(
                review,
                handoff,
                handoff_error,
                primary_error,
            )
        )
    handoff_errors.extend(binding_errors)
    selected_error = _select_claude_macos_terminal_handoff_error(
        primary_error,
        handoff_errors,
    )
    if selected_error is not None and all(
        selected_error is not error for error in handoff_errors
    ):
        selected_binding_errors = _bind_claude_macos_terminal_handoff_recovery(
            review,
            handoff,
            selected_error,
            primary_error,
        )
        if selected_binding_errors:
            selected_error = _select_claude_macos_terminal_handoff_error(
                selected_error,
                selected_binding_errors,
            )
    restore_error = _restore_claude_signal_mask_owner_bounded(handoff)
    if restore_error is not None:
        restore_binding_errors = _bind_claude_macos_terminal_handoff_recovery(
            review,
            handoff,
            restore_error,
            primary_error,
        )
        selected_error = _select_claude_macos_terminal_handoff_error(
            selected_error,
            [restore_error, *restore_binding_errors],
        )
        assert selected_error is not None
        raise selected_error
    if selected_error is not None:
        raise selected_error


def _complete_claude_macos_terminal_handoff_with_coordination_translation(
    review: ReviewWorkspace,
    handoff: _ClaudeMacOSTerminalHandoff,
    primary_error: BaseException | None,
) -> None:
    try:
        _complete_claude_macos_terminal_handoff(
            review,
            handoff,
            primary_error,
        )
    except ClaudeRefreshLockError as error:
        if _claude_timeout_root_state(error) is not None:
            raise
        failure = _claude_macos_refresh_lock_coordination_failure(error)
        attach_claude_refresh_lock_recovery(failure, error)
        try:
            effective_failure = _propagate_claude_persistence_state(
                review,
                error,
                failure,
            )
            if effective_failure is error:
                raise
            if effective_failure is not failure:
                raise effective_failure
            failure.__cause__ = error
            failure.__suppress_context__ = True
        except BaseException as validation_error:
            if validation_error is error:
                raise
            attach_claude_refresh_lock_recovery(validation_error, error)
            selected = _select_claude_macos_terminal_handoff_error(
                failure,
                [validation_error],
            )
            assert selected is not None
            if selected is failure:
                raise failure from error
            raise selected
        raise failure from error


@contextlib.contextmanager
def _owned_claude_macos_credentials(
    review: ReviewWorkspace,
) -> Iterator[tuple[_ClaudeLocalCredential, bytearray]]:
    selected: _ClaudeLocalCredential | None = None
    expected_credential: bytearray | None = None
    try:
        selected = _select_claude_macos_credential(review)
        expected_credential = bytearray(selected.payload)
        yield selected, expected_credential
    finally:
        if expected_credential is not None:
            expected_credential[:] = b"\x00" * len(expected_credential)
        if selected is not None:
            selected.payload[:] = b"\x00" * len(selected.payload)


@contextlib.contextmanager
def _claude_keychain_runtime(
    review: ReviewWorkspace,
    env: dict[str, str],
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None,
    *,
    process_started: Callable[[], bool] | None = None,
    process_quiescent: Callable[[], bool] | None = None,
) -> Iterator[dict[str, str]]:
    result = dict(env)
    if _claude_uses_explicit_auth(result):
        yield result
        return
    if refresh_lock_protocol is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude local-login credential-lock protocol is unavailable"
        )
    broker_raw = result.get(CLAUDE_KEYCHAIN_BROKER_EXECUTABLE_ENV)
    if not broker_raw:
        raise ReviewError("Claude Keychain broker executable identity is unavailable")
    broker = pathlib.Path(broker_raw)
    if not broker.is_absolute() or broker.name != "security":
        raise ReviewError("Claude Keychain broker executable identity is invalid")
    identity_directory = _allocate_claude_keychain_identity_directory(review)
    result[CLAUDE_KEYCHAIN_BROKER_IDENTITY_DIRECTORY_ENV] = str(identity_directory)
    identity_socket = identity_directory / CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET_NAME
    transaction = _ClaudeMacOSRefreshTransaction(
        process_started=process_started,
        process_quiescent=process_quiescent,
    )
    handoff: _ClaudeMacOSTerminalHandoff | None = None
    saved_terminal_error: BaseException | None = None
    pre_handoff_error: BaseException | None = None
    deferred_coordination_error: BaseException | None = None
    try:
        with _claude_macos_carrier_coordination(
            refresh_lock_protocol,
            require_explicit_context_release=True,
        ) as refresh_lock:
            refresh_lock.assert_held()
            try:
                with _claude_keychain_runtime_coordinated(
                    review,
                    result,
                    refresh_lock_protocol,
                    refresh_lock,
                    transaction,
                    identity_socket,
                ) as runtime_env:
                    yield runtime_env
            except BaseException as error:
                terminal_error: BaseException | None = error
                pre_handoff_error = terminal_error
                handoff = _ClaudeMacOSTerminalHandoff(
                    persistence_source=terminal_error,
                )
                _begin_claude_macos_terminal_handoff(
                    review,
                    refresh_lock,
                    terminal_error,
                    handoff,
                )
            else:
                terminal_error = None
                handoff = _ClaudeMacOSTerminalHandoff(
                    persistence_source=terminal_error,
                )
                _begin_claude_macos_terminal_handoff(
                    review,
                    refresh_lock,
                    terminal_error,
                    handoff,
                )
            failure = _settle_claude_macos_refresh_transaction(
                review,
                transaction,
                refresh_lock,
                terminal_error,
                handoff,
            )
            if failure is not None:
                raise failure
            saved_terminal_error = terminal_error
    except BaseException as coordination_error:
        if handoff is None or not handoff.signal_mask_owner_active:
            selected_error = coordination_error
            persistence_source = pre_handoff_error
            if persistence_source is None:
                (
                    persistence_source,
                    persistence_graph_complete,
                ) = _claude_persistence_source_from_error_graph(coordination_error)
                if not persistence_graph_complete:
                    setattr(
                        coordination_error,
                        "_codex_claude_refresh_persistence_failed",
                        True,
                    )
                    _attach_claude_persistence_signal_detail(
                        coordination_error,
                        CLAUDE_REFRESH_PERSISTENCE_DIAGNOSTIC,
                    )
            if (
                persistence_source is not None
                and persistence_source is not coordination_error
            ):
                attach_claude_refresh_lock_recovery(
                    coordination_error,
                    persistence_source,
                )
                try:
                    selected_error = _propagate_claude_persistence_state(
                        review,
                        persistence_source,
                        coordination_error,
                    )
                except BaseException as validation_error:
                    attach_claude_refresh_lock_recovery(
                        validation_error,
                        persistence_source,
                    )
                    selected = _select_claude_macos_terminal_handoff_error(
                        coordination_error,
                        [validation_error],
                    )
                    assert selected is not None
                    selected_error = selected
                    if selected_error is not coordination_error:
                        attach_claude_refresh_lock_recovery(
                            selected_error,
                            coordination_error,
                        )
            if selected_error is coordination_error:
                raise
            deferred_coordination_error = selected_error
        else:
            selected_error = coordination_error
            if (
                saved_terminal_error is not None
                and saved_terminal_error is not coordination_error
            ):
                selected = _select_claude_macos_terminal_handoff_error(
                    saved_terminal_error,
                    [coordination_error],
                )
                assert selected is not None
                selected_error = selected
                if selected_error is not coordination_error:
                    attach_claude_refresh_lock_recovery(
                        selected_error,
                        coordination_error,
                    )
            _complete_claude_macos_terminal_handoff_with_coordination_translation(
                review,
                handoff,
                selected_error,
            )
            raise
    if deferred_coordination_error is not None:
        raise deferred_coordination_error
    assert handoff is not None
    _complete_claude_macos_terminal_handoff_with_coordination_translation(
        review,
        handoff,
        saved_terminal_error,
    )


@contextlib.contextmanager
def _claude_keychain_runtime_coordinated(
    review: ReviewWorkspace,
    env: dict[str, str],
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    coordinated_refresh_lock: ClaudeRefreshLockLease,
    transaction: _ClaudeMacOSRefreshTransaction,
    identity_socket: pathlib.Path,
) -> Iterator[dict[str, str]]:
    result = dict(env)
    with _owned_claude_macos_credentials(review) as (
        selected,
        expected_credential,
    ):
        coordinated_refresh_lock.assert_held()
        with _claude_keychain_runtime_selected(
            review,
            result,
            refresh_lock_protocol,
            selected,
            expected_credential,
            identity_socket,
            coordinated_refresh_lock,
            transaction,
        ) as runtime_environment:
            yield runtime_environment


@contextlib.contextmanager
def _claude_keychain_runtime_selected(
    review: ReviewWorkspace,
    result: dict[str, str],
    refresh_lock_protocol: ClaudeRefreshLockProtocol,
    selected: _ClaudeLocalCredential,
    expected_credential: bytearray,
    identity_socket: pathlib.Path,
    coordinated_refresh_lock: ClaudeRefreshLockLease,
    transaction: _ClaudeMacOSRefreshTransaction,
) -> Iterator[dict[str, str]]:
    carrier_snapshot = selected.carrier_snapshot
    if carrier_snapshot is None:
        raise ReviewError("Claude macOS carrier snapshot is unavailable")
    try:
        fail_closed_recovery_root = _claude_macos_recovery_root(review)
    except BaseException as error:
        if _is_claude_control_flow_error(error):
            raise
        failure = ClaudeCredentialInspectionInconclusive(
            "the macOS Claude fail-closed recovery scope could not be initialized"
        )
        failure.__cause__ = error
        raise failure
    persistence_errors: list[BaseException] = []
    persisted_updates = 0
    runtime_state_lock = threading.Lock()
    runtime_abandon_requested = _ClaudeThreadEvent()
    staged_credential: bytearray | None = None
    staged_credential_generation: int | None = None
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
    quiescence_recovery_timeout_root_state = _ClaudeTimeoutRootState(
        lock=threading.RLock(),
        fail_closed_root=fail_closed_recovery_root,
    )
    quiescence_recovery_timeout_failure_lock = (
        quiescence_recovery_timeout_root_state.lock
    )
    sealed_timeout_note = _CLAUDE_TIMEOUT_SEALED_SAFE_NOTE
    late_timeout_control_flow_note = _CLAUDE_TIMEOUT_LATE_CONTROL_FLOW_NOTE
    late_timeout_ordinary_note = _CLAUDE_TIMEOUT_LATE_ORDINARY_NOTE

    def publish_quiescence_timeout_failure(
        error: BaseException,
    ) -> BaseException:
        nonlocal quiescence_recovery_timeout_failure
        with quiescence_recovery_timeout_failure_lock:
            if quiescence_recovery_timeout_failure is None:
                quiescence_recovery_timeout_failure = error
            return quiescence_recovery_timeout_failure

    def snapshot_quiescence_timeout_failure() -> BaseException | None:
        with quiescence_recovery_timeout_failure_lock:
            return quiescence_recovery_timeout_failure

    def safe_finalize_quiescence_timeout_failure(
        current: BaseException,
    ) -> BaseException:
        proof = _get_claude_retained_credential_proof(current)
        cleanup_artifact = getattr(
            current,
            "_codex_claude_retained_cleanup_artifact",
            None,
        )
        descriptor_bound, recovery_incomplete = _claude_cleanup_recovery_state(current)
        visible_link = isinstance(current.__cause__, BaseException) or (
            not current.__suppress_context__
            and isinstance(current.__context__, BaseException)
        )
        recovery_incomplete = recovery_incomplete or visible_link
        if _claude_exception_group_children(current):
            current = _safe_claude_cleanup_group_root(
                current,
                note=sealed_timeout_note,
                descriptor_bound=descriptor_bound,
                recovery_incomplete=recovery_incomplete,
            )
        else:
            _sanitize_claude_cleanup_primary_root(
                current,
                note=sealed_timeout_note,
                recovery_incomplete=recovery_incomplete,
            )
        _clear_claude_retained_credential_proof(current)
        with contextlib.suppress(AttributeError):
            delattr(current, "_codex_claude_retained_credential_carrier")
        if proof is not None:
            _set_claude_retained_credential_proof(current, proof)
            setattr(
                current,
                "_codex_claude_retained_credential_carrier",
                str(proof.artifact.parent.parent),
            )
        if cleanup_artifact == str(fail_closed_recovery_root):
            setattr(
                current,
                "_codex_claude_retained_cleanup_artifact",
                cleanup_artifact,
            )
        else:
            with contextlib.suppress(AttributeError):
                delattr(current, "_codex_claude_retained_cleanup_artifact")
        setattr(current, "_codex_claude_refresh_persistence_failed", True)
        setattr(
            current,
            "_codex_claude_keychain_handler_quiescence_unproven",
            True,
        )
        setattr(current, "_codex_claude_timeout_root_sealed_safe", True)
        return current

    def merge_late_quiescence_timeout_transform(
        current: BaseException,
        transform: Callable[[BaseException], BaseException],
        *,
        late_control_flow_hint: bool | None,
    ) -> BaseException:
        detached = ClaudeCredentialInspectionInconclusive(late_timeout_ordinary_note)
        setattr(
            detached,
            "_codex_claude_refresh_lock_descriptor_bound",
            True,
        )
        setattr(detached, "_codex_claude_cleanup_graph_incomplete", True)
        proof = _get_claude_retained_credential_proof(current)
        if proof is not None:
            _set_claude_retained_credential_proof(detached, proof)
            setattr(
                detached,
                "_codex_claude_retained_credential_carrier",
                str(proof.artifact.parent.parent),
            )
        try:
            transformed = transform(detached)
        except BaseException as late_error:
            transformed = late_error
        transformed_proof = _get_claude_retained_credential_proof(transformed)
        if transformed_proof is None:
            _clear_claude_retained_credential_proof(current)
            with contextlib.suppress(AttributeError):
                delattr(current, "_codex_claude_retained_credential_carrier")
        else:
            _set_claude_retained_credential_proof(current, transformed_proof)
            setattr(
                current,
                "_codex_claude_retained_credential_carrier",
                str(transformed_proof.artifact.parent.parent),
            )
        quiescence_recovery_timeout_root_state.proof_revision += 1
        transformed_is_control_flow = _is_claude_control_flow_error(transformed)
        late_control_flow = (
            True if transformed_is_control_flow else late_control_flow_hint
        )
        if late_control_flow is not None:
            count_attribute = (
                "_codex_claude_timeout_late_control_flow_count"
                if late_control_flow
                else "_codex_claude_timeout_late_ordinary_count"
            )
            prior_count = getattr(current, count_attribute, 0)
            if not isinstance(prior_count, int) or prior_count < 0:
                prior_count = 0
            setattr(
                current,
                count_attribute,
                min(prior_count + 1, sys.maxsize),
            )
            if prior_count == 0:
                add_note = getattr(current, "add_note", None)
                if callable(add_note):
                    add_note(
                        late_timeout_control_flow_note
                        if late_control_flow
                        else late_timeout_ordinary_note
                    )
        transformed_cleanup = getattr(
            transformed,
            "_codex_claude_retained_cleanup_artifact",
            None,
        )
        if (
            transformed_proof is None
            or late_control_flow is not None
            or isinstance(transformed_cleanup, str)
        ):
            setattr(
                current,
                "_codex_claude_retained_cleanup_artifact",
                str(fail_closed_recovery_root),
            )
            quiescence_recovery_timeout_root_state.scope_required = True
        setattr(current, "_codex_claude_cleanup_graph_incomplete", True)
        setattr(current, "_codex_claude_timeout_root_sealed_safe", True)
        setattr(
            current,
            "_codex_claude_timeout_root_state",
            quiescence_recovery_timeout_root_state,
        )
        return current

    def transform_quiescence_timeout_failure(
        transform: Callable[[BaseException], BaseException],
        *,
        late_control_flow_hint: bool | None = None,
    ) -> BaseException | None:
        nonlocal quiescence_recovery_timeout_failure
        with quiescence_recovery_timeout_failure_lock:
            current = quiescence_recovery_timeout_failure
            if current is None:
                return None
            if quiescence_recovery_timeout_root_state.sealed:
                return merge_late_quiescence_timeout_transform(
                    current,
                    transform,
                    late_control_flow_hint=late_control_flow_hint,
                )
            current = transform(current)
            quiescence_recovery_timeout_failure = current
            return current

    def seal_quiescence_timeout_failure(
        transform: Callable[[BaseException], BaseException],
        *,
        recovery_expectation: _ClaudeRecoveryExpectation | None,
        cleanup_scope_required: bool,
        prevalidated_published: bool,
    ) -> BaseException | None:
        nonlocal quiescence_recovery_timeout_failure
        with quiescence_recovery_timeout_failure_lock:
            current = quiescence_recovery_timeout_failure
            if current is None:
                return None
            if quiescence_recovery_timeout_root_state.sealed:
                return current
            current = transform(current)
            proof = _get_claude_retained_credential_proof(current)
            retained_value = getattr(
                current,
                "_codex_claude_retained_credential_carrier",
                None,
            )
            proof_matches_expectation = (
                recovery_expectation is not None
                and proof is not None
                and isinstance(retained_value, str)
                and pathlib.Path(retained_value) == recovery_expectation.carrier
                and proof.artifact == recovery_expectation.artifact
                and hmac.compare_digest(
                    proof.digest,
                    recovery_expectation.digest,
                )
                and _validated_claude_retained_credential_artifact(
                    review,
                    current,
                )
                == str(proof.artifact)
                and _get_claude_retained_credential_proof(current) is proof
            )
            if prevalidated_published != proof_matches_expectation:
                quiescence_recovery_timeout_root_state.proof_revision += 1
            effective_scope_required = (
                cleanup_scope_required or not proof_matches_expectation
            )
            if effective_scope_required:
                if not proof_matches_expectation:
                    _clear_claude_retained_credential_proof(current)
                    with contextlib.suppress(AttributeError):
                        delattr(
                            current,
                            "_codex_claude_retained_credential_carrier",
                        )
                _mark_claude_macos_recovery_cleanup_artifact(
                    current,
                    fail_closed_recovery_root,
                )
            else:
                with contextlib.suppress(AttributeError):
                    delattr(
                        current,
                        "_codex_claude_retained_cleanup_artifact",
                    )
            current = safe_finalize_quiescence_timeout_failure(current)
            quiescence_recovery_timeout_failure = current
            quiescence_recovery_timeout_root_state.root = current
            quiescence_recovery_timeout_root_state.sealed = True
            quiescence_recovery_timeout_root_state.scope_required = (
                effective_scope_required
            )
            setattr(
                current,
                "_codex_claude_timeout_root_state",
                quiescence_recovery_timeout_root_state,
            )
            return current

    def attach_quiescence_timeout_failure(
        secondary: BaseException,
    ) -> BaseException | None:
        return transform_quiescence_timeout_failure(
            lambda current: _attach_claude_credential_cleanup_failure(
                current,
                secondary,
            ),
            late_control_flow_hint=_is_claude_control_flow_error(secondary),
        )

    def _set_timeout_recovery_carrier(
        error: BaseException,
        carrier: pathlib.Path,
    ) -> BaseException:
        setattr(
            error,
            "_codex_claude_retained_credential_carrier",
            str(carrier),
        )
        return error

    def mark_quiescence_timeout_recovery_artifact(
        artifact: pathlib.Path,
        *,
        expected_digest: bytes,
    ) -> BaseException | None:
        try:
            proof = _capture_claude_retained_credential_proof(
                artifact,
                expected_digest=expected_digest,
            )
        except BaseException as proof_error:
            proof_failure = proof_error

            def apply_failure(error: BaseException) -> BaseException:
                _clear_claude_retained_credential_proof(error)
                if _is_claude_control_flow_error(error):
                    return _attach_claude_credential_cleanup_failure(
                        error,
                        proof_failure,
                    )
                if _is_claude_control_flow_error(proof_failure):
                    return _attach_claude_credential_cleanup_failure(
                        proof_failure,
                        error,
                    )
                return _attach_claude_credential_cleanup_failure(
                    error,
                    proof_failure,
                )

            return transform_quiescence_timeout_failure(
                apply_failure,
                late_control_flow_hint=_is_claude_control_flow_error(proof_failure),
            )

        def apply_proof(error: BaseException) -> BaseException:
            _set_claude_retained_credential_proof(error, proof)
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note(
                    "A macOS Claude recovery credential update remains at "
                    f"{artifact} for operator inspection."
                )
            return error

        return transform_quiescence_timeout_failure(apply_proof)

    def runtime_is_abandoned() -> bool:
        return runtime_abandon_requested.is_set()

    def transfer_abandoned_stage_locked(
        stage: _ClaudeMacOSDurableStage,
    ) -> bool:
        nonlocal durable_stage_inflight
        nonlocal quiescence_durable_stage
        if not runtime_is_abandoned() or durable_stage_inflight is not stage:
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
        return _validated_claude_retained_credential_artifact(
            review,
            error,
        ) == str(proof.artifact)

    def cleanup_late_durable_stage(
        stage: _ClaudeMacOSDurableStage,
    ) -> None:
        with runtime_state_lock:
            authoritative_expectation = quiescence_recovery_expectation
        effective_cleanup_error: BaseException | None = None
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
                cleanup_error = _mark_claude_macos_recovery_update_artifact(
                    cleanup_error,
                    authoritative_expectation.artifact,
                    expected_digest=authoritative_expectation.digest,
                )
            setattr(
                cleanup_error,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            with runtime_state_lock:
                if _is_claude_control_flow_error(cleanup_error):
                    persistence_errors.insert(0, cleanup_error)
                else:
                    persistence_errors.append(cleanup_error)
            effective_cleanup_error = cleanup_error
        else:
            with runtime_state_lock:
                durable_stage_carriers[:] = [
                    carrier
                    for carrier in durable_stage_carriers
                    if carrier[0] != stage.committed_carrier
                ]
        if effective_cleanup_error is not None:
            raise effective_cleanup_error

    def stage_refreshed_credential(
        updated: bytearray,
        commit_pending: Callable[[Callable[[], bool]], bool] | None = None,
        claim_terminal: Callable[[], bool] | None = None,
        observed_generation: int | None = None,
    ) -> bool:
        nonlocal durable_stage_generation, staged_credential
        nonlocal staged_credential_generation
        nonlocal durable_stage_reserved_generations
        nonlocal durable_stage_reserved_bytes
        nonlocal durable_stage_quota_exhausted_error
        nonlocal durable_stage_inflight
        nonlocal quiescence_recovery_candidate
        nonlocal quiescence_recovery_proven
        nonlocal quiescence_recovery_replaces_existing
        nonlocal quiescence_recovery_expectation
        if observed_generation is None:
            observed_generation = transaction.observe_refresh()
        if not transaction.generation_is_latest_observed(observed_generation):
            return False
        previous_staged_credential: bytearray | None = None

        def retire_superseded_generation() -> bool:
            nonlocal previous_staged_credential
            nonlocal staged_credential, staged_credential_generation
            with runtime_state_lock:
                if runtime_is_abandoned():
                    return False
                previous_staged_credential = staged_credential
                staged_credential = None
                staged_credential_generation = None
            return True

        if not transaction.publish_if_latest_observed(
            observed_generation,
            retire_superseded_generation,
        ):
            return False
        if previous_staged_credential is not None:
            previous_staged_credential[:] = b"\x00" * len(previous_staged_credential)
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
                malformed = _mark_claude_macos_recovery_update_artifact(
                    malformed,
                    retained_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
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
                durable_stage_reserved_generations >= normal_generation_limit
                or durable_stage_reserved_bytes + requested_bytes > normal_byte_limit
            )
            if not terminal_generation:
                durable_stage_reserved_generations += 1
                durable_stage_reserved_bytes += requested_bytes
                durable_stage_generation += 1
                generation = durable_stage_generation
        if terminal_generation:
            try:
                terminal_claimed = True if claim_terminal is None else claim_terminal()
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
                    claim_failure = _mark_claude_macos_recovery_update_artifact(
                        claim_failure,
                        retained_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
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
                quota_failure = _mark_claude_macos_recovery_update_artifact(
                    quota_failure,
                    retained_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=retained_digest,
                )
            with runtime_state_lock:
                persistence_errors.append(quota_failure)
            return False
        assert generation is not None
        setup_control_flow: BaseException | None = None
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
                    "the macOS Claude durable recovery stage could not be initialized"
                )
                setup_failure.__cause__ = setup_error
            setattr(
                setup_failure,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            with runtime_state_lock:
                previous_durable_entry = (
                    durable_stage_carriers[-1] if durable_stage_carriers else None
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
                setup_failure = _mark_claude_macos_recovery_update_artifact(
                    setup_failure,
                    previous_durable_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=previous_durable_digest,
                )
            setattr(
                setup_failure,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            with runtime_state_lock:
                persistence_errors.append(setup_failure)
            if _is_claude_control_flow_error(setup_error):
                setup_control_flow = setup_failure
            else:
                return False
        if setup_control_flow is not None:
            raise setup_control_flow
        committed_carrier: pathlib.Path | None = None
        staged: bytearray | None = None
        stage_control_flow: BaseException | None = None
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
                error = _mark_claude_macos_recovery_update_artifact(
                    error,
                    committed_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=stage.credential_digest,
                )
                setattr(
                    error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
            with runtime_state_lock:
                stage.error = error
                transferred_to_recovery = transfer_abandoned_stage_locked(stage)
                if not transferred_to_recovery and durable_stage_inflight is stage:
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
                            error = _attach_claude_credential_cleanup_failure(
                                error,
                                cleanup_error,
                            )
                            with runtime_state_lock:
                                stage.error = error
                    else:
                        for attribute in (
                            "_codex_claude_retained_credential_carrier",
                            "_codex_claude_retained_cleanup_artifact",
                        ):
                            value = getattr(error, attribute, None)
                            if not isinstance(value, str):
                                continue
                            with contextlib.suppress(ValueError):
                                pathlib.Path(value).relative_to(cleanup_candidate)
                                delattr(error, attribute)
                        proof = _get_claude_retained_credential_proof(error)
                        if proof is not None:
                            with contextlib.suppress(ValueError):
                                proof.artifact.relative_to(cleanup_candidate)
                                _clear_claude_retained_credential_proof(error)
            if not isinstance(retained_candidate, str):
                with runtime_state_lock:
                    previous_durable_entry = (
                        durable_stage_carriers[-1] if durable_stage_carriers else None
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
                    error = _mark_claude_macos_recovery_update_artifact(
                        error,
                        previous_durable_carrier
                        / "config"
                        / CLAUDE_CREDENTIAL_FILE_NAME,
                        expected_digest=previous_durable_digest,
                    )
                setattr(
                    error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
            with runtime_state_lock:
                stage.error = error
                if not runtime_is_abandoned():
                    persistence_errors.append(error)
            if _is_claude_control_flow_error(error):
                stage_control_flow = error
            else:
                return False
        if stage_control_flow is not None:
            raise stage_control_flow
        assert staged is not None
        assert committed_carrier is not None

        if abandoned_after_commit:
            staged[:] = b"\x00" * len(staged)
            if cleanup_late_carrier:
                decision_ready = stage.recovery_decided.wait(
                    timeout=CLAUDE_KEYCHAIN_RECOVERY_TIMEOUT_SECONDS
                )
                with runtime_state_lock:
                    if not decision_ready and not stage.recovery_decided.is_set():
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
            quota_failure = _mark_claude_macos_recovery_update_artifact(
                quota_failure,
                committed_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
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
            nonlocal staged_credential_generation
            nonlocal superseded_staged_credential
            nonlocal quiescence_recovery_candidate
            nonlocal quiescence_recovery_proven
            nonlocal quiescence_recovery_replaces_existing
            nonlocal quiescence_recovery_expectation

            def publish_latest() -> bool:
                nonlocal durable_stage_inflight, staged_credential
                nonlocal staged_credential_generation
                nonlocal superseded_staged_credential
                nonlocal quiescence_recovery_candidate
                nonlocal quiescence_recovery_proven
                nonlocal quiescence_recovery_replaces_existing
                nonlocal quiescence_recovery_expectation
                with runtime_state_lock:
                    if runtime_is_abandoned():
                        return False
                    superseded_staged_credential = staged_credential
                    staged_credential = staged
                    staged_credential_generation = observed_generation
                    quiescence_recovery_candidate = committed_carrier
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    quiescence_recovery_expectation = _ClaudeRecoveryExpectation(
                        committed_carrier,
                        committed_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                        stage.credential_digest,
                    )
                    if durable_stage_inflight is stage:
                        durable_stage_inflight = None
                return True

            return transaction.publish_if_latest_observed(
                observed_generation,
                publish_latest,
            )

        superseded_staged_credential: bytearray | None = None
        publish_control_flow: BaseException | None = None
        try:
            if commit_pending is None:
                committed_current = publish_current_generation()
            else:
                committed_current = commit_pending(publish_current_generation)
        except BaseException as publish_error:
            staged[:] = b"\x00" * len(staged)
            setattr(
                publish_error,
                "_codex_claude_retained_credential_carrier",
                str(committed_carrier),
            )
            publish_error = _mark_claude_macos_recovery_update_artifact(
                publish_error,
                committed_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                expected_digest=stage.credential_digest,
            )
            setattr(
                publish_error,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            with runtime_state_lock:
                transferred_to_recovery = transfer_abandoned_stage_locked(stage)
                if not transferred_to_recovery and durable_stage_inflight is stage:
                    durable_stage_inflight = None
                if _is_claude_control_flow_error(publish_error):
                    persistence_errors.insert(0, publish_error)
                else:
                    persistence_errors.append(publish_error)
            if _is_claude_control_flow_error(publish_error):
                publish_control_flow = publish_error
            else:
                return False
        if publish_control_flow is not None:
            raise publish_control_flow
        if committed_current:
            if superseded_staged_credential is not None:
                superseded_staged_credential[:] = b"\x00" * len(
                    superseded_staged_credential
                )
            return True
        staged[:] = b"\x00" * len(staged)
        with runtime_state_lock:
            transferred_to_recovery = transfer_abandoned_stage_locked(stage)
            if not transferred_to_recovery and durable_stage_inflight is stage:
                durable_stage_inflight = None
        return False

    def accept_refreshed_credential(
        updated: bytearray,
        observed_generation: int,
    ) -> bool:
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
                prior_error = persistence_errors[0] if persistence_errors else None
                callback_carrier_snapshot = carrier_snapshot
                callback_expected_credential = bytearray(expected_credential)
            if prior_error is not None:
                callback_expected_credential[:] = b"\x00" * len(
                    callback_expected_credential
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
                    quiescence_recovery_proven = prior_expectation is not None
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
                        retained_carrier = _retain_claude_macos_refreshed_credential(
                            review,
                            updated,
                            requested_carrier_root=recovery_candidate,
                        )
                except BaseException as recovery_error:
                    failed_recovery_expectation = recovery_expectation_from_error(
                        recovery_error,
                        recovery_candidate,
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
                            if quiescence_recovery_candidate == recovery_candidate:
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
                retained_cleanup_artifact = _validated_claude_retained_cleanup_artifact(
                    review,
                    prior_error,
                )
                if retained_cleanup_artifact is not None:
                    setattr(
                        retained_error,
                        "_codex_claude_retained_cleanup_artifact",
                        retained_cleanup_artifact,
                    )
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
                        quiescence_recovery_expectation = _ClaudeRecoveryExpectation(
                            retained_carrier,
                            retained_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                            updated_digest,
                        )
                        if deferred_persistence_note is not None:
                            _add_claude_persistence_note(
                                prior_error,
                                deferred_persistence_note,
                            )
                        persistence_errors[0] = replacement_error
                return False
            if (
                selected.source == "macos-keychain"
                or _claude_macos_carriers_share_refresh_token(callback_carrier_snapshot)
            ) and not _claude_keychain_credential_has_refresh_margin(updated):
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
                coordinated_refresh_lock=coordinated_refresh_lock,
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
            transaction.mark_host_commit_verified(observed_generation)
            return True
        except BaseException as error:
            callback_recovery_candidate: pathlib.Path | None = None
            try:
                proposed_recovery_candidate = new_recovery_candidate()
                with runtime_state_lock:
                    if runtime_is_abandoned():
                        return False
                    if quiescence_recovery_candidate is None:
                        quiescence_recovery_candidate = proposed_recovery_candidate
                        quiescence_recovery_replaces_existing = False
                        quiescence_recovery_proven = False
                        quiescence_recovery_expectation = None
                    callback_recovery_candidate = quiescence_recovery_candidate
                    callback_replaces_existing = quiescence_recovery_replaces_existing
                assert callback_recovery_candidate is not None
                if callback_replaces_existing:
                    _replace_claude_macos_recovery_credential(
                        review,
                        callback_recovery_candidate,
                        updated,
                    )
                    retained_carrier = callback_recovery_candidate
                else:
                    retained_carrier = _retain_claude_macos_refreshed_credential(
                        review,
                        updated,
                        requested_carrier_root=(callback_recovery_candidate),
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
                persistence_error = retained_error
                recovered_carrier = True
            with runtime_state_lock:
                if runtime_is_abandoned():
                    return False
                if recovered_carrier:
                    quiescence_recovery_candidate = retained_carrier
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    quiescence_recovery_expectation = _ClaudeRecoveryExpectation(
                        retained_carrier,
                        retained_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                        updated_digest,
                    )
                elif (
                    callback_recovery_candidate is not None
                    and quiescence_recovery_candidate == callback_recovery_candidate
                ):
                    if failed_recovery_expectation is not None:
                        quiescence_recovery_replaces_existing = True
                        quiescence_recovery_proven = True
                        quiescence_recovery_expectation = failed_recovery_expectation
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
                            persistence_error = (
                                _attach_claude_credential_cleanup_failure(
                                    persistence_error,
                                    prior_error,
                                )
                            )
                        persistence_errors[0] = persistence_error
            return False
        finally:
            if callback_expected_credential is not None:
                callback_expected_credential[:] = b"\x00" * len(
                    callback_expected_credential
                )

    def abandon_unquiescent_handler() -> None:
        runtime_abandon_requested.set()

    def recover_unquiescent_handler(
        updated: bytearray | None,
    ) -> BaseException | None:
        nonlocal durable_stage_inflight
        nonlocal staged_credential
        nonlocal staged_credential_generation
        nonlocal quiescence_durable_stage
        nonlocal quiescence_recovery_candidate
        nonlocal quiescence_recovery_proven
        nonlocal quiescence_recovery_replaces_existing
        nonlocal quiescence_recovery_expectation
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
            staged_credential_generation = None
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
            if _claude_timeout_root_state(error) is not None:
                return error
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
            if current_claim_present and not published_recovery_claim_is_current(error):
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
                error = _attach_claude_persistence_failure_preserving_control_flow(
                    error,
                    root_error,
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
                if inflight_stage.completed.is_set() and inflight_stage.committed:
                    recovery_candidate = inflight_stage.committed_carrier
                    replace_existing = True
                    recovery_proven = True
                    quiescence_recovery_candidate = recovery_candidate
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    recovery_expectation = _ClaudeRecoveryExpectation(
                        recovery_candidate,
                        recovery_candidate / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
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
                inflight_stage.recovery_decided.set()
                setattr(
                    quiescence_error,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                persistence_error = quiescence_error
                timeout_failure = attach_quiescence_timeout_failure(quiescence_error)
                if timeout_failure is not None:
                    persistence_error = timeout_failure
                return ensure_recovery_scope(persistence_error)
            with runtime_state_lock:
                if inflight_stage.committed:
                    recovery_candidate = inflight_stage.committed_carrier
                    replace_existing = True
                    recovery_proven = True
                    recovery_expectation = _ClaudeRecoveryExpectation(
                        recovery_candidate,
                        recovery_candidate / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
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
                and inflight_expectation.digest != inflight_stage.credential_digest
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
                        quiescence_error = _attach_claude_credential_cleanup_failure(
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
            retained_proof = _get_claude_retained_credential_proof(persistence_error)

            def merge_timeout_failure(
                timeout_failure: BaseException,
            ) -> BaseException:
                if retained_proof is not None:
                    setattr(
                        timeout_failure,
                        "_codex_claude_retained_credential_carrier",
                        str(retained_proof.artifact.parent.parent),
                    )
                    _copy_claude_retained_credential_proof(
                        persistence_error,
                        timeout_failure,
                    )
                return _attach_claude_credential_cleanup_failure(
                    timeout_failure,
                    persistence_error,
                )

            timeout_failure = transform_quiescence_timeout_failure(
                merge_timeout_failure,
                late_control_flow_hint=_is_claude_control_flow_error(persistence_error),
            )
            if timeout_failure is not None:
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
                    replace_existing = quiescence_recovery_replaces_existing
                    recovery_expectation = quiescence_recovery_expectation
                    recovery_proven = (
                        quiescence_recovery_proven
                        and recovery_expectation is not None
                        and recovery_expectation.carrier == recovery_candidate
                    )
        recovery_succeeded = False
        recovery_payload_digest = _claude_credential_digest(recovery_payload)
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
                recovery_error = _mark_claude_macos_recovery_update_artifact(
                    recovery_error,
                    recovery_expectation.artifact,
                    expected_digest=recovery_expectation.digest,
                )
            setattr(
                recovery_error,
                "_codex_claude_refresh_persistence_failed",
                True,
            )
            failed_recovery_error = recovery_error
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
                    recovery_candidate = failed_recovery_expectation.carrier
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

            def merge_failed_recovery(
                timeout_failure: BaseException,
            ) -> BaseException:
                if failed_recovery_expectation is not None:
                    setattr(
                        timeout_failure,
                        "_codex_claude_retained_credential_carrier",
                        str(failed_recovery_expectation.carrier),
                    )
                    _copy_claude_retained_credential_proof(
                        failed_recovery_error,
                        timeout_failure,
                    )
                return _attach_claude_credential_cleanup_failure(
                    timeout_failure,
                    persistence_error,
                )

            timeout_failure = transform_quiescence_timeout_failure(
                merge_failed_recovery,
                late_control_flow_hint=_is_claude_control_flow_error(persistence_error),
            )
            recovery_timed_out = timeout_failure is not None
            if recovery_timed_out and timeout_failure is not None:
                persistence_error = timeout_failure
        else:
            successful_expectation = _ClaudeRecoveryExpectation(
                retained_carrier,
                retained_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                recovery_payload_digest,
            )
            timeout_failure = snapshot_quiescence_timeout_failure()
            recovery_timed_out = timeout_failure is not None
            with runtime_state_lock:
                if not recovery_timed_out or (replace_existing and recovery_proven):
                    quiescence_recovery_candidate = retained_carrier
                    quiescence_recovery_replaces_existing = True
                    quiescence_recovery_proven = True
                    quiescence_recovery_expectation = successful_expectation
            if (
                recovery_timed_out
                and timeout_failure is not None
                and replace_existing
                and recovery_proven
            ):
                timeout_failure = transform_quiescence_timeout_failure(
                    lambda current: _set_timeout_recovery_carrier(
                        current,
                        retained_carrier,
                    )
                )
                timeout_failure = mark_quiescence_timeout_recovery_artifact(
                    retained_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=recovery_payload_digest,
                )
            if recovery_timed_out and not (replace_existing and recovery_proven):
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
                    timeout_failure = publish_quiescence_timeout_failure(
                        timeout_failure
                    )
                if late_cleanup_error is not None:

                    def merge_late_cleanup(
                        current: BaseException,
                    ) -> BaseException:
                        for attribute in (
                            "_codex_claude_retained_credential_carrier",
                            "_codex_claude_retained_cleanup_artifact",
                        ):
                            value = getattr(
                                late_cleanup_error,
                                attribute,
                                None,
                            )
                            if isinstance(value, str):
                                setattr(current, attribute, value)
                        _copy_claude_retained_credential_proof(
                            late_cleanup_error,
                            current,
                        )
                        return _attach_claude_credential_cleanup_failure(
                            current,
                            late_cleanup_error,
                        )

                    timeout_failure = transform_quiescence_timeout_failure(
                        merge_late_cleanup,
                        late_control_flow_hint=_is_claude_control_flow_error(
                            late_cleanup_error
                        ),
                    )
                    assert timeout_failure is not None
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
                        persistence_error = (
                            _attach_claude_persistence_failure_preserving_control_flow(
                                cleanup_error,
                                persistence_error,
                            )
                        )
                    else:
                        persistence_error = _attach_claude_credential_cleanup_failure(
                            persistence_error,
                            cleanup_error,
                        )
        if (
            inflight_stage is not None
            and inflight_stage.error is not None
            and inflight_stage.error is not persistence_error
        ):
            if _is_claude_control_flow_error(inflight_stage.error):
                persistence_error = (
                    _attach_claude_persistence_failure_preserving_control_flow(
                        inflight_stage.error,
                        persistence_error,
                    )
                )
            else:
                persistence_error = _attach_claude_credential_cleanup_failure(
                    persistence_error,
                    inflight_stage.error,
                )
        if _claude_timeout_root_state(persistence_error) is not None:
            if staged_fallback is not None:
                staged_fallback[:] = b"\x00" * len(staged_fallback)
            return persistence_error
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
        runtime_abandon_requested.set()
        failure = publish_quiescence_timeout_failure(
            new_recovery_timeout_scope_failure()
        )
        recovery_candidate: pathlib.Path | None = None
        recovery_proven = False
        recovery_expectation: _ClaudeRecoveryExpectation | None = None
        recovery_cleanup_scope_required = True
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
                inflight_stage = quiescence_durable_stage or durable_stage_inflight
                unresolved_inflight_stage = (
                    inflight_stage is not None
                    and not inflight_stage.recovery_decided.is_set()
                )
                if unresolved_inflight_stage and inflight_stage.terminal:
                    recovery_candidate = None
                    recovery_expectation = None
                    recovery_proven = False
                recovery_cleanup_scope_required = (
                    bool(durable_stage_carriers) or unresolved_inflight_stage
                )
        except BaseException as state_error:
            state_failure = state_error
            updated_failure = transform_quiescence_timeout_failure(
                lambda current: (
                    _attach_claude_persistence_failure_preserving_control_flow(
                        current,
                        state_failure,
                    )
                ),
                late_control_flow_hint=_is_claude_control_flow_error(state_failure),
            )
            assert updated_failure is not None
            failure = updated_failure
        finally:
            if state_acquired:
                runtime_state_lock.release()
        if recovery_candidate is not None and recovery_proven:
            assert recovery_expectation is not None
            updated_failure = transform_quiescence_timeout_failure(
                lambda current: _set_timeout_recovery_carrier(
                    current,
                    recovery_candidate,
                )
            )
            assert updated_failure is not None
            failure = updated_failure
            updated_failure = mark_quiescence_timeout_recovery_artifact(
                recovery_expectation.artifact,
                expected_digest=recovery_expectation.digest,
            )
            assert updated_failure is not None
            failure = updated_failure
        published_current = (
            recovery_expectation is not None
            and published_recovery_claim_is_current(
                failure,
                recovery_expectation,
            )
        )
        validated_failure = failure

        def finalize_timeout_failure(current: BaseException) -> BaseException:
            current_is_published = current is validated_failure and published_current
            if recovery_proven and not current_is_published:
                _clear_claude_retained_credential_proof(current)
                with contextlib.suppress(AttributeError):
                    delattr(
                        current,
                        "_codex_claude_retained_credential_carrier",
                    )
            if current_is_published and not recovery_cleanup_scope_required:
                with contextlib.suppress(AttributeError):
                    delattr(
                        current,
                        "_codex_claude_retained_cleanup_artifact",
                    )
            else:
                _mark_claude_macos_recovery_cleanup_artifact(
                    current,
                    fail_closed_recovery_root,
                )
            return current

        updated_failure = seal_quiescence_timeout_failure(
            finalize_timeout_failure,
            recovery_expectation=recovery_expectation,
            cleanup_scope_required=recovery_cleanup_scope_required,
            prevalidated_published=published_current,
        )
        assert updated_failure is not None
        return updated_failure

    capability = secrets.token_bytes(CLAUDE_KEYCHAIN_BROKER_CAPABILITY_BYTES)
    primary_error: BaseException | None = None
    try:
        with _claude_keychain_credential_server(
            selected.payload,
            capability,
            identity_socket=identity_socket,
            update_callback=stage_refreshed_credential,
            quiescence_callbacks=_ClaudeKeychainQuiescenceCallbacks(
                abandon=abandon_unquiescent_handler,
                recover=recover_unquiescent_handler,
                timeout_error=unquiescent_recovery_timeout_error,
                timeout_fallback_error=recovery_timeout_fallback_failure,
                fail_closed_error=unquiescent_fail_closed_error,
                fail_closed_fallback_error=fail_closed_scope_failure,
                write_observed=transaction.observe_refresh,
            ),
        ) as endpoint:
            result[CLAUDE_KEYCHAIN_BROKER_PORT_ENV] = str(endpoint.port)
            result[CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET_ENV] = str(
                endpoint.identity_socket
            )
            _update_claude_runtime_report(
                review,
                {
                    "authentication": {
                        "source": selected.source,
                        "carrier": "one-shot-security-broker",
                        "status": "sandbox-auth-staged",
                        "refresh_persistence": ("durable-recovery-before-ack"),
                    }
                },
            )
            yield _ClaudeKeychainRuntimeEnvironment(
                result,
                endpoint.prepare_runtime_process,
                endpoint.bind_runtime_process,
            )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        persistence_error: BaseException | None = None
        staged_for_commit: bytearray | None = None
        staged_for_commit_generation: int | None = None
        durable_carriers_for_cleanup: tuple[tuple[pathlib.Path, bytes], ...] = ()
        finalization_abandoned = (
            bool(
                primary_error is not None
                and getattr(
                    primary_error,
                    "_codex_claude_keychain_handler_quiescence_unproven",
                    False,
                )
            )
            or runtime_is_abandoned()
        )
        if not finalization_abandoned:
            errors_for_latest_reproof: tuple[BaseException, ...] = ()
            with runtime_state_lock:
                durable_carriers_for_cleanup = tuple(durable_stage_carriers)
                if staged_credential is not None:
                    staged_for_commit = staged_credential
                    staged_for_commit_generation = staged_credential_generation
                    staged_credential = None
                    staged_credential_generation = None
                if durable_carriers_for_cleanup and persistence_errors:
                    errors_for_latest_reproof = tuple(persistence_errors)
            if durable_carriers_for_cleanup and errors_for_latest_reproof:
                latest_durable_carrier, latest_durable_digest = (
                    durable_carriers_for_cleanup[-1]
                )
                latest_durable_artifact = (
                    latest_durable_carrier / "config" / CLAUDE_CREDENTIAL_FILE_NAME
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
                        or pathlib.Path(retained_value) != latest_durable_carrier
                        or existing_proof is None
                        or existing_proof.artifact != latest_durable_artifact
                        or not hmac.compare_digest(
                            existing_proof.digest,
                            latest_durable_digest,
                        )
                    ):
                        original_existing_error = existing_error
                        setattr(
                            existing_error,
                            "_codex_claude_retained_credential_carrier",
                            str(latest_durable_carrier),
                        )
                        existing_error = _mark_claude_macos_recovery_update_artifact(
                            existing_error,
                            latest_durable_artifact,
                            expected_digest=latest_durable_digest,
                        )
                        if existing_error is not original_existing_error:
                            with runtime_state_lock:
                                persistence_errors[:] = [
                                    existing_error
                                    if error is original_existing_error
                                    else error
                                    for error in persistence_errors
                                ]
        if staged_for_commit is None and durable_carriers_for_cleanup:
            with runtime_state_lock:
                if persistence_errors:
                    cleanup_primary = persistence_errors[0]
                else:
                    cleanup_primary = None
            if cleanup_primary is None:
                created_cleanup_primary = _retained_claude_macos_credential_error(
                    durable_carriers_for_cleanup[-1][0],
                    ClaudeCredentialInspectionInconclusive(
                        "Claude durable-stage finalization did not retain "
                        "a host-writeback candidate"
                    ),
                    expected_digest=durable_carriers_for_cleanup[-1][1],
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
            retained_proof = _get_claude_retained_credential_proof(cleanup_primary)
            if isinstance(retained_value, str) and retained_proof is not None:
                candidate_path = pathlib.Path(retained_value)
                expected_artifact = (
                    candidate_path / "config" / CLAUDE_CREDENTIAL_FILE_NAME
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
                original_cleanup_primary = cleanup_primary
                cleanup_primary = _mark_claude_macos_recovery_update_artifact(
                    cleanup_primary,
                    retained_path / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                    expected_digest=retained_digest,
                )
                if cleanup_primary is not original_cleanup_primary:
                    with runtime_state_lock:
                        persistence_errors[:] = [
                            cleanup_primary
                            if error is original_cleanup_primary
                            else error
                            for error in persistence_errors
                        ]
                setattr(
                    cleanup_primary,
                    "_codex_claude_refresh_persistence_failed",
                    True,
                )
                retained_proof = _get_claude_retained_credential_proof(cleanup_primary)
                expected_artifact = (
                    retained_path / "config" / CLAUDE_CREDENTIAL_FILE_NAME
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
                        cleanup_error = _mark_claude_macos_recovery_update_artifact(
                            cleanup_error,
                            retained_path / "config" / CLAUDE_CREDENTIAL_FILE_NAME,
                            expected_digest=retained_digest,
                        )
                    cleanup_failures.append(cleanup_error)
                    if _is_claude_control_flow_error(cleanup_error):
                        cleanup_stopped_early = cleanup_index + 1 < len(cleanup_targets)
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
                        root_primary = control_flow_cleanup or cleanup_primary
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
                    original_cleanup_primary = cleanup_primary
                    for cleanup_error in cleanup_failures:
                        cleanup_primary = _attach_claude_credential_cleanup_failure(
                            cleanup_primary,
                            cleanup_error,
                        )
                    if cleanup_primary is not original_cleanup_primary:
                        with runtime_state_lock:
                            persistence_errors[:] = [
                                cleanup_primary
                                if error is original_cleanup_primary
                                else error
                                for error in persistence_errors
                            ]
        if staged_for_commit is not None:
            accepted = False
            persistence_control_flow = False
            stale_durable_cleanup_errors: list[BaseException] = []
            stale_durable_cleanup_targets = durable_carriers_for_cleanup[:-1]
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
                    latest_carrier, latest_digest = durable_carriers_for_cleanup[-1]
                    latest_readback = _read_claude_macos_recovery_credential(
                        review,
                        latest_carrier,
                    )
                    if not hmac.compare_digest(
                        _claude_credential_digest(latest_readback),
                        latest_digest,
                    ) or not hmac.compare_digest(
                        latest_readback,
                        staged_for_commit,
                    ):
                        raise ClaudeCredentialInspectionInconclusive(
                            "the latest durable recovery carrier no longer "
                            "matches the acknowledged Claude credential"
                        )
                    latest_carrier_verified = True
                except BaseException as error:
                    if _is_claude_control_flow_error(error):
                        verification_error = error
                    elif isinstance(
                        error,
                        ClaudeCredentialInspectionInconclusive,
                    ) and "latest durable recovery carrier" in str(error):
                        verification_error = error
                    else:
                        verification_error = ClaudeCredentialInspectionInconclusive(
                            "cannot re-verify the latest durable recovery "
                            "carrier before host writeback"
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
                            and not _is_claude_control_flow_error(verification_error)
                        ):
                            effective_control_flow = (
                                _attach_claude_credential_cleanup_failure(
                                    existing_control_flow,
                                    verification_error,
                                )
                            )
                            persistence_errors.remove(existing_control_flow)
                            persistence_errors.insert(
                                0,
                                effective_control_flow,
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
                                cleanup_stopped_early = stale_index + 1 < len(
                                    stale_durable_cleanup_targets
                                )
                                if cleanup_stopped_early:
                                    try:
                                        recovery_root = _claude_macos_recovery_root(
                                            review
                                        )
                                    except BaseException as root_error:
                                        error = _attach_claude_persistence_failure_preserving_control_flow(
                                            error,
                                            root_error,
                                        )
                                    else:
                                        _mark_claude_macos_recovery_cleanup_artifact(
                                            error,
                                            recovery_root,
                                        )
                                elif not isinstance(
                                    getattr(
                                        error,
                                        ("_codex_claude_retained_cleanup_artifact"),
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
                                    ("_codex_claude_retained_credential_carrier"),
                                    str(latest_carrier),
                                )
                                error = _mark_claude_macos_recovery_update_artifact(
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
                        assert staged_for_commit_generation is not None
                        accepted = accept_refreshed_credential(
                            staged_for_commit,
                            staged_for_commit_generation,
                        )
                    except BaseException as error:
                        with runtime_state_lock:
                            if _is_claude_control_flow_error(error):
                                persistence_errors.insert(0, error)
                                persistence_control_flow = True
                            else:
                                persistence_errors.append(error)
                if accepted and not persistence_control_flow:
                    for durable_carrier, durable_digest in durable_carriers_for_cleanup[
                        -1:
                    ]:
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
                                    ("_codex_claude_retained_credential_carrier"),
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
                        _clear_claude_retained_credential_proof(cleanup_error)
                    with runtime_state_lock:
                        persistence_errors.extend(stale_durable_cleanup_errors)
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
                    and final_recovery_expectation.carrier == final_recovery_candidate
                )
                remaining_staged_credential = staged_credential
                staged_credential = None
                staged_credential_generation = None
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
                    persistence_error = abandonment_errors[0]
                    for secondary in abandonment_errors[1:]:
                        if secondary is persistence_error:
                            continue
                        if (
                            _get_claude_retained_credential_proof(persistence_error)
                            is None
                        ):
                            _copy_claude_retained_credential_proof(
                                secondary,
                                persistence_error,
                            )
                        secondary_cleanup_artifact = getattr(
                            secondary,
                            ("_codex_claude_retained_cleanup_artifact"),
                            None,
                        )
                        if isinstance(
                            secondary_cleanup_artifact, str
                        ) and not isinstance(
                            getattr(
                                persistence_error,
                                ("_codex_claude_retained_cleanup_artifact"),
                                None,
                            ),
                            str,
                        ):
                            setattr(
                                persistence_error,
                                ("_codex_claude_retained_cleanup_artifact"),
                                secondary_cleanup_artifact,
                            )
                        secondary_carrier = getattr(
                            secondary,
                            "_codex_claude_retained_credential_carrier",
                            None,
                        )
                        if not isinstance(
                            getattr(
                                persistence_error,
                                "_codex_claude_retained_credential_carrier",
                                None,
                            ),
                            str,
                        ) and isinstance(secondary_carrier, str):
                            setattr(
                                persistence_error,
                                "_codex_claude_retained_credential_carrier",
                                secondary_carrier,
                            )
                        if getattr(
                            secondary,
                            "_codex_claude_refresh_persistence_failed",
                            False,
                        ):
                            setattr(
                                persistence_error,
                                "_codex_claude_refresh_persistence_failed",
                                True,
                            )
                        persistence_error = (
                            _attach_claude_persistence_failure_preserving_control_flow(
                                persistence_error,
                                secondary,
                            )
                        )
                elif final_persistence_errors:
                    persistence_error = final_persistence_errors[0]
                    for secondary in final_persistence_errors[1:]:
                        persistence_error = _attach_claude_credential_cleanup_failure(
                            persistence_error,
                            secondary,
                        )
                elif final_runtime_abandoned:
                    persistence_error = ClaudeCredentialInspectionInconclusive(
                        "Claude Keychain broker handler quiescence could not "
                        "be proven before runtime cleanup"
                    )
                    setattr(
                        persistence_error,
                        ("_codex_claude_keychain_handler_quiescence_unproven"),
                        True,
                    )
                    if final_recovery_candidate is not None and final_recovery_proven:
                        assert final_recovery_expectation is not None
                        setattr(
                            persistence_error,
                            "_codex_claude_retained_credential_carrier",
                            str(final_recovery_candidate),
                        )
                        persistence_error = _mark_claude_macos_recovery_update_artifact(
                            persistence_error,
                            final_recovery_expectation.artifact,
                            expected_digest=(final_recovery_expectation.digest),
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
                                "refresh_persistence": ("broker-shutdown-inconclusive"),
                            }
                        },
                    )
                elif not _claude_macos_final_carrier_snapshot_is_current(
                    review,
                    final_carrier_snapshot,
                    refresh_lock_protocol,
                    transaction,
                    coordinated_refresh_lock=coordinated_refresh_lock,
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
                remaining_staged_credential[:] = b"\x00" * len(
                    remaining_staged_credential
                )
            expected_credential[:] = b"\x00" * len(expected_credential)
            selected.payload[:] = b"\x00" * len(selected.payload)
        if persistence_error is not None:
            if primary_error is not None:
                if not _is_claude_control_flow_error(
                    primary_error
                ) and _is_claude_control_flow_error(persistence_error):
                    persistence_error = _attach_claude_credential_cleanup_failure(
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
                    normalized_primary = _claude_macos_runtime_io_inconclusive(
                        review,
                        active_io_error,
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
        acl_free = libc.acl_free
        acl_free.argtypes = [ctypes.c_void_p]
        acl_free.restype = ctypes.c_int
    except (AttributeError, OSError) as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect {label} access controls"
        ) from error
    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, CLAUDE_ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot inspect {label} access controls"
        )
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        entry_status = acl_get_entry(acl, 0, ctypes.byref(entry))
        entry_errno = ctypes.get_errno()
        if entry_status == 0:
            raise ReviewError(f"{label} has an extended access control list")
        if entry_status != -1 or entry_errno != errno.EINVAL:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot inspect {label} access controls"
            )
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
        material = bytes(payload)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    else:
        try:
            os.close(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close {label}: {source}"
            ) from error
        return material
    finally:
        payload[:] = b"\x00" * len(payload)


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
        effective_uid = os.geteuid()
        if (
            effective_uid != 0
            and metadata.st_uid == effective_uid
            and metadata.st_mode & 0o077
        ):
            raise ReviewError(f"Claude review CA source is not owner-only: {source}")
        if descriptor is not None:
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
            _require_no_extended_acl(
                descriptor,
                label="Claude review CA directory",
            )
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
            with contextlib.suppress(OSError):
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
        _require_no_extended_acl(
            descriptor,
            label="Claude review CA directory",
        )
        path_after = path.lstat()
    except ReviewError:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    except OSError as error:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot validate a stable Claude review CA directory {source}: {error}"
        ) from error
    if _ca_source_metadata(path_before) != _ca_source_metadata(
        opened
    ) or _ca_source_metadata(opened) != _ca_source_metadata(path_after):
        with contextlib.suppress(OSError):
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
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    else:
        try:
            os.close(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close a stable Claude review CA source {source}: {error}"
            ) from error
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
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    else:
        try:
            os.close(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close a stable Claude review CA source {source}: {error}"
            ) from error
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


def _read_proxy_system_ca_source(path: pathlib.Path) -> bytes:
    source = "Claude proxy system CA bundle"
    try:
        descriptor = os.open(path, _ca_nofollow_flags(directory=False))
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot open a stable {source}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or (_is_claude_macos_host() and before.st_nlink != 1)
            or before.st_mode & 0o022
        ):
            raise ReviewError(f"{source} has unsafe metadata")
        _require_no_extended_acl(descriptor, label=source)
        payload = bytearray()
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, CLAUDE_CA_FILE_LIMIT_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > CLAUDE_CA_FILE_LIMIT_BYTES:
                raise ReviewError(f"{source} exceeds the size limit")
        after = os.fstat(descriptor)
    except OSError as error:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot read a stable {source}"
        ) from error
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    else:
        try:
            os.close(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close a stable {source}"
            ) from error
    try:
        path_after = path.lstat()
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"{source} changed while being read"
        ) from error
    if (
        _ca_source_metadata(before) != _ca_source_metadata(after)
        or _ca_source_metadata(after) != _ca_source_metadata(path_after)
        or len(payload) != before.st_size
    ):
        raise ClaudeExecutableInspectionInconclusive(
            f"{source} changed while being read"
        )
    return _extract_ca_certificates(bytes(payload), source=source)


def _read_proxy_system_ca_directory(path: pathlib.Path) -> dict[str, bytes]:
    source = "Claude proxy system CA directory"
    descriptor = _open_stable_ca_directory(path, source=source)
    snapshots: dict[str, bytes] = {}
    total_size = 0
    try:
        before = os.fstat(descriptor)
        names = _bounded_ca_directory_names(
            descriptor,
            CLAUDE_CA_DIR_ENTRY_LIMIT,
            too_many_message="Claude proxy system CA directory has too many entries",
        )
        for name in names:
            if CLAUDE_OPENSSL_CA_HASH_ENTRY_RE.fullmatch(name) is None:
                continue
            metadata = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISDIR(metadata.st_mode):
                continue
            raw_material, source_size = _read_ca_directory_entry_at_with_size(
                descriptor,
                name,
                metadata,
                source=f"{source}:{name}",
                extract_certificates=False,
            )
            total_size += source_size
            if total_size > CLAUDE_CA_DIR_LIMIT_BYTES:
                raise ReviewError("Claude proxy system CA directory is too large")
            try:
                material = _extract_ca_certificates(
                    raw_material,
                    source=f"{source}:{name}",
                )
            except ClaudeCACertificateNotFound:
                continue
            snapshots[str(path / name)] = material
        after = os.fstat(descriptor)
        if _ca_source_metadata(before) != _ca_source_metadata(after):
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy system CA directory changed while being read"
            )
    except OSError as error:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise ClaudeExecutableInspectionInconclusive(
            "cannot read a stable Claude proxy system CA directory"
        ) from error
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    else:
        try:
            os.close(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot close a stable Claude proxy system CA directory"
            ) from error
    return snapshots


def _release_uncommitted_ca_descriptor(
    descriptor: int | None,
    owned_descriptors: list[int],
    original_count: int,
) -> None:
    if descriptor is None:
        return
    if len(owned_descriptors) > original_count:
        owned_descriptors.pop()
    with contextlib.suppress(OSError):
        os.close(descriptor)


def _acquire_owned_ca_descriptor(
    opener: Callable[[], int],
    owned_descriptors: list[int],
) -> int:
    descriptor: int | None = None
    original_count = len(owned_descriptors)
    try:
        descriptor = opener()
        owned_descriptors.append(descriptor)
        return descriptor
    except BaseException:
        _release_uncommitted_ca_descriptor(
            descriptor,
            owned_descriptors,
            original_count,
        )
        raise


def _open_ca_directory_at(
    directory_descriptor: int,
    name: str,
    *,
    source: str,
    owned_descriptors: list[int],
) -> tuple[int, os.stat_result]:
    descriptor: int | None = None
    original_count = len(owned_descriptors)
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
        opened = os.fstat(descriptor)
        _require_safe_ca_directory_metadata(opened, source=source)
        _require_no_extended_acl(
            descriptor,
            label="Claude review CA path directory",
        )
        after = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if _ca_source_metadata(before) != _ca_source_metadata(
            opened
        ) or _ca_source_metadata(opened) != _ca_source_metadata(after):
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude review CA path directory changed while being opened: {source}"
            )
        owned_descriptors.append(descriptor)
        return descriptor, opened
    except ReviewError:
        _release_uncommitted_ca_descriptor(
            descriptor,
            owned_descriptors,
            original_count,
        )
        raise
    except OSError as error:
        operation = "open" if descriptor is None else "validate"
        _release_uncommitted_ca_descriptor(
            descriptor,
            owned_descriptors,
            original_count,
        )
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot {operation} a stable Claude review CA path directory "
            f"{source}: {error}"
        ) from error
    except BaseException:
        _release_uncommitted_ca_descriptor(
            descriptor,
            owned_descriptors,
            original_count,
        )
        raise


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
    primary_error: BaseException | None = None
    try:
        current_directory = _acquire_owned_ca_descriptor(
            lambda: os.dup(source_directory_descriptor),
            owned_descriptors,
        )
        source_directory_metadata = os.fstat(current_directory)
        _require_safe_ca_directory_metadata(
            source_directory_metadata,
            source=source,
        )
        _require_no_extended_acl(
            current_directory,
            label="Claude review CA path directory",
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
                    owned_descriptors=owned_descriptors,
                )
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
                    root_descriptor = _acquire_owned_ca_descriptor(
                        lambda: _open_stable_ca_directory(
                            pathlib.Path(os.sep),
                            source=source,
                        ),
                        owned_descriptors,
                    )
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
                    owned_descriptors=owned_descriptors,
                )
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
    except BaseException as error:
        primary_error = error
        raise
    finally:
        close_error: OSError | None = None
        for descriptor in reversed(owned_descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                close_error = close_error or error
        if primary_error is None and close_error is not None:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close Claude review CA path descriptor chain: {source}"
            ) from close_error


def _read_ca_path_from_parent_with_size(
    path: pathlib.Path,
    *,
    source: str,
    extract_certificates: bool = True,
) -> tuple[bytes, int]:
    source_directory = _open_stable_ca_directory(path.parent, source=source)
    try:
        result = _read_ca_path_at_with_size(
            source_directory,
            path.name,
            source=source,
            extract_certificates=extract_certificates,
        )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(source_directory)
        raise
    else:
        try:
            os.close(source_directory)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close Claude review CA source directory: {source}"
            ) from error
        return result


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
        result = _read_ca_path_at_with_size(
            root_directory,
            str(path),
            source=source,
            extract_certificates=extract_certificates,
        )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(root_directory)
        raise
    else:
        try:
            os.close(root_directory)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close Claude review CA root directory: {source}"
            ) from error
        return result


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
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot create a private Claude CA file"
        ) from error
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
    except ReviewError:
        raise
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot write a private Claude CA file"
        ) from error
    finally:
        active_error = sys.exc_info()[0] is not None
        cleanup_error: OSError | None = None
        if fd >= 0:
            try:
                os.close(fd)
            except OSError as error:
                cleanup_error = error
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            cleanup_error = cleanup_error or error
        if cleanup_error is not None and not active_error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot clean up a private Claude CA file"
            ) from cleanup_error


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
    trust_root: set[str] = set()
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
            raise ClaudeTrustPolicyUnavailable(f"{label} contain invalid constraints")
        settings = entry["trustSettings"]
        if not isinstance(settings, list):
            raise ClaudeTrustPolicyUnavailable(f"{label} contain invalid constraints")
        if not settings:
            unconditional.add(normalized)
            trust_root.add(normalized)
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
                # An empty constraints dictionary defaults to TrustRoot.
                if not setting:
                    has_unconditional_trust_root = True
                continue
            result = setting[CLAUDE_TRUST_RESULT_KEY]
            if type(result) is not int or result not in CLAUDE_TRUST_RESULTS:
                raise ClaudeTrustPolicyUnavailable(
                    f"{label} contain invalid constraints"
                )
            if result in CLAUDE_TRUST_UNCONSTRAINED_RESULTS and set(setting) == {
                CLAUDE_TRUST_RESULT_KEY
            }:
                if result == CLAUDE_TRUST_RESULT_TRUST_ROOT:
                    has_unconditional_trust_root = True
                else:
                    has_unconditional_trust_as_root = True
        if has_unconditional_trust_root or has_unconditional_trust_as_root:
            unconditional.add(normalized)
            if has_unconditional_trust_root:
                trust_root.add(normalized)
            if has_unconditional_trust_as_root:
                trust_as_root.add(normalized)
        else:
            constrained.add(normalized)
    return ClaudeTrustFingerprints(
        unconditional=tuple(sorted(unconditional)),
        trust_as_root=tuple(sorted(trust_as_root)),
        constrained=tuple(sorted(constrained)),
        trust_root=tuple(sorted(trust_root)),
    )


def _select_trust_certificates(
    materials: Iterable[tuple[str, bytes | bytearray]],
    fingerprints: Iterable[str],
    *,
    ca_root: pathlib.Path,
    trust_as_root_fingerprints: Iterable[str] = (),
    trust_root_fingerprints: Iterable[str] | None = None,
) -> ClaudeSelectedTrustMaterial:
    deadline = time.monotonic() + CLAUDE_TRUST_ROOT_VERIFY_TOTAL_SECONDS

    def require_time_remaining() -> None:
        now = time.monotonic()
        if now >= deadline:
            raise ReviewTimeoutError(
                "Claude additional trust root verification exceeded its deadline"
            )

    requested = tuple(fingerprints)
    requested_set = set(requested)
    trust_as_root = set(trust_as_root_fingerprints)
    trust_root = (
        requested_set - trust_as_root
        if trust_root_fingerprints is None
        else set(trust_root_fingerprints)
    )
    if not trust_as_root.issubset(requested_set) or not trust_root.issubset(
        requested_set
    ):
        raise ValueError("trust fingerprints must be selected trust anchors")
    if trust_root | trust_as_root != requested_set:
        raise ValueError("every selected trust anchor requires an authorization")
    if len(requested) > CLAUDE_ADDITIONAL_TRUST_ROOT_LIMIT:
        raise ClaudeTrustPolicyUnavailable(
            "Claude additional trust roots exceed the verification limit"
        )
    certificates: dict[str, bytes] = {}
    for source, data in materials:
        if not data:
            require_time_remaining()
            continue
        try:
            normalized = _extract_ca_certificates(bytes(data), source=source)
        except ReviewError:
            require_time_remaining()
            raise
        require_time_remaining()
        for block in CLAUDE_CERTIFICATE_BLOCK.findall(normalized):
            try:
                der, canonical = _canonical_ca_certificate(block, source=source)
            except ReviewError:
                require_time_remaining()
                raise
            require_time_remaining()
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
                require_time_remaining()
                raise ClaudeTrustPolicyUnavailable(
                    "Claude trust certificates contain a fingerprint collision"
                )
            certificates[fingerprint] = canonical
    selected: list[bytes] = []
    omitted: set[str] = set()
    for fingerprint in requested:
        canonical = certificates.get(fingerprint)
        if canonical is None:
            require_time_remaining()
            omitted.add(fingerprint)
            continue
        require_time_remaining()
        try:
            der, _ = _canonical_ca_certificate(
                canonical,
                source="Claude trust certificates",
            )
        except ReviewError:
            require_time_remaining()
            raise
        require_time_remaining()
        authorized = False
        for allow_non_self_signed in ((False,) if fingerprint in trust_root else ()) + (
            (True,) if fingerprint in trust_as_root else ()
        ):
            require_time_remaining()
            try:
                _verify_unconditional_trust_root(
                    der,
                    canonical,
                    ca_root=ca_root,
                    deadline=deadline,
                    allow_non_self_signed=allow_non_self_signed,
                )
            except ClaudeTrustCertificateInvalid:
                require_time_remaining()
                continue
            except ReviewError:
                require_time_remaining()
                raise
            require_time_remaining()
            authorized = True
            break
        if not authorized:
            require_time_remaining()
            omitted.add(fingerprint)
            continue
        selected.append(canonical)
    require_time_remaining()
    selected_material = ClaudeSelectedTrustMaterial(
        certificates=b"".join(selected),
        omitted_sha1_fingerprints=frozenset(omitted),
    )
    require_time_remaining()
    return selected_material


def _is_no_trust_settings(detail: str) -> bool:
    lines = [line.strip() for line in detail.splitlines() if line.strip()]
    return any(
        lines in ([message], [f"security: {message}"])
        for message in CLAUDE_TRUST_NO_SETTINGS
    )


@contextlib.contextmanager
def _managed_claude_trust_export_path(path: pathlib.Path) -> Iterator[None]:
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude trust export path could not be prepared"
        ) from error
    try:
        yield
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
        raise
    else:
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude trust export path could not be cleaned"
            ) from error


def _read_claude_trust_domain(
    client: pathlib.Path,
    security_env: dict[str, str],
    ca_root: pathlib.Path,
    *,
    domain: str,
    options: tuple[str, ...],
) -> ClaudeTrustFingerprints | None:
    trust_path = ca_root / f".{domain}-trust.plist"
    with _managed_claude_trust_export_path(trust_path):
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
                if completed.returncode == 1 and _is_no_trust_settings(detail):
                    return None
                raise ClaudeExecutableInspectionInconclusive(
                    f"Claude {domain} trust export failed inconclusively"
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
        return _classify_trust_fingerprints(trust_data, domain=domain)


def _require_claude_trust_export_tool(
    review: ReviewWorkspace,
    ca_root: pathlib.Path,
) -> tuple[pathlib.Path, dict[str, str]]:
    client = CLAUDE_KEYCHAIN_CLIENT
    try:
        client_metadata = client.stat()
    except FileNotFoundError as error:
        raise ClaudeTrustToolUnavailable(
            "Claude TLS setup requires Apple's security trust export tool"
        ) from error
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot inspect Apple's security trust export tool"
        ) from error
    if not stat.S_ISREG(client_metadata.st_mode) or not (
        client_metadata.st_mode & 0o111
    ):
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
    if completed.returncode != 0:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude TLS trust export capability probe failed inconclusively"
        )
    if normalized_lines not in CLAUDE_TRUST_EXPORT_HELP_VARIANTS:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude TLS trust export capability output was inconclusive"
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
    try:
        write_json(
            review.container_dir / CLAUDE_TRUST_POLICY_EVIDENCE_NAME,
            evidence,
        )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude trust policy evidence write was inconclusive"
        ) from error


def _terminalize_claude_trust_policy_evidence(
    review: ReviewWorkspace,
    evidence: dict[str, object],
    *,
    status: str,
    unresolved_resolution: str,
    primary_error: BaseException | None = None,
) -> None:
    evidence["status"] = status
    for key in ("bundled_root_resolution", "additional_root_resolution"):
        if evidence.get(key) in {"not-started", "pending"}:
            evidence[key] = unresolved_resolution
    try:
        _write_claude_trust_policy_evidence(review, evidence)
    except (OSError, ClaudeExecutableInspectionInconclusive):
        if primary_error is None:
            raise
        _attach_claude_trust_evidence_write_failure(primary_error)
    else:
        if primary_error is not None:
            _clear_claude_trust_evidence_write_failure(primary_error)


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
    except ClaudeTrustSettingsDeny as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="denied",
            unresolved_resolution="blocked",
            primary_error=error,
        )
        raise
    except ClaudeTrustPolicyUnavailable as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
            primary_error=error,
        )
        raise
    except ClaudeTrustToolUnavailable as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="unavailable",
            unresolved_resolution="unavailable",
            primary_error=error,
        )
        raise
    except ClaudeExecutableInspectionInconclusive as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
            primary_error=error,
        )
        raise
    except ReviewOutputLimitError as error:
        if error.limit_kind == "regular-file":
            failure = ClaudeTrustPolicyUnavailable(
                "Claude trust policy exceeds the inspection limit"
            )
            failure.__cause__ = error
            _terminalize_claude_trust_policy_evidence(
                review,
                evidence,
                status="blocked",
                unresolved_resolution="blocked",
                primary_error=failure,
            )
            raise failure
        failure = ClaudeExecutableInspectionInconclusive(
            "Claude trust export stream exceeded the inspection limit"
        )
        failure.__cause__ = error
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
            primary_error=failure,
        )
        raise failure
    except (
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewProcessLeakError,
    ) as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
            primary_error=error,
        )
        raise
    except ReviewError as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
            primary_error=error,
        )
        raise
    except BaseException as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
            primary_error=error,
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
    additional_trust_root: set[str] = set()
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
        try:
            classified = _read_claude_trust_domain(
                client,
                security_env,
                ca_root,
                domain=domain,
                options=options,
            )
            if classified is None:
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
            # Domains are ordered from highest to lowest precedence.
            resolved = additional_unconditional | constrained
            domain_unconditional = set(classified.unconditional) - resolved
            domain_constrained = (
                set(classified.constrained) - resolved - domain_unconditional
            )
            unconditional.update(domain_unconditional)
            additional_unconditional.update(domain_unconditional)
            classified_trust_root = set(classified.trust_root) | (
                set(classified.unconditional) - set(classified.trust_as_root)
            )
            additional_trust_root.update(classified_trust_root & domain_unconditional)
            additional_trust_as_root.update(
                set(classified.trust_as_root) & domain_unconditional
            )
            constrained.update(domain_constrained)
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
        except ReviewOutputLimitError as error:
            if error.limit_kind == "regular-file":
                record_domain_failure(domain, "blocked")
                failure = ClaudeTrustPolicyUnavailable(
                    f"Claude {domain} trust export exceeds the inspection limit"
                )
                failure.__cause__ = error
                defer_error(
                    2,
                    failure,
                )
            else:
                record_domain_failure(domain, "inconclusive")
                failure = ClaudeExecutableInspectionInconclusive(
                    f"Claude {domain} trust export stream exceeded the inspection limit"
                )
                failure.__cause__ = error
                defer_error(
                    1,
                    failure,
                )
        except ReviewError as error:
            record_domain_failure(domain, "blocked")
            defer_error(2, error)

    if deferred_error is not None:
        raise deferred_error[1]
    effective_unconditional = additional_unconditional - constrained
    effective_trust_root = additional_trust_root & effective_unconditional
    effective_trust_as_root = additional_trust_as_root & effective_unconditional
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
                raise ClaudeExecutableInspectionInconclusive(
                    f"Claude {source} certificate export failed inconclusively"
                )
        selected = _select_trust_certificates(
            ((source, completed.stdout) for source, completed in completed_exports),
            sorted(effective_unconditional),
            ca_root=ca_root,
            trust_as_root_fingerprints=sorted(effective_trust_as_root),
            trust_root_fingerprints=sorted(effective_trust_root),
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


def _snapshot_claude_tls_environment(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    ca_root: pathlib.Path,
) -> tuple[dict[str, str], dict[str, bytes]]:
    result = dict(env)
    snapshots: dict[str, bytes] = {}
    _require_private_claude_ca_root(ca_root)
    for key in CLAUDE_TLS_FILE_ENV_KEYS:
        raw = result.get(key)
        if not raw:
            continue
        source_path = pathlib.Path(raw)
        if not source_path.is_absolute():
            raise ReviewError(f"Claude review requires valid absolute {key}")
        destination = ca_root / f"{key.lower()}.pem"
        material = _read_ca_source(source_path, source=key)
        _write_private_ca_file(destination, material)
        _validate_ca_file(destination)
        result[key] = str(destination)
        snapshots[str(destination)] = material

    for key in CLAUDE_TLS_DIR_ENV_KEYS:
        raw_entries = [
            entry for entry in result.get(key, "").split(os.pathsep) if entry
        ]
        if not raw_entries:
            continue
        try:
            destination_root = pathlib.Path(
                tempfile.mkdtemp(prefix=f"{key.lower()}-", dir=ca_root)
            )
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot prepare Claude review {key} workspace"
            ) from error
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
            try:
                destination_dir.mkdir(mode=0o700)
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    f"cannot prepare Claude review {key} directory"
                ) from error
            copied = False
            source_directory = _open_stable_ca_directory(source_dir, source=key)
            try:
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
                                "cannot inspect Claude review CA directory entry: "
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
                        except ClaudeCACertificateNotFound:
                            continue
                        destination = destination_dir / source_name
                        _write_private_ca_file(destination, material)
                        _validate_ca_file(destination)
                        snapshots[str(destination)] = material
                        copied = True
                    directory_after = os.fstat(source_directory)
                    if _ca_source_metadata(directory_before) != _ca_source_metadata(
                        directory_after
                    ):
                        raise ClaudeExecutableInspectionInconclusive(
                            "Claude review CA directory changed while being read"
                        )
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        f"cannot inspect Claude review CA directory {key}"
                    ) from error
            except BaseException:
                with contextlib.suppress(OSError):
                    os.close(source_directory)
                raise
            else:
                try:
                    os.close(source_directory)
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        f"cannot close Claude review CA directory {key}"
                    ) from error
            if copied:
                prepared_dirs.append(destination_dir)
            else:
                try:
                    destination_dir.rmdir()
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        f"cannot clean up Claude review {key} directory"
                    ) from error
        if not prepared_dirs:
            raise ReviewError("Claude review CA directory contains no PEM certificates")
        result[key] = os.pathsep.join(str(path) for path in prepared_dirs)
    return result, snapshots


def _prepare_claude_generic_tls_environment(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    expected_snapshot_sha256: tuple[tuple[str, int, str, str], ...] | None = None,
) -> dict[str, str]:
    try:
        result, snapshots = _snapshot_claude_tls_environment(
            review,
            env,
            ca_root=review.container_dir / "claude-ca",
        )
    except ClaudeExecutableInspectionInconclusive:
        raise
    except ReviewError as error:
        if expected_snapshot_sha256 is None:
            raise
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy TLS snapshot changed between attempts"
        ) from error
    if expected_snapshot_sha256 is not None:
        _require_matching_claude_tls_snapshot(
            expected_snapshot_sha256,
            _claude_tls_snapshot_sha256(result, snapshots),
        )
    return result


def _claude_tls_snapshot_sha256(
    env: dict[str, str],
    snapshot_material: dict[str, bytes],
) -> tuple[tuple[str, int, str, str], ...]:
    bindings: list[tuple[str, int, str, str]] = []
    consumed: set[str] = set()
    for key in CLAUDE_TLS_FILE_ENV_KEYS:
        raw = env.get(key)
        if not raw:
            continue
        material = snapshot_material.get(raw)
        if material is None:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude TLS file snapshot binding is incomplete"
            )
        bindings.append((key, -1, "", hashlib.sha256(material).hexdigest()))
        consumed.add(raw)
    for key in CLAUDE_TLS_DIR_ENV_KEYS:
        for index, raw in enumerate(
            entry for entry in env.get(key, "").split(os.pathsep) if entry
        ):
            directory = pathlib.Path(raw)
            entries = sorted(
                (
                    pathlib.Path(path).name,
                    path,
                    material,
                )
                for path, material in snapshot_material.items()
                if pathlib.Path(path).parent == directory
            )
            if not entries:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude TLS directory snapshot binding is incomplete"
                )
            for name, path, material in entries:
                bindings.append(
                    (key, index, name, hashlib.sha256(material).hexdigest())
                )
                consumed.add(path)
    if consumed != set(snapshot_material):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude TLS snapshot binding contains unexpected material"
        )
    return tuple(sorted(bindings))


def _require_matching_claude_tls_snapshot(
    expected: tuple[tuple[str, int, str, str], ...],
    current: tuple[tuple[str, int, str, str], ...],
) -> None:
    if len(expected) != len(current):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy TLS snapshot changed between attempts"
        )
    for expected_entry, current_entry in zip(expected, current, strict=True):
        if expected_entry[:3] != current_entry[:3] or not hmac.compare_digest(
            expected_entry[3],
            current_entry[3],
        ):
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy TLS snapshot changed between attempts"
            )


def _read_claude_tls_snapshot_material(env: dict[str, str]) -> dict[str, bytes]:
    snapshots: dict[str, bytes] = {}
    total_size = 0
    for key in CLAUDE_TLS_FILE_ENV_KEYS:
        raw = env.get(key)
        if not raw:
            continue
        path = pathlib.Path(raw)
        material, source_size = _read_ca_source_with_size(
            path,
            source=key,
            extract_certificates=False,
        )
        total_size += source_size
        if total_size > CLAUDE_CA_DIR_LIMIT_BYTES:
            raise ReviewError("Claude TLS snapshot exceeds the size limit")
        snapshots[str(path)] = material

    entry_count = 0
    for key in CLAUDE_TLS_DIR_ENV_KEYS:
        for raw in (entry for entry in env.get(key, "").split(os.pathsep) if entry):
            directory = pathlib.Path(raw)
            descriptor = _open_stable_ca_directory(directory, source=key)
            try:
                before = os.fstat(descriptor)
                names = _bounded_ca_directory_names(
                    descriptor,
                    CLAUDE_CA_DIR_ENTRY_LIMIT - entry_count,
                    too_many_message="Claude TLS snapshot has too many entries",
                )
                entry_count += len(names)
                for name in names:
                    metadata = os.stat(
                        name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ClaudeExecutableInspectionInconclusive(
                            "Claude proxy TLS snapshot directory changed between "
                            "attempts"
                        )
                    material, source_size = _read_ca_source_at_with_size(
                        descriptor,
                        name,
                        source=f"{key}:{name}",
                        extract_certificates=False,
                    )
                    total_size += source_size
                    if total_size > CLAUDE_CA_DIR_LIMIT_BYTES:
                        raise ReviewError("Claude TLS snapshot exceeds the size limit")
                    snapshots[str(directory / name)] = material
                after = os.fstat(descriptor)
                if _ca_source_metadata(before) != _ca_source_metadata(after):
                    raise ClaudeExecutableInspectionInconclusive(
                        "Claude proxy TLS snapshot directory changed between attempts"
                    )
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    "cannot verify Claude proxy TLS snapshot directory"
                ) from error
            finally:
                try:
                    os.close(descriptor)
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        "cannot close Claude proxy TLS snapshot directory"
                    ) from error
    return snapshots


def _verify_claude_proxy_tls_snapshot(
    env: dict[str, str],
    expected: tuple[tuple[str, int, str, str], ...],
) -> None:
    try:
        current = _claude_tls_snapshot_sha256(
            env,
            _read_claude_tls_snapshot_material(env),
        )
    except ClaudeExecutableInspectionInconclusive:
        raise
    except ReviewError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy TLS snapshot changed between attempts"
        ) from error
    _require_matching_claude_tls_snapshot(expected, current)


def _prepare_claude_proxy_tls_environment(
    review: ReviewWorkspace,
    env: dict[str, str],
) -> tuple[
    dict[str, str],
    ssl.SSLContext | None,
    tuple[tuple[str, int, str, str], ...],
]:
    result, snapshots = _snapshot_claude_tls_environment(
        review,
        env,
        ca_root=review.container_dir / "claude-proxy-ca",
    )
    snapshot_sha256 = _claude_tls_snapshot_sha256(result, snapshots)
    context = (
        _proxy_ssl_context(result, snapshot_material=snapshots)
        if _claude_https_proxy_tls_required(result)
        else None
    )
    return result, context, snapshot_sha256


def _claude_proxy_tls_environment(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    trust_state: ClaudeTrustSessionState,
) -> tuple[dict[str, str], ssl.SSLContext | None]:
    if trust_state.proxy_tls_env is None:
        (
            trust_state.proxy_tls_env,
            trust_state.proxy_ssl_context,
            trust_state.proxy_tls_snapshot_sha256,
        ) = _prepare_claude_proxy_tls_environment(
            review,
            env,
        )
    else:
        if trust_state.proxy_tls_snapshot_sha256 is None:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy TLS snapshot binding is unavailable"
            )
        _verify_claude_proxy_tls_snapshot(
            trust_state.proxy_tls_env,
            trust_state.proxy_tls_snapshot_sha256,
        )
    if (
        _claude_https_proxy_tls_required(trust_state.proxy_tls_env)
        and trust_state.proxy_ssl_context is None
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy TLS context is unavailable"
        )
    return dict(trust_state.proxy_tls_env), trust_state.proxy_ssl_context


def _with_claude_tls_snapshot_inputs(
    env: dict[str, str],
    snapshot_env: dict[str, str],
) -> dict[str, str]:
    result = dict(env)
    for key in (*CLAUDE_TLS_FILE_ENV_KEYS, *CLAUDE_TLS_DIR_ENV_KEYS):
        value = snapshot_env.get(key)
        if value:
            result[key] = value
        else:
            result.pop(key, None)
    return result


def _require_private_claude_ca_root(path: pathlib.Path) -> None:
    try:
        path.mkdir(mode=0o700, exist_ok=True)
    except OSError as error:
        try:
            existing = path.lstat()
        except OSError:
            existing = None
        if existing is not None and (
            not stat.S_ISDIR(existing.st_mode)
            or existing.st_uid != os.geteuid()
            or existing.st_mode & 0o077
        ):
            raise ReviewError("Claude review CA directory has unsafe metadata")
        raise ClaudeExecutableInspectionInconclusive(
            "cannot prepare Claude review CA directory"
        ) from error
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise ReviewError("Claude CA workspace requires descriptor-safe directories")
    try:
        before = path.lstat()
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot inspect Claude review CA directory"
        ) from error
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o077
    ):
        raise ReviewError("Claude review CA directory has unsafe metadata")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory_flag,
        )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot open Claude review CA directory"
        ) from error
    try:
        try:
            opened = os.fstat(descriptor)
            after = path.lstat()
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot inspect Claude review CA directory"
            ) from error
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or _ca_source_metadata(before) != _ca_source_metadata(opened)
            or _ca_source_metadata(opened) != _ca_source_metadata(after)
        ):
            raise ReviewError("Claude review CA directory has unsafe metadata")
        _require_no_extended_acl(descriptor, label="Claude review CA directory")
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    else:
        try:
            os.close(descriptor)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot close Claude review CA directory"
            ) from error


def _write_private_ca_snapshot(path: pathlib.Path, data: bytes) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError as error:
        raise ReviewError(
            "Claude caller CA snapshot already exists before trust binding"
        ) from error
    except OSError as error:
        try:
            existing = path.lstat()
        except OSError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.geteuid()
            or existing.st_nlink != 1
            or existing.st_mode & 0o077
        ):
            raise ReviewError("caller CA snapshot has unsafe metadata")
        raise ClaudeExecutableInspectionInconclusive(
            "cannot create immutable caller CA snapshot"
        ) from error
    published = False
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
        published = True
    except ReviewError:
        raise
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot write immutable caller CA snapshot"
        ) from error
    finally:
        active_error = sys.exc_info()[0] is not None
        cleanup_error: OSError | None = None
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_error = error
        if not published:
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None and not active_error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot clean up immutable caller CA snapshot"
            ) from cleanup_error


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
    *,
    expected_snapshot_sha256: tuple[tuple[str, int, str, str], ...] | None = None,
) -> list[tuple[str, bytes]]:
    materials: list[tuple[str, bytes]] = []
    snapshot_material: dict[str, bytes] = {}
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
        snapshot_material[str(source_path)] = raw_material

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
                try:
                    before = os.fstat(descriptor)
                    names = _bounded_ca_directory_names(
                        descriptor,
                        CLAUDE_CA_DIR_ENTRY_LIMIT - directory_entry_count,
                        too_many_message=(
                            "Claude review CA directory has too many entries"
                        ),
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
                        snapshot_material[str(source_dir / name)] = raw_material
                        found_directory_certificate = True
                    after = os.fstat(descriptor)
                    if _ca_source_metadata(before) != _ca_source_metadata(after):
                        raise ClaudeExecutableInspectionInconclusive(
                            "Claude review CA directory changed while being read"
                        )
                except ReviewError:
                    raise
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        f"cannot inspect Claude review CA directory {key}: {error}"
                    ) from error
            except BaseException:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                raise
            else:
                try:
                    os.close(descriptor)
                except OSError as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        f"cannot close Claude review CA directory {key}: {error}"
                    ) from error
    if configured_directory and not found_directory_certificate:
        raise ReviewError("Claude review CA directory contains no PEM certificates")
    if expected_snapshot_sha256 is not None:
        _require_matching_claude_tls_snapshot(
            expected_snapshot_sha256,
            _claude_tls_snapshot_sha256(env, snapshot_material),
        )
    return materials


def _caller_ca_snapshot_material(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    trust_state: ClaudeTrustSessionState,
    expected_snapshot_sha256: tuple[tuple[str, int, str, str], ...] | None = None,
) -> bytes:
    snapshot = review.container_dir / "claude-ca" / CLAUDE_CALLER_CA_SNAPSHOT_NAME
    expected_digest = trust_state.caller_ca_snapshot_sha256
    if expected_digest is None:
        try:
            source_materials = _collect_claude_caller_ca_material(
                env,
                expected_snapshot_sha256=expected_snapshot_sha256,
            )
        except ClaudeExecutableInspectionInconclusive:
            raise
        except ReviewError as error:
            if expected_snapshot_sha256 is None:
                raise
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy TLS snapshot changed between attempts"
            ) from error
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
        trust_state.caller_ca_snapshot_sha256 = hashlib.sha256(material).hexdigest()
        trust_state.caller_ca_source_snapshot_sha256 = expected_snapshot_sha256
        return material

    bound_source_snapshot = trust_state.caller_ca_source_snapshot_sha256
    if expected_snapshot_sha256 is not None:
        if bound_source_snapshot is None:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude caller CA snapshot source binding is unavailable"
            )
        _require_matching_claude_tls_snapshot(
            expected_snapshot_sha256,
            bound_source_snapshot,
        )

    material = _read_claude_caller_ca_snapshot(snapshot)
    digest = hashlib.sha256(material).hexdigest()
    if not hmac.compare_digest(expected_digest, digest):
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
    expected_snapshot_sha256: tuple[tuple[str, int, str, str], ...] | None = None,
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
            expected_snapshot_sha256=expected_snapshot_sha256,
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
        try:
            bundle.chmod(0o400, follow_symlinks=False)
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "cannot make the Claude generated CA bundle read-only"
            ) from error
        bundle_material = _read_bounded_owner_file(
            bundle,
            source="generated bundle",
            limit_bytes=CLAUDE_CA_BUNDLE_LIMIT_BYTES,
            label="Claude generated CA bundle",
        )
        if bundle_material != merged:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude generated CA bundle changed during creation"
            )
        bundle_sha256 = hashlib.sha256(bundle_material).hexdigest()
        if trust_state.final_ca_bundle_sha256 is not None and not hmac.compare_digest(
            trust_state.final_ca_bundle_sha256,
            bundle_sha256,
        ):
            raise ClaudeExecutableInspectionInconclusive(
                "Claude generated CA bundle changed between attempts"
            )
        trust_state.final_ca_bundle_sha256 = bundle_sha256
        result = dict(env)
        for key in CLAUDE_TLS_BYPASS_ENV_KEYS:
            result.pop(key, None)
        for key in CLAUDE_TLS_DIR_ENV_KEYS:
            result.pop(key, None)
        for key in CLAUDE_TLS_REPLACEMENT_FILE_ENV_KEYS:
            result[key] = str(bundle)
        if env.get("NODE_EXTRA_CA_CERTS"):
            result["NODE_EXTRA_CA_CERTS"] = str(bundle)
        else:
            result.pop("NODE_EXTRA_CA_CERTS", None)
        result[CLAUDE_CERT_STORE_ENV] = CLAUDE_CERT_STORE
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="complete",
            unresolved_resolution="complete",
        )
        return result
    except ClaudeTrustSettingsDeny as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="denied",
            unresolved_resolution="blocked",
            primary_error=error,
        )
        raise
    except ClaudeTrustPolicyUnavailable as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
            primary_error=error,
        )
        raise
    except ClaudeTrustToolUnavailable as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="unavailable",
            unresolved_resolution="unavailable",
            primary_error=error,
        )
        raise
    except (
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewOutputLimitError,
        ReviewProcessLeakError,
        ClaudeExecutableInspectionInconclusive,
    ) as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
            primary_error=error,
        )
        raise
    except ReviewError as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="blocked",
            unresolved_resolution="blocked",
            primary_error=error,
        )
        raise
    except BaseException as error:
        _terminalize_claude_trust_policy_evidence(
            review,
            evidence,
            status="inconclusive",
            unresolved_resolution="inconclusive",
            primary_error=error,
        )
        raise


def _prepare_claude_tls_environment(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    executable_evidence: ClaudeExecutableTrustEvidence | None = None,
    trust_state: ClaudeTrustSessionState | None = None,
    expected_snapshot_sha256: tuple[tuple[str, int, str, str], ...] | None = None,
) -> dict[str, str]:
    if not _is_claude_macos_host():
        return _prepare_claude_generic_tls_environment(
            review,
            env,
            expected_snapshot_sha256=expected_snapshot_sha256,
        )
    if executable_evidence is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude macOS TLS preparation requires signed executable root evidence"
        )
    return _prepare_claude_macos_tls_environment(
        review,
        env,
        executable_evidence=executable_evidence,
        trust_state=trust_state or ClaudeTrustSessionState(),
        expected_snapshot_sha256=expected_snapshot_sha256,
    )


def _require_matching_claude_macos_tls_bundle(
    review: ReviewWorkspace,
    env: dict[str, str],
    *,
    trust_state: ClaudeTrustSessionState,
) -> None:
    expected_sha256 = trust_state.final_ca_bundle_sha256
    if expected_sha256 is None:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude generated CA bundle binding is unavailable"
        )
    bundle = review.container_dir / "claude-ca" / CLAUDE_CA_BUNDLE_NAME
    expected_path = str(bundle)
    if any(
        env.get(key) != expected_path for key in CLAUDE_TLS_REPLACEMENT_FILE_ENV_KEYS
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude generated CA bundle paths are inconsistent"
        )
    node_extra = env.get("NODE_EXTRA_CA_CERTS")
    if node_extra is not None and node_extra != expected_path:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude generated CA bundle paths are inconsistent"
        )
    if any(
        key in env for key in (*CLAUDE_TLS_DIR_ENV_KEYS, *CLAUDE_TLS_BYPASS_ENV_KEYS)
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude generated CA bundle environment changed before runtime launch"
        )
    if env.get(CLAUDE_CERT_STORE_ENV) != CLAUDE_CERT_STORE:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude generated CA bundle environment changed before runtime launch"
        )
    material = _read_bounded_owner_file(
        bundle,
        source="generated bundle",
        limit_bytes=CLAUDE_CA_BUNDLE_LIMIT_BYTES,
        label="Claude generated CA bundle",
    )
    if not hmac.compare_digest(expected_sha256, hashlib.sha256(material).hexdigest()):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude generated CA bundle changed before runtime launch"
        )
    try:
        metadata = bundle.lstat()
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot inspect the Claude generated CA bundle mode"
        ) from error
    if stat.S_IMODE(metadata.st_mode) != 0o400:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude generated CA bundle mode changed before runtime launch"
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


def _proxy_ca_subject_hashes(
    material: bytes,
    *,
    deadline: float,
    certificate_limit: int,
) -> tuple[frozenset[str], int]:
    try:
        openssl_metadata = CLAUDE_OPENSSL_CLIENT.lstat()
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy CA hash tooling is unavailable"
        ) from error
    if (
        not stat.S_ISREG(openssl_metadata.st_mode)
        or openssl_metadata.st_uid != 0
        or openssl_metadata.st_nlink != 1
        or openssl_metadata.st_mode & 0o6022
        or not os.access(CLAUDE_OPENSSL_CLIENT, os.X_OK)
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy CA hash tooling has unsafe metadata"
        )
    normalized = _extract_ca_certificates(
        material,
        source="Claude proxy CA hash entry",
    )
    blocks = CLAUDE_CERTIFICATE_BLOCK.findall(normalized)
    if len(blocks) > certificate_limit:
        raise ReviewError("Claude proxy CA hash certificate limit exceeded")
    canonical_blocks: list[bytes] = []
    for block in blocks:
        _der, canonical = _canonical_ca_certificate(
            block,
            source="Claude proxy CA hash entry",
        )
        # Prove certificate content in-process before interpreting external
        # subject-hash failures, whose diagnostics are operational evidence only.
        _proxy_ssl_context_from_material(
            canonical,
            source="Claude proxy CA hash entry",
        )
        canonical_blocks.append(canonical)
    hashes: set[str] = set()
    for block in canonical_blocks:
        call_started = time.monotonic()
        remaining_seconds = deadline - call_started
        if remaining_seconds <= 0:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy CA hash deadline expired"
            )
        call_deadline = min(
            deadline,
            call_started + CLAUDE_KEYCHAIN_QUERY_TIMEOUT_SECONDS,
        )
        try:
            completed = run_bounded_capture(
                (
                    str(CLAUDE_OPENSSL_CLIENT),
                    "x509",
                    "-subject_hash",
                    "-noout",
                ),
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                stdin=block,
                deadline=call_deadline,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=4096,
            )
        except ReviewTimeoutError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy CA subject hash timed out"
            ) from error
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy CA hash tooling could not be launched"
            ) from error
        try:
            if time.monotonic() >= deadline:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude proxy CA hash deadline expired"
                )
            match = re.fullmatch(rb"([0-9a-f]{8})\r?\n", bytes(completed.stdout))
            if completed.returncode != 0 or completed.stderr or match is None:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude proxy CA subject hash is inconclusive"
                )
            hashes.add(match.group(1).decode("ascii"))
        finally:
            completed.stdout[:] = b"\x00" * len(completed.stdout)
            completed.stderr[:] = b"\x00" * len(completed.stderr)
    if not hashes:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy CA hash entry contains no certificate"
        )
    return frozenset(hashes), len(blocks)


def _new_proxy_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_flags |= CLAUDE_PROXY_TLS_VERIFY_FLAGS
    return context


def _proxy_system_ca_directory_identity(
    metadata: os.stat_result,
) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _revalidate_proxy_system_ca_parent_chain(
    descriptors: tuple[int, ...],
    components: tuple[str, ...],
    expected_identities: tuple[tuple[int, ...], ...],
    expected_parent_metadata: tuple[int, ...],
    *,
    source: str,
) -> None:
    try:
        for index, (descriptor, expected) in enumerate(
            zip(descriptors, expected_identities, strict=True)
        ):
            if _proxy_system_ca_directory_identity(os.fstat(descriptor)) != expected:
                raise ClaudeExecutableInspectionInconclusive(
                    f"{source} parent path changed during inspection"
                )
            if index == 0:
                continue
            lexical = os.stat(
                components[index - 1],
                dir_fd=descriptors[index - 1],
                follow_symlinks=False,
            )
            if _proxy_system_ca_directory_identity(lexical) != expected:
                raise ClaudeExecutableInspectionInconclusive(
                    f"{source} parent path changed during inspection"
                )
        if _ca_source_metadata(os.fstat(descriptors[-1])) != expected_parent_metadata:
            raise ClaudeExecutableInspectionInconclusive(
                f"{source} parent path changed during inspection"
            )
        if components:
            lexical_parent = os.stat(
                components[-1],
                dir_fd=descriptors[-2],
                follow_symlinks=False,
            )
            if _ca_source_metadata(lexical_parent) != expected_parent_metadata:
                raise ClaudeExecutableInspectionInconclusive(
                    f"{source} parent path changed during inspection"
                )
    except ClaudeExecutableInspectionInconclusive:
        raise
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot revalidate the stable {source} parent path"
        ) from error


def _require_proxy_system_ca_absence_current(
    descriptors: tuple[int, ...],
    components: tuple[str, ...],
    expected_identities: tuple[tuple[int, ...], ...],
    expected_parent_metadata: tuple[int, ...],
    entry_name: str,
    *,
    source: str,
) -> None:
    for _ in range(2):
        try:
            os.stat(
                entry_name,
                dir_fd=descriptors[-1],
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot recheck the stable absence of {source}"
            ) from error
        else:
            raise ClaudeExecutableInspectionInconclusive(
                f"{source} appeared while the CA directory snapshot was bound"
            )
        _revalidate_proxy_system_ca_parent_chain(
            descriptors,
            components,
            expected_identities,
            expected_parent_metadata,
            source=source,
        )


@contextlib.contextmanager
def _proxy_system_ca_path_absence(
    path: pathlib.Path,
    *,
    source: str,
) -> Iterator[bool]:
    if (
        not path.is_absolute()
        or not path.name
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ClaudeExecutableInspectionInconclusive(
            f"{source} path is not lexically absolute"
        )
    components = tuple(path.parts[1:-1])
    descriptors: list[int] = []
    expected_identities: list[tuple[int, ...]] = []
    pending_descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        try:
            flags = _ca_nofollow_flags(directory=True)
            pending_descriptor = os.open(os.sep, flags)
            descriptors.append(pending_descriptor)
            pending_descriptor = None
            root_metadata = os.fstat(descriptors[0])
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise ClaudeExecutableInspectionInconclusive(
                    f"{source} root is not a stable directory"
                )
            expected_identities.append(
                _proxy_system_ca_directory_identity(root_metadata)
            )
            for component in components:
                parent_descriptor = descriptors[-1]
                before = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if not stat.S_ISDIR(before.st_mode):
                    raise ClaudeExecutableInspectionInconclusive(
                        f"{source} has an ambiguous parent path"
                    )
                pending_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=parent_descriptor,
                )
                descriptors.append(pending_descriptor)
                pending_descriptor = None
                opened = os.fstat(descriptors[-1])
                after = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                opened_identity = _proxy_system_ca_directory_identity(opened)
                if (
                    _proxy_system_ca_directory_identity(before) != opened_identity
                    or _proxy_system_ca_directory_identity(after) != opened_identity
                ):
                    raise ClaudeExecutableInspectionInconclusive(
                        f"{source} parent path changed while being opened"
                    )
                expected_identities.append(opened_identity)
            descriptor_snapshot = tuple(descriptors)
            identity_snapshot = tuple(expected_identities)
            parent_metadata_snapshot = _ca_source_metadata(
                os.fstat(descriptor_snapshot[-1])
            )
            _revalidate_proxy_system_ca_parent_chain(
                descriptor_snapshot,
                components,
                identity_snapshot,
                parent_metadata_snapshot,
                source=source,
            )
            try:
                os.stat(
                    path.name,
                    dir_fd=descriptor_snapshot[-1],
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                missing = True
            else:
                missing = False
            if missing:
                _require_proxy_system_ca_absence_current(
                    descriptor_snapshot,
                    components,
                    identity_snapshot,
                    parent_metadata_snapshot,
                    path.name,
                    source=source,
                )
            else:
                _revalidate_proxy_system_ca_parent_chain(
                    descriptor_snapshot,
                    components,
                    identity_snapshot,
                    parent_metadata_snapshot,
                    source=source,
                )
        except ClaudeExecutableInspectionInconclusive:
            raise
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot establish a stable lexical inspection of {source}"
            ) from error

        yield missing

        if missing:
            _require_proxy_system_ca_absence_current(
                descriptor_snapshot,
                components,
                identity_snapshot,
                parent_metadata_snapshot,
                path.name,
                source=source,
            )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[OSError] = []
        if pending_descriptor is not None and pending_descriptor not in descriptors:
            try:
                os.close(pending_descriptor)
            except OSError as error:
                cleanup_errors.append(error)
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_errors.append(error)
        if cleanup_errors and primary_error is None:
            raise ClaudeExecutableInspectionInconclusive(
                f"cannot close the stable {source} parent path"
            ) from cleanup_errors[0]


def _proxy_ssl_context_from_material(
    material: bytes,
    *,
    source: str,
) -> ssl.SSLContext:
    context = _new_proxy_ssl_context()
    try:
        context.load_verify_locations(cadata=material.decode("ascii"))
    except (UnicodeDecodeError, binascii.Error, ValueError, ssl.SSLError) as error:
        raise ReviewError(
            f"Claude review CA source contains an invalid certificate: {source}"
        ) from error
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy CA snapshot could not be loaded"
        ) from error
    return context


def _proxy_ssl_context_from_system_capath(
    default_capath: pathlib.Path,
    *,
    cafile_was_configured: bool,
) -> ssl.SSLContext:
    if not default_capath.is_absolute():
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy system CA directory is not absolute"
        )
    try:
        default_capath.lstat()
    except FileNotFoundError:
        with _proxy_system_ca_path_absence(
            default_capath,
            source="Claude proxy system CA directory",
        ) as capath_missing:
            if not capath_missing:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude proxy system CA directory appeared while its absence "
                    "was being proven"
                )
            if cafile_was_configured:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude proxy system CA file and directory are missing"
                )
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy system CA directory is missing"
            )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "cannot inspect Claude proxy system CA directory"
        ) from error
    default_snapshots = _read_proxy_system_ca_directory(default_capath)
    return _proxy_ssl_context(
        {"SSL_CERT_DIR": str(default_capath)},
        snapshot_material=default_snapshots,
    )


def _proxy_ssl_context(
    env: dict[str, str],
    *,
    snapshot_material: dict[str, bytes],
) -> ssl.SSLContext:
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
    configured_directories = [
        pathlib.Path(raw)
        for raw in env.get("SSL_CERT_DIR", "").split(os.pathsep)
        if raw
    ]
    directory_material: list[bytes] = []
    subject_hash_cache: dict[bytes, frozenset[str]] = {}
    subject_hash_deadline = time.monotonic() + CLAUDE_PROXY_CA_HASH_TIMEOUT_SECONDS
    remaining_hash_certificates = CLAUDE_PROXY_CA_HASH_CERTIFICATE_LIMIT
    for directory in configured_directories:
        indexed: dict[str, dict[int, bytes]] = {}
        for path, material in snapshot_material.items():
            snapshot_path = pathlib.Path(path)
            if snapshot_path.parent != directory:
                continue
            match = CLAUDE_OPENSSL_CA_HASH_ENTRY_RE.fullmatch(snapshot_path.name)
            if match is None:
                continue
            indexed.setdefault(match.group(1), {})[int(match.group(2))] = material
        for subject_hash in sorted(indexed):
            entries = indexed[subject_hash]
            index = 0
            while index in entries:
                if time.monotonic() >= subject_hash_deadline:
                    raise ClaudeExecutableInspectionInconclusive(
                        "Claude proxy CA hash deadline expired"
                    )
                material = entries[index]
                digest = hashlib.sha256(material).digest()
                material_hashes = subject_hash_cache.get(digest)
                if material_hashes is None:
                    material_hashes, consumed_certificates = _proxy_ca_subject_hashes(
                        material,
                        deadline=subject_hash_deadline,
                        certificate_limit=remaining_hash_certificates,
                    )
                    remaining_hash_certificates -= consumed_certificates
                    subject_hash_cache[digest] = material_hashes
                if material_hashes == {subject_hash}:
                    directory_material.append(material)
                index += 1
    if configured_directories and time.monotonic() >= subject_hash_deadline:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy CA hash deadline expired"
        )
    try:
        replacement_configured = cafile is not None or bool(configured_directories)
        if replacement_configured:
            materials: list[bytes] = []
            if cafile is not None:
                file_material = snapshot_material.get(cafile)
                if file_material is None:
                    raise ClaudeExecutableInspectionInconclusive(
                        "Claude proxy CA file snapshot is incomplete"
                    )
                materials.append(file_material)
            materials.extend(directory_material)
            if not materials:
                raise ReviewError(
                    "Claude proxy CA replacement contains no indexed certificates"
                )
            context = _proxy_ssl_context_from_material(
                b"".join(materials),
                source="Claude proxy CA snapshot",
            )
        else:
            if sys.platform == "darwin":
                default_cafile = CLAUDE_SYSTEM_CA_FILE
            else:
                defaults = ssl.get_default_verify_paths()
                openssl_cafile = getattr(defaults, "openssl_cafile", None)
                openssl_capath = getattr(defaults, "openssl_capath", None)
                default_cafile = (
                    pathlib.Path(openssl_cafile)
                    if isinstance(openssl_cafile, str) and openssl_cafile
                    else None
                )
                if default_cafile is not None:
                    if not default_cafile.is_absolute():
                        raise ClaudeExecutableInspectionInconclusive(
                            "Claude proxy system CA file is not absolute"
                        )
                    try:
                        default_cafile_metadata = default_cafile.lstat()
                    except FileNotFoundError:
                        with _proxy_system_ca_path_absence(
                            default_cafile,
                            source="Claude proxy system CA file",
                        ) as cafile_missing:
                            if not cafile_missing:
                                raise ClaudeExecutableInspectionInconclusive(
                                    "Claude proxy system CA file appeared while its "
                                    "absence was being proven"
                                )
                            if (
                                not isinstance(openssl_capath, str)
                                or not openssl_capath
                            ):
                                raise ClaudeExecutableInspectionInconclusive(
                                    "Claude proxy system CA file is missing and no CA "
                                    "directory is configured"
                                )
                            # Exiting this scope rechecks cafile absence after the
                            # capath snapshot has been bound into the in-memory context.
                            return _proxy_ssl_context_from_system_capath(
                                pathlib.Path(openssl_capath),
                                cafile_was_configured=True,
                            )
                    except OSError as error:
                        raise ClaudeExecutableInspectionInconclusive(
                            "cannot inspect Claude proxy system CA file"
                        ) from error
                    if stat.S_ISLNK(default_cafile_metadata.st_mode):
                        if not isinstance(openssl_capath, str) or not openssl_capath:
                            raise ClaudeExecutableInspectionInconclusive(
                                "Claude proxy system CA file is a symlink and no CA "
                                "directory is configured"
                            )
                        return _proxy_ssl_context_from_system_capath(
                            pathlib.Path(openssl_capath),
                            cafile_was_configured=True,
                        )
                    default_material = _read_proxy_system_ca_source(default_cafile)
                    return _proxy_ssl_context_from_material(
                        default_material,
                        source="Claude proxy system CA bundle",
                    )
                if not isinstance(openssl_capath, str) or not openssl_capath:
                    raise ClaudeExecutableInspectionInconclusive(
                        "Claude proxy system CA paths are unavailable"
                    )
                return _proxy_ssl_context_from_system_capath(
                    pathlib.Path(openssl_capath),
                    cafile_was_configured=False,
                )
            if not default_cafile.is_absolute():
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude proxy system CA file is not absolute"
                )
            try:
                resolved_default_cafile = default_cafile.resolve(strict=True)
            except OSError as error:
                raise ClaudeExecutableInspectionInconclusive(
                    "Claude proxy system CA file is unavailable"
                ) from error
            default_material = _read_proxy_system_ca_source(resolved_default_cafile)
            context = _proxy_ssl_context_from_material(
                default_material,
                source="Claude proxy system CA bundle",
            )
    except OSError as error:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy CA snapshot could not be loaded"
        ) from error
    if configured_directories and time.monotonic() >= subject_hash_deadline:
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy CA hash deadline expired"
        )
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


def _claude_https_proxy_tls_required(
    env: dict[str, str],
    *,
    allowed_targets: frozenset[tuple[str, int]] = CLAUDE_PROXY_TARGETS,
) -> bool:
    requires_tls = False
    for host, port in allowed_targets:
        upstream_url = _upstream_proxy_url(env, host=host, port=port)
        if upstream_url is None:
            continue
        parsed, _proxy_port = _parse_upstream_proxy_url(upstream_url)
        requires_tls = requires_tls or parsed.scheme == "https"
    return requires_tls


def _open_proxy_target(
    host: str,
    port: int,
    *,
    env: dict[str, str],
    upstream_ssl_context: ssl.SSLContext | None,
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
        if upstream_ssl_context is None:
            connection.close()
            raise ClaudeExecutableInspectionInconclusive(
                "Claude proxy TLS context is unavailable"
            )
        connection = upstream_ssl_context.wrap_socket(
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
            upstream = _open_proxy_target(
                *target,
                env=server.upstream_env,
                upstream_ssl_context=server.upstream_ssl_context,
            )
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
        upstream_ssl_context: ssl.SSLContext | None,
    ) -> None:
        self.allowed_targets = allowed_targets
        self.upstream_env = dict(upstream_env)
        self.upstream_ssl_context = upstream_ssl_context
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
        upstream_ssl_context: ssl.SSLContext | None,
    ) -> None:
        self.allowed_targets = allowed_targets
        self.upstream_env = dict(upstream_env)
        self.upstream_ssl_context = upstream_ssl_context
        super().__init__(str(socket_path), _ClaudeProxyHandler)
        self._initialize_serve_state()


def _shutdown_claude_proxy_server(
    server: _ClaudeProxyServeState,
    thread: threading.Thread | None,
    *,
    thread_start_state: _ClaudeThreadStartState,
    primary_error: BaseException | None,
    thread_start_error: BaseException | None = None,
    socket_path: pathlib.Path | None = None,
) -> None:
    cleanup_errors: list[BaseException] = []
    post_start_serve_error = False
    serving = False
    thread_may_have_started = (
        thread_start_state is not _ClaudeThreadStartState.NOT_STARTED
    )
    if thread_may_have_started:
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
    if thread_may_have_started and thread is not None:
        thread_stopped, quiescence_error = _bounded_claude_thread_quiescence(
            thread,
            thread_start_state,
            CLAUDE_PROXY_SERVER_SHUTDOWN_TIMEOUT_SECONDS,
        )
        if quiescence_error is not None:
            cleanup_errors.append(quiescence_error)
        if not thread_stopped:
            cleanup_errors.append(
                ClaudeCredentialInspectionInconclusive(
                    "Claude CONNECT proxy thread did not publish startup and "
                    "stop before the shutdown deadline"
                )
            )
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
    if thread_start_error is not None and not _claude_visible_error_chain_contains(
        primary_error,
        thread_start_error,
    ):
        cleanup_errors.insert(0, thread_start_error)
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
    upstream_ssl_context: ssl.SSLContext | None,
    allowed_targets: frozenset[tuple[str, int]] = CLAUDE_PROXY_TARGETS,
) -> Iterator[int]:
    if (
        _claude_https_proxy_tls_required(env, allowed_targets=allowed_targets)
        and upstream_ssl_context is None
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy TLS context is unavailable"
        )
    try:
        server = _ClaudeProxyServer(
            allowed_targets=allowed_targets,
            upstream_env=env,
            upstream_ssl_context=upstream_ssl_context,
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
    thread_start_state = _ClaudeThreadStartState.NOT_STARTED
    thread_start_error: BaseException | None = None
    thread_start_owner = _ClaudeThreadStartOwner()
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
        serve_cancelled.set()
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
            _start_claude_thread_inheriting_forwarded_signal_mask(
                thread,
                thread_start_owner=thread_start_owner,
            )
            start_snapshot = thread_start_owner.snapshot
            if start_snapshot.error is not None:
                raise start_snapshot.error
        except ForwardedSignal:
            raise
        except Exception as error:
            raise ClaudeCredentialInspectionInconclusive(
                f"Claude CONNECT proxy cannot start: {error}"
            ) from error
        serve_cancelled.clear()
        serve_admitted = True
        serve_gate.set()
        if not server.wait_until_serving(CLAUDE_PROXY_SERVER_START_TIMEOUT_SECONDS):
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
        start_handoff_error: BaseException | None = None
        snapshot_refresh_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        try:
            try:
                try:
                    final_start_snapshot = thread_start_owner.snapshot
                    thread_start_state = final_start_snapshot.state
                    thread_start_error = final_start_snapshot.error
                finally:
                    try:
                        if not serve_admitted:
                            serve_cancelled.set()
                    finally:
                        serve_gate.set()
            except BaseException as error:
                start_handoff_error = error
            final_start_snapshot = thread_start_owner.snapshot
            thread_start_state = final_start_snapshot.state
            thread_start_error = final_start_snapshot.error
        except BaseException as error:
            snapshot_refresh_error = error
        finally:
            try:
                _shutdown_claude_proxy_server(
                    server,
                    thread,
                    thread_start_state=thread_start_state,
                    primary_error=primary_error,
                    thread_start_error=thread_start_error,
                )
            except BaseException as error:
                cleanup_error = error
        selected_error = _select_claude_thread_start_related_error(
            start_handoff_error,
            snapshot_refresh_error,
        )
        selected_error = _select_claude_thread_start_related_error(
            selected_error,
            cleanup_error,
        )
        if (
            selected_error is not None
            and thread_start_error is not None
            and not _claude_visible_error_chain_contains(
                selected_error,
                thread_start_error,
            )
        ):
            selected_error = _select_claude_thread_start_related_error(
                thread_start_error,
                selected_error,
            )
        if selected_error is not None:
            selected_error = _select_claude_thread_start_related_error(
                primary_error,
                selected_error,
            )
            if selected_error is not primary_error:
                raise selected_error


@contextlib.contextmanager
def _claude_unix_connect_proxy(
    _review: ReviewWorkspace,
    env: dict[str, str],
    *,
    upstream_ssl_context: ssl.SSLContext | None,
    allowed_targets: frozenset[tuple[str, int]] = CLAUDE_PROXY_TARGETS,
) -> Iterator[pathlib.Path]:
    if (
        _claude_https_proxy_tls_required(env, allowed_targets=allowed_targets)
        and upstream_ssl_context is None
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy TLS context is unavailable"
        )
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
                upstream_ssl_context=upstream_ssl_context,
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
                f"Claude CONNECT proxy cannot make its Unix socket private: {error}"
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
        thread_start_state = _ClaudeThreadStartState.NOT_STARTED
        thread_start_error: BaseException | None = None
        thread_start_owner = _ClaudeThreadStartOwner()
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
            serve_cancelled.set()
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
                    f"Claude Unix CONNECT proxy cannot construct its thread: {error}"
                ) from error
            try:
                _start_claude_thread_inheriting_forwarded_signal_mask(
                    thread,
                    thread_start_owner=thread_start_owner,
                )
                start_snapshot = thread_start_owner.snapshot
                if start_snapshot.error is not None:
                    raise start_snapshot.error
            except ForwardedSignal:
                raise
            except Exception as error:
                raise ClaudeCredentialInspectionInconclusive(
                    f"Claude Unix CONNECT proxy cannot start: {error}"
                ) from error
            serve_cancelled.clear()
            serve_admitted = True
            serve_gate.set()
            if not server.wait_until_serving(CLAUDE_PROXY_SERVER_START_TIMEOUT_SECONDS):
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
            start_handoff_error: BaseException | None = None
            snapshot_refresh_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            try:
                try:
                    try:
                        final_start_snapshot = thread_start_owner.snapshot
                        thread_start_state = final_start_snapshot.state
                        thread_start_error = final_start_snapshot.error
                    finally:
                        try:
                            if not serve_admitted:
                                serve_cancelled.set()
                        finally:
                            serve_gate.set()
                except BaseException as error:
                    start_handoff_error = error
                final_start_snapshot = thread_start_owner.snapshot
                thread_start_state = final_start_snapshot.state
                thread_start_error = final_start_snapshot.error
            except BaseException as error:
                snapshot_refresh_error = error
            finally:
                try:
                    _shutdown_claude_proxy_server(
                        server,
                        thread,
                        thread_start_state=thread_start_state,
                        primary_error=primary_error,
                        thread_start_error=thread_start_error,
                        socket_path=socket_path,
                    )
                except BaseException as error:
                    cleanup_error = error
            selected_error = _select_claude_thread_start_related_error(
                start_handoff_error,
                snapshot_refresh_error,
            )
            selected_error = _select_claude_thread_start_related_error(
                selected_error,
                cleanup_error,
            )
            if (
                selected_error is not None
                and thread_start_error is not None
                and not _claude_visible_error_chain_contains(
                    selected_error,
                    thread_start_error,
                )
            ):
                selected_error = _select_claude_thread_start_related_error(
                    thread_start_error,
                    selected_error,
                )
            if selected_error is not None:
                selected_error = _select_claude_thread_start_related_error(
                    primary_error,
                    selected_error,
                )
                if selected_error is not primary_error:
                    raise selected_error


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
    descriptor_bound_workspace: bool = False,
) -> dict[str, str]:
    review_values = {
        "CODEX_ISOLATED_REVIEW_ROOT": (
            "." if descriptor_bound_workspace else str(review.workspace_root)
        ),
        "CODEX_ISOLATED_REVIEW_DIFF_FILE": (
            ".codex-review/review.diff"
            if descriptor_bound_workspace
            else str(review.diff_file)
        ),
        "CODEX_ISOLATED_REVIEW_PROMPT_FILE": (
            ".codex-review/review.prompt"
            if descriptor_bound_workspace
            else str(review.prompt_file)
        ),
        "CODEX_ISOLATED_REVIEW_RANGE": f"{review.base_ref}..{review.head_ref}",
    }
    if extra:
        review_values.update(extra)
    return child_environment(
        container_dir=review.container_dir,
        passthrough_keys=passthrough_keys,
        extra=review_values,
    )


def _claude_authentication_source(env: Mapping[str, str]) -> str:
    if env.get("ANTHROPIC_API_KEY"):
        return "api-key"
    if env.get("CLAUDE_CODE_OAUTH_TOKEN"):
        return "oauth-token"
    return "local-login"


def _claude_uses_explicit_auth(env: Mapping[str, str]) -> bool:
    return _claude_authentication_source(env) != "local-login"


def _strict_proxy_component_unquote(value: str) -> str:
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ReviewError(
            "credential-bearing proxy URL cannot be safely normalized for output "
            "redaction"
        )
    try:
        decoded = urllib.parse.unquote_to_bytes(value).decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError) as error:
        raise ReviewError(
            "credential-bearing proxy URL cannot be safely normalized for output "
            "redaction"
        ) from error
    if "\x00" in decoded:
        raise ReviewError(
            "credential-bearing proxy URL cannot be safely normalized for output "
            "redaction"
        )
    return decoded


def _proxy_percent_escape_case(value: str, *, upper: bool) -> str:
    def replace_escape(match: re.Match[str]) -> str:
        escape = match.group(0)
        return escape.upper() if upper else escape.lower()

    return re.sub(r"%[0-9A-Fa-f]{2}", replace_escape, value)


def _proxy_quote_preserving_escapes(value: str) -> str:
    output: list[str] = []
    start = 0
    for escape in re.finditer(r"%[0-9A-Fa-f]{2}", value):
        if escape.start() > start:
            output.append(
                urllib.parse.quote(
                    value[start : escape.start()],
                    safe=CLAUDE_PROXY_USERINFO_SAFE_CHARACTERS,
                )
            )
        output.append(escape.group(0))
        start = escape.end()
    if start < len(value):
        output.append(
            urllib.parse.quote(
                value[start:],
                safe=CLAUDE_PROXY_USERINFO_SAFE_CHARACTERS,
            )
        )
    return "".join(output)


def _proxy_component_redact_values(value: str) -> tuple[str, ...]:
    without_controls = value.translate(CLAUDE_PROXY_IGNORED_URL_CONTROLS)
    decoded = _strict_proxy_component_unquote(without_controls)
    without_diagnostic_controls = "".join(
        character
        for character in without_controls
        if unicodedata.category(character) != "Cc"
    )
    decoded_without_diagnostic_controls = "".join(
        character for character in decoded if unicodedata.category(character) != "Cc"
    )
    encoded = urllib.parse.quote(
        decoded,
        safe=CLAUDE_PROXY_USERINFO_SAFE_CHARACTERS,
    )
    diagnostic_encoded = urllib.parse.quote(
        decoded_without_diagnostic_controls,
        safe=CLAUDE_PROXY_USERINFO_SAFE_CHARACTERS,
    )
    preserving_encoded = _proxy_quote_preserving_escapes(without_controls)
    diagnostic_preserving_encoded = _proxy_quote_preserving_escapes(
        without_diagnostic_controls
    )
    variants = tuple(
        dict.fromkeys(
            item
            for item in (
                value,
                without_controls,
                _proxy_percent_escape_case(without_controls, upper=True),
                _proxy_percent_escape_case(without_controls, upper=False),
                without_diagnostic_controls,
                decoded,
                decoded_without_diagnostic_controls,
                encoded,
                _proxy_percent_escape_case(encoded, upper=False),
                preserving_encoded,
                _proxy_percent_escape_case(preserving_encoded, upper=True),
                _proxy_percent_escape_case(preserving_encoded, upper=False),
                diagnostic_encoded,
                _proxy_percent_escape_case(diagnostic_encoded, upper=False),
                diagnostic_preserving_encoded,
                _proxy_percent_escape_case(
                    diagnostic_preserving_encoded,
                    upper=True,
                ),
                _proxy_percent_escape_case(
                    diagnostic_preserving_encoded,
                    upper=False,
                ),
            )
            if item
        )
    )
    try:
        minimum_size = min(len(os.fsencode(item)) for item in variants)
    except UnicodeEncodeError as error:
        raise ReviewError(
            "credential-bearing proxy URL cannot be safely normalized for output "
            "redaction"
        ) from error
    if minimum_size < CLAUDE_PROXY_MINIMUM_STANDALONE_REDACTION_BYTES:
        raise ReviewError(
            "credential-bearing proxy URL contains a credential component too "
            "short for safe output redaction"
        )
    return variants


def _proxy_url_userinfo(value: str) -> tuple[str | None, bool]:
    special_match = re.match(r"(?is)^https?:(.*)$", value)
    if special_match is not None:
        authority = special_match.group(1).lstrip("/\\")
    else:
        _scheme, separator, remainder = value.partition("://")
        authority = remainder if separator else value
    for delimiter in ("/", "\\", "?", "#"):
        authority = authority.partition(delimiter)[0]
    userinfo, separator, _host = authority.rpartition("@")
    if not separator:
        return None, False
    if not userinfo:
        return None, True
    normalized_userinfo = userinfo.translate(CLAUDE_PROXY_IGNORED_URL_CONTROLS)
    username, password_separator, password = normalized_userinfo.partition(":")
    if password_separator:
        return (userinfo if username or password else None), True
    return (userinfo if normalized_userinfo else None), True


def _proxy_url_redact_values(value: str) -> tuple[str, ...]:
    candidate = value.strip()
    if not candidate:
        return ()
    normalized_candidate = candidate.translate(CLAUDE_PROXY_IGNORED_URL_CONTROLS)
    diagnostic_candidate = "".join(
        character
        for character in normalized_candidate
        if unicodedata.category(character) != "Cc"
    )
    candidates = tuple(
        dict.fromkeys((candidate, normalized_candidate, diagnostic_candidate))
    )
    parsed_userinfos = tuple(_proxy_url_userinfo(current) for current in candidates)
    userinfos = tuple(
        dict.fromkeys(
            userinfo
            for userinfo, _authority_at_seen in parsed_userinfos
            if userinfo is not None
        )
    )
    if not userinfos:
        authority_at_seen = any(observed for _userinfo, observed in parsed_userinfos)
        if "@" in diagnostic_candidate and (
            not authority_at_seen or diagnostic_candidate.count("@") != 1
        ):
            raise ReviewError(
                "proxy URL contains an ambiguous credential delimiter and cannot "
                "be safely redacted"
            )
        return ()
    values = [value, *candidates]
    for userinfo in userinfos:
        values.extend(_proxy_component_redact_values(userinfo))
        username, password_separator, password = userinfo.partition(":")
        if not password_separator:
            continue
        if password:
            values.extend(_proxy_component_redact_values(password))
            normalized_username = username.translate(CLAUDE_PROXY_IGNORED_URL_CONTROLS)
            normalized_password = password.translate(CLAUDE_PROXY_IGNORED_URL_CONTROLS)
            canonical_userinfo = (
                urllib.parse.quote(
                    _strict_proxy_component_unquote(normalized_username),
                    safe=CLAUDE_PROXY_USERINFO_SAFE_CHARACTERS,
                )
                + ":"
                + urllib.parse.quote(
                    _strict_proxy_component_unquote(normalized_password),
                    safe=CLAUDE_PROXY_USERINFO_SAFE_CHARACTERS,
                )
            )
            values.extend(
                (
                    canonical_userinfo,
                    _proxy_percent_escape_case(canonical_userinfo, upper=False),
                )
            )
        elif username:
            values.extend(_proxy_component_redact_values(username))
    return tuple(dict.fromkeys(item for item in values if item))


def claude_output_redact_values(environment: Mapping[str, str]) -> tuple[str, ...]:
    """Return the winning Claude credential and proxy transports for redaction."""

    values: list[str] = []
    if value := environment.get("ANTHROPIC_API_KEY"):
        values.append(value)
    elif value := environment.get("CLAUDE_CODE_OAUTH_TOKEN"):
        values.append(value)
    for key in CLAUDE_PROXY_URL_ENV_KEYS:
        if value := environment.get(key):
            values.extend(_proxy_url_redact_values(value))
    return tuple(dict.fromkeys(values))


def _select_claude_authentication(env: Mapping[str, str]) -> dict[str, str]:
    """Select one explicit source without retaining the losing credential."""

    selected = dict(env)
    if selected.get("ANTHROPIC_API_KEY"):
        selected.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
    elif selected.get("CLAUDE_CODE_OAUTH_TOKEN"):
        selected.pop("ANTHROPIC_API_KEY", None)
    else:
        for key in CLAUDE_EXPLICIT_AUTH_ENV_KEYS:
            selected.pop(key, None)
    return selected


def _claude_authentication_action(source: str) -> str:
    if source == "api-key":
        return CLAUDE_API_KEY_ACTION
    if source == "oauth-token":
        return CLAUDE_OAUTH_TOKEN_ACTION
    return CLAUDE_AUTH_LOGIN_ACTION


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
    if not _is_claude_linux_host() and not _claude_uses_explicit_auth(env):
        broker_raw = env.get(CLAUDE_KEYCHAIN_BROKER_EXECUTABLE_ENV)
        security = pathlib.Path(broker_raw) if broker_raw else None
        if (
            security is None
            or not security.is_absolute()
            or security.name != "security"
            or security != CLAUDE_KEYCHAIN_BROKER_INSTALL_PATH
        ):
            raise ReviewError(
                "Claude local-login sandbox requires the restricted Keychain broker"
            )
        _require_installed_claude_keychain_broker()
        entries.append(security.parent)
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
    workspace_path: pathlib.Path | None = None,
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
    workspace = (
        review.workspace_root.resolve() if workspace_path is None else workspace_path
    )
    if not workspace.is_absolute() or not workspace.is_dir():
        raise ReviewError("Claude Code review sandbox requires a valid workspace")
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
    keychain_broker_identity_socket: pathlib.Path | None = None
    canonical_keychain_broker_identity_socket: pathlib.Path | None = None
    if not _claude_uses_explicit_auth(env):
        broker_raw = env.get(CLAUDE_KEYCHAIN_BROKER_EXECUTABLE_ENV)
        if not broker_raw:
            raise ReviewError(
                "Claude local-login sandbox requires the restricted Keychain broker"
            )
        security_candidate = pathlib.Path(broker_raw)
        path_entries = tuple(
            pathlib.Path(entry)
            for entry in env.get("PATH", "").split(os.pathsep)
            if entry
        )
        if (
            not security_candidate.is_absolute()
            or security_candidate.name != "security"
            or security_candidate != CLAUDE_KEYCHAIN_BROKER_INSTALL_PATH
            or not path_entries
            or path_entries[0] != security_candidate.parent
        ):
            raise ReviewError(
                "Claude local-login sandbox requires the restricted Keychain broker"
            )
        _require_installed_claude_keychain_broker()
        auth_executables = _native_macho_dependencies(
            security_candidate,
            label="Claude Keychain broker",
        )
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
        identity_socket_raw = env.get(CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET_ENV)
        if not identity_socket_raw:
            raise ReviewError(
                "Claude local-login sandbox requires a Keychain broker identity socket"
            )
        keychain_broker_identity_socket = pathlib.Path(identity_socket_raw)
        identity_directory_raw = env.get(CLAUDE_KEYCHAIN_BROKER_IDENTITY_DIRECTORY_ENV)
        identity_directory = (
            pathlib.Path(identity_directory_raw) if identity_directory_raw else None
        )
        if (
            not keychain_broker_identity_socket.is_absolute()
            or identity_directory is None
            or not identity_directory.is_absolute()
            or keychain_broker_identity_socket.parent != identity_directory
            or keychain_broker_identity_socket.name
            != CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET_NAME
        ):
            raise ReviewError(
                "Claude local-login sandbox requires a valid Keychain broker "
                "identity socket"
            )
        canonical_keychain_broker_identity_socket = (
            _require_claude_keychain_identity_socket(keychain_broker_identity_socket)
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
        workspace,
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
        f"(global-name {json.dumps(name)})" for name in CLAUDE_REVIEW_BASE_MACH_SERVICES
    )
    network_filters = f'(remote ip "localhost:{proxy_port}")'
    if keychain_broker_port is not None:
        network_filters += f'(remote ip "localhost:{keychain_broker_port}")'
    if canonical_keychain_broker_identity_socket is not None:
        network_filters += _sandbox_path_filter(
            "literal",
            canonical_keychain_broker_identity_socket,
        )
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
        try:
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
        except OSError as error:
            raise ClaudeExecutableInspectionInconclusive(
                f"Claude executable probe launch was inconclusive: {error}"
            ) from error


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
    *,
    version: ClaudeVersion | None = None,
) -> ClaudeCapabilities | None:
    completed = _run_claude_probe(executable, env, "--help")
    help_text = (completed.stdout + b"\n" + completed.stderr).decode(
        "utf-8", errors="replace"
    )
    if completed.returncode != 0:
        raise InvalidReviewerExecutable(
            "Claude Code help probe failed before capability validation"
        )
    try:
        required_options, safe_mode_summary = validate_claude_help(help_text)
    except ClaudeSafetyContractInvalid as error:
        raise ClaudeSafeModeContractInvalid(str(error)) from error
    except ClaudeCapabilityError as error:
        raise InvalidReviewerExecutable(str(error)) from error
    if version is None:
        return None
    return ClaudeCapabilities(version, required_options, safe_mode_summary)


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
    if any(code in structured_error for code in STRUCTURED_AUTH_CODES):
        categories["auth"] = "structured-auth-code"
    if any(fragment in message for fragment in TRANSIENT_FAILURE_FRAGMENTS):
        source = (
            "structured"
            if any(
                fragment in structured_error for fragment in TRANSIENT_FAILURE_FRAGMENTS
            )
            else "stderr"
        )
        categories["transient"] = f"{source}-transient"
    if "auth" not in categories and any(
        fragment in message for fragment in AUTH_FAILURE_FRAGMENTS
    ):
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
        or (isinstance(api_error_status, str) and not api_error_status.strip())
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
        " ".join(raw_result.lower().split())
        if isinstance(raw_result, str)
        and "\r" not in raw_result
        and "\n" not in raw_result
        else None
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
    known_nonstatus_error_payloads_empty = all(
        result[key] is None
        or (isinstance(result[key], str) and not result[key].strip())
        or (isinstance(result[key], (list, dict)) and not result[key])
        for key in known_error_fields
        if key != "api_error_status"
    )
    api_error_status_empty = "api_error_status" not in result or (
        api_error_status is None
        or (isinstance(api_error_status, str) and not api_error_status.strip())
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
        and safe_subtype == "error_during_execution"
        and is_error is True
        and result_shape == "string"
        and unknown_field_count == 0
        and _claude_failure_metadata_is_supported(result)
        and known_nonstatus_error_payloads_empty
    )
    supported_result_success = (
        safe_type == "result"
        and safe_subtype == "success"
        and is_error is False
        and raw_result == "OK"
        and unknown_field_count == 0
        and _claude_failure_metadata_is_supported(result)
        and known_nonstatus_error_payloads_empty
        and api_error_status_empty
    )
    return {
        "api_error_status": safe_api_error_status,
        "api_error_status_present": "api_error_status" in result,
        "api_error_status_shape": (
            "missing"
            if "api_error_status" not in result
            else "null"
            if api_error_status is None
            else "empty"
            if isinstance(api_error_status, str) and not api_error_status.strip()
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


def _claude_entitlement_evidence_is_model_specific(
    result: dict[str, Any],
    *,
    requested_model: str,
) -> bool:
    values: list[str] = []
    codes: set[str] = set()
    malformed_code = False

    def collect(value: Any) -> None:
        nonlocal malformed_code
        if isinstance(value, str):
            values.append(value)
            return
        if isinstance(value, list):
            for item in value:
                collect(item)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "code":
                    if not isinstance(item, str) or "\r" in item or "\n" in item:
                        malformed_code = True
                        continue
                    codes.add(item.strip().lower())
                    continue
                collect(item)

    for key in CLAUDE_AUTH_WARMUP_ERROR_FIELDS - {"api_error_status"}:
        if key in result:
            if key == "code":
                if not isinstance(result[key], str) or (
                    "\r" in result[key] or "\n" in result[key]
                ):
                    malformed_code = True
                    continue
                codes.add(result[key].strip().lower())
                continue
            collect(result[key])
    if "result" in result:
        collect(result["result"])
    if malformed_code:
        return False

    explicit_codes = set(STRUCTURED_ENTITLEMENT_CODES)
    ambiguous_codes = set(STRUCTURED_AMBIGUOUS_MODEL_CODES)
    if codes - explicit_codes - ambiguous_codes:
        return False
    explicit_model_code = bool(codes & explicit_codes)

    requested_literal = requested_model.lower()
    requested_rejection = re.compile(
        r"\s*(?:error:\s*)?(?:"
        rf"{re.escape(requested_literal)}\s+(?:is|was)\s+not\s+"
        r"(?:available|enabled|allowed|included|supported|entitled)"
        r"(?:\s+(?:for|to|on|in|with|by)\s+"
        r"(?:(?:your|this|the)\s+)?"
        r"(?:(?:chatgpt\s+)?account(?:\s+plan)?|user|organization|organisation|plan|"
        r"current\s+plan|current\s+subscription))?|"
        r"(?:no access to|access (?:is )?denied for)\s+"
        rf"{re.escape(requested_literal)})\s*[.!]?\s*",
        re.I,
    )
    matched_model_rejection = False
    for value in values:
        if "\r" in value or "\n" in value:
            return False
        model_rejection = any(
            pattern.fullmatch(value)
            for pattern in CLAUDE_MODEL_ENTITLEMENT_TEXT_PATTERNS
        ) or requested_rejection.fullmatch(value)
        if model_rejection:
            matched_model_rejection = True
            continue
        if (
            value.strip()
            and CLAUDE_ENTITLEMENT_NEUTRAL_TEXT_PATTERN.fullmatch(value) is None
        ):
            return False
    return explicit_model_code or matched_model_rejection


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
        or result.get("subtype") != "error_during_execution"
        or result.get("is_error") is not True
        or not _claude_failure_metadata_is_supported(result)
    ):
        return None
    effective_model, model_usage_valid = _claude_model_usage_evidence(
        result,
        requested_model=requested_model,
    )
    if (
        not model_usage_valid
        or effective_model is None
        or not _model_matches(requested_model, effective_model)
    ):
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
        api_error_status = result.get("api_error_status")
        if type(api_error_status) is int and api_error_status != 401:
            return None
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
    if category == "entitlement" and not _claude_entitlement_evidence_is_model_specific(
        result,
        requested_model=requested_model,
    ):
        return None
    if category in {"entitlement", "transient"}:
        category_source = evidence_categories.get(category, "")
        if not category_source.startswith("structured-"):
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


def _structured_error_text(
    stdout: bytes,
) -> str:
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
    if not _claude_failure_metadata_is_supported(result):
        return None, effective_model, model_evidence_consistent
    for key in CLAUDE_AUTH_WARMUP_ERROR_FIELDS:
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


def _validate_claude_stream_handle(
    handle: BinaryIO,
    *,
    review: ReviewWorkspace,
    expected_runtime_cwd: str,
    requested_model: str,
    runtime_binding: Any | None = None,
    process_returncode: int,
) -> dict[str, Any]:
    if runtime_binding is None:
        return {
            "classification": "inconclusive",
            "reasons": ["runtime.binding-missing"],
        }
    try:
        handle.flush()
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            return {
                "classification": "inconclusive",
                "reasons": ["stream.capture-not-regular-file"],
            }
        handle.seek(0)
        result = _load_claude_stream_validator().validate_claude_stream(
            handle,
            host_workspace_cwd=review.workspace_root,
            expected_runtime_cwd=expected_runtime_cwd,
            requested_model=requested_model,
            runtime_binding=runtime_binding,
            process_returncode=process_returncode,
        )
        after = os.fstat(handle.fileno())
    except (OSError, RuntimeError, TypeError, ValueError):
        return {
            "classification": "inconclusive",
            "reasons": ["stream.capture-read-failed"],
        }
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        return {
            "classification": "inconclusive",
            "reasons": ["stream.capture-changed-during-validation"],
        }
    if not isinstance(result, dict):
        return {
            "classification": "inconclusive",
            "reasons": ["stream.validator-result-invalid"],
        }
    return result


def _validate_claude_stream_output_file(
    path: pathlib.Path,
    *,
    review: ReviewWorkspace,
    expected_runtime_cwd: str,
    requested_model: str,
    runtime_binding: Any | None,
    process_returncode: int,
) -> dict[str, Any]:
    no_follow_flag = getattr(os, "O_NOFOLLOW", None)
    if no_follow_flag is None:
        return {
            "classification": "inconclusive",
            "reasons": ["stream.capture-no-follow-unavailable"],
        }
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | no_follow_flag
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            return _validate_claude_stream_handle(
                handle,
                review=review,
                expected_runtime_cwd=expected_runtime_cwd,
                requested_model=requested_model,
                runtime_binding=runtime_binding,
                process_returncode=process_returncode,
            )
    except (OSError, RuntimeError, TypeError, ValueError):
        return {
            "classification": "inconclusive",
            "reasons": ["stream.capture-open-failed"],
        }
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_claude_attempt_stream(
    *,
    completed: Completed,
    output: AttemptOutput,
    review: ReviewWorkspace,
    expected_runtime_cwd: str,
    requested_model: str,
    runtime_binding: Any | None,
) -> dict[str, Any]:
    try:
        output.ensure_captured(completed)
        if output.stdout_file is None:
            return _validate_claude_stream_output_file(
                output.stdout_path,
                review=review,
                expected_runtime_cwd=expected_runtime_cwd,
                requested_model=requested_model,
                runtime_binding=runtime_binding,
                process_returncode=completed.returncode,
            )
        return _validate_claude_stream_handle(
            output.stdout_file,
            review=review,
            expected_runtime_cwd=expected_runtime_cwd,
            requested_model=requested_model,
            runtime_binding=runtime_binding,
            process_returncode=completed.returncode,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return {
            "classification": "inconclusive",
            "reasons": ["stream.validation-failed"],
        }


def _claude_stream_attempt_category(result: Mapping[str, Any]) -> str:
    classification = result.get("classification")
    if classification == "accepted":
        findings = result.get("findings")
        return (
            "success"
            if isinstance(findings, str) and findings.strip()
            else "runtime-unverified"
        )
    if classification == "blocked-authentication":
        return "auth"
    reasons = result.get("reasons")
    reason_set = (
        frozenset(reasons)
        if isinstance(reasons, list)
        and reasons
        and all(isinstance(reason, str) for reason in reasons)
        else frozenset()
    )
    if (
        classification == "blocked"
        and reason_set
        and reason_set <= CLAUDE_STREAM_ENTITLEMENT_REASONS
    ):
        return "entitlement"
    if classification == "blocked":
        return "permission-mismatch"
    return "runtime-unverified"


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


def _read_complete_output_handle(
    handle: BinaryIO,
    *,
    limit_bytes: int,
) -> bytes | None:
    if limit_bytes <= 0:
        raise ValueError("complete output limit must be positive")
    try:
        handle.flush()
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit_bytes:
            return None
        handle.seek(0)
        payload = handle.read(before.st_size + 1)
        after = os.fstat(handle.fileno())
    except OSError:
        return None
    if len(payload) != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_size,
    ) != (after.st_dev, after.st_ino, after.st_size):
        return None
    return payload


def _strict_jsonl_handle_objects(
    handle: BinaryIO,
) -> Iterable[dict[str, Any]]:
    handle.flush()
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("reviewer JSONL output is not a regular file")
    if metadata.st_size > REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES:
        raise ValueError("reviewer JSONL output exceeds the bounded parser limit")
    handle.seek(0)
    consumed = 0
    while raw_line := handle.readline(COPILOT_JSONL_RECORD_LIMIT_BYTES + 2):
        consumed += len(raw_line)
        if consumed > REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES:
            raise ValueError("reviewer JSONL output exceeds the bounded parser limit")
        line = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
        if len(line) > COPILOT_JSONL_RECORD_LIMIT_BYTES:
            raise ValueError("reviewer JSONL record exceeds the bounded parser limit")
        if not line.strip(b" \t\r"):
            continue
        text = line.decode("utf-8")
        parsed = strict_json_loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("reviewer JSONL record is not an object")
        yield parsed
    after = os.fstat(handle.fileno())
    if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise ValueError("reviewer JSONL output changed during parsing")


def _strict_jsonl_file_objects(path: pathlib.Path) -> Iterable[dict[str, Any]]:
    with path.open("rb") as handle:
        yield from _strict_jsonl_handle_objects(handle)


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


def _parse_codex_output(stdout: bytes) -> str | None:
    objects = _strict_jsonl_objects(stdout)
    if not objects:
        return None
    return _parse_codex_objects(objects)


def _parse_codex_objects(objects: Iterable[dict[str, Any]]) -> str | None:
    turn_started = False
    turn_completed = False
    final_text: str | None = None
    for event in objects:
        if turn_completed:
            return None
        event_type = event.get("type")
        if not isinstance(event_type, str):
            return None
        if event_type == "turn.started":
            if turn_started or turn_completed:
                return None
            turn_started = True
            continue
        if event_type == "turn.completed":
            if not turn_started:
                return None
            turn_completed = True
            continue
        if event_type in {"error", "turn.failed"}:
            return None
        if event_type != "item.completed":
            continue
        if not turn_started or turn_completed:
            return None
        item = event.get("item")
        if not isinstance(item, dict):
            return None
        item_type = item.get("type")
        if item_type == "error":
            return None
        if item_type != "agent_message":
            continue
        text = item.get("text")
        if not isinstance(text, str) or not text.strip():
            return None
        final_text = text.strip()
    if not turn_completed:
        return None
    return final_text


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
    }
    remaining_paths = dict(expected_paths)
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
            return False
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
    return minimal_seen and not remaining_paths


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


@dataclass
class AttemptOutput:
    stdout_path: pathlib.Path
    stderr_path: pathlib.Path
    stdout_file: BinaryIO | None = None
    stderr_file: BinaryIO | None = None

    def run_arguments(self) -> dict[str, object]:
        if self.stdout_file is None or self.stderr_file is None:
            return {
                "stdout_path": self.stdout_path,
                "stderr_path": self.stderr_path,
            }
        return {
            "stdout_file": self.stdout_file,
            "stderr_file": self.stderr_file,
        }

    def ensure_captured(self, completed: Completed) -> None:
        if self.stdout_file is not None:
            return
        if not self.stdout_path.exists():
            self.stdout_path.write_bytes(completed.stdout)
        if not self.stderr_path.exists():
            self.stderr_path.write_bytes(completed.stderr)

    def complete_stdout(
        self,
        completed: Completed,
        *,
        limit_bytes: int,
    ) -> bytes | None:
        if self.stdout_file is None:
            return completed.stdout if len(completed.stdout) <= limit_bytes else None
        return _read_complete_output_handle(self.stdout_file, limit_bytes=limit_bytes)

    def strict_stdout_jsonl(
        self,
        completed: Completed,
    ) -> Iterable[dict[str, Any]]:
        if self.stdout_file is None:
            objects = _strict_jsonl_objects(completed.stdout)
            if objects is None:
                raise ValueError("reviewer stdout is not strict JSONL")
            return objects
        return _strict_jsonl_handle_objects(self.stdout_file)

    def append_stderr(self, message: str) -> None:
        if self.stderr_file is None:
            _append_attempt_diagnostic(self.stderr_path, message)
            return
        payload = message.rstrip().encode("utf-8", errors="replace") + b"\n"
        try:
            self.stderr_file.seek(0, os.SEEK_END)
            if self.stderr_file.tell():
                self.stderr_file.write(b"\n")
            self.stderr_file.write(payload)
            self.stderr_file.flush()
        except OSError as error:
            raise ReviewError(
                f"cannot append bound attempt diagnostic: {error}"
            ) from error


@contextlib.contextmanager
def _attempt_output(
    review: ReviewWorkspace,
    index: int,
    runtime: str,
    model: str,
    launch: ReviewLaunchBinding | None,
) -> Iterator[AttemptOutput]:
    stdout_path, stderr_path = _attempt_paths_without_io(
        review,
        index,
        runtime,
        model,
    )
    if launch is None:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        yield AttemptOutput(stdout_path, stderr_path)
        return
    with contextlib.ExitStack() as stack:
        stdout_file = stack.enter_context(launch.open_attempt_file(stdout_path.name))
        stderr_file = stack.enter_context(launch.open_attempt_file(stderr_path.name))
        yield AttemptOutput(
            stdout_path,
            stderr_path,
            stdout_file,
            stderr_file,
        )


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
    output: AttemptOutput,
    category: str = "blocked-authentication",
    stream_validation: Mapping[str, Any] | None = None,
) -> Attempt:
    stream_category = (
        _claude_stream_attempt_category(stream_validation)
        if stream_validation is not None
        else None
    )
    if stream_category is not None:
        category = "auth" if stream_category == "auth" else "inconclusive"
    try:
        output.ensure_captured(completed)
    except (OSError, ReviewError):
        pass
    try:
        output.append_stderr(
            "Claude credential refresh persistence was not safely completed after "
            "the runtime attempt."
            + (
                " The canonical stream classification was preserved as "
                f"{stream_validation.get('classification')!r}."
                if stream_validation is not None
                else ""
            ),
        )
    except (OSError, ReviewError):
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
        stdout_path=str(output.stdout_path),
        stderr_path=str(output.stderr_path),
    )


def _claude_auth_rejection_after_credential_inspection(
    *,
    review: ReviewWorkspace,
    index: int,
    model: str,
    completed: Completed,
    output: AttemptOutput,
    inspection_error: BaseException,
    stream_validation: Mapping[str, Any] | None = None,
) -> BaseException | None:
    if (
        stream_validation is None
        or _claude_stream_attempt_category(stream_validation) != "auth"
    ):
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
            output=output,
            category="auth",
            stream_validation=stream_validation,
        ),
    )
    effective_failure = _propagate_claude_persistence_state(
        review,
        inspection_error,
        failure,
    )
    if effective_failure is not failure:
        return effective_failure
    return _attach_claude_credential_cleanup_failure(
        failure,
        inspection_error,
    )


def _claude_post_attempt_credential_failure(
    *,
    review: ReviewWorkspace,
    index: int,
    model: str,
    completed: Completed,
    output: AttemptOutput,
    inspection_error: BaseException,
    stream_validation: Mapping[str, Any],
    platform: str,
) -> BaseException:
    authentication_error = _claude_auth_rejection_after_credential_inspection(
        review=review,
        index=index,
        model=model,
        completed=completed,
        output=output,
        inspection_error=inspection_error,
        stream_validation=stream_validation,
    )
    if authentication_error is not None:
        return authentication_error
    failure = ClaudeCredentialInspectionInconclusive(
        f"Claude {platform} post-attempt credential persistence was "
        f"inconclusive: {inspection_error}"
    )
    setattr(failure, "_codex_claude_refresh_persistence_failed", True)
    effective_failure = _propagate_claude_persistence_state(
        review,
        inspection_error,
        failure,
    )
    if effective_failure is not failure:
        return effective_failure
    setattr(
        failure,
        "_codex_claude_persistence_attempt",
        _claude_persistence_failed_attempt(
            review=review,
            index=index,
            model=model,
            completed=completed,
            output=output,
            category="inconclusive",
            stream_validation=stream_validation,
        ),
    )
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
    model_evidence_consistent: bool = True,
    output: AttemptOutput | None = None,
    evidence_stdout: bytes | None = None,
) -> Attempt:
    if output is None:
        stdout_path, stderr_path = _attempt_paths(review, index, runtime, model)
        output = AttemptOutput(stdout_path, stderr_path)
    else:
        stdout_path = output.stdout_path
        stderr_path = output.stderr_path
    output.ensure_captured(completed)
    stdout_evidence = completed.stdout if evidence_stdout is None else evidence_stdout
    if completed.returncode != 0:
        final_text = None
    if completed.returncode == 0 and final_text:
        category = "success"
        reason = None
    elif runtime == "copilot" and completed.returncode == 0:
        category = "inconclusive"
        reason = "zero-exit-without-verified-final"
    else:
        category, reason = _classify_failure_evidence(
            stdout_evidence,
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
            output.append_stderr(
                "Copilot model discovery encountered a transient network failure",
            )
        if runtime == "claude":
            if category in {"auth", "entitlement", "transient"} and (
                _claude_supported_failure_category(
                    stdout_evidence,
                    stderr=completed.stderr,
                    requested_model=model,
                )
                != category
            ):
                reason = f"unverified-{category}-failure-envelope"
                category = "inconclusive"
            elif completed.returncode != 0 and category == "other":
                category = "inconclusive"
                reason = _claude_nonzero_failure_reason(stdout_evidence)
            elif completed.returncode == 0 and category == "other":
                result = _strict_json_object(stdout_evidence)
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
                output.append_stderr(
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
        output.append_stderr(detail)
        return replace(
            attempt,
            returncode=65,
            category="runtime-unverified",
            final_text=None,
            reason="malformed-model-usage",
        )
    if runtime == "claude" and completed.returncode == 0 and final_text is None:
        result = _strict_json_object(stdout_evidence)
        if result is None or result.get("type") != "result":
            output.append_stderr(
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
            output.append_stderr(detail)
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
        output.append_stderr(detail)
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
        output.append_stderr(mismatch)
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
        output.append_stderr(mismatch)
        attempt = replace(
            attempt,
            returncode=65,
            category="effort-mismatch",
            final_text=None,
            reason="effective-effort-mismatch",
        )
    return attempt


def _review_prompt_bytes(
    review: ReviewWorkspace,
    launch: ReviewLaunchBinding | None,
) -> bytes:
    if launch is None:
        return review.prompt_file.read_bytes()
    if launch.prompt is None:
        raise ReviewError("bound review prompt was not frozen before launch")
    return launch.prompt


def _review_prompt_text(
    review: ReviewWorkspace,
    launch: ReviewLaunchBinding | None,
) -> str:
    try:
        return _review_prompt_bytes(review, launch).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReviewError("bound review prompt is not valid UTF-8") from error


def _codex_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
    launch: ReviewLaunchBinding | None = None,
) -> Attempt:
    with _attempt_output(review, index, "codex", model, launch) as output:
        return _codex_attempt_with_output(
            review=review,
            model=model,
            index=index,
            env=env,
            launch=launch,
            output=output,
        )


def _codex_attempt_with_output(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
    launch: ReviewLaunchBinding | None,
    output: AttemptOutput,
) -> Attempt:
    executable = resolve_reviewer_executable("codex")
    if executable is None:
        raise FileNotFoundError("codex is not available in a validated executable path")
    env = _with_executable_path(env, executable)
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
        '":workspace_roots"={"."="read",".git"="deny"}}}'
    )
    prompt = _review_prompt_bytes(review, launch)
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
            "-",
        ),
        cwd=review.workspace_root if launch is None else None,
        cwd_fd=launch.workspace_descriptor if launch is not None else None,
        env=env,
        stdin=prompt,
        timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
        **output.run_arguments(),
    )
    final_text = None
    if completed.returncode == 0:
        try:
            final_text = _parse_codex_objects(output.strict_stdout_jsonl(completed))
        except (OSError, UnicodeDecodeError, ValueError):
            final_text = None
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
        output=output,
    )
    if permissions_verified is False or (
        attempt.category == "success" and permissions_verified is None
    ):
        detail = (
            "effective Codex sandbox did not preserve the isolated review permission "
            "profile; refusing to accept a result from a legacy or managed sandbox override"
        )
        output.append_stderr(detail)
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
    runtime_binding_sink: list[Any] | None = None,
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
    runtime_bindings: dict[str, Any] = {}

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
            container_dir=review.container_dir,
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
        capabilities = _require_claude_safe_mode(
            verified_executable,
            candidate_env,
            version=version,
        )
        runtime_executables[str(candidate.absolute())] = verified_executable
        runtime_evidence[str(candidate.absolute())] = executable_evidence
        if isinstance(verified, VerifiedClaudeExecutable):
            if capabilities is not None:
                try:
                    runtime_bindings[str(candidate.absolute())] = (
                        _load_claude_stream_validator().runtime_binding_from_verified_executable(
                            verified,
                            capabilities=capabilities,
                            authentication_source=_claude_authentication_source(
                                prepared_env
                            ),
                            launch_profile=(
                                "helper-linux"
                                if linux_host is not None
                                else "helper-darwin"
                            ),
                        )
                    )
                except (OSError, RuntimeError, TypeError, ValueError) as error:
                    raise ClaudeExecutableInspectionInconclusive(
                        "cannot bind the verified Claude runtime to its canonical "
                        "stream contract"
                    ) from error
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
                    "credential_lock_protocol": (
                        lock_protocol.identifier
                        if lock_protocol is not None
                        else "unverified"
                    ),
                },
                "outer_sandbox": {
                    "implementation": (
                        "bubblewrap" if _is_claude_linux_host() else "sandbox-exec"
                    ),
                    "status": "pending-runtime-launch",
                },
                "authentication": {
                    "source": _claude_authentication_source(prepared_env),
                    "carrier": (
                        "environment"
                        if _claude_uses_explicit_auth(prepared_env)
                        else (
                            "writable-private-config-guarded-writeback"
                            if _is_claude_linux_host()
                            else "one-shot-security-broker"
                        )
                    ),
                    "status": "configured",
                },
            }

    try:
        executable = resolve_reviewer_executable(
            "claude",
            candidate_validator=validate_candidate,
            inspection_error=ClaudeExecutableInspectionInconclusive,
        )
    except RejectedReviewerCandidates as error:
        raise ClaudeExecutableUnavailable(str(error)) from error
    if executable is None:
        if runtime_binding_sink is not None:
            runtime_binding_sink.clear()
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
    if runtime_binding_sink is not None:
        runtime_binding_sink.clear()
        runtime_binding = runtime_bindings.get(str(executable.absolute()))
        if runtime_binding is not None:
            runtime_binding_sink.append(runtime_binding)
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
    *,
    proxy_env: dict[str, str] | None = None,
    proxy_ssl_context: ssl.SSLContext | None = None,
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None = None,
    launch: ReviewLaunchBinding | None = None,
    writer_started: Callable[[], bool] | None = None,
    writer_quiescent: Callable[[], bool] | None = None,
) -> Iterator[Any]:
    runtime_proxy_env = env if proxy_env is None else proxy_env
    if (
        _claude_https_proxy_tls_required(runtime_proxy_env)
        and proxy_ssl_context is None
    ):
        raise ClaudeExecutableInspectionInconclusive(
            "Claude proxy TLS context is unavailable"
        )
    if launch is not None:
        launch.require_workspace_path(review.workspace_root)
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
        authentication_source = _claude_authentication_source(env)
        if authentication_source != "local-login":
            api_carrier = _create_or_validate_claude_runtime_directory(
                _claude_linux_private_directory(review, "api-carrier"),
                private=True,
            )
            config_dir = _create_or_validate_claude_runtime_directory(
                api_carrier / "config",
                private=True,
            )
            explicit_key = (
                "ANTHROPIC_API_KEY"
                if authentication_source == "api-key"
                else "CLAUDE_CODE_OAUTH_TOKEN"
            )
            auth_env[explicit_key] = env[explicit_key]
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
            _claude_unix_connect_proxy(
                review,
                runtime_proxy_env,
                upstream_ssl_context=proxy_ssl_context,
            )
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
            workspace_descriptor=(
                launch.workspace_descriptor if launch is not None else None
            ),
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
        if launch is not None:
            launch.require_workspace_path(review.workspace_root)
        _update_claude_runtime_report(
            review,
            {
                "phase": "runtime-ready",
                "outer_sandbox": {"status": "isolation-probe-verified"},
                "authentication": {
                    "source": authentication_source,
                    "carrier": (
                        "environment"
                        if authentication_source != "local-login"
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
        if launch is not None:
            launch.require_workspace_path(review.workspace_root)
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
        trailing_sentence_period = False
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
            trailing_sentence_period = right_ok
        if not left_ok or not right_ok:
            raise ReviewError(
                f"Claude review prompt contains an ambiguous host {label} path"
            )
        replacement = target
        if trailing_sentence_period and target == b".":
            # Preserve the sentence period without forming the parent-path
            # token; "./." still resolves to the descriptor-bound workspace.
            replacement = b"./"
        chunks.extend((prompt[cursor:occurrence], replacement))
        cursor = end


def _claude_review_prompt(
    review: ReviewWorkspace,
    prompt: bytes,
    *,
    linux: bool,
    descriptor_bound: bool = False,
) -> bytes:
    workspace = str(review.workspace_root).encode("utf-8")
    diff_file = str(review.diff_file).encode("utf-8")
    target_workspace = (
        b"/workspace" if linux else (b"." if descriptor_bound else workspace)
    )
    target_diff = (
        b"/workspace/.codex-review/review.diff"
        if linux
        else (b".codex-review/review.diff" if descriptor_bound else diff_file)
    )
    projected = prompt.replace(
        b"- Workspace: .\n",
        b"- Workspace: " + target_workspace + b"\n",
    ).replace(
        b"- Primary diff file: .codex-review/review.diff\n",
        b"- Primary diff file: " + target_diff + b"\n",
    )
    if linux or descriptor_bound:
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
        if linux:
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
    runtime_binding: Any | None = None,
    launch: ReviewLaunchBinding | None = None,
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None | object = (
        _UNRESOLVED_CLAUDE_REFRESH_LOCK_PROTOCOL
    ),
) -> Attempt:
    with _attempt_output(review, index, "claude", model, launch) as output:
        return _claude_attempt_with_output(
            review=review,
            model=model,
            index=index,
            env=env,
            executable=executable,
            executable_evidence=executable_evidence,
            trust_state=trust_state,
            runtime_binding=runtime_binding,
            launch=launch,
            refresh_lock_protocol=refresh_lock_protocol,
            output=output,
        )


def _claude_attempt_with_output(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
    executable: pathlib.Path | None,
    executable_evidence: ClaudeExecutableTrustEvidence | None,
    trust_state: ClaudeTrustSessionState | None,
    runtime_binding: Any | None = None,
    launch: ReviewLaunchBinding | None,
    refresh_lock_protocol: ClaudeRefreshLockProtocol | None | object,
    output: AttemptOutput,
) -> Attempt:
    if executable is None:
        runtime_binding_sink: list[Any] = []
        executable, env, executable_evidence = _resolve_validated_claude_executable(
            review=review,
            env=env,
            runtime_binding_sink=runtime_binding_sink,
        )
        runtime_binding = (
            runtime_binding_sink[0] if len(runtime_binding_sink) == 1 else None
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
    _require_matching_claude_executable_snapshot(
        executable,
        executable_evidence,
        container_dir=review.container_dir,
    )
    linux_host = _is_claude_linux_host()
    prompt = _claude_review_prompt(
        review,
        _review_prompt_bytes(review, launch),
        linux=linux_host,
        descriptor_bound=launch is not None,
    )
    if linux_host:
        _require_claude_linux_prompt_without_file_mentions(prompt)
    proxy_env, proxy_ssl_context = _claude_proxy_tls_environment(
        review,
        env,
        trust_state=trust_state,
    )
    attempt_env = _with_claude_review_tool_path(review, env)
    attempt_env = _with_claude_tls_snapshot_inputs(
        attempt_env,
        proxy_env,
    )
    attempt_env = _prepare_claude_tls_environment(
        review,
        attempt_env,
        executable_evidence=executable_evidence,
        trust_state=trust_state,
        expected_snapshot_sha256=trust_state.proxy_tls_snapshot_sha256,
    )
    _require_matching_claude_executable_snapshot(
        executable,
        executable_evidence,
        container_dir=review.container_dir,
    )
    authentication_source = _claude_authentication_source(attempt_env)
    if authentication_source != "local-login":
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
                    "source": authentication_source,
                    "carrier": (
                        "environment"
                        if authentication_source != "local-login"
                        else "one-shot-security-broker"
                    ),
                    "status": (
                        "configured"
                        if authentication_source != "local-login"
                        else "pending-source-selection"
                    ),
                    "model": model,
                },
                "attempt": None,
            },
        )
    settings = _claude_review_settings(linux=linux_host)
    arguments = _claude_review_arguments(
        model=model,
        settings=settings,
        linux=linux_host,
    )
    completed: Completed | None = None
    stream_validation: dict[str, Any] = {
        "classification": "inconclusive",
        "reasons": ["stream.runtime-not-complete"],
    }
    if linux_host:
        writer_start = ProcessStartOwner()
        writer_quiescent = threading.Event()
        try:
            _require_matching_claude_executable_snapshot(
                executable,
                executable_evidence,
                container_dir=review.container_dir,
            )
            with _claude_linux_review_runtime(
                review,
                executable,
                attempt_env,
                arguments,
                proxy_env=proxy_env,
                proxy_ssl_context=proxy_ssl_context,
                refresh_lock_protocol=selected_refresh_lock_protocol,
                launch=launch,
                writer_started=writer_start.may_have_started,
                writer_quiescent=writer_quiescent.is_set,
            ) as sandbox_command:
                _require_matching_claude_executable_snapshot(
                    executable,
                    executable_evidence,
                    container_dir=review.container_dir,
                )
                completed = run(
                    sandbox_command.argv,
                    cwd=review.workspace_root if launch is None else None,
                    pass_fds=sandbox_command.pass_fds,
                    env=sandbox_command.env,
                    stdin=prompt,
                    timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
                    output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
                    redact_values=output_redact_values(
                        claude_output_redact_values(env)
                    ),
                    on_process_starting=writer_start.publish_starting,
                    on_process_started=writer_start.publish_started,
                    on_process_quiescent=writer_quiescent.set,
                    **output.run_arguments(),
                )
                quiescence_signal_mask_owner = _ClaudeSignalMaskOwner()
                quiescence_error: BaseException | None = None
                try:
                    quiescence_mask = block_forwarded_signals(
                        signal_mask_owner=quiescence_signal_mask_owner,
                    )
                    if not (
                        quiescence_signal_mask_owner.owns_previous_signal_mask(
                            quiescence_mask
                        )
                    ):
                        quiescence_signal_mask_owner.publish_previous_signal_mask(
                            quiescence_mask
                        )
                    writer_quiescent.set()
                except BaseException as error:
                    quiescence_error = error
                    raise
                finally:
                    restore_error = _restore_claude_signal_mask_owner_bounded(
                        quiescence_signal_mask_owner
                    )
                    if restore_error is not None:
                        selected_error = _select_claude_thread_start_related_error(
                            quiescence_error,
                            restore_error,
                        )
                        assert selected_error is not None
                        raise selected_error
                stream_validation = _validate_claude_attempt_stream(
                    completed=completed,
                    output=output,
                    review=review,
                    expected_runtime_cwd=str(sandbox_command.workspace_path),
                    requested_model=model,
                    runtime_binding=runtime_binding,
                )
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
                        output=output,
                        inspection_error=error,
                        stream_validation=stream_validation,
                    )
                )
                if authentication_error is not None:
                    if authentication_error is error:
                        raise
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
                        output=output,
                        category="inconclusive",
                        stream_validation=stream_validation,
                    ),
                )
            raise translated_error from error
        except (LinuxCredentialUnavailable, LinuxCredentialUnsafe) as error:
            persistence_failed = completed is not None
            if completed is not None:
                authentication_rejected = (
                    _claude_stream_attempt_category(stream_validation) == "auth"
                )
                status = (
                    "blocked-authentication"
                    if authentication_rejected
                    else "inconclusive"
                )
                _update_claude_runtime_report_preserving_persistence(
                    review,
                    {
                        "phase": (
                            "blocked-authentication"
                            if authentication_rejected
                            else "authentication-inspection-inconclusive"
                        ),
                        "status": status,
                        **(
                            {"category": "blocked-authentication"}
                            if authentication_rejected
                            else {}
                        ),
                        "outer_sandbox": {
                            "status": "isolation-probe-verified",
                        },
                        "authentication": {
                            "status": (
                                "blocked-authentication"
                                if authentication_rejected
                                else "inspection-inconclusive"
                            ),
                            **(
                                {"category": "blocked-authentication"}
                                if authentication_rejected
                                else {}
                            ),
                            "model": model,
                            "failure_class": "refresh-persistence",
                        },
                        "attempt": {
                            "requested_model": model,
                            "effective_model": None,
                            "requested_effort": CLAUDE_REASONING_EFFORT,
                            "effective_effort": None,
                            "category": (
                                "blocked-authentication"
                                if authentication_rejected
                                else "inconclusive"
                            ),
                            "returncode": completed.returncode,
                            "failure_class": "refresh-persistence",
                        },
                    },
                    error,
                )
                translated_post_attempt_error = _claude_post_attempt_credential_failure(
                    review=review,
                    index=index,
                    model=model,
                    completed=completed,
                    output=output,
                    inspection_error=error,
                    stream_validation=stream_validation,
                    platform="Linux",
                )
                if translated_post_attempt_error is error:
                    raise
                raise translated_post_attempt_error from error
            _update_claude_runtime_report(
                review,
                {
                    "phase": "blocked-authentication",
                    "status": "blocked-authentication",
                    "category": "blocked-authentication",
                    "outer_sandbox": {"status": "pending-isolation-probe"},
                    "authentication": {
                        "status": "blocked-authentication",
                        "category": "blocked-authentication",
                        "model": model,
                        "failure_class": "credential-source",
                    },
                    "attempt": None,
                },
            )
            translated_error: ClaudeKeychainCredentialUnavailable
            if isinstance(error, LinuxCredentialUnsafe):
                translated_error = ClaudeCredentialUnsafe(
                    f"Claude Linux local-login credential is unsafe: {error}"
                )
            else:
                translated_error = ClaudeKeychainCredentialUnavailable(str(error))
            raise translated_error from error
        except BaseException as error:
            _record_claude_secondary_persistence_failure(
                review,
                error,
            )
            raise
    else:
        runtime_started = False
        process_start = ProcessStartOwner()
        process_quiescent = threading.Event()
        try:
            with contextlib.ExitStack() as stack:
                runtime_env = stack.enter_context(
                    _claude_keychain_runtime(
                        review,
                        attempt_env,
                        selected_refresh_lock_protocol,
                        process_started=process_start.may_have_started,
                        process_quiescent=process_quiescent.is_set,
                    )
                )
                proxy_port = stack.enter_context(
                    _claude_connect_proxy(
                        proxy_env,
                        upstream_ssl_context=proxy_ssl_context,
                    )
                )
                review_env = _with_claude_proxy_environment(
                    runtime_env,
                    proxy_port,
                )
                _require_matching_claude_macos_tls_bundle(
                    review,
                    review_env,
                    trust_state=trust_state,
                )
                bound_workspace = (
                    launch.require_workspace_path(review.workspace_root)
                    if launch is not None
                    else None
                )
                sandbox_profile = _claude_review_sandbox_profile(
                    executable,
                    review,
                    review_env,
                    proxy_port=proxy_port,
                    workspace_path=bound_workspace,
                )
                _update_claude_runtime_report(
                    review,
                    {
                        "phase": "runtime-launching",
                        "outer_sandbox": {"status": "profile-generated"},
                        "authentication": {"status": "sandbox-auth-staged"},
                    },
                )
                _require_matching_claude_executable_snapshot(
                    executable,
                    executable_evidence,
                    container_dir=review.container_dir,
                )
                _require_matching_claude_macos_tls_bundle(
                    review,
                    review_env,
                    trust_state=trust_state,
                )
                runtime_started = True
                if launch is not None:
                    launch.require_workspace_path(review.workspace_root)

                def verify_started_workspace() -> None:
                    process_start.publish_started()
                    if launch is not None:
                        launch.require_workspace_path(review.workspace_root)

                completed = run(
                    (
                        str(CLAUDE_PROBE_SANDBOX),
                        "-p",
                        sandbox_profile,
                        str(executable),
                        *arguments,
                    ),
                    cwd=review.workspace_root if launch is None else None,
                    cwd_fd=(
                        launch.workspace_descriptor if launch is not None else None
                    ),
                    env=review_env,
                    stdin=prompt,
                    timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
                    output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
                    prepare_process_spawned=getattr(
                        runtime_env,
                        "prepare_runtime_process",
                        None,
                    ),
                    on_process_spawned=getattr(
                        runtime_env,
                        "bind_runtime_process",
                        None,
                    ),
                    redact_values=output_redact_values(
                        claude_output_redact_values(env)
                    ),
                    on_process_starting=process_start.publish_starting,
                    on_process_started=verify_started_workspace,
                    on_process_quiescent=process_quiescent.set,
                    **output.run_arguments(),
                )
                quiescence_signal_mask_owner = _ClaudeSignalMaskOwner()
                quiescence_error: BaseException | None = None
                try:
                    quiescence_mask = block_forwarded_signals(
                        signal_mask_owner=quiescence_signal_mask_owner,
                    )
                    if not (
                        quiescence_signal_mask_owner.owns_previous_signal_mask(
                            quiescence_mask
                        )
                    ):
                        quiescence_signal_mask_owner.publish_previous_signal_mask(
                            quiescence_mask
                        )
                    process_quiescent.set()
                except BaseException as error:
                    quiescence_error = error
                    raise
                finally:
                    restore_error = _restore_claude_signal_mask_owner_bounded(
                        quiescence_signal_mask_owner
                    )
                    if restore_error is not None:
                        selected_error = _select_claude_thread_start_related_error(
                            quiescence_error,
                            restore_error,
                        )
                        assert selected_error is not None
                        raise selected_error
                stream_validation = _validate_claude_attempt_stream(
                    completed=completed,
                    output=output,
                    review=review,
                    expected_runtime_cwd=str(review.workspace_root),
                    requested_model=model,
                    runtime_binding=runtime_binding,
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
                        output=output,
                        inspection_error=error,
                        stream_validation=stream_validation,
                    )
                )
                if authentication_error is not None:
                    if authentication_error is error:
                        raise
                    raise authentication_error from error
                if _claude_timeout_root_state(error) is None:
                    setattr(
                        error,
                        "_codex_claude_persistence_attempt",
                        _claude_persistence_failed_attempt(
                            review=review,
                            index=index,
                            model=model,
                            completed=completed,
                            output=output,
                            category="inconclusive",
                            stream_validation=stream_validation,
                        ),
                    )
            raise
        except ClaudeKeychainCredentialUnavailable as error:
            persistence_failed = completed is not None
            if completed is not None:
                authentication_rejected = (
                    _claude_stream_attempt_category(stream_validation) == "auth"
                )
                status = (
                    "blocked-authentication"
                    if authentication_rejected
                    else "inconclusive"
                )
                _update_claude_runtime_report_preserving_persistence(
                    review,
                    {
                        "phase": (
                            "blocked-authentication"
                            if authentication_rejected
                            else "authentication-inspection-inconclusive"
                        ),
                        "status": status,
                        **(
                            {"category": "blocked-authentication"}
                            if authentication_rejected
                            else {}
                        ),
                        "outer_sandbox": {"status": "enforced-at-launch"},
                        "authentication": {
                            "status": (
                                "blocked-authentication"
                                if authentication_rejected
                                else "inspection-inconclusive"
                            ),
                            **(
                                {"category": "blocked-authentication"}
                                if authentication_rejected
                                else {}
                            ),
                            "model": model,
                            "failure_class": "refresh-persistence",
                        },
                        "attempt": {
                            "requested_model": model,
                            "effective_model": None,
                            "requested_effort": CLAUDE_REASONING_EFFORT,
                            "effective_effort": None,
                            "category": (
                                "blocked-authentication"
                                if authentication_rejected
                                else "inconclusive"
                            ),
                            "returncode": completed.returncode,
                            "failure_class": "refresh-persistence",
                        },
                    },
                    error,
                )
                translated_post_attempt_error = _claude_post_attempt_credential_failure(
                    review=review,
                    index=index,
                    model=model,
                    completed=completed,
                    output=output,
                    inspection_error=error,
                    stream_validation=stream_validation,
                    platform="macOS",
                )
                if translated_post_attempt_error is error:
                    raise
                raise translated_post_attempt_error from error
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
    stream_category = _claude_stream_attempt_category(stream_validation)
    final_text = None
    if stream_category == "success":
        candidate_findings = stream_validation.get("findings")
        if isinstance(candidate_findings, str) and candidate_findings.strip():
            final_text = candidate_findings
        else:
            stream_category = "runtime-unverified"
    effective_model = (
        model if stream_category in {"success", "auth", "entitlement"} else None
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
        output=output,
    )
    attempt = replace(
        attempt,
        category=stream_category,
        final_text=final_text if stream_category == "success" else None,
    )
    if stream_category in {"permission-mismatch", "runtime-unverified"}:
        output.append_stderr(
            "canonical Claude stream validation did not accept the complete "
            "versioned init, intermediate-event, terminal, model, permission, "
            "authentication, and child-return-code contract; refusing partial "
            "findings and model fallback",
        )
        attempt = replace(
            attempt,
            returncode=(65 if completed.returncode == 0 else completed.returncode),
            final_text=None,
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
            "capabilities": {
                "effective_init_contract": (
                    "verified" if stream_category == "success" else "rejected"
                ),
                "stream_validation": {
                    "classification": stream_validation.get("classification"),
                    "reasons": stream_validation.get("reasons", []),
                },
            },
            "authentication": {
                "source": authentication_source,
                "status": ("used" if stream_category == "success" else "configured"),
                "model": model,
            },
            "attempt": {
                "requested_model": model,
                "effective_model": attempt.effective_model,
                "requested_effort": CLAUDE_REASONING_EFFORT,
                "effective_effort": attempt.effective_effort,
                "category": attempt.category,
                "reason": attempt.reason,
                "returncode": attempt.returncode,
                "stream_validation_classification": stream_validation.get(
                    "classification"
                ),
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
    launch: ReviewLaunchBinding | None = None,
) -> Attempt:
    with _attempt_output(review, index, "copilot", model, launch) as output:
        return _copilot_attempt_with_output(
            review=review,
            model=model,
            index=index,
            env=env,
            launch=launch,
            output=output,
        )


def _copilot_attempt_with_output(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
    launch: ReviewLaunchBinding | None,
    output: AttemptOutput,
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
    with _attempt_output(
        review,
        index,
        "copilot-permissions",
        model,
        launch,
    ) as permission_output:
        permission_help = run(
            (str(executable), "help", "permissions"),
            env=env,
            capture_limit_bytes=COPILOT_PROBE_OUTPUT_LIMIT_BYTES,
            timeout_seconds=COPILOT_PROBE_TIMEOUT_SECONDS,
            output_file_limit_bytes=COPILOT_PROBE_OUTPUT_LIMIT_BYTES,
            **permission_output.run_arguments(),
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
        "." if launch is not None else str(review.workspace_root),
        "--prompt",
        _review_prompt_text(review, launch),
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
        cwd=review.workspace_root if launch is None else None,
        cwd_fd=launch.workspace_descriptor if launch is not None else None,
        env=env,
        timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
        **output.run_arguments(),
    )
    try:
        final_text, effective_model = _parse_copilot_objects(
            output.strict_stdout_jsonl(completed),
            requested_model=model,
        )
    except (OSError, UnicodeDecodeError, ValueError):
        final_text, effective_model = None, None
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
        output=output,
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


def _format_claude_runner_error(
    prefix: str,
    error: BaseException,
    *secondary_diagnostics: str | None,
) -> str:
    lines = [f"{prefix}{error}"]
    for diagnostic in secondary_diagnostics:
        if diagnostic is not None and diagnostic not in lines:
            lines.append(diagnostic)
    trust_diagnostic = _claude_trust_evidence_write_diagnostic(error)
    if trust_diagnostic is not None and trust_diagnostic not in lines:
        lines.append(trust_diagnostic)
    return "\n".join(lines) + "\n"


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


def _write_attempts(
    review: ReviewWorkspace,
    attempts: Iterable[Attempt],
    *,
    launch: ReviewLaunchBinding | None = None,
) -> None:
    value = [_attempt_summary(item) for item in attempts]
    if launch is not None:
        write_json_atomic_at(
            launch.container_descriptor,
            "attempts.json",
            value,
        )
        return
    attempts_error = write_bound_review_json(
        review.container_dir,
        expected=review.private_cleanup,
        name="attempts.json",
        value=value,
    )
    if attempts_error:
        raise ReviewError(f"cannot persist review attempts: {attempts_error}")


def _finish(
    review: ReviewWorkspace,
    attempts: list[Attempt],
    final_text: str | None,
    *,
    launch: ReviewLaunchBinding | None = None,
) -> Outcome:
    _write_attempts(review, attempts, launch=launch)
    if final_text:
        payload = final_text.rstrip("\r\n") + "\n"
        if launch is None:
            write_text_atomic(review.container_dir / "final.txt", payload)
        else:
            write_text_atomic_at(
                launch.container_descriptor,
                "final.txt",
                payload,
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


def _persist_runner_error(review: ReviewWorkspace, text: str) -> str | None:
    """Persist a runner diagnostic without following a replaced container path."""

    diagnostic_error = write_bound_runner_error(
        review.container_dir,
        expected=review.private_cleanup,
        text=text,
    )
    if diagnostic_error:
        print(
            text.rstrip("\n")
            + f"; runner diagnostic was not persisted: {diagnostic_error}",
            file=sys.stderr,
        )
    return diagnostic_error


def _persist_failure_artifacts(
    review: ReviewWorkspace,
    text: str,
    attempts: Iterable[Attempt],
) -> bool:
    """Persist failure artifacts only while the review container remains bound."""

    if _persist_runner_error(review, text):
        return False
    try:
        _write_attempts(review, attempts)
    except ReviewError as error:
        print(f"review attempts were not persisted: {error}", file=sys.stderr)
        return False
    return True


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
    _persist_failure_artifacts(
        review,
        f"Claude Code authentication requires user action: {detail}. {action}\n",
        attempts,
    )
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
    launch: ReviewLaunchBinding | None = None,
) -> tuple[str, str | None]:
    for model in models:
        index = len(attempts) + 1
        try:
            runner_args: dict[str, Any] = {
                "review": review,
                "model": model,
                "index": index,
                "env": env,
            }
            if launch is not None:
                runner_args["launch"] = launch
            attempt = runner(**runner_args)
        except (
            ReviewTimeoutError,
            ReviewOutputDrainError,
            ReviewOutputLimitError,
            ReviewProcessLeakError,
        ) as error:
            stdout_path, stderr_path = _attempt_paths_without_io(
                review,
                index,
                runtime,
                model,
            )
            diagnostic = f"review supervision failed: {error}"
            if launch is None:
                stdout_path.parent.mkdir(parents=True, exist_ok=True)
                stdout_path.touch(exist_ok=True)
                _append_attempt_diagnostic(stderr_path, diagnostic)
            else:
                with launch.open_existing_attempt_file(stdout_path.name):
                    pass
                with launch.open_existing_attempt_file(stderr_path.name) as stderr_file:
                    AttemptOutput(
                        stdout_path,
                        stderr_path,
                        stderr_file=stderr_file,
                    ).append_stderr(diagnostic)
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
            _write_attempts(review, attempts, launch=launch)
            raise
        attempts.append(attempt)
        _write_attempts(review, attempts, launch=launch)
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
    """Bind launch inputs, then execute the complete provider policy.

    The bound implementation calls ``validate_external_workspace``, records
    ``review workspace containment and integrity checks passed`` and
    ``secret-delta status is evaluated separately`` evidence, and routes
    interactive authentication through ``_finish_claude_auth_required``.
    """

    if reviewer not in ("codex", "claude"):
        _persist_runner_error(review, f"unknown reviewer: {reviewer}\n")
        return Outcome(2, None, tuple())

    if reviewer == "claude":
        if egress_consent not in CLAUDE_EGRESS_CONSENTS:
            _persist_runner_error(
                review,
                "The low-level Claude helper requires an explicit "
                "egress-consent reason.\n",
            )
            return Outcome(2, None, tuple())
    elif egress_consent is not None:
        _persist_runner_error(
            review,
            "egress-consent is valid only for the low-level Claude helper.\n",
        )
        return Outcome(2, None, tuple())

    try:
        launch = _open_review_launch_binding(review)
    except ReviewError as error:
        private_cleanup_error = remove_private_review_artifacts(
            review.container_dir,
            expected=review.private_cleanup,
        )
        cleanup_suffix = (
            f"; private artifact cleanup failed: {private_cleanup_error}"
            if private_cleanup_error
            else ""
        )
        diagnostic = (
            f"review egress workspace preflight failed: {error}{cleanup_suffix}\n"
        )
        _persist_runner_error(review, diagnostic)
        return Outcome(2, None, tuple())
    with launch:
        return _run_review_with_binding(
            review=review,
            reviewer=reviewer,
            egress_consent=egress_consent,
            launch=launch,
        )


def _build_low_level_helper_egress_record(
    review: ReviewWorkspace,
    *,
    egress_consent: str | None,
) -> dict[str, Any]:
    if review.content_variant == "head":
        include_source_wip = False
        included = [
            "tracked blobs materialized from the frozen head commit",
            "the complete generated frozen diff without secret redaction",
            "the review prompt and result",
        ]
        excluded = [
            "untracked files",
            "unrelated repositories",
            "broad workspace or home-directory content",
        ]
    elif review.content_variant == "source-wip":
        include_source_wip = True
        included = [
            (
                "tracked blobs plus staged, unstaged, and nonignored untracked "
                "contents materialized from the digest-bound source WIP snapshot"
            ),
            (
                "the complete generated frozen diff through the source WIP "
                "snapshot without secret redaction"
            ),
            "the review prompt and result",
        ]
        excluded = [
            "ignored untracked files and source content not captured by the WIP snapshot",
            "unrelated repositories",
            "broad workspace or home-directory content",
        ]
    else:
        raise ReviewError("review egress record has an invalid content variant")
    if include_source_wip != (review.content_variant == "source-wip"):
        raise ReviewError("review egress WIP marker contradicts its content variant")

    return {
        "consent": egress_consent,
        "reviewer": "low-level-helper",
        "requested_helper_reviewer": "claude",
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "review_range": f"{review.base_ref}..{review.head_ref}",
        "content_variant": review.content_variant,
        "include_source_wip": include_source_wip,
        "snapshot_tree_sha": review.snapshot_tree_sha,
        "scope_identity": review.scope_identity,
        "included": included,
        "excluded": excluded,
        "merge_gate": "secret-delta status is evaluated separately",
        "preflight": "review workspace containment and integrity checks passed",
    }


def _run_review_with_binding(
    *,
    review: ReviewWorkspace,
    reviewer: str,
    egress_consent: str | None,
    launch: ReviewLaunchBinding,
) -> Outcome:
    try:
        review = launch.runtime_review(review)
        synthetic_evidence = validate_external_workspace(review) or {}
        preflight_evidence = build_preflight_evidence(review, synthetic_evidence)
        preflight_json = encode_preflight_json(preflight_evidence)
        egress_record = (
            _build_low_level_helper_egress_record(
                review,
                egress_consent=egress_consent,
            )
            if reviewer == "claude"
            else None
        )
        launch.freeze_prompt(review.prompt_file)
    except ReviewError as error:
        private_cleanup_error = remove_private_review_artifacts(
            review.container_dir,
            expected=review.private_cleanup,
        )
        cleanup_suffix = (
            f"; private artifact cleanup failed: {private_cleanup_error}"
            if private_cleanup_error
            else ""
        )
        diagnostic = (
            f"review egress workspace preflight failed: {error}{cleanup_suffix}\n"
        )
        _persist_runner_error(review, diagnostic)
        return Outcome(2, None, tuple())

    private_cleanup_error = remove_private_review_artifacts(
        review.container_dir,
        expected=review.private_cleanup,
    )
    if private_cleanup_error:
        diagnostic = (
            f"review egress private artifact cleanup failed: {private_cleanup_error}\n"
        )
        _persist_runner_error(review, diagnostic)
        return Outcome(2, None, tuple())

    try:
        write_text_atomic_at(
            launch.container_descriptor,
            "preflight.json",
            preflight_json,
        )

        if egress_record is not None:
            write_json_atomic_at(
                launch.container_descriptor,
                "egress.json",
                egress_record,
            )
        review = launch.runtime_review(review)
    except ReviewError as error:
        diagnostic = f"review launch binding failed: {error}\n"
        try:
            write_text_atomic_at(
                launch.container_descriptor,
                "runner-error.txt",
                diagnostic,
            )
        except ReviewError as persistence_error:
            print(
                diagnostic.rstrip("\n")
                + "; runner diagnostic was not persisted: "
                + str(persistence_error),
                file=sys.stderr,
            )
        return Outcome(2, None, tuple())

    attempts: list[Attempt] = []

    if reviewer == "codex":
        env = _review_environment(
            review=review,
            passthrough_keys=CODEX_ENV_KEYS,
            descriptor_bound_workspace=True,
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
                launch=launch,
            )
        except FileNotFoundError as error:
            _persist_runner_error(review, f"{error}\n")
            return Outcome(127, None, tuple())
        except (
            ReviewTimeoutError,
            ReviewOutputDrainError,
            ReviewOutputLimitError,
            ReviewProcessLeakError,
        ) as error:
            _persist_failure_artifacts(
                review,
                f"Codex review was inconclusive: {error}\n",
                attempts,
            )
            return Outcome(75, None, tuple(attempts))
        return _finish(review, attempts, final_text, launch=launch)

    claude_env = _review_environment(
        review=review,
        passthrough_keys=CLAUDE_ENV_KEYS,
        extra={
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_SAFE_MODE": "1",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        },
        descriptor_bound_workspace=True,
    )
    claude_env = _select_claude_authentication(claude_env)
    explicit_claude_override = bool(os.environ.get("CODEX_REVIEW_CLAUDE_PATH"))
    claude_runtime_binding_sink: list[Any] = []
    try:
        linux_host = _is_claude_linux_host()
        prompt = _claude_review_prompt(
            review,
            _review_prompt_bytes(review, launch),
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
            runtime_binding_sink=claude_runtime_binding_sink,
        )
        claude_available = claude_executable is not None
        if claude_available:
            if not _is_claude_linux_host() and not _claude_uses_explicit_auth(
                claude_env
            ):
                claude_env = _prepare_claude_keychain_broker(review, claude_env)
            claude_env = _with_claude_review_tool_path(review, claude_env)
            _update_claude_runtime_report(
                review,
                {
                    "phase": "attempt-preflight-ready",
                    "authentication": {
                        "status": (
                            "configured"
                            if _claude_uses_explicit_auth(claude_env)
                            else "deferred-to-final-attempt"
                        )
                    },
                },
            )
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
            _persist_failure_artifacts(
                review,
                "Explicit CODEX_REVIEW_CLAUDE_PATH lacks a required secure "
                "runtime prerequisite; refusing Copilot fallback: "
                f"{error}\n",
                attempts,
            )
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
        _persist_failure_artifacts(
            review,
            _format_claude_runner_error(
                "Claude Code validation was inconclusive: ",
                error,
            ),
            attempts,
        )
        return Outcome(75, None, tuple(attempts))
    except ReviewError as error:
        _persist_failure_artifacts(
            review,
            _format_claude_runner_error(
                "Claude Code executable validation failed; refusing Copilot fallback: ",
                error,
            ),
            attempts,
        )
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
            launch: ReviewLaunchBinding | None = None,
        ) -> Attempt:
            with atomic_write_redactions(claude_output_redact_values(env)):
                return _claude_attempt(
                    review=review,
                    model=model,
                    index=index,
                    env=env,
                    executable=claude_executable,
                    executable_evidence=claude_executable_evidence,
                    trust_state=claude_trust_state,
                    runtime_binding=(
                        claude_runtime_binding_sink[0]
                        if len(claude_runtime_binding_sink) == 1
                        else None
                    ),
                    launch=launch,
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
                launch=launch,
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
            initial_diagnostic = f"Claude Code validation was inconclusive: {error}\n"
            if _persist_runner_error(review, initial_diagnostic):
                return Outcome(75, None, tuple(attempts))
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
            _persist_failure_artifacts(
                review,
                _format_claude_runner_error(
                    "Claude Code validation was inconclusive: ",
                    error,
                    persistence_diagnostic,
                ),
                attempts,
            )
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
                detail = f"{detail.rstrip('.')}; {persistence_diagnostic.rstrip('.')}"
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
                _persist_failure_artifacts(
                    review,
                    _format_claude_runner_error(
                        "Explicit CODEX_REVIEW_CLAUDE_PATH lacks a required secure "
                        "runtime prerequisite; refusing Copilot fallback: ",
                        error,
                    ),
                    attempts,
                )
                return Outcome(2, None, tuple(attempts))
            category = "unavailable"
            final_text = None
            write_text_atomic(
                review.container_dir / "claude-skip.txt",
                _format_claude_runner_error(
                    "Claude Code local authentication became unavailable: ",
                    error,
                ),
            )
        except ReviewError as error:
            persistence_diagnostic = _record_claude_secondary_persistence_failure(
                review,
                error,
            )
            _persist_failure_artifacts(
                review,
                _format_claude_runner_error(
                    "Claude Code failed executable validation; refusing Copilot "
                    "fallback: ",
                    error,
                    persistence_diagnostic,
                ),
                attempts,
            )
            return Outcome(2, None, tuple(attempts))
        if final_text:
            return _finish(review, attempts, final_text, launch=launch)
        if category == "auth":
            return _finish_claude_auth_required(
                review,
                attempts,
                "the restricted Claude runtime rejected the configured credential",
                action=_claude_authentication_action(
                    _claude_authentication_source(claude_env)
                ),
            )
        if category not in {"entitlement", "unavailable"}:
            return _finish(review, attempts, None, launch=launch)

    if egress_consent not in COPILOT_EGRESS_CONSENTS:
        _persist_failure_artifacts(
            review,
            "Claude Code was unavailable or lacked model entitlement, but "
            "explicit-claude-review does not authorize GitHub Copilot; only "
            "explicit-claude-with-copilot-fallback authorizes the separately "
            "requested compatibility fallback.\n",
            attempts,
        )
        return Outcome(2, None, tuple(attempts))

    try:
        copilot_available = resolve_reviewer_executable("copilot") is not None
    except ReviewError as error:
        _persist_failure_artifacts(
            review,
            f"Copilot CLI executable validation failed: {error}\n",
            attempts,
        )
        return Outcome(2, None, tuple(attempts))
    if not copilot_available:
        diagnostic_error = _persist_runner_error(
            review,
            "Claude Code was unavailable or lacked model entitlement, and "
            "Copilot CLI is unavailable.\n",
        )
        if diagnostic_error:
            return Outcome(1, None, tuple(attempts))
        return _finish(review, attempts, None, launch=launch)
    copilot_env = _review_environment(
        review=review,
        passthrough_keys=COPILOT_ENV_KEYS,
        descriptor_bound_workspace=True,
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
            launch=launch,
        )
    except (
        ReviewTimeoutError,
        ReviewOutputDrainError,
        ReviewOutputLimitError,
        ReviewProcessLeakError,
    ) as error:
        _persist_failure_artifacts(
            review,
            f"Copilot review was inconclusive: {error}\n",
            attempts,
        )
        return Outcome(75, None, tuple(attempts))
    except (FileNotFoundError, ReviewError) as error:
        _persist_failure_artifacts(
            review,
            f"Copilot CLI became unavailable or failed executable validation: {error}\n",
            attempts,
        )
        return Outcome(2, None, tuple(attempts))
    return _finish(review, attempts, final_text, launch=launch)
