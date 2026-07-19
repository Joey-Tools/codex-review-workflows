from __future__ import annotations

import errno
import json
import os
import pathlib
import re
import stat
import sys
import tempfile
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable

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
from .claude_linux import (
    LinuxHost,
    LinuxIsolationUnavailable,
    LinuxRuntimeError,
    LinuxRuntimeInspectionInconclusive,
    LinuxRuntimeUnsafe,
    LinuxUnsupportedHost,
    build_probe_command as build_claude_linux_probe_command,
    detect_host as detect_claude_linux_host,
    discover_native_toolchain as discover_claude_linux_toolchain,
    reject_wsl_windows_path as reject_claude_wsl_windows_path,
    reject_wsl_windows_paths as reject_claude_wsl_windows_paths,
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
    atomic_write_redactions,
    child_environment,
    output_redact_values,
    read_json,
    reviewer_executable_path,
    resolve_reviewer_executable,
    run,
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
CLAUDE_AUTH_STATUS_TIMEOUT_SECONDS = 20.0
CLAUDE_AUTH_STATUS_OUTPUT_LIMIT_BYTES = 64 * 1024
CLAUDE_JSONL_RECORD_LIMIT_BYTES = 4 * 1024 * 1024
CLAUDE_AUTH_LOGIN_ACTION = "Run `claude auth login`, then retry the review."
CLAUDE_API_KEY_ACTION = "Unset or replace `ANTHROPIC_API_KEY`, then retry the review."
CLAUDE_OAUTH_TOKEN_ACTION = (
    "Unset or replace `CLAUDE_CODE_OAUTH_TOKEN`, then retry the review."
)
CLAUDE_LINUX_BOOTSTRAP_LIBRARY_ROOT_CANDIDATES = (
    pathlib.Path("/lib"),
    pathlib.Path("/lib64"),
    pathlib.Path("/usr/lib"),
    pathlib.Path("/usr/lib64"),
)
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
CLAUDE_EGRESS_CONSENTS = (
    "explicit-claude-review",
    "double-review",
    "triple-review",
)
COPILOT_EGRESS_CONSENTS = ("double-review", "triple-review")
CODEX_ENV_KEYS = ("CODEX_HOME", "OPENAI_API_KEY")
CLAUDE_EXPLICIT_AUTH_ENV_KEYS = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
)
CLAUDE_PROXY_ENV_KEYS = (
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
)
CLAUDE_MODEL_SECRET_ENV_KEYS = (
    *CLAUDE_EXPLICIT_AUTH_ENV_KEYS,
    *CLAUDE_PROXY_ENV_KEYS,
)
CLAUDE_ENV_KEYS = (*CLAUDE_EXPLICIT_AUTH_ENV_KEYS, "NODE_EXTRA_CA_CERTS")
CLAUDE_INIT_KEYS = (
    "type",
    "subtype",
    "cwd",
    "session_id",
    "tools",
    "mcp_servers",
    "model",
    "permissionMode",
    "slash_commands",
    "apiKeySource",
    "claude_code_version",
    "output_style",
    "agents",
    "skills",
    "plugins",
    "capabilities",
    "analytics_disabled",
    "product_feedback_disabled",
    "uuid",
    "fast_mode_state",
)
CLAUDE_INIT_TOOLS = ("Bash", "Glob", "Grep", "Read")
CLAUDE_INIT_AGENTS = ("claude", "Explore", "general-purpose", "Plan")
CLAUDE_INIT_CAPABILITIES = ("interrupt_receipt_v1", "msg_lifecycle_v1")
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


class ClaudeProbeSandboxUnavailable(ReviewError):
    """The host does not provide the required Claude probe sandbox runtime."""


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


class ClaudeAuthenticationPreflightBlocked(ReviewError):
    """The effective Claude authentication source is absent or unsupported."""

    def __init__(
        self,
        detail: str,
        *,
        action: str,
        observed: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.action = action
        self.observed = observed or {}


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


def _claude_runtime_directory_identity(
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
        raise ReviewError(f"Claude runtime path must be a real directory: {path}")
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
                _claude_runtime_directory_identity(before),
                _claude_runtime_directory_identity(opened),
                _claude_runtime_directory_identity(after),
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


@dataclass(frozen=True)
class Outcome:
    returncode: int
    final_text: str | None
    attempts: tuple[Attempt, ...]


@dataclass(frozen=True)
class ClaudeAuthenticationEvidence:
    requested_source: str
    api_provider: str
    auth_method: str
    api_key_source: str | None


@dataclass(frozen=True)
class ClaudeBashStagingBaseline:
    staging_was_absent: bool
    parent_identity: tuple[int, int, int, int] | None


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


def _claude_pwd_home() -> pathlib.Path:
    try:
        import pwd

        raw_home = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, OSError) as error:
        raise ClaudeExecutableInspectionInconclusive(
            f"cannot resolve the current user's home: {error}"
        ) from error
    home = pathlib.Path(raw_home)
    if not home.is_absolute() or home == pathlib.Path("/"):
        raise ReviewError("the current user's HOME must be an absolute user directory")
    return home


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


def _claude_authentication_source(env: dict[str, str]) -> str:
    if env.get("ANTHROPIC_API_KEY"):
        return "api-key"
    if env.get("CLAUDE_CODE_OAUTH_TOKEN"):
        return "oauth-token"
    return "local-login"


def _review_scope_metadata(review: ReviewWorkspace) -> dict[str, str]:
    return {
        "content_variant": review.content_variant,
        "base_ref": review.base_ref,
        "head_ref": review.head_ref,
        "snapshot_tree_sha": review.snapshot_tree_sha,
        "scope_identity": review.scope_identity,
    }


def _select_claude_authentication(
    env: dict[str, str],
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Opaque-forward one explicit credential and redact its transport."""
    selected = dict(env)
    redact_values = tuple(
        dict.fromkeys(
            value
            for key in CLAUDE_MODEL_SECRET_ENV_KEYS
            if (value := selected.get(key))
        )
    )
    if selected.get("ANTHROPIC_API_KEY"):
        selected.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
    elif selected.get("CLAUDE_CODE_OAUTH_TOKEN"):
        selected.pop("ANTHROPIC_API_KEY", None)
    else:
        for key in CLAUDE_EXPLICIT_AUTH_ENV_KEYS:
            selected.pop(key, None)
    return selected, redact_values


def _claude_authentication_action(requested_source: str) -> str:
    if requested_source == "api-key":
        return CLAUDE_API_KEY_ACTION
    if requested_source == "oauth-token":
        return CLAUDE_OAUTH_TOKEN_ACTION
    return CLAUDE_AUTH_LOGIN_ACTION


def _claude_effective_authentication(
    payload: bytes,
    *,
    requested_source: str,
) -> ClaudeAuthenticationEvidence:
    status = _strict_json_object(payload)
    action = _claude_authentication_action(requested_source)
    if status is None:
        raise ReviewError(
            "Claude Code auth status did not return one strict JSON object"
        )
    logged_in = status.get("loggedIn")
    api_provider = status.get("apiProvider")
    auth_method = status.get("authMethod")
    api_key_source = status.get("apiKeySource")
    if logged_in is not True:
        raise ClaudeAuthenticationPreflightBlocked(
            f"Claude Code auth status reports no usable {requested_source}",
            action=action,
            observed={
                "logged_in": logged_in,
                "effective_api_provider": api_provider,
                "effective_auth_method": auth_method,
                "effective_api_key_source": api_key_source,
            },
        )
    if not isinstance(api_provider, str) or not isinstance(auth_method, str):
        raise ReviewError(
            "Claude Code auth status omitted its effective provider or method"
        )
    if api_key_source is not None and not isinstance(api_key_source, str):
        raise ReviewError("Claude Code auth status returned an invalid API-key source")

    expected: tuple[str, str, str | None]
    if requested_source == "api-key":
        expected = ("firstParty", "api_key", "ANTHROPIC_API_KEY")
    elif requested_source == "oauth-token":
        expected = ("firstParty", "oauth_token", None)
    else:
        expected = ("firstParty", "claude.ai", None)
    observed = (api_provider, auth_method, api_key_source)
    if observed != expected:
        source_detail = (
            f", apiKeySource={api_key_source!r}" if api_key_source is not None else ""
        )
        raise ClaudeAuthenticationPreflightBlocked(
            "Claude Code selected an unsupported or higher-priority authentication "
            f"source (provider={api_provider!r}, method={auth_method!r}"
            f"{source_detail}) instead of {requested_source}",
            action=(
                "Disable Claude apps gateway, ANTHROPIC_AUTH_TOKEN, cloud-provider "
                "authentication, and apiKeyHelper inputs, then retry the review."
            ),
            observed={
                "logged_in": logged_in,
                "effective_api_provider": api_provider,
                "effective_auth_method": auth_method,
                "effective_api_key_source": api_key_source,
            },
        )
    return ClaudeAuthenticationEvidence(
        requested_source=requested_source,
        api_provider=api_provider,
        auth_method=auth_method,
        api_key_source=api_key_source,
    )


def _claude_authentication_preflight(
    *,
    review: ReviewWorkspace,
    executable: pathlib.Path,
    env: dict[str, str],
    settings: str,
    index: int,
    redact_values: tuple[str, ...],
) -> ClaudeAuthenticationEvidence:
    requested_source = _claude_authentication_source(env)
    auth_dir = review.container_dir / "claude-auth-status"
    stdout_path = auth_dir / f"{index:02d}.stdout.log"
    stderr_path = auth_dir / f"{index:02d}.stderr.log"
    completed = run(
        (
            str(executable),
            "--safe-mode",
            "--setting-sources",
            "",
            "--settings",
            settings,
            "auth",
            "status",
            "--json",
        ),
        cwd=review.workspace_root,
        env=env,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout_seconds=CLAUDE_AUTH_STATUS_TIMEOUT_SECONDS,
        output_file_limit_bytes=CLAUDE_AUTH_STATUS_OUTPUT_LIMIT_BYTES,
        redact_values=output_redact_values(redact_values),
    )
    if completed.returncode != 0:
        raise ReviewError(
            "Claude Code auth-status preflight failed before review content was sent"
        )
    try:
        evidence = _claude_effective_authentication(
            completed.stdout,
            requested_source=requested_source,
        )
    except ClaudeAuthenticationPreflightBlocked as error:
        rejected = {
            "requested_source": requested_source,
            **error.observed,
            "status": "effective-auth-rejected",
        }
        _update_claude_runtime_report(review, {"authentication": rejected})
        egress_path = review.container_dir / "egress.json"
        if egress_path.exists():
            egress = read_json(egress_path)
            egress["authentication"] = rejected
            write_json(egress_path, egress)
        raise
    _update_claude_runtime_report(
        review,
        {
            "authentication": {
                "requested_source": evidence.requested_source,
                "effective_api_provider": evidence.api_provider,
                "effective_auth_method": evidence.auth_method,
                "effective_api_key_source": evidence.api_key_source,
                "status": "effective-auth-verified",
            }
        },
    )
    egress_path = review.container_dir / "egress.json"
    if egress_path.exists():
        egress = read_json(egress_path)
        egress["authentication"] = {
            "requested_source": evidence.requested_source,
            "effective_api_provider": evidence.api_provider,
            "effective_auth_method": evidence.auth_method,
            "effective_api_key_source": evidence.api_key_source,
            "status": "effective-auth-verified",
        }
        write_json(egress_path, egress)
    return evidence


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
        # These probes are credential-free and never enter a model-backed
        # permission mode, so the CLI's subprocess scrub is compatible here.
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
    if any(code in structured_primary_error for code in STRUCTURED_ENTITLEMENT_CODES):
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
        if (message := _structured_error_item_text(item))
    )


def _parse_claude_result_object(
    result: dict[str, Any],
    *,
    requested_model: str | None,
    structured_error: bool,
) -> tuple[str | None, str | None]:
    if result.get("type") != "result":
        return None, None
    model_usage = result.get("modelUsage")
    if not isinstance(model_usage, dict) or not model_usage:
        return None, None
    if any(
        not isinstance(key, str) or not key or not isinstance(value, dict)
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
        if value is not None and not (isinstance(value, str) and not value.strip()):
            return None, effective_model
    final_text = result.get("result")
    if not isinstance(final_text, str) or not final_text.strip() or not candidates:
        return None, effective_model
    if structured_error:
        return None, effective_model
    return final_text, effective_model


def _parse_claude_output(
    stdout: bytes, *, requested_model: str | None = None
) -> tuple[str | None, str | None]:
    result = _strict_json_object(stdout)
    if result is None:
        return None, None
    return _parse_claude_result_object(
        result,
        requested_model=requested_model,
        structured_error=bool(_structured_error_text(stdout).strip()),
    )


def _claude_init_contract_matches(
    init: dict[str, Any],
    *,
    review: ReviewWorkspace,
    requested_model: str,
    authentication: ClaudeAuthenticationEvidence,
) -> bool:
    if not set(CLAUDE_INIT_KEYS).issubset(init):
        return False
    if init.get("type") != "system" or init.get("subtype") != "init":
        return False
    if init.get("cwd") != str(review.workspace_root):
        return False
    if init.get("permissionMode") != "plan":
        return False
    tools = init.get("tools")
    if (
        not isinstance(tools, list)
        or len(tools) != len(CLAUDE_INIT_TOOLS)
        or set(tools) != set(CLAUDE_INIT_TOOLS)
    ):
        return False
    if any(
        init.get(key) != []
        for key in ("mcp_servers", "slash_commands", "skills", "plugins")
    ):
        return False
    agents = init.get("agents")
    if not isinstance(agents, list) or tuple(agents) != CLAUDE_INIT_AGENTS:
        return False
    capabilities = init.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or tuple(capabilities) != CLAUDE_INIT_CAPABILITIES
    ):
        return False
    model = init.get("model")
    if not isinstance(model, str) or not _model_matches(requested_model, model):
        return False
    expected_api_key_source = (
        "ANTHROPIC_API_KEY" if authentication.requested_source == "api-key" else "none"
    )
    if init.get("apiKeySource") != expected_api_key_source:
        return False
    if init.get("output_style") != "default" or init.get("fast_mode_state") != "off":
        return False
    if init.get("analytics_disabled") is not True:
        return False
    if not isinstance(init.get("product_feedback_disabled"), bool):
        return False
    if not all(
        isinstance(init.get(key), str) and init[key]
        for key in ("session_id", "uuid", "claude_code_version")
    ):
        return False
    return True


def _parse_claude_stream_objects(
    objects: Iterable[dict[str, Any]],
    *,
    review: ReviewWorkspace,
    requested_model: str,
    authentication: ClaudeAuthenticationEvidence,
) -> tuple[str | None, str | None, bool]:
    materialized = list(objects)
    if len(materialized) < 2:
        return None, None, False
    init_events = [
        item
        for item in materialized
        if item.get("type") == "system" and item.get("subtype") == "init"
    ]
    result_events = [item for item in materialized if item.get("type") == "result"]
    if (
        len(init_events) != 1
        or init_events[0] is not materialized[0]
        or len(result_events) != 1
        or result_events[0] is not materialized[-1]
    ):
        return None, None, False
    init_matches = _claude_init_contract_matches(
        init_events[0],
        review=review,
        requested_model=requested_model,
        authentication=authentication,
    )
    structured_error = any(_structured_error_item_text(item) for item in materialized)
    final_text, effective_model = _parse_claude_result_object(
        result_events[0],
        requested_model=requested_model,
        structured_error=structured_error,
    )
    terminal_matches = (
        final_text is not None
        and effective_model is not None
        and _model_matches(requested_model, effective_model)
    )
    return final_text, effective_model, init_matches and terminal_matches


def _strict_claude_jsonl_file_objects(
    path: pathlib.Path,
) -> Iterable[dict[str, Any]]:
    with path.open("rb") as handle:
        while raw_line := handle.readline(CLAUDE_JSONL_RECORD_LIMIT_BYTES + 2):
            line = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
            if len(line) > CLAUDE_JSONL_RECORD_LIMIT_BYTES:
                raise ValueError("Claude JSONL record exceeds the bounded parser limit")
            if not line.strip(b" \t\r"):
                continue
            parsed = json.loads(
                line.decode("utf-8"),
                parse_constant=_reject_nonstandard_json_constant,
                object_pairs_hook=_strict_json_object_from_pairs,
            )
            if not isinstance(parsed, dict):
                raise ValueError("Claude JSONL record is not an object")
            yield parsed


def _parse_claude_stream_output_file(
    path: pathlib.Path,
    *,
    review: ReviewWorkspace,
    requested_model: str,
    authentication: ClaudeAuthenticationEvidence,
) -> tuple[str | None, str | None, bool]:
    try:
        return _parse_claude_stream_objects(
            _strict_claude_jsonl_file_objects(path),
            review=review,
            requested_model=requested_model,
            authentication=authentication,
        )
    except (OSError, UnicodeDecodeError, ValueError):
        return None, None, False


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
    prepared_env = dict(env)
    prepared_env["HOME"] = str(_claude_pwd_home())
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
        candidate_env = _claude_preflight_probe_environment(
            home=probe_home,
            tmp=claude_tmp,
        )
        _require_claude_safe_mode(verified_executable, candidate_env)
        runtime_executables[str(candidate.absolute())] = verified_executable
        if isinstance(verified, VerifiedClaudeExecutable):
            authentication_source = _claude_authentication_source(prepared_env)
            runtime_reports[str(candidate.absolute())] = {
                "schema": 1,
                "phase": "publisher-and-cli-contract-verified",
                **_review_scope_metadata(review),
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
                    "safe_mode_help_contract": "verified",
                    "effective_init_contract": "pending-review-stream",
                    "native_sandbox": "requested-not-independently-observable",
                },
                "sandbox": {
                    "implementation": "claude-native-sandbox",
                    "status": "requested-not-independently-observable",
                },
                "authentication": {
                    "requested_source": authentication_source,
                    "status": "pending-effective-preflight",
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


def _claude_review_arguments(
    *,
    model: str,
    settings: str,
) -> tuple[str, ...]:
    return (
        "--print",
        "--model",
        model,
        "--effort",
        CLAUDE_REASONING_EFFORT,
        "--permission-mode",
        "plan",
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
        "Read,Grep,Glob,Bash",
        "--allowedTools",
        "Read(./**)",
        "--disallowedTools",
        "Edit,Write,NotebookEdit,WebFetch,WebSearch,Task",
    )


def _claude_review_settings(
    *,
    review: ReviewWorkspace,
    home: pathlib.Path,
) -> str:
    workspace = review.workspace_root.resolve()
    git_view = (review.git_dir or review.container_dir / "review.git").resolve()
    protected_files = (
        "~/.aws",
        "~/.claude",
        "~/.codex",
        "~/.config",
        "~/.copilot",
        "~/.gnupg",
        "~/.kube",
        "~/.ssh",
        "~/.git-credentials",
        "~/.netrc",
    )
    return json.dumps(
        {
            "disableAllHooks": True,
            "permissions": {"deny": list(CLAUDE_REVIEW_FILE_DENY_RULES)},
            "sandbox": {
                "enabled": True,
                "failIfUnavailable": True,
                "autoAllowBashIfSandboxed": False,
                "allowUnsandboxedCommands": False,
                "filesystem": {
                    "denyRead": [str(home)],
                    "allowRead": [str(workspace), str(git_view)],
                    "denyWrite": [str(home), str(workspace), str(git_view)],
                },
                "credentials": {
                    "files": [
                        {"path": path, "mode": "deny"} for path in protected_files
                    ],
                    "envVars": [
                        {"name": name, "mode": "deny"}
                        for name in CLAUDE_MODEL_SECRET_ENV_KEYS
                    ],
                },
            },
        },
        separators=(",", ":"),
    )


def _claude_review_prompt(
    review: ReviewWorkspace,
    prompt: bytes,
) -> bytes:
    workspace = str(review.workspace_root).encode("utf-8")
    diff_file = str(review.diff_file).encode("utf-8")
    projected = prompt.replace(
        b"- Workspace: .\n",
        b"- Workspace: " + workspace + b"\n",
    ).replace(
        b"- Primary diff file: .codex-review/review.diff\n",
        b"- Primary diff file: " + diff_file + b"\n",
    )
    if len(projected) > MAX_REVIEW_PROMPT_BYTES:
        raise ReviewError(
            "Claude projected review prompt exceeds the "
            f"{MAX_REVIEW_PROMPT_BYTES}-byte limit"
        )
    return projected


def _claude_directory_open_flags() -> int:
    directory_flag = getattr(os, "O_DIRECTORY", None)
    no_follow_flag = getattr(os, "O_NOFOLLOW", None)
    if directory_flag is None or no_follow_flag is None:
        raise ReviewError(
            "host does not support no-follow Claude staging directory inspection"
        )
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | directory_flag
        | no_follow_flag
        | getattr(os, "O_NONBLOCK", 0)
    )


def _claude_directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    )


def _claude_bash_staging_baseline(
    review: ReviewWorkspace,
) -> ClaudeBashStagingBaseline:
    """Capture the exact staging and parent identity before Claude starts."""

    workspace_descriptor: int | None = None
    parent_descriptor: int | None = None
    try:
        workspace_descriptor = os.open(
            review.workspace_root,
            _claude_directory_open_flags(),
        )
        try:
            parent_descriptor = os.open(
                ".claude",
                _claude_directory_open_flags(),
                dir_fd=workspace_descriptor,
            )
        except FileNotFoundError:
            return ClaudeBashStagingBaseline(
                staging_was_absent=True,
                parent_identity=None,
            )
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                return ClaudeBashStagingBaseline(
                    staging_was_absent=False,
                    parent_identity=None,
                )
            raise ReviewError("cannot inspect Claude Bash staging parent") from error
        opened_parent_identity = _claude_directory_identity(os.fstat(parent_descriptor))
        try:
            os.stat(
                ".cc-writes",
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            staging_was_absent = True
        except OSError as error:
            raise ReviewError("cannot inspect Claude Bash staging entry") from error
        else:
            staging_was_absent = False
        try:
            current_parent_identity = _claude_directory_identity(
                os.stat(
                    ".claude",
                    dir_fd=workspace_descriptor,
                    follow_symlinks=False,
                )
            )
        except FileNotFoundError as error:
            raise ReviewError(
                "Claude Bash staging parent disappeared during baseline capture"
            ) from error
        if current_parent_identity != opened_parent_identity:
            raise ReviewError(
                "Claude Bash staging parent changed during baseline capture"
            )
        return ClaudeBashStagingBaseline(
            staging_was_absent=staging_was_absent,
            parent_identity=opened_parent_identity,
        )
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError("cannot inspect Claude Bash staging path") from error
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if workspace_descriptor is not None:
            os.close(workspace_descriptor)


def _remove_empty_claude_bash_staging_parent(
    review: ReviewWorkspace,
    *,
    workspace_descriptor: int,
    parent_descriptor: int,
    parent_identity: tuple[int, int, int, int],
) -> None:
    """Quarantine and remove only the exact opened empty parent directory."""

    if os.listdir(parent_descriptor):
        return
    quarantine_root = pathlib.Path(
        tempfile.mkdtemp(
            prefix=".claude-bash-staging-quarantine-",
            dir=review.container_dir,
        )
    )
    quarantine_descriptor: int | None = None
    try:
        quarantine_descriptor = os.open(
            quarantine_root,
            _claude_directory_open_flags(),
        )
        try:
            os.rename(
                ".claude",
                "parent",
                src_dir_fd=workspace_descriptor,
                dst_dir_fd=quarantine_descriptor,
            )
        except OSError as error:
            raise ReviewError(
                "cannot quarantine empty Claude Bash staging parent"
            ) from error
        quarantined_identity = _claude_directory_identity(
            os.stat(
                "parent",
                dir_fd=quarantine_descriptor,
                follow_symlinks=False,
            )
        )
        if quarantined_identity != parent_identity:
            raise ReviewError(
                "Claude Bash staging parent changed before quarantine removal"
            )
        if os.listdir(parent_descriptor):
            raise ReviewError("Claude Bash staging parent changed after quarantine")
        os.rmdir("parent", dir_fd=quarantine_descriptor)
    finally:
        if quarantine_descriptor is not None:
            os.close(quarantine_descriptor)
        try:
            quarantine_root.rmdir()
        except OSError:
            pass


def _remove_claude_bash_staging_directory(
    review: ReviewWorkspace,
    *,
    baseline: ClaudeBashStagingBaseline,
) -> str:
    """Remove only a newly created exact empty native-Bash staging path."""

    if not baseline.staging_was_absent and baseline.parent_identity is None:
        return "preexisting-not-removed"
    workspace_descriptor: int | None = None
    parent_descriptor: int | None = None
    staging_descriptor: int | None = None
    try:
        workspace_descriptor = os.open(
            review.workspace_root,
            _claude_directory_open_flags(),
        )
        try:
            parent_descriptor = os.open(
                ".claude",
                _claude_directory_open_flags(),
                dir_fd=workspace_descriptor,
            )
        except FileNotFoundError:
            if baseline.parent_identity is not None:
                raise ReviewError("Claude Bash staging parent disappeared after launch")
            return "absent"
        parent_metadata = os.fstat(parent_descriptor)
        parent_identity = _claude_directory_identity(parent_metadata)
        if (
            baseline.parent_identity is not None
            and parent_identity != baseline.parent_identity
        ):
            raise ReviewError("Claude Bash staging parent changed after launch")
        current_parent_identity = _claude_directory_identity(
            os.stat(
                ".claude",
                dir_fd=workspace_descriptor,
                follow_symlinks=False,
            )
        )
        if current_parent_identity != parent_identity:
            raise ReviewError("Claude Bash staging parent changed during cleanup")
        if not baseline.staging_was_absent:
            return "preexisting-not-removed"
        if parent_metadata.st_uid != os.geteuid() or parent_metadata.st_mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            raise ReviewError("Claude Bash staging parent is unsafe")
        try:
            staging_descriptor = os.open(
                ".cc-writes",
                _claude_directory_open_flags(),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            current_parent_identity = _claude_directory_identity(
                os.stat(
                    ".claude",
                    dir_fd=workspace_descriptor,
                    follow_symlinks=False,
                )
            )
            if current_parent_identity != parent_identity:
                raise ReviewError(
                    "Claude Bash staging parent changed before absent return"
                )
            return "absent"
        opened = os.fstat(staging_descriptor)
        if opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700:
            raise ReviewError("Claude Bash staging directory is unsafe")
        if os.listdir(staging_descriptor):
            raise ReviewError("Claude Bash staging directory is not empty")
        final = os.fstat(staging_descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_uid,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ):
            raise ReviewError("Claude Bash staging directory changed during inspection")
        current = os.stat(
            ".cc-writes",
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_uid,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
        ):
            raise ReviewError("Claude Bash staging directory changed before removal")
        current_parent_identity = _claude_directory_identity(
            os.stat(
                ".claude",
                dir_fd=workspace_descriptor,
                follow_symlinks=False,
            )
        )
        if current_parent_identity != parent_identity:
            raise ReviewError(
                "Claude Bash staging parent changed before staging removal"
            )
        os.rmdir(".cc-writes", dir_fd=parent_descriptor)
        try:
            current_parent_identity = _claude_directory_identity(
                os.stat(
                    ".claude",
                    dir_fd=workspace_descriptor,
                    follow_symlinks=False,
                )
            )
        except FileNotFoundError as error:
            raise ReviewError(
                "Claude Bash staging parent disappeared during cleanup"
            ) from error
        if current_parent_identity != parent_identity:
            raise ReviewError("Claude Bash staging parent changed during cleanup")
        if baseline.parent_identity is not None:
            return "verified-and-removed"
        _remove_empty_claude_bash_staging_parent(
            review,
            workspace_descriptor=workspace_descriptor,
            parent_descriptor=parent_descriptor,
            parent_identity=parent_identity,
        )
        return "verified-and-removed"
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(
            "cannot verify and remove Claude Bash staging path"
        ) from error
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if workspace_descriptor is not None:
            os.close(workspace_descriptor)


def _claude_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
    executable: pathlib.Path | None = None,
    redact_values: tuple[str, ...] = (),
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

    home = _claude_pwd_home().resolve()
    if pathlib.Path(env.get("HOME", "")).resolve() != home:
        raise ReviewError("Claude Code review must preserve the current user's HOME")
    settings = _claude_review_settings(review=review, home=home)
    authentication = _claude_authentication_preflight(
        review=review,
        executable=executable,
        env=env,
        settings=settings,
        index=index,
        redact_values=redact_values,
    )
    prompt = _claude_review_prompt(
        review,
        review.prompt_file.read_bytes(),
    )
    stdout_path, stderr_path = _attempt_paths(review, index, "claude", model)
    arguments = _claude_review_arguments(model=model, settings=settings)
    _update_claude_runtime_report(
        review,
        {
            **_review_scope_metadata(review),
            "phase": "runtime-launching",
            "sandbox": {
                "implementation": "claude-native-sandbox",
                "status": "requested-not-independently-observable",
            },
            "authentication": {
                "requested_source": authentication.requested_source,
                "effective_api_provider": authentication.api_provider,
                "effective_auth_method": authentication.auth_method,
                "effective_api_key_source": authentication.api_key_source,
                "status": "effective-auth-verified",
                "model": model,
            },
            "attempt": None,
        },
    )
    claude_bash_staging_baseline = _claude_bash_staging_baseline(review)
    completed = run(
        (str(executable), *arguments),
        cwd=review.workspace_root,
        env=env,
        stdin=prompt,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout_seconds=REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        output_file_limit_bytes=REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
        redact_values=output_redact_values(redact_values),
    )
    post_attempt_workspace_verified = True
    claude_bash_staging_contract = "rejected"
    try:
        claude_bash_staging_contract = _remove_claude_bash_staging_directory(
            review,
            baseline=claude_bash_staging_baseline,
        )
        validate_external_workspace(review)
    except ReviewError:
        post_attempt_workspace_verified = False
        _append_attempt_diagnostic(
            stderr_path,
            "post-attempt external review workspace validation failed; refusing "
            "the Claude result and any model fallback",
        )
    if post_attempt_workspace_verified:
        final_text, effective_model, runtime_contract_verified = (
            _parse_claude_stream_output_file(
                stdout_path,
                review=review,
                requested_model=model,
                authentication=authentication,
            )
        )
    else:
        final_text = None
        effective_model = None
        runtime_contract_verified = False
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
    if not post_attempt_workspace_verified:
        attempt = replace(
            attempt,
            returncode=65,
            category="permission-mismatch",
            final_text=None,
        )
    elif completed.returncode == 0 and not runtime_contract_verified:
        _append_attempt_diagnostic(
            stderr_path,
            "effective Claude system/init or terminal result did not preserve the "
            "plan-mode, tool, model, and authentication contract; refusing a result "
            "that may reflect managed-policy or provider override",
        )
        attempt = replace(
            attempt,
            returncode=65,
            category="permission-mismatch",
            final_text=None,
        )
    authentication_status = (
        "used"
        if completed.returncode == 0
        and post_attempt_workspace_verified
        and runtime_contract_verified
        and attempt.category == "success"
        else "effective-auth-verified"
    )
    _update_claude_runtime_report(
        review,
        {
            "phase": "attempt-complete",
            "capabilities": {
                "effective_init_contract": (
                    "verified" if runtime_contract_verified else "rejected"
                ),
                "post_attempt_workspace_contract": (
                    "verified" if post_attempt_workspace_verified else "rejected"
                ),
                "claude_bash_staging_contract": claude_bash_staging_contract,
            },
            "sandbox": {
                "implementation": "claude-native-sandbox",
                "status": "requested-not-independently-observable",
            },
            "authentication": {
                "requested_source": authentication.requested_source,
                "effective_api_provider": authentication.api_provider,
                "effective_auth_method": authentication.auth_method,
                "effective_api_key_source": authentication.api_key_source,
                "status": authentication_status,
                "model": model,
            },
            "attempt": {
                "requested_model": model,
                "effective_model": attempt.effective_model,
                "requested_effort": CLAUDE_REASONING_EFFORT,
                "effective_effort": attempt.effective_effort,
                "category": attempt.category,
                "returncode": attempt.returncode,
                "effective_init_contract": runtime_contract_verified,
                "post_attempt_workspace_contract": (post_attempt_workspace_verified),
                "claude_bash_staging_contract": claude_bash_staging_contract,
            },
        },
    )
    if authentication_status == "used":
        egress_path = review.container_dir / "egress.json"
        if egress_path.exists():
            egress = read_json(egress_path)
            egress_authentication = egress.get("authentication")
            if not isinstance(egress_authentication, dict):
                raise ReviewError("Claude egress authentication evidence is invalid")
            egress_authentication["status"] = "used"
            egress_authentication["effective_init_contract"] = "verified"
            write_json(egress_path, egress)
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


def _attempt_summary(
    attempt: Attempt,
    *,
    review: ReviewWorkspace,
) -> dict[str, Any]:
    return {
        **_review_scope_metadata(review),
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
        [_attempt_summary(item, review=review) for item in attempts],
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
        f"Claude Code authentication requires user action: {detail}. {action}\n",
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
    if reviewer != "claude":
        return _run_review_impl(
            review=review,
            reviewer=reviewer,
            egress_consent=egress_consent,
        )
    raw_env = _review_environment(
        review=review,
        passthrough_keys=CLAUDE_ENV_KEYS,
        extra={
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_SAFE_MODE": "1",
            # Claude Code 2.1.212 forces permissionMode=default when this is 1.
            # Keep plan mode effective and delegate sandboxed-Bash credential
            # removal to the fail-closed native sandbox credentials policy.
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
        },
    )
    claude_env, redact_values = _select_claude_authentication(raw_env)
    with atomic_write_redactions(redact_values):
        return _run_review_impl(
            review=review,
            reviewer=reviewer,
            egress_consent=egress_consent,
            claude_env=claude_env,
            claude_redact_values=redact_values,
        )


def _run_review_impl(
    *,
    review: ReviewWorkspace,
    reviewer: str,
    egress_consent: str | None = None,
    claude_env: dict[str, str] | None = None,
    claude_redact_values: tuple[str, ...] = (),
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

    is_wip = review.content_variant == "source-wip"
    scope_description = (
        "digest-bound source WIP snapshot, scanned endpoint Git objects, diff, "
        "and review prompt"
        if is_wip
        else "detached clean head worktree, scanned endpoint Git objects, diff, "
        "and review prompt"
    )
    preflight_evidence = {
        "content_variant": review.content_variant,
        "review_range": f"{review.base_ref}..{review.head_ref}",
        "scope": scope_description,
        "scope_identity": review.scope_identity,
        "snapshot_tree_sha": review.snapshot_tree_sha,
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
                "content_variant": review.content_variant,
                "scope_identity": review.scope_identity,
                "snapshot_tree_sha": review.snapshot_tree_sha,
                "authentication": {
                    "requested_source": (
                        _claude_authentication_source(claude_env)
                        if claude_env is not None
                        else "unprepared"
                    ),
                    "status": "pending-effective-preflight",
                },
                "included": (
                    [
                        "the explicit digest-bound source WIP snapshot, including "
                        "staged, unstaged, and non-ignored untracked content",
                        "scanned base and head endpoint commit metadata and tree/blob closures",
                        "the helper-generated WIP snapshot tree/blob closure",
                        "the generated snapshot diff",
                        "the review prompt and result",
                    ]
                    if is_wip
                    else [
                        "tracked blobs materialized from the detached clean head commit",
                        "scanned base and head endpoint commit metadata and tree/blob closures",
                        "the generated frozen diff",
                        "the review prompt and result",
                    ]
                ),
                "excluded": [
                    "credential paths and high-confidence secrets blocked by preflight",
                    (
                        "ignored and otherwise uncaptured source files"
                        if is_wip
                        else "untracked files"
                    ),
                    "intermediate commit history and history-only tree/blob objects",
                    "unrelated repositories",
                    "real-HOME content, which is outside authorized review scope and "
                    "is not packaged in the review artifact",
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

    if claude_env is None:
        raise ReviewError("Claude Code review environment was not prepared")
    explicit_claude_override = bool(os.environ.get("CODEX_REVIEW_CLAUDE_PATH"))
    try:
        claude_executable, claude_env = _resolve_validated_claude_executable(
            review=review,
            env=claude_env,
        )
        claude_available = claude_executable is not None
    except (
        ClaudeProbeSandboxUnavailable,
        ClaudeExecutableUnavailable,
        ClaudeProvenanceVerifierUnavailable,
    ) as error:
        if explicit_claude_override and isinstance(
            error,
            (
                ClaudeExecutableUnavailable,
                ClaudeProbeSandboxUnavailable,
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
                redact_values=claude_redact_values,
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
        except ClaudeAuthenticationPreflightBlocked as error:
            return _finish_claude_auth_required(
                review,
                attempts,
                str(error),
                action=error.action,
            )
        except (
            FileNotFoundError,
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
            ClaudeExecutableUnavailable,
            ClaudeProbeSandboxUnavailable,
            ClaudeProvenanceVerifierUnavailable,
        ) as error:
            if explicit_claude_override and isinstance(
                error,
                (
                    ClaudeExecutableUnavailable,
                    ClaudeProbeSandboxUnavailable,
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
        if category == "auth":
            return _finish_claude_auth_required(
                review,
                attempts,
                "the restricted Claude runtime rejected the configured credential",
                action=(
                    CLAUDE_API_KEY_ACTION
                    if claude_env.get("ANTHROPIC_API_KEY")
                    else (
                        CLAUDE_OAUTH_TOKEN_ACTION
                        if claude_env.get("CLAUDE_CODE_OAUTH_TOKEN")
                        else CLAUDE_AUTH_LOGIN_ACTION
                    )
                ),
            )
        if category not in {"entitlement", "unavailable"}:
            return _finish(review, attempts, None)

    if egress_consent not in COPILOT_EGRESS_CONSENTS:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code was unavailable or lacked model entitlement, but "
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
