from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Callable, Mapping, Sequence

from .common import (
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    run_bounded_capture,
)
from .claude_version_policy import (
    CLAUDE_COMPATIBILITY_SPEC,
    ClaudeVersionPolicyError,
    parse_compatible_release_version,
)

if TYPE_CHECKING:
    from .claude_linux import HostRuntimeClosure


CLAUDE_RELEASE_BASE_URL = "https://downloads.claude.ai/claude-code-releases"
CLAUDE_RELEASE_KEY_FINGERPRINT = "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
CLAUDE_RELEASE_KEY_PATH = pathlib.Path(__file__).with_name("claude_code_release.asc")
CLAUDE_MANIFEST_MAX_BYTES = 256 * 1024
CLAUDE_SIGNATURE_MAX_BYTES = 64 * 1024
CLAUDE_BINARY_MAX_BYTES = 1024 * 1024 * 1024
CLAUDE_CACHE_METADATA_MAX_BYTES = 4 * 1024
CLAUDE_FETCH_TIMEOUT_SECONDS = 20.0
CLAUDE_FETCH_CHUNK_BYTES = 64 * 1024
CLAUDE_GPG_TIMEOUT_SECONDS = 15.0
CLAUDE_GPG_OUTPUT_MAX_BYTES = 64 * 1024
CLAUDE_GPG_EXECUTABLE_MAX_BYTES = 256 * 1024 * 1024
CLAUDE_GPG_DEPENDENCY_MAX_COUNT = 128
TRUSTED_OTOOL = pathlib.Path("/usr/bin/otool")
CLAUDE_SUPPORTED_PLATFORM_BINARIES: Mapping[str, str] = {
    "darwin-arm64": "claude",
    "darwin-x64": "claude",
    "linux-arm64": "claude",
    "linux-x64": "claude",
    "linux-arm64-musl": "claude",
    "linux-x64-musl": "claude",
}
TRUSTED_GPG_CANDIDATES = (
    pathlib.Path("/usr/bin/gpg"),
    pathlib.Path("/usr/bin/gpg2"),
    pathlib.Path("/usr/local/bin/gpg"),
    pathlib.Path("/usr/local/bin/gpg2"),
    pathlib.Path("/opt/homebrew/bin/gpg"),
    pathlib.Path("/opt/homebrew/bin/gpg2"),
)
_TRUSTED_LINUX_GPG_CANDIDATES = (
    pathlib.Path("/usr/bin/gpg"),
    pathlib.Path("/usr/bin/gpg2"),
)
_TRUSTED_DARWIN_GPG_CANDIDATES = TRUSTED_GPG_CANDIDATES
_DARWIN_SEALED_LIBRARY_ROOTS = (
    pathlib.PurePosixPath("/usr/lib"),
    pathlib.PurePosixPath("/System/Library"),
)
_DARWIN_HOMEBREW_ROOTS = (
    pathlib.PurePosixPath("/opt/homebrew"),
    pathlib.PurePosixPath("/usr/local"),
)
_DARWIN_HOMEBREW_DEPENDENCY_ROOTS = (
    pathlib.PurePosixPath("/opt/homebrew/opt"),
    pathlib.PurePosixPath("/opt/homebrew/Cellar"),
    pathlib.PurePosixPath("/usr/local/opt"),
    pathlib.PurePosixPath("/usr/local/Cellar"),
)

_RELEASE_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NATIVE_EXECUTABLE_MAGICS = {
    b"\x7fELF",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


class ClaudeProvenanceError(RuntimeError):
    """Base class for Claude Code release provenance failures."""


class ClaudeProvenanceInvalid(ClaudeProvenanceError):
    """The candidate or signed release metadata is deterministically invalid."""


class ClaudeProvenanceInconclusive(ClaudeProvenanceError):
    """A transient failure prevented a trustworthy provenance decision."""


class ClaudeProvenanceUnavailable(ClaudeProvenanceError):
    """A local provenance operation could not be completed."""


class ClaudeProvenanceDependencyUnavailable(ClaudeProvenanceUnavailable):
    """The host deterministically lacks a required provenance dependency."""


@dataclass(frozen=True)
class SignedClaudeManifest:
    version: str
    manifest_url: str
    signature_url: str
    manifest: bytes
    signature: bytes


@dataclass(frozen=True)
class ClaudeReleaseArtifact:
    version: str
    platform_key: str
    binary: str
    checksum: str
    size: int


@dataclass(frozen=True)
class VerifiedClaudeExecutable:
    executable: pathlib.Path
    artifact: ClaudeReleaseArtifact
    manifest_url: str
    signature_url: str
    gpg_path: pathlib.Path
    source_identity: tuple[int, ...] | None = None


@dataclass(frozen=True)
class _TrustedGpgSource:
    path: pathlib.Path
    descriptor: int
    identity: tuple[int, ...]
    size: int
    checksum: str


@dataclass(frozen=True)
class _TrustedGpgDependency:
    path: pathlib.Path
    identities: tuple[tuple[pathlib.Path, tuple[int, ...]], ...]


@dataclass(frozen=True)
class _TrustedGpgRuntime:
    darwin_dependencies: tuple[_TrustedGpgDependency, ...] = ()
    linux_closure: HostRuntimeClosure | None = None


@dataclass(frozen=True)
class _TrustedGpgTempRoot:
    requested: pathlib.Path
    resolved: pathlib.Path
    identities: tuple[tuple[pathlib.Path, tuple[int, ...]], ...]
    validator: Callable[[tuple[pathlib.Path, ...]], None] | None


ClaudeReleaseFetcher = Callable[..., bytes]


class _DuplicateManifestKey(ValueError):
    pass


class _FetchDeadlineExpired(TimeoutError):
    pass


class _FetchDeadlineCleanupDiagnostic(Exception):
    pass


def _add_deadline_cleanup_note(
    error: BaseException,
    cleanup_error: BaseException,
) -> None:
    note = (
        "Claude Code release deadline cleanup also failed: "
        f"{type(cleanup_error).__name__}: {cleanup_error}"
    )
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(note)
        return
    diagnostic = _FetchDeadlineCleanupDiagnostic(note)
    if error.__cause__ is not None:
        diagnostic.__cause__ = error.__cause__
    elif not error.__suppress_context__ and error.__context__ is not None:
        diagnostic.__context__ = error.__context__
    error.__cause__ = diagnostic


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant {value!r}")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ):
        return None


@contextlib.contextmanager
def _enforce_fetch_deadline(timeout_seconds: float):  # type: ignore[no-untyped-def]
    """Interrupt every synchronous URL-open phase at one absolute deadline."""

    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ClaudeProvenanceInconclusive(
            "Claude Code release download requires a positive finite timeout"
        )
    if threading.current_thread() is not threading.main_thread():
        raise ClaudeProvenanceInconclusive(
            "Claude Code release download cannot enforce its total timeout "
            "outside the main thread"
        )
    try:
        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        blocked_signals = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    except (AttributeError, OSError, ValueError) as error:
        raise ClaudeProvenanceInconclusive(
            "Claude Code release download cannot install its total timeout"
        ) from error
    if signal.SIGALRM in blocked_signals:
        raise ClaudeProvenanceInconclusive(
            "Claude Code release download cannot enforce its total timeout "
            "while SIGALRM is blocked"
        )
    if previous_timer != (0.0, 0.0) or previous_handler not in {
        signal.SIG_DFL,
        signal.SIG_IGN,
    }:
        raise ClaudeProvenanceInconclusive(
            "Claude Code release download cannot replace an existing process timer"
        )

    def expire(_signum, _frame):  # type: ignore[no-untyped-def]
        raise _FetchDeadlineExpired

    handler_restore_required = False
    timer_disarm_required = False
    active_error: BaseException | None = None
    try:
        try:
            handler_restore_required = True
            signal.signal(signal.SIGALRM, expire)
            timer_disarm_required = True
            signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
        except (OSError, ValueError) as error:
            raise ClaudeProvenanceInconclusive(
                "Claude Code release download cannot install its total timeout"
            ) from error
        yield time.monotonic() + timeout_seconds
    except BaseException as error:
        active_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        timer_is_safe = not timer_disarm_required
        if timer_disarm_required:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                timer_is_safe = True
            except BaseException as error:
                cleanup_errors.append(error)
                try:
                    timer_is_safe = signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
                except BaseException as state_error:
                    cleanup_errors.append(state_error)
                    timer_is_safe = False
        if handler_restore_required and timer_is_safe:
            try:
                signal.signal(signal.SIGALRM, previous_handler)
            except BaseException as error:
                cleanup_errors.append(error)
        cleanup_error = next(
            (error for error in cleanup_errors if not isinstance(error, Exception)),
            cleanup_errors[0] if cleanup_errors else None,
        )
        if cleanup_error is not None:
            for error in cleanup_errors:
                if error is not cleanup_error:
                    _add_deadline_cleanup_note(cleanup_error, error)
            if active_error is not None and not isinstance(active_error, Exception):
                _add_deadline_cleanup_note(active_error, cleanup_error)
            elif not isinstance(cleanup_error, Exception):
                if active_error is not None:
                    _add_deadline_cleanup_note(cleanup_error, active_error)
                raise cleanup_error
            else:
                raise ClaudeProvenanceInconclusive(
                    "Claude Code release download cannot safely clear its total timeout"
                ) from cleanup_error


def _decode_strict_json(payload: bytes, *, label: str) -> object:
    try:
        text = payload.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as error:
        raise ClaudeProvenanceInvalid(f"{label} is not UTF-8") from error
    except _DuplicateManifestKey as error:
        raise ClaudeProvenanceInvalid(
            f"{label} contains duplicate key: {error.args[0]!r}"
        ) from error
    except (json.JSONDecodeError, ValueError) as error:
        raise ClaudeProvenanceInvalid(
            f"{label} is invalid JSON: {getattr(error, 'msg', str(error))}"
        ) from error


def require_supported_release_version(version: str) -> tuple[int, int, int]:
    """Validate one stable Claude Code release in the compatible range."""

    try:
        return parse_compatible_release_version(version)
    except ClaudeVersionPolicyError as error:
        raise ClaudeProvenanceInvalid(
            "Claude Code version is outside the supported range "
            f"{CLAUDE_COMPATIBILITY_SPEC}: {version!r}"
        ) from error


def release_artifact_urls(version: str) -> tuple[str, str]:
    require_supported_release_version(version)
    base = f"{CLAUDE_RELEASE_BASE_URL}/{version}"
    return f"{base}/manifest.json", f"{base}/manifest.json.sig"


def _read_response_body_with_deadline(
    response: object,
    *,
    max_bytes: int,
    deadline: float,
) -> bytes:
    payload = bytearray()
    read_chunk = getattr(response, "read1", None)
    if not callable(read_chunk):
        read_chunk = getattr(response, "read")

    while len(payload) <= max_bytes:
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise ClaudeProvenanceInconclusive(
                "Claude Code release download exceeded its total timeout"
            )

        # urllib's timeout applies to each socket operation. Tighten the
        # standard HTTPResponse socket before every bounded read so header
        # latency cannot grant the response body a fresh full timeout.
        response_fp = getattr(response, "fp", None)
        response_raw = getattr(response_fp, "raw", None)
        response_socket = getattr(response_raw, "_sock", None)
        set_socket_timeout = getattr(response_socket, "settimeout", None)
        if callable(set_socket_timeout):
            set_socket_timeout(remaining_seconds)

        chunk = read_chunk(min(CLAUDE_FETCH_CHUNK_BYTES, max_bytes + 1 - len(payload)))
        if time.monotonic() >= deadline:
            raise ClaudeProvenanceInconclusive(
                "Claude Code release download exceeded its total timeout"
            )
        if not chunk:
            break
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise ClaudeProvenanceInconclusive(
                "Claude Code release download returned a non-bytes body chunk"
            )
        payload.extend(chunk)

    return bytes(payload)


def _default_fetcher(
    url: str,
    *,
    max_bytes: int,
    timeout_seconds: float,
) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream, application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "codex-review-workflows/claude-provenance",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with _enforce_fetch_deadline(timeout_seconds) as deadline:
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise _FetchDeadlineExpired
            with opener.open(request, timeout=remaining_seconds) as response:
                final_url = response.geturl()
                if final_url != url:
                    raise ClaudeProvenanceInvalid(
                        "Claude Code release download redirected away from the exact URL"
                    )
                status = getattr(response, "status", 200)
                if status != 200:
                    raise ClaudeProvenanceInconclusive(
                        f"Claude Code release download returned HTTP {status}"
                    )
                content_encoding = response.headers.get("Content-Encoding", "identity")
                if content_encoding.lower() not in {"", "identity"}:
                    raise ClaudeProvenanceInvalid(
                        "Claude Code release download used an unexpected "
                        "content encoding"
                    )
                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        announced_size = int(content_length)
                    except ValueError as error:
                        raise ClaudeProvenanceInvalid(
                            "Claude Code release download has an invalid Content-Length"
                        ) from error
                    if announced_size < 0 or announced_size > max_bytes:
                        raise ClaudeProvenanceInvalid(
                            "Claude Code release download exceeds its byte limit"
                        )
                payload = _read_response_body_with_deadline(
                    response,
                    max_bytes=max_bytes,
                    deadline=deadline,
                )
    except _FetchDeadlineExpired as error:
        raise ClaudeProvenanceInconclusive(
            "Claude Code release download exceeded its total timeout"
        ) from error
    except urllib.error.HTTPError as error:
        if error.code in {404, 410}:
            raise ClaudeProvenanceInvalid(
                f"Claude Code release artifact does not exist: HTTP {error.code}"
            ) from error
        if 300 <= error.code < 400:
            raise ClaudeProvenanceInvalid(
                "Claude Code release download redirected away from the exact URL"
            ) from error
        raise ClaudeProvenanceInconclusive(
            f"cannot fetch Claude Code release artifact: HTTP {error.code}"
        ) from error
    except ClaudeProvenanceError:
        raise
    except urllib.error.URLError as error:
        if isinstance(getattr(error, "reason", None), _FetchDeadlineExpired):
            raise ClaudeProvenanceInconclusive(
                "Claude Code release download exceeded its total timeout"
            ) from error
        raise ClaudeProvenanceInconclusive(
            f"cannot fetch Claude Code release artifact: {error}"
        ) from error
    except (TimeoutError, ssl.SSLError, OSError) as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot fetch Claude Code release artifact: {error}"
        ) from error
    return payload


def _fetch_bounded(
    fetcher: ClaudeReleaseFetcher,
    url: str,
    *,
    max_bytes: int,
    timeout_seconds: float,
    label: str,
) -> bytes:
    try:
        payload = fetcher(
            url,
            max_bytes=max_bytes,
            timeout_seconds=timeout_seconds,
        )
    except ClaudeProvenanceError:
        raise
    except Exception as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot fetch Claude Code {label}: {error}"
        ) from error
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise ClaudeProvenanceInvalid(
            f"Claude Code {label} fetcher returned a non-bytes payload"
        )
    result = bytes(payload)
    if not result:
        raise ClaudeProvenanceInvalid(f"Claude Code {label} is empty")
    if len(result) > max_bytes:
        raise ClaudeProvenanceInvalid(
            f"Claude Code {label} exceeds the {max_bytes}-byte limit"
        )
    return result


def fetch_signed_manifest(
    version: str,
    *,
    fetcher: ClaudeReleaseFetcher | None = None,
    timeout_seconds: float = CLAUDE_FETCH_TIMEOUT_SECONDS,
) -> SignedClaudeManifest:
    """Fetch one exact-version manifest and detached signature with hard limits."""

    manifest_url, signature_url = release_artifact_urls(version)
    selected_fetcher = fetcher or _default_fetcher
    manifest = _fetch_bounded(
        selected_fetcher,
        manifest_url,
        max_bytes=CLAUDE_MANIFEST_MAX_BYTES,
        timeout_seconds=timeout_seconds,
        label="release manifest",
    )
    signature = _fetch_bounded(
        selected_fetcher,
        signature_url,
        max_bytes=CLAUDE_SIGNATURE_MAX_BYTES,
        timeout_seconds=timeout_seconds,
        label="release manifest signature",
    )
    return SignedClaudeManifest(
        version=version,
        manifest_url=manifest_url,
        signature_url=signature_url,
        manifest=manifest,
        signature=signature,
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateManifestKey(key)
        result[key] = value
    return result


def parse_signed_manifest_artifact(
    manifest: bytes,
    *,
    version: str,
    platform_key: str,
) -> ClaudeReleaseArtifact:
    """Parse one already-authenticated manifest entry using strict JSON rules."""

    require_supported_release_version(version)
    expected_binary = CLAUDE_SUPPORTED_PLATFORM_BINARIES.get(platform_key)
    if expected_binary is None:
        raise ClaudeProvenanceInvalid(
            f"unsupported Claude Code release platform: {platform_key!r}"
        )
    value = _decode_strict_json(
        manifest,
        label="Claude Code release manifest",
    )
    if not isinstance(value, dict):
        raise ClaudeProvenanceInvalid(
            "Claude Code release manifest root is not an object"
        )
    manifest_version = value.get("version")
    if manifest_version != version:
        raise ClaudeProvenanceInvalid(
            "Claude Code release manifest version does not match the requested version"
        )
    platforms = value.get("platforms")
    if not isinstance(platforms, dict):
        raise ClaudeProvenanceInvalid(
            "Claude Code release manifest has no valid platforms object"
        )
    entry = platforms.get(platform_key)
    if not isinstance(entry, dict):
        raise ClaudeProvenanceInvalid(
            f"Claude Code release manifest has no {platform_key!r} artifact"
        )
    binary = entry.get("binary")
    if binary != expected_binary:
        raise ClaudeProvenanceInvalid(
            f"Claude Code {platform_key} artifact has unexpected binary name"
        )
    checksum = entry.get("checksum")
    if not isinstance(checksum, str) or _SHA256.fullmatch(checksum) is None:
        raise ClaudeProvenanceInvalid(
            f"Claude Code {platform_key} artifact has an invalid SHA-256 checksum"
        )
    size = entry.get("size")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > CLAUDE_BINARY_MAX_BYTES
    ):
        raise ClaudeProvenanceInvalid(
            f"Claude Code {platform_key} artifact has an invalid size"
        )
    return ClaudeReleaseArtifact(
        version=version,
        platform_key=platform_key,
        binary=binary,
        checksum=checksum,
        size=size,
    )


def _pure_path_is_relative_to(
    path: pathlib.PurePosixPath,
    root: pathlib.PurePosixPath,
) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _darwin_admin_gid() -> int | None:
    if sys.platform != "darwin":
        return None
    try:
        import grp

        return grp.getgrnam("admin").gr_gid
    except (ImportError, KeyError):
        return None


def _darwin_homebrew_path(path: pathlib.Path) -> bool:
    pure = pathlib.PurePosixPath(str(path))
    return any(_pure_path_is_relative_to(pure, root) for root in _DARWIN_HOMEBREW_ROOTS)


def _darwin_homebrew_dependency_path(path: pathlib.Path) -> bool:
    pure = pathlib.PurePosixPath(str(path))
    return any(
        _pure_path_is_relative_to(pure, root)
        for root in _DARWIN_HOMEBREW_DEPENDENCY_ROOTS
    )


def _allows_trusted_gpg_group_write(
    path: pathlib.Path,
    metadata: os.stat_result,
) -> bool:
    admin_gid = _darwin_admin_gid()
    return (
        admin_gid is not None
        and _darwin_homebrew_path(path)
        and metadata.st_uid in {0, os.geteuid()}
        and metadata.st_gid == admin_gid
        and not metadata.st_mode & stat.S_IWOTH
    )


def _gpg_parent_identities(
    path: pathlib.Path,
) -> tuple[tuple[pathlib.Path, tuple[int, ...]], ...] | None:
    identities: list[tuple[pathlib.Path, tuple[int, ...]]] = []
    current = path.parent
    while True:
        metadata = current.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            return None
        if (
            metadata.st_uid not in {0, os.geteuid()}
            or (metadata.st_mode & stat.S_IWOTH)
            or (
                metadata.st_mode & stat.S_IWGRP
                and not _allows_trusted_gpg_group_write(current, metadata)
            )
        ):
            return None
        identities.append((current, _stat_identity(metadata)))
        if current.parent == current:
            return tuple(identities)
        current = current.parent


def _gpg_descriptor_identity(value: os.stat_result) -> tuple[int, ...]:
    """Track FD content metadata while ignoring path-link bookkeeping."""

    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
    )


def _directory_anchor_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


def _critical_path_identity(value: os.stat_result) -> tuple[int, ...]:
    if stat.S_ISDIR(value.st_mode):
        return _directory_anchor_identity(value)
    return _stat_identity(value)


def _trusted_temp_ancestor_metadata(
    path: pathlib.Path,
) -> os.stat_result:
    metadata = path.stat(follow_symlinks=False)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or (
            metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and not (metadata.st_uid == 0 and mode == 0o1777)
        )
    ):
        raise ClaudeProvenanceInvalid(
            "trusted GPG temporary root has an unsafe parent chain"
        )
    return metadata


def _trusted_temp_parent_chain(
    start: pathlib.Path,
) -> tuple[tuple[pathlib.Path, tuple[int, ...]], ...]:
    identities: list[tuple[pathlib.Path, tuple[int, ...]]] = []
    current = start
    while True:
        try:
            metadata = _trusted_temp_ancestor_metadata(current)
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"cannot inspect the trusted GPG temporary parent chain: {error}"
            ) from error
        identities.append((current, _directory_anchor_identity(metadata)))
        if current.parent == current:
            return tuple(identities)
        current = current.parent


def _resolve_trusted_gpg_temp_root(
    candidate: pathlib.Path,
    *,
    validator: Callable[[tuple[pathlib.Path, ...]], None] | None,
) -> _TrustedGpgTempRoot:
    requested = candidate.expanduser().absolute()
    if not candidate.is_absolute():
        raise ClaudeProvenanceInvalid(
            "trusted GPG temporary root must be an absolute path"
        )
    try:
        requested_metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
        resolved_metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot resolve the trusted GPG temporary root: {error}"
        ) from error
    resolved_mode = stat.S_IMODE(resolved_metadata.st_mode)
    is_system_temp = resolved_metadata.st_uid == 0 and resolved_mode == 0o1777
    is_private_temp = (
        resolved_metadata.st_uid == os.geteuid()
        and resolved_mode == 0o700
        and stat.S_ISDIR(requested_metadata.st_mode)
        and requested == resolved
    )
    if not stat.S_ISDIR(resolved_metadata.st_mode) or not (
        is_system_temp or is_private_temp
    ):
        raise ClaudeProvenanceInvalid(
            "trusted GPG temporary root must be a root-owned sticky 1777 "
            "system directory or a current-user 0700 real directory"
        )

    identities: dict[pathlib.Path, tuple[int, ...]] = {
        requested: _critical_path_identity(requested_metadata),
        resolved: _directory_anchor_identity(resolved_metadata),
    }
    for path, identity in (
        *_trusted_temp_parent_chain(requested.parent),
        *_trusted_temp_parent_chain(resolved.parent),
    ):
        identities[path] = identity
    trust = _TrustedGpgTempRoot(
        requested=requested,
        resolved=resolved,
        identities=tuple(identities.items()),
        validator=validator,
    )
    _require_stable_trusted_gpg_temp_root(trust)
    return trust


def _require_stable_trusted_gpg_temp_root(
    trust: _TrustedGpgTempRoot,
) -> None:
    try:
        if trust.requested.resolve(strict=True) != trust.resolved:
            raise ClaudeProvenanceInconclusive(
                "trusted GPG temporary root target changed"
            )
        for path, expected in trust.identities:
            current = path.lstat()
            if _critical_path_identity(current) != expected:
                raise ClaudeProvenanceInconclusive(
                    "trusted GPG temporary root or parent changed"
                )
        if trust.validator is not None:
            trust.validator(tuple(path for path, _identity in trust.identities))
    except ClaudeProvenanceError:
        raise
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"trusted GPG temporary root changed: {error}"
        ) from error
    except Exception as error:
        raise ClaudeProvenanceInconclusive(
            "cannot verify the trusted GPG temporary filesystem provenance"
        ) from error


def _private_gpg_home_identity(
    home: pathlib.Path,
    trust: _TrustedGpgTempRoot,
) -> tuple[int, ...]:
    _require_stable_trusted_gpg_temp_root(trust)
    try:
        metadata = home.stat(follow_symlinks=False)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot inspect the private GPG home: {error}"
        ) from error
    if (
        home.parent != trust.resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ClaudeProvenanceInvalid(
            "private GPG home must be a current-user 0700 directory directly "
            "under the trusted temporary root"
        )
    return _directory_anchor_identity(metadata)


def _require_stable_private_gpg_home(
    home: pathlib.Path,
    expected_identity: tuple[int, ...],
    trust: _TrustedGpgTempRoot,
) -> None:
    if _private_gpg_home_identity(home, trust) != expected_identity:
        raise ClaudeProvenanceInconclusive(
            "private GPG home changed before verifier execution"
        )


def _stable_trusted_gpg_candidate(
    candidate: pathlib.Path,
) -> _TrustedGpgSource | None:
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (OSError, RuntimeError) as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot resolve a trusted GPG candidate: {error}"
        ) from error
    try:
        before = resolved.stat(follow_symlinks=False)
        parent_identities = _gpg_parent_identities(resolved)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot inspect a trusted GPG candidate: {error}"
        ) from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid not in {0, os.geteuid()}
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or before.st_size < 4
        or before.st_size > CLAUDE_GPG_EXECUTABLE_MAX_BYTES
        or not os.access(resolved, os.X_OK)
        or parent_identities is None
    ):
        raise ClaudeProvenanceInvalid(
            "trusted GPG candidate has unsafe filesystem metadata"
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot open a trusted GPG candidate: {error}"
        ) from error
    try:
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode) or _stat_identity(
            opened_before
        ) != _stat_identity(before):
            os.close(descriptor)
            raise ClaudeProvenanceInconclusive(
                "trusted GPG executable or its path changed while opening"
            )
        magic = os.read(descriptor, 4)
        os.lseek(descriptor, 0, os.SEEK_SET)
        checksum, bytes_read = _bounded_descriptor_digest(
            descriptor,
            max_bytes=CLAUDE_GPG_EXECUTABLE_MAX_BYTES,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        opened_after = os.fstat(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise ClaudeProvenanceInconclusive(
            f"cannot inspect a stable trusted GPG executable: {error}"
        ) from error
    try:
        after = resolved.stat(follow_symlinks=False)
        parents_after = _gpg_parent_identities(resolved)
    except OSError as error:
        os.close(descriptor)
        raise ClaudeProvenanceInconclusive(
            f"trusted GPG executable changed during inspection: {error}"
        ) from error
    if (
        len(
            {
                _stat_identity(before),
                _stat_identity(opened_before),
                _stat_identity(opened_after),
                _stat_identity(after),
            }
        )
        != 1
        or parents_after != parent_identities
        or bytes_read != opened_after.st_size
    ):
        os.close(descriptor)
        raise ClaudeProvenanceInconclusive(
            "trusted GPG executable or its path changed during inspection"
        )
    if magic not in _NATIVE_EXECUTABLE_MAGICS:
        os.close(descriptor)
        raise ClaudeProvenanceInvalid(
            "trusted GPG candidate is not a native executable"
        )
    return _TrustedGpgSource(
        path=resolved,
        descriptor=descriptor,
        identity=_gpg_descriptor_identity(opened_after),
        size=opened_after.st_size,
        checksum=checksum,
    )


def _resolve_trusted_gpg_source(
    candidates: Sequence[pathlib.Path],
    *,
    require_root_owner: bool = False,
) -> _TrustedGpgSource:
    invalid_candidates: list[ClaudeProvenanceInvalid] = []
    for candidate in candidates:
        if not candidate.is_absolute():
            invalid_candidates.append(
                ClaudeProvenanceInvalid("trusted GPG candidate path is not absolute")
            )
            continue
        # Group-writable parent directories are intentionally allowed for
        # current-user Homebrew installations. The retained source descriptor,
        # rather than this replaceable path, is the snapshot trust anchor.
        try:
            source = _stable_trusted_gpg_candidate(candidate)
        except ClaudeProvenanceInvalid as error:
            invalid_candidates.append(error)
            continue
        if source is None:
            continue
        try:
            source_owner = os.fstat(source.descriptor).st_uid
        except OSError as error:
            os.close(source.descriptor)
            raise ClaudeProvenanceInconclusive(
                f"cannot revalidate trusted GPG ownership: {error}"
            ) from error
        if not require_root_owner or source_owner == 0:
            return source
        os.close(source.descriptor)
        invalid_candidates.append(
            ClaudeProvenanceInvalid("trusted Linux GPG candidate is not root-owned")
        )
    if invalid_candidates:
        raise ClaudeProvenanceInvalid(
            "no candidate satisfies the trusted native GPG contract"
        ) from invalid_candidates[0]
    raise ClaudeProvenanceDependencyUnavailable(
        "no trusted native GPG executable is available for Claude Code provenance"
    )


def resolve_trusted_gpg(
    candidates: Sequence[pathlib.Path] | None = None,
) -> pathlib.Path:
    """Resolve GPG from fixed paths inside the same-user host trust boundary."""

    selected = candidates
    require_root_owner = False
    if selected is None:
        if sys.platform.startswith("linux"):
            selected = _TRUSTED_LINUX_GPG_CANDIDATES
            require_root_owner = True
        else:
            selected = _TRUSTED_DARWIN_GPG_CANDIDATES
    source = (
        _resolve_trusted_gpg_source(selected, require_root_owner=True)
        if require_root_owner
        else _resolve_trusted_gpg_source(selected)
    )
    try:
        return source.path
    finally:
        os.close(source.descriptor)


def _copy_gpg_snapshot(
    source_descriptor: int,
    destination_descriptor: int,
    *,
    max_bytes: int,
) -> tuple[str, int]:
    try:
        os.lseek(source_descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot rewind the trusted GPG executable descriptor: {error}"
        ) from error
    digest = hashlib.sha256()
    total = 0
    while True:
        remaining = max_bytes - total
        try:
            chunk = os.read(
                source_descriptor,
                min(1024 * 1024, remaining + 1),
            )
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"cannot read the trusted GPG executable descriptor: {error}"
            ) from error
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            break
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            try:
                written = os.write(destination_descriptor, view)
            except OSError as error:
                raise ClaudeProvenanceUnavailable(
                    f"cannot write the private GPG executable snapshot: {error}"
                ) from error
            if written <= 0:
                raise ClaudeProvenanceUnavailable(
                    "short write while creating the private GPG executable snapshot"
                )
            view = view[written:]
    return digest.hexdigest(), total


def _materialize_trusted_gpg_snapshot(
    source: _TrustedGpgSource,
    home: pathlib.Path,
) -> pathlib.Path:
    """Copy a stable GPG source FD into one fresh private execution path."""

    try:
        home_before = home.lstat()
        resolved_home = home.resolve(strict=True)
        home_resolved = resolved_home.stat(follow_symlinks=False)
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot inspect the private GPG snapshot directory: {error}"
        ) from error
    if (
        not stat.S_ISDIR(home_before.st_mode)
        or home_before.st_uid != os.geteuid()
        or stat.S_IMODE(home_before.st_mode) != 0o700
        or _stat_identity(home_before) != _stat_identity(home_resolved)
    ):
        raise ClaudeProvenanceInvalid(
            "private GPG snapshot directory must be a current-user 0700 real directory"
        )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        home_descriptor = os.open(resolved_home, directory_flags)
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot open the private GPG snapshot directory: {error}"
        ) from error

    temporary_name = f".gpg-verifier.{secrets.token_hex(16)}.tmp"
    final_name = "gpg-verifier"
    destination_descriptor = -1
    temporary_exists = False
    final_exists = False
    completed = False
    try:
        try:
            home_opened = os.fstat(home_descriptor)
            source_before = os.fstat(source.descriptor)
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"cannot inspect stable GPG snapshot descriptors: {error}"
            ) from error
        if _stat_identity(home_opened) != _stat_identity(home_before):
            raise ClaudeProvenanceInconclusive(
                "private GPG snapshot directory changed while opening"
            )
        if (
            _gpg_descriptor_identity(source_before) != source.identity
            or not stat.S_ISREG(source_before.st_mode)
            or source_before.st_size != source.size
            or source.size < 4
            or source.size > CLAUDE_GPG_EXECUTABLE_MAX_BYTES
        ):
            raise ClaudeProvenanceInconclusive(
                "trusted GPG executable descriptor changed before snapshotting"
            )
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            destination_descriptor = os.open(
                temporary_name,
                create_flags,
                0o600,
                dir_fd=home_descriptor,
            )
            temporary_exists = True
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot create an exclusive private GPG snapshot: {error}"
            ) from error

        source_digest, source_size = _copy_gpg_snapshot(
            source.descriptor,
            destination_descriptor,
            max_bytes=CLAUDE_GPG_EXECUTABLE_MAX_BYTES,
        )
        try:
            source_after = os.fstat(source.descriptor)
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"cannot recheck the trusted GPG descriptor: {error}"
            ) from error
        if (
            _gpg_descriptor_identity(source_after) != source.identity
            or source_size != source.size
            or source_digest != source.checksum
        ):
            raise ClaudeProvenanceInconclusive(
                "trusted GPG executable descriptor changed while snapshotting"
            )
        try:
            os.fchmod(destination_descriptor, 0o500)
            os.fsync(destination_descriptor)
            destination_before = os.fstat(destination_descriptor)
            os.lseek(destination_descriptor, 0, os.SEEK_SET)
            snapshot_digest, snapshot_size = _bounded_descriptor_digest(
                destination_descriptor,
                max_bytes=CLAUDE_GPG_EXECUTABLE_MAX_BYTES,
            )
            destination_after = os.fstat(destination_descriptor)
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot finalize the private GPG executable snapshot: {error}"
            ) from error
        if (
            len(
                {
                    _stat_identity(destination_before),
                    _stat_identity(destination_after),
                }
            )
            != 1
            or not stat.S_ISREG(destination_after.st_mode)
            or destination_after.st_uid != os.geteuid()
            or stat.S_IMODE(destination_after.st_mode) != 0o500
            or destination_after.st_nlink != 1
            or snapshot_size != source_size
            or snapshot_digest != source_digest
        ):
            raise ClaudeProvenanceInvalid(
                "private GPG executable snapshot does not match its stable source"
            )
        os.close(destination_descriptor)
        destination_descriptor = -1

        try:
            os.link(
                temporary_name,
                final_name,
                src_dir_fd=home_descriptor,
                dst_dir_fd=home_descriptor,
                follow_symlinks=False,
            )
            final_exists = True
            os.unlink(temporary_name, dir_fd=home_descriptor)
            temporary_exists = False
            os.fsync(home_descriptor)
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot atomically publish the private GPG snapshot: {error}"
            ) from error

        verify_flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            verification_descriptor = os.open(
                final_name,
                verify_flags,
                dir_fd=home_descriptor,
            )
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot reopen the private GPG executable snapshot: {error}"
            ) from error
        try:
            published_before = os.fstat(verification_descriptor)
            published_digest, published_size = _bounded_descriptor_digest(
                verification_descriptor,
                max_bytes=CLAUDE_GPG_EXECUTABLE_MAX_BYTES,
            )
            published_after = os.fstat(verification_descriptor)
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"cannot verify the published private GPG snapshot: {error}"
            ) from error
        finally:
            os.close(verification_descriptor)
        try:
            named_after = os.stat(
                final_name,
                dir_fd=home_descriptor,
                follow_symlinks=False,
            )
            home_after = os.fstat(home_descriptor)
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"private GPG snapshot changed after publication: {error}"
            ) from error
        if (
            len(
                {
                    _stat_identity(published_before),
                    _stat_identity(published_after),
                    _stat_identity(named_after),
                }
            )
            != 1
            or published_after.st_uid != os.geteuid()
            or stat.S_IMODE(published_after.st_mode) != 0o500
            or published_after.st_nlink != 1
            or published_size != source.size
            or published_digest != source_digest
            or _snapshot_root_identity(home_after)
            != _snapshot_root_identity(home_before)
        ):
            raise ClaudeProvenanceInvalid(
                "published private GPG executable snapshot is not stable"
            )
        completed = True
        return resolved_home / final_name
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=home_descriptor)
            except OSError:
                pass
        if final_exists and not completed:
            try:
                os.unlink(final_name, dir_fd=home_descriptor)
            except OSError:
                pass
        os.close(home_descriptor)


def _clean_absolute_dependency_path(raw: str) -> pathlib.Path:
    if (
        not raw.startswith("/")
        or raw.endswith("/")
        or "\x00" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise ClaudeProvenanceInvalid(
            f"GPG has an unsafe dynamic dependency path: {raw!r}"
        )
    return pathlib.Path(raw)


def _darwin_sealed_dependency(path: pathlib.Path) -> bool:
    pure = pathlib.PurePosixPath(str(path))
    return any(
        _pure_path_is_relative_to(pure, root) for root in _DARWIN_SEALED_LIBRARY_ROOTS
    )


def _capture_gpg_dependency_chain(
    path: pathlib.Path,
) -> _TrustedGpgDependency:
    if not _darwin_homebrew_dependency_path(path):
        raise ClaudeProvenanceInvalid(
            f"GPG dynamic dependency is outside sealed or Homebrew roots: {path}"
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot resolve GPG dynamic dependency {path}: {error}"
        ) from error
    if not _darwin_homebrew_dependency_path(resolved):
        raise ClaudeProvenanceInvalid(
            f"GPG dynamic dependency escapes the Homebrew prefix: {path}"
        )

    captured: dict[pathlib.Path, tuple[int, ...]] = {}
    for candidate in (path, resolved):
        current = pathlib.Path(candidate.anchor)
        components = candidate.parts[1:]
        for index, part in enumerate(components):
            current /= part
            try:
                metadata = current.lstat()
            except OSError as error:
                raise ClaudeProvenanceInconclusive(
                    f"cannot inspect GPG dynamic dependency {current}: {error}"
                ) from error
            is_final = index == len(components) - 1
            if metadata.st_uid not in {0, os.geteuid()}:
                raise ClaudeProvenanceInvalid(
                    f"GPG dynamic dependency has an untrusted owner: {current}"
                )
            writable_regular_or_directory = not stat.S_ISLNK(metadata.st_mode) and (
                metadata.st_mode & stat.S_IWOTH
                or metadata.st_mode & stat.S_IWGRP
                and (
                    not stat.S_ISDIR(metadata.st_mode)
                    or not _allows_trusted_gpg_group_write(current, metadata)
                )
            )
            if writable_regular_or_directory:
                raise ClaudeProvenanceInvalid(
                    f"GPG dynamic dependency has an untrusted writable path: {current}"
                )
            if is_final:
                if candidate == resolved and not stat.S_ISREG(metadata.st_mode):
                    raise ClaudeProvenanceInvalid(
                        f"GPG dynamic dependency is not a regular file: {current}"
                    )
                if candidate != resolved and not (
                    stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                ):
                    raise ClaudeProvenanceInvalid(
                        f"GPG dynamic dependency is not a file or symlink: {current}"
                    )
            elif not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
                raise ClaudeProvenanceInvalid(
                    f"GPG dynamic dependency parent is not a directory: {current}"
                )
            captured[current] = _stat_identity(metadata)
    dependency = _TrustedGpgDependency(path, tuple(captured.items()))
    _revalidate_gpg_dependency(dependency)
    return dependency


def _revalidate_gpg_dependency(dependency: _TrustedGpgDependency) -> None:
    for path, expected in dependency.identities:
        try:
            current = path.lstat()
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"GPG dynamic dependency changed before execution: {path}: {error}"
            ) from error
        if _stat_identity(current) != expected:
            raise ClaudeProvenanceInconclusive(
                f"GPG dynamic dependency changed before execution: {path}"
            )


def _run_otool(path: pathlib.Path, option: str) -> str:
    if option not in {"-L", "-l"}:
        raise ValueError(f"unsupported otool option: {option}")
    try:
        metadata = TRUSTED_OTOOL.stat(follow_symlinks=False)
    except FileNotFoundError as error:
        raise ClaudeProvenanceDependencyUnavailable(
            f"trusted macOS otool is unavailable: {error}"
        ) from error
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot inspect trusted macOS otool: {error}"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(TRUSTED_OTOOL, os.X_OK)
    ):
        raise ClaudeProvenanceInvalid(
            "trusted macOS otool has unsafe filesystem metadata"
        )
    try:
        result = run_bounded_capture(
            (str(TRUSTED_OTOOL), option, str(path)),
            env={
                "HOME": "/var/empty",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            timeout_seconds=CLAUDE_GPG_TIMEOUT_SECONDS,
            stdout_limit_bytes=CLAUDE_GPG_OUTPUT_MAX_BYTES,
            stderr_limit_bytes=CLAUDE_GPG_OUTPUT_MAX_BYTES,
        )
    except (
        ReviewTimeoutError,
        ReviewOutputLimitError,
        ReviewOutputDrainError,
        ReviewProcessLeakError,
    ) as error:
        raise ClaudeProvenanceInconclusive(
            f"bounded macOS GPG dependency inspection failed: {error}"
        ) from error
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot start bounded macOS GPG dependency inspection: {error}"
        ) from error
    if result.returncode != 0:
        detail = bytes(result.stderr).decode("utf-8", errors="replace").strip()
        raise ClaudeProvenanceInconclusive(
            f"macOS otool could not inspect the GPG runtime: {detail}"
        )
    try:
        return bytes(result.stdout).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ClaudeProvenanceInvalid(
            "macOS otool returned non-UTF-8 GPG dependency metadata"
        ) from error


def _parse_otool_dependencies(
    path: pathlib.Path, output: str
) -> tuple[pathlib.Path, ...]:
    lines = output.splitlines()
    if not lines or lines[0] != f"{path}:":
        raise ClaudeProvenanceInvalid(
            "macOS otool returned malformed GPG dependency metadata"
        )
    dependencies: list[pathlib.Path] = []
    for raw_line in lines[1:]:
        line = raw_line.strip()
        if not line:
            continue
        dependency, marker, _detail = line.rpartition(" (compatibility version ")
        if not marker:
            raise ClaudeProvenanceInvalid(
                "macOS otool returned malformed GPG dependency metadata"
            )
        if dependency.startswith("@"):
            raise ClaudeProvenanceInvalid(
                f"GPG uses an unsupported dyld-relative dependency: {dependency}"
            )
        dependencies.append(_clean_absolute_dependency_path(dependency))
    return tuple(dependencies)


def _parse_otool_load_commands(
    path: pathlib.Path,
    output: str,
) -> tuple[tuple[str, str | None], ...]:
    lines = output.splitlines()
    if not lines or lines[0] != f"{path}:":
        raise ClaudeProvenanceInvalid(
            "macOS otool returned malformed GPG load-command metadata"
        )
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for raw_line in lines[1:]:
        line = raw_line.strip()
        if re.fullmatch(r"Load command [0-9]+", line) is not None:
            if current is not None:
                blocks.append(current)
            current = []
            continue
        if not line:
            continue
        if current is None:
            raise ClaudeProvenanceInvalid(
                "macOS otool returned malformed GPG load-command metadata"
            )
        current.append(line)
    if current is not None:
        blocks.append(current)
    if not blocks:
        raise ClaudeProvenanceInvalid(
            "macOS otool returned no GPG load-command metadata"
        )

    commands: list[tuple[str, str | None]] = []
    for block in blocks:
        command_lines = tuple(
            match.group(1)
            for line in block
            if (match := re.fullmatch(r"cmd ([A-Z0-9_]+)", line)) is not None
        )
        if len(command_lines) != 1:
            raise ClaudeProvenanceInvalid(
                "macOS otool returned malformed GPG load-command metadata"
            )
        command = command_lines[0]
        name: str | None = None
        if command == "LC_LOAD_DYLINKER":
            names = tuple(
                match.group(1)
                for line in block
                if (
                    match := re.fullmatch(
                        r"name (.+) \(offset [0-9]+\)",
                        line,
                    )
                )
                is not None
            )
            if len(names) != 1:
                raise ClaudeProvenanceInvalid(
                    "macOS otool returned malformed GPG dynamic-linker metadata"
                )
            name = names[0]
        commands.append((command, name))
    return tuple(commands)


def _validate_darwin_gpg_load_commands(
    path: pathlib.Path,
    output: str,
    *,
    main_executable: bool,
) -> None:
    commands = _parse_otool_load_commands(path, output)
    if any(
        command in {"LC_RPATH", "LC_DYLD_ENVIRONMENT"} for command, _name in commands
    ):
        raise ClaudeProvenanceInvalid(
            "GPG uses an unsupported mutable dyld search path"
        )
    dynamic_linkers = tuple(
        name for command, name in commands if command == "LC_LOAD_DYLINKER"
    )
    if main_executable:
        if dynamic_linkers != ("/usr/lib/dyld",):
            raise ClaudeProvenanceInvalid(
                "GPG main executable must use exactly one sealed /usr/lib/dyld loader"
            )
    elif dynamic_linkers:
        raise ClaudeProvenanceInvalid(
            "GPG dynamic dependency unexpectedly declares LC_LOAD_DYLINKER"
        )


def _collect_darwin_gpg_dependencies(
    executable: pathlib.Path,
) -> tuple[_TrustedGpgDependency, ...]:
    pending = [executable]
    visited: set[pathlib.Path] = set()
    captured: dict[pathlib.Path, _TrustedGpgDependency] = {}
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        if len(visited) > CLAUDE_GPG_DEPENDENCY_MAX_COUNT:
            raise ClaudeProvenanceInvalid(
                "macOS GPG dynamic dependency closure is too large"
            )
        current_identity = captured.get(current)
        if current != executable and current_identity is None:
            current_identity = _capture_gpg_dependency_chain(current)
            captured[current] = current_identity
        if current_identity is not None:
            _revalidate_gpg_dependency(current_identity)
        _validate_darwin_gpg_load_commands(
            current,
            _run_otool(current, "-l"),
            main_executable=current == executable,
        )
        for dependency in _parse_otool_dependencies(
            current,
            _run_otool(current, "-L"),
        ):
            if _darwin_sealed_dependency(dependency):
                continue
            identity = captured.get(dependency)
            if identity is None:
                identity = _capture_gpg_dependency_chain(dependency)
                captured[dependency] = identity
            _revalidate_gpg_dependency(identity)
            pending.append(dependency)
        if current_identity is not None:
            _revalidate_gpg_dependency(current_identity)
    return tuple(captured[path] for path in sorted(captured, key=str))


def _prepare_trusted_gpg_runtime(executable: pathlib.Path) -> _TrustedGpgRuntime:
    if sys.platform == "darwin":
        return _TrustedGpgRuntime(
            darwin_dependencies=_collect_darwin_gpg_dependencies(executable)
        )
    if sys.platform.startswith("linux"):
        from . import claude_linux

        host = claude_linux.detect_host()
        try:
            closure = claude_linux.collect_host_runtime_closure(
                host,
                executable,
                executable_owner_uids=frozenset({0, os.geteuid()}),
            )
        except claude_linux.LinuxRuntimeInspectionInconclusive as error:
            raise ClaudeProvenanceInconclusive(
                f"cannot inspect the trusted Linux GPG runtime: {error}"
            ) from error
        except claude_linux.LinuxHostDependencyUnavailable as error:
            raise ClaudeProvenanceDependencyUnavailable(
                f"trusted Linux GPG runtime dependency is unavailable: {error}"
            ) from error
        except claude_linux.LinuxRuntimeError as error:
            raise ClaudeProvenanceInvalid(
                f"trusted Linux GPG runtime dependency is unsafe: {error}"
            ) from error
        return _TrustedGpgRuntime(
            linux_closure=closure,
        )
    raise ClaudeProvenanceDependencyUnavailable(
        f"GPG provenance verification is unsupported on {sys.platform}"
    )


def _revalidate_trusted_gpg_runtime(runtime: _TrustedGpgRuntime) -> None:
    for dependency in runtime.darwin_dependencies:
        _revalidate_gpg_dependency(dependency)
    if runtime.linux_closure is not None:
        from . import claude_linux

        try:
            claude_linux.revalidate_host_runtime_closure(runtime.linux_closure)
        except claude_linux.LinuxRuntimeInspectionInconclusive as error:
            raise ClaudeProvenanceInconclusive(
                f"trusted Linux GPG runtime changed before execution: {error}"
            ) from error
        except claude_linux.LinuxRuntimeError as error:
            raise ClaudeProvenanceInvalid(
                f"trusted Linux GPG runtime became unsafe: {error}"
            ) from error


def _run_gpg(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = run_bounded_capture(
            tuple(argv),
            env=dict(env),
            timeout_seconds=timeout_seconds,
            stdout_limit_bytes=CLAUDE_GPG_OUTPUT_MAX_BYTES,
            stderr_limit_bytes=CLAUDE_GPG_OUTPUT_MAX_BYTES,
        )
        return subprocess.CompletedProcess(
            list(argv),
            completed.returncode,
            bytes(completed.stdout),
            bytes(completed.stderr),
        )
    except ReviewTimeoutError as error:
        raise ClaudeProvenanceInconclusive(
            "GPG timed out while verifying Claude Code release provenance"
        ) from error
    except (
        ReviewOutputLimitError,
        ReviewOutputDrainError,
        ReviewProcessLeakError,
    ) as error:
        raise ClaudeProvenanceInconclusive(
            "GPG did not produce bounded, trustworthy provenance output"
        ) from error
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot run trusted GPG executable: {error}"
        ) from error


def _gpg_base_argv(gpg_path: pathlib.Path, home: pathlib.Path) -> list[str]:
    return [
        str(gpg_path),
        "--homedir",
        str(home),
        "--batch",
        "--no-tty",
        "--no-options",
        "--no-auto-key-retrieve",
    ]


def _listed_gpg_fingerprints(output: bytes) -> set[str]:
    fingerprints: set[str] = set()
    for raw_line in output.decode("utf-8", errors="replace").splitlines():
        fields = raw_line.split(":")
        if len(fields) > 9 and fields[0] == "fpr":
            fingerprints.add(fields[9].upper())
    return fingerprints


def _valid_signature_fingerprints(output: bytes) -> list[tuple[str, str | None]]:
    signatures: list[tuple[str, str | None]] = []
    for raw_line in output.decode("utf-8", errors="replace").splitlines():
        marker = "[GNUPG:] VALIDSIG "
        if not raw_line.startswith(marker):
            continue
        fields = raw_line[len(marker) :].split()
        if not fields:
            continue
        signer = fields[0].upper()
        primary = fields[-1].upper() if len(fields) >= 10 else None
        signatures.append((signer, primary))
    return signatures


def verify_manifest_signature(
    bundle: SignedClaudeManifest,
    *,
    temp_root: pathlib.Path,
    temp_root_validator: Callable[[tuple[pathlib.Path, ...]], None] | None = None,
    gpg_candidates: Sequence[pathlib.Path] | None = None,
    timeout_seconds: float = CLAUDE_GPG_TIMEOUT_SECONDS,
) -> pathlib.Path:
    """Verify a detached manifest signature in a fresh, isolated GPG home."""

    trusted_temp_root = _resolve_trusted_gpg_temp_root(
        temp_root,
        validator=temp_root_validator,
    )
    try:
        release_key = CLAUDE_RELEASE_KEY_PATH.read_bytes()
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot read vendored Claude Code release key: {error}"
        ) from error
    with tempfile.TemporaryDirectory(
        prefix="claude-provenance-gpg-",
        dir=trusted_temp_root.resolved,
    ) as raw_home:
        home = pathlib.Path(raw_home)
        home.chmod(0o700)
        home = home.resolve(strict=True)
        _require_stable_trusted_gpg_temp_root(trusted_temp_root)
        selected_gpg_candidates = gpg_candidates
        require_root_owner = False
        if selected_gpg_candidates is None:
            if sys.platform.startswith("linux"):
                selected_gpg_candidates = _TRUSTED_LINUX_GPG_CANDIDATES
                require_root_owner = True
            else:
                selected_gpg_candidates = _TRUSTED_DARWIN_GPG_CANDIDATES
        gpg_source = (
            _resolve_trusted_gpg_source(
                selected_gpg_candidates,
                require_root_owner=True,
            )
            if require_root_owner
            else _resolve_trusted_gpg_source(selected_gpg_candidates)
        )
        try:
            gpg_path = gpg_source.path
            gpg_execution_path = _materialize_trusted_gpg_snapshot(
                gpg_source,
                home,
            )
        finally:
            os.close(gpg_source.descriptor)
        gpg_runtime = _prepare_trusted_gpg_runtime(gpg_execution_path)
        home_identity = _private_gpg_home_identity(home, trusted_temp_root)
        key_path = home / "claude-code-release.asc"
        keyring_path = home / "claude-code-release.gpg"
        manifest_path = home / "manifest.json"
        signature_path = home / "manifest.json.sig"
        for path, payload in (
            (key_path, release_key),
            (manifest_path, bundle.manifest),
            (signature_path, bundle.signature),
        ):
            path.write_bytes(payload)
            path.chmod(0o600)
        env = {
            "GNUPGHOME": str(home),
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        base = _gpg_base_argv(gpg_execution_path, home)
        _require_stable_private_gpg_home(home, home_identity, trusted_temp_root)
        _revalidate_trusted_gpg_runtime(gpg_runtime)
        dearmored = _run_gpg(
            [*base, "--dearmor", "--output", str(keyring_path), str(key_path)],
            env=env,
            timeout_seconds=timeout_seconds,
        )
        if dearmored.returncode != 0:
            raise ClaudeProvenanceInvalid(
                "trusted GPG could not decode the vendored Claude Code release key"
            )
        try:
            keyring_path.chmod(0o600)
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot secure the temporary Claude Code release keyring: {error}"
            ) from error
        release_keyring = [
            *base,
            "--no-default-keyring",
            "--keyring",
            str(keyring_path),
        ]
        _require_stable_private_gpg_home(home, home_identity, trusted_temp_root)
        _revalidate_trusted_gpg_runtime(gpg_runtime)
        listed = _run_gpg(
            [
                *release_keyring,
                "--with-colons",
                "--fingerprint",
                "--fingerprint",
            ],
            env=env,
            timeout_seconds=timeout_seconds,
        )
        if listed.returncode != 0:
            raise ClaudeProvenanceUnavailable(
                "trusted GPG could not inspect the vendored Claude Code release key"
            )
        fingerprints = _listed_gpg_fingerprints(listed.stdout)
        if CLAUDE_RELEASE_KEY_FINGERPRINT not in fingerprints:
            raise ClaudeProvenanceInvalid(
                "vendored Claude Code release key fingerprint does not match the pin"
            )
        _require_stable_private_gpg_home(home, home_identity, trusted_temp_root)
        _revalidate_trusted_gpg_runtime(gpg_runtime)
        verified = _run_gpg(
            [
                *release_keyring,
                "--status-fd=1",
                "--verify",
                str(signature_path),
                str(manifest_path),
            ],
            env=env,
            timeout_seconds=timeout_seconds,
        )
        signatures = _valid_signature_fingerprints(verified.stdout)
        expected_signature = any(
            signer == CLAUDE_RELEASE_KEY_FINGERPRINT
            or primary == CLAUDE_RELEASE_KEY_FINGERPRINT
            for signer, primary in signatures
        )
        if verified.returncode != 0 or not expected_signature:
            raise ClaudeProvenanceInvalid(
                "Claude Code release manifest signature is not valid for the pinned key"
            )
        _require_stable_private_gpg_home(home, home_identity, trusted_temp_root)
    return gpg_path


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require_trusted_release_source_metadata(
    path: pathlib.Path,
    metadata: os.stat_result,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ClaudeProvenanceInvalid(
            f"Claude Code executable is not a regular file: {path}"
        )
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ClaudeProvenanceInvalid(
            f"Claude Code executable has an untrusted owner: {path}"
        )
    if metadata.st_mode & (
        stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    ):
        raise ClaudeProvenanceInvalid(
            f"Claude Code executable has unsafe mode bits: {path}"
        )


def _trusted_release_source_parent_chain(
    path: pathlib.Path,
) -> tuple[tuple[pathlib.Path, tuple[int, ...]], ...]:
    identities: list[tuple[pathlib.Path, tuple[int, ...]]] = []
    current = path.parent
    while True:
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"cannot inspect the Claude Code executable parent chain: {error}"
            ) from error
        mode = stat.S_IMODE(metadata.st_mode)
        root_owned_sticky_temp = metadata.st_uid == 0 and mode == 0o1777
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or (
                metadata.st_mode
                & (
                    stat.S_IWGRP
                    | stat.S_IWOTH
                    | stat.S_ISUID
                    | stat.S_ISGID
                    | stat.S_ISVTX
                )
                and not root_owned_sticky_temp
            )
        ):
            raise ClaudeProvenanceInvalid(
                f"Claude Code executable has an unsafe parent directory: {current}"
            )
        identities.append((current, _directory_anchor_identity(metadata)))
        if current.parent == current:
            return tuple(identities)
        current = current.parent


def _ensure_private_cache_directory(path: pathlib.Path) -> pathlib.Path:
    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot prepare Claude Code provenance cache {path}: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ClaudeProvenanceInvalid(
            f"Claude Code provenance cache path is not a directory: {path}"
        )
    if metadata.st_uid != os.geteuid():
        raise ClaudeProvenanceInvalid(
            f"Claude Code provenance cache directory has an unexpected owner: {path}"
        )
    try:
        path.chmod(0o700)
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot secure Claude Code provenance cache {path}: {error}"
        ) from error
    return path.resolve(strict=True)


def _read_private_cache_file(
    path: pathlib.Path,
    *,
    max_bytes: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ClaudeProvenanceInvalid(
            f"cannot open Claude Code provenance cache file {path}: {error}"
        ) from error
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            before = os.fstat(handle.fileno())
            payload = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot read a stable Claude Code provenance cache file {path}: {error}"
        ) from error
    if _stat_identity(before) != _stat_identity(after):
        raise ClaudeProvenanceInconclusive(
            f"Claude Code provenance cache file changed while being read: {path}"
        )
    if not stat.S_ISREG(before.st_mode):
        raise ClaudeProvenanceInvalid(
            f"Claude Code provenance cache file is not regular: {path}"
        )
    if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600:
        raise ClaudeProvenanceInvalid(
            f"Claude Code provenance cache file is not private: {path}"
        )
    if not payload or len(payload) > max_bytes:
        raise ClaudeProvenanceInvalid(
            f"Claude Code provenance cache file has an invalid size: {path}"
        )
    return payload


def _load_cached_manifest(
    cache_dir: pathlib.Path,
    *,
    version: str,
) -> SignedClaudeManifest | None:
    root = _ensure_private_cache_directory(cache_dir)
    version_dir = root / version
    if not version_dir.exists():
        return None
    version_dir = _ensure_private_cache_directory(version_dir)
    ready_path = version_dir / "ready.json"
    if not ready_path.exists():
        return None
    metadata_payload = _read_private_cache_file(
        ready_path,
        max_bytes=CLAUDE_CACHE_METADATA_MAX_BYTES,
    )
    metadata = _decode_strict_json(
        metadata_payload,
        label="Claude Code provenance cache metadata",
    )
    if not isinstance(metadata, dict):
        raise ClaudeProvenanceInvalid(
            "Claude Code provenance cache metadata root is not an object"
        )
    if metadata.get("schema") != 1 or metadata.get("version") != version:
        raise ClaudeProvenanceInvalid(
            "Claude Code provenance cache metadata does not match the requested release"
        )
    manifest = _read_private_cache_file(
        version_dir / "manifest.json",
        max_bytes=CLAUDE_MANIFEST_MAX_BYTES,
    )
    signature = _read_private_cache_file(
        version_dir / "manifest.json.sig",
        max_bytes=CLAUDE_SIGNATURE_MAX_BYTES,
    )
    expected_manifest_digest = metadata.get("manifest_sha256")
    expected_signature_digest = metadata.get("signature_sha256")
    if (
        not isinstance(expected_manifest_digest, str)
        or _SHA256.fullmatch(expected_manifest_digest) is None
        or not isinstance(expected_signature_digest, str)
        or _SHA256.fullmatch(expected_signature_digest) is None
    ):
        raise ClaudeProvenanceInvalid(
            "Claude Code provenance cache metadata has invalid digests"
        )
    if (
        hashlib.sha256(manifest).hexdigest() != expected_manifest_digest
        or hashlib.sha256(signature).hexdigest() != expected_signature_digest
    ):
        raise ClaudeProvenanceInvalid(
            "Claude Code provenance cache content does not match its metadata"
        )
    manifest_url, signature_url = release_artifact_urls(version)
    return SignedClaudeManifest(
        version=version,
        manifest_url=manifest_url,
        signature_url=signature_url,
        manifest=manifest,
        signature=signature,
    )


def _write_private_cache_file(path: pathlib.Path, payload: bytes) -> None:
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = pathlib.Path(raw_temporary)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot write Claude Code provenance cache file {path}: {error}"
        ) from error
    finally:
        temporary.unlink(missing_ok=True)


def _cache_verified_manifest(
    cache_dir: pathlib.Path,
    bundle: SignedClaudeManifest,
) -> None:
    root = _ensure_private_cache_directory(cache_dir)
    version_dir = _ensure_private_cache_directory(root / bundle.version)
    ready_path = version_dir / "ready.json"
    if ready_path.exists():
        existing = _load_cached_manifest(root, version=bundle.version)
        if existing != bundle:
            raise ClaudeProvenanceInvalid(
                "Claude Code provenance cache already contains different release data"
            )
        return
    _write_private_cache_file(version_dir / "manifest.json", bundle.manifest)
    _write_private_cache_file(version_dir / "manifest.json.sig", bundle.signature)
    metadata = json.dumps(
        {
            "schema": 1,
            "version": bundle.version,
            "manifest_sha256": hashlib.sha256(bundle.manifest).hexdigest(),
            "signature_sha256": hashlib.sha256(bundle.signature).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    _write_private_cache_file(ready_path, metadata)


def _sha256_file_descriptor(handle) -> tuple[str, int]:  # type: ignore[no-untyped-def]
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        digest.update(chunk)
    return digest.hexdigest(), total


def _verify_release_executable_with_identity(
    executable: pathlib.Path,
    artifact: ClaudeReleaseArtifact,
) -> tuple[pathlib.Path, tuple[int, ...]]:
    """Hash a stable executable and return its descriptor-bound identity."""

    try:
        resolved = executable.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot resolve Claude Code executable {executable}: {error}"
        ) from error
    parent_chain_before = _trusted_release_source_parent_chain(resolved)
    try:
        before = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot stat Claude Code executable {resolved}: {error}"
        ) from error
    _require_trusted_release_source_metadata(resolved, before)
    if not os.access(resolved, os.X_OK):
        raise ClaudeProvenanceInvalid(
            f"Claude Code executable is not executable: {resolved}"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"Claude Code executable changed before it could be opened: {error}"
        ) from error
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened_before = os.fstat(handle.fileno())
            try:
                _require_trusted_release_source_metadata(resolved, opened_before)
            except ClaudeProvenanceInvalid as error:
                raise ClaudeProvenanceInconclusive(
                    "Claude Code executable changed while it was opened"
                ) from error
            source_identity = _stat_identity(opened_before)
            if not stat.S_ISREG(
                opened_before.st_mode
            ) or source_identity != _stat_identity(before):
                raise ClaudeProvenanceInconclusive(
                    "Claude Code executable changed while it was opened"
                )
            if opened_before.st_size == artifact.size:
                checksum, bytes_read = _sha256_file_descriptor(handle)
            else:
                checksum, bytes_read = "", 0
            opened_after = os.fstat(handle.fileno())
            try:
                _require_trusted_release_source_metadata(resolved, opened_after)
            except ClaudeProvenanceInvalid as error:
                raise ClaudeProvenanceInconclusive(
                    "Claude Code executable changed while it was hashed"
                ) from error
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot hash a stable Claude Code executable: {error}"
        ) from error
    try:
        after = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"Claude Code executable changed after hashing: {error}"
        ) from error
    try:
        _require_trusted_release_source_metadata(resolved, after)
    except ClaudeProvenanceInvalid as error:
        raise ClaudeProvenanceInconclusive(
            "Claude Code executable changed after hashing"
        ) from error
    parent_chain_after = _trusted_release_source_parent_chain(resolved)
    identities = {
        _stat_identity(before),
        source_identity,
        _stat_identity(opened_after),
        _stat_identity(after),
    }
    if len(identities) != 1:
        raise ClaudeProvenanceInconclusive(
            "Claude Code executable changed while its provenance was verified"
        )
    if parent_chain_before != parent_chain_after:
        raise ClaudeProvenanceInconclusive(
            "Claude Code executable parent chain changed while its provenance "
            "was verified"
        )
    if source_identity[7] != artifact.size:
        raise ClaudeProvenanceInvalid(
            "Claude Code executable size does not match the signed release manifest"
        )
    if bytes_read != artifact.size:
        raise ClaudeProvenanceInconclusive(
            "Claude Code executable size changed while its provenance was verified"
        )
    if checksum != artifact.checksum:
        raise ClaudeProvenanceInvalid(
            "Claude Code executable SHA-256 does not match the signed release manifest"
        )
    return resolved, source_identity


def verify_release_executable(
    executable: pathlib.Path,
    artifact: ClaudeReleaseArtifact,
) -> pathlib.Path:
    """Hash a stable executable and require the signed artifact size and digest."""

    verified_path, _source_identity = _verify_release_executable_with_identity(
        executable,
        artifact,
    )
    return verified_path


def _snapshot_filename(artifact: ClaudeReleaseArtifact) -> str:
    require_supported_release_version(artifact.version)
    expected_binary = CLAUDE_SUPPORTED_PLATFORM_BINARIES.get(artifact.platform_key)
    if expected_binary != artifact.binary:
        raise ClaudeProvenanceInvalid(
            "Claude Code snapshot artifact has an unsupported platform or binary"
        )
    if _SHA256.fullmatch(artifact.checksum) is None:
        raise ClaudeProvenanceInvalid(
            "Claude Code snapshot artifact has an invalid SHA-256 checksum"
        )
    if (
        not isinstance(artifact.size, int)
        or isinstance(artifact.size, bool)
        or artifact.size <= 0
        or artifact.size > CLAUDE_BINARY_MAX_BYTES
    ):
        raise ClaudeProvenanceInvalid(
            "Claude Code snapshot artifact has an invalid signed size"
        )
    return f"claude-{artifact.version}-{artifact.platform_key}-{artifact.checksum}"


def _snapshot_root_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


def _open_private_snapshot_root(
    snapshot_root: pathlib.Path,
) -> tuple[pathlib.Path, int, tuple[int, ...]]:
    root = snapshot_root.expanduser().absolute()
    created = False
    try:
        root.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    except OSError as error:
        raise ClaudeProvenanceUnavailable(
            f"cannot create Claude Code executable snapshot root {root}: {error}"
        ) from error
    if created:
        try:
            root.chmod(0o700)
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot secure Claude Code executable snapshot root {root}: {error}"
            ) from error
    try:
        before = root.lstat()
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot inspect Claude Code executable snapshot root {root}: {error}"
        ) from error
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o700
    ):
        raise ClaudeProvenanceInvalid(
            "Claude Code executable snapshot root must be a current-user "
            f"0700 real directory: {root}"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(root, flags)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot open a stable Claude Code executable snapshot root: {error}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        after = root.lstat()
        resolved = root.resolve(strict=True)
        resolved_metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        os.close(descriptor)
        raise ClaudeProvenanceInconclusive(
            f"Claude Code executable snapshot root changed while opening: {error}"
        ) from error
    identities = {
        _stat_identity(before),
        _stat_identity(opened),
        _stat_identity(after),
        _stat_identity(resolved_metadata),
    }
    if len(identities) != 1:
        os.close(descriptor)
        raise ClaudeProvenanceInconclusive(
            "Claude Code executable snapshot root changed while opening"
        )
    return resolved, descriptor, _snapshot_root_identity(opened)


def _require_stable_snapshot_root(
    root: pathlib.Path,
    expected_identity: tuple[int, ...],
) -> None:
    try:
        current = root.stat(follow_symlinks=False)
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"Claude Code executable snapshot root changed: {error}"
        ) from error
    if _snapshot_root_identity(current) != expected_identity:
        raise ClaudeProvenanceInconclusive(
            "Claude Code executable snapshot root changed during materialization"
        )


def _bounded_descriptor_digest(
    descriptor: int,
    *,
    max_bytes: int,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        remaining = max_bytes - total
        chunk = os.read(descriptor, min(1024 * 1024, remaining + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            break
        digest.update(chunk)
    return digest.hexdigest(), total


def _verify_snapshot_entry(
    root_descriptor: int,
    name: str,
    artifact: ClaudeReleaseArtifact,
) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=root_descriptor)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ClaudeProvenanceInvalid(
            f"cannot safely open reusable Claude Code executable snapshot: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o500
            or before.st_nlink != 1
            or before.st_size != artifact.size
        ):
            raise ClaudeProvenanceInvalid(
                "reusable Claude Code executable snapshot has unsafe metadata"
            )
        checksum, bytes_read = _bounded_descriptor_digest(
            descriptor,
            max_bytes=artifact.size,
        )
        after = os.fstat(descriptor)
    except ClaudeProvenanceError:
        raise
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"cannot verify a stable Claude Code executable snapshot: {error}"
        ) from error
    finally:
        os.close(descriptor)
    try:
        named_after = os.stat(
            name,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            f"Claude Code executable snapshot changed after verification: {error}"
        ) from error
    if (
        len(
            {
                _stat_identity(before),
                _stat_identity(after),
                _stat_identity(named_after),
            }
        )
        != 1
    ):
        raise ClaudeProvenanceInconclusive(
            "Claude Code executable snapshot changed while it was verified"
        )
    if bytes_read != artifact.size or checksum != artifact.checksum:
        raise ClaudeProvenanceInvalid(
            "reusable Claude Code executable snapshot does not match the signed release"
        )
    return True


def _create_exclusive_snapshot_temporary(
    root_descriptor: int,
    final_name: str,
) -> tuple[str, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _ in range(32):
        name = f".{final_name}.{secrets.token_hex(8)}.tmp"
        try:
            return name, os.open(name, flags, 0o600, dir_fd=root_descriptor)
        except FileExistsError:
            continue
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot create Claude Code executable snapshot temporary: {error}"
            ) from error
    raise ClaudeProvenanceUnavailable(
        "cannot allocate an exclusive Claude Code executable snapshot temporary"
    )


def _copy_and_hash_snapshot(
    source_descriptor: int,
    destination_descriptor: int,
    *,
    max_bytes: int,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        remaining = max_bytes - total
        chunk = os.read(source_descriptor, min(1024 * 1024, remaining + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            break
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(destination_descriptor, view)
            if written <= 0:
                raise OSError("short write while materializing Claude Code snapshot")
            view = view[written:]
    return digest.hexdigest(), total


def _require_verified_source_identity(
    source: pathlib.Path,
    expected_identity: tuple[int, ...] | None,
) -> None:
    if expected_identity is None:
        return
    try:
        current_identity = _stat_identity(source.stat(follow_symlinks=False))
    except OSError as error:
        raise ClaudeProvenanceInconclusive(
            "verified Claude Code executable changed after provenance "
            f"verification: {error}"
        ) from error
    if current_identity != expected_identity:
        raise ClaudeProvenanceInconclusive(
            "verified Claude Code executable changed after provenance verification"
        )


def materialize_verified_executable(
    verified: VerifiedClaudeExecutable,
    snapshot_root: pathlib.Path,
) -> VerifiedClaudeExecutable:
    """Copy a verified release into a private, digest-keyed executable snapshot."""

    final_name = _snapshot_filename(verified.artifact)
    source = verified.executable.expanduser()
    if not source.is_absolute():
        raise ClaudeProvenanceInvalid(
            "verified Claude Code executable path must be absolute"
        )
    _require_verified_source_identity(source, verified.source_identity)

    root, root_descriptor, root_identity = _open_private_snapshot_root(snapshot_root)
    temporary_name: str | None = None
    source_descriptor = -1
    destination_descriptor = -1
    try:
        if _verify_snapshot_entry(root_descriptor, final_name, verified.artifact):
            _require_verified_source_identity(source, verified.source_identity)
            _require_stable_snapshot_root(root, root_identity)
            return replace(verified, executable=root / final_name)

        try:
            source_before = source.stat(follow_symlinks=False)
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"verified Claude Code executable changed before snapshotting: {error}"
            ) from error
        source_identity = _stat_identity(source_before)
        if (
            verified.source_identity is not None
            and source_identity != verified.source_identity
        ):
            raise ClaudeProvenanceInconclusive(
                "verified Claude Code executable changed after provenance verification"
            )
        if (
            not stat.S_ISREG(source_before.st_mode)
            or not os.access(source, os.X_OK)
            or source_before.st_size != verified.artifact.size
        ):
            raise ClaudeProvenanceInconclusive(
                "verified Claude Code executable changed before snapshotting"
            )
        source_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            source_descriptor = os.open(source, source_flags)
            source_opened = os.fstat(source_descriptor)
            if (
                not stat.S_ISREG(source_opened.st_mode)
                or _stat_identity(source_opened) != source_identity
            ):
                raise ClaudeProvenanceInconclusive(
                    "verified Claude Code executable changed while opening"
                )
            source_after_open = source.stat(follow_symlinks=False)
        except OSError as error:
            if source_descriptor >= 0:
                os.close(source_descriptor)
                source_descriptor = -1
            raise ClaudeProvenanceInconclusive(
                f"verified Claude Code executable changed while opening: {error}"
            ) from error
        if (
            len(
                {
                    source_identity,
                    _stat_identity(source_opened),
                    _stat_identity(source_after_open),
                }
            )
            != 1
        ):
            raise ClaudeProvenanceInconclusive(
                "verified Claude Code executable changed while opening"
            )

        temporary_name, destination_descriptor = _create_exclusive_snapshot_temporary(
            root_descriptor,
            final_name,
        )
        try:
            checksum, bytes_copied = _copy_and_hash_snapshot(
                source_descriptor,
                destination_descriptor,
                max_bytes=verified.artifact.size,
            )
            source_after_copy = os.fstat(source_descriptor)
            source_named_after = source.stat(follow_symlinks=False)
        except OSError as error:
            raise ClaudeProvenanceInconclusive(
                f"verified Claude Code executable changed while copying: {error}"
            ) from error
        if (
            len(
                {
                    source_identity,
                    _stat_identity(source_after_copy),
                    _stat_identity(source_named_after),
                }
            )
            != 1
        ):
            raise ClaudeProvenanceInconclusive(
                "verified Claude Code executable changed while copying"
            )
        if (
            bytes_copied != verified.artifact.size
            or checksum != verified.artifact.checksum
        ):
            raise ClaudeProvenanceInconclusive(
                "verified Claude Code executable changed after provenance verification"
            )
        try:
            os.fchmod(destination_descriptor, 0o500)
            os.fsync(destination_descriptor)
            destination_metadata = os.fstat(destination_descriptor)
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot finalize Claude Code executable snapshot: {error}"
            ) from error
        if (
            not stat.S_ISREG(destination_metadata.st_mode)
            or destination_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(destination_metadata.st_mode) != 0o500
            or destination_metadata.st_nlink != 1
            or destination_metadata.st_size != verified.artifact.size
        ):
            raise ClaudeProvenanceInvalid(
                "new Claude Code executable snapshot has unsafe metadata"
            )
        os.close(destination_descriptor)
        destination_descriptor = -1

        if _verify_snapshot_entry(root_descriptor, final_name, verified.artifact):
            _require_stable_snapshot_root(root, root_identity)
            return replace(verified, executable=root / final_name)
        try:
            os.replace(
                temporary_name,
                final_name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
            )
            temporary_name = None
            os.fsync(root_descriptor)
        except OSError as error:
            raise ClaudeProvenanceUnavailable(
                f"cannot publish Claude Code executable snapshot: {error}"
            ) from error
        if not _verify_snapshot_entry(root_descriptor, final_name, verified.artifact):
            raise ClaudeProvenanceInconclusive(
                "published Claude Code executable snapshot disappeared"
            )
        _require_stable_snapshot_root(root, root_identity)
        return replace(verified, executable=root / final_name)
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=root_descriptor)
            except OSError:
                pass
        os.close(root_descriptor)


def verify_claude_release(
    executable: pathlib.Path,
    *,
    version: str,
    platform_key: str,
    gpg_temp_root: pathlib.Path,
    gpg_temp_root_validator: Callable[[tuple[pathlib.Path, ...]], None] | None = None,
    fetcher: ClaudeReleaseFetcher | None = None,
    cache_dir: pathlib.Path | None = None,
    gpg_candidates: Sequence[pathlib.Path] | None = None,
    fetch_timeout_seconds: float = CLAUDE_FETCH_TIMEOUT_SECONDS,
    gpg_timeout_seconds: float = CLAUDE_GPG_TIMEOUT_SECONDS,
) -> VerifiedClaudeExecutable:
    """Verify publisher provenance for one selected compatible Claude release."""

    require_supported_release_version(version)
    bundle = (
        _load_cached_manifest(cache_dir, version=version)
        if cache_dir is not None
        else None
    )
    fetched = bundle is None
    if bundle is None:
        bundle = fetch_signed_manifest(
            version,
            fetcher=fetcher,
            timeout_seconds=fetch_timeout_seconds,
        )
    gpg_path = verify_manifest_signature(
        bundle,
        temp_root=gpg_temp_root,
        temp_root_validator=gpg_temp_root_validator,
        gpg_candidates=gpg_candidates,
        timeout_seconds=gpg_timeout_seconds,
    )
    artifact = parse_signed_manifest_artifact(
        bundle.manifest,
        version=version,
        platform_key=platform_key,
    )
    if fetched and cache_dir is not None:
        _cache_verified_manifest(cache_dir, bundle)
    verified_path, source_identity = _verify_release_executable_with_identity(
        executable,
        artifact,
    )
    return VerifiedClaudeExecutable(
        executable=verified_path,
        artifact=artifact,
        manifest_url=bundle.manifest_url,
        signature_url=bundle.signature_url,
        gpg_path=gpg_path,
        source_identity=source_identity,
    )
