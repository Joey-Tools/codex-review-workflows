from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import select
import signal
import shutil
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterable, Mapping, Sequence

from .common import (
    ForwardedSignal,
    ReviewError,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    TRUSTED_PATH,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    forwarded_signals,
    is_relative_to,
    resolve_git,
    restore_signal_mask,
    run_bounded_capture,
)


DEFAULT_TIMEOUT_SECONDS = 1_800.0
DEFAULT_STREAM_LIMIT_BYTES = 64 * 1024 * 1024
DEFAULT_PROMPT_LIMIT_BYTES = 256 * 1024
CLAUDE_PREFLIGHT_EVIDENCE_LIMIT_BYTES = 16 * 1024
CLAUDE_BINARY_LIMIT_BYTES = 1024 * 1024 * 1024
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
MATERIALIZER_LOGICAL_OBJECT_BYTES_LIMIT = 2 * 1024 * 1024 * 1024
MATERIALIZER_CHECKOUT_ENTRY_COUNT_LIMIT = 100_000
MATERIALIZER_CHECKOUT_BLOB_BYTES_LIMIT = 2 * 1024 * 1024 * 1024
MATERIALIZER_CHECKOUT_PATH_BYTES_LIMIT = 64 * 1024 * 1024
MATERIALIZER_PACK_BYTES_LIMIT = 256 * 1024 * 1024
MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES = 1024 * 1024
FULL_OBJECT_ID = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
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
            "Claude launch snapshot cleanup failed after "
            f"{process_reason}; {detail}"
        )


def _checkout_tree_output_limit(oid_length: int) -> int:
    return MATERIALIZER_CHECKOUT_PATH_BYTES_LIMIT + (
        MATERIALIZER_CHECKOUT_ENTRY_COUNT_LIMIT * (oid_length + 16)
    )


@dataclass(frozen=True)
class WorktreeValidation:
    root: pathlib.Path
    head_sha: str
    symlink_count: int
    guidance_count: int


@dataclass(frozen=True)
class MaterializedWorktree:
    root: pathlib.Path
    base_sha: str
    head_sha: str
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
    identity: Mapping[str, int]
    artifact_size: int
    artifact_checksum: str
    preflight_checksum: str


@dataclass(frozen=True)
class _ClaudeLaunchSnapshot:
    path: pathlib.Path
    name: str
    identity: tuple[int, int]


def _git_environment() -> dict[str, str]:
    environment = {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
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
        "core.fileMode=true",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.multiPackIndex=false",
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
) -> None:
    capture = run_bounded_capture(
        (str(git), "--version"),
        cwd=cwd,
        env=dict(environment),
        timeout_seconds=30.0,
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
        f"core.attributesFile={os.devnull}",
        "-c",
        f"core.excludesFile={os.devnull}",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={hooks}",
        "-c",
        "core.multiPackIndex=false",
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


def _audit_materialized_local_config(
    root: pathlib.Path,
    oid_length: int,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> None:
    payload = _materializer_git_capture(
        git,
        environment,
        hooks,
        (
            "config",
            "--file",
            str(root / ".git" / "config"),
            "--no-includes",
            "--null",
            "--list",
        ),
    )
    records = _parse_git_config_records(
        payload,
        label="materialized direct local Git config",
    )
    configured_keys = frozenset(key for key, _value in records)
    _validate_git_config_includes(configured_keys)

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


def _materializer_source_object_format(
    common: pathlib.Path,
    oid_length: int,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
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
        parsed = _materializer_git_capture(
            git,
            environment,
            hooks,
            ("config", "--file", "-", "--no-includes", "--null", "--list"),
            stdin=config_payload,
        )
    finally:
        config_payload[:] = b"\x00" * len(config_payload)
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


def _validate_materialized_admin_directory(root: pathlib.Path) -> pathlib.Path:
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
    except OSError as error:
        raise NamedLaneGuardError(
            "materialized Git config is not a private regular file"
        ) from error
    if (
        not stat.S_ISREG(config_metadata.st_mode)
        or stat.S_ISLNK(config_metadata.st_mode)
        or config_metadata.st_uid != _current_user_id()
    ):
        raise NamedLaneGuardError(
            "materialized Git config is not a private regular file"
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


def _validate_materialized_object_storage(
    git_directory: pathlib.Path,
    *,
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

    for candidate, label in (
        (git_directory / "shallow", "shallow repository state"),
        (git_directory / "info" / "sparse-checkout", "sparse checkout state"),
    ):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise NamedLaneGuardError(
                f"materialized Git {label} cannot be inspected"
            ) from error
        raise NamedLaneGuardError(f"materialized Git {label} is not allowed")

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


def _materializer_reachable_manifest(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
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


def _materializer_pack_manifest(
    root: pathlib.Path,
    manifest: bytearray,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> bytearray:
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
    transferred = False
    try:
        if capture.returncode != 0:
            raise NamedLaneGuardError("bounded materializer Git pack-objects failed")
        transferred = True
        return capture.stdout
    finally:
        capture.stderr[:] = b"\x00" * len(capture.stderr)
        if not transferred:
            capture.stdout[:] = b"\x00" * len(capture.stdout)


def _materializer_import_reachable_objects(
    root: pathlib.Path,
    base_sha: str,
    head_sha: str,
    storage: _MaterializerSourceStorage,
    git: pathlib.Path,
    environment: Mapping[str, str],
    hooks: pathlib.Path,
) -> frozenset[bytes]:
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
    manifest, metadata = _materializer_reachable_manifest(
        root,
        base_sha,
        head_sha,
        git,
        alternate_environment,
        hooks,
    )
    pack_payload: bytearray | None = None
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
        pack_payload = _materializer_pack_manifest(
            root,
            manifest,
            git,
            alternate_environment,
            hooks,
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
        return frozenset(metadata)
    finally:
        manifest[:] = b"\x00" * len(manifest)
        if pack_payload is not None:
            pack_payload[:] = b"\x00" * len(pack_payload)


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
        _audit_materialized_local_config(
            destination,
            len(frozen_head),
            git,
            environment,
            directories["hooks"],
        )
        _validate_materialized_object_storage(git_directory)
        imported_objects = _materializer_import_reachable_objects(
            destination,
            frozen_base,
            frozen_head,
            source_storage,
            git,
            environment,
            directories["hooks"],
        )
        _validate_materialized_object_storage(git_directory)
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
        )
        _validate_materialized_object_storage(git_directory)
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
        _validate_materialized_object_storage(git_directory)
        result = MaterializedWorktree(
            root=destination,
            base_sha=frozen_base,
            head_sha=frozen_head,
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


def _resolve_worktree_root(
    worktree: pathlib.Path,
    *,
    deadline_monotonic: float | None = None,
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


def _effective_git_config_keys(root: pathlib.Path) -> frozenset[bytes]:
    return frozenset(
        key
        for key in _git_capture(
            root,
            ("config", "--no-includes", "--null", "--name-only", "--list"),
            neutralize_external_diff=False,
            neutralize_fsmonitor=False,
        ).split(b"\0")
        if key
    )


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
    root: pathlib.Path,
    configured_keys: frozenset[bytes],
) -> None:
    if not any(key.lower() == b"core.fsmonitor" for key in configured_keys):
        return
    message = "effective core.fsmonitor must be disabled before reviewer launch"
    raw_output = _git_capture(
        root,
        ("config", "--no-includes", "--null", "--get", "core.fsmonitor"),
        neutralize_fsmonitor=False,
    )
    if not raw_output.endswith(b"\0") or b"\0" in raw_output[:-1]:
        raise NamedLaneGuardError(message)
    raw_value = os.fsdecode(raw_output[:-1])
    try:
        effective = _git_capture(
            root,
            (
                "config",
                "--no-includes",
                "--null",
                "--type=bool",
                "--fixed-value",
                "--get",
                "core.fsmonitor",
                raw_value,
            ),
            neutralize_fsmonitor=False,
        )
    except NamedLaneGuardError as error:
        raise NamedLaneGuardError(message) from error
    if effective != b"false\0":
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


def validate_worktree(
    worktree: pathlib.Path,
    head_sha: str,
    guidance_paths: Sequence[str] = (),
) -> WorktreeValidation:
    if FULL_OBJECT_ID.fullmatch(head_sha) is None:
        raise NamedLaneGuardError("frozen head must be a full Git object ID")
    root = _resolve_worktree_root(worktree)
    actual_head = os.fsdecode(
        _git_capture(root, ("rev-parse", "--verify", "HEAD^{commit}"))
    ).strip()
    frozen_head = os.fsdecode(
        _git_capture(root, ("rev-parse", "--verify", f"{head_sha}^{{commit}}"))
    ).strip()
    if not actual_head or actual_head != frozen_head:
        raise NamedLaneGuardError("worktree HEAD does not match the frozen head")
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
    configured_keys = _effective_git_config_keys(root)
    _validate_git_config_includes(configured_keys)
    _validate_core_fsmonitor_config(root, configured_keys)
    _validate_executable_git_config(configured_keys)
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
    return WorktreeValidation(
        root=root,
        head_sha=frozen_head,
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
    committed: bool = False

    def commit(self) -> None:
        self.committed = True


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
        cleanup_mask = block_forwarded_signals()
        pending_cleanup_signal: signal.Signals | None = None
        if state.committed:
            if cleanup_mask is not None:
                consume_pending_forwarded_signal()
            restore_signal_mask(
                cleanup_mask if initial_mask_restored else previous_mask
            )
            for forwarded, previous in previous_handlers.items():
                signal.signal(forwarded, previous)
        else:
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
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | nofollow
            | nonblocking,
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
    try:
        import pwd

        account = pwd.getpwuid(os.getuid())
    except (ImportError, KeyError, OSError) as error:
        raise NamedLaneGuardError(
            "current POSIX account cannot be resolved safely"
        ) from error
    environment = {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CEILING_DIRECTORIES": str(worktree.parent),
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
                raise control_error.with_traceback(control_error.__traceback__) from error
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
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    command: Sequence[str],
    preflight_result: pathlib.Path,
    prompt: bytes,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    stream_limit_bytes: int = DEFAULT_STREAM_LIMIT_BYTES,
    inherit_node_extra_ca_certs: bool = False,
    deadline_monotonic: float | None = None,
    _receipt_emitter: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
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
    executable = pathlib.Path(command[0])
    if not executable.is_absolute():
        raise NamedLaneGuardError("Claude executable path must be absolute")
    binding = _load_claude_executable_binding(
        preflight_result,
        worktree=root,
        command_path=executable,
    )
    stdout = _validate_output_path(stdout_path, root)
    try:
        stderr = _validate_output_path(stderr_path, root)
        try:
            if stdout.path == stderr.path:
                raise NamedLaneGuardError("stdout and stderr paths must differ")
            snapshot_mask = block_forwarded_signals()
            if snapshot_mask is None:
                raise NamedLaneGuardError(
                    "Claude launch snapshot lifecycle requires main-thread signal masking"
                )
            snapshot: _ClaudeLaunchSnapshot | None = None
            capture = None
            process_error: BaseException | None = None
            try:
                snapshot = _create_claude_launch_snapshot(
                    binding,
                    stdout,
                    deadline_monotonic=deadline,
                )
                snapshot_command = (str(snapshot.path), *tuple(command[1:]))
                restore_signal_mask(snapshot_mask)
                try:
                    capture = run_bounded_capture(
                        snapshot_command,
                        cwd=root,
                        env=_claude_environment(root, inherit_node_extra_ca_certs),
                        stdin=bytearray(prompt),
                        timeout_seconds=_remaining_deadline_seconds(
                            deadline,
                            "Claude process supervision",
                        ),
                        stdout_limit_bytes=stream_limit,
                        stderr_limit_bytes=stream_limit,
                    )
                except BaseException as error:
                    process_error = error
            finally:
                lifecycle_error = (
                    process_error if process_error is not None else sys.exc_info()[1]
                )
                cleanup_error: BaseException | None = None
                if snapshot is not None:
                    try:
                        if block_forwarded_signals() is None:
                            raise NamedLaneGuardError(
                                "Claude launch snapshot cleanup requires main-thread "
                                "signal masking"
                            )
                        _cleanup_claude_launch_snapshot(snapshot, stdout)
                    except BaseException as error:
                        cleanup_error = error
                    deferred_signal: signal.Signals | None = None
                    mask_restore_error: BaseException | None = None
                    try:
                        deferred_signal = _restore_claude_snapshot_signal_mask(
                            snapshot_mask
                        )
                    except BaseException as error:
                        mask_restore_error = error
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
                    deferred_signal = _restore_claude_snapshot_signal_mask(snapshot_mask)
                    if deferred_signal is not None:
                        raise ForwardedSignal(deferred_signal)
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
                    result = {
                        "status": ("complete" if capture.returncode == 0 else "failed"),
                        "returncode": capture.returncode,
                        "stdout_path": str(stdout.path),
                        "stdout_bytes": len(capture.stdout),
                        "stderr_path": str(stderr.path),
                        "stderr_bytes": len(capture.stderr),
                        "launch_binding": {
                            "mode": "verified-snapshot",
                            "preflight_sha256": binding.preflight_checksum,
                            "resolved_path": str(binding.source_path),
                            "identity": dict(_expected_executable_identity(binding)),
                            "artifact_sha256": binding.artifact_checksum,
                            "artifact_size": binding.artifact_size,
                        },
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

    materialize = subparsers.add_parser(
        "materialize-worktree",
        help="Create a private repository from a bounded frozen object closure.",
    )
    materialize.add_argument("--source", required=True)
    materialize.add_argument("--worktree", required=True)
    materialize.add_argument("--base", required=True)
    materialize.add_argument("--head", required=True)

    validate = subparsers.add_parser(
        "validate-worktree",
        help="Validate tracked symlink containment for a frozen named-lane worktree.",
    )
    validate.add_argument("--worktree", required=True)
    validate.add_argument("--head", required=True)
    validate.add_argument("--guidance", action="append", default=[])

    claude = subparsers.add_parser(
        "run-claude",
        help="Run an exact Claude executable under bounded process supervision.",
    )
    claude.add_argument("--worktree", required=True)
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
    claude.add_argument("claude_argv", nargs=argparse.REMAINDER)
    return parser


def _emit(payload: dict[str, object], *, stream: object | None = None) -> None:
    if stream is None:
        stream = sys.stdout
    print(json.dumps(payload, sort_keys=True), file=stream)


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
) -> None:
    terminal_mask, _deferred_signal = _block_materializer_cleanup_signals()
    if terminal_mask is None:
        raise NamedLaneGuardError(
            "terminal failure publication requires main-thread signal masking"
        )
    _emit(payload, stream=sys.stderr)
    sys.stderr.flush()
    _install_post_terminal_signal_handlers()
    consume_pending_forwarded_signal()
    signal_state.commit()
    restore_signal_mask(terminal_mask)


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
        reason = str(error)
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    safety_command = args.command_name in {
        "materialize-worktree",
        "validate-worktree",
    }
    try:
        if args.command_name == "materialize-worktree":
            with _structured_forwarded_signals() as signal_state:
                try:
                    result = materialize_worktree(
                        pathlib.Path(args.source),
                        pathlib.Path(args.worktree),
                        args.base,
                        args.head,
                        defer_signal_handoff=True,
                    )
                    _emit_materialized_receipt(result)
                except (
                    ForwardedSignal,
                    ReviewTimeoutError,
                    ReviewOutputLimitError,
                    ReviewOutputDrainError,
                    ReviewProcessLeakError,
                    NamedLaneGuardError,
                    ReviewError,
                    OSError,
                    ValueError,
                ) as error:
                    returncode, payload = _materializer_failure_payload(error)
                    _emit_structured_terminal_failure(payload, signal_state)
                    return returncode
                signal_state.commit()
                return 0

        if args.command_name == "validate-worktree":
            with _structured_forwarded_signals():
                result = validate_worktree(
                    pathlib.Path(args.worktree),
                    args.head,
                    args.guidance,
                )
                _emit(
                    {
                        "status": "ok",
                        "head": result.head_sha,
                        "symlink_count": result.symlink_count,
                        "guidance_count": result.guidance_count,
                    }
                )
            return 0

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
                stdout_path=pathlib.Path(args.stdout_path),
                stderr_path=pathlib.Path(args.stderr_path),
                command=command,
                preflight_result=pathlib.Path(args.preflight_result),
                prompt=prompt,
                timeout_seconds=_remaining_deadline_seconds(
                    deadline,
                    "Claude named lane",
                ),
                stream_limit_bytes=stream_limit,
                inherit_node_extra_ca_certs=args.inherit_node_extra_ca_certs,
                deadline_monotonic=deadline,
                _receipt_emitter=_emit_claude_receipt,
            )
            signal_state.commit()
            return 0 if result["status"] == "complete" else 1
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
            {"status": status, "reason": str(error)},
            stream=sys.stderr,
        )
        return 2
