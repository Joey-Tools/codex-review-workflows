from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import pathlib
import re
import secrets
import select
import signal
import stat
import sys
import time
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Mapping, Sequence

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
GIT_OUTPUT_LIMIT_BYTES = 32 * 1024 * 1024
SYMLINK_TARGET_LIMIT_BYTES = 16 * 1024
SYMLINK_COUNT_LIMIT = 4_096
SYMLINK_BATCH_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024
SUBMODULE_ACTIVE_PATHSPEC_COUNT_LIMIT = 4_096
SUBMODULE_ACTIVE_PATHSPEC_ARGV_LIMIT_BYTES = 128 * 1024
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


@dataclass(frozen=True)
class WorktreeValidation:
    root: pathlib.Path
    head_sha: str
    symlink_count: int
    guidance_count: int


@dataclass(frozen=True)
class _OutputTarget:
    path: pathlib.Path
    parent_fd: int


@dataclass(frozen=True)
class _PublishedOutput:
    target: _OutputTarget
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
        "PATH": TRUSTED_PATH,
    }
    return environment


def _git_capture(
    root: pathlib.Path,
    arguments: Iterable[str],
    *,
    output_limit_bytes: int = GIT_OUTPUT_LIMIT_BYTES,
    allow_no_match: bool = False,
    neutralize_external_diff: bool = True,
    neutralize_fsmonitor: bool = True,
    stdin: bytearray | None = None,
) -> bytes:
    git = resolve_git()
    safety_config = [
        str(git),
        "--no-pager",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.hooksPath=/dev/null",
    ]
    if neutralize_fsmonitor:
        safety_config.extend(("-c", "core.fsmonitor=false"))
    if neutralize_external_diff:
        safety_config.extend(("-c", "diff.external="))
    safety_config.extend(("-c", "color.ui=false", "-C", str(root)))
    command = (*safety_config, *tuple(arguments))
    capture = run_bounded_capture(
        command,
        env=_git_environment(),
        stdin=stdin,
        timeout_seconds=30.0,
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


def _resolve_worktree_root(worktree: pathlib.Path) -> pathlib.Path:
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
    top_level = os.fsdecode(
        _git_capture(resolved, ("rev-parse", "--show-toplevel"))
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
            if not lower_key.startswith(b"submodule.") or not lower_key.endswith(
                b".path"
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
) -> tuple[tuple[bytes, bytes], ...]:
    if not payload:
        return ()
    if not payload.endswith(b"\0"):
        raise NamedLaneGuardError(f"malformed {label} record")
    records: list[tuple[bytes, bytes]] = []
    for record in payload[:-1].split(b"\0"):
        key, separator, value = record.partition(b"\n")
        if not separator or not key:
            raise NamedLaneGuardError(f"malformed {label} record")
        records.append((key, value))
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
        _git_capture(root, ("ls-tree", "-r", "-z", "--full-tree", frozen_head))
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


@contextlib.contextmanager
def _structured_forwarded_signals() -> Iterable[None]:
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
        yield
    finally:
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
        or (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
        != (lexical_metadata.st_dev, lexical_metadata.st_ino)
    ):
        raise NamedLaneGuardError("Claude output parent changed after validation")


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
    target = _OutputTarget(path=canonical, parent_fd=parent_fd)
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
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow,
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


def _open_private_temporary(target: _OutputTarget) -> tuple[int, str]:
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    for flag_name in ("O_CLOEXEC", "O_NOFOLLOW"):
        open_flags |= getattr(os, flag_name, 0)
    for _attempt in range(16):
        name = f".named-lane-{secrets.token_hex(16)}"
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
    try:
        identity = _output_identity(os.fstat(descriptor))
    except OSError as error:
        os.close(descriptor)
        raise NamedLaneGuardError(
            "Claude output temporary file cannot be inspected safely"
        ) from error
    published: _PublishedOutput | None = None
    try:
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
    prompt: bytes,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    stream_limit_bytes: int = DEFAULT_STREAM_LIMIT_BYTES,
    inherit_node_extra_ca_certs: bool = False,
    deadline_monotonic: float | None = None,
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
    root = _resolve_worktree_root(worktree)
    if not command:
        raise NamedLaneGuardError("Claude command is required")
    executable = pathlib.Path(command[0])
    if not executable.is_absolute():
        raise NamedLaneGuardError("Claude executable path must be absolute")
    try:
        metadata = executable.lstat()
        resolved_executable = executable.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Claude executable is not safely accessible"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved_executable != executable
        or not os.access(executable, os.X_OK)
    ):
        raise NamedLaneGuardError(
            "Claude executable must be an exact absolute executable regular file"
        )
    stdout = _validate_output_path(stdout_path, root)
    try:
        stderr = _validate_output_path(stderr_path, root)
        try:
            if stdout.path == stderr.path:
                raise NamedLaneGuardError("stdout and stderr paths must differ")
            capture = run_bounded_capture(
                command,
                cwd=root,
                env=_claude_environment(inherit_node_extra_ca_certs),
                stdin=bytearray(prompt),
                timeout_seconds=_remaining_deadline_seconds(
                    deadline,
                    "Claude process supervision",
                ),
                stdout_limit_bytes=stream_limit,
                stderr_limit_bytes=stream_limit,
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
                    }
                    deferred_signal = consume_pending_forwarded_signal()
                    if deferred_signal is not None:
                        publication_phase = "interrupted"
                        raise ForwardedSignal(deferred_signal)
                    restore_signal_mask(publication_mask)
                    publication_phase = "committed"
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


def _emit(payload: dict[str, object], *, stream: object = sys.stdout) -> None:
    print(json.dumps(payload, sort_keys=True), file=stream)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command_name == "validate-worktree":
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
        with _structured_forwarded_signals():
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
                prompt=prompt,
                timeout_seconds=_remaining_deadline_seconds(
                    deadline,
                    "Claude named lane",
                ),
                stream_limit_bytes=stream_limit,
                inherit_node_extra_ca_certs=args.inherit_node_extra_ca_certs,
                deadline_monotonic=deadline,
            )
        _emit(result)
        return 0 if result["status"] == "complete" else 1
    except ForwardedSignal as error:
        status = (
            "blocked-safety"
            if args.command_name == "validate-worktree"
            else "inconclusive"
        )
        _emit(
            {"status": status, "reason": "forwarded-signal"},
            stream=sys.stderr,
        )
        return 128 + int(error.signum)
    except ReviewTimeoutError:
        status = (
            "blocked-safety"
            if args.command_name == "validate-worktree"
            else "inconclusive"
        )
        _emit(
            {"status": status, "reason": "deadline"},
            stream=sys.stderr,
        )
        return 2
    except ReviewOutputLimitError:
        status = (
            "blocked-safety"
            if args.command_name == "validate-worktree"
            else "inconclusive"
        )
        _emit(
            {"status": status, "reason": "output-limit"},
            stream=sys.stderr,
        )
        return 2
    except ReviewOutputDrainError:
        status = (
            "blocked-safety"
            if args.command_name == "validate-worktree"
            else "inconclusive"
        )
        _emit(
            {"status": status, "reason": "output-drain"},
            stream=sys.stderr,
        )
        return 2
    except ReviewProcessLeakError:
        status = (
            "blocked-safety"
            if args.command_name == "validate-worktree"
            else "inconclusive"
        )
        _emit(
            {"status": status, "reason": "process-leak"},
            stream=sys.stderr,
        )
        return 2
    except (NamedLaneGuardError, ReviewError, OSError, ValueError) as error:
        status = (
            "blocked-safety"
            if args.command_name == "validate-worktree"
            else "inconclusive"
        )
        _emit(
            {"status": status, "reason": str(error)},
            stream=sys.stderr,
        )
        return 2
