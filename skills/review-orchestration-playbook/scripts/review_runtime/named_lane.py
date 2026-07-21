from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from typing import Iterable, Sequence

from .common import (
    ForwardedSignal,
    ReviewError,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    TRUSTED_PATH,
    is_relative_to,
    resolve_git,
    run_bounded_capture,
)


DEFAULT_TIMEOUT_SECONDS = 1_800.0
DEFAULT_STREAM_LIMIT_BYTES = 64 * 1024 * 1024
DEFAULT_PROMPT_LIMIT_BYTES = 256 * 1024
GIT_OUTPUT_LIMIT_BYTES = 32 * 1024 * 1024
SYMLINK_TARGET_LIMIT_BYTES = 16 * 1024
FULL_OBJECT_ID = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")


class NamedLaneGuardError(ReviewError):
    """A named-lane safety or invocation precondition failed."""


@dataclass(frozen=True)
class WorktreeValidation:
    root: pathlib.Path
    head_sha: str
    symlink_count: int
    guidance_count: int


def _git_environment() -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
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
) -> bytes:
    git = resolve_git()
    command = (
        str(git),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "diff.external=",
        "-c",
        "color.ui=false",
        "-C",
        str(root),
        *tuple(arguments),
    )
    capture = run_bounded_capture(
        command,
        env=_git_environment(),
        timeout_seconds=30.0,
        stdout_limit_bytes=output_limit_bytes,
        stderr_limit_bytes=1024 * 1024,
    )
    try:
        if capture.returncode != 0:
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
    if resolved != lexical:
        raise NamedLaneGuardError("worktree path must not traverse a symlink")
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


def _read_symlink_blob(root: pathlib.Path, object_id: str) -> str:
    payload = _git_capture(
        root,
        ("cat-file", "blob", object_id),
        output_limit_bytes=SYMLINK_TARGET_LIMIT_BYTES + 1,
    )
    if len(payload) > SYMLINK_TARGET_LIMIT_BYTES or b"\0" in payload:
        raise NamedLaneGuardError("frozen Git symlink target is invalid")
    return os.fsdecode(payload)


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
    if _git_capture(
        root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
    ):
        raise NamedLaneGuardError("worktree must be clean before reviewer launch")
    tree = _parse_tree(
        _git_capture(root, ("ls-tree", "-r", "-z", "--full-tree", frozen_head))
    )
    symlinks = [path for path, entry in tree.items() if entry[0] == "120000"]
    for path in symlinks:
        mode, object_type, object_id = tree[path]
        if mode != "120000" or object_type != "blob":
            raise NamedLaneGuardError("frozen Git symlink entry has an invalid type")
        _validate_materialized_symlink(
            root,
            path,
            _read_symlink_blob(root, object_id),
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


def _validate_output_path(path: pathlib.Path, worktree: pathlib.Path) -> pathlib.Path:
    if not path.is_absolute():
        raise NamedLaneGuardError("output paths must be absolute")
    resolved = path.resolve(strict=False)
    if is_relative_to(resolved, worktree):
        raise NamedLaneGuardError("Claude output paths must stay outside the worktree")
    parent = resolved.parent
    try:
        parent_metadata = parent.lstat()
        parent_resolved = parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NamedLaneGuardError(
            "Claude output parent is not safely accessible"
        ) from error
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(
        parent_metadata.st_mode
    ):
        raise NamedLaneGuardError("Claude output parent must be a real directory")
    if parent_resolved != parent:
        raise NamedLaneGuardError("Claude output parent must not traverse a symlink")
    if resolved.exists() or resolved.is_symlink():
        raise NamedLaneGuardError("Claude output path must not already exist")
    return resolved


def _write_private_bytes(path: pathlib.Path, payload: bytes | bytearray) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise NamedLaneGuardError(
                "Claude output path appeared during write"
            ) from error
    finally:
        temporary.unlink(missing_ok=True)


def run_claude(
    *,
    worktree: pathlib.Path,
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    command: Sequence[str],
    prompt: bytes,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    stream_limit_bytes: int = DEFAULT_STREAM_LIMIT_BYTES,
) -> dict[str, object]:
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
    timeout = _validate_positive_finite(float(timeout_seconds), "timeout")
    if stream_limit_bytes <= 0:
        raise NamedLaneGuardError("stream limit must be positive")
    stdout = _validate_output_path(stdout_path, root)
    stderr = _validate_output_path(stderr_path, root)
    if stdout == stderr:
        raise NamedLaneGuardError("stdout and stderr paths must differ")
    capture = run_bounded_capture(
        command,
        cwd=root,
        env=dict(os.environ),
        stdin=bytearray(prompt),
        timeout_seconds=timeout,
        stdout_limit_bytes=stream_limit_bytes,
        stderr_limit_bytes=stream_limit_bytes,
    )
    try:
        stdout_written = False
        try:
            _write_private_bytes(stdout, capture.stdout)
            stdout_written = True
            _write_private_bytes(stderr, capture.stderr)
        except Exception:
            if stdout_written:
                stdout.unlink(missing_ok=True)
            raise
        return {
            "status": "complete" if capture.returncode == 0 else "failed",
            "returncode": capture.returncode,
            "stdout_path": str(stdout),
            "stdout_bytes": len(capture.stdout),
            "stderr_path": str(stderr),
            "stderr_bytes": len(capture.stderr),
        }
    finally:
        capture.stdout[:] = b"\x00" * len(capture.stdout)
        capture.stderr[:] = b"\x00" * len(capture.stderr)


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
        if args.prompt_limit_bytes <= 0:
            raise NamedLaneGuardError("prompt limit must be positive")
        prompt = sys.stdin.buffer.read(args.prompt_limit_bytes + 1)
        if len(prompt) > args.prompt_limit_bytes:
            raise NamedLaneGuardError(
                "Claude control prompt exceeded its bounded limit"
            )
        result = run_claude(
            worktree=pathlib.Path(args.worktree),
            stdout_path=pathlib.Path(args.stdout_path),
            stderr_path=pathlib.Path(args.stderr_path),
            command=command,
            prompt=prompt,
            timeout_seconds=args.timeout_seconds,
            stream_limit_bytes=args.stream_limit_bytes,
        )
        _emit(result)
        return 0 if result["status"] == "complete" else 1
    except ForwardedSignal as error:
        _emit(
            {"status": "inconclusive", "reason": "forwarded-signal"},
            stream=sys.stderr,
        )
        return 128 + int(error.signum)
    except ReviewTimeoutError:
        _emit(
            {"status": "inconclusive", "reason": "deadline"},
            stream=sys.stderr,
        )
        return 2
    except ReviewOutputLimitError:
        _emit(
            {"status": "inconclusive", "reason": "output-limit"},
            stream=sys.stderr,
        )
        return 2
    except ReviewOutputDrainError:
        _emit(
            {"status": "inconclusive", "reason": "output-drain"},
            stream=sys.stderr,
        )
        return 2
    except ReviewProcessLeakError:
        _emit(
            {"status": "inconclusive", "reason": "process-leak"},
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
