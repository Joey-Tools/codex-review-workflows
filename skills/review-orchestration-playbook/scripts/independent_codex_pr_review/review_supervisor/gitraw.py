from __future__ import annotations

import errno
import hashlib
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator

from .constants import (
    MAX_BLOB_BYTES,
    MAX_RANGE_METADATA_AGGREGATE_BYTES,
    MAX_RANGE_METADATA_LIST_BYTES,
    MAX_RANGE_METADATA_OBJECT_BYTES,
    MAX_RANGE_METADATA_OBJECTS,
    MAX_RAW_BLOB_BYTES,
    MAX_SYMLINK_BYTES,
    MAX_TREE_ENTRIES,
    MAX_TREE_METADATA_BYTES,
    RANGE_METADATA_VERIFY_SECONDS,
    REGISTRATION_DESCENDANT_COUNT_CAP,
    REGISTRATION_PATH_BYTES_CAP,
)
from .errors import blocked, inconclusive
from .models import Identity, TreeEntry, TreeManifest
from .process import (
    SpawnedProcess,
    anchored_group_members,
    process_group_members,
    process_start_identity,
    signal_anchored_group,
    terminal_status,
    wait_terminal,
)
from .secureio import (
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    open_directory,
    open_regular_at,
    open_regular_nofollow,
    publish_bytes,
    raw_directory_entries,
    read_fd_exact,
    validate_private_directory_fd,
)
from .signal_relay import (
    DeferredSignalScope,
    begin_bound_signal_deferral,
    checkpoint_bound_signal_interrupt,
)


CAT_FILE_CLOSE_TIMEOUT_SECONDS = 5.0
CAT_FILE_READ_TIMEOUT_SECONDS = 30.0
CAT_FILE_STDERR_LIMIT_BYTES = 8192
PROCESS_GROUP_TERMINATE_GRACE_SECONDS = 0.1
PROCESS_GROUP_CLEANUP_TIMEOUT_SECONDS = 2.0
PROCESS_GROUP_EMPTY_CONFIRMATIONS = 2
LOCAL_CONFIG_BYTES_LIMIT = 1024 * 1024
GITDIR_POINTER_BYTES_LIMIT = 64 * 1024
_CONFIG_SECTION_PATTERN = re.compile(rb"^\[\s*([A-Za-z0-9][A-Za-z0-9-]*)")
_CONFIG_KEY_PATTERN = re.compile(rb"^([A-Za-z][A-Za-z0-9-]*)")


class GitProcessClosureUnproven(RuntimeError):
    def __init__(
        self,
        process: subprocess.Popen[bytes] | None,
        group_anchor: SpawnedProcess | None,
        cleanup_error: BaseException,
    ) -> None:
        if process is None and group_anchor is not None:
            raise ValueError("a Git process-group anchor requires a process")
        self.process = process
        self.pid = process.pid if process is not None else None
        self.group_anchor = group_anchor
        self._post_closure_cleanup: list[
            tuple[Callable[[], None], pathlib.Path | None]
        ] = []
        self._signal_deferral_releases: list[Callable[[bool], None]] = []
        identity = (
            "not-applicable"
            if process is None
            else group_anchor.start_identity
            if group_anchor is not None
            else "unbound"
        )
        super().__init__(
            "Git process or control-resource closure is unproven: "
            f"pid={self.pid}, start_identity={identity}, "
            f"cleanup_error={type(cleanup_error).__name__}"
        )

    @property
    def retained_cleanup_paths(self) -> tuple[pathlib.Path, ...]:
        return tuple(path for _, path in self._post_closure_cleanup if path is not None)

    @property
    def process_receipt(self) -> dict[str, int | str | None]:
        if self.process is None:
            return {
                "identity_status": "not-applicable",
                "pid": None,
                "pgid": None,
                "start_identity": None,
            }
        anchor = self.group_anchor
        return {
            "identity_status": "anchored" if anchor is not None else "unbound",
            "pid": self.pid,
            "pgid": anchor.pgid if anchor is not None else None,
            "start_identity": anchor.start_identity if anchor is not None else None,
        }

    def add_post_closure_cleanup(
        self,
        cleanup: Callable[[], None],
        *,
        retained_path: pathlib.Path | None = None,
    ) -> None:
        self._post_closure_cleanup.append((cleanup, retained_path))

    def bind_signal_deferral_release(
        self,
        release: Callable[[bool], None],
    ) -> None:
        self._signal_deferral_releases.append(release)

    def finish_signal_deferral(self, *, deliver: bool) -> None:
        releases = self._signal_deferral_releases
        self._signal_deferral_releases = []
        errors: list[BaseException] = []
        for release in releases:
            try:
                release(deliver)
            except BaseException as error:
                errors.append(error)
        if errors:
            raise errors[0]

    def finish_post_closure_cleanup(self) -> bool:
        while self._post_closure_cleanup:
            cleanup, _ = self._post_closure_cleanup[0]
            try:
                cleanup()
            except BaseException:
                return False
            self._post_closure_cleanup.pop(0)
        return True


def retry_git_process_closure(failure: GitProcessClosureUnproven) -> bool:
    process = failure.process
    if process is not None:
        try:
            if process.returncode is None:
                if failure.group_anchor is None:
                    _abort_unanchored_fresh_session(process)
                else:
                    _terminate_process(process, group_anchor=failure.group_anchor)
        except BaseException:
            return False
        try:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        except BaseException:
            return False
    post_closure_cleanup_complete = failure.finish_post_closure_cleanup()
    return post_closure_cleanup_complete


@dataclass(frozen=True)
class RepositoryInfo:
    repo: pathlib.Path
    common_git_dir: pathlib.Path
    object_directory: pathlib.Path
    object_directory_identity: Identity
    object_format: str
    object_hex_length: int
    base_sha: str
    head_sha: str
    git_executable: str
    temporary_control_parent: pathlib.Path | None = None
    temporary_control_parent_identity: Identity | None = None


@dataclass(frozen=True)
class GitControlBinding:
    path: pathlib.Path
    root_identity: Identity
    config_identity: Identity
    config_sha256: str


@dataclass(frozen=True)
class WorktreeRegistration:
    worktree: pathlib.Path
    registration: pathlib.Path
    control: GitControlBinding
    worktree_identity: Identity
    registration_identity: Identity
    marker_identity: Identity
    descendant_count: int
    descendant_path_bytes: int


@dataclass(frozen=True)
class RangeMetadataReceipt:
    object_count: int
    aggregate_bytes: int
    sha256: str
    object_ids: frozenset[str]


@dataclass(frozen=True)
class AuthenticatedTreeEntry:
    mode: int
    object_type: str
    object_id: str
    path: bytes


def sanitized_git_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "HOME": "/var/empty",
    }
    if extra:
        environment.update(extra)
    return environment


def _terminate_process(
    process: subprocess.Popen[bytes],
    *,
    group_anchor: SpawnedProcess | None = None,
) -> int | None:
    if group_anchor is None:
        if process.poll() is not None:
            return process.returncode
        try:
            process.terminate()
            return process.wait(timeout=1)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                return process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                return None

    if group_anchor.pid != process.pid or group_anchor.pgid != process.pid:
        raise ValueError("process group is not bound to its leader")

    deadline = time.monotonic() + PROCESS_GROUP_CLEANUP_TIMEOUT_SECONDS
    signal_anchored_group(group_anchor, signal.SIGTERM)
    grace_deadline = min(
        deadline,
        time.monotonic() + PROCESS_GROUP_TERMINATE_GRACE_SECONDS,
    )
    while time.monotonic() < grace_deadline:
        time.sleep(min(0.01, grace_deadline - time.monotonic()))
    signal_anchored_group(group_anchor, signal.SIGKILL)

    wait_terminal(process.pid, deadline=deadline)
    _wait_anchored_group_without_other_members(group_anchor, deadline=deadline)
    return _reap_process_group_leader(process, deadline=deadline)


def _wait_anchored_group_without_other_members(
    group_anchor: SpawnedProcess,
    *,
    deadline: float,
) -> None:
    empty_confirmations = 0
    while True:
        members = anchored_group_members(group_anchor, deadline=deadline)
        if any(pid != group_anchor.pid for pid in members):
            empty_confirmations = 0
            signal_anchored_group(group_anchor, signal.SIGKILL)
        else:
            empty_confirmations += 1
            if empty_confirmations >= PROCESS_GROUP_EMPTY_CONFIRMATIONS:
                return
        if time.monotonic() >= deadline:
            raise TimeoutError("process-group members survived cleanup")
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))


def _settle_terminal_process_group(
    process: subprocess.Popen[bytes],
    *,
    group_anchor: SpawnedProcess,
) -> int:
    if group_anchor.pid != process.pid or group_anchor.pgid != process.pid:
        raise ValueError("process group is not bound to its leader")
    deadline = time.monotonic() + PROCESS_GROUP_CLEANUP_TIMEOUT_SECONDS
    # The leader is still an unreaped anchor here. Kill any original-group
    # residue and prove that no other group member remains before its one reap.
    signal_anchored_group(group_anchor, signal.SIGKILL)
    _wait_anchored_group_without_other_members(group_anchor, deadline=deadline)
    return _reap_process_group_leader(process, deadline=deadline)


def _reap_process_group_leader(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("process-group leader reap deadline expired")
    return process.wait(timeout=remaining)


def _abort_unanchored_fresh_session(process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + PROCESS_GROUP_CLEANUP_TIMEOUT_SECONDS
    try:
        # WNOWAIT proves this numeric PID is still our unreaped child before an
        # identity-less cleanup is allowed to address its fresh process group.
        terminal_status(process.pid)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        except PermissionError:
            if terminal_status(process.pid) is None:
                raise
        wait_terminal(process.pid, deadline=deadline)
        while True:
            members = process_group_members(process.pid, deadline=deadline)
            if not any(pid != process.pid for pid in members):
                break
            os.killpg(process.pid, signal.SIGKILL)
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "unanchored fresh-session group members survived cleanup"
                )
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        _reap_process_group_leader(process, deadline=deadline)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _bind_fresh_session(process: subprocess.Popen[bytes]) -> SpawnedProcess:
    start_identity = process_start_identity(process.pid)
    if os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
        raise ChildProcessError("fresh Git process session identity is invalid")
    return SpawnedProcess(
        pid=process.pid,
        pgid=process.pid,
        acknowledgement_fd=-1,
        passed_fd_numbers=(),
        start_identity=start_identity,
    )


def run_bounded(
    argv: tuple[str, ...],
    *,
    cwd: pathlib.Path,
    environment: dict[str, str],
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    input_bytes: bytes | None = None,
) -> tuple[int, bytes, bytes]:
    process: subprocess.Popen[bytes] | None = None
    group_anchor: SpawnedProcess | None = None
    selector: selectors.BaseSelector | None = None
    returncode: int | None = None
    signal_scope = begin_bound_signal_deferral()
    pending_error: BaseException | None = None
    closure_failure: GitProcessClosureUnproven | None = None
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=(subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
        group_anchor = _bind_fresh_session(process)
        checkpoint_bound_signal_interrupt(force=True)
        if (
            process.stdout is None
            or process.stderr is None
            or (input_bytes is not None and process.stdin is None)
        ):
            raise RuntimeError("cannot create bounded Git pipes")
        selector = selectors.DefaultSelector()
        streams = {
            process.stdout.fileno(): (process.stdout, stdout_limit),
            process.stderr.fileno(): (process.stderr, stderr_limit),
        }
        buffers: dict[int, bytearray] = {fd: bytearray() for fd in streams}
        for fd in streams:
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ)
        input_offset = 0
        input_fd: int | None = None
        if input_bytes is not None:
            assert process.stdin is not None
            input_fd = process.stdin.fileno()
            os.set_blocking(input_fd, False)
            selector.register(input_fd, selectors.EVENT_WRITE)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            checkpoint_bound_signal_interrupt(force=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded Git command timed out")
            events = selector.select(min(remaining, 0.25))
            checkpoint_bound_signal_interrupt(force=True)
            for key, _ in events:
                fd = key.fd
                if input_fd is not None and fd == input_fd:
                    try:
                        written = os.write(
                            input_fd,
                            input_bytes[input_offset : input_offset + 64 * 1024],
                        )
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(input_bytes)
                    except BlockingIOError:
                        continue
                    input_offset += written
                    if input_offset >= len(input_bytes):
                        selector.unregister(input_fd)
                        process.stdin.close()
                        input_fd = None
                    continue
                try:
                    chunk = os.read(fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(fd)
                    continue
                _, limit = streams[fd]
                if len(buffers[fd]) + len(chunk) > limit:
                    raise OverflowError("bounded Git output exceeded its byte cap")
                buffers[fd].extend(chunk)
            if returncode is None and terminal_status(process.pid) is not None:
                if input_fd is not None:
                    selector.unregister(input_fd)
                    assert process.stdin is not None
                    process.stdin.close()
                    input_fd = None
                returncode = _settle_terminal_process_group(
                    process,
                    group_anchor=group_anchor,
                )
        if returncode is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded Git command timed out before reap")
            wait_terminal(process.pid, deadline=deadline)
            returncode = _settle_terminal_process_group(
                process,
                group_anchor=group_anchor,
            )
        return (
            returncode,
            bytes(buffers[process.stdout.fileno()]),
            bytes(buffers[process.stderr.fileno()]),
        )
    except BaseException as error:
        pending_error = error
        try:
            if process is not None and process.returncode is None:
                if group_anchor is None:
                    _abort_unanchored_fresh_session(process)
                else:
                    _terminate_process(process, group_anchor=group_anchor)
        except BaseException as cleanup_error:
            assert process is not None
            closure_failure = GitProcessClosureUnproven(
                process,
                group_anchor,
                cleanup_error,
            )
            if signal_scope is not None:
                transferred_scope = signal_scope
                signal_scope = None
                closure_failure.bind_signal_deferral_release(
                    lambda deliver: transferred_scope.finish(deliver=deliver)
                )
            pending_error = closure_failure
            raise closure_failure from error
        checkpoint_bound_signal_interrupt(force=True)
        raise
    finally:
        finalizer_errors: list[BaseException] = []
        if selector is not None:
            try:
                selector.close()
            except BaseException as error:
                finalizer_errors.append(error)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is None or stream.closed:
                    continue
                try:
                    stream.close()
                except BaseException as error:
                    finalizer_errors.append(error)
        if signal_scope is not None:
            try:
                signal_scope.finish(deliver=closure_failure is None)
            except BaseException as error:
                finalizer_errors.append(error)
        control_flow = next(
            (error for error in finalizer_errors if not isinstance(error, Exception)),
            None,
        )
        if control_flow is not None and closure_failure is None:
            raise control_flow
        if finalizer_errors and pending_error is None:
            raise finalizer_errors[0]


def _drain_started_process(
    process: subprocess.Popen[bytes],
    *,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    group_anchor: SpawnedProcess | None = None,
) -> tuple[int, bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        _terminate_process(process, group_anchor=group_anchor)
        raise RuntimeError("cannot drain bounded Git pipes")
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): (process.stdout, stdout_limit),
        process.stderr.fileno(): (process.stderr, stderr_limit),
    }
    buffers: dict[int, bytearray] = {fd: bytearray() for fd in streams}
    deadline = time.monotonic() + timeout
    try:
        for descriptor in streams:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        while selector.get_map():
            checkpoint_bound_signal_interrupt(force=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded Git shutdown timed out")
            events = selector.select(min(remaining, 0.25))
            checkpoint_bound_signal_interrupt(force=True)
            if not events and group_anchor is None and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ) for key in selector.get_map().values()
                ]
            for key, _ in events:
                descriptor = key.fd
                try:
                    chunk = os.read(descriptor, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    continue
                _, limit = streams[descriptor]
                if len(buffers[descriptor]) + len(chunk) > limit:
                    raise OverflowError(
                        "bounded Git shutdown output exceeded its byte cap"
                    )
                buffers[descriptor].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bounded Git shutdown timed out before reap")
        if group_anchor is None:
            returncode = process.wait(timeout=remaining)
        else:
            wait_terminal(process.pid, deadline=deadline)
            terminated = _terminate_process(process, group_anchor=group_anchor)
            if terminated is None:
                raise TimeoutError("cat-file process-group leader was not reaped")
            returncode = terminated
        return (
            returncode,
            bytes(buffers[process.stdout.fileno()]),
            bytes(buffers[process.stderr.fileno()]),
        )
    except BaseException:
        _terminate_process(process, group_anchor=group_anchor)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def _git_error(argv: tuple[str, ...], stderr: bytes) -> str:
    tail = stderr[-8192:].decode("utf-8", "replace")
    return f"Git command failed ({' '.join(argv[1:4])}): {tail.strip()}"


def _read_optional_git_file(
    parent_fd: int,
    name: bytes,
    *,
    max_bytes: int,
) -> bytes | None:
    try:
        fd, identity = open_regular_at(
            parent_fd,
            name,
            expected_uid=os.getuid(),
        )
    except FileNotFoundError:
        return None
    try:
        if identity.mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise OSError(
                errno.EPERM,
                "local Git metadata is writable outside its owner",
            )
        if identity.size > max_bytes:
            raise ValueError("local Git metadata file exceeds its byte limit")
        content = read_fd_exact(
            fd,
            max_bytes=max_bytes,
            expected_size=identity.size,
        )
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if identity != identity_from_stat(current):
            raise OSError(
                errno.ESTALE,
                "local Git metadata identity changed while reading",
            )
        # The descriptor/path identity and single-link policy protect custody;
        # exact reread protects content stability without treating timestamps as
        # content evidence.
        if identity_from_stat(os.fstat(fd)) != identity:
            raise OSError(
                errno.ESTALE,
                "local Git metadata descriptor identity changed while reading",
            )
        if (
            read_fd_exact(
                fd,
                max_bytes=max_bytes,
                expected_size=identity.size,
            )
            != content
        ):
            raise OSError(
                errno.ESTALE,
                "local Git metadata content changed while reading",
            )
        return content
    finally:
        os.close(fd)


def _metadata_path(base: pathlib.Path, raw: bytes, *, label: str) -> pathlib.Path:
    if not raw or b"\0" in raw or b"\r" in raw or b"\n" in raw:
        raise ValueError(f"{label} path is malformed")
    value = pathlib.Path(os.fsdecode(raw))
    return pathlib.Path(
        os.path.abspath(os.fspath(value if value.is_absolute() else base / value))
    )


def _parse_gitdir_pointer(raw: bytes, *, repo: pathlib.Path) -> pathlib.Path:
    prefix = b"gitdir:"
    if not raw.endswith(b"\n") or not raw.lower().startswith(prefix):
        raise ValueError("worktree .git pointer is malformed")
    value = raw[len(prefix) : -1].strip()
    return _metadata_path(repo, value, label="worktree gitdir")


def _reject_local_config_includes(raw: bytes, *, label: str) -> str | None:
    if len(raw) > LOCAL_CONFIG_BYTES_LIMIT or b"\0" in raw:
        raise ValueError(f"{label} is malformed or exceeds its byte limit")
    section: bytes | None = None
    object_format: str | None = None
    for physical_line in raw.splitlines():
        line = physical_line.strip()
        if not line or line.startswith((b"#", b";")):
            continue
        if line.startswith(b"["):
            match = _CONFIG_SECTION_PATTERN.match(line)
            if match is None or b"]" not in line:
                raise ValueError(f"{label} contains a malformed section")
            section = match.group(1).lower()
            if section in {b"include", b"includeif"}:
                raise ValueError(f"{label} contains a forbidden include directive")
            continue
        key_match = _CONFIG_KEY_PATTERN.match(line)
        if key_match is None:
            raise ValueError(f"{label} contains a malformed key")
        key = key_match.group(1).lower()
        if key in {b"include", b"includeif"} or line.lower().startswith(
            (b"include.", b"includeif.")
        ):
            raise ValueError(f"{label} contains a forbidden include directive")
        if section == b"extensions" and key == b"objectformat":
            value = line[key_match.end() :].lstrip()
            if value.startswith(b"="):
                value = value[1:].strip()
            if value not in {b"sha1", b"sha256"}:
                raise ValueError(f"{label} contains an unsupported object format")
            parsed = value.decode("ascii")
            if object_format is not None and parsed != object_format:
                raise ValueError(f"{label} contains conflicting object formats")
            object_format = parsed
    return object_format


def _preflight_local_git_config(repo: pathlib.Path) -> tuple[pathlib.Path, str]:
    repo_fd = open_directory(repo)
    git_dir_fd: int | None = None
    common_fd: int | None = None
    try:
        dot_git = os.stat(b".git", dir_fd=repo_fd, follow_symlinks=False)
        if stat.S_ISDIR(dot_git.st_mode):
            git_dir = repo / ".git"
        elif stat.S_ISREG(dot_git.st_mode):
            pointer = _read_optional_git_file(
                repo_fd,
                b".git",
                max_bytes=GITDIR_POINTER_BYTES_LIMIT,
            )
            assert pointer is not None
            git_dir = _parse_gitdir_pointer(pointer, repo=repo)
        else:
            raise ValueError("source repository .git entry is unsafe")

        git_dir_fd, _ = open_absolute_directory_chain(git_dir)
        common_pointer = _read_optional_git_file(
            git_dir_fd,
            b"commondir",
            max_bytes=GITDIR_POINTER_BYTES_LIMIT,
        )
        common = (
            git_dir
            if common_pointer is None
            else _metadata_path(
                git_dir,
                common_pointer.strip(),
                label="Git common directory",
            )
        )
        common_fd, _ = open_absolute_directory_chain(common)
        config = _read_optional_git_file(
            common_fd,
            b"config",
            max_bytes=LOCAL_CONFIG_BYTES_LIMIT,
        )
        if config is None:
            raise FileNotFoundError(
                errno.ENOENT,
                "source repository has no local config",
                common / "config",
            )
        object_format = _reject_local_config_includes(
            config,
            label="source repository config",
        )
        worktree_config = _read_optional_git_file(
            git_dir_fd,
            b"config.worktree",
            max_bytes=LOCAL_CONFIG_BYTES_LIMIT,
        )
        if worktree_config is not None:
            worktree_format = _reject_local_config_includes(
                worktree_config,
                label="source worktree config",
            )
            if worktree_format is not None and worktree_format != object_format:
                raise ValueError("source local configs disagree on object format")
            object_format = object_format or worktree_format
        return common, object_format or "sha1"
    finally:
        if common_fd is not None:
            os.close(common_fd)
        if git_dir_fd is not None:
            os.close(git_dir_fd)
        os.close(repo_fd)


def inspect_repository(
    *,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
    git_executable: str,
    temporary_control_parent: pathlib.Path | None = None,
) -> RepositoryInfo:
    executable = pathlib.Path(git_executable)
    if not executable.is_absolute():
        raise blocked(
            "Git executable must be an absolute path",
            stage="git-preflight",
            code="git-path-not-absolute",
        )
    executable_stat = os.stat(executable)
    if (
        not stat.S_ISREG(executable_stat.st_mode)
        or not executable_stat.st_mode & stat.S_IXUSR
        or executable_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise blocked(
            "Git executable is not a stable executable file",
            stage="git-preflight",
            code="git-executable-unsafe",
        )
    canonical_repo = repo.resolve(strict=True)
    try:
        common, preflight_object_format = _preflight_local_git_config(canonical_repo)
    except FileNotFoundError as error:
        raise blocked(
            f"repository local config or metadata is missing: {error}",
            stage="git-preflight",
            code="git-config-missing",
        ) from error
    except OSError as error:
        if error.errno == errno.ESTALE:
            message = "repository local config or metadata failed revalidation"
            code = "git-config-revalidation-mismatch"
        elif error.errno in {
            errno.EPERM,
            errno.ELOOP,
            errno.ENOTDIR,
            errno.EINVAL,
            errno.EMLINK,
        }:
            message = "repository local config or metadata mismatched access policy"
            code = "git-config-policy-mismatch"
        else:
            message = "repository local config or metadata is unreadable"
            code = "git-config-unreadable"
        raise blocked(
            f"{message}: {error}",
            stage="git-preflight",
            code=code,
        ) from error
    except ValueError as error:
        raise blocked(
            f"repository local config or metadata mismatched policy: {error}",
            stage="git-preflight",
            code="git-config-mismatch",
        ) from error
    try:
        objects = common / "objects"
        objects_fd, objects_identity = open_absolute_directory_chain(objects)
        os.close(objects_fd)
    except FileNotFoundError as error:
        raise blocked(
            f"repository object directory is missing: {error}",
            stage="git-preflight",
            code="git-object-directory-missing",
        ) from error
    except OSError as error:
        raise blocked(
            f"repository object directory is unreadable: {error}",
            stage="git-preflight",
            code="git-object-directory-unreadable",
        ) from error

    temporary_control_parent_identity: Identity | None = None
    if temporary_control_parent is not None:
        if (
            not temporary_control_parent.is_absolute()
            or temporary_control_parent
            != pathlib.Path(os.path.abspath(temporary_control_parent))
        ):
            raise blocked(
                "temporary Git control parent is not canonical",
                stage="git-preflight",
                code="git-control-parent-invalid",
            )
        temporary_parent_fd, temporary_control_parent_identity = (
            open_absolute_directory_chain(temporary_control_parent)
        )
        try:
            validate_private_directory_fd(
                temporary_parent_fd,
                temporary_control_parent,
            )
        finally:
            os.close(temporary_parent_fd)

    width = 40 if preflight_object_format == "sha1" else 64
    provisional = RepositoryInfo(
        repo=canonical_repo,
        common_git_dir=common,
        object_directory=objects,
        object_directory_identity=objects_identity,
        object_format=preflight_object_format,
        object_hex_length=width,
        base_sha=base_sha,
        head_sha=head_sha,
        git_executable=str(executable),
        temporary_control_parent=temporary_control_parent,
        temporary_control_parent_identity=temporary_control_parent_identity,
    )

    try:
        with temporary_git_control(provisional) as control:

            def query(*arguments: str, cap: int = 8192) -> bytes:
                argv = _git_control_argv(provisional, control, *arguments)
                code, stdout, stderr = run_bounded(
                    argv,
                    cwd=control.path.parent,
                    environment=_git_control_environment(provisional, control),
                    timeout=15,
                    stdout_limit=cap,
                    stderr_limit=8192,
                )
                if code != 0:
                    raise ValueError(_git_error(argv, stderr))
                return stdout.strip()

            format_raw = query("rev-parse", "--show-object-format")
            resolved_base = query("rev-parse", "--verify", f"{base_sha}^{{commit}}")
            resolved_head = query("rev-parse", "--verify", f"{head_sha}^{{commit}}")
        if format_raw.decode("ascii", "strict") != preflight_object_format:
            raise ValueError("private Git control view has the wrong object format")
        if (
            resolved_base.decode("ascii") != base_sha
            or resolved_head.decode("ascii") != head_sha
        ):
            raise ValueError(
                "requested range does not resolve to the exact supplied commits"
            )
        if len(base_sha) != width or len(head_sha) != width:
            raise ValueError("commit IDs do not match the repository object format")
        _revalidate_object_directory(provisional)
        return provisional
    except GitProcessClosureUnproven:
        raise
    except Exception as error:
        raise blocked(
            f"cannot authenticate repository and frozen range: {error}",
            stage="git-preflight",
            code="frozen-range-invalid",
        ) from error


def _parse_tree_record(record: bytes, *, object_width: int) -> TreeEntry:
    try:
        header, path = record.split(b"\t", 1)
        mode_raw, object_type_raw, object_id_raw, size_raw = header.split()
    except ValueError as error:
        raise ValueError("malformed ls-tree record") from error
    if (
        len(mode_raw) != 6
        or len(object_id_raw) != object_width
        or any(byte not in b"0123456789abcdef" for byte in object_id_raw)
    ):
        raise ValueError("ls-tree record has malformed mode or object ID")
    try:
        mode = int(mode_raw, 8)
    except ValueError as error:
        raise ValueError("ls-tree mode is invalid") from error
    object_type = object_type_raw.decode("ascii", "strict")
    if mode in {0o100644, 0o100755, 0o120000}:
        if object_type != "blob" or not size_raw.isdigit():
            raise ValueError("regular/symlink entry is not a sized blob")
        size = int(size_raw, 10)
        maximum = MAX_SYMLINK_BYTES if mode == 0o120000 else MAX_BLOB_BYTES
        if size > maximum:
            raise ValueError("tree blob exceeds its per-object limit")
    elif mode == 0o160000:
        if object_type != "commit" or size_raw != b"-":
            raise ValueError("gitlink entry is malformed")
        size = None
    else:
        raise ValueError(f"unsupported tracked Git mode: {mode_raw!r}")
    validate_raw_path(path)
    return TreeEntry(
        mode=mode,
        object_type=object_type,
        object_id=object_id_raw.decode("ascii"),
        size=size,
        path=path,
    )


def validate_raw_path(path: bytes) -> None:
    if (
        not path
        or path.startswith(b"/")
        or path.endswith(b"/")
        or b"//" in path
        or b"\0" in path
    ):
        raise ValueError("tree path has invalid slash semantics")
    for component in path.split(b"/"):
        if component in {b"", b".", b".."}:
            raise ValueError("tree path has an invalid component")


def _revalidate_object_directory(info: RepositoryInfo) -> None:
    descriptor, observed = open_absolute_directory_chain(info.object_directory)
    try:
        if not directory_identities_match(
            observed,
            info.object_directory_identity,
        ):
            raise OSError(
                errno.ESTALE,
                "repository object directory identity or access policy changed",
            )
    finally:
        os.close(descriptor)


def _git_control_argv(
    info: RepositoryInfo,
    control: GitControlBinding,
    *arguments: str,
) -> tuple[str, ...]:
    return (
        info.git_executable,
        "--git-dir",
        str(control.path),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "pack.useBitmaps=false",
        *arguments,
    )


def _git_control_environment(
    info: RepositoryInfo,
    control: GitControlBinding,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    revalidate_git_control(info, control)
    _revalidate_object_directory(info)
    values = {
        "GIT_DIR": str(control.path),
        "GIT_OBJECT_DIRECTORY": str(info.object_directory),
    }
    if extra:
        values.update(extra)
    return sanitized_git_environment(values)


@contextmanager
def temporary_git_control(
    info: RepositoryInfo,
) -> Iterator[GitControlBinding]:
    signal_scope = begin_bound_signal_deferral()
    try:
        try:
            parent, binding = _create_temporary_git_control(info)
        except GitProcessClosureUnproven as failure:
            if signal_scope is not None:
                transferred_scope = signal_scope
                signal_scope = None
                failure.bind_signal_deferral_release(
                    lambda deliver: transferred_scope.finish(deliver=deliver)
                )
            raise
        try:
            yield binding
        except GitProcessClosureUnproven as failure:
            failure.add_post_closure_cleanup(
                lambda: _cleanup_temporary_git_control(info, parent, binding.path),
                retained_path=parent,
            )
            if signal_scope is not None:
                transferred_scope = signal_scope
                signal_scope = None
                failure.bind_signal_deferral_release(
                    lambda deliver: transferred_scope.finish(deliver=deliver)
                )
            raise
        except BaseException as error:
            try:
                _cleanup_temporary_git_control(info, parent, binding.path)
            except BaseException as cleanup_error:
                failure = GitProcessClosureUnproven(None, None, cleanup_error)
                failure.add_post_closure_cleanup(
                    lambda: _cleanup_temporary_git_control(
                        info,
                        parent,
                        binding.path,
                    ),
                    retained_path=parent,
                )
                if signal_scope is not None:
                    transferred_scope = signal_scope
                    signal_scope = None
                    failure.bind_signal_deferral_release(
                        lambda deliver: transferred_scope.finish(deliver=deliver)
                    )
                raise failure from error
            raise
        else:
            try:
                _cleanup_temporary_git_control(info, parent, binding.path)
            except BaseException as cleanup_error:
                failure = GitProcessClosureUnproven(None, None, cleanup_error)
                failure.add_post_closure_cleanup(
                    lambda: _cleanup_temporary_git_control(
                        info,
                        parent,
                        binding.path,
                    ),
                    retained_path=parent,
                )
                if signal_scope is not None:
                    transferred_scope = signal_scope
                    signal_scope = None
                    failure.bind_signal_deferral_release(
                        lambda deliver: transferred_scope.finish(deliver=deliver)
                    )
                raise failure from cleanup_error
    finally:
        if signal_scope is not None:
            signal_scope.finish()


def _open_bound_temporary_control_parent(
    info: RepositoryInfo,
    path: pathlib.Path,
) -> int:
    descriptor, identity = open_absolute_directory_chain(path)
    try:
        expected_path = info.temporary_control_parent
        expected_identity = info.temporary_control_parent_identity
        if (expected_path is None) != (expected_identity is None):
            raise ValueError("temporary Git control parent binding is incomplete")
        if expected_path is not None:
            assert expected_identity is not None
            if path != expected_path:
                raise OSError(
                    errno.ESTALE,
                    "temporary Git control parent path changed",
                )
            validate_private_directory_fd(descriptor, path)
            if not directory_identities_match(identity, expected_identity):
                raise OSError(
                    errno.ESTALE,
                    "temporary Git control parent identity changed",
                )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _create_temporary_git_control(
    info: RepositoryInfo,
) -> tuple[pathlib.Path, GitControlBinding]:
    temporary_parent = info.temporary_control_parent
    expected_parent_identity = info.temporary_control_parent_identity
    if (temporary_parent is None) != (expected_parent_identity is None):
        raise ValueError("temporary Git control parent binding is incomplete")
    if temporary_parent is not None:
        parent_fd = _open_bound_temporary_control_parent(info, temporary_parent)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    parent = pathlib.Path(
        tempfile.mkdtemp(
            prefix="codex-git-control-",
            dir=temporary_parent,
        )
    )
    control = parent / "git"
    parent_root_fd: int | None = None
    try:
        parent_root_fd = _open_bound_temporary_control_parent(info, parent.parent)
        os.fsync(parent_root_fd)
        binding = create_sanitized_view(info, control)
        if temporary_parent is not None:
            parent_fd = _open_bound_temporary_control_parent(info, temporary_parent)
            os.close(parent_fd)
        return parent, binding
    except BaseException as error:
        try:
            _cleanup_temporary_git_control(info, parent, control)
        except BaseException as cleanup_error:
            failure = GitProcessClosureUnproven(None, None, cleanup_error)
            failure.add_post_closure_cleanup(
                lambda: _cleanup_temporary_git_control(info, parent, control),
                retained_path=parent,
            )
            raise failure from error
        raise
    finally:
        if parent_root_fd is not None:
            os.close(parent_root_fd)


def _cleanup_temporary_git_control(
    info: RepositoryInfo,
    parent: pathlib.Path,
    control: pathlib.Path,
) -> None:
    parent_root_fd = _open_bound_temporary_control_parent(info, parent.parent)
    try:
        try:
            os.stat(
                os.fsencode(parent.name),
                dir_fd=parent_root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            os.fsync(parent_root_fd)
            return
        try:
            os.lstat(control)
        except FileNotFoundError:
            pass
        else:
            remove_sanitized_view(control, allow_partial=True)
        os.rmdir(os.fsencode(parent.name), dir_fd=parent_root_fd)
        os.fsync(parent_root_fd)
    finally:
        os.close(parent_root_fd)


def enumerate_tree(info: RepositoryInfo, commit: str) -> TreeManifest:
    try:
        with temporary_git_control(info) as control:
            argv = _git_control_argv(
                info,
                control,
                "ls-tree",
                "-rz",
                "-l",
                "--full-tree",
                "-r",
                commit,
            )
            code, stdout, stderr = run_bounded(
                argv,
                cwd=control.path.parent,
                environment=_git_control_environment(info, control),
                timeout=120,
                stdout_limit=MAX_TREE_METADATA_BYTES,
                stderr_limit=8192,
            )
    except (TimeoutError, OverflowError) as error:
        raise inconclusive(
            f"frozen tree enumeration did not complete safely: {error}",
            stage="tree-enumeration",
            code="tree-enumeration-bounded-failure",
        ) from error
    if code != 0:
        raise blocked(
            _git_error(argv, stderr),
            stage="tree-enumeration",
            code="tree-enumeration-failed",
        )
    if stdout and not stdout.endswith(b"\0"):
        raise blocked(
            "ls-tree output is not NUL-terminated",
            stage="tree-enumeration",
            code="tree-stream-malformed",
        )
    records = stdout[:-1].split(b"\0") if stdout else []
    if len(records) > MAX_TREE_ENTRIES:
        raise blocked(
            "frozen tree exceeds the entry limit",
            stage="tree-enumeration",
            code="tree-entry-cap",
        )
    entries: list[TreeEntry] = []
    previous: bytes | None = None
    aggregate_regular = 0
    gitlinks = 0
    try:
        for record in records:
            entry = _parse_tree_record(record, object_width=info.object_hex_length)
            if previous is not None and entry.path <= previous:
                raise ValueError("frozen paths are not in strict raw-byte order")
            previous = entry.path
            if entry.is_regular:
                assert entry.size is not None
                aggregate_regular += entry.size
                if aggregate_regular > MAX_RAW_BLOB_BYTES:
                    raise ValueError("aggregate regular blob bytes exceed the limit")
            elif entry.is_gitlink:
                gitlinks += 1
            entries.append(entry)
    except ValueError as error:
        raise blocked(
            f"frozen tree stream is invalid: {error}",
            stage="tree-enumeration",
            code="tree-stream-invalid",
        ) from error
    return TreeManifest(
        commit=commit,
        entries=tuple(entries),
        metadata_bytes=len(stdout),
        aggregate_regular_bytes=aggregate_regular,
        gitlink_count=gitlinks,
    )


def object_digest(object_format: str, payload: bytes) -> str:
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def manifest_digest(manifest: TreeManifest) -> str:
    digest = hashlib.sha256()
    for entry in manifest.entries:
        size = b"-" if entry.size is None else str(entry.size).encode("ascii")
        digest.update(
            f"{entry.mode:06o} {entry.object_type} {entry.object_id} ".encode("ascii")
        )
        digest.update(size)
        digest.update(b"\t")
        digest.update(entry.path)
        digest.update(b"\0")
    return digest.hexdigest()


class CatFileBatch:
    def __init__(self, info: RepositoryInfo) -> None:
        self.info = info
        process: subprocess.Popen[bytes] | None = None
        group_anchor: SpawnedProcess | None = None
        self._control_parent: pathlib.Path | None = None
        self.control: GitControlBinding | None = None
        self._signal_scope: DeferredSignalScope | None = begin_bound_signal_deferral()
        try:
            self._control_parent, self.control = _create_temporary_git_control(info)
            argv = _git_control_argv(
                info,
                self.control,
                "cat-file",
                "--batch",
            )
            process = subprocess.Popen(
                argv,
                cwd=self.control.path.parent,
                env=_git_control_environment(info, self.control),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                start_new_session=True,
            )
            self.process = process
            self.process_group = process.pid
            group_anchor = _bind_fresh_session(process)
            self.group_anchor = group_anchor
            checkpoint_bound_signal_interrupt(force=True)
            if (
                process.stdin is None
                or process.stdout is None
                or process.stderr is None
            ):
                raise RuntimeError("cannot create cat-file batch pipes")
        except GitProcessClosureUnproven as failure:
            self._attach_signal_deferral(failure)
            raise
        except BaseException as error:
            try:
                try:
                    if process is not None and process.returncode is None:
                        if group_anchor is None:
                            _abort_unanchored_fresh_session(process)
                        else:
                            _terminate_process(
                                process,
                                group_anchor=group_anchor,
                            )
                finally:
                    if process is not None:
                        for stream in (
                            process.stdin,
                            process.stdout,
                            process.stderr,
                        ):
                            if stream is not None and not stream.closed:
                                stream.close()
            except BaseException as cleanup_error:
                assert process is not None
                failure = GitProcessClosureUnproven(
                    process,
                    group_anchor,
                    cleanup_error,
                )
                self._attach_post_closure_cleanup(failure)
                self._attach_signal_deferral(failure)
                raise failure from error
            try:
                self._cleanup_private_control()
            except BaseException as cleanup_error:
                raise self._control_cleanup_failure(
                    cleanup_error,
                ) from error
            else:
                self._finish_signal_scope()
            raise
        self.requests = 0
        self.closed = False
        self.stderr = bytearray()

    def _finish_signal_scope(self, *, deliver: bool = True) -> None:
        scope = getattr(self, "_signal_scope", None)
        if scope is None:
            return
        self._signal_scope = None
        scope.finish(deliver=deliver)

    def _attach_post_closure_cleanup(
        self,
        failure: GitProcessClosureUnproven,
    ) -> None:
        failure.add_post_closure_cleanup(
            self._finish_after_unproven_closure,
            retained_path=self._control_parent,
        )

    def _attach_signal_deferral(
        self,
        failure: GitProcessClosureUnproven,
    ) -> None:
        failure.bind_signal_deferral_release(
            lambda deliver: self._finish_signal_scope(deliver=deliver)
        )

    def _finish_after_unproven_closure(self) -> None:
        process = getattr(self, "process", None)
        if process is not None:
            for stream in (
                process.stdin,
                process.stdout,
                process.stderr,
            ):
                if stream is not None and not stream.closed:
                    stream.close()
        self.closed = True
        self._cleanup_private_control()

    def _control_cleanup_failure(
        self,
        cleanup_error: BaseException,
    ) -> GitProcessClosureUnproven:
        process = getattr(self, "process", None)
        group_anchor = getattr(self, "group_anchor", None)
        failure = GitProcessClosureUnproven(
            process,
            group_anchor if process is not None else None,
            cleanup_error,
        )
        self._attach_post_closure_cleanup(failure)
        self._attach_signal_deferral(failure)
        return failure

    def _cleanup_private_control(self) -> None:
        parent = self._control_parent
        control = self.control
        if parent is None or control is None:
            return
        _cleanup_temporary_git_control(self.info, parent, control.path)
        self._control_parent = None
        self.control = None

    def read_blob(
        self,
        entry: TreeEntry,
        *,
        consumer: Callable[[bytes], None] | None = None,
        capture: bool = False,
    ) -> bytes | None:
        if self.closed or entry.size is None or entry.object_type != "blob":
            raise ValueError("invalid cat-file blob request")
        _, _, payload = self._read_object(
            entry.object_id,
            allowed_types=frozenset({"blob"}),
            expected_type="blob",
            expected_size=entry.size,
            maximum_size=entry.size,
            deadline=time.monotonic() + CAT_FILE_READ_TIMEOUT_SECONDS,
            consumer=consumer,
            capture=capture,
        )
        return payload

    def verify_object(
        self,
        object_id: str,
        *,
        allowed_types: frozenset[str],
        maximum_size: int,
        deadline: float,
    ) -> tuple[str, int]:
        object_type, size, _ = self._read_object(
            object_id,
            allowed_types=allowed_types,
            expected_type=None,
            expected_size=None,
            maximum_size=maximum_size,
            deadline=deadline,
            consumer=None,
            capture=False,
        )
        return object_type, size

    def read_object_payload(
        self,
        object_id: str,
        *,
        allowed_types: frozenset[str],
        maximum_size: int,
        deadline: float,
    ) -> tuple[str, bytes]:
        object_type, _, payload = self._read_object(
            object_id,
            allowed_types=allowed_types,
            expected_type=None,
            expected_size=None,
            maximum_size=maximum_size,
            deadline=deadline,
            consumer=None,
            capture=True,
        )
        assert payload is not None
        return object_type, payload

    def _read_object(
        self,
        object_id: str,
        *,
        allowed_types: frozenset[str],
        expected_type: str | None,
        expected_size: int | None,
        maximum_size: int,
        deadline: float,
        consumer: Callable[[bytes], None] | None,
        capture: bool,
    ) -> tuple[str, int, bytes | None]:
        if (
            self.closed
            or not allowed_types
            or maximum_size < 0
            or len(object_id) != self.info.object_hex_length
            or any(character not in "0123456789abcdef" for character in object_id)
        ):
            raise ValueError("invalid cat-file object request")
        request = object_id.encode("ascii") + b"\n"
        observed_type: str | None = None
        observed_size: int | None = None
        digest = None
        payload_remaining: int | None = None
        captured = bytearray() if capture else None
        header = bytearray()
        request_offset = 0
        protocol_state = "header"
        selector = selectors.DefaultSelector()
        stdin_fd = self.process.stdin.fileno()
        stdout_fd = self.process.stdout.fileno()
        stderr_fd = self.process.stderr.fileno()
        try:
            for descriptor in (stdin_fd, stdout_fd, stderr_fd):
                os.set_blocking(descriptor, False)
            selector.register(stdin_fd, selectors.EVENT_WRITE, "stdin")
            selector.register(stdout_fd, selectors.EVENT_READ, "stdout")
            selector.register(stderr_fd, selectors.EVENT_READ, "stderr")

            while protocol_state != "done":
                checkpoint_bound_signal_interrupt(force=True)
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise TimeoutError("cat-file object request timed out")
                events = selector.select(min(remaining_time, 0.25))
                checkpoint_bound_signal_interrupt(force=True)
                events.sort(key=lambda event: event[0].data != "stderr")
                for key, _ in events:
                    descriptor = key.fd
                    if key.data == "stdin":
                        try:
                            written = os.write(
                                descriptor,
                                request[request_offset:],
                            )
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as error:
                            raise ValueError(
                                "cat-file request pipe ended early"
                            ) from error
                        if written <= 0:
                            raise ValueError("cat-file request pipe ended early")
                        request_offset += written
                        if request_offset == len(request):
                            selector.unregister(descriptor)
                        continue

                    if key.data == "stderr":
                        stderr_room = CAT_FILE_STDERR_LIMIT_BYTES - len(self.stderr)
                        try:
                            chunk = os.read(
                                descriptor,
                                min(64 * 1024, stderr_room + 1),
                            )
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(descriptor)
                            continue
                        if len(chunk) > stderr_room:
                            raise OverflowError("cat-file stderr exceeded its byte cap")
                        self.stderr.extend(chunk)
                        continue

                    if protocol_state == "header":
                        read_size = 257 - len(header)
                    elif protocol_state == "payload":
                        assert payload_remaining is not None
                        read_size = min(64 * 1024, payload_remaining)
                    else:
                        read_size = 1
                    try:
                        chunk = os.read(descriptor, read_size)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        if protocol_state == "header":
                            raise ValueError(
                                "cat-file emitted an invalid bounded header"
                            )
                        if protocol_state == "payload":
                            raise ValueError("cat-file payload ended early")
                        raise ValueError("cat-file payload delimiter ended early")

                    offset = 0
                    while offset < len(chunk):
                        if protocol_state == "header":
                            newline = chunk.find(b"\n", offset)
                            if newline < 0:
                                header.extend(chunk[offset:])
                                if len(header) > 256:
                                    raise ValueError(
                                        "cat-file emitted an invalid bounded header"
                                    )
                                offset = len(chunk)
                                continue
                            header.extend(chunk[offset:newline])
                            if len(header) > 256:
                                raise ValueError(
                                    "cat-file emitted an invalid bounded header"
                                )
                            try:
                                (
                                    observed_id_raw,
                                    observed_type_raw,
                                    observed_size_raw,
                                ) = header.split(b" ")
                                candidate_type = observed_type_raw.decode(
                                    "ascii",
                                    "strict",
                                )
                            except (UnicodeDecodeError, ValueError) as error:
                                raise ValueError(
                                    f"cat-file header mismatch: {bytes(header)!r}"
                                ) from error
                            if (
                                observed_id_raw != object_id.encode("ascii")
                                or candidate_type not in allowed_types
                                or not observed_size_raw.isdigit()
                                or (
                                    len(observed_size_raw) > 1
                                    and observed_size_raw.startswith(b"0")
                                )
                            ):
                                raise ValueError(
                                    f"cat-file header mismatch: {bytes(header)!r}"
                                )
                            candidate_size = int(observed_size_raw, 10)
                            if (
                                expected_type is not None
                                and candidate_type != expected_type
                            ) or (
                                expected_size is not None
                                and candidate_size != expected_size
                            ):
                                raise ValueError(
                                    f"cat-file header mismatch: {bytes(header)!r}"
                                )
                            if candidate_size > maximum_size:
                                raise ValueError("cat-file object exceeds its byte cap")
                            observed_type = candidate_type
                            observed_size = candidate_size
                            payload_remaining = candidate_size
                            digest = hashlib.new(self.info.object_format)
                            digest.update(
                                f"{candidate_type} {candidate_size}\0".encode("ascii")
                            )
                            offset = newline + 1
                            protocol_state = (
                                "payload" if payload_remaining else "delimiter"
                            )
                            continue

                        if protocol_state == "payload":
                            assert payload_remaining is not None
                            assert digest is not None
                            chunk_size = min(
                                len(chunk) - offset,
                                payload_remaining,
                            )
                            payload = chunk[offset : offset + chunk_size]
                            digest.update(payload)
                            if captured is not None:
                                captured.extend(payload)
                            if consumer is not None:
                                consumer(payload)
                            payload_remaining -= chunk_size
                            offset += chunk_size
                            if payload_remaining == 0:
                                protocol_state = "delimiter"
                            continue

                        if chunk[offset : offset + 1] != b"\n":
                            raise ValueError("cat-file payload delimiter is invalid")
                        offset += 1
                        protocol_state = "done"
                        if offset != len(chunk):
                            raise ValueError(
                                "cat-file emitted bytes after the exact response"
                            )

                if protocol_state == "done" and request_offset != len(request):
                    raise ValueError(
                        "cat-file responded before the request was complete"
                    )

            if time.monotonic() >= deadline:
                raise TimeoutError("cat-file object request timed out")
            if (
                digest is None
                or observed_type is None
                or observed_size is None
                or digest.hexdigest() != object_id
            ):
                raise ValueError("raw Git object digest mismatch")
            self.requests += 1
            return (
                observed_type,
                observed_size,
                bytes(captured) if captured is not None else None,
            )
        except BaseException:
            self.abort()
            raise
        finally:
            selector.close()

    def close(self) -> None:
        if self.closed:
            return
        group_settled = False
        try:
            self.process.stdin.close()
            stderr_limit = CAT_FILE_STDERR_LIMIT_BYTES - len(self.stderr)
            if stderr_limit < 0:
                raise OverflowError("cat-file stderr exceeded its byte cap")
            returncode, extra, stderr = _drain_started_process(
                self.process,
                timeout=CAT_FILE_CLOSE_TIMEOUT_SECONDS,
                stdout_limit=1,
                stderr_limit=stderr_limit,
                group_anchor=self.group_anchor,
            )
            group_settled = True
            self.stderr.extend(stderr)
        except (OverflowError, subprocess.TimeoutExpired, TimeoutError) as error:
            self._settle_after_error(error)
            group_settled = True
            raise ValueError(
                "cat-file producer failed or emitted invalid bounded shutdown output"
            ) from error
        except BaseException as error:
            self._settle_after_error(error)
            group_settled = True
            raise
        finally:
            if group_settled:
                for stream in (
                    self.process.stdin,
                    self.process.stdout,
                    self.process.stderr,
                ):
                    if stream is not None and not stream.closed:
                        stream.close()
                self.closed = True
                try:
                    self._cleanup_private_control()
                except BaseException as cleanup_error:
                    raise self._control_cleanup_failure(
                        cleanup_error,
                    ) from cleanup_error
                else:
                    self._finish_signal_scope()
        if extra:
            raise ValueError("cat-file emitted bytes after the exact request stream")
        if len(stderr) > CAT_FILE_STDERR_LIMIT_BYTES or returncode != 0:
            raise ValueError(
                "cat-file producer failed or emitted oversized diagnostics"
            )

    def _settle_after_error(self, error: BaseException) -> None:
        if self.process.returncode is not None:
            return
        try:
            _terminate_process(
                self.process,
                group_anchor=self.group_anchor,
            )
        except BaseException as cleanup_error:
            failure = GitProcessClosureUnproven(
                self.process,
                self.group_anchor,
                cleanup_error,
            )
            self._attach_post_closure_cleanup(failure)
            self._attach_signal_deferral(failure)
            raise failure from error

    def abort(self) -> None:
        if self.closed:
            return
        try:
            if self.process.returncode is None:
                _terminate_process(
                    self.process,
                    group_anchor=self.group_anchor,
                )
        except BaseException as cleanup_error:
            failure = GitProcessClosureUnproven(
                self.process,
                self.group_anchor,
                cleanup_error,
            )
            self._attach_post_closure_cleanup(failure)
            self._attach_signal_deferral(failure)
            raise failure from cleanup_error
        for stream in (
            self.process.stdin,
            self.process.stdout,
            self.process.stderr,
        ):
            if stream is not None and not stream.closed:
                stream.close()
        self.closed = True
        try:
            self._cleanup_private_control()
        except BaseException as cleanup_error:
            raise self._control_cleanup_failure(cleanup_error) from cleanup_error
        else:
            self._finish_signal_scope()

    def __enter__(self) -> "CatFileBatch":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is None:
            self.close()
        else:
            self.abort()


def _parse_commit_tree_id(info: RepositoryInfo, payload: bytes) -> str:
    headers, separator, _ = payload.partition(b"\n\n")
    if not separator:
        raise ValueError("commit object has no header terminator")
    lines = headers.split(b"\n")
    if not lines or not lines[0].startswith(b"tree "):
        raise ValueError("commit object has no leading tree header")
    if any(line.startswith(b"tree ") for line in lines[1:]):
        raise ValueError("commit object has duplicate tree headers")
    raw_tree_id = lines[0][len(b"tree ") :]
    if len(raw_tree_id) != info.object_hex_length or any(
        byte not in b"0123456789abcdef" for byte in raw_tree_id
    ):
        raise ValueError("commit object has a malformed tree ID")
    return raw_tree_id.decode("ascii")


def _parse_raw_tree(
    info: RepositoryInfo,
    payload: bytes,
) -> tuple[AuthenticatedTreeEntry, ...]:
    raw_oid_bytes = info.object_hex_length // 2
    cursor = 0
    entries: list[AuthenticatedTreeEntry] = []
    names: set[bytes] = set()
    previous_key: bytes | None = None
    mode_types = {
        b"40000": (0o040000, "tree"),
        b"100644": (0o100644, "blob"),
        b"100755": (0o100755, "blob"),
        b"120000": (0o120000, "blob"),
        b"160000": (0o160000, "commit"),
    }
    while cursor < len(payload):
        mode_end = payload.find(b" ", cursor)
        if mode_end <= cursor:
            raise ValueError("tree object has a malformed mode")
        name_end = payload.find(b"\0", mode_end + 1)
        if name_end <= mode_end + 1:
            raise ValueError("tree object has a malformed name")
        object_end = name_end + 1 + raw_oid_bytes
        if object_end > len(payload):
            raise ValueError("tree object has a truncated object ID")
        mode_raw = payload[cursor:mode_end]
        try:
            mode, object_type = mode_types[mode_raw]
        except KeyError as error:
            raise ValueError("tree object has an unsupported mode") from error
        name = payload[mode_end + 1 : name_end]
        if b"/" in name or name in {b".", b".."}:
            raise ValueError("tree object has an invalid path component")
        if name in names:
            raise ValueError("tree object has a duplicate path component")
        names.add(name)
        sort_key = name + (b"/" if object_type == "tree" else b"\0")
        if previous_key is not None and sort_key <= previous_key:
            raise ValueError("tree object entries are not in canonical order")
        previous_key = sort_key
        entries.append(
            AuthenticatedTreeEntry(
                mode=mode,
                object_type=object_type,
                object_id=payload[name_end + 1 : object_end].hex(),
                path=name,
            )
        )
        cursor = object_end
    return tuple(entries)


def _authenticated_tree_entries(
    info: RepositoryInfo,
    batch: CatFileBatch,
    *,
    commit: str,
    closure_ids: frozenset[str],
    deadline: float,
) -> tuple[AuthenticatedTreeEntry, ...]:
    object_type, commit_payload = batch.read_object_payload(
        commit,
        allowed_types=frozenset({"commit"}),
        maximum_size=MAX_RANGE_METADATA_OBJECT_BYTES,
        deadline=deadline,
    )
    if object_type != "commit":
        raise ValueError("frozen endpoint object is not a commit")
    root_tree = _parse_commit_tree_id(info, commit_payload)
    if root_tree not in closure_ids:
        raise ValueError("metadata closure omits an endpoint root tree")

    tree_cache: dict[str, tuple[AuthenticatedTreeEntry, ...]] = {}
    aggregate_tree_bytes = 0

    def load_tree(tree_id: str) -> tuple[AuthenticatedTreeEntry, ...]:
        nonlocal aggregate_tree_bytes
        cached = tree_cache.get(tree_id)
        if cached is not None:
            return cached
        if tree_id not in closure_ids:
            raise ValueError("metadata closure omits a reachable subtree")
        remaining = MAX_TREE_METADATA_BYTES - aggregate_tree_bytes
        candidate_type, tree_payload = batch.read_object_payload(
            tree_id,
            allowed_types=frozenset({"tree"}),
            maximum_size=min(
                MAX_RANGE_METADATA_OBJECT_BYTES,
                max(0, remaining),
            ),
            deadline=deadline,
        )
        if candidate_type != "tree":
            raise ValueError("reachable subtree object is not a tree")
        aggregate_tree_bytes += len(tree_payload)
        if aggregate_tree_bytes > MAX_TREE_METADATA_BYTES:
            raise ValueError("authenticated tree metadata exceeds its byte cap")
        parsed = _parse_raw_tree(info, tree_payload)
        tree_cache[tree_id] = parsed
        return parsed

    flattened: list[AuthenticatedTreeEntry] = []
    active: set[str] = set()
    accounted_bytes = 0
    stack: list[tuple[bool, str, bytes]] = [(True, root_tree, b"")]
    while stack:
        entering, tree_id, prefix = stack.pop()
        if not entering:
            active.remove(tree_id)
            continue
        if tree_id in active:
            raise ValueError("authenticated tree graph contains a cycle")
        active.add(tree_id)
        stack.append((False, tree_id, prefix))
        entries = load_tree(tree_id)
        for entry in reversed(entries):
            path = entry.path if not prefix else prefix + b"/" + entry.path
            validate_raw_path(path)
            accounted_bytes += len(path) + 128
            if accounted_bytes > MAX_TREE_METADATA_BYTES:
                raise ValueError(
                    "authenticated flattened tree exceeds its metadata cap"
                )
            if entry.object_type == "tree":
                stack.append((True, entry.object_id, path))
                continue
            flattened.append(
                AuthenticatedTreeEntry(
                    mode=entry.mode,
                    object_type=entry.object_type,
                    object_id=entry.object_id,
                    path=path,
                )
            )
            if len(flattened) > MAX_TREE_ENTRIES:
                raise ValueError("authenticated tree exceeds its entry cap")
    flattened.sort(key=lambda entry: entry.path)
    if any(
        current.path <= previous.path
        for previous, current in zip(flattened, flattened[1:])
    ):
        raise ValueError("authenticated flattened paths are not unique")
    return tuple(flattened)


def _require_manifest_matches_authenticated_tree(
    manifest: TreeManifest,
    authenticated: tuple[AuthenticatedTreeEntry, ...],
) -> None:
    observed = tuple(
        AuthenticatedTreeEntry(
            mode=entry.mode,
            object_type=entry.object_type,
            object_id=entry.object_id,
            path=entry.path,
        )
        for entry in manifest.entries
    )
    if observed != authenticated:
        raise blocked(
            "ls-tree manifest differs from raw authenticated tree objects",
            stage="range-object-verification",
            code="range-tree-manifest-mismatch",
        )


def _verify_reachable_metadata_objects(
    info: RepositoryInfo,
) -> RangeMetadataReceipt:
    deadline = time.monotonic() + RANGE_METADATA_VERIFY_SECONDS
    try:
        with temporary_git_control(info) as control:
            argv = _git_control_argv(
                info,
                control,
                "rev-list",
                "--objects",
                "--no-object-names",
                "--filter=blob:none",
                info.base_sha,
                info.head_sha,
                "--",
            )
            code, stdout, stderr = run_bounded(
                argv,
                cwd=control.path.parent,
                environment=_git_control_environment(info, control),
                timeout=max(0.001, deadline - time.monotonic()),
                stdout_limit=MAX_RANGE_METADATA_LIST_BYTES,
                stderr_limit=8192,
            )
        if code != 0:
            raise ValueError(_git_error(argv, stderr))
        if stderr:
            raise ValueError("metadata closure enumeration emitted diagnostics")
        if not stdout or not stdout.endswith(b"\n"):
            raise ValueError("metadata closure output is not line-terminated")
        raw_ids = stdout[:-1].split(b"\n")
        if len(raw_ids) > MAX_RANGE_METADATA_OBJECTS:
            raise ValueError("metadata closure exceeds its object-count cap")

        object_ids: list[str] = []
        seen: set[str] = set()
        for raw_id in raw_ids:
            if len(raw_id) != info.object_hex_length or any(
                byte not in b"0123456789abcdef" for byte in raw_id
            ):
                raise ValueError("metadata closure contains a malformed object ID")
            object_id = raw_id.decode("ascii")
            if object_id in seen:
                raise ValueError("metadata closure contains a duplicate object ID")
            seen.add(object_id)
            object_ids.append(object_id)
        if info.base_sha not in seen or info.head_sha not in seen:
            raise ValueError("metadata closure omits a frozen endpoint commit")
        object_ids.sort()

        aggregate_bytes = 0
        endpoint_types: dict[str, str] = {}
        receipt = hashlib.sha256()
        with CatFileBatch(info) as batch:
            for object_id in object_ids:
                remaining = MAX_RANGE_METADATA_AGGREGATE_BYTES - aggregate_bytes
                object_type, size = batch.verify_object(
                    object_id,
                    allowed_types=frozenset({"commit", "tree", "tag"}),
                    maximum_size=min(
                        MAX_RANGE_METADATA_OBJECT_BYTES,
                        max(0, remaining),
                    ),
                    deadline=deadline,
                )
                aggregate_bytes += size
                if aggregate_bytes > MAX_RANGE_METADATA_AGGREGATE_BYTES:
                    raise ValueError("metadata closure exceeds its aggregate byte cap")
                if object_id in {info.base_sha, info.head_sha}:
                    endpoint_types[object_id] = object_type
                receipt.update(f"{object_id} {object_type} {size}\0".encode("ascii"))
        if any(
            endpoint_types.get(endpoint) != "commit"
            for endpoint in {info.base_sha, info.head_sha}
        ):
            raise ValueError("frozen endpoint object is not a commit")
        return RangeMetadataReceipt(
            object_count=len(object_ids),
            aggregate_bytes=aggregate_bytes,
            sha256=receipt.hexdigest(),
            object_ids=frozenset(object_ids),
        )
    except GitProcessClosureUnproven:
        raise
    except (TimeoutError, OverflowError) as error:
        raise inconclusive(
            f"reachable metadata verification did not complete safely: {error}",
            stage="range-object-verification",
            code="range-object-verification-bounded-failure",
        ) from error
    except (OSError, UnicodeError, ValueError) as error:
        raise blocked(
            f"reachable metadata verification failed: {error}",
            stage="range-object-verification",
            code="range-object-verification-failed",
        ) from error


def authenticated_range_manifests(
    info: RepositoryInfo,
) -> tuple[TreeManifest, TreeManifest]:
    closure = _verify_reachable_metadata_objects(info)
    deadline = time.monotonic() + RANGE_METADATA_VERIFY_SECONDS
    try:
        with CatFileBatch(info) as batch:
            authenticated_base = _authenticated_tree_entries(
                info,
                batch,
                commit=info.base_sha,
                closure_ids=closure.object_ids,
                deadline=deadline,
            )
            authenticated_head = _authenticated_tree_entries(
                info,
                batch,
                commit=info.head_sha,
                closure_ids=closure.object_ids,
                deadline=deadline,
            )
    except GitProcessClosureUnproven:
        raise
    except (TimeoutError, OverflowError) as error:
        raise inconclusive(
            f"endpoint tree authentication did not complete safely: {error}",
            stage="range-object-verification",
            code="range-tree-authentication-bounded-failure",
        ) from error
    except (OSError, UnicodeError, ValueError) as error:
        raise blocked(
            f"endpoint tree authentication failed: {error}",
            stage="range-object-verification",
            code="range-tree-authentication-failed",
        ) from error
    base = enumerate_tree(info, info.base_sha)
    head = enumerate_tree(info, info.head_sha)
    _require_manifest_matches_authenticated_tree(base, authenticated_base)
    _require_manifest_matches_authenticated_tree(head, authenticated_head)
    return base, head


def control_git_dir_for_worktree(path: pathlib.Path) -> pathlib.Path:
    return path.parent / f".{path.name}.git-control"


def add_detached_worktree(
    info: RepositoryInfo,
    path: pathlib.Path,
    *,
    lock_reason: str = "independent-codex-pr-review",
    control: GitControlBinding | None = None,
) -> WorktreeRegistration:
    if (
        not isinstance(lock_reason, str)
        or not lock_reason
        or len(lock_reason.encode("utf-8")) > 512
        or any(character in lock_reason for character in ("\0", "\r", "\n"))
    ):
        raise ValueError("worktree lock reason is invalid")
    if control is None:
        control = create_sanitized_view(
            info,
            control_git_dir_for_worktree(path),
        )
    else:
        revalidate_git_control(info, control)
    argv = _git_control_argv(
        info,
        control,
        "worktree",
        "add",
        "--detach",
        "--no-checkout",
        "--no-guess-remote",
        "--lock",
        "--reason",
        lock_reason,
        str(path),
        info.head_sha,
    )
    code, _, stderr = run_bounded(
        argv,
        cwd=path.parent,
        environment=_git_control_environment(info, control),
        timeout=120,
        stdout_limit=8 * 1024 * 1024,
        stderr_limit=8 * 1024 * 1024,
    )
    if code != 0:
        raise ValueError(_git_error(argv, stderr))
    worktree_fd, worktree_identity = open_absolute_directory_chain(path)
    try:
        names = raw_directory_entries(path, cap=2)
        if names != (b".git",):
            raise ValueError("new no-checkout worktree does not contain only .git")
        marker_fd, marker_identity = open_regular_nofollow(
            path / ".git",
            expected_uid=os.getuid(),
        )
        try:
            marker = read_fd_exact(
                marker_fd, max_bytes=4096, expected_size=marker_identity.size
            )
        finally:
            os.close(marker_fd)
    finally:
        os.close(worktree_fd)
    if (
        not marker.startswith(b"gitdir: ")
        or not marker.endswith(b"\n")
        or marker.count(b"\n") != 1
    ):
        raise ValueError("linked-worktree .git marker is malformed")
    registration = pathlib.Path(os.fsdecode(marker[len(b"gitdir: ") : -1])).resolve(
        strict=True
    )
    expected_parent = (control.path / "worktrees").resolve(strict=True)
    if registration.parent != expected_parent:
        raise ValueError(
            "worktree registration is outside the common Git worktrees directory"
        )
    registration_fd, registration_identity = open_absolute_directory_chain(registration)
    try:
        locked_fd, locked_identity = open_regular_at(
            registration_fd,
            b"locked",
            expected_uid=os.getuid(),
            private_metadata=True,
        )
        try:
            locked = read_fd_exact(
                locked_fd,
                max_bytes=513,
                expected_size=locked_identity.size,
            )
        finally:
            os.close(locked_fd)
        if locked != lock_reason.encode("utf-8") + b"\n":
            raise ValueError("worktree lock reason differs from its creation intent")
        count, path_bytes = enumerate_registration_fd(registration_fd)
    finally:
        os.close(registration_fd)
    return WorktreeRegistration(
        worktree=path,
        registration=registration,
        control=control,
        worktree_identity=worktree_identity,
        registration_identity=registration_identity,
        marker_identity=marker_identity,
        descendant_count=count,
        descendant_path_bytes=path_bytes,
    )


def enumerate_registration_fd(root_fd: int) -> tuple[int, int]:
    count = 0
    path_bytes = 0
    stack: list[tuple[int, bytes]] = [(os.dup(root_fd), b"")]
    try:
        while stack:
            current_fd, prefix = stack.pop()
            try:
                names = tuple(os.fsencode(name) for name in os.listdir(current_fd))
                if len(names) > REGISTRATION_DESCENDANT_COUNT_CAP + 1:
                    raise ValueError("worktree registration exceeds its descendant cap")
                for name in names:
                    relative = name if not prefix else prefix + b"/" + name
                    count += 1
                    path_bytes += len(relative)
                    if (
                        count > REGISTRATION_DESCENDANT_COUNT_CAP
                        or path_bytes > REGISTRATION_PATH_BYTES_CAP
                    ):
                        raise ValueError(
                            "worktree registration exceeds its reserved manifest bounds"
                        )
                    metadata = os.stat(
                        name,
                        dir_fd=current_fd,
                        follow_symlinks=False,
                    )
                    if stat.S_ISDIR(metadata.st_mode):
                        child_fd = os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=current_fd,
                        )
                        if not directory_identities_match(
                            identity_from_stat(os.fstat(child_fd)),
                            identity_from_stat(metadata),
                        ):
                            os.close(child_fd)
                            raise OSError(
                                errno.ESTALE,
                                "worktree registration directory identity changed",
                            )
                        stack.append((child_fd, relative))
            finally:
                os.close(current_fd)
        return count, path_bytes
    finally:
        for pending_fd, _ in stack:
            os.close(pending_fd)


def enumerate_registration(path: pathlib.Path) -> tuple[int, int]:
    root_fd = open_directory(path)
    try:
        return enumerate_registration_fd(root_fd)
    finally:
        os.close(root_fd)


def initialize_index(info: RepositoryInfo, registration: WorktreeRegistration) -> None:
    environment = _git_control_environment(
        info,
        registration.control,
        {
            "GIT_WORK_TREE": str(registration.worktree),
            "GIT_INDEX_FILE": str(registration.registration / "index"),
        },
    )
    argv = _git_control_argv(
        info,
        registration.control,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.sparseCheckout=false",
        "-c",
        "core.sparseCheckoutCone=false",
        "-c",
        "core.splitIndex=false",
        "-c",
        "core.untrackedCache=false",
        "read-tree",
        "--reset",
        info.head_sha,
    )
    code, _, stderr = run_bounded(
        argv,
        cwd=registration.worktree,
        environment=environment,
        timeout=60,
        stdout_limit=8192,
        stderr_limit=8192,
    )
    if code != 0:
        raise ValueError(_git_error(argv, stderr))


def _git_control_config(info: RepositoryInfo) -> bytes:
    repository_format_version = 1 if info.object_format == "sha256" else 0
    config = (
        b"[core]\n\trepositoryformatversion = "
        + str(repository_format_version).encode("ascii")
        + b"\n\tbare = true\n"
        + b"\thooksPath = /dev/null\n"
        + b"\tfsmonitor = false\n"
    )
    if info.object_format == "sha256":
        config += b"[extensions]\n\tobjectFormat = sha256\n"
    return config


def _read_git_control_binding_once(
    info: RepositoryInfo,
    view: pathlib.Path,
) -> GitControlBinding:
    view_fd, root_identity = open_absolute_directory_chain(
        view,
        private_leaf=True,
    )
    try:
        config_fd, config_identity = open_regular_at(
            view_fd,
            b"config",
            expected_uid=os.getuid(),
            private_metadata=True,
        )
        try:
            if stat.S_IMODE(config_identity.mode) != 0o400:
                raise OSError(
                    errno.EPERM,
                    "private Git control config access policy is unsafe",
                )
            config = read_fd_exact(
                config_fd,
                max_bytes=LOCAL_CONFIG_BYTES_LIMIT,
                expected_size=config_identity.size,
            )
        finally:
            os.close(config_fd)
    finally:
        os.close(view_fd)
    expected = _git_control_config(info)
    if config != expected:
        raise ValueError("private Git control config content mismatched")
    return GitControlBinding(
        path=view,
        root_identity=root_identity,
        config_identity=config_identity,
        config_sha256=hashlib.sha256(config).hexdigest(),
    )


def _read_git_control_binding(
    info: RepositoryInfo,
    view: pathlib.Path,
) -> GitControlBinding:
    for attempt in range(2):
        try:
            return _read_git_control_binding_once(info, view)
        except OSError as error:
            if error.errno != errno.ESTALE or attempt:
                raise
    raise AssertionError("unreachable Git control revalidation state")


def revalidate_git_control(
    info: RepositoryInfo,
    control: GitControlBinding,
) -> None:
    observed = _read_git_control_binding(info, control.path)
    if not directory_identities_match(
        observed.root_identity,
        control.root_identity,
    ):
        raise OSError(
            errno.ESTALE,
            "private Git control directory identity or access policy changed",
        )
    if observed.config_identity != control.config_identity:
        raise OSError(
            errno.ESTALE,
            "private Git control config identity or access policy changed",
        )
    if observed.config_sha256 != control.config_sha256:
        raise OSError(
            errno.ESTALE,
            "private Git control config content changed",
        )


def create_sanitized_view(
    info: RepositoryInfo,
    view: pathlib.Path,
) -> GitControlBinding:
    parent_fd, _ = open_absolute_directory_chain(view.parent, private_leaf=True)
    view_fd: int | None = None
    try:
        os.mkdir(os.fsencode(view.name), 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        view_fd = os.open(
            os.fsencode(view.name),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        validate_private_directory_fd(view_fd, view)
        for name in ("objects", "refs", "worktrees"):
            os.mkdir(os.fsencode(name), 0o700, dir_fd=view_fd)
            child_fd = os.open(
                os.fsencode(name),
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=view_fd,
            )
            try:
                validate_private_directory_fd(child_fd, view / name)
            finally:
                os.close(child_fd)
        os.fsync(view_fd)
    finally:
        if view_fd is not None:
            os.close(view_fd)
        os.close(parent_fd)
    publish_bytes(view / "config", _git_control_config(info), mode=0o400)
    publish_bytes(view / "HEAD", b"ref: refs/heads/invalid\n")
    return _read_git_control_binding(info, view)


def remove_sanitized_view(view: pathlib.Path, *, allow_partial: bool = False) -> None:
    parent_fd = open_directory(view.parent)
    view_fd: int | None = None
    objects_fd: int | None = None
    refs_fd: int | None = None
    worktrees_fd: int | None = None
    try:
        view_fd = os.open(
            os.fsencode(view.name),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        validate_private_directory_fd(view_fd, view)
        view_stat = os.fstat(view_fd)
        if view_stat.st_uid != os.getuid() or stat.S_IMODE(view_stat.st_mode) != 0o700:
            raise ValueError("sanitized Git view root identity is unsafe")
        names = {os.fsencode(value) for value in os.listdir(view_fd)}
        required_names = {b"HEAD", b"config", b"objects", b"refs"}
        expected_names = required_names | {b"worktrees"}
        if (
            not allow_partial and not required_names <= names
        ) or not names <= expected_names:
            rendered = sorted(os.fsdecode(name) for name in names)
            raise ValueError(f"sanitized Git view entry set changed: {rendered!r}")
        for name in (b"HEAD", b"config"):
            if name not in names:
                continue
            metadata = os.stat(name, dir_fd=view_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise ValueError("sanitized Git view file identity is unsafe")
        if b"objects" in names:
            objects_fd = os.open(
                b"objects",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=view_fd,
            )
            objects_stat = os.fstat(objects_fd)
            if (
                objects_stat.st_uid != os.getuid()
                or stat.S_IMODE(objects_stat.st_mode) != 0o700
                or os.listdir(objects_fd)
            ):
                raise ValueError("sanitized Git object view is not empty and private")
        if b"refs" in names:
            refs_fd = os.open(
                b"refs",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=view_fd,
            )
            refs_stat = os.fstat(refs_fd)
            if (
                refs_stat.st_uid != os.getuid()
                or stat.S_IMODE(refs_stat.st_mode) != 0o700
                or os.listdir(refs_fd)
            ):
                raise ValueError("sanitized Git refs view is not empty and private")
        if b"worktrees" in names:
            worktrees_fd = os.open(
                b"worktrees",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=view_fd,
            )
            worktrees_stat = os.fstat(worktrees_fd)
            if (
                worktrees_stat.st_uid != os.getuid()
                or stat.S_IMODE(worktrees_stat.st_mode) != 0o700
                or os.listdir(worktrees_fd)
            ):
                raise ValueError(
                    "sanitized Git worktree registry is not empty and private"
                )
        for name in (b"HEAD", b"config"):
            if name in names:
                os.unlink(name, dir_fd=view_fd)
        if objects_fd is not None:
            os.close(objects_fd)
            objects_fd = None
            os.rmdir(b"objects", dir_fd=view_fd)
        if refs_fd is not None:
            os.close(refs_fd)
            refs_fd = None
            os.rmdir(b"refs", dir_fd=view_fd)
        if worktrees_fd is not None:
            os.close(worktrees_fd)
            worktrees_fd = None
            os.rmdir(b"worktrees", dir_fd=view_fd)
        os.fsync(view_fd)
        os.close(view_fd)
        view_fd = None
        os.rmdir(os.fsencode(view.name), dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if objects_fd is not None:
            os.close(objects_fd)
        if refs_fd is not None:
            os.close(refs_fd)
        if worktrees_fd is not None:
            os.close(worktrees_fd)
        if view_fd is not None:
            os.close(view_fd)
        os.close(parent_fd)


def _view_environment(
    info: RepositoryInfo,
    registration: WorktreeRegistration,
    view: GitControlBinding,
) -> dict[str, str]:
    return _git_control_environment(
        info,
        view,
        {
            "GIT_INDEX_FILE": str(registration.registration / "index"),
        },
    )


def check_attributes(
    info: RepositoryInfo,
    registration: WorktreeRegistration,
    view: GitControlBinding,
    paths: tuple[bytes, ...],
) -> None:
    input_bytes = b"\0".join(paths) + b"\0"
    accepted_value_bytes = len(b"unspecified")
    fixed_record_bytes = (
        len(b"filter") + len(b"working-tree-encoding") + accepted_value_bytes * 2 + 6
    )
    stdout_limit = max(
        8192,
        sum(len(path) * 2 + fixed_record_bytes for path in paths),
    )
    argv = (
        info.git_executable,
        "-c",
        "core.attributesFile=/dev/null",
        "check-attr",
        "--cached",
        "-z",
        "--stdin",
        "filter",
        "working-tree-encoding",
    )
    code, stdout, stderr = run_bounded(
        argv,
        cwd=registration.worktree,
        environment=_view_environment(info, registration, view),
        timeout=120,
        stdout_limit=stdout_limit,
        stderr_limit=8192,
        input_bytes=input_bytes,
    )
    if code != 0:
        raise ValueError(_git_error(argv, stderr))
    fields = stdout.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) != len(paths) * 6:
        raise ValueError("check-attr returned an unexpected record count")
    for offset, path in enumerate(paths):
        first_path, first_attr, first_value, second_path, second_attr, second_value = (
            fields[offset * 6 : offset * 6 + 6]
        )
        if (first_path, first_attr, second_path, second_attr) != (
            path,
            b"filter",
            path,
            b"working-tree-encoding",
        ):
            raise ValueError("check-attr returned an unexpected path or attribute")
        for value in (first_value, second_value):
            if value not in {b"unspecified", b"unset"}:
                raise blocked(
                    f"path has conversion attributes: {os.fsdecode(path)}",
                    stage="checkout-attributes",
                    code="blocked-checkout-attributes",
                )


def verify_index(
    info: RepositoryInfo,
    registration: WorktreeRegistration,
    view: GitControlBinding,
    manifest: TreeManifest,
) -> None:
    argv = (info.git_executable, "ls-files", "--stage", "-z")
    code, stdout, stderr = run_bounded(
        argv,
        cwd=registration.worktree,
        environment=_view_environment(info, registration, view),
        timeout=120,
        stdout_limit=MAX_TREE_METADATA_BYTES,
        stderr_limit=8192,
    )
    if code != 0:
        raise ValueError(_git_error(argv, stderr))
    expected = b"".join(
        f"{entry.mode:06o} {entry.object_id} 0\t".encode("ascii") + entry.path + b"\0"
        for entry in manifest.entries
    )
    if stdout != expected:
        raise ValueError("frozen index does not exactly match the head manifest")


def remove_both_present_worktree(
    info: RepositoryInfo,
    registration: WorktreeRegistration,
) -> None:
    for subcommand in (
        ("worktree", "unlock", str(registration.worktree)),
        ("worktree", "remove", "--force", str(registration.worktree)),
    ):
        argv = _git_control_argv(info, registration.control, *subcommand)
        code, _, stderr = run_bounded(
            argv,
            cwd=registration.worktree.parent,
            environment=_git_control_environment(info, registration.control),
            timeout=120,
            stdout_limit=8192,
            stderr_limit=8192,
        )
        if code != 0:
            raise ValueError(_git_error(argv, stderr))


def verify_worktree_absent(
    info: RepositoryInfo,
    worktree: pathlib.Path,
    control: GitControlBinding,
) -> None:
    try:
        os.lstat(worktree)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("worktree path still exists after removal")
    revalidate_git_control(info, control)
    registrations_parent = control.path / "worktrees"
    try:
        parent_fd = open_directory(registrations_parent)
    except FileNotFoundError:
        return
    try:
        names = tuple(os.fsencode(name) for name in os.listdir(parent_fd))
        if len(names) > 100_000:
            raise ValueError("common Git worktree namespace exceeds its inspection cap")
        expected_marker = worktree / ".git"
        for name in names:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(
                    "common Git worktree namespace contains a non-directory"
                )
            registration_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                try:
                    gitdir_fd, gitdir_identity = open_regular_at(
                        registration_fd,
                        b"gitdir",
                        expected_uid=os.getuid(),
                    )
                except FileNotFoundError:
                    continue
                try:
                    raw = read_fd_exact(
                        gitdir_fd,
                        max_bytes=4096,
                        expected_size=gitdir_identity.size,
                    )
                finally:
                    os.close(gitdir_fd)
                target = pathlib.Path(os.fsdecode(raw.strip()))
                if target == expected_marker:
                    raise ValueError(
                        "an alias Git registration still references the removed worktree"
                    )
            finally:
                os.close(registration_fd)
    finally:
        os.close(parent_fd)
