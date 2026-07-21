from __future__ import annotations

import hashlib
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

from .constants import (
    MAX_BLOB_BYTES,
    MAX_RAW_BLOB_BYTES,
    MAX_SYMLINK_BYTES,
    MAX_TREE_ENTRIES,
    MAX_TREE_METADATA_BYTES,
    REGISTRATION_DESCENDANT_COUNT_CAP,
    REGISTRATION_PATH_BYTES_CAP,
)
from .errors import blocked, inconclusive
from .models import Identity, TreeEntry, TreeManifest
from .process import (
    SpawnedProcess,
    process_start_identity,
    signal_anchored_group,
    wait_terminal,
)
from .secureio import (
    open_absolute_directory_chain,
    open_directory,
    open_regular_at,
    open_regular_nofollow,
    publish_bytes,
    raw_directory_entries,
    read_fd_exact,
    validate_private_directory_fd,
)


CAT_FILE_CLOSE_TIMEOUT_SECONDS = 5.0
CAT_FILE_READ_TIMEOUT_SECONDS = 30.0
CAT_FILE_STDERR_LIMIT_BYTES = 8192
CAT_FILE_TERMINATE_GRACE_SECONDS = 0.1
CAT_FILE_TERMINATE_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class RepositoryInfo:
    repo: pathlib.Path
    common_git_dir: pathlib.Path
    object_format: str
    object_hex_length: int
    base_sha: str
    head_sha: str
    git_executable: str


@dataclass(frozen=True)
class WorktreeRegistration:
    worktree: pathlib.Path
    registration: pathlib.Path
    worktree_identity: Identity
    registration_identity: Identity
    marker_identity: Identity
    descendant_count: int
    descendant_path_bytes: int


def sanitized_git_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
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
        raise ValueError("cat-file process group is not bound to its leader")

    deadline = time.monotonic() + CAT_FILE_TERMINATE_TIMEOUT_SECONDS
    signal_anchored_group(group_anchor, signal.SIGTERM)
    grace_deadline = min(
        deadline,
        time.monotonic() + CAT_FILE_TERMINATE_GRACE_SECONDS,
    )
    while time.monotonic() < grace_deadline:
        time.sleep(min(0.01, grace_deadline - time.monotonic()))
    signal_anchored_group(group_anchor, signal.SIGKILL)

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("cat-file process-group termination timed out")
    return process.wait(timeout=remaining)


def _abort_unanchored_fresh_session(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=CAT_FILE_TERMINATE_TIMEOUT_SECONDS)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


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
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=False,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_process(process)
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
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded Git command timed out")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ) for key in selector.get_map().values()
                ]
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
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bounded Git command timed out before reap")
        returncode = process.wait(timeout=remaining)
        return (
            returncode,
            bytes(buffers[process.stdout.fileno()]),
            bytes(buffers[process.stderr.fileno()]),
        )
    except BaseException:
        _terminate_process(process)
        raise
    finally:
        selector.close()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        process.stderr.close()


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
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded Git shutdown timed out")
            events = selector.select(min(remaining, 0.25))
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


def inspect_repository(
    *,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
    git_executable: str,
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
    environment = sanitized_git_environment()

    def query(*arguments: str, cap: int = 8192) -> bytes:
        argv = (
            str(executable),
            "-C",
            str(canonical_repo),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            *arguments,
        )
        code, stdout, stderr = run_bounded(
            argv,
            cwd=canonical_repo,
            environment=environment,
            timeout=15,
            stdout_limit=cap,
            stderr_limit=8192,
        )
        if code != 0:
            raise ValueError(_git_error(argv, stderr))
        return stdout.strip()

    try:
        common_raw = query("rev-parse", "--path-format=absolute", "--git-common-dir")
        format_raw = query("rev-parse", "--show-object-format")
        resolved_base = query("rev-parse", "--verify", f"{base_sha}^{{commit}}")
        resolved_head = query("rev-parse", "--verify", f"{head_sha}^{{commit}}")
        common = pathlib.Path(os.fsdecode(common_raw)).resolve(strict=True)
        if format_raw not in {b"sha1", b"sha256"}:
            raise ValueError("repository object format is unsupported")
        object_format = format_raw.decode("ascii")
        width = 40 if object_format == "sha1" else 64
        if (
            resolved_base.decode("ascii") != base_sha
            or resolved_head.decode("ascii") != head_sha
        ):
            raise ValueError(
                "requested range does not resolve to the exact supplied commits"
            )
        if len(base_sha) != width or len(head_sha) != width:
            raise ValueError("commit IDs do not match the repository object format")
        common_fd, _ = open_absolute_directory_chain(common)
        os.close(common_fd)
        objects = common / "objects"
        objects_fd, _ = open_absolute_directory_chain(objects)
        os.close(objects_fd)
        return RepositoryInfo(
            repo=canonical_repo,
            common_git_dir=common,
            object_format=object_format,
            object_hex_length=width,
            base_sha=base_sha,
            head_sha=head_sha,
            git_executable=str(executable),
        )
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


def enumerate_tree(info: RepositoryInfo, commit: str) -> TreeManifest:
    argv = (
        info.git_executable,
        "--git-dir",
        str(info.common_git_dir),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "ls-tree",
        "-rz",
        "-l",
        "--full-tree",
        "-r",
        commit,
    )
    try:
        code, stdout, stderr = run_bounded(
            argv,
            cwd=info.repo,
            environment=sanitized_git_environment(),
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
        argv = (
            info.git_executable,
            "--git-dir",
            str(info.common_git_dir),
            "-c",
            "core.hooksPath=/dev/null",
            "cat-file",
            "--batch",
        )
        self.process = subprocess.Popen(
            argv,
            cwd=info.repo,
            env=sanitized_git_environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
        self.process_group = self.process.pid
        try:
            start_identity = process_start_identity(self.process.pid)
        except BaseException:
            _abort_unanchored_fresh_session(self.process)
            raise
        self.group_anchor = SpawnedProcess(
            pid=self.process.pid,
            pgid=self.process_group,
            acknowledgement_fd=-1,
            passed_fd_numbers=(),
            start_identity=start_identity,
        )
        if (
            self.process.stdin is None
            or self.process.stdout is None
            or self.process.stderr is None
        ):
            _terminate_process(
                self.process,
                group_anchor=self.group_anchor,
            )
            raise RuntimeError("cannot create cat-file batch pipes")
        self.requests = 0
        self.closed = False
        self.stderr = bytearray()

    def read_blob(
        self,
        entry: TreeEntry,
        *,
        consumer: Callable[[bytes], None] | None = None,
        capture: bool = False,
    ) -> bytes | None:
        if self.closed or entry.size is None or entry.object_type != "blob":
            raise ValueError("invalid cat-file blob request")
        request = entry.object_id.encode("ascii") + b"\n"
        expected_header = f"{entry.object_id} blob {entry.size}".encode("ascii")
        digest = hashlib.new(self.info.object_format)
        digest.update(f"blob {entry.size}\0".encode("ascii"))
        payload_remaining = entry.size
        captured = bytearray() if capture else None
        header = bytearray()
        request_offset = 0
        protocol_state = "header"
        deadline = time.monotonic() + CAT_FILE_READ_TIMEOUT_SECONDS
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
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise TimeoutError("cat-file blob request timed out")
                events = selector.select(min(remaining_time, 0.25))
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
                            if header != expected_header:
                                raise ValueError(
                                    f"cat-file header mismatch: {bytes(header)!r}"
                                )
                            offset = newline + 1
                            protocol_state = (
                                "payload" if payload_remaining else "delimiter"
                            )
                            continue

                        if protocol_state == "payload":
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
                raise TimeoutError("cat-file blob request timed out")
            if digest.hexdigest() != entry.object_id:
                raise ValueError("raw Git blob digest mismatch")
            self.requests += 1
            return bytes(captured) if captured is not None else None
        except BaseException:
            self.abort()
            raise
        finally:
            selector.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
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
            self.stderr.extend(stderr)
        except (OverflowError, subprocess.TimeoutExpired, TimeoutError) as error:
            raise ValueError(
                "cat-file producer failed or emitted invalid bounded shutdown output"
            ) from error
        except BaseException:
            _terminate_process(
                self.process,
                group_anchor=self.group_anchor,
            )
            for stream in (
                self.process.stdin,
                self.process.stdout,
                self.process.stderr,
            ):
                if stream is not None and not stream.closed:
                    stream.close()
            raise
        if extra:
            raise ValueError("cat-file emitted bytes after the exact request stream")
        if len(stderr) > CAT_FILE_STDERR_LIMIT_BYTES or returncode != 0:
            raise ValueError(
                "cat-file producer failed or emitted oversized diagnostics"
            )

    def abort(self) -> None:
        if not self.closed:
            self.closed = True
            _terminate_process(
                self.process,
                group_anchor=self.group_anchor,
            )
            for stream in (
                self.process.stdin,
                self.process.stdout,
                self.process.stderr,
            ):
                if stream is not None:
                    stream.close()

    def __enter__(self) -> "CatFileBatch":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is None:
            self.close()
        else:
            self.abort()


def _git_worktree_argv(info: RepositoryInfo, *args: str) -> tuple[str, ...]:
    return (
        info.git_executable,
        "-C",
        str(info.repo),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        *args,
    )


def add_detached_worktree(
    info: RepositoryInfo, path: pathlib.Path
) -> WorktreeRegistration:
    argv = _git_worktree_argv(
        info,
        "worktree",
        "add",
        "--detach",
        "--no-checkout",
        "--no-guess-remote",
        "--lock",
        "--reason",
        "independent-codex-pr-review",
        str(path),
        info.head_sha,
    )
    code, _, stderr = run_bounded(
        argv,
        cwd=info.repo,
        environment=sanitized_git_environment(),
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
    expected_parent = (info.common_git_dir / "worktrees").resolve(strict=True)
    if registration.parent != expected_parent:
        raise ValueError(
            "worktree registration is outside the common Git worktrees directory"
        )
    registration_fd, registration_identity = open_absolute_directory_chain(registration)
    os.close(registration_fd)
    count, path_bytes = enumerate_registration(registration)
    return WorktreeRegistration(
        worktree=path,
        registration=registration,
        worktree_identity=worktree_identity,
        registration_identity=registration_identity,
        marker_identity=marker_identity,
        descendant_count=count,
        descendant_path_bytes=path_bytes,
    )


def enumerate_registration(path: pathlib.Path) -> tuple[int, int]:
    count = 0
    path_bytes = 0
    stack: list[tuple[pathlib.Path, bytes]] = [(path, b"")]
    while stack:
        current, prefix = stack.pop()
        current_fd = open_directory(current)
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
                metadata = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    stack.append((current / os.fsdecode(name), relative))
        finally:
            os.close(current_fd)
    return count, path_bytes


def initialize_index(info: RepositoryInfo, registration: WorktreeRegistration) -> None:
    environment = sanitized_git_environment(
        {
            "GIT_DIR": str(registration.registration),
            "GIT_WORK_TREE": str(registration.worktree),
        }
    )
    argv = (
        info.git_executable,
        "-c",
        "core.hooksPath=/dev/null",
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


def create_sanitized_view(info: RepositoryInfo, view: pathlib.Path) -> None:
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
        for name in ("objects", "refs"):
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
    repository_format_version = 1 if info.object_format == "sha256" else 0
    config = (
        b"[core]\n\trepositoryformatversion = "
        + str(repository_format_version).encode("ascii")
        + b"\n\tbare = true\n"
    )
    if info.object_format == "sha256":
        config += b"[extensions]\n\tobjectFormat = sha256\n"
    publish_bytes(view / "config", config)
    publish_bytes(view / "HEAD", b"ref: refs/heads/invalid\n")


def remove_sanitized_view(view: pathlib.Path, *, allow_partial: bool = False) -> None:
    parent_fd = open_directory(view.parent)
    view_fd: int | None = None
    objects_fd: int | None = None
    refs_fd: int | None = None
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
        expected_names = {b"HEAD", b"config", b"objects", b"refs"}
        if (
            not allow_partial and names != expected_names
        ) or not names <= expected_names:
            raise ValueError("sanitized Git view entry set changed")
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
        if view_fd is not None:
            os.close(view_fd)
        os.close(parent_fd)


def _view_environment(
    info: RepositoryInfo,
    registration: WorktreeRegistration,
    view: pathlib.Path,
) -> dict[str, str]:
    return sanitized_git_environment(
        {
            "GIT_DIR": str(view),
            "GIT_INDEX_FILE": str(registration.registration / "index"),
            "GIT_OBJECT_DIRECTORY": str(info.common_git_dir / "objects"),
        }
    )


def check_attributes(
    info: RepositoryInfo,
    registration: WorktreeRegistration,
    view: pathlib.Path,
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
    view: pathlib.Path,
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
        argv = _git_worktree_argv(info, *subcommand)
        code, _, stderr = run_bounded(
            argv,
            cwd=info.repo,
            environment=sanitized_git_environment(),
            timeout=120,
            stdout_limit=8192,
            stderr_limit=8192,
        )
        if code != 0:
            raise ValueError(_git_error(argv, stderr))


def verify_worktree_absent(info: RepositoryInfo, worktree: pathlib.Path) -> None:
    try:
        os.lstat(worktree)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("worktree path still exists after removal")
    registrations_parent = info.common_git_dir / "worktrees"
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
