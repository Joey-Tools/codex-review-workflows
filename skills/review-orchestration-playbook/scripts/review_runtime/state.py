from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import math
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, BinaryIO, Callable, Iterator

from .common import (
    PROCESS_GROUP_TERM_GRACE_SECONDS,
    ForwardedSignal,
    ReviewError,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    forwarded_signals,
    read_json,
    restore_signal_mask,
    signal_process_group,
    tail_text,
    terminate_process_group,
    unblock_forwarded_signals,
    write_json,
    write_text_atomic,
)
from .providers import run_review
from .workspace import (
    MAX_PREFLIGHT_JSON_BYTES,
    ReviewWorkspace,
    _inspect_control_directory,
    _load_control_artifact_state,
    _read_bounded_json,
    cleanup_workspace,
    prepare_workspace,
    validate_workspace_layout,
)


STATE_FILE = "state.json"
STATE_MARKER = ".isolated-review-state"
EXIT_FILE = "exit-code"
LOCK_FILE = "runner.lock"
CLEANUP_LOCK_FILE = "cleanup.lock"
FINAL_CLEANUP_TIMEOUT_SECONDS = 30.0
RUNNER_SHUTDOWN_GRACE_SECONDS = PROCESS_GROUP_TERM_GRACE_SECONDS * 4
PRIMARY_DIFF_RELATIVE_PATH = ".codex-review/review.diff"
SAFE_LEGACY_LOCK_MODES = frozenset({0o600, 0o604, 0o640, 0o644})
PRIVATE_STATE_LEGACY_LOCK_MODES = SAFE_LEGACY_LOCK_MODES | {0o664}
_STARTED_PROCESSES: dict[int, subprocess.Popen[bytes]] = {}


def _regular_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _validate_regular_file_path_identity(
    path: pathlib.Path,
    descriptor: int,
    *,
    label: str,
    expected_mode: int | None = None,
    expected_size: int | None = None,
    dir_fd: int | None = None,
    allow_group_or_other_write: bool = False,
) -> os.stat_result:
    try:
        descriptor_before = os.fstat(descriptor)
        path_before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        descriptor_after = os.fstat(descriptor)
        path_after = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as error:
        raise ReviewError(f"cannot validate {label}: {error}") from error

    descriptor_identity = _regular_file_identity(descriptor_before)
    if descriptor_identity != _regular_file_identity(descriptor_after):
        raise ReviewError(f"{label} changed while its identity was validated")
    path_identity = _regular_file_identity(path_before)
    if path_identity != _regular_file_identity(path_after):
        raise ReviewError(f"{label} path changed while its identity was validated")
    if descriptor_identity != path_identity:
        raise ReviewError(f"{label} path does not match its open file descriptor")
    if not stat.S_ISREG(descriptor_after.st_mode):
        raise ReviewError(f"{label} is not a regular file")
    if descriptor_after.st_uid != os.getuid():
        raise ReviewError(f"{label} is not owned by the current user")
    if descriptor_after.st_nlink != 1:
        raise ReviewError(f"{label} must have exactly one hard link")
    if expected_mode is not None:
        if stat.S_IMODE(descriptor_after.st_mode) != expected_mode:
            raise ReviewError(f"{label} mode must be exactly {expected_mode:04o}")
    elif (
        not allow_group_or_other_write
        and descriptor_after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ReviewError(f"{label} must not be group or other writable")
    if expected_size is not None and descriptor_after.st_size != expected_size:
        raise ReviewError(f"{label} has an unexpected size")
    return descriptor_after


def validate_private_lock_file(
    path: pathlib.Path,
    handle: BinaryIO,
    *,
    label: str,
    dir_fd: int | None = None,
) -> None:
    _validate_regular_file_path_identity(
        path,
        handle.fileno(),
        label=label,
        expected_mode=0o600,
        dir_fd=dir_fd,
    )


def validate_safe_legacy_lock_file(
    path: pathlib.Path,
    handle: BinaryIO,
    *,
    label: str,
    allowed_modes: frozenset[int] = SAFE_LEGACY_LOCK_MODES,
    dir_fd: int | None = None,
) -> os.stat_result:
    metadata = _validate_regular_file_path_identity(
        path,
        handle.fileno(),
        label=label,
        dir_fd=dir_fd,
        allow_group_or_other_write=True,
    )
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in allowed_modes:
        raise ReviewError(f"{label} has an unsafe legacy mode")
    if mode == 0o664 and metadata.st_size != 0:
        raise ReviewError(f"{label} legacy 0664 file must be empty")
    return metadata


def open_private_lock_file(
    path: pathlib.Path,
    *,
    label: str,
    allow_legacy_read_mode: bool = False,
    allowed_legacy_modes: frozenset[int] = SAFE_LEGACY_LOCK_MODES,
    dir_fd: int | None = None,
) -> BinaryIO:
    existing_flags = (
        os.O_RDWR
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    created = False
    try:
        try:
            descriptor = os.open(
                path,
                existing_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            created = True
        except FileExistsError:
            existing_metadata = os.stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=False,
            )
            existing_identity = (
                existing_metadata.st_dev,
                existing_metadata.st_ino,
            )
            descriptor = os.open(path, existing_flags, dir_fd=dir_fd)
            opened_metadata = os.fstat(descriptor)
            if existing_identity != (
                opened_metadata.st_dev,
                opened_metadata.st_ino,
            ):
                raise ReviewError(f"{label} changed before it could be opened safely")
        if created:
            os.fchmod(descriptor, 0o600)
        handle = os.fdopen(descriptor, "r+b", buffering=0)
        descriptor = None
        try:
            if allow_legacy_read_mode:
                validate_safe_legacy_lock_file(
                    path,
                    handle,
                    label=label,
                    allowed_modes=allowed_legacy_modes,
                    dir_fd=dir_fd,
                )
            else:
                validate_private_lock_file(
                    path,
                    handle,
                    label=label,
                    dir_fd=dir_fd,
                )
        except BaseException:
            handle.close()
            raise
        return handle
    except OSError as error:
        raise ReviewError(f"cannot open {label} safely: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    # Directory contents may legitimately change while cleanup waiters race to
    # create the lock or remove a workspace. Bind the open descriptor to the
    # same directory and its safety metadata, not content-derived timestamps
    # or link counts.
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    )


def _validate_private_directory_path_identity(
    path: pathlib.Path,
    descriptor: int,
    *,
    label: str,
    expected_mode: int | None = None,
    dir_fd: int | None = None,
) -> None:
    try:
        descriptor_before = os.fstat(descriptor)
        path_before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        descriptor_after = os.fstat(descriptor)
        path_after = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as error:
        raise ReviewError(f"cannot validate {label}: {error}") from error

    descriptor_identity = _directory_identity(descriptor_before)
    if descriptor_identity != _directory_identity(descriptor_after):
        raise ReviewError(f"{label} changed while its identity was validated")
    path_identity = _directory_identity(path_before)
    if path_identity != _directory_identity(path_after):
        raise ReviewError(f"{label} path changed while its identity was validated")
    if descriptor_identity != path_identity:
        raise ReviewError(f"{label} path does not match its open descriptor")
    if not stat.S_ISDIR(descriptor_after.st_mode):
        raise ReviewError(f"{label} is not a real directory")
    if descriptor_after.st_uid != os.geteuid():
        raise ReviewError(f"{label} is not owned by the current user")
    mode = stat.S_IMODE(descriptor_after.st_mode)
    if expected_mode is not None:
        if mode != expected_mode:
            raise ReviewError(f"{label} mode must be exactly {expected_mode:04o}")
    elif descriptor_after.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ReviewError(f"{label} must not be group or other writable")


@contextmanager
def _open_private_cleanup_state_directory(
    state_dir: pathlib.Path,
) -> Iterator[tuple[int, Callable[[], None]]]:
    review_root = state_dir.parent
    if review_root.name != ".codex-tmp" or not state_dir.name.startswith(
        "isolated-review-"
    ):
        raise ReviewError("review state directory is outside a private review root")
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | os.O_NOFOLLOW
    )
    review_root_fd: int | None = None
    state_dir_fd: int | None = None
    try:
        review_root_fd = os.open(review_root, flags)
        state_dir_fd = os.open(state_dir.name, flags, dir_fd=review_root_fd)

        def revalidate() -> None:
            assert review_root_fd is not None
            assert state_dir_fd is not None
            _validate_private_directory_path_identity(
                review_root,
                review_root_fd,
                label="review state root",
            )
            _validate_private_directory_path_identity(
                pathlib.Path(state_dir.name),
                state_dir_fd,
                label="review state directory",
                expected_mode=0o700,
                dir_fd=review_root_fd,
            )

        revalidate()
        yield state_dir_fd, revalidate
    except OSError as error:
        raise ReviewError(
            f"cannot open review state directory safely: {error}"
        ) from error
    finally:
        if state_dir_fd is not None:
            os.close(state_dir_fd)
        if review_root_fd is not None:
            os.close(review_root_fd)


def _state_path(state_dir: pathlib.Path) -> pathlib.Path:
    state_dir = state_dir.expanduser().resolve()
    marker = state_dir / STATE_MARKER
    if not marker.is_file():
        raise ReviewError(f"not an isolated-review state directory: {state_dir}")
    return state_dir / STATE_FILE


def load_state(state_dir: pathlib.Path) -> dict[str, Any]:
    return read_json(_state_path(state_dir))


def load_review_state(
    state_dir: pathlib.Path,
) -> tuple[dict[str, Any], ReviewWorkspace]:
    resolved_state_dir = state_dir.expanduser().resolve()
    state = load_state(resolved_state_dir)
    review_value = state.get("workspace")
    if not isinstance(review_value, dict):
        raise ReviewError("review state does not contain a workspace object")
    try:
        review = ReviewWorkspace.from_json(review_value)
    except (KeyError, TypeError, ValueError) as error:
        raise ReviewError(
            f"review state contains an invalid workspace: {error}"
        ) from error
    validate_workspace_layout(review)
    if review.container_dir.resolve(strict=False) != resolved_state_dir:
        raise ReviewError("review state container does not match its state directory")
    return state, review


def _read_exit_code(state_dir: pathlib.Path) -> int | None:
    path = state_dir / EXIT_FILE
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ReviewError(f"cannot read review exit code {path}: {error}") from error
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        raise ReviewError(f"invalid exit code in {path}: {text!r}")


def _runner_lock_held(lock_path: pathlib.Path) -> bool:
    try:
        handle = lock_path.open("rb")
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ReviewError(
            f"cannot open review runner lock {lock_path}: {error}"
        ) from error
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError as error:
            raise ReviewError(
                f"cannot probe review runner lock {lock_path}: {error}"
            ) from error
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError as error:
            raise ReviewError(
                f"cannot release review runner lock probe {lock_path}: {error}"
            ) from error
        return False
    finally:
        handle.close()


def _reap_started_process(pid: int) -> None:
    process = _STARTED_PROCESSES.get(pid)
    if process is None:
        return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        return
    _STARTED_PROCESSES.pop(pid, None)


def start(
    *,
    script_path: pathlib.Path,
    repo: pathlib.Path,
    reviewer: str,
    base_ref: str,
    head_ref: str,
    prompt_file: pathlib.Path | None,
    keep_workspace: bool,
    egress_consent: str | None,
    synthetic_secret_exemptions: tuple[str, ...] = (),
    publisher: Callable[[pathlib.Path], None] | None = None,
) -> pathlib.Path:
    process: subprocess.Popen[bytes] | None = None
    review: ReviewWorkspace | None = None
    lock_handle = None
    pending_signal: signal.Signals | None = None
    spawning = False
    published = False
    cleaning = False
    handlers_restored = False

    def forward_signal(signum: int, _frame: object) -> None:
        nonlocal pending_signal
        forwarded = signal.Signals(signum)
        pending_signal = forwarded
        if cleaning:
            return
        if process is None:
            if spawning:
                return
            raise ForwardedSignal(forwarded)
        signal_process_group(process, forwarded)
        raise ForwardedSignal(forwarded)

    previous_handlers: dict[signal.Signals, object] = {}
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        for forwarded in forwarded_signals():
            previous_handlers[forwarded] = signal.getsignal(forwarded)
            signal.signal(forwarded, forward_signal)

    def accept_workspace(prepared: ReviewWorkspace) -> None:
        nonlocal review
        review = prepared

    try:
        prepare_workspace(
            repo=repo,
            base_ref=base_ref,
            head_ref=head_ref,
            ownership_handoff=accept_workspace,
            synthetic_secret_exemptions=synthetic_secret_exemptions,
            prompt_override=prompt_file,
        )
        if review is None:
            raise ReviewError("workspace ownership handoff did not complete")
        state_dir = review.container_dir
        write_text_atomic(state_dir / STATE_MARKER, "isolated-review-state-v1\n")
        stdout_path = state_dir / "runner.stdout.log"
        stderr_path = state_dir / "runner.stderr.log"
        state: dict[str, Any] = {
            "version": 1,
            "reviewer": reviewer,
            "workspace": review.to_json(),
            "keep_workspace": keep_workspace,
            "egress_consent": egress_consent,
            "synthetic_secret_exemptions": list(synthetic_secret_exemptions),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "final_path": str(state_dir / "final.txt"),
            "attempts_path": str(state_dir / "attempts.json"),
            "started_at": time.time(),
        }
        write_json(state_dir / STATE_FILE, state)
        lock_path = state_dir / LOCK_FILE
        lock_handle = lock_path.open("wb")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (
            stdout_path.open("wb") as stdout_handle,
            stderr_path.open("wb") as stderr_handle,
        ):
            spawning = True
            spawn_mask = block_forwarded_signals()
            try:
                process = subprocess.Popen(
                    (
                        sys.executable,
                        str(script_path),
                        "_run-state",
                        "--state-dir",
                        str(state_dir),
                        "--lock-fd",
                        str(lock_handle.fileno()),
                    ),
                    cwd=review.workspace_root,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(lock_handle.fileno(),),
                )
            finally:
                spawning = False
                restore_signal_mask(spawn_mask)
        if pending_signal is not None:
            signal_process_group(process, pending_signal)
            raise ForwardedSignal(pending_signal)
        state["pid"] = process.pid
        _STARTED_PROCESSES[process.pid] = process
        write_json(state_dir / STATE_FILE, state)
        publication_mask = block_forwarded_signals()
        publication_signal: signal.Signals | None = None
        try:
            if publisher is not None:
                publisher(state_dir)
            published = True
            if publication_mask is not None:
                publication_signal = consume_pending_forwarded_signal()
        finally:
            restore_signal_mask(publication_mask)
        if publication_signal is not None:
            pending_signal = publication_signal
            signal_process_group(process, publication_signal)
            raise ForwardedSignal(publication_signal)
        return state_dir
    except BaseException as error:
        cleaning = True
        cleanup_mask = block_forwarded_signals()
        cleanup_signal: signal.Signals | None = None
        cleanup_error: str | None = None
        try:
            if process is not None:
                terminate_process_group(
                    process,
                    initial_signal=pending_signal or signal.SIGTERM,
                    signal_already_sent=pending_signal is not None,
                    grace_seconds=RUNNER_SHUTDOWN_GRACE_SECONDS,
                )
                _STARTED_PROCESSES.pop(process.pid, None)
            if review is not None and not published:
                cleanup_error = cleanup_workspace(review, keep_container=False)
        finally:
            for forwarded, previous in previous_handlers.items():
                signal.signal(forwarded, previous)
            handlers_restored = True
            if cleanup_mask is not None:
                cleanup_signal = consume_pending_forwarded_signal()
                if cleanup_signal is not None:
                    pending_signal = cleanup_signal
            restore_signal_mask(cleanup_mask)
        if pending_signal is not None:
            details: list[str] = []
            if isinstance(error, ForwardedSignal) and error.detail:
                details.append(error.detail)
            elif isinstance(error, ReviewError):
                details.append(str(error))
            if cleanup_error and review is not None:
                details.append(
                    "review startup failed and cleanup failed; evidence retained at "
                    f"{review.container_dir}: {cleanup_error}"
                )
            raise ForwardedSignal(
                pending_signal,
                detail="; ".join(details) or None,
            ) from error
        if cleanup_error and review is not None:
            raise ReviewError(
                "review startup failed and cleanup failed; evidence retained at "
                f"{review.container_dir}: {cleanup_error}"
            ) from error
        raise
    finally:
        if lock_handle is not None:
            lock_handle.close()
        if not handlers_restored:
            for forwarded, previous in previous_handlers.items():
                signal.signal(forwarded, previous)


def run_state(
    *,
    state_dir: pathlib.Path,
    terminal_process: bool = False,
) -> int:
    exit_code = 1
    pending_signal: signal.Signals | None = None
    suppress_signal_raise = False
    state_loaded = False

    def record_signal(signum: int, _frame: object) -> None:
        nonlocal pending_signal
        pending_signal = signal.Signals(signum)
        if not suppress_signal_raise:
            raise ForwardedSignal(pending_signal)

    previous_handlers: dict[signal.Signals, object] = {}
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        for forwarded in forwarded_signals():
            previous_handlers[forwarded] = signal.getsignal(forwarded)
            signal.signal(forwarded, record_signal)

    try:
        state, review = load_review_state(state_dir)
        state_loaded = True
        unblock_forwarded_signals()
        reviewer = state.get("reviewer")
        if not isinstance(reviewer, str):
            raise ReviewError("review state does not contain a reviewer")
        consent_value = state.get("egress_consent")
        egress_consent = consent_value if isinstance(consent_value, str) else None
        outcome = run_review(
            review=review,
            reviewer=reviewer,
            egress_consent=egress_consent,
        )
        exit_code = outcome.returncode
    except ForwardedSignal as error:
        exit_code = 128 + int(error.signum)
        if state_loaded and error.detail:
            try:
                write_text_atomic(
                    state_dir / "runner-error.txt",
                    "review orchestration interrupted by signal "
                    f"{int(error.signum)}: {error.detail}\n",
                )
            except Exception:
                pass
    except Exception as error:
        if state_loaded:
            write_text_atomic(
                state_dir / "runner-error.txt", f"{type(error).__name__}: {error}\n"
            )
        exit_code = 1
    finally:
        suppress_signal_raise = True
        previous_mask = block_forwarded_signals()
        try:
            while True:
                masked_signal = (
                    consume_pending_forwarded_signal()
                    if previous_mask is not None
                    else None
                )
                if pending_signal is None:
                    pending_signal = masked_signal
                if pending_signal is not None:
                    exit_code = 128 + int(pending_signal)
                if state_loaded:
                    write_text_atomic(state_dir / EXIT_FILE, f"{exit_code}\n")
                if previous_mask is None:
                    break
                pending_signal = consume_pending_forwarded_signal()
                if pending_signal is None:
                    break
            if not terminal_process:
                for forwarded, previous in previous_handlers.items():
                    signal.signal(forwarded, previous)
        finally:
            if not terminal_process:
                restore_signal_mask(previous_mask)
    return exit_code


def status(state_dir: pathlib.Path) -> dict[str, Any]:
    state_dir = state_dir.expanduser().resolve()
    state, review = load_review_state(state_dir)
    pid_value = state.get("pid")
    pid = pid_value if isinstance(pid_value, int) else 0
    process_running = _runner_lock_held(state_dir / LOCK_FILE)
    running = process_running
    if running:
        exit_code = None
    else:
        exit_code = _read_exit_code(state_dir)
        if exit_code is not None:
            _reap_started_process(pid)
    if exit_code is None and not running:
        exit_code = 1
        write_text_atomic(state_dir / EXIT_FILE, "1\n")
        write_text_atomic(
            state_dir / "runner-error.txt",
            "review runner exited without recording a terminal result\n",
        )
    fallback_workspace_retained = (
        not running
        and _should_retain_fallback_workspace(
            state_dir=state_dir,
            state=state,
            review=review,
            exit_code=exit_code,
        )
    )
    attempts: list[Any] = []
    attempts_path = state_dir / "attempts.json"
    if attempts_path.is_file():
        try:
            parsed_attempts = json.loads(attempts_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            parsed_attempts = []
        if isinstance(parsed_attempts, list):
            for item in parsed_attempts:
                if not isinstance(item, dict):
                    continue
                summary = dict(item)
                legacy_final = summary.pop("final_text", None)
                if legacy_final is not None:
                    summary["final_available"] = bool(legacy_final)
                attempts.append(summary)
    return {
        "state_dir": str(state_dir),
        "reviewer": state.get("reviewer"),
        "egress_consent": state.get("egress_consent"),
        "pid": pid or None,
        "runner_lock_held": process_running,
        "running": running,
        "exit_code": exit_code,
        "fallback_workspace_retained": fallback_workspace_retained,
        "fallback_workspace": (
            str(review.workspace_root) if fallback_workspace_retained else ""
        ),
        "attempts": attempts,
        "stdout_tail": tail_text(state_dir / "runner.stdout.log"),
        "stderr_tail": tail_text(state_dir / "runner.stderr.log"),
        "runner_error": tail_text(state_dir / "runner-error.txt"),
        "cleanup_error": tail_text(state_dir / "cleanup-error.txt"),
    }


def _should_retain_fallback_workspace(
    *,
    state_dir: pathlib.Path,
    state: dict[str, Any],
    review: ReviewWorkspace,
    exit_code: int | None,
) -> bool:
    if (
        state.get("reviewer") != "codex"
        or exit_code != 127
        or not review.workspace_root.is_dir()
    ):
        return False
    try:
        preflight = _read_bounded_json(
            state_dir / "preflight.json",
            label="retained fallback preflight evidence",
            max_bytes=MAX_PREFLIGHT_JSON_BYTES,
        )
        if (
            preflight.get("review_range")
            != f"{review.base_ref}..{review.head_ref}"
            or preflight.get("status")
            != "sensitive-content and escaping-symlink checks passed"
        ):
            return False
        primary_diff = preflight.get("primary_diff")
        if (
            not isinstance(primary_diff, dict)
            or set(primary_diff) != {"path", "sha256", "size"}
            or primary_diff.get("path") != PRIMARY_DIFF_RELATIVE_PATH
            or type(primary_diff.get("size")) is not int
            or primary_diff["size"] < 0
            or not isinstance(primary_diff.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", primary_diff["sha256"]) is None
        ):
            return False

        expected_diff_path = review.workspace_root / PRIMARY_DIFF_RELATIVE_PATH
        if review.diff_file != expected_diff_path:
            return False
        control_state = _load_control_artifact_state(container_dir=state_dir)
        expected_diff = control_state.artifacts["review.diff"]
        if (
            primary_diff["size"] != expected_diff.size
            or primary_diff["sha256"] != expected_diff.sha256
        ):
            return False
        control_dir = review.workspace_root / ".codex-review"
        _inspect_control_directory(control_dir, expected=control_state.directory)
        flags = (
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(expected_diff_path, flags)
        except OSError as error:
            raise ReviewError(
                f"cannot open retained fallback primary diff safely: {error}"
            ) from error
        try:
            _validate_regular_file_path_identity(
                expected_diff_path,
                descriptor,
                label="retained fallback primary diff",
                expected_size=expected_diff.size,
            )
        finally:
            os.close(descriptor)
        _inspect_control_directory(control_dir, expected=control_state.directory)
    except ReviewError:
        return False
    # This synchronous status path intentionally validates only bounded metadata.
    # The actual fallback consumer must supervise a complete read and verify the
    # primary diff SHA-256 against both attestations before using any diff bytes.
    return True


def _validate_timeout(timeout_seconds: float | None) -> None:
    if timeout_seconds is not None and (
        not math.isfinite(timeout_seconds) or timeout_seconds < 0
    ):
        raise ReviewError("wait timeout must be a non-negative finite number")


def wait(
    state_dir: pathlib.Path,
    *,
    timeout_seconds: float | None,
) -> int:
    _validate_timeout(timeout_seconds)
    state_dir = state_dir.expanduser().resolve()
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    while True:
        summary = status(state_dir)
        if not summary["running"]:
            break
        if deadline is not None and time.monotonic() >= deadline:
            return 124
        remaining = None if deadline is None else deadline - time.monotonic()
        time.sleep(0.25 if remaining is None else min(0.25, max(0.0, remaining)))

    cleanup_code = _cleanup_terminal_workspace(
        state_dir,
        deadline=deadline,
        force=False,
    )
    if cleanup_code != 0:
        return cleanup_code
    exit_code = _read_exit_code(state_dir)
    return 1 if exit_code is None else exit_code


def cleanup(state_dir: pathlib.Path, *, timeout_seconds: float | None) -> int:
    _validate_timeout(timeout_seconds)
    state_dir = state_dir.expanduser().resolve()
    if status(state_dir)["running"]:
        return 3
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    return _cleanup_terminal_workspace(state_dir, deadline=deadline, force=True)


def _cleanup_terminal_workspace(
    state_dir: pathlib.Path,
    *,
    deadline: float | None,
    force: bool,
) -> int:
    cleanup_lock_name = pathlib.Path(CLEANUP_LOCK_FILE)
    cleanup_error_path = state_dir / "cleanup-error.txt"
    with (
        _open_private_cleanup_state_directory(state_dir) as (
            state_dir_fd,
            revalidate_state_directory,
        ),
        open_private_lock_file(
            cleanup_lock_name,
            label="review cleanup lock",
            allow_legacy_read_mode=True,
            allowed_legacy_modes=PRIVATE_STATE_LEGACY_LOCK_MODES,
            dir_fd=state_dir_fd,
        ) as cleanup_lock,
    ):
        if not _acquire_cleanup_lock(cleanup_lock, deadline=deadline):
            return 124
        revalidate_state_directory()
        cleanup_lock_transferred = False

        def transfer_cleanup_lock() -> None:
            nonlocal cleanup_lock_transferred
            cleanup_lock_transferred = True

        try:
            locked_metadata = validate_safe_legacy_lock_file(
                cleanup_lock_name,
                cleanup_lock,
                label="review cleanup lock",
                allowed_modes=PRIVATE_STATE_LEGACY_LOCK_MODES,
                dir_fd=state_dir_fd,
            )
            if stat.S_IMODE(locked_metadata.st_mode) != 0o600:
                os.fchmod(cleanup_lock.fileno(), 0o600)
                os.fsync(cleanup_lock.fileno())
            validate_private_lock_file(
                cleanup_lock_name,
                cleanup_lock,
                label="review cleanup lock",
                dir_fd=state_dir_fd,
            )
            state, review = load_review_state(state_dir)
            keep_workspace = bool(state.get("keep_workspace"))
            exit_code = _read_exit_code(state_dir)
            retain_for_fallback = _should_retain_fallback_workspace(
                state_dir=state_dir,
                state=state,
                review=review,
                exit_code=exit_code,
            )
            should_keep = not force and (keep_workspace or retain_for_fallback)
            if review.workspace_root.exists() and not should_keep:
                cleanup_completed, cleanup_error = _cleanup_before_deadline(
                    review,
                    deadline=deadline,
                    cleanup_lock_fd=cleanup_lock.fileno(),
                    lock_handoff=transfer_cleanup_lock,
                )
                if not cleanup_completed:
                    return 124
                if cleanup_error:
                    write_text_atomic(cleanup_error_path, cleanup_error + "\n")
                    return 1
            if not should_keep and not review.workspace_root.exists():
                try:
                    cleanup_error_path.unlink(missing_ok=True)
                except OSError as error:
                    raise ReviewError(
                        f"cannot clear resolved cleanup error {cleanup_error_path}: "
                        f"{error}"
                    ) from error
            if cleanup_error_path.is_file():
                return 1
            return 0
        finally:
            if not cleanup_lock_transferred:
                fcntl.flock(cleanup_lock.fileno(), fcntl.LOCK_UN)


def _acquire_cleanup_lock(handle, *, deadline: float | None) -> bool:
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if deadline is not None and time.monotonic() >= deadline:
                return False
            remaining = None if deadline is None else deadline - time.monotonic()
            time.sleep(0.05 if remaining is None else min(0.05, max(0.0, remaining)))


def _cleanup_before_deadline(
    review: ReviewWorkspace,
    *,
    deadline: float | None,
    cleanup_lock_fd: int,
    lock_handoff: Callable[[], None],
) -> tuple[bool, str | None]:
    if deadline is None:
        return True, cleanup_workspace(review, keep_container=True)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False, None
    worker_path = pathlib.Path(__file__).resolve().with_name("cleanup_worker.py")
    handoff_mask = block_forwarded_signals()
    try:
        try:
            worker = subprocess.Popen(
                (
                    sys.executable,
                    str(worker_path),
                    str(review.container_dir),
                    str(cleanup_lock_fd),
                ),
                close_fds=True,
                pass_fds=(cleanup_lock_fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            return True, f"cannot start bounded cleanup worker: {error}"
        lock_handoff()
    finally:
        restore_signal_mask(handoff_mask)

    while True:
        returncode = worker.poll()
        if returncode is not None:
            if returncode == 0:
                return True, None
            cleanup_error = tail_text(review.container_dir / "cleanup-error.txt")
            return (
                True,
                cleanup_error or "cleanup worker exited without completing",
            )
        if time.monotonic() >= deadline:
            threading.Thread(
                target=worker.wait,
                daemon=True,
            ).start()
            return False, None
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def final(state_dir: pathlib.Path) -> tuple[int, str]:
    summary = status(state_dir)
    if summary["running"]:
        return 3, "review is still running"
    wait_code = wait(state_dir, timeout_seconds=FINAL_CLEANUP_TIMEOUT_SECONDS)
    if wait_code == 124:
        return 3, "review completed but workspace cleanup did not finish before timeout"
    cleanup_error = tail_text(state_dir.expanduser().resolve() / "cleanup-error.txt")
    if cleanup_error:
        return 1, f"review completed but workspace cleanup failed: {cleanup_error}"
    summary = status(state_dir)
    exit_code = summary["exit_code"]
    final_path = state_dir.expanduser().resolve() / "final.txt"
    if exit_code == 0 and final_path.is_file():
        text = final_path.read_text(encoding="utf-8", errors="replace").strip()
        if text:
            return 0, text
    details = (
        summary.get("runner_error")
        or summary.get("stderr_tail")
        or "review failed without a final artifact"
    )
    if summary.get("fallback_workspace_retained"):
        details = (
            f"{details}\nfrozen workspace retained for clean-context fallback: "
            f"{summary['fallback_workspace']}"
        )
    return int(wait_code or exit_code or 1), str(details)
