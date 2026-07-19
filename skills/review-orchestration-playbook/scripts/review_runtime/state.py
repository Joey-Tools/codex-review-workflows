from __future__ import annotations

import fcntl
import json
import math
import os
import pathlib
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

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
    PRIVATE_HELPER_ARTIFACT_NAMES,
    CleanupIdentity,
    LegacyReviewWorkspace,
    PrivateCleanupEvidence,
    ReviewWorkspace,
    cleanup_legacy_workspace,
    cleanup_workspace,
    load_bound_private_cleanup_state,
    parse_partial_private_cleanup_evidence,
    parse_private_cleanup_evidence,
    prepare_workspace,
    remove_legacy_private_review_artifacts,
    remove_partial_review_container,
    remove_private_review_artifacts,
    validate_workspace_layout,
)


STATE_FILE = "state.json"
STATE_MARKER = ".isolated-review-state"
LEGACY_STATE_SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 2
LEGACY_STATE_MARKER = b"isolated-review-state-v1\n"
COMPATIBLE_STATE_MARKER_SCHEMA_VERSION = 2
STATE_MARKER_SCHEMA_VERSION = 3
LEGACY_STATE_REQUIRED_FIELDS = frozenset(
    {
        "attempts_path",
        "egress_consent",
        "final_path",
        "keep_workspace",
        "reviewer",
        "started_at",
        "stderr_path",
        "stdout_path",
        "version",
        "workspace",
    }
)
LEGACY_STATE_OPTIONAL_FIELDS = frozenset({"pid", "synthetic_secret_exemptions"})
EXIT_FILE = "exit-code"
LOCK_FILE = "runner.lock"
CLEANUP_LOCK_FILE = "cleanup.lock"
FINAL_CLEANUP_TIMEOUT_SECONDS = 30.0
RUNNER_SHUTDOWN_GRACE_SECONDS = PROCESS_GROUP_TERM_GRACE_SECONDS * 4
_STARTED_PROCESSES: dict[int, subprocess.Popen[bytes]] = {}


@dataclass(frozen=True)
class LoadedStateMarker:
    version: int
    phase: str
    private_cleanup: PrivateCleanupEvidence | None
    source_root: pathlib.Path | None


def _state_path(state_dir: pathlib.Path) -> pathlib.Path:
    state_dir = state_dir.expanduser().resolve()
    marker = state_dir / STATE_MARKER
    if not marker.is_file():
        raise ReviewError(f"not an isolated-review state directory: {state_dir}")
    return state_dir / STATE_FILE


def _state_marker_payload(review: ReviewWorkspace) -> dict[str, Any]:
    return {
        "container_dir": str(review.container_dir),
        "phase": "ready",
        "private_cleanup": review.private_cleanup.to_json(),
        "source_root": str(review.source_root),
        "version": STATE_MARKER_SCHEMA_VERSION,
    }


def _preparing_state_marker_payload(
    container: pathlib.Path,
    private_cleanup: PrivateCleanupEvidence,
) -> dict[str, Any]:
    return {
        "container_dir": str(container),
        "phase": "preparing",
        "private_cleanup": private_cleanup.to_json(),
        "source_root": str(container.parent.parent),
        "version": STATE_MARKER_SCHEMA_VERSION,
    }


def _fsync_state_marker_container(
    container: pathlib.Path,
    *,
    expected: CleanupIdentity,
) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(container, flags)
        opened = os.fstat(descriptor)
        current = os.lstat(container)
        for metadata in (opened, current):
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or CleanupIdentity(metadata.st_dev, metadata.st_ino) != expected
            ):
                raise ReviewError(
                    "isolated-review state marker container identity changed"
                )
        os.fsync(descriptor)
        final = os.lstat(container)
        if CleanupIdentity(final.st_dev, final.st_ino) != expected:
            raise ReviewError("isolated-review state marker container identity changed")
    except OSError as error:
        raise ReviewError(
            f"cannot durably persist isolated-review state marker: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_state_marker_payload(
    container: pathlib.Path,
    payload: dict[str, Any],
    *,
    expected: CleanupIdentity,
) -> None:
    write_json(container / STATE_MARKER, payload)
    _fsync_state_marker_container(container, expected=expected)


def _write_preparing_state_marker(
    container: pathlib.Path,
    private_cleanup: PrivateCleanupEvidence,
) -> None:
    _write_state_marker_payload(
        container,
        _preparing_state_marker_payload(container, private_cleanup),
        expected=private_cleanup.container,
    )


def _write_state_marker(review: ReviewWorkspace) -> None:
    _write_state_marker_payload(
        review.container_dir,
        _state_marker_payload(review),
        expected=review.private_cleanup.container,
    )


def _reject_duplicate_marker_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewError(
                f"isolated-review state marker has duplicate field: {key}"
            )
        value[key] = item
    return value


def _validate_marker_container(
    raw_container: Any,
    *,
    resolved_state_dir: pathlib.Path,
) -> None:
    if not isinstance(raw_container, str):
        raise ReviewError("isolated-review state marker container is invalid")
    try:
        marker_container = (
            pathlib.Path(raw_container).expanduser().resolve(strict=False)
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise ReviewError(
            "isolated-review state marker container is invalid"
        ) from error
    if marker_container != resolved_state_dir:
        raise ReviewError("isolated-review state marker container is invalid")


def _canonical_v3_marker_path(raw_path: Any, *, label: str) -> pathlib.Path:
    if not isinstance(raw_path, str):
        raise ReviewError(f"isolated-review state marker {label} is invalid")
    candidate = pathlib.Path(raw_path)
    if not candidate.is_absolute():
        raise ReviewError(f"isolated-review state marker {label} is not canonical")
    normalized = pathlib.Path(os.path.normpath(os.fspath(candidate)))
    if candidate != normalized:
        raise ReviewError(f"isolated-review state marker {label} is not canonical")
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as error:
        raise ReviewError(f"isolated-review state marker {label} is invalid") from error
    if resolved != candidate:
        raise ReviewError(f"isolated-review state marker {label} is not canonical")
    return resolved


def _validate_v3_marker_layout(
    raw_source_root: Any,
    raw_container: Any,
    *,
    resolved_state_dir: pathlib.Path,
) -> pathlib.Path:
    source_root = _canonical_v3_marker_path(
        raw_source_root,
        label="source root",
    )
    container = _canonical_v3_marker_path(
        raw_container,
        label="container",
    )
    if (
        container != resolved_state_dir
        or container.parent != source_root / ".codex-tmp"
        or not container.name.startswith("isolated-review-")
        or container.name == "isolated-review-"
    ):
        raise ReviewError("isolated-review state marker layout is invalid")
    return source_root


def _load_state_marker(state_dir: pathlib.Path) -> LoadedStateMarker:
    resolved_state_dir = state_dir.expanduser().resolve(strict=False)
    marker_path = resolved_state_dir / STATE_MARKER
    try:
        encoded = marker_path.read_bytes()
    except OSError as error:
        raise ReviewError(
            f"cannot read isolated-review state marker {marker_path}: {error}"
        ) from error
    if encoded == LEGACY_STATE_MARKER:
        return LoadedStateMarker(
            version=LEGACY_STATE_SCHEMA_VERSION,
            phase="legacy",
            private_cleanup=None,
            source_root=None,
        )
    try:
        marker = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_marker_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReviewError("isolated-review state marker is invalid") from error
    if not isinstance(marker, dict):
        raise ReviewError("isolated-review state marker is not a JSON object")
    version = marker.get("version")
    if type(version) is not int:
        raise ReviewError("isolated-review state marker version is invalid")
    if version == COMPATIBLE_STATE_MARKER_SCHEMA_VERSION:
        if set(marker) != {"container_dir", "private_cleanup", "version"}:
            raise ReviewError("isolated-review state marker fields are invalid")
        _validate_marker_container(
            marker["container_dir"],
            resolved_state_dir=resolved_state_dir,
        )
        return LoadedStateMarker(
            version=version,
            phase="ready",
            private_cleanup=parse_private_cleanup_evidence(marker["private_cleanup"]),
            source_root=None,
        )
    if version != STATE_MARKER_SCHEMA_VERSION:
        raise ReviewError("isolated-review state marker version is invalid")
    if set(marker) != {
        "container_dir",
        "phase",
        "private_cleanup",
        "source_root",
        "version",
    }:
        raise ReviewError("isolated-review state marker fields are invalid")
    source_root = _validate_v3_marker_layout(
        marker["source_root"],
        marker["container_dir"],
        resolved_state_dir=resolved_state_dir,
    )
    phase = marker["phase"]
    if not isinstance(phase, str) or phase not in {"preparing", "ready"}:
        raise ReviewError("isolated-review state marker phase is invalid")
    cleanup_parser = (
        parse_private_cleanup_evidence
        if phase == "ready"
        else parse_partial_private_cleanup_evidence
    )
    return LoadedStateMarker(
        version=version,
        phase=phase,
        private_cleanup=cleanup_parser(marker["private_cleanup"]),
        source_root=source_root,
    )


def _load_state_marker_cleanup(
    state_dir: pathlib.Path,
) -> PrivateCleanupEvidence:
    marker = _load_state_marker(state_dir)
    if marker.private_cleanup is None:
        raise ReviewError("legacy isolated-review state marker has no cleanup identity")
    return marker.private_cleanup


def load_state(state_dir: pathlib.Path) -> dict[str, Any]:
    return read_json(_state_path(state_dir))


def _validate_legacy_state(
    state: dict[str, Any],
    *,
    state_dir: pathlib.Path,
) -> None:
    fields = set(state)
    if not LEGACY_STATE_REQUIRED_FIELDS <= fields or not fields <= (
        LEGACY_STATE_REQUIRED_FIELDS | LEGACY_STATE_OPTIONAL_FIELDS
    ):
        raise ReviewError("legacy v1 review state fields are invalid")
    if not isinstance(state["reviewer"], str):
        raise ReviewError("legacy v1 review state reviewer is invalid")
    if type(state["keep_workspace"]) is not bool:
        raise ReviewError("legacy v1 review state keep flag is invalid")
    if state["egress_consent"] is not None and not isinstance(
        state["egress_consent"], str
    ):
        raise ReviewError("legacy v1 review state egress consent is invalid")
    if not isinstance(state["workspace"], dict):
        raise ReviewError("legacy v1 review state workspace is invalid")
    started_at = state["started_at"]
    if (
        type(started_at) not in {int, float}
        or not math.isfinite(started_at)
        or started_at < 0
    ):
        raise ReviewError("legacy v1 review state start time is invalid")
    expected_paths = {
        "attempts_path": state_dir / "attempts.json",
        "final_path": state_dir / "final.txt",
        "stderr_path": state_dir / "runner.stderr.log",
        "stdout_path": state_dir / "runner.stdout.log",
    }
    if any(state[field] != str(path) for field, path in expected_paths.items()):
        raise ReviewError("legacy v1 review state artifact paths are invalid")
    if "synthetic_secret_exemptions" in state:
        exemptions = state["synthetic_secret_exemptions"]
        if not isinstance(exemptions, list) or any(
            not isinstance(item, str) for item in exemptions
        ):
            raise ReviewError(
                "legacy v1 review state synthetic secret exemptions are invalid"
            )
    if "pid" in state and (type(state["pid"]) is not int or state["pid"] <= 0):
        raise ReviewError("legacy v1 review state pid is invalid")


def load_review_state(
    state_dir: pathlib.Path,
) -> tuple[dict[str, Any], ReviewWorkspace | LegacyReviewWorkspace]:
    resolved_state_dir = state_dir.expanduser().resolve()
    marker = _load_state_marker(resolved_state_dir)
    state = load_state(resolved_state_dir)
    version = state.get("version")
    if type(version) is not int or version not in {
        LEGACY_STATE_SCHEMA_VERSION,
        STATE_SCHEMA_VERSION,
    }:
        raise ReviewError("review state version is invalid")
    if version == LEGACY_STATE_SCHEMA_VERSION:
        if marker.version != LEGACY_STATE_SCHEMA_VERSION:
            raise ReviewError("review state and marker versions are inconsistent")
        _validate_legacy_state(state, state_dir=resolved_state_dir)
        workspace_type = LegacyReviewWorkspace
    else:
        if (
            marker.version
            not in {
                COMPATIBLE_STATE_MARKER_SCHEMA_VERSION,
                STATE_MARKER_SCHEMA_VERSION,
            }
            or marker.phase != "ready"
        ):
            raise ReviewError("review state and marker versions are inconsistent")
        workspace_type = ReviewWorkspace
    review_value = state.get("workspace")
    if not isinstance(review_value, dict):
        raise ReviewError("review state does not contain a workspace object")
    try:
        review = workspace_type.from_json(review_value)
    except (KeyError, TypeError, ValueError, ReviewError) as error:
        raise ReviewError(
            f"review state contains an invalid workspace: {error}"
        ) from error
    validate_workspace_layout(review)
    if review.container_dir.resolve(strict=False) != resolved_state_dir:
        raise ReviewError("review state container does not match its state directory")
    if isinstance(review, LegacyReviewWorkspace):
        return state, review
    marker_cleanup = marker.private_cleanup
    if marker_cleanup is None:
        raise ReviewError("review state marker cleanup identity is missing")
    if marker_cleanup != review.private_cleanup:
        raise ReviewError(
            "review state cleanup identity does not match its state marker"
        )
    load_bound_private_cleanup_state(
        review.container_dir,
        expected=review.private_cleanup,
    )
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
    lock_container: pathlib.Path | None = None
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

    def ensure_preparation_lock(container: pathlib.Path) -> None:
        nonlocal lock_container, lock_handle
        lock_path = container / LOCK_FILE
        if lock_handle is not None:
            if lock_container != container:
                raise ReviewError(
                    "workspace preparation lock container changed during handoff"
                )
            opened = os.fstat(lock_handle.fileno())
            try:
                current = os.lstat(lock_path)
            except OSError as error:
                raise ReviewError(
                    f"workspace preparation lock changed during handoff: {error}"
                ) from error
            if CleanupIdentity(opened.st_dev, opened.st_ino) != CleanupIdentity(
                current.st_dev,
                current.st_ino,
            ):
                raise ReviewError("workspace preparation lock changed during handoff")
            return

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        candidate = None
        try:
            descriptor = os.open(lock_path, flags, 0o600)
            candidate = os.fdopen(descriptor, "w+b")
            descriptor = None
            opened = os.fstat(candidate.fileno())
            current = os.lstat(lock_path)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or CleanupIdentity(opened.st_dev, opened.st_ino)
                != CleanupIdentity(current.st_dev, current.st_ino)
            ):
                raise ReviewError("workspace preparation lock is invalid")
            fcntl.flock(candidate.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock_handle = candidate
            lock_container = container
            candidate = None
        except OSError as error:
            raise ReviewError(
                f"cannot acquire workspace preparation lock {lock_path}: {error}"
            ) from error
        finally:
            if candidate is not None:
                candidate.close()
            elif descriptor is not None:
                os.close(descriptor)

    def accept_preparation_cleanup(
        container: pathlib.Path,
        private_cleanup: PrivateCleanupEvidence,
    ) -> None:
        ensure_preparation_lock(container)
        _write_preparing_state_marker(container, private_cleanup)

    def accept_workspace(prepared: ReviewWorkspace) -> None:
        nonlocal review
        if lock_handle is None:
            accept_preparation_cleanup(
                prepared.container_dir,
                prepared.private_cleanup,
            )
        else:
            ensure_preparation_lock(prepared.container_dir)
        _write_state_marker(prepared)
        review = prepared

    try:
        prepare_workspace(
            repo=repo,
            base_ref=base_ref,
            head_ref=head_ref,
            ownership_handoff=accept_workspace,
            preparation_cleanup_handoff=accept_preparation_cleanup,
            synthetic_secret_exemptions=synthetic_secret_exemptions,
            prompt_override=prompt_file,
        )
        if review is None:
            raise ReviewError("workspace ownership handoff did not complete")
        state_dir = review.container_dir
        stdout_path = state_dir / "runner.stdout.log"
        stderr_path = state_dir / "runner.stderr.log"
        state: dict[str, Any] = {
            "version": STATE_SCHEMA_VERSION,
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
        if lock_handle is None or lock_container != state_dir:
            raise ReviewError("workspace preparation lock handoff did not complete")
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
        if isinstance(review, LegacyReviewWorkspace):
            raise ReviewError(
                "legacy v1 review state cannot be resumed; start a new review"
            )
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
    fallback_workspace_retained = not running and _should_retain_fallback_workspace(
        state_dir=state_dir,
        state=state,
        review=review,
        exit_code=exit_code,
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
    review: ReviewWorkspace | LegacyReviewWorkspace,
    exit_code: int | None,
) -> bool:
    if (
        state.get("reviewer") != "codex"
        or exit_code != 127
        or not review.workspace_root.is_dir()
    ):
        return False
    try:
        preflight = read_json(state_dir / "preflight.json")
    except ReviewError:
        return False
    if isinstance(review, LegacyReviewWorkspace):
        return (
            preflight.get("review_range") == f"{review.base_ref}..{review.head_ref}"
            and preflight.get("status")
            == "sensitive-content and escaping-symlink checks passed"
        )
    preflight_matches = (
        preflight.get("review_range") == f"{review.base_ref}..{review.head_ref}"
        and preflight.get("private_artifacts") == "removed"
        and preflight.get("status") == "secret-delta and escaping-symlink checks passed"
    )
    try:
        cleanup_state = load_bound_private_cleanup_state(
            review.container_dir,
            expected=review.private_cleanup,
        )
    except ReviewError:
        return False
    return preflight_matches and cleanup_state.private_artifacts_removed == frozenset(
        PRIVATE_HELPER_ARTIFACT_NAMES
    )


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
    _state_path(state_dir)
    if _runner_lock_held(state_dir / LOCK_FILE):
        return 3
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    return _cleanup_terminal_workspace(state_dir, deadline=deadline, force=True)


def _cleanup_terminal_workspace(
    state_dir: pathlib.Path,
    *,
    deadline: float | None,
    force: bool,
) -> int:
    cleanup_lock_path = state_dir / CLEANUP_LOCK_FILE
    cleanup_error_path = state_dir / "cleanup-error.txt"
    with cleanup_lock_path.open("a+b") as cleanup_lock:
        if not _acquire_cleanup_lock(cleanup_lock, deadline=deadline):
            return 124
        cleanup_lock_transferred = False

        def transfer_cleanup_lock() -> None:
            nonlocal cleanup_lock_transferred
            cleanup_lock_transferred = True

        try:
            if force and _runner_lock_held(state_dir / LOCK_FILE):
                return 3
            try:
                state, review = load_review_state(state_dir)
            except ReviewError as state_error:
                if not force or not (state_dir / STATE_MARKER).is_file():
                    raise
                try:
                    marker = _load_state_marker(state_dir)
                except ReviewError as marker_error:
                    raise ReviewError(
                        f"{state_error}; private artifact cleanup identity failed: "
                        f"{marker_error}"
                    ) from state_error
                state_path = state_dir / STATE_FILE
                if (
                    marker.version == STATE_MARKER_SCHEMA_VERSION
                    and marker.phase in {"preparing", "ready"}
                    and marker.private_cleanup is not None
                    and not os.path.lexists(state_path)
                ):
                    partial_cleanup_error = remove_partial_review_container(
                        state_dir,
                        expected=marker.private_cleanup,
                    )
                    if partial_cleanup_error:
                        raise ReviewError(
                            f"{state_error}; partial container cleanup failed: "
                            f"{partial_cleanup_error}"
                        ) from state_error
                    return 0
                if marker.version == LEGACY_STATE_SCHEMA_VERSION:
                    raise ReviewError(
                        f"{state_error}; legacy v1 state requires manual recovery"
                    ) from state_error
                if marker.phase != "ready" or marker.private_cleanup is None:
                    raise
                private_cleanup_error = remove_private_review_artifacts(
                    state_dir,
                    expected=marker.private_cleanup,
                )
                if private_cleanup_error:
                    raise ReviewError(
                        f"{state_error}; private artifact cleanup failed: "
                        f"{private_cleanup_error}"
                    ) from state_error
                raise
            keep_workspace = bool(state.get("keep_workspace"))
            exit_code = _read_exit_code(state_dir)
            retain_for_fallback = _should_retain_fallback_workspace(
                state_dir=state_dir,
                state=state,
                review=review,
                exit_code=exit_code,
            )
            should_keep = not force and (keep_workspace or retain_for_fallback)
            if should_keep:
                if isinstance(review, LegacyReviewWorkspace):
                    cleanup_error = remove_legacy_private_review_artifacts(review)
                else:
                    cleanup_error = remove_private_review_artifacts(
                        review.container_dir,
                        expected=review.private_cleanup,
                    )
                cleanup_completed = True
            else:
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
            try:
                cleanup_error_path.unlink(missing_ok=True)
            except OSError as error:
                raise ReviewError(
                    f"cannot clear resolved cleanup error {cleanup_error_path}: {error}"
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


def _cleanup_review_workspace(
    review: ReviewWorkspace | LegacyReviewWorkspace,
    *,
    keep_container: bool,
) -> str | None:
    if isinstance(review, LegacyReviewWorkspace):
        return cleanup_legacy_workspace(review, keep_container=keep_container)
    return cleanup_workspace(review, keep_container=keep_container)


def _cleanup_before_deadline(
    review: ReviewWorkspace | LegacyReviewWorkspace,
    *,
    deadline: float | None,
    cleanup_lock_fd: int,
    lock_handoff: Callable[[], None],
) -> tuple[bool, str | None]:
    if deadline is None:
        return True, _cleanup_review_workspace(review, keep_container=True)
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
