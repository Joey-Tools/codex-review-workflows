from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

from .common import ReviewError, read_json, tail_text, write_json, write_text_atomic
from .providers import run_review
from .workspace import (
    ReviewWorkspace,
    cleanup_workspace,
    prepare_workspace,
    validate_workspace_layout,
)


STATE_FILE = "state.json"
STATE_MARKER = ".isolated-review-state"
EXIT_FILE = "exit-code"
_STARTED_PROCESSES: dict[int, subprocess.Popen[bytes]] = {}


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
    except OSError:
        return None
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        raise ReviewError(f"invalid exit code in {path}: {text!r}")


def _pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    process = _STARTED_PROCESSES.get(pid)
    if process is not None:
        return process.poll() is None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


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
) -> pathlib.Path:
    review = prepare_workspace(
        repo=repo,
        base_ref=base_ref,
        head_ref=head_ref,
        prompt_override=prompt_file,
    )
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
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "final_path": str(state_dir / "final.txt"),
        "attempts_path": str(state_dir / "attempts.json"),
        "started_at": time.time(),
    }
    write_json(state_dir / STATE_FILE, state)
    try:
        with (
            stdout_path.open("wb") as stdout_handle,
            stderr_path.open("wb") as stderr_handle,
        ):
            process = subprocess.Popen(
                (
                    sys.executable,
                    str(script_path),
                    "_run-state",
                    "--state-dir",
                    str(state_dir),
                ),
                cwd=review.workspace_root,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                start_new_session=True,
                close_fds=True,
            )
    except Exception:
        cleanup_workspace(review, keep_container=False)
        raise
    state["pid"] = process.pid
    _STARTED_PROCESSES[process.pid] = process
    write_json(state_dir / STATE_FILE, state)
    return state_dir


def run_state(*, state_dir: pathlib.Path, shim_source: pathlib.Path) -> int:
    state, review = load_review_state(state_dir)
    reviewer = state.get("reviewer")
    if not isinstance(reviewer, str):
        raise ReviewError("review state does not contain a reviewer")
    exit_code = 1
    try:
        consent_value = state.get("egress_consent")
        egress_consent = consent_value if isinstance(consent_value, str) else None
        outcome = run_review(
            review=review,
            reviewer=reviewer,
            shim_source=shim_source,
            egress_consent=egress_consent,
        )
        exit_code = outcome.returncode
    except Exception as error:
        write_text_atomic(
            state_dir / "runner-error.txt", f"{type(error).__name__}: {error}\n"
        )
        exit_code = 1
    finally:
        write_text_atomic(state_dir / EXIT_FILE, f"{exit_code}\n")
    return exit_code


def status(state_dir: pathlib.Path) -> dict[str, Any]:
    state_dir = state_dir.expanduser().resolve()
    state, _review = load_review_state(state_dir)
    exit_code = _read_exit_code(state_dir)
    pid_value = state.get("pid")
    pid = pid_value if isinstance(pid_value, int) else 0
    process_running = _pid_running(pid)
    running = exit_code is None and process_running
    if exit_code is not None:
        _reap_started_process(pid)
    if exit_code is None and not running:
        exit_code = 1
        write_text_atomic(state_dir / EXIT_FILE, "1\n")
        write_text_atomic(
            state_dir / "runner-error.txt",
            "review runner exited without recording a terminal result\n",
        )
    attempts: list[Any] = []
    attempts_path = state_dir / "attempts.json"
    if attempts_path.is_file():
        try:
            parsed_attempts = json.loads(attempts_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            parsed_attempts = []
        if isinstance(parsed_attempts, list):
            attempts = parsed_attempts
    return {
        "state_dir": str(state_dir),
        "reviewer": state.get("reviewer"),
        "egress_consent": state.get("egress_consent"),
        "pid": pid or None,
        "running": running,
        "exit_code": exit_code,
        "attempts": attempts,
        "stdout_tail": tail_text(state_dir / "runner.stdout.log"),
        "stderr_tail": tail_text(state_dir / "runner.stderr.log"),
        "runner_error": tail_text(state_dir / "runner-error.txt"),
        "cleanup_error": tail_text(state_dir / "cleanup-error.txt"),
    }


def wait(
    state_dir: pathlib.Path,
    *,
    timeout_seconds: float | None,
) -> int:
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    while True:
        summary = status(state_dir)
        if not summary["running"]:
            break
        if deadline is not None and time.monotonic() >= deadline:
            return 124
        time.sleep(0.25)

    state, review = load_review_state(state_dir)
    keep_workspace = bool(state.get("keep_workspace"))
    if review.workspace_root.exists() and not keep_workspace:
        cleanup_error = cleanup_workspace(review, keep_container=True)
        if cleanup_error:
            write_text_atomic(state_dir / "cleanup-error.txt", cleanup_error + "\n")
            return 1
    if (state_dir / "cleanup-error.txt").is_file():
        return 1
    exit_code = _read_exit_code(state_dir)
    return 1 if exit_code is None else exit_code


def final(state_dir: pathlib.Path) -> tuple[int, str]:
    summary = status(state_dir)
    if summary["running"]:
        return 3, "review is still running"
    wait_code = wait(state_dir, timeout_seconds=0)
    cleanup_error = tail_text(state_dir.expanduser().resolve() / "cleanup-error.txt")
    if cleanup_error:
        return 1, f"review completed but workspace cleanup failed: {cleanup_error}"
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
    return int(wait_code or exit_code or 1), str(details)
