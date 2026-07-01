from __future__ import annotations

import json
import os
import pathlib
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Iterable


class ReviewError(RuntimeError):
    """A user-facing review helper failure."""


class ForwardedSignal(RuntimeError):
    """A termination signal forwarded to the active reviewer process group."""

    def __init__(self, signum: signal.Signals, *, detail: str | None = None) -> None:
        self.signum = signum
        self.detail = detail
        message = f"review orchestration received signal {int(signum)}"
        if detail:
            message += f"; {detail}"
        super().__init__(message)


@dataclass(frozen=True)
class Completed:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


TRUSTED_PATH = os.pathsep.join(
    (
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    )
)

BASE_ENV_KEYS = (
    "ALL_PROXY",
    "COLORTERM",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "HOME",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "NO_COLOR",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SHELL",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TERM",
    "USER",
    "XDG_CONFIG_HOME",
)

PROCESS_GROUP_TERM_GRACE_SECONDS = 0.5
PROCESS_GROUP_POLL_SECONDS = 0.05


def write_text_atomic(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = pathlib.Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def write_json(path: pathlib.Path, value: Any) -> None:
    write_text_atomic(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReviewError(f"cannot read review state {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReviewError(f"review state is not a JSON object: {path}")
    return value


def tail_text(
    path: pathlib.Path,
    *,
    line_count: int = 40,
    byte_count: int = 64 * 1024,
) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - byte_count)
            handle.seek(start)
            data = handle.read(byte_count)
    except OSError:
        return ""
    if start:
        _partial, separator, remainder = data.partition(b"\n")
        if separator:
            data = remainder
    lines = data.decode("utf-8", errors="replace").splitlines()
    return "\n".join(lines[-line_count:])


def run(
    argv: Iterable[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    stdin: bytes | None = None,
    check: bool = False,
    stdout_path: pathlib.Path | None = None,
    stderr_path: pathlib.Path | None = None,
    capture_limit_bytes: int = 4 * 1024 * 1024,
) -> Completed:
    command = tuple(str(item) for item in argv)
    if (stdout_path is None) != (stderr_path is None):
        raise ReviewError("stdout_path and stderr_path must be provided together")
    if stdout_path is None or stderr_path is None:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        result = Completed(
            command, completed.returncode, completed.stdout, completed.stderr
        )
    else:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            stdout_path.open("wb") as stdout_handle,
            stderr_path.open("wb") as stderr_handle,
        ):
            returncode = _run_logged_process(
                command,
                cwd=cwd,
                env=env,
                stdin=stdin,
                stdout_handle=stdout_handle,
                stderr_handle=stderr_handle,
            )
        result = Completed(
            command,
            returncode,
            _read_bounded_bytes(stdout_path, capture_limit_bytes),
            _read_bounded_bytes(stderr_path, capture_limit_bytes),
        )
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = result.stdout.decode("utf-8", errors="replace").strip()
        raise ReviewError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{detail}"
        )
    return result


def forwarded_signals() -> tuple[signal.Signals, ...]:
    forwarded = [signal.SIGTERM, signal.SIGINT]
    for name in ("SIGHUP", "SIGQUIT"):
        candidate = getattr(signal, name, None)
        if candidate is not None and candidate not in forwarded:
            forwarded.append(candidate)
    return tuple(forwarded)


def block_forwarded_signals() -> set[signal.Signals] | None:
    if (
        os.name != "posix"
        or threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "pthread_sigmask")
    ):
        return None
    return signal.pthread_sigmask(signal.SIG_BLOCK, forwarded_signals())


def restore_signal_mask(previous: set[signal.Signals] | None) -> None:
    if previous is not None:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def unblock_forwarded_signals() -> None:
    if os.name == "posix" and hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, forwarded_signals())


def consume_pending_forwarded_signal() -> signal.Signals | None:
    if not hasattr(signal, "sigpending") or not hasattr(signal, "sigwait"):
        return None
    pending = set(signal.sigpending()).intersection(forwarded_signals())
    if not pending:
        return None
    ordered = sorted(pending, key=int)
    for pending_signal in ordered:
        signal.sigwait({pending_signal})
    return ordered[0]


def _process_group_exists(process_pid: int) -> bool:
    if os.name != "posix":
        return False
    try:
        os.killpg(process_pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def signal_process_group(
    process: subprocess.Popen[bytes], signum: signal.Signals
) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signum)
            return
        except ProcessLookupError:
            return
    try:
        if signum == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
    except ProcessLookupError:
        pass


def terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    initial_signal: signal.Signals = signal.SIGTERM,
    signal_already_sent: bool = False,
    grace_seconds: float = PROCESS_GROUP_TERM_GRACE_SECONDS,
) -> None:
    if os.name != "posix":
        if process.poll() is None:
            if not signal_already_sent:
                signal_process_group(process, initial_signal)
            try:
                process.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        return
    if not _process_group_exists(process.pid):
        return
    if not signal_already_sent:
        signal_process_group(process, initial_signal)
    deadline = time.monotonic() + grace_seconds
    while _process_group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(PROCESS_GROUP_POLL_SECONDS)
    if _process_group_exists(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass


def _run_logged_process(
    command: tuple[str, ...],
    *,
    cwd: pathlib.Path | None,
    env: dict[str, str] | None,
    stdin: bytes | None,
    stdout_handle: BinaryIO,
    stderr_handle: BinaryIO,
) -> int:
    process: subprocess.Popen[bytes] | None = None
    pending_signal: signal.Signals | None = None

    def forward_signal(signum: int, _frame: object) -> None:
        nonlocal pending_signal
        forwarded = signal.Signals(signum)
        pending_signal = forwarded
        if process is None:
            return
        signal_process_group(process, forwarded)
        raise ForwardedSignal(forwarded)

    previous_handlers: dict[signal.Signals, object] = {}
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        for forwarded in forwarded_signals():
            previous_handlers[forwarded] = signal.getsignal(forwarded)
            signal.signal(forwarded, forward_signal)

    cleanup_signal = signal.SIGTERM
    try:
        if pending_signal is not None:
            raise ForwardedSignal(pending_signal)
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=stderr_handle,
            start_new_session=os.name == "posix",
        )
        if pending_signal is not None:
            signal_process_group(process, pending_signal)
            raise ForwardedSignal(pending_signal)
        process.communicate(input=stdin)
        return int(process.returncode)
    except ForwardedSignal as error:
        cleanup_signal = error.signum
        raise
    finally:
        previous_mask = block_forwarded_signals()
        pending_cleanup_signal: signal.Signals | None = None
        try:
            if process is not None:
                terminate_process_group(
                    process,
                    initial_signal=cleanup_signal,
                    signal_already_sent=pending_signal is not None,
                )
            for forwarded, previous in previous_handlers.items():
                signal.signal(forwarded, previous)
            if previous_mask is not None:
                pending_cleanup_signal = consume_pending_forwarded_signal()
        finally:
            restore_signal_mask(previous_mask)
        if pending_cleanup_signal is not None:
            raise ForwardedSignal(pending_cleanup_signal)


def _read_bounded_bytes(path: pathlib.Path, limit: int) -> bytes:
    if limit <= 0:
        raise ReviewError("capture_limit_bytes must be positive")
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size <= limit:
                return handle.read()
            head_size = limit // 2
            tail_size = limit - head_size
            head = handle.read(head_size)
            handle.seek(size - tail_size)
            tail = handle.read(tail_size)
    except OSError as error:
        raise ReviewError(
            f"cannot read bounded command output {path}: {error}"
        ) from error
    return head + b"\n... bounded capture omitted middle bytes ...\n" + tail


def resolve_executable(
    name: str, preferred_paths: Iterable[str]
) -> pathlib.Path | None:
    for candidate in preferred_paths:
        path = pathlib.Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    discovered = shutil.which(name, path=TRUSTED_PATH)
    if discovered is None:
        return None
    path = pathlib.Path(discovered).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    return path


def _nvm_version_key(path: pathlib.Path) -> tuple[int, ...]:
    try:
        version = path.parents[1].name.removeprefix("v")
    except IndexError:
        return ()
    parts: list[int] = []
    for value in version.split("."):
        if not value.isdigit():
            return ()
        parts.append(int(value))
    return tuple(parts)


def _user_executable_candidates(name: str) -> list[pathlib.Path]:
    home_value = os.environ.get("HOME")
    if not home_value:
        return []
    home = pathlib.Path(home_value).expanduser().absolute()
    candidates: list[pathlib.Path] = []
    nvm_bin = os.environ.get("NVM_BIN")
    if nvm_bin:
        nvm_path = pathlib.Path(nvm_bin).expanduser().absolute()
        if is_relative_to(nvm_path, home):
            candidates.append(nvm_path / name)
    candidates.append(home / ".nvm/current/bin" / name)
    nvm_candidates = list((home / ".nvm/versions/node").glob(f"*/bin/{name}"))
    candidates.extend(sorted(nvm_candidates, key=_nvm_version_key, reverse=True))
    candidates.extend(
        (
            home / ".local/bin" / name,
            home / ".volta/bin" / name,
            home / ".asdf/shims" / name,
            home / ".bun/bin" / name,
            home / ".npm-global/bin" / name,
            home / "bin" / name,
        )
    )
    return candidates


ENV_SHEBANG = re.compile(
    rb"^#![ \t]*/usr/bin/env(?:[ \t]+-S)?[ \t]+([A-Za-z0-9_.+-]+)(?:[ \t]|$)"
)


def _env_shebang_runtime(path: pathlib.Path) -> pathlib.Path | None:
    try:
        with path.open("rb") as handle:
            first_line = handle.readline(512)
    except OSError:
        return None
    match = ENV_SHEBANG.match(first_line.rstrip(b"\r\n"))
    if match is None:
        return None
    interpreter = match.group(1).decode("ascii")
    candidates = _user_executable_candidates(interpreter)
    discovered = shutil.which(interpreter, path=TRUSTED_PATH)
    if discovered:
        candidates.append(pathlib.Path(discovered))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.absolute()
    return None


def reviewer_executable_path(
    path: pathlib.Path,
    *,
    base_path: str = TRUSTED_PATH,
) -> str:
    entries = [str(path.parent)]
    runtime = _env_shebang_runtime(path)
    if runtime is not None and str(runtime.parent) not in entries:
        entries.append(str(runtime.parent))
    for entry in base_path.split(os.pathsep):
        if entry and entry not in entries:
            entries.append(entry)
    return os.pathsep.join(entries)


def _executable_identity_matches(
    path: pathlib.Path,
    markers: Iterable[str],
) -> bool:
    env = {
        "HOME": os.environ.get("HOME", str(pathlib.Path.home())),
        "NO_COLOR": "1",
        "PATH": reviewer_executable_path(path),
    }
    try:
        completed = subprocess.run(
            (str(path), "--version"),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    output = f"{completed.stdout.decode(errors='replace')}\n{completed.stderr.decode(errors='replace')}".lower()
    return all(marker.lower() in output for marker in markers)


def resolve_reviewer_executable(name: str) -> pathlib.Path | None:
    specs = {
        "codex": (
            "CODEX_REVIEW_CODEX_PATH",
            ("/opt/homebrew/bin/codex", "/usr/local/bin/codex"),
            ("codex-cli",),
        ),
        "claude": (
            "CODEX_REVIEW_CLAUDE_PATH",
            ("/opt/homebrew/bin/claude", "/usr/local/bin/claude"),
            ("claude code",),
        ),
        "copilot": (
            "CODEX_REVIEW_COPILOT_PATH",
            ("/opt/homebrew/bin/copilot", "/usr/local/bin/copilot"),
            ("github copilot cli",),
        ),
    }
    if name not in specs:
        raise ReviewError(f"unknown review executable: {name}")
    override_key, system_paths, markers = specs[name]
    override_value = os.environ.get(override_key)
    if override_value:
        override = pathlib.Path(override_value).expanduser()
        if not override.is_absolute():
            raise ReviewError(f"{override_key} must be an absolute executable path")
        if not override.is_file() or not os.access(override, os.X_OK):
            raise ReviewError(f"{override_key} is not executable: {override}")
        if not _executable_identity_matches(override, markers):
            raise ReviewError(
                f"{override_key} did not identify as the expected {name} CLI: {override}"
            )
        return override.absolute()

    candidates = [
        *(pathlib.Path(value) for value in system_paths),
        *_user_executable_candidates(name),
    ]
    discovered = shutil.which(name, path=TRUSTED_PATH)
    if discovered:
        candidates.append(pathlib.Path(discovered))
    seen: set[str] = set()
    rejected: list[pathlib.Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        if _executable_identity_matches(candidate, markers):
            return candidate.absolute()
        rejected.append(candidate.absolute())
    if rejected:
        paths = ", ".join(str(path) for path in rejected)
        raise ReviewError(
            f"found {name} CLI candidate(s), but executable identity validation "
            f"failed or timed out: {paths}"
        )
    return None


def resolve_git() -> pathlib.Path:
    path = resolve_executable(
        "git",
        ("/opt/homebrew/bin/git", "/usr/local/bin/git", "/usr/bin/git"),
    )
    if path is None:
        raise ReviewError("git is not available in a trusted executable path")
    return path


def is_relative_to(path: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def child_environment(
    *,
    container_dir: pathlib.Path,
    passthrough_keys: Iterable[str] = (),
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    allowed_keys = {*BASE_ENV_KEYS, *passthrough_keys}
    env = {key: os.environ[key] for key in allowed_keys if key in os.environ}
    env.update(
        {
            "PATH": TRUSTED_PATH,
            "TMPDIR": str(container_dir / "tmp"),
            "TMP": str(container_dir / "tmp"),
            "TEMP": str(container_dir / "tmp"),
        }
    )
    (container_dir / "tmp").mkdir(parents=True, exist_ok=True)
    if extra:
        env.update(extra)
    return env
