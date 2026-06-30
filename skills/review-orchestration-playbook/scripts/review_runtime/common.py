from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Iterable


class ReviewError(RuntimeError):
    """A user-facing review helper failure."""


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
    "HOME",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "NO_COLOR",
    "NO_PROXY",
    "SHELL",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TERM",
    "USER",
    "XDG_CONFIG_HOME",
)


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


def tail_text(path: pathlib.Path, *, line_count: int = 40) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-line_count:])


def run(
    argv: Iterable[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    stdin: bytes | None = None,
    check: bool = False,
) -> Completed:
    command = tuple(str(item) for item in argv)
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
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = result.stdout.decode("utf-8", errors="replace").strip()
        raise ReviewError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{detail}"
        )
    return result


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


def require_path_within(
    path: pathlib.Path, parent: pathlib.Path, *, label: str
) -> pathlib.Path:
    resolved_path = path.resolve(strict=False)
    resolved_parent = parent.resolve(strict=False)
    if not is_relative_to(resolved_path, resolved_parent):
        raise ReviewError(f"{label} escapes its review container: {resolved_path}")
    return resolved_path


def install_readonly_git_shim(
    *,
    container_dir: pathlib.Path,
    source: pathlib.Path,
) -> pathlib.Path:
    shim_dir = container_dir / "tool-shims"
    shim_dir.mkdir(parents=True, exist_ok=True)
    target = shim_dir / "git"
    text = source.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        raise ReviewError(f"readonly git shim is empty: {source}")
    lines[0] = f"#!{pathlib.Path(sys.executable).resolve()}"
    write_text_atomic(target, "\n".join(lines) + "\n")
    target.chmod(0o755)
    return shim_dir


def child_environment(
    *,
    container_dir: pathlib.Path,
    shim_source: pathlib.Path,
    passthrough_keys: Iterable[str] = (),
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    real_git = resolve_git()
    shim_dir = install_readonly_git_shim(
        container_dir=container_dir, source=shim_source
    )
    allowed_keys = {*BASE_ENV_KEYS, *passthrough_keys}
    env = {key: os.environ[key] for key in allowed_keys if key in os.environ}
    env.update(
        {
            "PATH": f"{shim_dir}{os.pathsep}{TRUSTED_PATH}",
            "CODEX_REAL_GIT": str(real_git),
            "CODEX_ISOLATED_REVIEW_GIT_POLICY": "readonly-shim",
            "CODEX_ISOLATED_REVIEW_GIT_SHIM": str(shim_dir / "git"),
            "TMPDIR": str(container_dir / "tmp"),
            "TMP": str(container_dir / "tmp"),
            "TEMP": str(container_dir / "tmp"),
        }
    )
    (container_dir / "tmp").mkdir(parents=True, exist_ok=True)
    if extra:
        env.update(extra)
    return env
