from __future__ import annotations

import atexit
import hashlib
import json
import os
import pathlib
import pwd
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

from review_supervisor.constants import (
    CONTROL_ARTIFACT_SPECS,
    HELPER_PREFLIGHT_STATUS,
    HELPER_STATE_MARKER_TEXT,
)
from review_supervisor.secureio import identity_from_stat


_RUNTIME_ROOT: pathlib.Path | None = None
_RUNTIME_ROOT_PID: int | None = None


def _validated_private_runtime_parent(raw_path: str) -> pathlib.Path | None:
    candidate = pathlib.Path(raw_path)
    if not candidate.is_absolute():
        return None
    try:
        canonical = candidate.resolve(strict=True)
    except OSError:
        return None
    try:
        str(canonical).encode("ascii")
    except UnicodeEncodeError:
        return None

    owner_uid = os.getuid()
    current = pathlib.Path("/")
    try:
        root_metadata = current.stat(follow_symlinks=False)
    except OSError:
        return None
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != 0
        or root_metadata.st_mode
        & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
    ):
        return None
    for part in canonical.parts[1:]:
        current /= part
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError:
            return None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, owner_uid}
            or metadata.st_mode
            & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        ):
            return None

    try:
        leaf = canonical.stat(follow_symlinks=False)
    except OSError:
        return None
    if leaf.st_uid != owner_uid or not os.access(canonical, os.W_OK | os.X_OK):
        return None
    return canonical


def _private_runtime_parent() -> pathlib.Path:
    account_home = pwd.getpwuid(os.getuid()).pw_dir
    # Shared OS runtime roots have unrelated metadata churn that invalidates
    # executable path-identity checks while a fixture is under authentication.
    candidates = (
        *_repository_runtime_candidates(),
        account_home,
        os.environ.get("XDG_RUNTIME_DIR"),
        os.environ.get("TMPDIR"),
    )
    for raw_path in candidates:
        if raw_path and (parent := _validated_private_runtime_parent(raw_path)):
            return parent
    raise RuntimeError("no trusted private test runtime parent is available")


def _repository_runtime_candidates() -> tuple[str, ...]:
    git = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin")
    if git is None:
        return ()
    environment = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    try:
        result = subprocess.run(
            (
                git,
                "-C",
                str(pathlib.Path(__file__).resolve().parent),
                "rev-parse",
                "--path-format=absolute",
                "--show-toplevel",
                "--git-common-dir",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if result.returncode != 0 or len(result.stdout) > 8192:
        return ()
    try:
        checkout_text, common_text = result.stdout.decode("utf-8").splitlines()
    except (UnicodeDecodeError, ValueError):
        return ()
    checkout = pathlib.Path(checkout_text)
    common_dir = pathlib.Path(common_text)
    candidates = [str(checkout.parent)]
    if common_dir.name == ".git":
        candidates.append(str(common_dir.parent.parent))
    return tuple(dict.fromkeys(candidates))


def _cleanup_process_runtime_root(path: pathlib.Path, owner_pid: int) -> None:
    if os.getpid() == owner_pid:
        shutil.rmtree(path, ignore_errors=True)


def _process_runtime_root() -> pathlib.Path:
    global _RUNTIME_ROOT, _RUNTIME_ROOT_PID

    current_pid = os.getpid()
    if _RUNTIME_ROOT is not None and _RUNTIME_ROOT_PID == current_pid:
        return _RUNTIME_ROOT

    root = pathlib.Path(
        tempfile.mkdtemp(
            prefix=".codex-review-tests-",
            dir=_private_runtime_parent(),
        )
    )
    os.chmod(root, 0o700)
    metadata = root.stat(follow_symlinks=False)
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        shutil.rmtree(root, ignore_errors=True)
        raise RuntimeError("test runtime root has an unsafe identity")
    _RUNTIME_ROOT = root
    _RUNTIME_ROOT_PID = current_pid
    atexit.register(_cleanup_process_runtime_root, root, current_pid)
    return root


@contextmanager
def owned_temporary_directory(prefix: str) -> Iterator[pathlib.Path]:
    path = pathlib.Path(
        tempfile.mkdtemp(
            prefix=f".codex-review-{prefix}",
            dir=_process_runtime_root(),
        )
    )
    os.chmod(path, 0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path)


def _write(path: pathlib.Path, content: bytes) -> None:
    path.write_bytes(content)
    os.chmod(path, 0o600)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _names_digest(names: set[str]) -> str:
    return _digest(b"\0".join(name.encode("ascii") for name in sorted(names)))


def bind_attempt_state(
    state: dict[str, object],
    *,
    retention_root: pathlib.Path,
    attempt_dir: pathlib.Path,
) -> dict[str, object]:
    if attempt_dir.parent != retention_root:
        raise ValueError("test attempt is not an exact retention-root child")
    state.update(
        {
            "retention_root_binding": {
                "path": str(retention_root),
                "identity": identity_from_stat(
                    os.stat(retention_root, follow_symlinks=False)
                ).to_json(),
            },
            "attempt_directory_binding": {
                "path": str(attempt_dir),
                "identity": identity_from_stat(
                    os.stat(attempt_dir, follow_symlinks=False)
                ).to_json(),
            },
        }
    )
    return state


def build_helper_fixture(
    root: pathlib.Path,
    *,
    source_repo: pathlib.Path | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    primary_diff: bytes | None = None,
) -> dict[str, object]:
    repo = source_repo or root / "repo"
    state_dir = root / "helper-state"
    workspace = state_dir / "workspace"
    control = workspace / ".codex-review"
    directories = (
        (state_dir, workspace, control)
        if source_repo is not None
        else (repo, state_dir, workspace, control)
    )
    for directory in directories:
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)

    base = base_sha or "1" * 40
    head = head_sha or "2" * 40
    artifacts: dict[str, bytes] = {
        "changed-paths.z": b"paths",
        "changed-blob-findings.z": b"findings",
        "synthetic-secret-manifest.json": b"{}\n",
        "synthetic-changed-evidence.json": b"{}\n",
        "review.diff": (
            primary_diff
            if primary_diff is not None
            else b"diff --git a/a.txt b/a.txt\n+new\n"
        ),
        "review.prompt": b"review\n",
    }
    artifact_records: list[dict[str, object]] = []
    for name in CONTROL_ARTIFACT_SPECS:
        content = artifacts[name]
        _write(control / name, content)
        if name == "changed-paths.z":
            record_count: int | None = 1
        elif name == "changed-blob-findings.z":
            record_count = 3
        else:
            record_count = None
        artifact_records.append(
            {
                "name": name,
                "record_count": record_count,
                "sha256": _digest(content),
                "size": len(content),
            }
        )

    control_stat = os.stat(control, follow_symlinks=False)
    control_state = {
        "artifacts": artifact_records,
        "directory": {
            "ctime_ns": control_stat.st_ctime_ns,
            "device": control_stat.st_dev,
            "entry_count": len(artifacts),
            "entry_names_sha256": _names_digest(set(artifacts)),
            "inode": control_stat.st_ino,
            "link_count": control_stat.st_nlink,
            "mode": control_stat.st_mode,
            "mtime_ns": control_stat.st_mtime_ns,
            "uid": control_stat.st_uid,
        },
        "schema_version": 2,
    }
    diff = artifacts["review.diff"]
    preflight = {
        "status": HELPER_PREFLIGHT_STATUS,
        "review_range": f"{base}..{head}",
        "primary_diff": {
            "path": ".codex-review/review.diff",
            "sha256": _digest(diff),
            "size": len(diff),
        },
    }
    helper_state = {
        "version": 1,
        "reviewer": "codex",
        "keep_workspace": True,
        "workspace": {
            "source_root": str(repo),
            "container_dir": str(state_dir),
            "workspace_root": str(workspace),
            "base_ref": base,
            "head_ref": head,
            "diff_file": str(control / "review.diff"),
            "prompt_file": str(control / "review.prompt"),
        },
    }
    _write(state_dir / ".isolated-review-state", HELPER_STATE_MARKER_TEXT)
    _write(state_dir / "runner.lock", b"")
    _write(state_dir / "cleanup.lock", b"")
    _write(state_dir / "exit-code", b"0\n")
    _write(
        state_dir / "state.json",
        (
            json.dumps(helper_state, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
    )
    _write(
        state_dir / "preflight.json",
        (json.dumps(preflight, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )
    _write(
        state_dir / "control-artifact-state.json",
        (
            json.dumps(control_state, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
    )
    return {
        "repo": repo,
        "state_dir": state_dir,
        "workspace": workspace,
        "base": base,
        "head": head,
        "diff": diff,
    }
