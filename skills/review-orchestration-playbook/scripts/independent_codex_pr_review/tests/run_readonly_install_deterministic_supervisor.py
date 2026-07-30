from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile

from .support import _private_runtime_parent


EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
READONLY_INSTALL_PARENT = pathlib.Path("/private/tmp")


def _tree_snapshot(root: pathlib.Path) -> dict[str, tuple[str, int, str | None]]:
    snapshot: dict[str, tuple[str, int, str | None]] = {}
    paths = (root, *sorted(root.rglob("*")))
    for path in paths:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            kind = "file"
        elif stat.S_ISDIR(metadata.st_mode):
            digest = None
            kind = "directory"
        elif stat.S_ISLNK(metadata.st_mode):
            digest = hashlib.sha256(os.readlink(path).encode("utf-8")).hexdigest()
            kind = "symlink"
        else:
            digest = None
            kind = "other"
        snapshot[relative] = (kind, mode, digest)
    return snapshot


def _set_tree_read_only(root: pathlib.Path) -> None:
    for path in (root, *sorted(root.rglob("*"))):
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _restore_owner_write(root: pathlib.Path) -> None:
    for path in sorted(
        (root, *root.rglob("*")),
        key=lambda item: len(item.parts),
    ):
        if path.is_symlink():
            continue
        try:
            mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
            path.chmod(mode | stat.S_IWUSR)
        except FileNotFoundError:
            continue


def _bounded_failure_text(value: str, *, limit: int = 16_384) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]


def main() -> int:
    if sys.platform != "darwin":
        print("read-only installed supervisor regression requires Darwin", file=sys.stderr)
        return 2
    parent_metadata = READONLY_INSTALL_PARENT.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or not parent_metadata.st_mode & stat.S_ISVTX
        or not parent_metadata.st_mode & stat.S_IWOTH
    ):
        print("/private/tmp is not the expected 01777-style parent", file=sys.stderr)
        return 2

    source_root = pathlib.Path(__file__).resolve().parents[1]
    install_container = pathlib.Path(
        tempfile.mkdtemp(
            prefix=".codex-review-readonly-install-",
            dir=READONLY_INSTALL_PARENT,
        )
    )
    runtime_parent = pathlib.Path(
        tempfile.mkdtemp(
            prefix=".codex-review-readonly-runtime-",
            dir=_private_runtime_parent(),
        )
    )
    os.chmod(install_container, 0o700)
    os.chmod(runtime_parent, 0o700)
    installed_root = install_container / "independent_codex_pr_review"
    try:
        shutil.copytree(
            source_root,
            installed_root,
            symlinks=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        _set_tree_read_only(installed_root)
        before = _tree_snapshot(installed_root)
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONPYCACHEPREFIX", None)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                EXPLICIT_RUNTIME_PARENT_ENV: str(runtime_parent),
            }
        )
        completed = subprocess.run(
            (
                sys.executable,
                "-B",
                "-m",
                "tests.run_required_deterministic_supervisor",
            ),
            cwd=installed_root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
        after = _tree_snapshot(installed_root)
        runtime_residue = sorted(path.name for path in runtime_parent.iterdir())
        summary = {
            "install_parent_is_sticky_world_writable": True,
            "release_tree_immutable": after == before,
            "returncode": completed.returncode,
            "runtime_residue": runtime_residue,
        }
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        if completed.returncode != 0 or after != before or runtime_residue:
            if completed.stdout:
                print(_bounded_failure_text(completed.stdout), file=sys.stderr)
            if completed.stderr:
                print(_bounded_failure_text(completed.stderr), file=sys.stderr)
            return 1
        return 0
    except subprocess.TimeoutExpired as error:
        print("read-only installed supervisor regression timed out", file=sys.stderr)
        for value in (error.stdout, error.stderr):
            if value:
                text = (
                    value.decode("utf-8", "replace")
                    if isinstance(value, bytes)
                    else value
                )
                print(_bounded_failure_text(text), file=sys.stderr)
        return 1
    finally:
        if installed_root.exists():
            _restore_owner_write(installed_root)
        shutil.rmtree(install_container, ignore_errors=True)
        shutil.rmtree(runtime_parent, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
