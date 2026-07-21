from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

from review_supervisor.constants import (
    CONTROL_ARTIFACT_SPECS,
    HELPER_PREFLIGHT_STATUS,
    HELPER_STATE_MARKER_TEXT,
)


RUNTIME_ROOT = pathlib.Path(__file__).parent / ".runtime"


@contextmanager
def owned_temporary_directory(prefix: str) -> Iterator[pathlib.Path]:
    RUNTIME_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = pathlib.Path(tempfile.mkdtemp(prefix=prefix, dir=RUNTIME_ROOT))
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


def build_helper_fixture(
    root: pathlib.Path,
    *,
    source_repo: pathlib.Path | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
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
        "review.diff": b"diff --git a/a.txt b/a.txt\n+new\n",
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
