from __future__ import annotations

import os
import pathlib
import re
from dataclasses import dataclass

from .constants import (
    HELPER_PREFLIGHT_STATUS,
    HELPER_STATE_MARKER_TEXT,
    MAX_CONTROL_STATE_BYTES,
    MAX_DIFF_BYTES,
    MAX_EVIDENCE_PRIMARY_BYTES,
    MAX_PREFLIGHT_BYTES,
    PRIMARY_DIFF_RELATIVE_PATH,
)
from .custody import (
    _open_child_directory,
    _read_leaf_bytes,
    _read_leaf_json,
    _validate_control_state,
    _validate_runner_complete,
)
from .evidence import (
    EvidenceError,
    EvidenceBundle,
    build_primary_evidence_bundle,
)
from .models import Identity
from .secureio import (
    open_absolute_directory_chain,
    open_regular_at,
    read_fd_exact,
    sha256_bytes,
)


HEX_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class FrozenSourceError(ValueError):
    pass


@dataclass
class FrozenSourceCustody:
    workspace_root: pathlib.Path
    workspace_identity: Identity
    workspace_fd: int
    diff_fd: int
    diff_identity: Identity
    diff_size: int
    diff_sha256: str
    review_range: str
    preflight_sha256: str
    control_state_sha256: str
    _closed: bool = False

    def build_bundle(self) -> EvidenceBundle:
        if self._closed:
            raise FrozenSourceError("frozen source custody is closed")
        content = read_fd_exact(
            self.diff_fd,
            max_bytes=MAX_EVIDENCE_PRIMARY_BYTES,
            expected_size=self.diff_size,
        )
        if sha256_bytes(content) != self.diff_sha256:
            raise FrozenSourceError("held retained diff changed after authentication")
        try:
            return build_primary_evidence_bundle(
                content,
                expected_sha256=self.diff_sha256,
            )
        except EvidenceError as error:
            raise FrozenSourceError(
                "held retained diff cannot be serialized as reviewer evidence"
            ) from error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        first_error: OSError | None = None
        for fd in (self.diff_fd, self.workspace_fd):
            try:
                os.close(fd)
            except OSError as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    def __enter__(self) -> FrozenSourceCustody:
        if self._closed:
            raise FrozenSourceError("frozen source custody is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def authenticate_frozen_source(
    *,
    state_dir: pathlib.Path,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
) -> FrozenSourceCustody:
    if (
        not state_dir.is_absolute()
        or not repo.is_absolute()
        or any(part in {".", ".."} for part in (*state_dir.parts, *repo.parts))
        or HEX_OBJECT.fullmatch(base_sha) is None
        or HEX_OBJECT.fullmatch(head_sha) is None
    ):
        raise FrozenSourceError("frozen source inputs are not exact absolute values")

    state_fd: int | None = None
    workspace_fd: int | None = None
    control_fd: int | None = None
    diff_fd: int | None = None
    try:
        state_fd, _ = open_absolute_directory_chain(
            state_dir,
            private_leaf=True,
        )
        marker, _ = _read_leaf_bytes(state_fd, b".isolated-review-state", max_bytes=64)
        if marker != HELPER_STATE_MARKER_TEXT:
            raise FrozenSourceError("helper state marker is invalid")
        state, _, _ = _read_leaf_json(
            state_fd,
            b"state.json",
            max_bytes=MAX_PREFLIGHT_BYTES,
        )
        if (
            not isinstance(state, dict)
            or state.get("version") != 1
            or state.get("reviewer") != "codex"
            or state.get("keep_workspace") is not True
        ):
            raise FrozenSourceError("helper state is not a retained Codex review")
        workspace = state.get("workspace")
        workspace_keys = {
            "base_ref",
            "container_dir",
            "diff_file",
            "head_ref",
            "prompt_file",
            "source_root",
            "workspace_root",
        }
        if not isinstance(workspace, dict) or set(workspace) != workspace_keys:
            raise FrozenSourceError("helper workspace state is malformed")
        if (
            workspace["container_dir"] != str(state_dir)
            or workspace["base_ref"] != base_sha
            or workspace["head_ref"] != head_sha
            or pathlib.Path(workspace["source_root"]).resolve(strict=True)
            != repo.resolve(strict=True)
        ):
            raise FrozenSourceError("helper state does not bind the requested source")

        workspace_root = pathlib.Path(workspace["workspace_root"])
        expected_diff = workspace_root / PRIMARY_DIFF_RELATIVE_PATH
        if (
            not workspace_root.is_absolute()
            or pathlib.Path(workspace["diff_file"]) != expected_diff
        ):
            raise FrozenSourceError("helper diff path is not canonical")
        _validate_runner_complete(state_fd)
        exit_code, _ = _read_leaf_bytes(state_fd, b"exit-code", max_bytes=32)
        if exit_code.strip() != b"0":
            raise FrozenSourceError("retained helper review did not exit cleanly")

        review_range = f"{base_sha}..{head_sha}"
        preflight, preflight_raw, _ = _read_leaf_json(
            state_fd,
            b"preflight.json",
            max_bytes=MAX_PREFLIGHT_BYTES,
        )
        if (
            not isinstance(preflight, dict)
            or preflight.get("status") != HELPER_PREFLIGHT_STATUS
            or preflight.get("review_range") != review_range
        ):
            raise FrozenSourceError("helper preflight does not attest the review range")
        primary = preflight.get("primary_diff")
        if (
            not isinstance(primary, dict)
            or set(primary) != {"path", "sha256", "size"}
            or primary.get("path") != PRIMARY_DIFF_RELATIVE_PATH
            or type(primary.get("size")) is not int
            or not 0 <= primary["size"] <= MAX_DIFF_BYTES
            or not isinstance(primary.get("sha256"), str)
            or HEX_SHA256.fullmatch(primary["sha256"]) is None
        ):
            raise FrozenSourceError("helper primary_diff attestation is malformed")

        control_state, control_raw, _ = _read_leaf_json(
            state_fd,
            b"control-artifact-state.json",
            max_bytes=MAX_CONTROL_STATE_BYTES,
        )
        workspace_fd, workspace_identity = open_absolute_directory_chain(
            workspace_root,
            private_leaf=True,
        )
        try:
            os.stat(b".git", dir_fd=workspace_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FrozenSourceError("retained helper workspace contains .git")
        control_fd, _ = _open_child_directory(
            workspace_fd,
            b".codex-review",
            label="helper control directory",
            display_path=workspace_root / ".codex-review",
        )
        diff_size, diff_sha256 = _validate_control_state(
            control_state,
            control_fd=control_fd,
        )
        if (primary["size"], primary["sha256"]) != (diff_size, diff_sha256):
            raise FrozenSourceError(
                "preflight and control-state primary diff attestations differ"
            )
        if not 1 <= diff_size <= MAX_EVIDENCE_PRIMARY_BYTES:
            raise FrozenSourceError("retained diff exceeds the independent gate bound")
        diff_fd, diff_identity = open_regular_at(
            control_fd,
            b"review.diff",
            expected_uid=os.getuid(),
            require_link_one=True,
        )
        content = read_fd_exact(
            diff_fd,
            max_bytes=MAX_EVIDENCE_PRIMARY_BYTES,
            expected_size=diff_size,
        )
        if diff_identity.size != diff_size or sha256_bytes(content) != diff_sha256:
            raise FrozenSourceError(
                "retained diff differs from helper control evidence"
            )
        os.lseek(diff_fd, 0, os.SEEK_SET)
        result = FrozenSourceCustody(
            workspace_root=workspace_root,
            workspace_identity=workspace_identity,
            workspace_fd=workspace_fd,
            diff_fd=diff_fd,
            diff_identity=diff_identity,
            diff_size=diff_size,
            diff_sha256=diff_sha256,
            review_range=review_range,
            preflight_sha256=sha256_bytes(preflight_raw),
            control_state_sha256=sha256_bytes(control_raw),
        )
        workspace_fd = None
        diff_fd = None
        return result
    except FrozenSourceError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise FrozenSourceError(
            "retained helper source authentication failed"
        ) from error
    finally:
        for fd in (diff_fd, control_fd, workspace_fd, state_fd):
            if fd is not None:
                os.close(fd)
