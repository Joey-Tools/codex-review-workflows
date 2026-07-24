from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import re
import socket
import stat
import time
from dataclasses import dataclass
from typing import Any

from .constants import (
    CONTROL_ARTIFACT_SPECS,
    HELPER_PREFLIGHT_STATUS,
    HELPER_SAFE_LOCK_MODES,
    HELPER_STATE_MARKER_TEXT,
    MAX_CONTROL_STATE_BYTES,
    MAX_DIFF_BYTES,
    MAX_PREFLIGHT_BYTES,
    PRIMARY_DIFF_RELATIVE_PATH,
)
from .errors import SupervisorError, blocked, inconclusive
from .models import HelperCustody, Identity
from .secureio import (
    acquire_flock,
    decode_json_bytes,
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    open_regular_at,
    read_fd_exact,
    sha256_bytes,
    validate_private_directory_fd,
)
from .wire import receive_record, send_record


HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
HEX_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IDENTITY_FIELDS = {
    "device",
    "inode",
    "link_count",
    "mode",
    "size",
    "uid",
}
_DIRECTORY_PROTOCOL_FIELDS = {"device", "inode", "mode", "uid"}


@dataclass
class CustodyHandles:
    cleanup_lock_fd: int
    source_fd: int
    evidence: HelperCustody

    def close(self) -> None:
        for fd in (self.source_fd, self.cleanup_lock_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def helper_custody_evidence_matches(
    actual: HelperCustody | dict[str, Any],
    expected: HelperCustody | dict[str, Any],
) -> bool:
    """Compare custody protocol evidence at the protected-property boundary."""

    actual_value = actual.to_json() if isinstance(actual, HelperCustody) else actual
    expected_value = (
        expected.to_json() if isinstance(expected, HelperCustody) else expected
    )
    if (
        not isinstance(actual_value, dict)
        or not isinstance(expected_value, dict)
        or set(actual_value) != set(expected_value)
    ):
        return False
    actual_state = actual_value.get("state_identity")
    expected_state = expected_value.get("state_identity")
    if (
        not isinstance(actual_state, dict)
        or not isinstance(expected_state, dict)
        or set(actual_state) != _IDENTITY_FIELDS
        or set(expected_state) != _IDENTITY_FIELDS
        or any(type(actual_state[field]) is not int for field in _IDENTITY_FIELDS)
        or any(type(expected_state[field]) is not int for field in _IDENTITY_FIELDS)
        or any(
            actual_state[field] != expected_state[field]
            for field in _DIRECTORY_PROTOCOL_FIELDS
        )
    ):
        return False
    normalized = dict(actual_value)
    normalized["state_identity"] = dict(expected_state)
    try:
        return json.dumps(
            normalized,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ) == json.dumps(
            expected_value,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        return False


def _read_leaf_json(
    parent_fd: int,
    name: bytes,
    *,
    max_bytes: int,
) -> tuple[Any, bytes, Identity]:
    fd, identity = open_regular_at(parent_fd, name, expected_uid=os.getuid())
    try:
        if identity.size > max_bytes:
            raise ValueError(f"{os.fsdecode(name)} exceeds {max_bytes} bytes")
        raw = read_fd_exact(fd, max_bytes=max_bytes, expected_size=identity.size)
        return decode_json_bytes(raw), raw, identity
    finally:
        os.close(fd)


def _read_leaf_bytes(
    parent_fd: int,
    name: bytes,
    *,
    max_bytes: int,
) -> tuple[bytes, Identity]:
    fd, identity = open_regular_at(parent_fd, name, expected_uid=os.getuid())
    try:
        return read_fd_exact(
            fd, max_bytes=max_bytes, expected_size=identity.size
        ), identity
    finally:
        os.close(fd)


def _open_child_directory(
    parent_fd: int,
    name: bytes,
    *,
    label: str,
    display_path: pathlib.Path,
) -> tuple[int, Identity]:
    fd = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity = validate_private_directory_fd(fd, display_path)
        if not directory_identities_match(identity, identity_from_stat(path_stat)):
            raise ValueError(f"{label} changed while it was opened")
        return fd, identity
    except BaseException:
        os.close(fd)
        raise


def _directory_names(fd: int, *, cap: int) -> tuple[str, ...]:
    names = os.listdir(fd)
    if len(names) > cap:
        raise ValueError("directory entry count exceeds its bound")
    if any("/" in name or "\0" in name or not name for name in names):
        raise ValueError("directory contains an invalid entry name")
    return tuple(names)


def _entry_names_digest(names: tuple[str, ...] | set[str]) -> str:
    encoded = b"\0".join(name.encode("ascii") for name in sorted(names))
    return hashlib.sha256(encoded).hexdigest()


def _validate_control_state(
    payload: Any,
    *,
    control_fd: int,
) -> tuple[int, str]:
    if not isinstance(payload, dict) or set(payload) != {
        "artifacts",
        "directory",
        "schema_version",
    }:
        raise ValueError("control-artifact-state fields are invalid")
    if payload["schema_version"] != 2:
        raise ValueError("control-artifact-state schema is unsupported")
    directory = payload["directory"]
    directory_fields = {
        "ctime_ns",
        "device",
        "entry_count",
        "entry_names_sha256",
        "inode",
        "link_count",
        "mode",
        "mtime_ns",
        "uid",
    }
    if not isinstance(directory, dict) or set(directory) != directory_fields:
        raise ValueError("control directory evidence is malformed")
    integer_fields = directory_fields - {"entry_names_sha256"}
    if any(type(directory[field]) is not int for field in integer_fields):
        raise ValueError("control directory evidence contains a non-integer field")
    actual_stat = os.fstat(control_fd)
    actual_names = _directory_names(control_fd, cap=len(CONTROL_ARTIFACT_SPECS))
    actual_identity = {
        "device": actual_stat.st_dev,
        "inode": actual_stat.st_ino,
        "mode": actual_stat.st_mode,
        "uid": actual_stat.st_uid,
    }
    expected_identity = {
        field: directory[field] for field in ("device", "inode", "mode", "uid")
    }
    if actual_identity != expected_identity:
        raise ValueError("control directory no longer matches helper evidence")
    if (
        len(actual_names) != directory["entry_count"]
        or _entry_names_digest(actual_names) != directory["entry_names_sha256"]
        or set(actual_names) != set(CONTROL_ARTIFACT_SPECS)
    ):
        raise ValueError("control directory has an unexpected entry-name set")

    artifacts = payload["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(CONTROL_ARTIFACT_SPECS):
        raise ValueError("control artifact list is malformed")
    by_name: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "record_count",
            "sha256",
            "size",
        }:
            raise ValueError("control artifact entry is malformed")
        name = item["name"]
        if (
            not isinstance(name, str)
            or name not in CONTROL_ARTIFACT_SPECS
            or name in by_name
        ):
            raise ValueError("control artifact name is invalid or duplicate")
        limit, record_limit = CONTROL_ARTIFACT_SPECS[name]
        size = item["size"]
        digest = item["sha256"]
        record_count = item["record_count"]
        if type(size) is not int or not 0 <= size <= limit:
            raise ValueError("control artifact size is invalid")
        if not isinstance(digest, str) or HEX_DIGEST.fullmatch(digest) is None:
            raise ValueError("control artifact digest is invalid")
        if record_limit is None:
            if record_count is not None:
                raise ValueError("control artifact record count must be null")
        elif (
            type(record_count) is not int
            or not 0 <= record_count <= record_limit
            or ((size == 0) != (record_count == 0))
            or (name == "changed-blob-findings.z" and record_count % 3)
        ):
            raise ValueError("control artifact record count is invalid")
        by_name[name] = item
    diff = by_name["review.diff"]
    return diff["size"], diff["sha256"]


def _validate_runner_complete(state_fd: int) -> None:
    lock_fd, lock_identity = open_regular_at(
        state_fd,
        b"runner.lock",
        expected_uid=os.getuid(),
        require_link_one=True,
    )
    try:
        if stat.S_IMODE(lock_identity.mode) not in HELPER_SAFE_LOCK_MODES:
            raise ValueError("helper runner lock mode is unsafe")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("helper review is still running") from error
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)
    raw_exit, _ = _read_leaf_bytes(state_fd, b"exit-code", max_bytes=32)
    try:
        int(raw_exit.decode("ascii").strip())
    except ValueError as error:
        raise ValueError("helper exit-code is malformed") from error


def authenticate_helper_state(
    *,
    state_dir: pathlib.Path,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
) -> HelperCustody:
    if (
        not state_dir.is_absolute()
        or not repo.is_absolute()
        or any(part in {".", ".."} for part in state_dir.parts)
        or any(part in {".", ".."} for part in repo.parts)
    ):
        raise blocked(
            "helper state and repository paths must be absolute",
            stage="source-authentication",
            code="non-absolute-input",
        )
    if HEX_OBJECT.fullmatch(base_sha) is None or HEX_OBJECT.fullmatch(head_sha) is None:
        raise blocked(
            "base and head must be full hexadecimal object IDs",
            stage="source-authentication",
            code="non-exact-range",
        )
    state_fd: int | None = None
    workspace_fd: int | None = None
    control_fd: int | None = None
    try:
        state_fd, state_identity = open_absolute_directory_chain(
            state_dir,
            private_leaf=True,
        )
        marker, _ = _read_leaf_bytes(state_fd, b".isolated-review-state", max_bytes=64)
        if marker != HELPER_STATE_MARKER_TEXT:
            raise ValueError("helper state marker is invalid")
        state, _, _ = _read_leaf_json(
            state_fd, b"state.json", max_bytes=MAX_PREFLIGHT_BYTES
        )
        if not isinstance(state, dict) or state.get("version") != 1:
            raise ValueError("helper state schema is invalid")
        if state.get("reviewer") != "codex" or state.get("keep_workspace") is not True:
            raise ValueError("helper state is not a Codex --keep-workspace attempt")
        workspace = state.get("workspace")
        expected_workspace_fields = {
            "source_root",
            "container_dir",
            "workspace_root",
            "base_ref",
            "head_ref",
            "diff_file",
            "prompt_file",
        }
        if (
            not isinstance(workspace, dict)
            or set(workspace) != expected_workspace_fields
        ):
            raise ValueError("helper workspace state is malformed")
        if workspace["container_dir"] != str(state_dir):
            raise ValueError(
                "helper container path does not match the supplied state directory"
            )
        canonical_repo = repo.resolve(strict=True)
        source_root = pathlib.Path(workspace["source_root"])
        if source_root.resolve(strict=True) != canonical_repo:
            raise ValueError(
                "helper source repository does not match the requested repository"
            )
        if workspace["base_ref"] != base_sha or workspace["head_ref"] != head_sha:
            raise ValueError("helper state does not bind the exact requested base/head")
        review_range = f"{base_sha}..{head_sha}"
        workspace_root = pathlib.Path(workspace["workspace_root"])
        if not workspace_root.is_absolute():
            raise ValueError("helper workspace path is not absolute")
        expected_diff_path = workspace_root / PRIMARY_DIFF_RELATIVE_PATH
        if pathlib.Path(workspace["diff_file"]) != expected_diff_path:
            raise ValueError("helper primary diff path is not canonical")

        _validate_runner_complete(state_fd)
        preflight, preflight_raw, _ = _read_leaf_json(
            state_fd,
            b"preflight.json",
            max_bytes=MAX_PREFLIGHT_BYTES,
        )
        if not isinstance(preflight, dict):
            raise ValueError("helper preflight is not an object")
        if (
            preflight.get("status") != HELPER_PREFLIGHT_STATUS
            or preflight.get("review_range") != review_range
        ):
            raise ValueError(
                "helper preflight does not attest the requested frozen range"
            )
        primary = preflight.get("primary_diff")
        if (
            not isinstance(primary, dict)
            or set(primary) != {"path", "sha256", "size"}
            or primary.get("path") != PRIMARY_DIFF_RELATIVE_PATH
            or type(primary.get("size")) is not int
            or not 0 <= primary["size"] <= MAX_DIFF_BYTES
            or not isinstance(primary.get("sha256"), str)
            or HEX_DIGEST.fullmatch(primary["sha256"]) is None
        ):
            raise ValueError("helper primary_diff attestation is malformed")

        control_state, control_raw, _ = _read_leaf_json(
            state_fd,
            b"control-artifact-state.json",
            max_bytes=MAX_CONTROL_STATE_BYTES,
        )
        workspace_fd, _ = open_absolute_directory_chain(
            workspace_root,
            private_leaf=True,
        )
        try:
            os.stat(b".git", dir_fd=workspace_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("helper frozen workspace unexpectedly contains .git")
        control_fd, _ = _open_child_directory(
            workspace_fd,
            b".codex-review",
            label="helper control directory",
            display_path=workspace_root / ".codex-review",
        )
        control_diff_size, control_diff_sha256 = _validate_control_state(
            control_state,
            control_fd=control_fd,
        )
        if (primary["size"], primary["sha256"]) != (
            control_diff_size,
            control_diff_sha256,
        ):
            raise ValueError(
                "preflight and control-state primary diff attestations differ"
            )
        source_fd, source_identity = open_regular_at(
            control_fd,
            b"review.diff",
            expected_uid=os.getuid(),
            require_link_one=True,
        )
        os.close(source_fd)
        if source_identity.size != primary["size"]:
            raise ValueError("retained primary diff length changed")

        cleanup_fd, cleanup_identity = open_regular_at(
            state_fd,
            b"cleanup.lock",
            expected_uid=os.getuid(),
            require_link_one=True,
        )
        os.close(cleanup_fd)
        if stat.S_IMODE(cleanup_identity.mode) not in HELPER_SAFE_LOCK_MODES:
            raise ValueError("helper cleanup lock mode is unsafe")

        return HelperCustody(
            state_dir=str(state_dir),
            state_identity=state_identity,
            workspace_root=str(workspace_root),
            source_path=str(expected_diff_path),
            source_identity=source_identity,
            cleanup_lock_path=str(state_dir / "cleanup.lock"),
            cleanup_lock_identity=cleanup_identity,
            review_range=review_range,
            base_sha=base_sha,
            head_sha=head_sha,
            diff_length=primary["size"],
            diff_sha256=primary["sha256"],
            preflight_sha256=sha256_bytes(preflight_raw),
            control_state_sha256=sha256_bytes(control_raw),
        )
    except Exception as error:
        if isinstance(error, SupervisorError):
            raise
        raise blocked(
            f"helper custody authentication failed: {error}",
            stage="source-authentication",
            code="helper-custody-invalid",
        ) from error
    finally:
        for fd in (control_fd, workspace_fd, state_fd):
            if fd is not None:
                os.close(fd)


def acquire_source_custody(
    *,
    expected: HelperCustody,
    repo: pathlib.Path,
    deadline: float,
) -> CustodyHandles:
    state_dir = pathlib.Path(expected.state_dir)
    state_fd: int | None = None
    workspace_fd: int | None = None
    control_fd: int | None = None
    cleanup_fd: int | None = None
    source_fd: int | None = None
    try:
        state_fd, state_identity = open_absolute_directory_chain(
            state_dir,
            private_leaf=True,
        )
        if not directory_identities_match(state_identity, expected.state_identity):
            raise ValueError("helper state directory identity changed")
        cleanup_fd, cleanup_identity = open_regular_at(
            state_fd,
            b"cleanup.lock",
            expected_uid=os.getuid(),
            require_link_one=True,
        )
        if stat.S_IMODE(cleanup_identity.mode) not in HELPER_SAFE_LOCK_MODES:
            raise ValueError("helper cleanup lock mode changed")
        acquire_flock(cleanup_fd, fcntl.LOCK_SH, deadline=deadline)

        refreshed = authenticate_helper_state(
            state_dir=state_dir,
            repo=repo,
            base_sha=expected.base_sha,
            head_sha=expected.head_sha,
        )
        if not helper_custody_evidence_matches(refreshed, expected):
            raise ValueError("helper custody evidence changed before handoff")
        workspace_fd, _ = open_absolute_directory_chain(
            pathlib.Path(expected.workspace_root),
            private_leaf=True,
        )
        control_fd, _ = _open_child_directory(
            workspace_fd,
            b".codex-review",
            label="helper control directory",
            display_path=pathlib.Path(expected.workspace_root) / ".codex-review",
        )
        source_fd, source_identity = open_regular_at(
            control_fd,
            b"review.diff",
            expected_uid=os.getuid(),
            require_link_one=True,
        )
        if source_identity != expected.source_identity:
            raise ValueError("retained primary diff identity changed before handoff")
        result = CustodyHandles(
            cleanup_lock_fd=cleanup_fd,
            source_fd=source_fd,
            evidence=refreshed,
        )
        cleanup_fd = None
        source_fd = None
        return result
    except Exception as error:
        raise inconclusive(
            f"cannot acquire helper source custody: {error}",
            stage="handoff",
            code="source-custody-unavailable",
        ) from error
    finally:
        for fd in (source_fd, cleanup_fd, control_fd, workspace_fd, state_fd):
            if fd is not None:
                os.close(fd)


def custody_helper_main(
    *,
    control_fd: int,
    state_dir: pathlib.Path,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
    token: str,
) -> int:
    control = socket.socket(fileno=control_fd)
    handles: CustodyHandles | None = None
    try:
        send_record(
            control,
            {"type": "custody-helper-ready", "token": token, "pid": os.getpid()},
            deadline=time.monotonic() + 5,
        )
        request, descriptors = receive_record(
            control,
            deadline=time.monotonic() + 30,
        )
        if descriptors:
            raise ValueError("custody helper request contained descriptors")
        if (
            request.get("type") != "acquire-source-custody"
            or request.get("token") != token
        ):
            raise ValueError("custody helper request is invalid")
        expected_value = request.get("expected")
        if not isinstance(expected_value, dict):
            raise ValueError("custody helper expected evidence is malformed")
        expected = authenticate_helper_state(
            state_dir=state_dir,
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
        )
        if not helper_custody_evidence_matches(expected, expected_value):
            raise ValueError(
                "custody helper evidence differs from pre-admission evidence"
            )
        handles = acquire_source_custody(
            expected=expected,
            repo=repo,
            deadline=time.monotonic() + 30,
        )
        send_record(
            control,
            {
                "type": "source-custody-result",
                "token": token,
                "ok": True,
                "evidence": handles.evidence.to_json(),
            },
            deadline=time.monotonic() + 5,
            fds=(handles.cleanup_lock_fd, handles.source_fd),
        )
        acknowledgement, descriptors = receive_record(
            control,
            deadline=time.monotonic() + 5,
        )
        if descriptors or acknowledgement != {
            "type": "source-custody-received",
            "token": token,
        }:
            raise ValueError("custody helper acknowledgement is invalid")
        return 0
    except BaseException as error:
        try:
            send_record(
                control,
                {
                    "type": "source-custody-result",
                    "token": token,
                    "ok": False,
                    "error": f"{type(error).__name__}: {error}",
                },
                deadline=time.monotonic() + 1,
            )
        except BaseException:
            pass
        return 1
    finally:
        if handles is not None:
            handles.close()
        control.close()
