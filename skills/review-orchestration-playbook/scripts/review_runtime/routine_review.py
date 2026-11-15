"""Parent-side review disposition and dependency-based local revalidation.

Inputs are observations made by the orchestrator, never reviewer self-attestation.
This module does not execute a reviewer or prove a sandbox boundary.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import errno
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

MAX_INPUT_BYTES = 2 * 1024 * 1024
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SNAPSHOT_BYTES = 256 * 1024 * 1024


def _boolean(record: dict[str, Any], key: str) -> bool:
    value = record[key]
    if type(value) is not bool:
        raise ValueError(f"{key} must be a boolean")
    return value


def _scope(record: dict[str, Any]) -> dict[str, str]:
    kind = record.get("scope_kind", "commit")
    if kind not in ("commit", "snapshot"):
        raise ValueError("unsupported scope_kind")
    keys = ("base_sha", "head_sha") if kind == "commit" else ("base_sha", "source_head_sha")
    for key in keys:
        if not isinstance(record.get(key), str) or not OID.fullmatch(record[key]):
            raise ValueError(f"{key} must be a full lowercase object ID")
    if len(record[keys[0]]) != len(record[keys[1]]):
        raise ValueError("scope endpoints must use the same object format")
    result = {key: record[key] for key in keys}
    if kind == "snapshot":
        if "head_sha" in record:
            raise ValueError("a snapshot cannot claim a reviewed commit head_sha")
        snapshot_id = record.get("snapshot_id")
        if not isinstance(snapshot_id, str) or re.fullmatch(r"[0-9a-f]{64}", snapshot_id) is None:
            raise ValueError("snapshot_id must be a full lowercase SHA-256 digest")
        result.update(scope_kind=kind, snapshot_id=snapshot_id)
    return result


def _paths(record: dict[str, Any], key: str) -> set[str]:
    value = record[key]
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a path array")
    result: set[str] = set()
    for path in value:
        if (
            not isinstance(path, str)
            or not path
            or "\x00" in path
            or PurePosixPath(path).is_absolute()
            or any(part in ("", ".", "..") or part.casefold() == ".git" for part in path.split("/"))
        ):
            raise ValueError(f"{key} must contain repository-relative leaf paths")
        path.encode("utf-8", errors="strict")
        result.add(path)
    return result


def _read_snapshot_path(root_fd: int, path: str, remaining: int) -> tuple[bytes, str]:
    """Pin traversal without following links; protect content and executable mode.

    Metadata churn and same-content replacement are harmless to this property.
    This is not an atomic multi-file filesystem snapshot or same-UID isolation.
    """
    with ExitStack() as stack:
        parent = root_fd
        parts = path.split("/")
        for part in parts[:-1]:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            stack.callback(os.close, parent)
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent,
        )
        stack.callback(os.close, descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"snapshot path is not a regular file: {path}")
        if metadata.st_size > remaining:
            raise ValueError("snapshot exceeds the 256 MiB capture capacity; narrow the scope")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, remaining - len(payload) + 1))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > remaining:
                raise ValueError("snapshot exceeds the 256 MiB capture capacity; narrow the scope")
        return bytes(payload), "100755" if metadata.st_mode & 0o111 else "100644"


def _snapshot_identity(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def _require_deleted_leaf(root_fd: int, path: str, present: set[str]) -> None:
    """A deleted Git leaf may become a directory or lie below a new file."""
    with ExitStack() as stack:
        parent = root_fd
        parts = path.split("/")
        for index, part in enumerate(parts[:-1]):
            try:
                descriptor = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent,
                )
            except FileNotFoundError:
                return
            except OSError as error:
                if error.errno not in (errno.ENOTDIR, errno.ELOOP):
                    raise
                metadata = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode) and "/".join(parts[:index + 1]) in present:
                    return
                raise
            stack.callback(os.close, descriptor)
            parent = descriptor
        try:
            metadata = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(metadata.st_mode):
            return
        raise ValueError(f"declared deletion is present or unsupported: {path}")


def capture_snapshot(record: dict[str, Any], source: Path, output: Path) -> dict[str, Any]:
    """Capture caller-selected final file content; never read or write Git state."""
    if os.name != "posix":
        raise ValueError("snapshot capture requires POSIX no-follow traversal")
    endpoints = {key: record[key] for key in ("base_sha", "source_head_sha")}
    _scope({**endpoints, "scope_kind": "snapshot", "snapshot_id": "0" * 64})
    paths = _paths(record, "paths")
    deleted = _paths(record, "deleted_paths")
    if paths & deleted or not (paths | deleted):
        raise ValueError("snapshot paths must be nonempty and disjoint from deletions")
    source = source.absolute()
    output = output.absolute()
    if output.resolve().is_relative_to(source.resolve()) or any(
        part.casefold() == ".git" for part in output.resolve().parts
    ):
        raise ValueError("snapshot output must be outside the source checkout")
    manifest = {"version": 1, "scope_kind": "snapshot", **endpoints, "entries": []}
    output.mkdir(mode=0o700)
    root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        remaining = SNAPSHOT_BYTES
        for path in sorted(paths):
            payload, mode = _read_snapshot_path(root_fd, path, remaining)
            remaining -= len(payload)
            target = output / "files" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(payload)
            target.chmod(0o700 if mode == "100755" else 0o600)
            manifest["entries"].append({
                "path": path, "mode": mode, "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        for path in sorted(deleted):
            manifest["entries"].append({"path": path, "deleted": True})
        # Re-read selected content rather than treating timestamp or directory
        # entry changes as source mutation. Failed reads remain failed reads.
        for entry in manifest["entries"]:
            if entry.get("deleted"):
                _require_deleted_leaf(root_fd, entry["path"], paths)
                continue
            payload, mode = _read_snapshot_path(root_fd, entry["path"], SNAPSHOT_BYTES)
            if mode != entry["mode"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
                raise ValueError(f"source content changed during capture: {entry['path']}")
    finally:
        os.close(root_fd)
    receipt = {**manifest, "snapshot_id": _snapshot_identity(manifest)}
    serialized = json.dumps(receipt, sort_keys=True) + "\n"
    if len(serialized.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("snapshot manifest exceeds the 2 MiB capacity; narrow the scope")
    with (output / "snapshot.json").open("x", encoding="utf-8") as stream:
        stream.write(serialized)
    return receipt


def validate_snapshot(output: Path, expected_id: str) -> dict[str, Any]:
    root_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        raw, _ = _read_snapshot_path(root_fd, "snapshot.json", MAX_INPUT_BYTES)
        receipt = json.loads(raw)
        scope = _scope(receipt)
        snapshot_id = scope["snapshot_id"]
        if snapshot_id != expected_id:
            raise ValueError("snapshot differs from the parent-owned identity")
        manifest = {key: value for key, value in receipt.items() if key != "snapshot_id"}
        if type(manifest.get("version")) is not int or manifest["version"] != 1 or _snapshot_identity(manifest) != snapshot_id:
            raise ValueError("snapshot manifest digest mismatch")
        entries = manifest["entries"]
        if not isinstance(entries, list) or not entries:
            raise ValueError("snapshot entries must be a nonempty array")
        _paths({"paths": [entry["path"] for entry in entries]}, "paths")
        if len({entry["path"] for entry in entries}) != len(entries):
            raise ValueError("duplicate snapshot paths")
        remaining = SNAPSHOT_BYTES
        present = {"files/" + entry["path"] for entry in entries if entry.get("deleted") is not True}
        for entry in entries:
            if entry.get("deleted") is True:
                if set(entry) != {"path", "deleted"}:
                    raise ValueError("invalid deletion entry")
                _require_deleted_leaf(root_fd, "files/" + entry["path"], present)
                continue
            if set(entry) != {"path", "mode", "size", "sha256"}:
                raise ValueError("invalid snapshot file entry")
            payload, mode = _read_snapshot_path(root_fd, "files/" + entry["path"], remaining)
            remaining -= len(payload)
            if (len(payload), mode, hashlib.sha256(payload).hexdigest()) != (
                entry["size"], entry["mode"], entry["sha256"],
            ):
                raise ValueError(f"snapshot content mismatch: {entry['path']}")
        return {**scope, "snapshot_valid": True, "merge_approval": False}
    finally:
        os.close(root_fd)


def classify(record: dict[str, Any]) -> dict[str, Any]:
    """Keep source conclusions separate from execution and acceptance."""
    scope = _scope(record)
    code = record["code_outcome"]
    if code not in ("clean", "findings", "incomplete"):
        raise ValueError("unsupported code_outcome")
    flags = {
        key: _boolean(record, key)
        for key in (
            "terminal_received",
            "scope_complete",
            "boundary_intact",
            "source_unchanged",
            "evidence_complete",
            "unresolved_execution_error",
        )
    }
    diagnostics = record.get("diagnostics", [])
    if not isinstance(diagnostics, list) or any(
        not isinstance(item, str) for item in diagnostics
    ):
        raise ValueError("diagnostics must be a string array")
    if not flags["boundary_intact"] or not flags["source_unchanged"]:
        execution = "invalid"
    elif (
        not flags["terminal_received"]
        or not flags["evidence_complete"]
        or flags["unresolved_execution_error"]
    ):
        execution = "incomplete"
    else:
        execution = "complete-with-warnings" if diagnostics else "complete"
    accepted = (
        execution in ("complete", "complete-with-warnings")
        and flags["scope_complete"]
        and code == "clean"
    )
    return {
        **scope,
        "code_outcome": code,
        "execution_status": execution,
        "scope_complete": flags["scope_complete"],
        "accepted": accepted,
        "diagnostics": diagnostics,
        **({"merge_approval": False} if "snapshot_id" in scope else {}),
    }


def revalidation_plan(record: dict[str, Any]) -> dict[str, Any]:
    """Plan reuse of a local unit; never issue new-head review approval."""
    _scope(record)
    if record.get("scope_kind", "commit") != "commit":
        raise ValueError("snapshot changes require a new capture and review")
    reviewed = _paths(record, "reviewed_paths")
    dependencies = _paths(record, "dependency_paths")
    changed = _paths(record, "changed_paths")
    if not reviewed:
        raise ValueError("reviewed_paths must not be empty")
    prior_clean = _boolean(record, "prior_clean")
    complete = _boolean(record, "dependencies_complete")
    base_same = _boolean(record, "base_unchanged")
    control_same = _boolean(record, "control_policy_unchanged")
    intersects = sorted(changed & (reviewed | dependencies))
    reusable = prior_clean and complete and base_same and control_same and not intersects
    if not prior_clean:
        reason = "prior-unit-not-clean"
    elif not complete:
        reason = "dependency-coverage-unknown"
    elif not base_same or not control_same:
        reason = "scope-or-control-changed"
    elif intersects:
        reason = "affected-paths"
    else:
        reason = "dependencies-unchanged"
    return {
        "base_sha": record["base_sha"],
        "head_sha": record["head_sha"],
        "action": "retain-unit-evidence" if reusable else "review-unit",
        "reason": reason,
        "affected_paths": intersects,
        "current_head_integration_required": True,
        "current_head_approved": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("classify", "revalidate", "snapshot", "validate-snapshot"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--snapshot-id")
    args = parser.parse_args(argv)
    try:
        if args.operation == "validate-snapshot":
            if args.output is None or args.snapshot_id is None:
                raise ValueError("--output and --snapshot-id are required")
            print(json.dumps(validate_snapshot(args.output, args.snapshot_id), sort_keys=True))
            return 0
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("parent record exceeds the 2 MiB input limit")
        record = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(record, dict):
            raise ValueError("parent record must be an object")
        if args.operation == "snapshot":
            if args.source is None or args.output is None:
                raise ValueError("--source and --output are required")
            result = capture_snapshot(record, args.source, args.output)
        else:
            result = classify(record) if args.operation == "classify" else revalidation_plan(record)
    except (OSError, KeyError, TypeError, ValueError, UnicodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

