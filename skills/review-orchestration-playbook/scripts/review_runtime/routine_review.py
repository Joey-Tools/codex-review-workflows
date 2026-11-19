"""Routine preparation, Codex startup, disposition and local revalidation.

Disposition inputs are parent observations, never reviewer self-attestation.
Preparation and startup do not grant consent or supply review acceptance.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import errno
import hashlib
import json
import os
import re
import selectors
import shutil
import subprocess
import time
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


def _assessment_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("classify", "revalidate", "snapshot", "validate-snapshot", "prepare", "validate", "config", "run"))
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


FEATURES = (
    "apps", "plugins", "computer_use", "browser_use", "browser_use_external",
    "browser_use_full_cdp_access", "image_generation", "goals",
    "skill_mcp_dependency_install", "multi_agent", "multi_agent_v2",
    "daemon_auto_start", "hooks", "cli_daybreak",
)
PROFILES = {"gpt-6.1-sol": False, "gpt-6-sol": True}


def git_environment() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_NOSYSTEM="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
        GIT_NO_REPLACE_OBJECTS="1", GIT_ATTR_NOSYSTEM="1", GIT_PAGER="cat",
        GIT_ALLOW_PROTOCOL="file", GIT_OPTIONAL_LOCKS="0",
    )
    return env


def git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "--no-pager", "--literal-pathspecs", "-c", "core.hooksPath=" + os.devnull,
         "-c", "core.fsmonitor=false", "-c", "diff.external=", "-c",
         "core.attributesFile=" + os.devnull, "-C", str(root), *args],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=git_environment(), check=True,
    ).stdout


def write_record(path: Path, record: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")


def read_record(path: Path) -> dict:
    return json.loads(path.read_text())


def leaf_paths(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("paths must be a nonempty array of tracked file paths")
    result = []
    for path in value:
        if (not isinstance(path, str) or not path or "\x00" in path
                or PurePosixPath(path).is_absolute()
                or any(part in ("", ".", "..") or part.casefold() == ".git"
                       for part in path.split("/"))):
            raise ValueError("paths must be repository-relative leaf paths")
        if path not in result:
            result.append(path)
    return result


def head_entries(root: Path, head: str, paths: list[str]) -> dict[str, tuple[str, str]]:
    entries = {}
    raw = git(root, "ls-tree", "-r", "-z", head, "--", *paths)
    for row in raw.split(b"\x00"):
        if not row:
            continue
        meta, name = row.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        path = name.decode("utf-8")
        if path not in paths or kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("materialize only explicitly selected regular tracked files")
        entries[path] = (mode, oid)
    if set(entries) != set(paths):
        raise ValueError("a selected path is absent at head or is not a regular file")
    return entries


def blob_identity(path: Path, object_format: str) -> tuple[str, str]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"selected file is no longer regular: {path}")
    digest = hashlib.new(object_format)
    digest.update(f"blob {metadata.st_size}\0".encode())
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return ("100755" if metadata.st_mode & 0o111 else "100644", digest.hexdigest())


def prepare(source: Path, worktree: Path, base: str, head: str, paths: list[str]) -> dict:
    source, worktree = source.resolve(), worktree.absolute()
    # Resolve before cloning, so an invalid range never starts a large copy.
    base = git(source, "rev-parse", "--verify", base + "^{commit}").decode().strip()
    head = git(source, "rev-parse", "--verify", head + "^{commit}").decode().strip()
    git(source, "merge-base", "--is-ancestor", base, head)
    entries = head_entries(source, head, paths)
    if worktree.exists() or worktree.is_symlink():
        raise ValueError("workspace destination must not exist")
    subprocess.run(
        ["git", "-c", "core.hooksPath=" + os.devnull, "clone", "--no-local",
         "--no-hardlinks", "--no-checkout", str(source), str(worktree)],
        env=git_environment(), check=True,
    )
    git(worktree, "fetch", "--no-tags", "--no-write-fetch-head", str(source), base, head)
    git(worktree, "remote", "remove", "origin")
    git(worktree, "update-ref", "--no-deref", "HEAD", head)
    git(worktree, "read-tree", head)
    all_paths = git(worktree, "ls-files", "-z")
    git(worktree, "update-index", "--skip-worktree", "-z", "--stdin", data=all_paths)
    selected = b"".join(path.encode() + b"\x00" for path in paths)
    git(worktree, "update-index", "--no-skip-worktree", "-z", "--stdin", data=selected)
    for name, (mode, oid) in entries.items():
        target = worktree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git(worktree, "cat-file", "blob", oid))
        target.chmod(0o755 if mode == "100755" else 0o644)
    record = {
        "worktree": str(worktree), "base": base, "head": head,
        "object_format": git(worktree, "rev-parse", "--show-object-format").decode().strip(),
        "paths": paths, "entries": {name: list(value) for name, value in entries.items()},
        "config_sha256": hashlib.sha256((worktree / ".git/config").read_bytes()).hexdigest(),
        "strategy": "independent-local-clone-selected-checkout",
    }
    validate(record)
    return record


def validate(record: dict) -> None:
    root = Path(record["worktree"])
    if git(root, "rev-parse", "HEAD").decode().strip() != record["head"]:
        raise ValueError("workspace head changed")
    git(root, "merge-base", "--is-ancestor", record["base"], record["head"])
    if hashlib.sha256((root / ".git/config").read_bytes()).hexdigest() != record["config_sha256"]:
        raise ValueError("workspace Git configuration changed")
    paths = leaf_paths(record["paths"])
    entries = head_entries(root, record["head"], paths)
    if {name: list(value) for name, value in entries.items()} != record["entries"]:
        raise ValueError("workspace record does not match frozen tracked entries")
    for name, expected in entries.items():
        if blob_identity(root / name, record["object_format"]) != expected:
            raise ValueError(f"selected content or executable mode changed: {name}")
    git(root, "diff-index", "--cached", "--quiet", record["head"], "--")
    if git(root, "ls-files", "--others", "--exclude-standard", "-z"):
        raise ValueError("workspace contains untracked content")


def read_config(prefix: list[str], neutral: Path) -> dict:
    process = subprocess.Popen(
        prefix + ["app-server", "--listen", "stdio://"], cwd=neutral,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    selector = selectors.DefaultSelector()
    pending = b""
    consumed = 0
    deadline = time.monotonic() + 45
    for pipe in (process.stdout, process.stderr):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)

    def request(value: dict, identifier: int) -> dict:
        nonlocal pending, consumed
        process.stdin.write((json.dumps(value) + "\n").encode())
        process.stdin.flush()
        while time.monotonic() < deadline:
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                result = json.loads(line)
                if result.get("id") == identifier:
                    if "error" in result:
                        raise ValueError("effective configuration RPC failed")
                    return result["result"]
            for key, _ in selector.select(0.2):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                consumed += len(data)
                if consumed > 8 * 1024 * 1024:
                    raise ValueError("effective configuration response exceeded capture capacity")
                if key.fileobj is process.stdout:
                    pending += data
            if process.poll() is not None and not selector.get_map():
                break
        raise ValueError("effective configuration unavailable before startup deadline")

    try:
        request({"id": 0, "method": "initialize", "params": {
            "clientInfo": {"name": "routine-review", "version": "1"}}}, 0)
        process.stdin.write(b'{"method":"initialized","params":{}}\n')
        process.stdin.flush()
        return request({"id": 1, "method": "config/read", "params": {
            "includeLayers": False}}, 1)["config"]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        selector.close()
        for pipe in (process.stdin, process.stdout, process.stderr):
            pipe.close()


def configuration(codex: str, neutral: Path, model: str) -> dict:
    codex = shutil.which(codex)
    if codex is None:
        raise ValueError("Codex executable not found")
    codex = str(Path(codex).resolve())
    neutral = neutral.resolve()
    neutral.mkdir(mode=0o700, parents=True, exist_ok=True)
    prefix = [codex, "-a", "never", "-m", model, "-c", 'model_provider="openai"',
              "-c", 'model_reasoning_effort="high"', "-C", str(neutral)]
    for name in FEATURES:
        value = PROFILES[model] if name == "cli_daybreak" else False
        prefix += ["-c", f"features.{name}={str(value).lower()}"]
    prefix += ["-c", "agents.enabled=false", "-c", "memories.generate_memories=false",
               "-c", 'web_search="disabled"', "-c", "notify=[]"]
    first = read_config(prefix, neutral)
    if not isinstance(first.get("mcp_servers"), dict):
        raise ValueError("effective MCP configuration is unavailable")
    names = sorted(first["mcp_servers"])
    extra = "{" + ",".join(json.dumps(name) + "={enabled=false}" for name in names) + "}"
    if names:
        prefix += ["-c", "mcp_servers=" + extra]
    final = read_config(prefix, neutral) if names else first
    features = final.get("features", {})
    if (final.get("model") != model or final.get("model_reasoning_effort") != "high"
            or final.get("model_provider", "openai") != "openai"
            or any(features.get(name) is not (PROFILES[model] if name == "cli_daybreak" else False)
                   for name in FEATURES)
            or set(final.get("mcp_servers", {})) != set(names)
            or any(item.get("enabled", True) for item in final.get("mcp_servers", {}).values())):
        raise ValueError("requested read-only review configuration is not effective")
    version = subprocess.check_output([codex, "--version"], text=True).strip()
    return {"launch_prefix": prefix, "neutral_root": str(neutral), "selected_model": model,
            "selected_reasoning": "high", "daybreak": PROFILES[model],
            "cli_version": version, "mcp_names": names, "model_threads_started": 0}


def run_review(workspace: dict, config: dict, output: Path, prompt: str) -> int:
    validate(workspace)
    output = output.resolve()
    output.mkdir(mode=0o700)
    argv = config["launch_prefix"] + ["exec", "--sandbox", "read-only",
            "--skip-git-repo-check", "--json", "-o", str(output / "final.txt"), "-"]
    write_record(output / "launch.json", {"argv": argv, "base": workspace["base"],
                 "head": workspace["head"], "model": config["selected_model"],
                 "reasoning": config["selected_reasoning"], "daybreak": config["daybreak"]})
    with (output / "stream.jsonl").open("xb") as stream:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stream,
                                   stderr=stream, env=git_environment(), cwd=config["neutral_root"])
        write_record(output / "process.json", {"pid": process.pid, "launcher_pid": os.getpid()})
        process.communicate(input=prompt.encode())
    write_record(output / "exit.json", {"returncode": process.returncode})
    validate(workspace)
    return process.returncode



def _startup_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    for name in ("source", "worktree", "base", "head", "paths_json", "record"):
        prep.add_argument("--" + name.replace("_", "-"), required=True)
    check = commands.add_parser("validate")
    check.add_argument("--record", required=True)
    config = commands.add_parser("config")
    config.add_argument("--codex", default="codex")
    config.add_argument("--neutral-root", required=True)
    config.add_argument("--model", choices=PROFILES, default="gpt-6.1-sol")
    config.add_argument("--record", required=True)
    run = commands.add_parser("run")
    for name in ("workspace_record", "config_record", "output", "prompt_file"):
        run.add_argument("--" + name.replace("_", "-"), required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        record = prepare(Path(args.source), Path(args.worktree), args.base, args.head,
                         leaf_paths(json.loads(Path(args.paths_json).read_text())))
        write_record(Path(args.record), record)
        print(json.dumps({"worktree": record["worktree"], "base": record["base"],
                          "head": record["head"], "materialized_files": len(record["paths"])}))
    elif args.command == "validate":
        validate(read_record(Path(args.record)))
        print("Routine workspace validation passed.")
    elif args.command == "config":
        record = configuration(args.codex, Path(args.neutral_root), args.model)
        write_record(Path(args.record), record)
        print(json.dumps({key: record[key] for key in ("selected_model", "selected_reasoning",
                                                     "daybreak", "cli_version", "model_threads_started")}))
    else:
        return run_review(read_record(Path(args.workspace_record)),
                          read_record(Path(args.config_record)), Path(args.output),
                          Path(args.prompt_file).read_text())
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in ("prepare", "validate", "config", "run"):
        try:
            return _startup_main(arguments)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print(f"routine review: {error}", file=sys.stderr)
            return 1
    return _assessment_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
