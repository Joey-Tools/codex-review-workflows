"""Sparse Git preparation and reusable standalone Codex review startup.

Routine profile only. The parent selects scope and judges the terminal result.
This is cooperative task isolation, not protection against hostile same-UID code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import selectors
import shutil
import stat
import subprocess
import sys
import time


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
    git(worktree, "remote", "remove", "origin")
    git(worktree, "update-ref", "--no-deref", "HEAD", head)
    git(worktree, "read-tree", head)
    all_paths = git(worktree, "ls-files", "-z")
    git(worktree, "update-index", "--skip-worktree", "-z", "--stdin", data=all_paths)
    selected = b"".join(path.encode() + b"\x00" for path in paths)
    git(worktree, "update-index", "--no-skip-worktree", "-z", "--stdin", data=selected)
    git(worktree, "checkout-index", "--stdin", "-z", data=selected)
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
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("workspace contains modified or untracked content")


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


def main() -> int:
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
    args = parser.parse_args()
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


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"routine review: {error}", file=sys.stderr)
        raise SystemExit(1)
