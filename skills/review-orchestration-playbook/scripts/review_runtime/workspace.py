from __future__ import annotations

import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from typing import BinaryIO, Callable, Iterator

from .common import (
    TRUSTED_PATH,
    ForwardedSignal,
    ReviewError,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    is_relative_to,
    resolve_git,
    restore_signal_mask,
    run,
    write_text_atomic,
)
from .prompt import build_review_prompt


SECRET_PATTERNS = (
    (
        "pgp-private-key",
        re.compile(rb"-----BEGIN PGP PRIVATE[ ]KEY BLOCK-----"),
    ),
    (
        "private-key",
        re.compile(
            rb"-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    ("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "aws-secret-key",
        re.compile(
            rb"(?i)aws_secret_access_key\s*[:=]\s*['\"]?"
            rb"[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
        ),
    ),
    ("anthropic-key", re.compile(rb"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    ("openai-key", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    (
        "github-token",
        re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("gitlab-token", re.compile(rb"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm-token", re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(rb"\bpypi-[A-Za-z0-9_-]{50,}\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe-live-key", re.compile(rb"\bsk_live_[A-Za-z0-9]{16,}\b")),
)
SECRET_KEY_PATTERN = (
    rb"(?i)(?:api[_-]?(?:key|token)|access[_-]?token|auth[_-]?token|"
    rb"bearer[_-]?token|client[_-]?secret|password|passwd|private[_-]?token|"
    rb"refresh[_-]?token|secret[_-]?(?:key|token))['\"]?\s*[:=]\s*"
)
QUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN + rb"(['\"])([^\r\n'\"]{16,512})\1"
)
OVERSIZED_QUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN + rb"(['\"])[^\r\n'\"]{513}"
)
UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN
    + rb"([-A-Za-z0-9_./+=!@#$%^&*?~:;]{16,512})(?=[ \t]*(?:[#;]|\r?$))",
    re.MULTILINE,
)
OVERSIZED_UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    SECRET_KEY_PATTERN + rb"[-A-Za-z0-9_./+=!@#$%^&*?~:;]{513}"
)
PLACEHOLDER_SECRET_PATTERN = re.compile(
    rb"(?:"
    rb"\$\{[A-Za-z_][A-Za-z0-9_]*\}"
    rb"|<[A-Za-z_][A-Za-z0-9_.-]*>"
    rb"|(?:changeme|dummy|example|fake|placeholder|redacted)"
    rb"(?:[-_ ](?:credential|key|password|sample|secret|test|token|value)){0,2}"
    rb"|(?:must[-_ ]not[-_ ]pass|not[-_ ]a[-_ ]real|parent[-_ ]only)"
    rb"(?:[-_ ](?:credential|key|password|secret|token|value))?"
    rb")",
    re.IGNORECASE,
)
SENSITIVE_ANYWHERE_NAMES = {
    ".git-credentials",
    ".netrc",
    "service-account.json",
    "service_account.json",
    "token.json",
}
SENSITIVE_PATH_SUFFIXES = (
    (".aws", "credentials"),
    (".docker", "config.json"),
    (".kube", "config"),
)
SENSITIVE_FILE_NAMES = {
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
SENSITIVE_SUFFIXES = (".jks", ".keystore", ".p12", ".pfx")
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template")
PROTECTED_REVIEW_PATHS = (".codex", ".agents")
MAX_SNAPSHOT_BLOB_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_ENTRIES = 100_000
MAX_TREE_METADATA_BYTES = 128 * 1024 * 1024
MAX_DIFF_BYTES = 128 * 1024 * 1024
MAX_CHANGED_METADATA_BYTES = 128 * 1024 * 1024
MAX_CHANGED_ENTRIES = 100_000
MAX_CHANGED_BLOB_SCAN_BYTES = 512 * 1024 * 1024
MAX_REVIEW_PROMPT_BYTES = 64 * 1024
LONG_ALPHANUMERIC_SECRET = re.compile(rb"[A-Za-z0-9]{24,512}")
LONG_NUMERIC_SECRET = re.compile(rb"[0-9]{16,512}")


@dataclass(frozen=True)
class ReviewWorkspace:
    source_root: pathlib.Path
    container_dir: pathlib.Path
    workspace_root: pathlib.Path
    base_ref: str
    head_ref: str
    diff_file: pathlib.Path
    prompt_file: pathlib.Path

    def to_json(self) -> dict[str, str]:
        return {key: str(value) for key, value in asdict(self).items()}

    @classmethod
    def from_json(cls, value: dict[str, str]) -> "ReviewWorkspace":
        return cls(
            source_root=pathlib.Path(value["source_root"]),
            container_dir=pathlib.Path(value["container_dir"]),
            workspace_root=pathlib.Path(value["workspace_root"]),
            base_ref=value["base_ref"],
            head_ref=value["head_ref"],
            diff_file=pathlib.Path(value["diff_file"]),
            prompt_file=pathlib.Path(value["prompt_file"]),
        )


def _git_environment(*, object_directory: pathlib.Path | None = None) -> dict[str, str]:
    env = {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": TRUSTED_PATH,
        "SSH_ASKPASS": "/usr/bin/false",
    }
    if object_directory is not None:
        env["GIT_OBJECT_DIRECTORY"] = str(object_directory)
    return env


def _git(repo: pathlib.Path, *args: str, check: bool = True):
    return run(
        (
            str(resolve_git()),
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "diff.external=",
            "-C",
            str(repo),
            *args,
        ),
        env=_git_environment(),
        check=check,
    )


def _create_sanitized_git_view(
    *,
    source_root: pathlib.Path,
    container: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    object_result = _git(source_root, "rev-parse", "--git-path", "objects")
    object_value = pathlib.Path(object_result.stdout.decode("utf-8").strip())
    object_directory = (
        object_value if object_value.is_absolute() else source_root / object_value
    ).resolve()
    if not object_directory.is_dir():
        raise ReviewError(f"Git object directory does not exist: {object_directory}")
    format_result = _git(source_root, "rev-parse", "--show-object-format")
    object_format = format_result.stdout.decode("utf-8").strip()
    if object_format not in {"sha1", "sha256"}:
        raise ReviewError(f"unsupported Git object format: {object_format!r}")

    git_view = container / "git-view"
    (git_view / "objects").mkdir(parents=True)
    (git_view / "refs").mkdir()
    write_text_atomic(git_view / "HEAD", "ref: refs/heads/unused\n")
    format_version = 1 if object_format == "sha256" else 0
    config = f"[core]\n\trepositoryformatversion = {format_version}\n\tbare = true\n"
    if object_format == "sha256":
        config += "[extensions]\n\tobjectFormat = sha256\n"
    write_text_atomic(git_view / "config", config)
    return git_view, object_directory


def _frozen_command(
    *,
    git_view: pathlib.Path,
    args: tuple[str, ...],
) -> tuple[str, ...]:
    return (
        str(resolve_git()),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "diff.external=",
        f"--git-dir={git_view}",
        *args,
    )


def _commit_uses_reserved_control_path(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    commit: str,
    label: str,
) -> bool:
    with tempfile.TemporaryFile() as error_output:
        process = subprocess.Popen(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-z", "--name-only", commit),
            ),
            env=_git_environment(object_directory=object_directory),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=error_output,
        )
        if process.stdout is None:
            _stop_process(process)
            raise ReviewError(f"failed to create frozen {label} tree metadata pipe")
        reserved = False
        try:
            for name in _iter_nul_records(
                process.stdout,
                byte_limit=MAX_TREE_METADATA_BYTES,
                record_limit=MAX_SNAPSHOT_ENTRIES,
                label=f"frozen {label} tree metadata",
            ):
                if os.fsdecode(name).casefold() == ".codex-review":
                    reserved = True
            _close_pipe(process.stdout)
            returncode = process.wait()
        except BaseException:
            _close_pipe(process.stdout)
            _stop_process(process)
            raise
        if returncode != 0:
            raise ReviewError(
                f"cannot inspect frozen {label} tree metadata: "
                f"{_process_stderr(error_output)}"
            )
        return reserved


def _reject_protected_review_path_aliases(workspace_root: pathlib.Path) -> None:
    for name in PROTECTED_REVIEW_PATHS:
        candidate = workspace_root / name
        if candidate.is_symlink():
            raise ReviewError(
                f"the frozen head uses a symlink for protected top-level path {name}"
            )


def resolve_repo_root(repo: pathlib.Path) -> pathlib.Path:
    candidate = repo.expanduser().resolve()
    result = _git(candidate, "rev-parse", "--show-toplevel")
    root = pathlib.Path(result.stdout.decode("utf-8").strip()).resolve()
    if not root.is_dir():
        raise ReviewError(f"repository root does not exist: {root}")
    return root


def resolve_commit(repo: pathlib.Path, ref: str, *, label: str) -> str:
    result = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}", check=False)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReviewError(f"cannot resolve {label} {ref!r}: {detail}")
    return result.stdout.decode("utf-8").strip()


def _require_ancestor_range(
    repo: pathlib.Path,
    *,
    base_sha: str,
    head_sha: str,
) -> None:
    ancestor = _git(
        repo,
        "merge-base",
        "--is-ancestor",
        base_sha,
        head_sha,
        check=False,
    )
    if ancestor.returncode == 0:
        return
    if ancestor.returncode != 1:
        raise ReviewError("cannot verify that the frozen base is an ancestor of head")
    merge_base = _git(repo, "merge-base", base_sha, head_sha, check=False)
    if merge_base.returncode == 0 and merge_base.stdout.strip():
        suggestion = merge_base.stdout.decode("ascii").strip()
        detail = f"; use merge base {suggestion} as --base-ref"
    else:
        detail = "; the commits have no merge base"
    raise ReviewError(
        f"frozen base {base_sha} is not an ancestor of head {head_sha}{detail}"
    )


def _remove_partial_container(container: pathlib.Path) -> str | None:
    try:
        shutil.rmtree(container)
    except FileNotFoundError:
        return None
    except OSError as error:
        return str(error)
    return None


def _retained_container_detail(container: pathlib.Path, cleanup_error: str) -> str:
    return (
        "review workspace preparation failed and cleanup failed; evidence retained at "
        f"{container}: {cleanup_error}"
    )


def _new_container(
    source_root: pathlib.Path,
) -> tuple[pathlib.Path, set[signal.Signals] | None]:
    handoff_mask = block_forwarded_signals()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    suffix = uuid.uuid4().hex[:10]
    review_root = source_root / ".codex-tmp"
    container: pathlib.Path | None = None
    try:
        try:
            os.mkdir(review_root, mode=0o700)
        except FileExistsError:
            pass
        try:
            root_status = os.lstat(review_root)
        except OSError as error:
            raise ReviewError(
                f"cannot inspect review root {review_root}: {error}"
            ) from error
        if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
            raise ReviewError(
                f"review root must be a real directory, not a symlink: {review_root}"
            )
        if root_status.st_uid != os.geteuid():
            raise ReviewError(
                f"review root must be owned by the current user: {review_root}"
            )
        if root_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReviewError(
                f"review root must not be group or other writable: {review_root}"
            )
        if review_root.resolve() != review_root.absolute():
            raise ReviewError(
                f"review root resolves outside the source repository: {review_root}"
            )

        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            root_fd = os.open(review_root, flags)
        except OSError as error:
            raise ReviewError(
                f"cannot securely open review root {review_root}: {error}"
            ) from error
        try:
            opened_status = os.fstat(root_fd)
            if (opened_status.st_dev, opened_status.st_ino) != (
                root_status.st_dev,
                root_status.st_ino,
            ):
                raise ReviewError("review root changed while opening it securely")
            name = f"isolated-review-{stamp}-{suffix}"
            container = review_root / name
            os.mkdir(name, mode=0o700, dir_fd=root_fd)
            descriptor_status = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            path_status = os.lstat(container)
            if (descriptor_status.st_dev, descriptor_status.st_ino) != (
                path_status.st_dev,
                path_status.st_ino,
            ):
                raise ReviewError(
                    "review root changed while creating the private container"
                )
        finally:
            os.close(root_fd)
        return container, handoff_mask
    except BaseException as error:
        cleanup_error: str | None = None
        if container is not None:
            cleanup_error = _remove_partial_container(container)
        cleanup_signal = (
            consume_pending_forwarded_signal()
            if handoff_mask is not None
            else None
        )
        try:
            restore_signal_mask(handoff_mask)
        except ForwardedSignal as forwarded:
            detail = forwarded.detail
            if detail is None and container is not None and cleanup_error:
                detail = _retained_container_detail(container, cleanup_error)
            raise ForwardedSignal(forwarded.signum, detail=detail) from error
        if cleanup_signal is not None:
            detail = (
                _retained_container_detail(container, cleanup_error)
                if container is not None and cleanup_error
                else None
            )
            raise ForwardedSignal(cleanup_signal, detail=detail) from error
        if container is not None and cleanup_error:
            raise ReviewError(
                _retained_container_detail(container, cleanup_error)
            ) from error
        raise


def _iter_nul_records(
    stream: BinaryIO,
    *,
    byte_limit: int | None = None,
    record_limit: int | None = None,
    label: str = "Git metadata",
) -> Iterator[bytes]:
    pending = bytearray()
    total_bytes = 0
    records = 0
    while chunk := stream.read(64 * 1024):
        total_bytes += len(chunk)
        if byte_limit is not None and total_bytes > byte_limit:
            raise ReviewError(f"{label} exceeds the {byte_limit}-byte review limit")
        pending.extend(chunk)
        while True:
            boundary = pending.find(0)
            if boundary < 0:
                break
            records += 1
            if record_limit is not None and records > record_limit:
                raise ReviewError(
                    f"{label} exceeds the {record_limit}-entry review limit"
                )
            yield bytes(pending[:boundary])
            del pending[: boundary + 1]
    if pending:
        raise ReviewError("unterminated record from git ls-tree")


def _parse_tree_record(record: bytes) -> tuple[str, str, str, pathlib.PurePosixPath]:
    try:
        metadata, raw_path = record.split(b"\t", 1)
        raw_mode, raw_type, raw_object = metadata.split(b" ", 2)
        mode = raw_mode.decode("ascii")
        object_type = raw_type.decode("ascii")
        object_id = raw_object.decode("ascii")
        relative = pathlib.PurePosixPath(os.fsdecode(raw_path))
    except (UnicodeDecodeError, ValueError) as error:
        raise ReviewError("malformed record from git ls-tree") from error
    path_display = _redact_secret_path(os.fsdecode(raw_path), "snapshot path")
    if not raw_path or relative.is_absolute() or ".." in relative.parts:
        raise ReviewError(f"unsafe path in frozen Git tree: {path_display}")
    if any(part.casefold() == ".git" for part in relative.parts):
        raise ReviewError(f"reserved .git path in frozen Git tree: {path_display}")
    return mode, object_type, object_id, relative


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = stream.read(min(64 * 1024, size - len(value)))
        if not chunk:
            raise ReviewError("unexpected end of git cat-file output")
        value.extend(chunk)
    return bytes(value)


def _copy_exact(stream: BinaryIO, destination: BinaryIO, size: int) -> None:
    remaining = size
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise ReviewError("unexpected end of git cat-file output")
        destination.write(chunk)
        remaining -= len(chunk)


def _copy_limited(
    stream: BinaryIO,
    destination: BinaryIO,
    *,
    limit: int,
    label: str,
    record_limit: int | None = None,
) -> int:
    copied = 0
    records = 0
    while chunk := stream.read(1024 * 1024):
        copied += len(chunk)
        if copied > limit:
            raise ReviewError(f"{label} exceeds the {limit}-byte review limit")
        if record_limit is not None:
            records += chunk.count(b"\0")
            if records > record_limit:
                raise ReviewError(
                    f"{label} exceeds the {record_limit}-entry review limit"
                )
        destination.write(chunk)
    return copied


def _materialize_blob(
    *,
    cat_input: BinaryIO,
    cat_output: BinaryIO,
    workspace_root: pathlib.Path,
    destination: pathlib.Path,
    object_id: str,
    mode: str,
    materialized_bytes: int,
) -> int:
    destination_display = _redact_secret_path(
        os.fspath(destination),
        "snapshot path",
    )
    cat_input.write(object_id.encode("ascii") + b"\n")
    cat_input.flush()
    header = cat_output.readline()
    fields = header.rstrip(b"\n").split(b" ")
    if len(fields) != 3:
        raise ReviewError(f"unexpected git cat-file header: {header!r}")
    actual_object, object_type, raw_size = fields
    try:
        size = int(raw_size)
    except ValueError as error:
        raise ReviewError(f"invalid git cat-file blob size: {header!r}") from error
    try:
        actual_object_id = actual_object.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReviewError(f"invalid git cat-file object id: {header!r}") from error
    if actual_object_id != object_id or object_type != b"blob":
        raise ReviewError(f"unexpected git cat-file object: {header!r}")

    if mode != "120000" and size > MAX_SNAPSHOT_BLOB_BYTES:
        raise ReviewError(
            "frozen Git tree blob exceeds the per-file review limit: "
            f"{destination_display}"
        )
    if size > MAX_SNAPSHOT_BYTES - materialized_bytes:
        raise ReviewError("frozen Git tree exceeds the total review snapshot limit")

    resolved_parent = destination.parent.resolve(strict=False)
    if not is_relative_to(resolved_parent, workspace_root.resolve(strict=False)):
        raise ReviewError(
            f"frozen Git tree path escapes workspace: {destination_display}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)

    if mode == "120000":
        if size > 16 * 1024:
            raise ReviewError(
                f"oversized symlink target in frozen Git tree: {destination_display}"
            )
        target_bytes = _read_exact(cat_output, size)
        if b"\0" in target_bytes:
            raise ReviewError(
                f"NUL in frozen Git tree symlink target: {destination_display}"
            )
        target_text = os.fsdecode(target_bytes)
        try:
            target = (destination.parent / target_text).resolve(strict=False)
        except RuntimeError as error:
            raise ReviewError(
                f"symlink loop in frozen Git tree: {destination_display}"
            ) from error
        if not is_relative_to(target, workspace_root.resolve(strict=False)):
            target_display = _redact_secret_path(target_text, "symlink target")
            raise ReviewError(
                "frozen Git tree symlink escapes workspace: "
                f"{destination_display} -> {target_display}"
            )
        destination.symlink_to(target_text)
    elif mode in {"100644", "100755"}:
        with destination.open("xb") as handle:
            _copy_exact(cat_output, handle, size)
        destination.chmod(0o755 if mode == "100755" else 0o644)
    else:
        raise ReviewError(
            f"unsupported mode in frozen Git tree: {mode} {destination_display}"
        )
    if cat_output.read(1) != b"\n":
        raise ReviewError("missing delimiter after git cat-file blob")
    return materialized_bytes + size


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _close_pipe(stream: BinaryIO | None) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except OSError:
        pass


def _process_stderr(handle: BinaryIO) -> str:
    handle.flush()
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    handle.seek(max(0, size - 64 * 1024))
    return handle.read().decode("utf-8", errors="replace").strip()


def _materialize_frozen_tree(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    head_sha: str,
    workspace_root: pathlib.Path,
) -> None:
    workspace_root.mkdir()
    environment = _git_environment(object_directory=object_directory)
    with (
        tempfile.TemporaryFile() as tree_stderr,
        tempfile.TemporaryFile() as cat_stderr,
    ):
        tree_process = subprocess.Popen(
            _frozen_command(
                git_view=git_view,
                args=("ls-tree", "-rz", "--full-tree", "-r", head_sha),
            ),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=tree_stderr,
        )
        try:
            cat_process = subprocess.Popen(
                _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=cat_stderr,
            )
        except BaseException:
            _close_pipe(tree_process.stdout)
            _stop_process(tree_process)
            raise
        if (
            tree_process.stdout is None
            or cat_process.stdin is None
            or cat_process.stdout is None
        ):
            _stop_process(tree_process)
            _stop_process(cat_process)
            raise ReviewError(
                "failed to create pipes for frozen Git tree materialization"
            )
        materialized_bytes = 0
        materialized_entries = 0
        try:
            for record in _iter_nul_records(
                tree_process.stdout,
                byte_limit=MAX_TREE_METADATA_BYTES,
                label="frozen Git tree metadata",
            ):
                materialized_entries += 1
                if materialized_entries > MAX_SNAPSHOT_ENTRIES:
                    raise ReviewError(
                        "frozen Git tree exceeds the review entry-count limit"
                    )
                mode, object_type, object_id, relative = _parse_tree_record(record)
                destination = workspace_root.joinpath(*relative.parts)
                path_display = _redact_secret_path(
                    os.fspath(relative),
                    "snapshot path",
                )
                try:
                    if mode == "160000" and object_type == "commit":
                        resolved_parent = destination.parent.resolve(strict=False)
                        if not is_relative_to(
                            resolved_parent, workspace_root.resolve(strict=False)
                        ):
                            raise ReviewError(
                                "frozen Git tree path escapes workspace: "
                                f"{path_display}"
                            )
                        destination.mkdir(parents=True, exist_ok=False)
                        continue
                    if object_type != "blob":
                        raise ReviewError(
                            "unsupported object in frozen Git tree: "
                            f"{object_type} {path_display}"
                        )
                    materialized_bytes = _materialize_blob(
                        cat_input=cat_process.stdin,
                        cat_output=cat_process.stdout,
                        workspace_root=workspace_root,
                        destination=destination,
                        object_id=object_id,
                        mode=mode,
                        materialized_bytes=materialized_bytes,
                    )
                except OSError as error:
                    error_code = (
                        f" (errno {error.errno})" if error.errno is not None else ""
                    )
                    raise ReviewError(
                        "filesystem error while materializing frozen Git tree path "
                        f"{path_display}{error_code}"
                    ) from error
            _close_pipe(tree_process.stdout)
            tree_returncode = tree_process.wait()
            _close_pipe(cat_process.stdin)
            _close_pipe(cat_process.stdout)
            cat_returncode = cat_process.wait()
        except BaseException:
            _close_pipe(cat_process.stdin)
            _close_pipe(tree_process.stdout)
            _close_pipe(cat_process.stdout)
            _stop_process(tree_process)
            _stop_process(cat_process)
            raise
        if tree_returncode != 0:
            raise ReviewError(
                f"cannot enumerate frozen Git tree: {_process_stderr(tree_stderr)}"
            )
        if cat_returncode != 0:
            raise ReviewError(
                f"cannot materialize frozen Git blobs: {_process_stderr(cat_stderr)}"
            )


def _write_frozen_diff(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    destination: pathlib.Path,
) -> None:
    with destination.open("xb") as output, tempfile.TemporaryFile() as error_output:
        process = subprocess.Popen(
            _frozen_command(
                git_view=git_view,
                args=(
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--binary",
                    "--submodule=diff",
                    base_sha,
                    head_sha,
                ),
            ),
            env=_git_environment(object_directory=object_directory),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=error_output,
        )
        if process.stdout is None:
            _stop_process(process)
            raise ReviewError("failed to create frozen review diff pipe")
        try:
            _copy_limited(
                process.stdout,
                output,
                limit=MAX_DIFF_BYTES,
                label="frozen review diff",
            )
            _close_pipe(process.stdout)
            returncode = process.wait()
        except BaseException:
            _close_pipe(process.stdout)
            _stop_process(process)
            raise
        if returncode != 0:
            raise ReviewError(
                f"cannot generate frozen review diff: {_process_stderr(error_output)}"
            )


def _write_limited_diff_metadata(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    args: tuple[str, ...],
    output: BinaryIO,
    error_output: BinaryIO,
    label: str,
    record_limit: int,
) -> None:
    process = subprocess.Popen(
        _frozen_command(git_view=git_view, args=args),
        env=_git_environment(object_directory=object_directory),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=error_output,
    )
    if process.stdout is None:
        _stop_process(process)
        raise ReviewError(f"failed to create {label} pipe")
    try:
        _copy_limited(
            process.stdout,
            output,
            limit=MAX_CHANGED_METADATA_BYTES,
            label=label,
            record_limit=record_limit,
        )
        _close_pipe(process.stdout)
        returncode = process.wait()
    except BaseException:
        _close_pipe(process.stdout)
        _stop_process(process)
        raise
    if returncode != 0:
        raise ReviewError(f"cannot generate {label}: {_process_stderr(error_output)}")


def _write_frozen_changed_paths(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    destination: pathlib.Path,
) -> None:
    with destination.open("xb") as output, tempfile.TemporaryFile() as error_output:
        _write_limited_diff_metadata(
            git_view=git_view,
            object_directory=object_directory,
            args=(
                "diff",
                "--name-only",
                "-z",
                "--no-renames",
                base_sha,
                head_sha,
            ),
            output=output,
            error_output=error_output,
            label="frozen changed paths",
            record_limit=MAX_CHANGED_ENTRIES,
        )


def _scan_batch_blob(
    *,
    cat_input: BinaryIO,
    cat_output: BinaryIO,
    object_id: str,
    scanned_bytes: int,
) -> tuple[str | None, int]:
    cat_input.write(object_id.encode("ascii") + b"\n")
    cat_input.flush()
    header = cat_output.readline()
    fields = header.rstrip(b"\n").split(b" ")
    if len(fields) != 3 or fields[1] != b"blob":
        raise ReviewError(f"unexpected git cat-file scan header: {header!r}")
    try:
        actual_object = fields[0].decode("ascii")
        size = int(fields[2])
    except (UnicodeDecodeError, ValueError) as error:
        raise ReviewError(f"invalid git cat-file scan header: {header!r}") from error
    if actual_object != object_id:
        raise ReviewError(f"unexpected git cat-file scan object: {header!r}")
    if size > MAX_SNAPSHOT_BLOB_BYTES:
        raise ReviewError("changed Git blob exceeds the per-file review scan limit")
    if size > MAX_CHANGED_BLOB_SCAN_BYTES - scanned_bytes:
        raise ReviewError("changed Git blobs exceed the total review scan limit")
    rule = _stream_secret_rule(cat_output, size=size)
    if cat_output.read(1) != b"\n":
        raise ReviewError("missing delimiter after scanned git cat-file blob")
    return rule, scanned_bytes + size


def _write_changed_blob_findings(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    base_sha: str,
    head_sha: str,
    destination: pathlib.Path,
) -> None:
    environment = _git_environment(object_directory=object_directory)
    with (
        tempfile.TemporaryFile() as raw_output,
        tempfile.TemporaryFile() as raw_error,
        tempfile.TemporaryFile() as cat_error,
        destination.open("xb") as findings_output,
    ):
        _write_limited_diff_metadata(
            git_view=git_view,
            object_directory=object_directory,
            args=(
                "diff",
                "--raw",
                "-z",
                "--no-abbrev",
                "--no-renames",
                base_sha,
                head_sha,
            ),
            output=raw_output,
            error_output=raw_error,
            label="changed blob metadata",
            record_limit=MAX_CHANGED_ENTRIES * 2,
        )
        raw_output.seek(0)
        cat_process = subprocess.Popen(
            _frozen_command(git_view=git_view, args=("cat-file", "--batch")),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=cat_error,
        )
        if cat_process.stdin is None or cat_process.stdout is None:
            _stop_process(cat_process)
            raise ReviewError("failed to create pipes for changed Git blob scanning")
        try:
            records = iter(_iter_nul_records(raw_output))
            scanned_bytes = 0
            for metadata in records:
                if not metadata.startswith(b":"):
                    raise ReviewError(f"invalid raw Git diff record: {metadata!r}")
                fields = metadata[1:].split()
                if len(fields) != 5:
                    raise ReviewError(f"invalid raw Git diff metadata: {metadata!r}")
                old_mode, new_mode, old_object, new_object, _status = fields
                try:
                    raw_path = next(records)
                except StopIteration as error:
                    raise ReviewError(
                        "raw Git diff is missing a changed path"
                    ) from error
                for side, mode, raw_object in (
                    ("base", old_mode, old_object),
                    ("head", new_mode, new_object),
                ):
                    if mode in {b"000000", b"160000"}:
                        continue
                    try:
                        object_id = raw_object.decode("ascii")
                    except UnicodeDecodeError as error:
                        raise ReviewError(
                            f"invalid changed Git object id: {raw_object!r}"
                        ) from error
                    rule, scanned_bytes = _scan_batch_blob(
                        cat_input=cat_process.stdin,
                        cat_output=cat_process.stdout,
                        object_id=object_id,
                        scanned_bytes=scanned_bytes,
                    )
                    if rule:
                        findings_output.write(
                            side.encode("ascii")
                            + b"\0"
                            + raw_path
                            + b"\0"
                            + rule.encode("ascii")
                            + b"\0"
                        )
            _close_pipe(cat_process.stdin)
            _close_pipe(cat_process.stdout)
            cat_returncode = cat_process.wait()
        except BaseException:
            _close_pipe(cat_process.stdin)
            _close_pipe(cat_process.stdout)
            _stop_process(cat_process)
            raise
        if cat_returncode != 0:
            raise ReviewError(
                f"cannot scan changed Git blobs: {_process_stderr(cat_error)}"
            )


def validate_workspace_layout(review: ReviewWorkspace) -> None:
    source_root = review.source_root.resolve(strict=False)
    container_dir = review.container_dir.resolve(strict=False)
    expected_parent = (source_root / ".codex-tmp").resolve(strict=False)
    if container_dir.parent != expected_parent or not container_dir.name.startswith(
        "isolated-review-"
    ):
        raise ReviewError(
            f"review container is outside the source repository review root: {container_dir}"
        )
    expected_workspace = container_dir / "workspace"
    if review.workspace_root.resolve(strict=False) != expected_workspace:
        raise ReviewError(
            f"review workspace escapes its container: {review.workspace_root}"
        )
    control_dir = expected_workspace / ".codex-review"
    if review.diff_file.resolve(strict=False) != control_dir / "review.diff":
        raise ReviewError(
            f"review diff escapes its control directory: {review.diff_file}"
        )
    if review.prompt_file.resolve(strict=False) != control_dir / "review.prompt":
        raise ReviewError(
            f"review prompt escapes its control directory: {review.prompt_file}"
        )


def validate_external_workspace(review: ReviewWorkspace) -> None:
    validate_workspace_layout(review)
    workspace_root = review.workspace_root.resolve(strict=True)
    for candidate in review.workspace_root.rglob("*"):
        if not candidate.is_symlink():
            continue
        relative = candidate.relative_to(review.workspace_root).as_posix()
        candidate_display = _redact_secret_path(relative, "snapshot path")
        try:
            target = candidate.resolve(strict=False)
        except RuntimeError as error:
            raise ReviewError(
                f"external review symlink loop: {candidate_display}"
            ) from error
        if not is_relative_to(target, workspace_root):
            target_display = _redact_secret_path(
                os.fspath(target),
                "symlink target",
            )
            raise ReviewError(
                "external review symlink escapes the frozen workspace: "
                f"{candidate_display} -> {target_display}"
            )

    sensitive_findings: list[str] = []
    sensitive_finding_count = 0

    def record_finding(value: str) -> None:
        nonlocal sensitive_finding_count
        sensitive_finding_count += 1
        if len(sensitive_findings) < 10:
            sensitive_findings.append(value)

    changed_paths_file = review.workspace_root / ".codex-review/changed-paths.z"
    try:
        with changed_paths_file.open("rb") as handle:
            for raw_path in _iter_nul_records(handle):
                path_secret_rule = _value_secret_rule(raw_path)
                if path_secret_rule:
                    record_finding(
                        f"<redacted changed path> "
                        f"({path_secret_rule}; changed-path-name)"
                    )
                    continue
                changed_path = os.fsdecode(raw_path)
                path_rule = _sensitive_path_rule(changed_path)
                if path_rule:
                    path_display = _redact_secret_path(changed_path, "changed path")
                    record_finding(f"{path_display} ({path_rule}; changed-path)")
    except OSError as error:
        raise ReviewError(
            f"cannot validate external review changed paths: {error}"
        ) from error
    changed_blob_findings = (
        review.workspace_root / ".codex-review/changed-blob-findings.z"
    )
    try:
        with changed_blob_findings.open("rb") as handle:
            records = iter(_iter_nul_records(handle))
            for raw_side in records:
                try:
                    raw_path = next(records)
                    raw_rule = next(records)
                    side = raw_side.decode("ascii")
                    rule = raw_rule.decode("ascii")
                except (StopIteration, UnicodeDecodeError) as error:
                    raise ReviewError(
                        "external review changed-blob findings are malformed"
                    ) from error
                path_display = _redact_secret_path(
                    os.fsdecode(raw_path),
                    "changed blob path",
                )
                record_finding(f"{path_display} ({rule}; {side}-blob)")
    except OSError as error:
        raise ReviewError(
            f"cannot validate external review changed blobs: {error}"
        ) from error
    for candidate in review.workspace_root.rglob("*"):
        relative = candidate.relative_to(review.workspace_root).as_posix()
        path_secret_rule = _value_secret_rule(os.fsencode(relative))
        if path_secret_rule:
            record_finding(
                f"<redacted snapshot path> ({path_secret_rule}; path-name)"
            )
            continue
        path_display = _redact_secret_path(relative, "snapshot path")
        path_rule = _sensitive_path_rule(relative)
        if path_rule:
            record_finding(f"{path_display} ({path_rule})")
            continue
        if candidate.is_symlink():
            try:
                target = os.readlink(candidate)
            except OSError as error:
                error_code = (
                    f" (errno {error.errno})" if error.errno is not None else ""
                )
                raise ReviewError(
                    f"cannot inspect external review symlink {path_display}{error_code}"
                ) from error
            target_secret_rule = _value_secret_rule(os.fsencode(target))
            if target_secret_rule:
                record_finding(
                    f"{path_display} -> <redacted symlink target> "
                    f"({target_secret_rule}; symlink-target)"
                )
            continue
        if not candidate.is_file():
            continue
        secret_rule = _file_secret_rule(candidate)
        if secret_rule:
            record_finding(f"{path_display} ({secret_rule})")
    if sensitive_finding_count:
        summary = ", ".join(sensitive_findings)
        if sensitive_finding_count > len(sensitive_findings):
            summary += f", and {sensitive_finding_count - len(sensitive_findings)} more"
        raise ReviewError(
            "sensitive content preflight blocked external review; remove or narrow "
            f"these paths before egress: {summary}"
        )


def _redact_secret_path(value: str, label: str) -> str:
    if _value_secret_rule(os.fsencode(value)):
        return f"<redacted {label}>"
    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character.isprintable() and not 0xD800 <= codepoint <= 0xDFFF:
            escaped.append(character)
        elif codepoint <= 0xFF:
            escaped.append(f"\\x{codepoint:02x}")
        elif codepoint <= 0xFFFF:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(f"\\U{codepoint:08x}")
    return "".join(escaped)


def _sensitive_path_rule(relative: str) -> str | None:
    normalized = relative.casefold()
    parts = pathlib.PurePosixPath(normalized).parts
    name = parts[-1] if parts else ""
    if name in SENSITIVE_ANYWHERE_NAMES or name in SENSITIVE_FILE_NAMES:
        return "credential-path"
    if any(
        len(parts) >= len(suffix) and parts[-len(suffix) :] == suffix
        for suffix in SENSITIVE_PATH_SUFFIXES
    ):
        return "credential-path"
    if name == ".env" or name.endswith(".env") or (
        name.startswith(".env.")
        and not any(name.endswith(suffix) for suffix in SAFE_ENV_SUFFIXES)
    ):
        return "environment-file"
    if name.endswith(SENSITIVE_SUFFIXES):
        return "credential-container"
    return None


def _file_secret_rule(path: pathlib.Path) -> str | None:
    try:
        with path.open("rb") as handle:
            return _stream_secret_rule(handle)
    except OSError as error:
        path_display = _redact_secret_path(os.fspath(path), "snapshot path")
        error_code = f" (errno {error.errno})" if error.errno is not None else ""
        raise ReviewError(
            f"cannot scan external review content {path_display}{error_code}"
        ) from error


def _stream_secret_rule(stream: BinaryIO, *, size: int | None = None) -> str | None:
    overlap = 4096
    pending = b""
    remaining = size
    finding: str | None = None
    while remaining is None or remaining > 0:
        read_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
        chunk = stream.read(read_size)
        if not chunk:
            if remaining not in (None, 0):
                raise ReviewError("unexpected end of Git blob during sensitive scan")
            break
        if remaining is not None:
            remaining -= len(chunk)
        if finding is None:
            finding = _value_secret_rule(pending + chunk)
        pending = (pending + chunk)[-overlap:]
    return finding


def _value_secret_rule(value: bytes) -> str | None:
    for rule, pattern in SECRET_PATTERNS:
        if pattern.search(value):
            return rule
    if OVERSIZED_QUOTED_SECRET_ASSIGNMENT.search(
        value
    ) or OVERSIZED_UNQUOTED_SECRET_ASSIGNMENT.search(value):
        return "generic-secret-assignment"
    for match in QUOTED_SECRET_ASSIGNMENT.finditer(value):
        candidate = match.group(2).lower()
        if not _is_placeholder_secret(candidate):
            return "generic-secret-assignment"
    for match in UNQUOTED_SECRET_ASSIGNMENT.finditer(value):
        candidate = match.group(1)
        if not _is_placeholder_secret(
            candidate.lower()
        ) and _looks_like_unquoted_secret(candidate):
            return "generic-secret-assignment"
    return None


def _is_placeholder_secret(candidate: bytes) -> bool:
    return PLACEHOLDER_SECRET_PATTERN.fullmatch(candidate.strip()) is not None


def _looks_like_unquoted_secret(candidate: bytes) -> bool:
    if LONG_NUMERIC_SECRET.fullmatch(candidate):
        return True
    if LONG_ALPHANUMERIC_SECRET.fullmatch(candidate):
        return True
    character_classes = sum(
        (
            any(97 <= value <= 122 for value in candidate),
            any(65 <= value <= 90 for value in candidate),
            any(48 <= value <= 57 for value in candidate),
            any(
                33 <= value <= 126
                and not 48 <= value <= 57
                and not 65 <= value <= 90
                and not 97 <= value <= 122
                for value in candidate
            ),
        )
    )
    return character_classes >= 3 and any(48 <= value <= 57 for value in candidate)


def _read_prompt_template(path: pathlib.Path) -> str:
    try:
        with path.open("rb") as handle:
            encoded = handle.read(MAX_REVIEW_PROMPT_BYTES + 1)
    except OSError as error:
        raise ReviewError(f"cannot read review prompt override: {error}") from error
    if len(encoded) > MAX_REVIEW_PROMPT_BYTES:
        raise ReviewError(
            f"review prompt exceeds the {MAX_REVIEW_PROMPT_BYTES}-byte limit"
        )
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReviewError("review prompt override is not valid UTF-8") from error


def _validate_prompt_size(prompt: str) -> None:
    if len(prompt.encode("utf-8")) > MAX_REVIEW_PROMPT_BYTES:
        raise ReviewError(
            f"review prompt exceeds the {MAX_REVIEW_PROMPT_BYTES}-byte limit"
        )


def prepare_workspace(
    *,
    repo: pathlib.Path,
    base_ref: str,
    head_ref: str,
    ownership_handoff: Callable[[ReviewWorkspace], None],
    prompt_override: pathlib.Path | None = None,
) -> ReviewWorkspace:
    source_root = resolve_repo_root(repo)
    base_sha = resolve_commit(source_root, base_ref, label="base ref")
    head_sha = resolve_commit(source_root, head_ref, label="head ref")
    _require_ancestor_range(
        source_root,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    container, handoff_mask = _new_container(source_root)
    ownership_transferred = False

    try:
        restore_signal_mask(handoff_mask)
        handoff_mask = None
        workspace_root = container / "workspace"
        git_view, object_directory = _create_sanitized_git_view(
            source_root=source_root,
            container=container,
        )
        for label, commit in (("base", base_sha), ("head", head_sha)):
            if _commit_uses_reserved_control_path(
                git_view=git_view,
                object_directory=object_directory,
                commit=commit,
                label=label,
            ):
                raise ReviewError(
                    f"the frozen {label} uses the reserved top-level .codex-review path"
                )
        _materialize_frozen_tree(
            git_view=git_view,
            object_directory=object_directory,
            head_sha=head_sha,
            workspace_root=workspace_root,
        )
        _reject_protected_review_path_aliases(workspace_root)
        control_dir = workspace_root / ".codex-review"
        if control_dir.exists() or control_dir.is_symlink():
            raise ReviewError(
                "the frozen head uses the reserved top-level .codex-review path"
            )
        control_dir.mkdir()
        changed_paths_file = control_dir / "changed-paths.z"
        _write_frozen_changed_paths(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
            destination=changed_paths_file,
        )
        changed_blob_findings = control_dir / "changed-blob-findings.z"
        _write_changed_blob_findings(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
            destination=changed_blob_findings,
        )
        diff_file = control_dir / "review.diff"
        _write_frozen_diff(
            git_view=git_view,
            object_directory=object_directory,
            base_sha=base_sha,
            head_sha=head_sha,
            destination=diff_file,
        )
        shutil.rmtree(git_view)

        prompt_file = control_dir / "review.prompt"
        if prompt_override is None:
            prompt = build_review_prompt(
                workspace=workspace_root,
                diff_file=diff_file,
                base_ref=base_sha,
                head_ref=head_sha,
            )
        else:
            template = _read_prompt_template(prompt_override.expanduser().resolve())
            replacements = {
                "workspace": str(workspace_root),
                "diff_file": str(diff_file),
                "base_ref": base_sha,
                "head_ref": head_sha,
                "review_range": f"{base_sha}..{head_sha}",
            }
            prompt = re.sub(
                r"\{(workspace|diff_file|base_ref|head_ref|review_range)\}",
                lambda match: replacements[match.group(1)],
                template,
            )
        _validate_prompt_size(prompt)
        write_text_atomic(prompt_file, prompt)
        review = ReviewWorkspace(
            source_root=source_root,
            container_dir=container,
            workspace_root=workspace_root,
            base_ref=base_sha,
            head_ref=head_sha,
            diff_file=diff_file,
            prompt_file=prompt_file,
        )
        validate_workspace_layout(review)
        ownership_mask = block_forwarded_signals()
        try:
            ownership_handoff(review)
            ownership_transferred = True
        finally:
            restore_signal_mask(ownership_mask)
        return review
    except BaseException as error:
        if ownership_transferred:
            raise
        cleanup_mask = block_forwarded_signals()
        cleanup_signal: signal.Signals | None = None
        cleanup_error: str | None = None
        try:
            cleanup_error = _remove_partial_container(container)
            if cleanup_mask is not None:
                cleanup_signal = consume_pending_forwarded_signal()
        finally:
            try:
                restore_signal_mask(cleanup_mask)
            except ForwardedSignal as forwarded:
                detail = forwarded.detail
                if detail is None and cleanup_error:
                    detail = _retained_container_detail(container, cleanup_error)
                raise ForwardedSignal(forwarded.signum, detail=detail) from error
        if cleanup_signal is not None:
            detail = (
                _retained_container_detail(container, cleanup_error)
                if cleanup_error
                else None
            )
            raise ForwardedSignal(cleanup_signal, detail=detail) from error
        if cleanup_error:
            raise ReviewError(
                _retained_container_detail(container, cleanup_error)
            ) from error
        raise
    finally:
        if handoff_mask is not None:
            restore_signal_mask(handoff_mask)


def cleanup_workspace(review: ReviewWorkspace, *, keep_container: bool) -> str | None:
    validate_workspace_layout(review)
    try:
        if review.workspace_root.exists():
            shutil.rmtree(review.workspace_root)
        if not keep_container:
            shutil.rmtree(review.container_dir)
    except OSError as error:
        return str(error)
    return None
