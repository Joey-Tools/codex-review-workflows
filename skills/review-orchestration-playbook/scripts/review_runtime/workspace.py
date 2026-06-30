from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from typing import BinaryIO, Iterator

from .common import (
    TRUSTED_PATH,
    ReviewError,
    is_relative_to,
    resolve_git,
    run,
    write_text_atomic,
)
from .prompt import build_review_prompt


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
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": TRUSTED_PATH,
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
    config = "[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
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


def _new_container(source_root: pathlib.Path) -> pathlib.Path:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    suffix = uuid.uuid4().hex[:10]
    container = source_root / ".codex-tmp" / f"isolated-review-{stamp}-{suffix}"
    container.mkdir(parents=True, exist_ok=False)
    return container


def _iter_nul_records(stream: BinaryIO) -> Iterator[bytes]:
    pending = bytearray()
    while chunk := stream.read(64 * 1024):
        pending.extend(chunk)
        while True:
            boundary = pending.find(0)
            if boundary < 0:
                break
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
        raise ReviewError(f"malformed record from git ls-tree: {record!r}") from error
    if not raw_path or relative.is_absolute() or ".." in relative.parts:
        raise ReviewError(f"unsafe path in frozen Git tree: {os.fsdecode(raw_path)!r}")
    if any(part.casefold() == ".git" for part in relative.parts):
        raise ReviewError(f"reserved .git path in frozen Git tree: {relative}")
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


def _materialize_blob(
    *,
    cat_input: BinaryIO,
    cat_output: BinaryIO,
    workspace_root: pathlib.Path,
    destination: pathlib.Path,
    object_id: str,
    mode: str,
) -> None:
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

    resolved_parent = destination.parent.resolve(strict=False)
    if not is_relative_to(resolved_parent, workspace_root.resolve(strict=False)):
        raise ReviewError(f"frozen Git tree path escapes workspace: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    if mode == "120000":
        if size > 16 * 1024:
            raise ReviewError(
                f"oversized symlink target in frozen Git tree: {destination}"
            )
        target_bytes = _read_exact(cat_output, size)
        if b"\0" in target_bytes:
            raise ReviewError(f"NUL in frozen Git tree symlink target: {destination}")
        target_text = os.fsdecode(target_bytes)
        try:
            target = (destination.parent / target_text).resolve(strict=False)
        except RuntimeError as error:
            raise ReviewError(
                f"symlink loop in frozen Git tree: {destination}"
            ) from error
        if not is_relative_to(target, workspace_root.resolve(strict=False)):
            raise ReviewError(
                f"frozen Git tree symlink escapes workspace: {destination} -> {target_text}"
            )
        destination.symlink_to(target_text)
    elif mode in {"100644", "100755"}:
        with destination.open("xb") as handle:
            _copy_exact(cat_output, handle, size)
        destination.chmod(0o755 if mode == "100755" else 0o644)
    else:
        raise ReviewError(f"unsupported mode in frozen Git tree: {mode} {destination}")
    if cat_output.read(1) != b"\n":
        raise ReviewError("missing delimiter after git cat-file blob")


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
        try:
            for record in _iter_nul_records(tree_process.stdout):
                mode, object_type, object_id, relative = _parse_tree_record(record)
                destination = workspace_root.joinpath(*relative.parts)
                if mode == "160000" and object_type == "commit":
                    resolved_parent = destination.parent.resolve(strict=False)
                    if not is_relative_to(
                        resolved_parent, workspace_root.resolve(strict=False)
                    ):
                        raise ReviewError(
                            f"frozen Git tree path escapes workspace: {destination}"
                        )
                    destination.mkdir(parents=True, exist_ok=False)
                    continue
                if object_type != "blob":
                    raise ReviewError(
                        f"unsupported object in frozen Git tree: {object_type} {relative}"
                    )
                _materialize_blob(
                    cat_input=cat_process.stdin,
                    cat_output=cat_process.stdout,
                    workspace_root=workspace_root,
                    destination=destination,
                    object_id=object_id,
                    mode=mode,
                )
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
        completed = subprocess.run(
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
            stdout=output,
            stderr=error_output,
            check=False,
        )
        if completed.returncode != 0:
            raise ReviewError(
                f"cannot generate frozen review diff: {_process_stderr(error_output)}"
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
        try:
            target = candidate.resolve(strict=False)
        except RuntimeError as error:
            raise ReviewError(f"external review symlink loop: {candidate}") from error
        if not is_relative_to(target, workspace_root):
            raise ReviewError(
                f"external review symlink escapes the frozen workspace: {candidate} -> {target}"
            )


def prepare_workspace(
    *,
    repo: pathlib.Path,
    base_ref: str,
    head_ref: str,
    prompt_override: pathlib.Path | None = None,
) -> ReviewWorkspace:
    source_root = resolve_repo_root(repo)
    base_sha = resolve_commit(source_root, base_ref, label="base ref")
    head_sha = resolve_commit(source_root, head_ref, label="head ref")
    container = _new_container(source_root)
    workspace_root = container / "workspace"

    try:
        git_view, object_directory = _create_sanitized_git_view(
            source_root=source_root,
            container=container,
        )
        _materialize_frozen_tree(
            git_view=git_view,
            object_directory=object_directory,
            head_sha=head_sha,
            workspace_root=workspace_root,
        )
        control_dir = workspace_root / ".codex-review"
        if control_dir.exists() or control_dir.is_symlink():
            raise ReviewError(
                "the frozen head uses the reserved top-level .codex-review path"
            )
        control_dir.mkdir()
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
            prompt = prompt_override.expanduser().resolve().read_text(encoding="utf-8")
            prompt = (
                prompt.replace("{workspace}", str(workspace_root))
                .replace("{diff_file}", str(diff_file))
                .replace("{base_ref}", base_sha)
                .replace("{head_ref}", head_sha)
                .replace("{review_range}", f"{base_sha}..{head_sha}")
            )
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
        return review
    except Exception:
        shutil.rmtree(container, ignore_errors=True)
        raise


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
