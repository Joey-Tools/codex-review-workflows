from __future__ import annotations

import io
import os
import pathlib
import shutil
import tarfile
import time
import uuid
from dataclasses import asdict, dataclass

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


def _frozen_git(
    *,
    git_view: pathlib.Path,
    object_directory: pathlib.Path,
    args: tuple[str, ...],
    check: bool = True,
):
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
            f"--git-dir={git_view}",
            *args,
        ),
        env=_git_environment(object_directory=object_directory),
        check=check,
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


def _extract_frozen_archive(archive_bytes: bytes, workspace_root: pathlib.Path) -> None:
    workspace_root.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            relative = pathlib.PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ReviewError(f"unsafe path in frozen Git archive: {member.name}")
            if member.isdev() or member.isfifo():
                raise ReviewError(
                    f"unsupported special file in frozen Git archive: {member.name}"
                )
            destination = workspace_root.joinpath(*relative.parts)
            if member.issym():
                target = (destination.parent / member.linkname).resolve(strict=False)
                if not is_relative_to(target, workspace_root.resolve(strict=False)):
                    raise ReviewError(
                        f"frozen Git archive symlink escapes workspace: {member.name} -> {member.linkname}"
                    )
            if member.islnk():
                target = workspace_root.joinpath(
                    *pathlib.PurePosixPath(member.linkname).parts
                ).resolve(strict=False)
                if not is_relative_to(target, workspace_root.resolve(strict=False)):
                    raise ReviewError(
                        f"frozen Git archive hardlink escapes workspace: {member.name} -> {member.linkname}"
                    )
        archive.extractall(workspace_root, members=members, filter="data")


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
        archive_result = _frozen_git(
            git_view=git_view,
            object_directory=object_directory,
            args=("archive", "--format=tar", head_sha),
        )
        _extract_frozen_archive(archive_result.stdout, workspace_root)

        diff_result = _frozen_git(
            git_view=git_view,
            object_directory=object_directory,
            args=(
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                "--submodule=diff",
                base_sha,
                head_sha,
            ),
            check=False,
        )
        if diff_result.returncode != 0:
            detail = diff_result.stderr.decode("utf-8", errors="replace").strip()
            raise ReviewError(f"cannot generate frozen review diff: {detail}")
        shutil.rmtree(git_view)
        control_dir = workspace_root / ".codex-review"
        control_dir.mkdir()
        diff_file = control_dir / "review.diff"
        diff_file.write_bytes(diff_result.stdout)

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
