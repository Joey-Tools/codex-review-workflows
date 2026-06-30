from __future__ import annotations

import pathlib
import shutil
import time
import uuid
from dataclasses import asdict, dataclass

from .common import ReviewError, resolve_git, run, write_text_atomic
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


def _git(repo: pathlib.Path, *args: str, check: bool = True):
    return run((str(resolve_git()), "-C", str(repo), *args), check=check)


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
    git = resolve_git()

    added = False
    try:
        run(
            (
                str(git),
                "-C",
                str(source_root),
                "worktree",
                "add",
                "--detach",
                str(workspace_root),
                head_sha,
            ),
            check=True,
        )
        added = True

        if (workspace_root / ".gitmodules").is_file():
            result = run(
                (
                    str(git),
                    "-C",
                    str(workspace_root),
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                    "--no-fetch",
                )
            )
            if result.returncode != 0:
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                raise ReviewError(
                    "cannot materialize frozen submodules without fetching; "
                    f"initialize the required objects in the source repo first: {detail}"
                )

        diff_result = run(
            (
                str(git),
                "-C",
                str(workspace_root),
                "diff",
                "--binary",
                "--submodule=diff",
                base_sha,
                head_sha,
            )
        )
        if diff_result.returncode != 0:
            detail = diff_result.stderr.decode("utf-8", errors="replace").strip()
            raise ReviewError(f"cannot generate frozen review diff: {detail}")
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
        if added:
            run(
                (
                    str(git),
                    "-C",
                    str(source_root),
                    "worktree",
                    "remove",
                    "--force",
                    str(workspace_root),
                )
            )
        shutil.rmtree(container, ignore_errors=True)
        raise


def cleanup_workspace(review: ReviewWorkspace, *, keep_container: bool) -> str | None:
    validate_workspace_layout(review)
    git = resolve_git()
    error_text: str | None = None
    if review.workspace_root.exists():
        result = run(
            (
                str(git),
                "-C",
                str(review.source_root),
                "worktree",
                "remove",
                "--force",
                str(review.workspace_root),
            )
        )
        if result.returncode != 0:
            error_text = result.stderr.decode("utf-8", errors="replace").strip()
            shutil.rmtree(review.workspace_root, ignore_errors=True)
            run((str(git), "-C", str(review.source_root), "worktree", "prune"))
    if not keep_container and error_text is None:
        shutil.rmtree(review.container_dir, ignore_errors=True)
    return error_text
