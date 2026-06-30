from __future__ import annotations

import json
import pathlib
import re
from dataclasses import asdict, dataclass, replace
from typing import Any, Callable, Iterable

from .common import (
    Completed,
    child_environment,
    resolve_executable,
    run,
    write_json,
    write_text_atomic,
)
from .workspace import ReviewWorkspace


CODEX_MODELS = ("gpt-5.6-sol", "gpt-5.5")
CODEX_REASONING_EFFORT = "xhigh"
CLAUDE_MODELS = ("claude-opus-4-8", "claude-opus-4-7")
COPILOT_MODELS = ("claude-opus-4.8", "claude-opus-4.7")
CLAUDE_REASONING_EFFORT = "max"
COPILOT_REASONING_EFFORT = "max"
CLAUDE_EGRESS_CONSENTS = (
    "explicit-claude-review",
    "double-review",
    "triple-review",
)

TRANSIENT_FAILURE_FRAGMENTS = (
    "at capacity",
    "capacity is temporarily",
    "overloaded",
    "rate limit",
    "rate_limit",
    "too many requests",
    "temporarily unavailable",
    "service unavailable",
    "gateway timeout",
    "timed out",
    "timeout",
    "connection reset",
    "connection refused",
    "network error",
    "status 429",
    "status 500",
    "status 502",
    "status 503",
    "status 504",
)

ENTITLEMENT_FAILURE_FRAGMENTS = (
    "not available for your account",
    "not available on your plan",
    "not available on your current plan",
    "not available with your current subscription",
    "not included in your plan",
    "not enabled for your account",
    "not enabled for this user",
    "not enabled for this organization",
    "not entitled",
    "user is not entitled",
    "does not have access to the model",
    "don't have access to the model",
    "do not have access to the model",
    "model access is disabled",
    "model is disabled by your organization",
    "model is not allowed by your organization",
    "not in your organization's allowed models",
    "not in your organisation's allowed models",
    "model is not available to this account",
    "model is not available for this user",
    "not supported with your chatgpt account",
    "not supported when using codex with a chatgpt account",
    "unsupported model for this account",
    "model_not_enabled",
    "model_not_entitled",
)

AUTH_FAILURE_FRAGMENTS = (
    "authentication failed",
    "not authenticated",
    "not logged in",
    "login required",
    "invalid api key",
    "invalid token",
    "unauthorized",
    "status 401",
)


@dataclass(frozen=True)
class Attempt:
    runtime: str
    requested_model: str
    effective_model: str | None
    returncode: int
    category: str
    final_text: str | None
    stdout_path: str
    stderr_path: str


@dataclass(frozen=True)
class Outcome:
    returncode: int
    final_text: str | None
    attempts: tuple[Attempt, ...]


def classify_failure(stdout: bytes | str, stderr: bytes | str) -> str:
    def decode(value: bytes | str) -> str:
        return (
            value.decode("utf-8", errors="replace")
            if isinstance(value, bytes)
            else value
        )

    message = f"{decode(stderr)}\n{decode(stdout)}".lower()
    if any(fragment in message for fragment in TRANSIENT_FAILURE_FRAGMENTS):
        return "transient"
    if any(fragment in message for fragment in AUTH_FAILURE_FRAGMENTS):
        return "auth"
    if any(fragment in message for fragment in ENTITLEMENT_FAILURE_FRAGMENTS):
        return "entitlement"
    return "other"


def _normalize_model(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _model_matches(requested: str, effective: str) -> bool:
    requested_normalized = _normalize_model(requested)
    effective_normalized = _normalize_model(effective)
    return effective_normalized.startswith(requested_normalized)


def _json_objects(stdout: bytes) -> list[dict[str, Any]]:
    text = stdout.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    values: list[dict[str, Any]] = []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        values.append(parsed)
        return values
    for line in text.splitlines():
        try:
            parsed_line = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed_line, dict):
            values.append(parsed_line)
    return values


def _find_text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        for key in (
            "result",
            "final",
            "content",
            "text",
            "message",
            "response",
            "data",
        ):
            if key in value:
                found = _find_text(value[key])
                if found:
                    return found
    if isinstance(value, list):
        for item in reversed(value):
            found = _find_text(item)
            if found:
                return found
    return None


def _find_model(value: Any) -> str | None:
    if isinstance(value, dict):
        model_usage = value.get("modelUsage")
        if isinstance(model_usage, dict) and model_usage:
            first = next(iter(model_usage))
            if isinstance(first, str):
                return first
        for key in ("model", "modelName", "model_id", "modelId"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for key in ("data", "metadata", "result", "usage"):
            if key in value:
                found = _find_model(value[key])
                if found:
                    return found
    if isinstance(value, list):
        for item in reversed(value):
            found = _find_model(item)
            if found:
                return found
    return None


def _parse_structured_output(stdout: bytes) -> tuple[str | None, str | None]:
    objects = _json_objects(stdout)
    final_text: str | None = None
    effective_model: str | None = None
    for item in reversed(objects):
        if final_text is None:
            final_text = _find_text(item)
        if effective_model is None:
            effective_model = _find_model(item)
        if final_text is not None and effective_model is not None:
            break
    return final_text, effective_model


def _attempt_paths(
    review: ReviewWorkspace, index: int, runtime: str, model: str
) -> tuple[pathlib.Path, pathlib.Path]:
    safe_model = re.sub(r"[^A-Za-z0-9_.-]+", "-", model)
    prefix = review.container_dir / "attempts" / f"{index:02d}-{runtime}-{safe_model}"
    prefix.parent.mkdir(parents=True, exist_ok=True)
    return pathlib.Path(f"{prefix}.stdout.log"), pathlib.Path(f"{prefix}.stderr.log")


def _record_attempt(
    *,
    review: ReviewWorkspace,
    index: int,
    runtime: str,
    model: str,
    completed: Completed,
    final_text: str | None,
    effective_model: str | None,
) -> Attempt:
    stdout_path, stderr_path = _attempt_paths(review, index, runtime, model)
    stdout_path.write_bytes(completed.stdout)
    stderr_path.write_bytes(completed.stderr)
    category = (
        "success"
        if completed.returncode == 0 and final_text
        else classify_failure(completed.stdout, completed.stderr)
    )
    attempt = Attempt(
        runtime=runtime,
        requested_model=model,
        effective_model=effective_model,
        returncode=completed.returncode,
        category=category,
        final_text=final_text,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )
    if (
        attempt.category == "success"
        and effective_model
        and not _model_matches(model, effective_model)
    ):
        mismatch = (
            f"requested model {model!r} was replaced by {effective_model!r}; "
            "refusing to infer an entitlement failure from silent model substitution"
        )
        write_text_atomic(
            stderr_path,
            completed.stderr.decode("utf-8", errors="replace") + "\n" + mismatch + "\n",
        )
        attempt = replace(
            attempt,
            returncode=65,
            category="model-mismatch",
            final_text=None,
        )
    return attempt


def _codex_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
) -> Attempt:
    executable = resolve_executable(
        "codex", ("/opt/homebrew/bin/codex", "/usr/local/bin/codex")
    )
    if executable is None:
        raise FileNotFoundError("codex is not available in a trusted executable path")
    attempt_final = review.container_dir / "attempts" / f"{index:02d}-codex-final.txt"
    prompt = review.prompt_file.read_bytes()
    completed = run(
        (
            str(executable),
            "-s",
            "read-only",
            "-m",
            model,
            "-c",
            f'model_reasoning_effort="{CODEX_REASONING_EFFORT}"',
            "exec",
            "--json",
            "-o",
            str(attempt_final),
            "-",
        ),
        cwd=review.workspace_root,
        env=env,
        stdin=prompt,
    )
    final_text = None
    if completed.returncode == 0 and attempt_final.is_file():
        final_text = (
            attempt_final.read_text(encoding="utf-8", errors="replace").strip() or None
        )
    return _record_attempt(
        review=review,
        index=index,
        runtime="codex",
        model=model,
        completed=completed,
        final_text=final_text,
        effective_model=model if final_text else None,
    )


def _claude_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
) -> Attempt:
    executable = resolve_executable(
        "claude", ("/opt/homebrew/bin/claude", "/usr/local/bin/claude")
    )
    if executable is None:
        raise FileNotFoundError("claude is not available in a trusted executable path")
    completed = run(
        (
            str(executable),
            "--print",
            "--model",
            model,
            "--effort",
            CLAUDE_REASONING_EFFORT,
            "--permission-mode",
            "plan",
            "--output-format",
            "json",
            "--no-session-persistence",
            "--no-chrome",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--mcp-config",
            "{}",
            "--setting-sources",
            "",
            "--tools",
            "Read,Grep,Glob",
        ),
        cwd=review.workspace_root,
        env=env,
        stdin=review.prompt_file.read_bytes(),
    )
    final_text, effective_model = _parse_structured_output(completed.stdout)
    return _record_attempt(
        review=review,
        index=index,
        runtime="claude",
        model=model,
        completed=completed,
        final_text=final_text if completed.returncode == 0 else None,
        effective_model=effective_model,
    )


def _copilot_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
) -> Attempt:
    executable = resolve_executable(
        "copilot", ("/opt/homebrew/bin/copilot", "/usr/local/bin/copilot")
    )
    if executable is None:
        raise FileNotFoundError("copilot is not available in a trusted executable path")
    command = [
        str(executable),
        "--prompt",
        review.prompt_file.read_text(encoding="utf-8"),
        "--model",
        model,
        "--reasoning-effort",
        COPILOT_REASONING_EFFORT,
        "--output-format",
        "json",
        "--mode",
        "plan",
        "--allow-all-tools",
        "--disable-builtin-mcps",
        "--no-bash-env",
        "--no-custom-instructions",
        "--no-experimental",
        "--no-remote",
        "--no-remote-export",
        "--no-color",
        "--no-ask-user",
    ]
    sensitive_names = sorted(
        name
        for name in env
        if any(
            marker in name.upper()
            for marker in (
                "API_KEY",
                "CREDENTIAL",
                "PASSWORD",
                "PRIVATE_KEY",
                "SECRET",
                "TOKEN",
            )
        )
    )
    if sensitive_names:
        command.append(f"--secret-env-vars={','.join(sensitive_names)}")
    completed = run(
        command,
        cwd=review.workspace_root,
        env=env,
    )
    final_text, effective_model = _parse_structured_output(completed.stdout)
    return _record_attempt(
        review=review,
        index=index,
        runtime="copilot",
        model=model,
        completed=completed,
        final_text=final_text if completed.returncode == 0 else None,
        effective_model=effective_model,
    )


AttemptRunner = Callable[..., Attempt]


def _finish(
    review: ReviewWorkspace, attempts: list[Attempt], final_text: str | None
) -> Outcome:
    write_json(
        review.container_dir / "attempts.json", [asdict(item) for item in attempts]
    )
    if final_text:
        write_text_atomic(
            review.container_dir / "final.txt", final_text.rstrip() + "\n"
        )
        return Outcome(0, final_text, tuple(attempts))
    if attempts and attempts[-1].category == "transient":
        return Outcome(75, None, tuple(attempts))
    return Outcome(1, None, tuple(attempts))


def _run_model_chain(
    *,
    review: ReviewWorkspace,
    models: Iterable[str],
    runner: AttemptRunner,
    env: dict[str, str],
    attempts: list[Attempt],
) -> tuple[str, str | None]:
    for model in models:
        attempt = runner(
            review=review,
            model=model,
            index=len(attempts) + 1,
            env=env,
        )
        attempts.append(attempt)
        if attempt.category == "success":
            return "success", attempt.final_text
        if attempt.category != "entitlement":
            return attempt.category, None
    return "entitlement", None


def run_review(
    *,
    review: ReviewWorkspace,
    reviewer: str,
    shim_source: pathlib.Path,
    egress_consent: str | None = None,
) -> Outcome:
    if reviewer == "claude":
        if egress_consent not in CLAUDE_EGRESS_CONSENTS:
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                "Claude-family review requires an explicit egress-consent reason.\n",
            )
            return Outcome(2, None, tuple())
        write_json(
            review.container_dir / "egress.json",
            {
                "consent": egress_consent,
                "reviewer": "claude-family",
                "review_range": f"{review.base_ref}..{review.head_ref}",
                "included": [
                    "tracked files in the detached worktree at the frozen head",
                    "the generated frozen diff",
                    "the review prompt and result",
                ],
                "excluded": [
                    "credentials or secrets",
                    "untracked files",
                    "unrelated repositories",
                    "broad workspace or home-directory content",
                ],
            },
        )
    elif egress_consent is not None:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "egress-consent is valid only for the Claude-family reviewer.\n",
        )
        return Outcome(2, None, tuple())

    env = child_environment(
        container_dir=review.container_dir,
        shim_source=shim_source,
        extra={
            "CODEX_ISOLATED_REVIEW_ROOT": str(review.workspace_root),
            "CODEX_ISOLATED_REVIEW_DIFF_FILE": str(review.diff_file),
            "CODEX_ISOLATED_REVIEW_PROMPT_FILE": str(review.prompt_file),
            "CODEX_ISOLATED_REVIEW_RANGE": f"{review.base_ref}..{review.head_ref}",
        },
    )
    attempts: list[Attempt] = []

    if reviewer == "codex":
        try:
            _, final_text = _run_model_chain(
                review=review,
                models=CODEX_MODELS,
                runner=_codex_attempt,
                env=env,
                attempts=attempts,
            )
        except FileNotFoundError as error:
            write_text_atomic(review.container_dir / "runner-error.txt", f"{error}\n")
            return Outcome(127, None, tuple())
        return _finish(review, attempts, final_text)

    if reviewer != "claude":
        write_text_atomic(
            review.container_dir / "runner-error.txt", f"unknown reviewer: {reviewer}\n"
        )
        return Outcome(2, None, tuple())

    claude_available = (
        resolve_executable(
            "claude", ("/opt/homebrew/bin/claude", "/usr/local/bin/claude")
        )
        is not None
    )
    if claude_available:
        category, final_text = _run_model_chain(
            review=review,
            models=CLAUDE_MODELS,
            runner=_claude_attempt,
            env=env,
            attempts=attempts,
        )
        if final_text:
            return _finish(review, attempts, final_text)
        if category != "entitlement":
            return _finish(review, attempts, None)

    copilot_available = (
        resolve_executable(
            "copilot", ("/opt/homebrew/bin/copilot", "/usr/local/bin/copilot")
        )
        is not None
    )
    if not copilot_available:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code was unavailable or lacked model entitlement, and Copilot CLI is unavailable.\n",
        )
        return _finish(review, attempts, None)
    _, final_text = _run_model_chain(
        review=review,
        models=COPILOT_MODELS,
        runner=_copilot_attempt,
        env=env,
        attempts=attempts,
    )
    return _finish(review, attempts, final_text)
