from __future__ import annotations

import json
import os
import pathlib
import re
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable

from .common import (
    Completed,
    ReviewError,
    child_environment,
    reviewer_executable_path,
    resolve_reviewer_executable,
    run,
    write_json,
    write_text_atomic,
)
from .workspace import ReviewWorkspace, validate_external_workspace


CODEX_MODELS = ("gpt-5.6-sol", "gpt-5.5")
CODEX_REASONING_EFFORT = "xhigh"
CLAUDE_MODELS = ("claude-sonnet-5", "claude-opus-4-8", "claude-opus-4-7")
# GitHub's supported-models matrix lists all pinned IDs for Copilot CLI. The
# shorter command-reference examples can lag product availability.
COPILOT_MODELS = ("claude-sonnet-5", "claude-opus-4.8", "claude-opus-4.7")
CLAUDE_REASONING_EFFORT = "max"
COPILOT_REASONING_EFFORT = "max"
COPILOT_PERMISSION_HELP_FRAGMENTS = (
    "tool availability is controlled via the --available-tools and --excluded-tools options",
    "these filters decide which tools the model can see",
    "by default, file access is restricted to paths within the current working directory",
    "--disallow-temp-dir flag prevents automatic access",
    "denial rules always take precedence over allow rules, even --allow-all-tools",
)
CLAUDE_SAFE_MODE_HELP_FRAGMENTS = (
    "--safe-mode",
    "all customizations",
    "claude.md",
    "disabled",
    "model selection, built-in tools, and permissions work normally",
    "claude_code_safe_mode=1",
)
CLAUDE_EGRESS_CONSENTS = (
    "explicit-claude-review",
    "double-review",
    "triple-review",
)
COPILOT_EGRESS_CONSENTS = ("double-review", "triple-review")
CODEX_ENV_KEYS = ("CODEX_HOME", "OPENAI_API_KEY")
CLAUDE_ENV_KEYS = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CONFIG_DIR",
)
COPILOT_ENV_KEYS = (
    "COPILOT_GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
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
    "does not have access to this model",
    "don't have access to the model",
    "don't have access to this model",
    "do not have access to the model",
    "do not have access to this model",
    "account has no access to this model",
    "organization has no access to this model",
    "organisation has no access to this model",
    "model access is disabled",
    "model access has been disabled",
    "model is disabled by your organization",
    "model is disabled for your organization",
    "model is not allowed by your organization",
    "model is not enabled for your organization",
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

STRUCTURED_ENTITLEMENT_CODES = (
    "model_access_denied",
    "model_not_enabled",
    "model_not_entitled",
    "model_permission_denied",
)
STRUCTURED_AMBIGUOUS_MODEL_CODES = ("model_not_found", "not_found_error")

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
CODEX_ARG_TRANSPORT_NAME = re.compile(r"codex-arg0[A-Za-z0-9]+")


@dataclass(frozen=True)
class Attempt:
    runtime: str
    requested_model: str
    effective_model: str | None
    requested_effort: str
    effective_effort: str | None
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


def _review_environment(
    *,
    review: ReviewWorkspace,
    passthrough_keys: Iterable[str],
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    review_values = {
        "CODEX_ISOLATED_REVIEW_ROOT": str(review.workspace_root),
        "CODEX_ISOLATED_REVIEW_DIFF_FILE": str(review.diff_file),
        "CODEX_ISOLATED_REVIEW_PROMPT_FILE": str(review.prompt_file),
        "CODEX_ISOLATED_REVIEW_RANGE": f"{review.base_ref}..{review.head_ref}",
    }
    if extra:
        review_values.update(extra)
    return child_environment(
        container_dir=review.container_dir,
        passthrough_keys=passthrough_keys,
        extra=review_values,
    )


def _with_executable_path(
    env: dict[str, str],
    executable: pathlib.Path,
) -> dict[str, str]:
    result = dict(env)
    result["PATH"] = reviewer_executable_path(
        executable,
        base_path=result.get("PATH", ""),
    )
    return result


def _require_claude_safe_mode(
    executable: pathlib.Path,
    env: dict[str, str],
) -> None:
    completed = run(
        (str(executable), "--help"),
        cwd=pathlib.Path(os.path.abspath(os.sep)),
        env=env,
    )
    help_text = " ".join(
        (completed.stdout + b"\n" + completed.stderr)
        .decode("utf-8", errors="replace")
        .lower()
        .split()
    )
    if completed.returncode != 0 or not all(
        fragment in help_text for fragment in CLAUDE_SAFE_MODE_HELP_FRAGMENTS
    ):
        raise ReviewError(
            "Claude Code does not expose verifiable --safe-mode semantics that "
            "disable CLAUDE.md and other project customizations"
        )


def classify_failure(stdout: bytes | str, stderr: bytes | str) -> str:
    def decode(value: bytes | str) -> str:
        return (
            value.decode("utf-8", errors="replace")
            if isinstance(value, bytes)
            else value
        )

    stdout_bytes = stdout.encode() if isinstance(stdout, str) else stdout
    structured_error = _structured_error_text(stdout_bytes).lower()
    message = f"{decode(stderr)}\n{structured_error}".lower()
    if any(fragment in message for fragment in TRANSIENT_FAILURE_FRAGMENTS):
        return "transient"
    if any(fragment in message for fragment in AUTH_FAILURE_FRAGMENTS):
        return "auth"
    if any(fragment in message for fragment in ENTITLEMENT_FAILURE_FRAGMENTS):
        return "entitlement"
    if any(code in structured_error for code in STRUCTURED_ENTITLEMENT_CODES):
        return "entitlement"
    if (
        any(code in structured_error for code in STRUCTURED_AMBIGUOUS_MODEL_CODES)
        and "model" in structured_error
        and any(
            marker in structured_error
            for marker in (
                "access",
                "account",
                "organization",
                "organisation",
                "plan",
                "entitled",
                "available",
            )
        )
    ):
        return "entitlement"
    return "other"


def _normalize_model(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _model_matches(requested: str, effective: str) -> bool:
    requested_normalized = _normalize_model(requested)
    effective_normalized = _normalize_model(effective)
    return effective_normalized == requested_normalized


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


def _error_payload_text(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, dict):
        result: list[str] = []
        for key in (
            "code",
            "type",
            "subtype",
            "status",
            "message",
            "reason",
            "detail",
            "error",
            "errors",
        ):
            if key in value:
                result.extend(_error_payload_text(value[key]))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_error_payload_text(item))
        return result
    return []


def _structured_error_text(stdout: bytes) -> str:
    messages: list[str] = []

    def error_state(value: Any) -> tuple[bool, str]:
        if not isinstance(value, dict):
            return False, ""
        tokens = [
            item.lower()
            for key in ("type", "subtype", "status")
            if isinstance((item := value.get(key)), str)
        ]
        explicit = value.get("is_error") is True or any(
            token == "error"
            or token in {"failed", "failure", "error_during_execution"}
            or token.endswith(".failed")
            or token.endswith(".failure")
            or token.endswith(".error")
            or token.endswith("_error")
            or token.startswith("error_")
            for token in tokens
        )
        return explicit, " ".join(tokens)

    for item in _json_objects(stdout):
        explicit_error, state_text = error_state(item)
        if not explicit_error:
            continue
        messages.append(f"event {state_text or 'explicit error'}")
        for key in ("error", "errors", "message", "reason", "detail", "code"):
            if key in item:
                messages.extend(_error_payload_text(item[key]))
        api_error_status = item.get("api_error_status")
        if isinstance(api_error_status, (int, str)):
            messages.append(f"status {api_error_status}")
    return "\n".join(messages)


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


def _find_model(value: Any, *, requested_model: str | None = None) -> str | None:
    if isinstance(value, dict):
        model_usage = value.get("modelUsage")
        if isinstance(model_usage, dict) and model_usage:
            candidates = [key for key in model_usage if isinstance(key, str) and key]
            if requested_model is not None:
                for candidate in candidates:
                    if _model_matches(requested_model, candidate):
                        return candidate
            if candidates:
                return candidates[-1]
        for key in ("model", "modelName", "model_id", "modelId"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for key in ("data", "metadata", "result", "usage"):
            if key in value:
                found = _find_model(value[key], requested_model=requested_model)
                if found:
                    return found
    if isinstance(value, list):
        for item in reversed(value):
            found = _find_model(item, requested_model=requested_model)
            if found:
                return found
    return None


def _parse_structured_output(
    stdout: bytes, *, requested_model: str | None = None
) -> tuple[str | None, str | None]:
    objects = _json_objects(stdout)
    final_text: str | None = None
    effective_model: str | None = None
    for item in reversed(objects):
        if final_text is None:
            final_text = _find_text(item)
        if effective_model is None:
            effective_model = _find_model(item, requested_model=requested_model)
        if final_text is not None and effective_model is not None:
            break
    if _structured_error_text(stdout).strip():
        final_text = None
    return final_text, effective_model


def _codex_thread_id(stdout: bytes) -> str | None:
    for item in _json_objects(stdout):
        if item.get("type") != "thread.started":
            continue
        thread_id = item.get("thread_id")
        if isinstance(thread_id, str) and thread_id:
            return thread_id
    return None


def _codex_session_metadata(
    stdout: bytes,
    env: dict[str, str],
    *,
    review_root: pathlib.Path,
) -> tuple[str | None, str | None, bool | None]:
    thread_id = _codex_thread_id(stdout)
    if thread_id is None:
        return None, None, None
    codex_home_value = env.get("CODEX_HOME")
    if codex_home_value:
        codex_home = pathlib.Path(codex_home_value).expanduser()
    else:
        home_value = env.get("HOME")
        if not home_value:
            return None, None, None
        codex_home = pathlib.Path(home_value).expanduser() / ".codex"
    sessions_root = codex_home / "sessions"
    try:
        candidates = sorted(
            sessions_root.glob(f"*/*/*/rollout-*-{thread_id}.jsonl"),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
    except OSError:
        return None, None, None
    for candidate in candidates:
        try:
            with candidate.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(item, dict) or item.get("type") != "turn_context":
                        continue
                    payload = item.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    model = payload.get("model")
                    effort = payload.get("effort")
                    return (
                        model if isinstance(model, str) and model else None,
                        effort if isinstance(effort, str) and effort else None,
                        _codex_permissions_match(
                            payload,
                            review_root=review_root,
                            codex_home=codex_home,
                        ),
                    )
        except OSError:
            continue
    return None, None, None


def _codex_permissions_match(
    payload: dict[str, Any],
    *,
    review_root: pathlib.Path,
    codex_home: pathlib.Path | None = None,
) -> bool:
    sandbox_policy = payload.get("sandbox_policy")
    permission_profile = payload.get("permission_profile")
    if (
        payload.get("approval_policy") != "never"
        or not isinstance(sandbox_policy, dict)
        or sandbox_policy.get("type") != "read-only"
        or not isinstance(permission_profile, dict)
        or permission_profile.get("type") != "managed"
        or permission_profile.get("network") != "restricted"
    ):
        return False
    filesystem = permission_profile.get("file_system")
    if (
        not isinstance(filesystem, dict)
        or filesystem.get("type") != "restricted"
        or filesystem.get("glob_scan_max_depth") != 8
    ):
        return False
    entries = filesystem.get("entries")
    if not isinstance(entries, list):
        return False

    expected_paths = {
        str(review_root.resolve()): "read",
        str((review_root / ".git").resolve()): "deny",
        str((review_root / ".codex").resolve()): "deny",
        str((review_root / ".agents").resolve()): "deny",
    }
    expected_globs = {
        str(review_root.resolve() / "*.env"): "deny",
        str(review_root.resolve() / "**/*.env"): "deny",
    }
    remaining_paths = dict(expected_paths)
    remaining_globs = dict(expected_globs)
    minimal_seen = False
    arg_transport_seen = False
    codex_arg_root = (
        (codex_home.expanduser().resolve() / "tmp/arg0")
        if codex_home is not None
        else None
    )
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("access"), str):
            return False
        path_value = entry.get("path")
        if not isinstance(path_value, dict):
            return False
        path_type = path_value.get("type")
        access = entry["access"]
        if path_type == "special":
            value = path_value.get("value")
            if (
                minimal_seen
                or access != "read"
                or value != {"kind": "minimal"}
            ):
                return False
            minimal_seen = True
            continue
        if path_type == "glob_pattern":
            pattern = path_value.get("pattern")
            if not isinstance(pattern, str) or remaining_globs.pop(pattern, None) != access:
                return False
            continue
        if path_type != "path":
            return False
        value = path_value.get("path")
        if not isinstance(value, str):
            return False
        expected_access = remaining_paths.pop(value, None)
        if expected_access == access:
            continue
        candidate = pathlib.Path(value).expanduser()
        if (
            codex_arg_root is not None
            and access == "read"
            and not arg_transport_seen
            and candidate.is_absolute()
            and candidate.parent == codex_arg_root
            and CODEX_ARG_TRANSPORT_NAME.fullmatch(candidate.name) is not None
        ):
            arg_transport_seen = True
            continue
        return False
    return minimal_seen and not remaining_paths and not remaining_globs


def _attempt_paths(
    review: ReviewWorkspace, index: int, runtime: str, model: str
) -> tuple[pathlib.Path, pathlib.Path]:
    safe_model = re.sub(r"[^A-Za-z0-9_.-]+", "-", model)
    prefix = review.container_dir / "attempts" / f"{index:02d}-{runtime}-{safe_model}"
    prefix.parent.mkdir(parents=True, exist_ok=True)
    return pathlib.Path(f"{prefix}.stdout.log"), pathlib.Path(f"{prefix}.stderr.log")


def _append_attempt_diagnostic(path: pathlib.Path, message: str) -> None:
    with path.open("ab") as handle:
        if handle.tell():
            handle.write(b"\n")
        handle.write(message.rstrip().encode("utf-8", errors="replace") + b"\n")


def _record_attempt(
    *,
    review: ReviewWorkspace,
    index: int,
    runtime: str,
    model: str,
    completed: Completed,
    final_text: str | None,
    effective_model: str | None,
    requested_effort: str,
    effective_effort: str | None,
    require_verified_model: bool = False,
    require_verified_effort: bool = False,
) -> Attempt:
    stdout_path, stderr_path = _attempt_paths(review, index, runtime, model)
    if not stdout_path.exists():
        stdout_path.write_bytes(completed.stdout)
    if not stderr_path.exists():
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
        requested_effort=requested_effort,
        effective_effort=effective_effort,
        returncode=completed.returncode,
        category=category,
        final_text=final_text,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )
    if attempt.category == "success" and (
        (require_verified_model and effective_model is None)
        or (require_verified_effort and effective_effort is None)
    ):
        detail = (
            "successful reviewer result did not expose required runtime verification "
            "metadata; refusing to mark the pinned lane successful"
        )
        _append_attempt_diagnostic(stderr_path, detail)
        return replace(
            attempt,
            returncode=65,
            category="runtime-unverified",
            final_text=None,
        )
    if effective_model and not _model_matches(model, effective_model):
        mismatch = (
            f"requested model {model!r} was replaced by {effective_model!r}; "
            "refusing to infer an entitlement failure from silent model substitution"
        )
        _append_attempt_diagnostic(stderr_path, mismatch)
        attempt = replace(
            attempt,
            returncode=65,
            category="model-mismatch",
            final_text=None,
        )
    if effective_effort and effective_effort.lower() != requested_effort.lower():
        mismatch = (
            f"requested effort {requested_effort!r} was replaced by {effective_effort!r}; "
            "refusing to accept the pinned lane"
        )
        _append_attempt_diagnostic(stderr_path, mismatch)
        attempt = replace(
            attempt,
            returncode=65,
            category="effort-mismatch",
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
    executable = resolve_reviewer_executable("codex")
    if executable is None:
        raise FileNotFoundError("codex is not available in a validated executable path")
    env = _with_executable_path(env, executable)
    attempt_final = review.container_dir / "attempts" / f"{index:02d}-codex-final.txt"
    attempt_final.parent.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = _attempt_paths(review, index, "codex", model)
    tool_home = review.container_dir / "tool-home"
    tool_home.mkdir(exist_ok=True)
    shell_values = {
        key: env[key]
        for key in (
            "CODEX_ISOLATED_REVIEW_DIFF_FILE",
            "CODEX_ISOLATED_REVIEW_PROMPT_FILE",
            "CODEX_ISOLATED_REVIEW_RANGE",
            "CODEX_ISOLATED_REVIEW_ROOT",
            "PATH",
            "TEMP",
            "TMP",
            "TMPDIR",
        )
        if key in env
    }
    shell_values["HOME"] = str(tool_home)
    shell_environment = (
        "shell_environment_policy.set={"
        + ",".join(
            f"{key}={json.dumps(value)}" for key, value in sorted(shell_values.items())
        )
        + "}"
    )
    permission_profile = (
        '{"filesystem"={"glob_scan_max_depth"=8,":minimal"="read",'
        '":workspace_roots"={"."="read",".git"="deny",'
        '".codex"="deny",".agents"="deny","*.env"="deny",'
        '"**/*.env"="deny"}'
        "}}"
    )
    prompt = review.prompt_file.read_bytes()
    completed = run(
        (
            str(executable),
            "-c",
            'approval_policy="never"',
            "-c",
            'default_permissions="isolated_review"',
            "-c",
            f"permissions.isolated_review={permission_profile}",
            "-c",
            'shell_environment_policy.inherit="none"',
            "-c",
            shell_environment,
            "-c",
            "project_doc_max_bytes=0",
            "-m",
            model,
            "-c",
            f'model_reasoning_effort="{CODEX_REASONING_EFFORT}"',
            "exec",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--json",
            "-o",
            str(attempt_final),
            "-",
        ),
        cwd=review.workspace_root,
        env=env,
        stdin=prompt,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    final_text = None
    if completed.returncode == 0 and attempt_final.is_file():
        final_text = (
            attempt_final.read_text(encoding="utf-8", errors="replace").strip() or None
        )
    effective_model, effective_effort, permissions_verified = _codex_session_metadata(
        completed.stdout,
        env,
        review_root=review.workspace_root,
    )
    attempt = _record_attempt(
        review=review,
        index=index,
        runtime="codex",
        model=model,
        completed=completed,
        final_text=final_text,
        effective_model=effective_model,
        requested_effort=CODEX_REASONING_EFFORT,
        effective_effort=effective_effort,
        require_verified_model=True,
        require_verified_effort=True,
    )
    if permissions_verified is False or (
        attempt.category == "success" and permissions_verified is None
    ):
        detail = (
            "effective Codex sandbox did not preserve the isolated review permission "
            "profile; refusing to accept a result from a legacy or managed sandbox override"
        )
        _append_attempt_diagnostic(stderr_path, detail)
        return replace(
            attempt,
            returncode=65,
            category="permission-mismatch",
            final_text=None,
        )
    return attempt


def _claude_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
) -> Attempt:
    executable = resolve_reviewer_executable("claude")
    if executable is None:
        raise FileNotFoundError(
            "claude is not available in a validated executable path"
        )
    env = _with_executable_path(env, executable)
    _require_claude_safe_mode(executable, env)
    stdout_path, stderr_path = _attempt_paths(review, index, "claude", model)
    settings = json.dumps(
        {
            "permissions": {
                "deny": [
                    "Read(~/.aws/**)",
                    "Read(~/.claude/**)",
                    "Read(~/.codex/**)",
                    "Read(~/.config/**)",
                    "Read(~/.copilot/**)",
                    "Read(~/.gnupg/**)",
                    "Read(~/.kube/**)",
                    "Read(~/.ssh/**)",
                    "Read(~/.git-credentials)",
                    "Read(~/.netrc)",
                ]
            }
        },
        separators=(",", ":"),
    )
    completed = run(
        (
            str(executable),
            "--print",
            "--model",
            model,
            "--effort",
            CLAUDE_REASONING_EFFORT,
            "--permission-mode",
            "dontAsk",
            "--output-format",
            "json",
            "--no-session-persistence",
            "--safe-mode",
            "--no-chrome",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--mcp-config",
            "{}",
            "--setting-sources",
            "",
            "--settings",
            settings,
            "--tools",
            "Read,Grep,Glob",
            "--allowedTools",
            "Read(./**)",
            "--disallowedTools",
            "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch,Task",
        ),
        cwd=review.workspace_root,
        env=env,
        stdin=review.prompt_file.read_bytes(),
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    final_text, effective_model = _parse_structured_output(
        completed.stdout, requested_model=model
    )
    return _record_attempt(
        review=review,
        index=index,
        runtime="claude",
        model=model,
        completed=completed,
        final_text=final_text if completed.returncode == 0 else None,
        effective_model=effective_model,
        requested_effort=CLAUDE_REASONING_EFFORT,
        effective_effort=None,
        require_verified_model=True,
    )


def _copilot_attempt(
    *,
    review: ReviewWorkspace,
    model: str,
    index: int,
    env: dict[str, str],
) -> Attempt:
    executable = resolve_reviewer_executable("copilot")
    if executable is None:
        raise FileNotFoundError(
            "copilot is not available in a validated executable path"
        )
    env = _with_executable_path(env, executable)
    copilot_home = review.container_dir / "copilot-home"
    try:
        copilot_home.mkdir(mode=0o700, exist_ok=True)
    except OSError as error:
        raise ReviewError(f"cannot create isolated Copilot home: {error}") from error
    if copilot_home.is_symlink() or not copilot_home.is_dir():
        raise ReviewError("isolated Copilot home is not a real directory")
    env = dict(env)
    env["COPILOT_HOME"] = str(copilot_home)
    permission_help = run((str(executable), "help", "permissions"), env=env)
    normalized_permission_help = " ".join(
        (permission_help.stdout + b"\n" + permission_help.stderr)
        .decode("utf-8", errors="replace")
        .lower()
        .split()
    )
    if permission_help.returncode != 0 or any(
        fragment not in normalized_permission_help
        for fragment in COPILOT_PERMISSION_HELP_FRAGMENTS
    ):
        raise ReviewError(
            "Copilot CLI did not expose the required cwd-only path verifier, "
            "temporary-directory denial, and deny-over-allow permission semantics"
        )
    stdout_path, stderr_path = _attempt_paths(review, index, "copilot", model)
    command = [
        str(executable),
        "-C",
        str(review.workspace_root),
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
        "--available-tools=view,glob,grep",
        "--allow-all-tools",
        "--deny-tool=write",
        "--deny-tool=shell",
        "--deny-tool=url",
        "--disallow-temp-dir",
        "--disable-builtin-mcps",
        "--no-bash-env",
        "--no-custom-instructions",
        "--no-experimental",
        "--no-remote",
        "--no-remote-export",
        "--no-color",
        "--no-ask-user",
        "--no-auto-update",
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
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    final_text, effective_model = _parse_structured_output(
        completed.stdout, requested_model=model
    )
    return _record_attempt(
        review=review,
        index=index,
        runtime="copilot",
        model=model,
        completed=completed,
        final_text=final_text if completed.returncode == 0 else None,
        effective_model=effective_model,
        requested_effort=COPILOT_REASONING_EFFORT,
        effective_effort=None,
        require_verified_model=True,
    )


AttemptRunner = Callable[..., Attempt]


def _attempt_summary(attempt: Attempt) -> dict[str, Any]:
    return {
        "runtime": attempt.runtime,
        "requested_model": attempt.requested_model,
        "effective_model": attempt.effective_model,
        "requested_effort": attempt.requested_effort,
        "effective_effort": attempt.effective_effort,
        "returncode": attempt.returncode,
        "category": attempt.category,
        "final_available": bool(attempt.final_text),
        "stdout_path": attempt.stdout_path,
        "stderr_path": attempt.stderr_path,
    }


def _write_attempts(review: ReviewWorkspace, attempts: Iterable[Attempt]) -> None:
    write_json(
        review.container_dir / "attempts.json",
        [_attempt_summary(item) for item in attempts],
    )


def _finish(
    review: ReviewWorkspace, attempts: list[Attempt], final_text: str | None
) -> Outcome:
    _write_attempts(review, attempts)
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
        _write_attempts(review, attempts)
        if attempt.category == "success":
            return "success", attempt.final_text
        if attempt.category != "entitlement":
            return attempt.category, None
    return "entitlement", None


def run_review(
    *,
    review: ReviewWorkspace,
    reviewer: str,
    egress_consent: str | None = None,
) -> Outcome:
    if reviewer not in ("codex", "claude"):
        write_text_atomic(
            review.container_dir / "runner-error.txt", f"unknown reviewer: {reviewer}\n"
        )
        return Outcome(2, None, tuple())

    if reviewer == "claude":
        if egress_consent not in CLAUDE_EGRESS_CONSENTS:
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                "Claude-family review requires an explicit egress-consent reason.\n",
            )
            return Outcome(2, None, tuple())
    elif egress_consent is not None:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "egress-consent is valid only for the Claude-family reviewer.\n",
        )
        return Outcome(2, None, tuple())

    try:
        validate_external_workspace(review)
    except ReviewError as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            f"review egress workspace preflight failed: {error}\n",
        )
        return Outcome(2, None, tuple())

    write_json(
        review.container_dir / "preflight.json",
        {
            "review_range": f"{review.base_ref}..{review.head_ref}",
            "scope": "frozen tracked workspace, diff, and review prompt",
            "status": "sensitive-content and escaping-symlink checks passed",
        },
    )

    if reviewer == "claude":
        write_json(
            review.container_dir / "egress.json",
            {
                "consent": egress_consent,
                "reviewer": "claude-family",
                "review_range": f"{review.base_ref}..{review.head_ref}",
                "included": [
                    "tracked blobs materialized from the frozen head commit",
                    "the generated frozen diff",
                    "the review prompt and result",
                ],
                "excluded": [
                    "credential paths and high-confidence secrets blocked by preflight",
                    "untracked files",
                    "unrelated repositories",
                    "broad workspace or home-directory content",
                ],
                "preflight": "sensitive-content and escaping-symlink checks passed",
            },
        )

    attempts: list[Attempt] = []

    if reviewer == "codex":
        env = _review_environment(
            review=review,
            passthrough_keys=CODEX_ENV_KEYS,
        )
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

    try:
        claude_available = resolve_reviewer_executable("claude") is not None
    except ReviewError as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code executable validation failed; refusing Copilot fallback: "
            f"{error}\n",
        )
        write_json(review.container_dir / "attempts.json", [])
        return Outcome(2, None, tuple(attempts))
    if claude_available:
        claude_env = _review_environment(
            review=review,
            passthrough_keys=CLAUDE_ENV_KEYS,
            extra={"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"},
        )
        try:
            category, final_text = _run_model_chain(
                review=review,
                models=CLAUDE_MODELS,
                runner=_claude_attempt,
                env=claude_env,
                attempts=attempts,
            )
        except FileNotFoundError:
            category = "unavailable"
            final_text = None
        except ReviewError as error:
            write_text_atomic(
                review.container_dir / "runner-error.txt",
                "Claude Code failed executable validation; "
                f"refusing Copilot fallback: {error}\n",
            )
            _write_attempts(review, attempts)
            return Outcome(2, None, tuple(attempts))
        if final_text:
            return _finish(review, attempts, final_text)
        if category not in {"entitlement", "unavailable"}:
            return _finish(review, attempts, None)

    if egress_consent not in COPILOT_EGRESS_CONSENTS:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code was unavailable or lacked model entitlement, but "
            "explicit-claude-review does not authorize GitHub Copilot fallback.\n",
        )
        _write_attempts(review, attempts)
        return Outcome(2, None, tuple(attempts))

    try:
        copilot_available = resolve_reviewer_executable("copilot") is not None
    except ReviewError as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            f"Copilot CLI executable validation failed: {error}\n",
        )
        _write_attempts(review, attempts)
        return Outcome(2, None, tuple(attempts))
    if not copilot_available:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            "Claude Code was unavailable or lacked model entitlement, and Copilot CLI is unavailable.\n",
        )
        return _finish(review, attempts, None)
    copilot_env = _review_environment(
        review=review,
        passthrough_keys=COPILOT_ENV_KEYS,
    )
    try:
        _, final_text = _run_model_chain(
            review=review,
            models=COPILOT_MODELS,
            runner=_copilot_attempt,
            env=copilot_env,
            attempts=attempts,
        )
    except (FileNotFoundError, ReviewError) as error:
        write_text_atomic(
            review.container_dir / "runner-error.txt",
            f"Copilot CLI became unavailable or failed executable validation: {error}\n",
        )
        _write_attempts(review, attempts)
        return Outcome(2, None, tuple(attempts))
    return _finish(review, attempts, final_text)
