from __future__ import annotations

import inspect
import pathlib
import re
import subprocess
import sys
import unittest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by Python 3.10 CI
    import tomli as tomllib


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SKILL_ROOT.parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import claude_linux, providers  # noqa: E402


def _workflow_key_markers(
    indent: str,
    key: str,
    *,
    list_item: bool = False,
) -> tuple[str, ...]:
    prefix = f"{indent}- " if list_item else indent
    return tuple(
        f"{prefix}{spelling}"
        for spelling in (key, f"'{key}'", f'"{key}"')
    )


def _workflow_matching_key_marker(
    line: str,
    indent: str,
    key: str,
    *,
    list_item: bool = False,
) -> str | None:
    for key_prefix in _workflow_key_markers(
        indent,
        key,
        list_item=list_item,
    ):
        if not line.startswith(key_prefix):
            continue
        suffix = line.removeprefix(key_prefix)
        stripped_suffix = suffix.lstrip(" \t")
        if not stripped_suffix.startswith(":"):
            continue
        spacing_length = len(suffix) - len(stripped_suffix)
        return line[: len(key_prefix) + spacing_length + 1]
    return None


def _workflow_strip_yaml_comment(value: str) -> str:
    in_single_quote = False
    in_double_quote = False
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if in_double_quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_double_quote = False
        elif in_single_quote:
            if character == "'":
                if index + 1 < len(value) and value[index + 1] == "'":
                    index += 1
                else:
                    in_single_quote = False
        elif character == '"':
            in_double_quote = True
        elif character == "'":
            in_single_quote = True
        elif character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
        index += 1
    return value.rstrip()


def _workflow_block_scalar_header_indents(
    line: str,
) -> tuple[int, int | None] | None:
    indentation = len(line) - len(line.lstrip())
    candidate = line.lstrip()
    header_indent = indentation
    if candidate.startswith("- "):
        candidate = candidate.removeprefix("- ").lstrip()
        header_indent += 2
    candidate = _workflow_strip_yaml_comment(candidate).strip()
    block_header = r"[|>](?:[1-9][+-]?|[+-][1-9]?|)"
    match = re.fullmatch(rf"(?P<header>{block_header})", candidate)
    if match is not None:
        header_indent = indentation
    key = r'''(?:[A-Za-z_][A-Za-z0-9_-]*|'[^']*'|"[^"\\]*")'''
    if match is None:
        match = re.fullmatch(
            rf"{key}[ \t]*:[ \t]*(?P<header>{block_header})",
            candidate,
        )
    if match is None:
        return None
    indentation_indicator = re.search(r"[1-9]", match.group("header"))
    content_indent = (
        header_indent + int(indentation_indicator.group())
        if indentation_indicator is not None
        else None
    )
    return header_indent, content_indent


def _workflow_inline_quoted_scalar_is_complete(value: str) -> bool:
    quote = value[:1]
    if quote not in ("'", '"'):
        return True

    index = 1
    while index < len(value):
        character = value[index]
        if quote == "'" and character == "'":
            if index + 1 < len(value) and value[index + 1] == "'":
                index += 2
                continue
            trailing = value[index + 1 :]
            return not trailing.strip() or (
                trailing[:1].isspace()
                and trailing.lstrip().startswith("#")
            )
        if quote == '"' and character == "\\":
            index += 2
            continue
        if quote == '"' and character == '"':
            trailing = value[index + 1 :]
            return not trailing.strip() or (
                trailing[:1].isspace()
                and trailing.lstrip().startswith("#")
            )
        index += 1
    return False


def _workflow_line_has_unsupported_quoted_scalar(candidate: str) -> bool:
    key = r'''(?:[A-Za-z_][A-Za-z0-9_-]*|'[^']*'|"[^"\\]*")'''
    mapping = re.fullmatch(
        rf"{key}[ \t]*:[ \t]*(?P<value>.*)",
        candidate,
    )
    value = mapping.group("value") if mapping is not None else candidate
    value = value.lstrip()
    return value[:1] in ("'", '"') and not _workflow_inline_quoted_scalar_is_complete(
        value
    )


def _workflow_has_unsupported_mapping_key_syntax(lines: tuple[str, ...]) -> bool:
    block_header_indent: int | None = None
    block_content_indent: int | None = None
    for line in lines:
        if block_header_indent is not None:
            if not line.strip():
                continue
            indentation = len(line) - len(line.lstrip())
            if block_content_indent is None and indentation > block_header_indent:
                block_content_indent = indentation
                continue
            if block_content_indent is not None and indentation >= block_content_indent:
                continue
            block_header_indent = None
            block_content_indent = None

        candidate = line.lstrip()
        if candidate.startswith("- "):
            candidate = candidate.removeprefix("- ").lstrip()
        if not candidate or candidate.startswith("#"):
            continue
        if candidate == "?" or candidate.startswith("? "):
            return True
        if candidate.startswith(("!", "&", "*")) and ":" in candidate:
            return True
        if _workflow_matching_key_marker(candidate, "", "<<") is not None:
            return True
        if _workflow_line_has_unsupported_quoted_scalar(candidate):
            return True
        if not candidate.startswith('"'):
            scalar_header_indents = _workflow_block_scalar_header_indents(line)
            if scalar_header_indents is not None:
                block_header_indent, block_content_indent = scalar_header_indents
            continue
        escaped = False
        index = 1
        while index < len(candidate):
            character = candidate[index]
            if character == "\\":
                escaped = True
                index += 2
                continue
            if character == '"':
                if escaped and candidate[index + 1 :].lstrip().startswith(":"):
                    return True
                break
            index += 1
        else:
            if escaped:
                return True
        scalar_header_indents = _workflow_block_scalar_header_indents(line)
        if scalar_header_indents is not None:
            block_header_indent, block_content_indent = scalar_header_indents
    return False


def _workflow_job_lines(workflow: str, job_name: str) -> tuple[str, ...]:
    workflow_lines = tuple(workflow.splitlines())
    if workflow.startswith("\ufeff") or _workflow_has_unsupported_mapping_key_syntax(
        workflow_lines
    ):
        return ()

    jobs_indexes: list[int] = []
    for index, line in enumerate(workflow_lines):
        marker = _workflow_matching_key_marker(line, "", "jobs")
        if marker is None:
            continue
        if _workflow_strip_yaml_comment(line.removeprefix(marker).strip()):
            return ()
        jobs_indexes.append(index)
    if len(jobs_indexes) != 1:
        return ()

    jobs_lines: list[str] = []
    for line in workflow_lines[jobs_indexes[0] + 1 :]:
        if line.strip() and not line.lstrip().startswith("#"):
            indentation = len(line) - len(line.lstrip())
            if indentation == 0:
                break
        jobs_lines.append(line)

    job_indexes: list[int] = []
    for index, line in enumerate(jobs_lines):
        marker = _workflow_matching_key_marker(line, "  ", job_name)
        if marker is None:
            continue
        if _workflow_strip_yaml_comment(line.removeprefix(marker).strip()):
            return ()
        job_indexes.append(index)
    if len(job_indexes) != 1:
        return ()

    job_lines: list[str] = []
    for line in jobs_lines[job_indexes[0] + 1 :]:
        ignorable = not line.strip() or line.lstrip().startswith("#")
        if not ignorable:
            indentation = len(line) - len(line.lstrip())
            if indentation <= 2:
                break
        job_lines.append(line)
    return tuple(job_lines)


def _workflow_dependency_scalar(value: str) -> str | None:
    candidate = _workflow_strip_yaml_comment(value).strip()
    if candidate[:1] in ("'", '"'):
        if len(candidate) < 2 or candidate[-1] != candidate[0]:
            return None
        candidate = candidate[1:-1]
    elif candidate[-1:] in ("'", '"'):
        return None
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", candidate) is None:
        return None
    return candidate


def _workflow_inline_sequence_values(value: str) -> tuple[str, ...] | None:
    if not value.startswith("[") or not value.endswith("]"):
        return None
    items = value[1:-1].split(",")
    if items and not items[-1].strip():
        items.pop()
    values: list[str] = []
    for item in items:
        dependency = _workflow_dependency_scalar(item)
        if dependency is None:
            return None
        values.append(dependency)
    return tuple(values) if values else None


def _workflow_sequence_item_value(line: str, indentation: int) -> str | None:
    marker = f"{' ' * indentation}-"
    if line == marker:
        return ""
    if line.startswith(f"{marker} "):
        return line.removeprefix(f"{marker} ")
    return None


def _workflow_has_plain_mapping_key_at_indent(line: str, indentation: int) -> bool:
    if len(line) - len(line.lstrip()) != indentation:
        return False
    candidate = line[indentation:]
    key = r'''(?:[A-Za-z_][A-Za-z0-9_-]*|'[^']*'|"[^"\\]*")'''
    return re.match(rf"{key}[ \t]*:", candidate) is not None


def _workflow_sequence_values(
    lines: tuple[str, ...],
    key_indent: int,
) -> tuple[str, ...] | None:
    values: list[str] = []
    sequence_indent: int | None = None
    index = 0

    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue
        indentation = len(line) - len(line.lstrip())
        if sequence_indent is None:
            if indentation < key_indent:
                return None
            item_value = _workflow_sequence_item_value(line, indentation)
            if item_value is None:
                return None
            sequence_indent = indentation
        else:
            if indentation < sequence_indent:
                if indentation < key_indent or _workflow_has_plain_mapping_key_at_indent(
                    line,
                    key_indent,
                ):
                    break
                return None
            if indentation > sequence_indent:
                return None
            item_value = _workflow_sequence_item_value(line, sequence_indent)
            if item_value is None:
                if sequence_indent == key_indent and _workflow_has_plain_mapping_key_at_indent(
                    line,
                    key_indent,
                ):
                    break
                return None

        candidate = _workflow_strip_yaml_comment(item_value).strip()
        dependency = _workflow_dependency_scalar(candidate)
        if dependency is not None:
            values.append(dependency)
            index += 1
            continue
        if candidate:
            return None

        nested_index = index + 1
        while nested_index < len(lines) and (
            not lines[nested_index].strip()
            or lines[nested_index].lstrip().startswith("#")
        ):
            nested_index += 1
        if nested_index >= len(lines):
            return None
        nested_line = lines[nested_index]
        nested_indent = len(nested_line) - len(nested_line.lstrip())
        if nested_indent <= sequence_indent:
            return None
        dependency = _workflow_dependency_scalar(nested_line.strip())
        if dependency is None:
            return None
        values.append(dependency)
        index = nested_index + 1

    return tuple(values) if values else None


def _workflow_job_needs(workflow: str, job_name: str) -> tuple[str, ...]:
    job_lines = _workflow_job_lines(workflow, job_name)

    for index, line in enumerate(job_lines):
        marker = _workflow_matching_key_marker(line, "    ", "needs")
        if marker is None:
            continue
        scalar_or_inline = _workflow_strip_yaml_comment(
            line.removeprefix(marker).strip()
        )
        if scalar_or_inline:
            if scalar_or_inline.startswith("["):
                return _workflow_inline_sequence_values(scalar_or_inline) or ()
            dependency = _workflow_dependency_scalar(scalar_or_inline)
            return (dependency,) if dependency is not None else ()
        return (
            _workflow_sequence_values(tuple(job_lines[index + 1 :]), 4) or ()
        )
    return ()


def _workflow_env_bindings(
    lines: tuple[str, ...],
    env_indent: str,
) -> dict[str, str] | None:
    variable_indent = f"{env_indent}  "
    bindings: dict[str, str] = {}
    in_env = False
    expression_prefix = "${{ needs."
    expression_suffix = ".result }}"

    for line in lines:
        marker = _workflow_matching_key_marker(line, env_indent, "env")
        step_item_marker = (
            _workflow_matching_key_marker(
                line,
                env_indent[:-2],
                "env",
                list_item=True,
            )
            if env_indent
            else None
        )
        if marker is not None or step_item_marker is not None:
            in_env = True
            continue
        if not in_env:
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation <= len(env_indent):
            break
        if indentation != len(variable_indent):
            return None
        binding = line.removeprefix(variable_indent)
        match = re.fullmatch(
            r"(?P<variable>[A-Za-z_][A-Za-z0-9_]*_RESULT)"
            r"[ \t]*:[ \t]+(?P<expression>.+)",
            binding,
        )
        if match is None:
            return None
        variable = match.group("variable")
        expression = match.group("expression").strip()
        if variable in bindings:
            return None
        if not (
            expression.startswith(expression_prefix)
            and expression.endswith(expression_suffix)
        ):
            return None
        dependency = expression[len(expression_prefix) : -len(expression_suffix)]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", dependency) is None:
            return None
        bindings[variable] = dependency
    return bindings


def _workflow_scope_has_key(
    lines: tuple[str, ...],
    indent: str,
    key: str,
) -> bool:
    return any(
        _workflow_matching_key_marker(line, indent, key) is not None
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    )


def _workflow_job_steps(job_lines: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    steps_indexes: list[int] = []
    for index, line in enumerate(job_lines):
        marker = _workflow_matching_key_marker(line, "    ", "steps")
        if marker is None:
            continue
        if _workflow_strip_yaml_comment(line.removeprefix(marker).strip()):
            return ()
        steps_indexes.append(index)
    if len(steps_indexes) != 1:
        return ()
    steps_index = steps_indexes[0]

    steps: list[list[str]] = []
    current_step: list[str] | None = None
    for line in job_lines[steps_index + 1 :]:
        indentation = len(line) - len(line.lstrip())
        ignorable = not line.strip() or line.lstrip().startswith("#")
        if not ignorable and indentation <= 4:
            break
        if line == "      -" or line.startswith("      - "):
            current_step = [line]
            steps.append(current_step)
        elif current_step is not None:
            current_step.append(line)
    return tuple(tuple(step) for step in steps)


def _workflow_job_top_level_values(
    job_lines: tuple[str, ...], key: str
) -> tuple[str, ...]:
    values: list[str] = []
    for line in job_lines:
        marker = _workflow_matching_key_marker(line, "    ", key)
        if marker is not None:
            values.append(line.removeprefix(marker).strip())
    return tuple(values)


def _workflow_continue_on_error_is_disabled(values: tuple[str, ...]) -> bool:
    normalized = tuple(
        _workflow_strip_yaml_comment(value).strip() for value in values
    )
    return normalized in ((), ("false",))


def _workflow_job_propagates_failure(workflow: str, job_name: str) -> bool:
    job_lines = _workflow_job_lines(workflow, job_name)
    if not job_lines:
        return False
    return _workflow_continue_on_error_is_disabled(
        _workflow_job_top_level_values(job_lines, "continue-on-error")
    )


def _workflow_run_defaults_block_is_unsafe(
    lines: tuple[str, ...],
    run_index: int,
    run_indent: int,
) -> bool:
    child_indent: int | None = None
    working_directory_seen = False

    for line in lines[run_index + 1 :]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation <= run_indent:
            break
        if child_indent is None:
            child_indent = indentation
        if indentation != child_indent:
            return True
        marker = _workflow_matching_key_marker(
            line,
            " " * child_indent,
            "working-directory",
        )
        if marker is None or working_directory_seen:
            return True
        value = _workflow_strip_yaml_comment(line.removeprefix(marker).strip())
        if not value or value.startswith(("*", "&", "!", "{", "[", "|", ">")):
            return True
        working_directory_seen = True

    return not working_directory_seen


def _workflow_scope_has_unsafe_run_defaults(
    lines: tuple[str, ...],
    defaults_indent: str,
) -> bool:
    for index, line in enumerate(lines):
        defaults_marker = _workflow_matching_key_marker(
            line,
            defaults_indent,
            "defaults",
        )
        if defaults_marker is None:
            continue
        if _workflow_strip_yaml_comment(
            line.removeprefix(defaults_marker).strip()
        ):
            return True

        run_seen = False
        for nested_index, nested_line in enumerate(
            lines[index + 1 :],
            start=index + 1,
        ):
            stripped = nested_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indentation = len(nested_line) - len(nested_line.lstrip())
            if indentation <= len(defaults_indent):
                break
            nested_indent = " " * indentation
            run_marker = _workflow_matching_key_marker(
                nested_line,
                nested_indent,
                "run",
            )
            if run_marker is not None:
                if run_seen:
                    return True
                if _workflow_strip_yaml_comment(
                    nested_line.removeprefix(run_marker).strip()
                ):
                    return True
                if _workflow_run_defaults_block_is_unsafe(
                    lines,
                    nested_index,
                    indentation,
                ):
                    return True
                run_seen = True
    return False


def _workflow_step_top_level_values(
    step: tuple[str, ...], key: str
) -> tuple[str, ...]:
    values: list[str] = []
    for line in step:
        marker = _workflow_matching_key_marker(
            line,
            "      ",
            key,
            list_item=True,
        ) or _workflow_matching_key_marker(line, "        ", key)
        if marker is not None:
            values.append(line.removeprefix(marker).strip())
    return tuple(values)


def _workflow_step_run_body(step: tuple[str, ...]) -> str:
    for index, line in enumerate(step):
        marker = _workflow_matching_key_marker(
            line,
            "      ",
            "run",
            list_item=True,
        ) or _workflow_matching_key_marker(line, "        ", "run")
        if marker is None:
            continue
        header = _workflow_strip_yaml_comment(line.removeprefix(marker)).strip()
        scalar_header_indents = _workflow_block_scalar_header_indents(line)
        if scalar_header_indents is None:
            if header[:1] in "|>":
                return ""
            run_indent = len(line) - len(line.lstrip())
            for continuation_line in step[index + 1 :]:
                if (
                    not continuation_line.strip()
                    or continuation_line.lstrip().startswith("#")
                ):
                    continue
                continuation_indent = len(continuation_line) - len(
                    continuation_line.lstrip()
                )
                if continuation_indent <= run_indent:
                    break
                return ""
            return header
        if header.startswith(">"):
            return ""
        body: list[str] = []
        _, body_indent = scalar_header_indents
        for body_line in step[index + 1 :]:
            indentation = len(body_line) - len(body_line.lstrip())
            if body_line.strip():
                if body_indent is None:
                    body_indent = indentation
                elif indentation < body_indent:
                    break
            body.append(body_line.strip())
        return "\n".join(body)
    return ""


def _workflow_job_success_guards(workflow: str, job_name: str) -> tuple[str, ...]:
    if workflow.startswith("\ufeff"):
        return ()
    job_lines = _workflow_job_lines(workflow, job_name)
    workflow_lines = tuple(workflow.splitlines())
    if _workflow_has_unsupported_mapping_key_syntax(workflow_lines):
        return ()
    if _workflow_job_top_level_values(job_lines, "runs-on") != ("ubuntu-latest",):
        return ()
    if any(
        _workflow_scope_has_key(job_lines, "    ", key)
        for key in ("container", "services", "strategy")
    ):
        return ()
    if _workflow_scope_has_key(
        workflow_lines,
        "",
        "env",
    ) or _workflow_scope_has_key(job_lines, "    ", "env"):
        return ()
    if _workflow_scope_has_unsafe_run_defaults(
        workflow_lines, ""
    ) or _workflow_scope_has_unsafe_run_defaults(job_lines, "    "):
        return ()
    job_continue_on_error = _workflow_job_top_level_values(
        job_lines, "continue-on-error"
    )
    if not _workflow_continue_on_error_is_disabled(job_continue_on_error):
        return ()
    guarded_dependencies: list[str] = []
    steps = _workflow_job_steps(job_lines)
    if not steps:
        return ()
    for step in steps:
        if _workflow_step_top_level_values(step, "if"):
            return ()
        step_continue_on_error = _workflow_step_top_level_values(
            step, "continue-on-error"
        )
        if not _workflow_continue_on_error_is_disabled(step_continue_on_error):
            return ()
        if _workflow_step_top_level_values(step, "shell"):
            return ()
        if _workflow_step_top_level_values(step, "uses"):
            return ()
        if _workflow_step_top_level_values(step, "env") != ("",):
            return ()
        if len(_workflow_step_top_level_values(step, "run")) != 1:
            return ()
        step_bindings = _workflow_env_bindings(step, "        ")
        if not step_bindings:
            return ()
        run_body = _workflow_step_run_body(step)
        commands = tuple(line.strip() for line in run_body.splitlines() if line.strip())
        if not commands:
            return ()
        step_dependencies: list[str] = []
        for command in commands:
            dependency = next(
                (
                    candidate
                    for variable, candidate in step_bindings.items()
                    if candidate is not None
                    and command == f'test "${variable}" = "success"'
                ),
                None,
            )
            if dependency is None:
                return ()
            step_dependencies.append(dependency)
        for dependency in step_dependencies:
            if dependency not in guarded_dependencies:
                guarded_dependencies.append(dependency)
    return tuple(guarded_dependencies)


class RepositoryContractTest(unittest.TestCase):
    def test_only_canonical_review_skill_entrypoint_remains(self) -> None:
        self.assertTrue((SKILL_ROOT / "SKILL.md").is_file())
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("installs a readonly Git shim", skill)
        for relative in (
            "skills/external-review-playbook/SKILL.md",
            "skills/pr-readiness-review-workflow/SKILL.md",
            "skills/copilot-review-playbook/SKILL.md",
            "skills/review-orchestration-playbook/scripts/isolated_external_review",
            "skills/review-orchestration-playbook/scripts/isolated_copilot_review",
            "skills/review-orchestration-playbook/scripts/git_readonly_shim",
        ):
            self.assertFalse((REPO_ROOT / relative).exists(), relative)

    def test_healthy_bounded_wait_is_not_task_completion(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("only an intermediate poll, not task completion", skill)
        self.assertIn("Keep the parent task active", skill)
        self.assertIn("do not end the task merely because one wait window expires", skill)

    def test_models_are_pinned_in_runtime_and_clean_context_agent(self) -> None:
        self.assertEqual(providers.CODEX_MODELS, ("gpt-5.6-sol", "gpt-5.5"))
        self.assertEqual(providers.CODEX_REASONING_EFFORT, "xhigh")
        self.assertEqual(
            providers.CLAUDE_MODELS,
            ("claude-opus-4-8", "claude-opus-4-7"),
        )
        self.assertEqual(
            providers.COPILOT_MODELS,
            ("claude-opus-4.8", "claude-opus-4.7"),
        )
        for candidate in (
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/helper-contract.md",
        ):
            self.assertNotIn(
                "claude-sonnet-5",
                candidate.read_text(encoding="utf-8"),
                str(candidate),
            )
        with (REPO_ROOT / "agents/reviewer.toml").open("rb") as handle:
            reviewer = tomllib.load(handle)
        self.assertEqual(reviewer["model"], "gpt-5.6-sol")
        self.assertEqual(reviewer["model_reasoning_effort"], "xhigh")

    def test_claude_policy_defaults_to_local_login_in_safe_mode(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("ordinary local Claude login by default", skill)
        self.assertIn("runs in safe mode", helper_contract)
        self.assertIn(
            "hardening-compatible `default` permission mode",
            helper_contract,
        )
        self.assertIn(
            "helper-owned outer sandbox",
            helper_contract,
        )
        self.assertNotIn("safe mode with `dontAsk` permissions", helper_contract)
        self.assertIn("per-version signed manifest", helper_contract)
        self.assertIn("manifest checksum", helper_contract)
        self.assertIn("downloads.claude.ai", helper_contract)
        self.assertIn("deny-by-default Seatbelt profile", helper_contract)
        self.assertIn("current-account Keychain item", helper_contract)
        self.assertIn("helper-controlled proxy", helper_contract)
        self.assertIn(">=2.1.187,<3.0.0", helper_contract)
        self.assertIn("Linux and WSL2", helper_contract)
        self.assertNotIn("requires `ANTHROPIC_API_KEY`", skill)

    def test_claude_oauth_freshness_is_per_model_attempt(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        runtime_trust = (
            SKILL_ROOT / "references/claude-runtime-trust.md"
        ).read_text(encoding="utf-8")

        self.assertEqual(providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS, 1800.0)
        self.assertEqual(providers.CLAUDE_AUTH_EXPIRY_MARGIN_SECONDS, 120.0)
        self.assertEqual(
            providers.CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS,
            1920.0,
        )
        self.assertEqual(
            claude_linux.DEFAULT_CREDENTIAL_VALIDITY_SECONDS,
            providers.CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS,
        )
        self.assertNotIn(
            "attempt_count",
            inspect.signature(
                providers._validate_fresh_claude_keychain_credential
            ).parameters,
        )
        attempt_source = inspect.getsource(providers._claude_attempt)
        warmup_source = inspect.getsource(providers._warm_claude_local_login)
        run_review_source = inspect.getsource(providers.run_review)
        linux_runtime_source = inspect.getsource(
            providers._claude_linux_review_runtime
        )
        self.assertIn("_warm_claude_local_login", attempt_source)
        self.assertIn("_prepare_claude_tls_environment", attempt_source)
        self.assertIn("ClaudeKeychainBrokerUnavailable", attempt_source)
        self.assertEqual(
            attempt_source.count("ClaudeLoopbackUnavailable"),
            2,
        )
        self.assertIn('"failure_class": "credential-read"', attempt_source)
        self.assertEqual(
            warmup_source.count(
                "_require_fresh_claude_keychain_credential_for_auth_preflight"
            ),
            2,
        )
        self.assertIn(
            "isinstance(credential_error, ClaudeKeychainBrokerUnavailable)",
            warmup_source,
        )
        self.assertIn("ClaudeAuthWarmupEntitlement", attempt_source)
        self.assertIn("require_verified_model=True", attempt_source)
        self.assertIn("CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS", linux_runtime_source)
        self.assertNotIn("_warm_claude_local_login", run_review_source)
        self.assertNotIn("_prepare_claude_tls_environment", run_review_source)
        self.assertEqual(
            run_review_source.count("ClaudeKeychainBrokerUnavailable"),
            2,
        )
        self.assertNotIn("_require_fresh_claude_linux_credential", run_review_source)

        self.assertIn("current model attempt", skill)
        self.assertIn(
            "Local-login credential freshness is an attempt-boundary property",
            helper_contract,
        )
        self.assertIn(
            "complete 30-minute timeout plus the 2-minute safety margin",
            helper_contract,
        )
        self.assertIn("current attempt's model", helper_contract)
        self.assertIn("Every later Opus attempt repeats", helper_contract)
        self.assertIn("API_KEY` skips local-login warmup and staging", helper_contract)
        self.assertIn("returns exit `75`; it never authorizes Copilot", helper_contract)
        self.assertIn(
            "either the initial or post-warmup credential freshness read",
            helper_contract,
        )
        self.assertIn(
            "attempt-local restricted Keychain broker failure",
            helper_contract,
        )
        self.assertIn(
            "A structured transient warmup remains inconclusive",
            helper_contract,
        )
        self.assertIn(
            "credential-read timeout, output-limit, drain, or process-leak",
            helper_contract,
        )
        self.assertIn(
            "only with `double-review` or `triple-review` consent",
            helper_contract,
        )
        self.assertIn("At every model-attempt boundary", runtime_trust)
        self.assertIn("authentication-preflight-inconclusive", runtime_trust)
        self.assertIn("authentication-preflight-entitlement", runtime_trust)
        self.assertIn("authentication-preflight-unavailable", runtime_trust)
        self.assertIn(
            "while the model whose inconclusive authentication gate failed is not",
            runtime_trust,
        )
        self.assertIn(
            "exact-model-verified entitlement denial",
            helper_contract,
        )
        self.assertIn(
            "with no final text and without claiming that the final broker",
            helper_contract,
        )
        self.assertIn("explicitly in an error state", helper_contract)
        self.assertIn(
            "entitlement-shaped stderr is not fallback evidence",
            helper_contract,
        )
        self.assertIn("overwrites any earlier entitlement model", helper_contract)
        self.assertIn("full stdout/stderr is retained", helper_contract)
        self.assertIn(
            "authentication failure remains unavailable",
            helper_contract,
        )
        self.assertIn(
            "missing or mismatched model metadata stops the",
            runtime_trust,
        )

    def test_claude_linux_file_tools_are_workspace_only_across_supported_versions(
        self,
    ) -> None:
        self.assertEqual(claude_linux.CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS, "Read")
        self.assertEqual(
            claude_linux.CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS,
            "Read(./**)",
        )
        self.assertEqual(
            claude_linux.CLAUDE_LINUX_REVIEW_PERMISSION_MODE,
            "dontAsk",
        )
        cli_denies = set(
            claude_linux.CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS.split(",")
        )
        self.assertTrue({"Grep", "Glob"}.issubset(cli_denies))
        self.assertIn(
            "Read(//config/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )
        self.assertIn(
            "Read(//proc/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )
        self.assertNotIn(
            "Read(/config/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )

    def test_ci_targets_only_the_canonical_runtime_and_tests(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("review-orchestration-playbook/tests", workflow)
        self.assertNotIn("external-review-playbook", workflow)
        self.assertNotIn("copilot-review-playbook", workflow)

    def test_ci_preserves_the_required_test_status_context(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("\n  platform_tests:\n", workflow)
        self.assertIn("name: platform-tests (${{ matrix.os }})", workflow)
        self.assertIn("\n  test:\n", workflow)
        self.assertIn("\n    name: test\n", workflow)
        test_job_lines = _workflow_job_lines(workflow, "test")
        self.assertEqual(
            _workflow_job_top_level_values(test_job_lines, "if"),
            ("${{ always() }}",),
        )
        dependencies = _workflow_job_needs(workflow, "test")
        self.assertIn("platform_tests", dependencies)
        self.assertEqual(
            set(_workflow_job_success_guards(workflow, "test")),
            set(dependencies),
        )
        for dependency in dependencies:
            self.assertTrue(
                _workflow_job_propagates_failure(workflow, dependency),
                dependency,
            )
        self.assertIn(
            "PLATFORM_TESTS_RESULT: ${{ needs.platform_tests.result }}",
            workflow,
        )
        self.assertIn(
            'test "$PLATFORM_TESTS_RESULT" = "success"',
            workflow,
        )

    def test_ci_dependency_parser_scopes_needs_to_the_selected_job(self) -> None:
        def guarded_needs(*needs_lines: str) -> str:
            return (
                "jobs:\n"
                "  test:\n"
                "    needs:\n"
                + "".join(f"{line}\n" for line in needs_lines)
                + "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          COMPATIBILITY_RESULT: ${{ needs.compatibility_tests.result }}\n"
                "          PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
                "        run: |\n"
                '          test "$COMPATIBILITY_RESULT" = "success"\n'
                '          test "$PLATFORM_RESULT" = "success"\n'
            )

        scalar = "jobs:\n  test:\n    needs: 'platform_tests'\n    runs-on: ubuntu-latest\n"
        scalar_with_comment = (
            "jobs:\n"
            "  test:\n"
            "    needs: platform_tests # Required status dependency.\n"
        )
        list_form = (
            "jobs:\n"
            "  test:\n"
            "    needs:\n"
            "      - compatibility_tests\n"
            "      # Comments do not end a YAML block list.\n"
            "\n"
            '      - "platform_tests" # Required status dependency.\n'
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - env:\n"
            "          COMPATIBILITY_RESULT: ${{ needs.compatibility_tests.result }}\n"
            "          PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            "        run: |\n"
            '          test "$COMPATIBILITY_RESULT" = "success"\n'
            '          test "$PLATFORM_RESULT" = "success"\n'
        )
        inline_list = (
            "jobs:\n"
            "  test:\n"
            "    needs: [compatibility_tests, 'platform_tests']\n"
            "    runs-on: ubuntu-latest\n"
        )
        inline_list_with_comment = (
            "jobs:\n"
            "  test:\n"
            "    needs: [compatibility_tests, 'platform_tests'] # Required jobs.\n"
        )
        inline_list_with_trailing_comma = (
            "jobs:\n"
            "  test:\n"
            "    needs: [compatibility_tests, 'platform_tests',] # Required jobs.\n"
        )
        malformed_inline_lists = (
            "jobs:\n  test:\n    needs: [platform_tests,,]\n",
            "jobs:\n  test:\n    needs: [,]\n",
            "jobs:\n  test:\n    needs: [platform_tests, ,]\n",
            "jobs:\n  test:\n    needs: [ ]\n",
        )
        quoted_block_header = (
            "jobs:\n"
            "  test:\n"
            '    "needs" : # Required jobs.\n'
            "      - compatibility_tests\n"
            "      - platform_tests # Required status dependency.\n"
        )
        indentless_block_list = (
            "jobs:\n"
            "  test:\n"
            "    needs:\n"
            "    - compatibility_tests\n"
            "    # Comments do not end an indentless YAML block list.\n"
            "\n"
            "    - platform_tests # Required status dependency.\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - env:\n"
            "          COMPATIBILITY_RESULT: ${{ needs.compatibility_tests.result }}\n"
            "          PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            "        run: |\n"
            '          test "$COMPATIBILITY_RESULT" = "success"\n'
            '          test "$PLATFORM_RESULT" = "success"\n'
        )
        bare_dash_first = guarded_needs(
            "      - # The scalar follows on the next physical line.",
            "        # Comments do not create an empty sequence item.",
            "        compatibility_tests",
            "      - platform_tests",
        )
        bare_dash_middle = guarded_needs(
            "      - compatibility_tests",
            "      -",
            '        "platform_tests"',
        )
        indentless_bare_dash = guarded_needs(
            "    -",
            "      compatibility_tests",
            "    - platform_tests",
        )
        incomplete_bare_dash = guarded_needs(
            "      - compatibility_tests",
            "      -",
        )
        alias_after_prefix = (
            "name: &platform_dependency platform_tests\n"
            + guarded_needs(
                "      - compatibility_tests",
                "      - *platform_dependency",
            )
        )
        inline_alias_after_prefix = (
            "name: &platform_dependency platform_tests\n"
            "jobs:\n"
            "  test:\n"
            "    needs: [compatibility_tests, *platform_dependency]\n"
        )
        unsupported_sequence_nodes = (
            guarded_needs(
                "      - compatibility_tests",
                "      - !!str platform_tests",
            ),
            guarded_needs(
                "      - compatibility_tests",
                "      - [platform_tests]",
            ),
            guarded_needs(
                "      - compatibility_tests",
                "      - job: platform_tests",
            ),
            guarded_needs(
                "      - compatibility_tests",
                "      - |-",
                "        platform_tests",
            ),
        )
        other_job_only = (
            "jobs:\n"
            "  platform_gate:\n"
            "    needs:\n"
            "      - platform_tests\n"
            "  test:\n"
            "    needs: compatibility_tests\n"
        )
        split_step_guard = (
            "jobs:\n"
            "  test:\n"
            "    needs: platform_tests\n"
            "    steps:\n"
            "      - name: Bind result\n"
            "        env:\n"
            "          PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            "        run: echo bound\n"
            "      - name: Check result\n"
            "        run: test \"$PLATFORM_RESULT\" = \"success\"\n"
        )
        job_env_guard = (
            "jobs:\n"
            "  test:\n"
            "    needs: platform_tests\n"
            "    env:\n"
            "      PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            "    steps:\n"
            "      - name: Forge a later job environment value\n"
            '        run: echo "PLATFORM_RESULT=success" >> "$GITHUB_ENV"\n'
            "      - name: Check result\n"
            "        run: test \"$PLATFORM_RESULT\" = \"success\"\n"
        )
        shadowed_job_env_guard = (
            "jobs:\n"
            "  test:\n"
            "    needs: platform_tests\n"
            "    env:\n"
            "      PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            "    steps:\n"
            "      - name: Check a shadowed result\n"
            "        env:\n"
            "          PLATFORM_RESULT: success\n"
            "        run: test \"$PLATFORM_RESULT\" = \"success\"\n"
        )
        name_only_guard = (
            "jobs:\n"
            "  test:\n"
            "    needs: platform_tests\n"
            "    steps:\n"
            "      - name: test \"$PLATFORM_RESULT\" = \"success\"\n"
            "        env:\n"
            "          PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            "        run: echo unchecked\n"
        )
        inline_block_run_guard = (
            "jobs:\n"
            "  test:\n"
            "    needs: platform_tests\n"
            "    env:\n"
            "      PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            "    steps:\n"
            "      - run: |\n"
            "          test \"$PLATFORM_RESULT\" = \"success\"\n"
        )
        other_job_always = (
            "jobs:\n"
            "  platform_gate:\n"
            "    if: ${{ always() }}\n"
            "  test:\n"
            "    needs: platform_tests\n"
        )
        poisoned_step_environment = (
            "jobs:\n"
            "  test:\n"
            "    needs: platform_tests\n"
            "    steps:\n"
            "      - name: Poison later default-shell steps\n"
            "        run: |\n"
            '          echo "BASH_ENV=$RUNNER_TEMP/guard-bypass" >> "$GITHUB_ENV"\n'
            '          echo "test() { return 0; }" > "$RUNNER_TEMP/guard-bypass"\n'
            "      - name: Check result\n"
            "        env:\n"
            "          PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            '        run: test "$PLATFORM_RESULT" = "success"\n'
        )
        root_scalar_job_decoy = (
            "name: |\n"
            "  test:\n"
            "    needs: platform_tests\n"
            "    runs-on: ubuntu-latest\n"
            "on: push\n"
            "jobs:\n"
            "  compatibility_tests:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: true\n"
            "  test:\n"
            "    needs: compatibility_tests\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo unchecked\n"
        )

        self.assertEqual(_workflow_job_needs(scalar, "test"), ("platform_tests",))
        self.assertEqual(
            _workflow_job_needs(scalar_with_comment, "test"),
            ("platform_tests",),
        )
        self.assertEqual(
            _workflow_job_needs(list_form, "test"),
            ("compatibility_tests", "platform_tests"),
        )
        self.assertEqual(
            _workflow_job_needs(inline_list, "test"),
            ("compatibility_tests", "platform_tests"),
        )
        self.assertEqual(
            _workflow_job_needs(inline_list_with_comment, "test"),
            ("compatibility_tests", "platform_tests"),
        )
        self.assertEqual(
            _workflow_job_needs(inline_list_with_trailing_comma, "test"),
            ("compatibility_tests", "platform_tests"),
        )
        for workflow in malformed_inline_lists:
            self.assertEqual(_workflow_job_needs(workflow, "test"), ())
        self.assertEqual(
            _workflow_job_needs(quoted_block_header, "test"),
            ("compatibility_tests", "platform_tests"),
        )
        self.assertEqual(
            _workflow_job_needs(indentless_block_list, "test"),
            ("compatibility_tests", "platform_tests"),
        )
        for workflow in (bare_dash_first, bare_dash_middle, indentless_bare_dash):
            self.assertEqual(
                _workflow_job_needs(workflow, "test"),
                ("compatibility_tests", "platform_tests"),
            )
            self.assertEqual(
                _workflow_job_success_guards(workflow, "test"),
                ("compatibility_tests", "platform_tests"),
            )
        for workflow in (
            incomplete_bare_dash,
            alias_after_prefix,
            inline_alias_after_prefix,
            *unsupported_sequence_nodes,
        ):
            self.assertEqual(_workflow_job_needs(workflow, "test"), ())
        self.assertEqual(
            _workflow_job_needs(other_job_only, "test"),
            ("compatibility_tests",),
        )
        self.assertEqual(
            _workflow_job_success_guards(list_form, "test"),
            ("compatibility_tests", "platform_tests"),
        )
        self.assertEqual(
            _workflow_job_success_guards(indentless_block_list, "test"),
            ("compatibility_tests", "platform_tests"),
        )
        self.assertEqual(_workflow_job_success_guards(split_step_guard, "test"), ())
        self.assertEqual(_workflow_job_success_guards(job_env_guard, "test"), ())
        self.assertEqual(
            _workflow_job_success_guards(shadowed_job_env_guard, "test"),
            (),
        )
        self.assertEqual(_workflow_job_success_guards(name_only_guard, "test"), ())
        self.assertEqual(
            _workflow_job_success_guards(inline_block_run_guard, "test"), ()
        )
        self.assertEqual(
            _workflow_job_top_level_values(
                _workflow_job_lines(other_job_always, "test"),
                "if",
            ),
            (),
        )
        self.assertEqual(
            _workflow_job_success_guards(poisoned_step_environment, "test"),
            (),
        )
        self.assertEqual(
            _workflow_job_needs(root_scalar_job_decoy, "test"),
            ("compatibility_tests",),
        )
        self.assertEqual(
            _workflow_job_success_guards(root_scalar_job_decoy, "test"),
            (),
        )

    def test_ci_direct_dependency_jobs_propagate_failures(self) -> None:
        def dependency_workflow(*job_properties: str) -> str:
            return (
                "jobs:\n"
                "  platform_tests:\n"
                "    runs-on: ubuntu-latest\n"
                + "".join(f"    {property_line}\n" for property_line in job_properties)
                + "    steps:\n"
                "      - run: true\n"
            )

        safe_workflows = (
            dependency_workflow(),
            dependency_workflow("continue-on-error: false"),
            dependency_workflow(
                "'continue-on-error': false # Failures remain visible."
            ),
        )
        for workflow in safe_workflows:
            self.assertTrue(
                _workflow_job_propagates_failure(workflow, "platform_tests")
            )

        unsafe_workflows = {
            "true": dependency_workflow("continue-on-error: true"),
            "expression": dependency_workflow(
                "continue-on-error: ${{ matrix.experimental }}"
            ),
            "quoted-false": dependency_workflow("continue-on-error: 'false'"),
            "empty": dependency_workflow("continue-on-error:"),
            "tagged": dependency_workflow("continue-on-error: !!bool false"),
            "anchored": dependency_workflow("continue-on-error: &tolerance false"),
            "aliased": dependency_workflow(
                "tolerance: &tolerance false",
                "continue-on-error: *tolerance",
            ),
            "flow": dependency_workflow("continue-on-error: [false]"),
            "block": dependency_workflow(
                "continue-on-error: |-",
                "  false",
            ),
            "duplicate": dependency_workflow(
                "continue-on-error: false",
                "'continue-on-error': false",
            ),
            "multiline-quoted-decoy": dependency_workflow(
                "name: 'decoy",
                "continue-on-error: false",
                "'",
                "continue-on-error: true",
            ),
        }
        for name, workflow in unsafe_workflows.items():
            with self.subTest(name=name):
                self.assertFalse(
                    _workflow_job_propagates_failure(workflow, "platform_tests")
                )
        self.assertFalse(
            _workflow_job_propagates_failure(dependency_workflow(), "missing")
        )

    def test_ci_structural_scan_rejects_multiline_quoted_scalars(self) -> None:
        multiline_scalars = (
            (
                "jobs:",
                "  test:",
                "    steps:",
                "      - name: 'single-quoted decoy",
                "        env:",
                "        '",
            ),
            (
                "jobs:",
                "  test:",
                "    steps:",
                '      - name: "double-quoted decoy',
                "        env:",
                '        "',
            ),
        )
        for lines in multiline_scalars:
            self.assertTrue(_workflow_has_unsupported_mapping_key_syntax(lines))

        self.assertFalse(
            _workflow_has_unsupported_mapping_key_syntax(
                (
                    "name: 'Joey''s workflow'   ",
                    'run-name: "Guard # status" # Inline comment.',
                    "description: |",
                    "  name: 'shell text can keep an unmatched quote",
                    "jobs:",
                )
            )
        )

    def test_ci_success_guard_parser_rejects_non_propagating_steps(self) -> None:
        def guarded_workflow(
            *,
            first_step_line: str = "      - name: Check result",
            step_properties: tuple[str, ...] = (),
            run_lines: tuple[str, ...] = (
                '        run: test "$PLATFORM_RESULT" = "success"',
            ),
            job_properties: tuple[str, ...] = (),
            extra_env_bindings: tuple[str, ...] = (),
            result_variable: str = "PLATFORM_RESULT",
            runs_on: str = "ubuntu-latest",
            steps_line: str = "    steps:",
            leading_step_lines: tuple[str, ...] = (),
            trailing_job_lines: tuple[str, ...] = (),
        ) -> str:
            return (
                "jobs:\n"
                "  test:\n"
                "    needs: platform_tests\n"
                + f"    runs-on: {runs_on}\n"
                + "".join(f"    {property_line}\n" for property_line in job_properties)
                + f"{steps_line}\n"
                + "".join(f"{line}\n" for line in leading_step_lines)
                + f"{first_step_line}\n"
                + "".join(f"        {property_line}\n" for property_line in step_properties)
                + "        env:\n"
                + f"          {result_variable}: ${{{{ needs.platform_tests.result }}}}\n"
                + "".join(
                    f"          {binding}\n" for binding in extra_env_bindings
                )
                + "".join(f"{line}\n" for line in run_lines)
                + "".join(f"{line}\n" for line in trailing_job_lines)
            )

        def anchored_shell_workflow(
            *,
            target_job_properties: tuple[str, ...] = (),
            workflow_tail: tuple[str, ...] = (),
        ) -> str:
            return (
                "jobs:\n"
                "  platform_tests:\n"
                "    runs-on: ubuntu-latest\n"
                "    defaults:\n"
                "      run: &evil\n"
                '        shell: "bash -c \'exit 0\' {0}"\n'
                "    steps:\n"
                "      - run: true\n"
                + guarded_workflow(
                    job_properties=target_job_properties
                ).removeprefix("jobs:\n")
                + "".join(f"{line}\n" for line in workflow_tail)
            )

        explicit_indent_cross_step_poison = (
            "jobs:\n"
            "  test:\n"
            "    needs: [compatibility_tests, platform_tests]\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: Check compatibility and poison later shells\n"
            "        env:\n"
            "          COMPATIBILITY_RESULT: "
            "${{ needs.compatibility_tests.result }}\n"
            "        run: |2-\n"
            '            test "$COMPATIBILITY_RESULT" = "success"\n'
            "          printf '%s\\n' 'test() { return 0; }' > "
            '"$RUNNER_TEMP/guard-bypass"\n'
            '          echo "BASH_ENV=$RUNNER_TEMP/guard-bypass" >> "$GITHUB_ENV"\n'
            "      - name: Check platform\n"
            "        env:\n"
            "          PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            "        run: |-\n"
            '          test "$PLATFORM_RESULT" = "success"\n'
        )
        multiline_quoted_step_decoy = (
            "jobs:\n"
            "  test:\n"
            "    needs: platform_tests\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: 'decoy\n"
            "        env:\n"
            "          PLATFORM_RESULT: ${{ needs.platform_tests.result }}\n"
            '        run: test "$PLATFORM_RESULT" = "success"\n'
            "        '\n"
            "        run: true\n"
        )

        unsafe_workflows = {
            "conditional-after-name": guarded_workflow(
                step_properties=("if: ${{ false }}",)
            ),
            "conditional-first": guarded_workflow(
                first_step_line="      - if: ${{ false }}"
            ),
            "tolerated-after-name": guarded_workflow(
                step_properties=("continue-on-error: true",)
            ),
            "tolerated-first": guarded_workflow(
                first_step_line="      - continue-on-error: true"
            ),
            "tolerated-job": guarded_workflow(
                job_properties=("continue-on-error: true",)
            ),
            "inline-steps": guarded_workflow(steps_line="    steps: []"),
            "duplicate-steps": guarded_workflow(
                trailing_job_lines=(
                    "    'steps':",
                    "      - run: true",
                )
            ),
            "dedented-job-comment-before-tolerance": guarded_workflow(
                trailing_job_lines=(
                    "  # This comment does not end the selected job.",
                    "  ",
                    "    continue-on-error: true",
                )
            ),
            "dedented-step-comment-before-tolerance": guarded_workflow(
                run_lines=(
                    '        run: test "$PLATFORM_RESULT" = "success"',
                    "    # This comment does not end the current step.",
                    "    ",
                    "        continue-on-error: true",
                )
            ),
            "custom-shell": guarded_workflow(step_properties=("shell: bash {0}",)),
            "quoted-conditional": guarded_workflow(
                step_properties=('"if": ${{ false }}',)
            ),
            "quoted-spaced-conditional": guarded_workflow(
                step_properties=('"if" : ${{ false }}',)
            ),
            "escaped-quoted-conditional": guarded_workflow(
                step_properties=('"i\\u0066" : ${{ false }}',)
            ),
            "explicit-conditional": guarded_workflow(
                step_properties=(
                    "? if",
                    ": ${{ github.event_name == 'push' }}",
                )
            ),
            "tagged-conditional": guarded_workflow(
                step_properties=("!!str if: ${{ github.event_name == 'push' }}",)
            ),
            "anchored-conditional": guarded_workflow(
                step_properties=(
                    "&condition_key if: ${{ github.event_name == 'push' }}",
                )
            ),
            "aliased-conditional": guarded_workflow(
                first_step_line="      - name: &condition_key if",
                step_properties=(
                    "*condition_key: ${{ github.event_name == 'push' }}",
                ),
            ),
            "quoted-tolerated-step": guarded_workflow(
                step_properties=("'continue-on-error': true",)
            ),
            "quoted-tolerated-job": guarded_workflow(
                job_properties=('"continue-on-error": true',)
            ),
            "quoted-custom-shell": guarded_workflow(
                step_properties=('"shell": bash {0}',)
            ),
            "workflow-default-shell": (
                "defaults:\n"
                "  run:\n"
                "    shell: bash {0}\n"
                + guarded_workflow()
            ),
            "job-default-shell": guarded_workflow(
                job_properties=(
                    "defaults:",
                    "  run:",
                    "    shell: bash {0}",
                )
            ),
            "narrow-workflow-default-shell": (
                "defaults:\n"
                " run:\n"
                "  shell: bash {0}\n"
                + guarded_workflow()
            ),
            "narrow-job-default-shell": guarded_workflow(
                job_properties=(
                    "defaults:",
                    " run:",
                    "  shell: bash {0}",
                )
            ),
            "workflow-flow-default-shell": (
                "defaults:\n"
                "  run:\n"
                '    { shell: "bash -c \'exit 0\' {0}" }\n'
                + guarded_workflow()
            ),
            "job-flow-default-shell": guarded_workflow(
                job_properties=(
                    "defaults:",
                    "  run:",
                    '    { shell: "bash -c \'exit 0\' {0}" }',
                )
            ),
            "quoted-workflow-flow-default-shell": (
                "defaults:\n"
                "  run:\n"
                '    { "shell": "bash -c \'exit 0\' {0}" }\n'
                + guarded_workflow()
            ),
            "multiline-job-flow-default-shell": guarded_workflow(
                job_properties=(
                    "defaults:",
                    "  run:",
                    "    {",
                    '      shell: "bash -c \'exit 0\' {0}",',
                    "    }",
                )
            ),
            "workflow-flow-default-sequence": (
                "defaults:\n"
                "  run:\n"
                '    [ { shell: "bash -c \'exit 0\' {0}" } ]\n'
                + guarded_workflow()
            ),
            "workflow-alias-default-shell": anchored_shell_workflow(
                workflow_tail=(
                    "defaults:",
                    "  run:",
                    "    *evil",
                )
            ),
            "job-alias-default-shell": anchored_shell_workflow(
                target_job_properties=(
                    "defaults:",
                    "  run:",
                    "    *evil",
                )
            ),
            "quoted-job-alias-default-shell": anchored_shell_workflow(
                target_job_properties=(
                    "'defaults':",
                    '  "run":',
                    "    *evil # Inherit the anchored custom shell.",
                )
            ),
            "job-merge-default-shell": anchored_shell_workflow(
                target_job_properties=(
                    "defaults:",
                    "  run:",
                    "    <<: *evil",
                )
            ),
            "tagged-working-directory": (
                "defaults:\n"
                "  run:\n"
                "    working-directory: !!str scripts\n"
                + guarded_workflow()
            ),
            "anchored-working-directory": (
                "defaults:\n"
                "  run:\n"
                "    working-directory: &path scripts\n"
                + guarded_workflow(
                    job_properties=(
                        "defaults:",
                        "  run:",
                        "    working-directory: *path",
                    )
                )
            ),
            "block-scalar-working-directory": (
                "defaults:\n"
                "  run:\n"
                "    working-directory: |-\n"
                "      scripts\n"
                + guarded_workflow()
            ),
            "quoted-workflow-default-shell": (
                "'defaults':\n"
                '  "run":\n'
                "    'shell': bash {0}\n"
                + guarded_workflow()
            ),
            "escaped-quoted-workflow-default-shell": (
                '"def\\u0061ults":\n'
                "  run:\n"
                "    shell: bash {0}\n"
                + guarded_workflow()
            ),
            "bom-workflow-default-shell": (
                "\ufeffdefaults:\n"
                "  run:\n"
                "    shell: bash {0}\n"
                + guarded_workflow()
            ),
            "workflow-environment": (
                "env:\n"
                "  BASH_ENV: /tmp/guard-bypass\n"
                + guarded_workflow()
            ),
            "tagged-workflow-environment": (
                "!!str env:\n"
                '  BASH_FUNC_test%%: "() { return 0; }"\n'
                + guarded_workflow()
            ),
            "job-environment": guarded_workflow(
                job_properties=(
                    "'env':",
                    "  BASH_ENV: /tmp/guard-bypass",
                )
            ),
            "step-environment": guarded_workflow(
                extra_env_bindings=("BASH_ENV: /tmp/guard-bypass",)
            ),
            "shell-startup-variable-as-result-binding": guarded_workflow(
                result_variable="BASH_ENV",
                run_lines=('        run: test "$BASH_ENV" = "success"',),
            ),
            "tab-separated-step-environment": guarded_workflow(
                extra_env_bindings=('BASH_FUNC_test%%:\t"() { return 0; }"',)
            ),
            "shell-injected-environment-name": guarded_workflow(
                result_variable='PATH";true;echo"',
                run_lines=('        run: test "$PATH";true;echo"" = "success"',),
            ),
            "custom-runner": guarded_workflow(runs_on="self-hosted"),
            "job-container-environment": guarded_workflow(
                job_properties=(
                    "container:",
                    "  image: bash:latest",
                    "  env:",
                    '    BASH_FUNC_test%%: "() { return 0; }"',
                )
            ),
            "job-services": guarded_workflow(
                job_properties=(
                    "services:",
                    "  database:",
                    "    image: postgres:latest",
                )
            ),
            "job-strategy": guarded_workflow(
                job_properties=(
                    "strategy:",
                    "  matrix:",
                    "    shard: [one, two]",
                )
            ),
            "commented-command": guarded_workflow(
                run_lines=(
                    "        run: |",
                    '          # test "$PLATFORM_RESULT" = "success"',
                )
            ),
            "echoed-command": guarded_workflow(
                run_lines=(
                    "        run: echo 'test \"$PLATFORM_RESULT\" = \"success\"'",
                )
            ),
            "masked-inline-command": guarded_workflow(
                run_lines=(
                    '        run: test "$PLATFORM_RESULT" = "success" || true',
                )
            ),
            "continued-inline-command": guarded_workflow(
                run_lines=(
                    '        run: test "$PLATFORM_RESULT" = "success"',
                    "          ; true",
                )
            ),
            "folded-run": guarded_workflow(
                run_lines=(
                    "        run: >-",
                    '          test "$PLATFORM_RESULT" = "success"',
                    '          test "$PLATFORM_RESULT" = "success"',
                )
            ),
            "explicit-indent-cross-step-poison": explicit_indent_cross_step_poison,
            "multiline-quoted-step-decoy": multiline_quoted_step_decoy,
            "uses-step": guarded_workflow(
                step_properties=("uses: actions/checkout@v4",)
            ),
            "duplicate-run": guarded_workflow(
                run_lines=(
                    '        run: test "$PLATFORM_RESULT" = "success"',
                    "        'run': true",
                )
            ),
            "bare-dash-poisoning-step": guarded_workflow(
                leading_step_lines=(
                    "      -",
                    "        name: Poison later shell startup",
                    "        run: |",
                    '          echo "BASH_ENV=$RUNNER_TEMP/guard-bypass" >> "$GITHUB_ENV"',
                )
            ),
            "disabled-errexit": guarded_workflow(
                run_lines=(
                    "        run: |",
                    "          set +e",
                    '          test "$PLATFORM_RESULT" = "success"',
                    "          true",
                )
            ),
            "aliased-steps": (
                "jobs:\n"
                "  platform_tests:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps: &shared_steps\n"
                "      - run: true\n"
                "  test:\n"
                "    needs: platform_tests\n"
                "    runs-on: ubuntu-latest\n"
                "    steps: *shared_steps\n"
            ),
        }

        literal_block_scalar_steps = (
            (
                (
                    "      - run: |2-",
                    "            first command",
                    "          second command",
                ),
                "first command\nsecond command",
            ),
            (
                (
                    "      - 'run': |-2",
                    "            first quoted-key command",
                    "          second quoted-key command",
                ),
                "first quoted-key command\nsecond quoted-key command",
            ),
            (
                (
                    "      - name: Nested quoted run key",
                    '        "run" : |+2',
                    "            first nested command",
                    "          second nested command",
                ),
                "first nested command\nsecond nested command",
            ),
            (
                (
                    "      - name: Nested single-quoted run key",
                    "        'run': |2+",
                    "            first kept command",
                    "          second kept command",
                ),
                "first kept command\nsecond kept command",
            ),
            (
                (
                    "      - run: |",
                    "          first implicit command",
                    "            second deeper implicit command",
                ),
                "first implicit command\nsecond deeper implicit command",
            ),
        )
        self.assertEqual(
            _workflow_block_scalar_header_indents("      - run: |"),
            (8, None),
        )
        for step, expected_body in literal_block_scalar_steps:
            self.assertEqual(_workflow_step_run_body(step), expected_body)
        for folded_header in (">2+", ">+2"):
            self.assertEqual(
                _workflow_step_run_body(
                    (
                        f"      - run: {folded_header}",
                        "            first folded command",
                        "          second folded command",
                    )
                ),
                "",
            )

        for name, workflow in unsafe_workflows.items():
            with self.subTest(name=name):
                self.assertEqual(_workflow_job_success_guards(workflow, "test"), ())

        safe_workflows = (
            guarded_workflow(step_properties=("continue-on-error: false",)),
            guarded_workflow(
                step_properties=(
                    "continue-on-error: false # Failures remain visible.",
                )
            ),
            guarded_workflow(step_properties=('"continue-on-error": false',)),
            guarded_workflow(job_properties=("continue-on-error: false",)),
            guarded_workflow(steps_line='    "steps":'),
            guarded_workflow(steps_line="    'steps':"),
            guarded_workflow(steps_line="    steps :"),
            guarded_workflow(steps_line="    steps: # Guard steps follow."),
            (
                "defaults:\n"
                "  run:\n"
                "    working-directory: scripts\n"
                + guarded_workflow()
            ),
            (
                "defaults:\n"
                "  run:\n"
                "    # Quoted keys and values remain ordinary block mappings.\n"
                '    "working-directory": "scripts"\n'
                + guarded_workflow()
            ),
            guarded_workflow(
                job_properties=(
                    "defaults:",
                    "  run:",
                    "    working-directory: scripts",
                )
            ),
            (
                "jobs:\n"
                "  other:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: |2-\n"
                "            printf '%s\\n' 'more-indented first line'\n"
                "          ! grep -q '^foo:' config.txt\n"
                "      - 'run': >2+\n"
                "            printf '%s\\n' 'more-indented folded first line'\n"
                "          ! grep -q '^bar:' config.txt\n"
                '      - "run" : |+2\n'
                "            printf '%s\\n' 'more-indented quoted first line'\n"
                "          ! grep -q '^baz:' config.txt\n"
                "      - run: |\n"
                "          ! grep -q '^implicit:' config.txt\n"
                + guarded_workflow().removeprefix("jobs:\n")
            ),
            (
                "jobs:\n"
                "  other:\n"
                "    defaults:\n"
                "      run:\n"
                "        shell: bash {0}\n"
                + guarded_workflow().removeprefix("jobs:\n")
            ),
        )
        for workflow in safe_workflows:
            self.assertEqual(
                _workflow_job_success_guards(workflow, "test"),
                ("platform_tests",),
            )

    def test_helper_declares_and_tests_its_minimum_python_runtime(self) -> None:
        entrypoint = (SCRIPTS / "isolated_review").read_text(encoding="utf-8")
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

        guard = "if sys.version_info < (3, 10):"
        self.assertIn(guard, entrypoint)
        self.assertLess(entrypoint.index(guard), entrypoint.index("from review_runtime"))
        self.assertIn('python-version: "3.10"', workflow)
        self.assertIn("tomli==2.2.1", workflow)
        self.assertIn("requires Python 3.10 or later", readme)

    def test_full_pr_readiness_retains_both_local_codex_gates(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        for value in (readiness, contracts):
            self.assertIn("independent-codex-pr-review", value)
            self.assertIn("offline-frozen-diff-review", value)
        self.assertIn("standalone double/triple-review", readiness)
        self.assertLess(
            readiness.index("3. Run `offline-frozen-diff-review` first"),
            readiness.index("4. After the helper preflight passes"),
        )
        self.assertIn("Require its retained `preflight.json`", readiness)

    def test_independent_codex_process_output_is_task_scoped_and_bounded(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("stdout and stderr in task-scoped bounded sinks", readiness)
        self.assertIn("--output-last-message <task-scoped-target>", readiness)
        self.assertIn("byte limits for each process log and the final-message", readiness)
        self.assertIn("default 30-minute / 16-MiB / 64-KiB limits", readiness)
        self.assertIn("deadline expires or any output limit", readiness)
        self.assertIn("limit-terminated attempt is inconclusive", readiness)
        self.assertIn("bounded sinks", readiness)
        self.assertIn("bounded FIFO/pipe", readiness)
        self.assertIn("distinct fresh ordinary artifact", readiness)
        self.assertIn("only that ordinary artifact", readiness)
        self.assertIn(
            "Never implement the final-message cap with process-wide `RLIMIT_FSIZE`",
            readiness,
        )
        self.assertIn("terminate the reviewer with `SIGXFSZ`", readiness)
        self.assertIn(
            "a parent supervisor that enforces the caps on parent-owned bounded sinks",
            readiness,
        )
        self.assertIn("Enforce every cap while the reviewer runs", readiness)
        self.assertIn("OS-enforced job/cgroup/container", readiness)
        self.assertIn("survives `setsid` / `setpgid`", readiness)
        self.assertIn("verified kernel no-child-process policy", readiness)
        self.assertIn("fully self-contained artifact-only review", readiness)
        self.assertIn("complete diff and permitted neighboring evidence", readiness)
        self.assertIn("tool calls are forbidden", readiness)
        self.assertIn("report `blocked` and do not launch", readiness)
        self.assertIn("descendant polling is not a substitute", readiness)
        self.assertIn("separate 10-second deadline", readiness)
        self.assertIn("stat every ordinary output artifact again", readiness)
        self.assertIn("never use FIFO metadata", readiness)
        self.assertIn("even after exit zero", readiness)
        self.assertIn("quiescence or sink closure cannot be confirmed", readiness)
        self.assertIn("Poll only with bounded status probes", readiness)
        self.assertIn("Parent-Process Output Budget", readiness)
        self.assertIn("do not stream either process output", contracts)
        self.assertIn("--output-last-message <task-scoped-target>", contracts)
        self.assertIn("unique path that does not exist before the attempt", contracts)
        self.assertIn("freshly created before launch at one path", contracts)
        self.assertIn("different ordinary artifact path", contracts)
        self.assertIn("byte limit for the final-message artifact", contracts)
        self.assertIn("30-minute deadline, 16 MiB", contracts)
        self.assertIn("64 KiB for the final-message artifact", contracts)
        self.assertIn("send `TERM`", contracts)
        self.assertIn("send `KILL`", contracts)
        self.assertIn("when the deadline expires", contracts)
        self.assertIn("hard per-file quota or bounded sink", contracts)
        self.assertIn("bounded FIFO/pipe reader", contracts)
        self.assertIn(
            "Do not set process-wide file-size limits such as `RLIMIT_FSIZE`",
            contracts,
        )
        self.assertIn("unrelated internal session and state files", contracts)
        self.assertIn("terminate the reviewer with `SIGXFSZ`", contracts)
        self.assertIn("invalid harness attempt, not review evidence", contracts)
        self.assertIn(
            "a parent supervisor enforces the relevant byte ceilings",
            contracts,
        )
        self.assertIn("Direct-path monitoring or a post-exit size check alone", contracts)
        self.assertIn("OS-enforced job, cgroup, or container", contracts)
        self.assertIn("survives `setsid` / `setpgid`", contracts)
        self.assertIn("kernel-enforced no-child-process policy", contracts)
        self.assertIn("fully self-contained artifact-only review", contracts)
        self.assertIn("complete diff and permitted neighboring evidence", contracts)
        self.assertIn("prompt forbids tool calls", contracts)
        self.assertIn("report `blocked` and do not launch", contracts)
        self.assertIn("descendant polling may provide diagnostics", contracts)
        self.assertIn("never substitute for containment", contracts)
        self.assertIn("separate 10-second close deadline", contracts)
        self.assertIn("waiting indefinitely", contracts)
        self.assertIn("Do not accept a final-message artifact", contracts)
        self.assertIn("file byte or line counts", contracts)
        self.assertIn("attempt exits zero", contracts)
        self.assertIn("creates it as a nonempty file", contracts)
        self.assertIn("stat both process logs and the ordinary final-message artifact", contracts)
        self.assertIn("Never use a FIFO's `st_size`", contracts)
        self.assertIn("even when it exited zero", contracts)
        self.assertIn("reaches or exceeds", contracts)
        self.assertIn("record only the byte counts", contracts)
        self.assertIn("remove the oversized artifact", contracts)
        self.assertIn("reject any stale or partial result", contracts)
        self.assertIn("On a nonzero exit or a missing/empty file", contracts)
        self.assertIn("read at most the final 8 KiB of stderr", contracts)
        self.assertIn("byte-count-limited read", contracts)
        self.assertIn("truncates before inserting text", contracts)
        self.assertIn("line-count-only command", contracts)
        self.assertIn("single long JSON or trace line", contracts)
        self.assertIn("runtime-verification failure as `blocked`", contracts)
        self.assertIn("otherwise report `inconclusive`", contracts)
        self.assertIn("Never read the complete stderr", contracts)
        self.assertIn(
            "Remove task-scoped process logs and the final-message file",
            contracts,
        )
        self.assertIn("reported blocker or recovery handoff", contracts)
        self.assertIn("remove the oversized log", contracts)
        self.assertIn("read at most the final 8 KiB of stderr", readiness)
        self.assertIn("line-count-only tail is not bounded", readiness)

    def test_review_prompts_do_not_use_unbounded_only_matching_samples(self) -> None:
        forbidden = "rg -o --max-count 80"
        candidates = [SKILL_ROOT / "SKILL.md", SKILL_ROOT / "scripts/review_runtime/prompt.py"]
        candidates.extend((SKILL_ROOT / "references").glob("*.md"))
        for candidate in candidates:
            self.assertNotIn(
                forbidden,
                candidate.read_text(encoding="utf-8"),
                str(candidate),
            )

    def test_cli_rejects_claude_lane_without_visible_consent(self) -> None:
        completed = subprocess.run(
            (
                str(SCRIPTS / "isolated_review"),
                "--reviewer",
                "claude",
                "--base-ref",
                "base",
                "--head-ref",
                "head",
            ),
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--egress-consent", completed.stderr)

    def test_approval_template_covers_both_copilot_fallback_reasons(self) -> None:
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("if Claude Code is unavailable", consent)
        self.assertIn(
            "all pinned Claude models are entitlement-blocked",
            consent,
        )

    def test_triple_review_consent_names_all_provider_organizations(self) -> None:
        candidates = [
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/egress-consent.md",
        ]
        repo_agents = REPO_ROOT / "AGENTS.md"
        if repo_agents.is_file():
            candidates.append(repo_agents)
        for candidate in candidates:
            content = candidate.read_text(encoding="utf-8")
            self.assertIn(
                "OpenAI, Anthropic, and Microsoft/GitHub",
                content,
                str(candidate),
            )


if __name__ == "__main__":
    unittest.main()
