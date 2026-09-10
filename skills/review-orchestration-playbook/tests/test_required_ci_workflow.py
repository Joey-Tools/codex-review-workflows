from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
REUSABLE_HEADER = """name: Required CI

on:
  workflow_call:

"""
EXPECTED_REPOSITORY = "Joey-Tools/codex-review-workflows"
REPOSITORY_BINDING = f"repository: {EXPECTED_REPOSITORY}"
REF_BINDING = "ref: ${{ github.sha }}"
PERSIST_CREDENTIALS_BINDING = "persist-credentials: false"
REPOSITORY_GUARD = (
    "      - name: Reject unexpected repository\n"
    f"        if: ${{{{ github.repository != '{EXPECTED_REPOSITORY}' }}}}\n"
    "        run: exit 1"
)
MAPPING_ENTRY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_-]+):(?P<value>.*)$")
EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
SECRET_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_.])secrets(?![A-Za-z0-9_])", re.IGNORECASE
)
BASE_CHECKOUT_INPUTS = {
    "repository": EXPECTED_REPOSITORY,
    "ref": "${{ github.sha }}",
    "persist-credentials": "false",
}
SHALLOW_CHECKOUT_INPUTS = {**BASE_CHECKOUT_INPUTS, "fetch-depth": "1"}


def bind_checkout_inputs(source: str) -> str:
    lines = source.splitlines(keepends=True)
    bound: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        bound.append(line)
        stripped = line.lstrip()
        if stripped.startswith(("- uses: actions/checkout@", "uses: actions/checkout@")):
            step_indent = line[: len(line) - len(line.lstrip())]
            with_indent = f"{step_indent}  " if stripped.startswith("- uses:") else step_indent
            with_line = f"{with_indent}with:\n"
            field_indent = f"{with_indent}  "
            bound.extend(
                [
                    with_line,
                    f"{field_indent}{REPOSITORY_BINDING}\n",
                    f"{field_indent}{REF_BINDING}\n",
                ]
            )
            if index + 1 < len(lines) and lines[index + 1] == with_line:
                index += 1
                while index + 1 < len(lines) and lines[index + 1].startswith(field_indent):
                    index += 1
                    field = lines[index]
                    key = field[len(field_indent) :].split(":", 1)[0]
                    if key not in {"repository", "ref", "persist-credentials"}:
                        bound.append(field)
            bound.append(f"{field_indent}{PERSIST_CREDENTIALS_BINDING}\n")
        index += 1
    return "".join(bound)


def checkout_step_blocks(source: str) -> list[str]:
    lines = source.splitlines(keepends=True)
    blocks: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped.startswith(("- uses: actions/checkout@", "uses: actions/checkout@")):
            continue
        use_indent = line[: len(line) - len(line.lstrip())]
        step_indent = use_indent if stripped.startswith("- uses:") else use_indent[:-2]
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.startswith(f"{step_indent}- "):
                break
            end += 1
        blocks.append("".join(lines[index:end]))
    return blocks


def without_repository_guards(source: str) -> str:
    return source.replace(REPOSITORY_GUARD + "\n", "")


class ContractSyntaxError(ValueError):
    pass


def line_indent(line: str) -> int:
    prefix = line[: len(line) - len(line.lstrip(" \t"))]
    if "\t" in prefix:
        raise ContractSyntaxError("tab indentation is not allowed")
    return len(prefix)


def mapping_entry(line: str) -> tuple[str, str]:
    stripped = line.lstrip(" ")
    if stripped.startswith("- "):
        raise ContractSyntaxError("unexpected sequence mapping entry")

    match = MAPPING_ENTRY_RE.fullmatch(stripped)
    if match is None:
        raise ContractSyntaxError("unsupported mapping syntax")
    return match.group("key"), match.group("value").strip()


def significant_line_indices(lines: list[str], start: int, end: int) -> list[int]:
    return [
        index
        for index in range(start, end)
        if lines[index].strip() and not lines[index].lstrip().startswith("#")
    ]


def block_end(lines: list[str], parent_index: int) -> int:
    parent_indent = line_indent(lines[parent_index])
    for index in significant_line_indices(lines, parent_index + 1, len(lines)):
        if line_indent(lines[index]) <= parent_indent:
            return index
    return len(lines)


def direct_mapping(
    lines: list[str], parent_index: int
) -> dict[str, tuple[str, int]]:
    indices = significant_line_indices(
        lines, parent_index + 1, block_end(lines, parent_index)
    )
    if not indices:
        return {}

    direct_indent = min(line_indent(lines[index]) for index in indices)
    entries: dict[str, tuple[str, int]] = {}
    for index in indices:
        if line_indent(lines[index]) != direct_indent:
            continue
        key, value = mapping_entry(lines[index])
        if key in entries:
            raise ContractSyntaxError(f"duplicate mapping key: {key}")
        entries[key] = (value, index)
    return entries


def root_mapping(lines: list[str]) -> dict[str, tuple[str, int]]:
    entries: dict[str, tuple[str, int]] = {}
    for index in significant_line_indices(lines, 0, len(lines)):
        if line_indent(lines[index]) != 0:
            continue
        key, value = mapping_entry(lines[index])
        if key in entries:
            raise ContractSyntaxError(f"duplicate root mapping key: {key}")
        entries[key] = (value, index)
    return entries


def scalar_mapping_values(
    lines: list[str], entries: dict[str, tuple[str, int]]
) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, (value, index) in entries.items():
        descendants = significant_line_indices(
            lines, index + 1, block_end(lines, index)
        )
        if not value or descendants:
            raise ContractSyntaxError(f"mapping value must be scalar: {key}")
        values[key] = value
    return values


def checkout_input_maps(source: str) -> list[dict[str, str]]:
    lines = source.splitlines()
    checkout_indices = [
        index
        for index, line in enumerate(lines)
        if line.lstrip().startswith("- uses: actions/checkout@")
    ]
    if source.count("actions/checkout@") != len(checkout_indices):
        raise ContractSyntaxError("unrecognized checkout reference")

    inputs: list[dict[str, str]] = []
    for checkout_index in checkout_indices:
        step_indent = line_indent(lines[checkout_index])
        end = len(lines)
        for index in significant_line_indices(lines, checkout_index + 1, len(lines)):
            indent = line_indent(lines[index])
            if indent < step_indent or (
                indent == step_indent and lines[index].lstrip().startswith("- ")
            ):
                end = index
                break

        step_entries: dict[str, tuple[str, int]] = {}
        for index in significant_line_indices(lines, checkout_index + 1, end):
            if line_indent(lines[index]) != step_indent + 2:
                continue
            key, value = mapping_entry(lines[index])
            if key in step_entries:
                raise ContractSyntaxError(f"duplicate checkout step key: {key}")
            step_entries[key] = (value, index)

        if "with" not in step_entries or step_entries["with"][0]:
            raise ContractSyntaxError(
                "checkout step must have one block-form with mapping"
            )
        fields = direct_mapping(lines, step_entries["with"][1])
        inputs.append(scalar_mapping_values(lines, fields))
    return inputs


def required_ci_contract_violations(source: str) -> list[str]:
    violations: list[str] = []
    try:
        lines = source.splitlines()
        roots = root_mapping(lines)

        permissions_value, permissions_index = roots.get("permissions", (None, -1))
        if permissions_value != "" or permissions_index < 0:
            violations.append("top-level permissions")
        else:
            permissions = direct_mapping(lines, permissions_index)
            permission_values = scalar_mapping_values(lines, permissions)
            if permission_values != {"contents": "read"}:
                violations.append("top-level permissions")

        jobs_value, jobs_index = roots.get("jobs", (None, -1))
        if jobs_value != "" or jobs_index < 0:
            violations.append("jobs mapping")
        else:
            jobs = direct_mapping(lines, jobs_index)
            for _job, (job_value, job_index) in jobs.items():
                if job_value:
                    raise ContractSyntaxError("job must use block mapping syntax")
                job_entries = direct_mapping(lines, job_index)
                if "permissions" in job_entries:
                    violations.append("job-level permissions")
                if "secrets" in job_entries:
                    violations.append("job-level secrets")

        on_value, on_index = roots.get("on", (None, -1))
        if on_value != "" or on_index < 0:
            violations.append("workflow_call mapping")
        else:
            workflow_call = direct_mapping(lines, on_index).get("workflow_call")
            if workflow_call is None or workflow_call[0]:
                violations.append("workflow_call mapping")
            elif "secrets" in direct_mapping(lines, workflow_call[1]):
                violations.append("workflow_call secrets")

        expressions = EXPRESSION_RE.findall(source)
        if source.count("${{") != len(expressions):
            violations.append("malformed expression")
        if any(SECRET_REFERENCE_RE.search(expression) for expression in expressions):
            violations.append("secret expression")

        checkout_inputs = checkout_input_maps(source)
        if (
            len(checkout_inputs) != 4
            or checkout_inputs.count(BASE_CHECKOUT_INPUTS) != 3
            or checkout_inputs.count(SHALLOW_CHECKOUT_INPUTS) != 1
        ):
            violations.append("checkout inputs")
    except ContractSyntaxError:
        violations.append("unsupported workflow syntax")
    return violations


class RequiredCIWorkflowTests(unittest.TestCase):
    def test_reusable_entry_preserves_the_complete_required_test_graph(self) -> None:
        source = (WORKFLOW_DIR / "ci.yml").read_text(encoding="utf-8")
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")

        permissions = source.index("permissions:\n")
        expected = REUSABLE_HEADER + bind_checkout_inputs(source[permissions:])

        self.assertEqual(without_repository_guards(reusable), expected)

    def test_reusable_entry_is_read_only_and_caller_only(self) -> None:
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")
        header, _separator, _body = reusable.partition("permissions:\n")

        self.assertEqual(header, REUSABLE_HEADER)
        self.assertEqual(required_ci_contract_violations(reusable), [])
        self.assertNotIn("inputs.repository", reusable)
        self.assertNotIn("inputs.ref", reusable)

        near_misses = {
            "issues write": reusable.replace(
                "permissions:\n  contents: read\n",
                "permissions:\n  contents: read\n  issues: write\n",
                1,
            ),
            "pull requests write": reusable.replace(
                "permissions:\n  contents: read\n",
                "permissions:\n  contents: read\n  pull-requests: write\n",
                1,
            ),
            "write all": reusable.replace(
                "permissions:\n  contents: read\n", "permissions: write-all\n", 1
            ),
            "duplicate root permissions": reusable.replace(
                "env:\n", "permissions:\n  contents: read\n\nenv:\n", 1
            ),
            "job permissions mapping": reusable.replace(
                "    strategy:\n",
                "    permissions:\n      contents: write\n    strategy:\n",
                1,
            ),
            "job permissions scalar": reusable.replace(
                "    strategy:\n", "    permissions: write-all\n    strategy:\n", 1
            ),
            "job permissions flow mapping": reusable.replace(
                "    strategy:\n",
                "    permissions: {contents: write}\n    strategy:\n",
                1,
            ),
            "workflow call secrets": reusable.replace(
                "  workflow_call:\n",
                "  workflow_call:\n"
                "    secrets:\n"
                "      WRITE_PAT:\n"
                "        required: false\n",
                1,
            ),
            "workflow call secrets inherit": reusable.replace(
                "  workflow_call:\n", "  workflow_call:\n    secrets: inherit\n", 1
            ),
            "job secrets mapping": reusable.replace(
                "    strategy:\n",
                "    secrets:\n      WRITE_PAT: inherited\n    strategy:\n",
                1,
            ),
            "job secrets inherit": reusable.replace(
                "    strategy:\n", "    secrets: inherit\n    strategy:\n", 1
            ),
            "secret dot expression": reusable.replace(
                "run: exit 1", "run: echo ${{ secrets.WRITE_PAT }}", 1
            ),
            "secret bracket expression": reusable.replace(
                "run: exit 1", "run: echo ${{ secrets['WRITE_PAT'] }}", 1
            ),
            "secret dynamic expression": reusable.replace(
                "run: exit 1", "run: echo ${{ secrets[inputs.secret_name] }}", 1
            ),
            "bare secret context": reusable.replace(
                "run: exit 1", "run: echo ${{ toJSON(secrets) }}", 1
            ),
            "secret multiline expression": reusable.replace(
                "run: exit 1",
                "run: echo ${{ SeCrEtS\n          [inputs.secret_name] }}",
                1,
            ),
        }
        expected_violations = {
            "issues write": "top-level permissions",
            "pull requests write": "top-level permissions",
            "write all": "top-level permissions",
            "duplicate root permissions": "unsupported workflow syntax",
            "job permissions mapping": "job-level permissions",
            "job permissions scalar": "job-level permissions",
            "job permissions flow mapping": "job-level permissions",
            "workflow call secrets": "workflow_call secrets",
            "workflow call secrets inherit": "workflow_call secrets",
            "job secrets mapping": "job-level secrets",
            "job secrets inherit": "job-level secrets",
            "secret dot expression": "secret expression",
            "secret bracket expression": "secret expression",
            "secret dynamic expression": "secret expression",
            "bare secret context": "secret expression",
            "secret multiline expression": "secret expression",
        }
        for label, near_miss in near_misses.items():
            with self.subTest(label=label):
                self.assertNotEqual(near_miss, reusable)
                self.assertIn(
                    expected_violations[label],
                    required_ci_contract_violations(near_miss),
                )

    def test_every_checkout_is_guarded_and_bound_to_the_exact_repository(self) -> None:
        reusable = (WORKFLOW_DIR / "required-ci.yml").read_text(encoding="utf-8")
        header, _separator, _body = reusable.partition("permissions:\n")
        blocks = checkout_step_blocks(reusable)

        self.assertEqual(header, REUSABLE_HEADER)
        self.assertEqual(len(blocks), 4)
        self.assertEqual(reusable.count(REPOSITORY_GUARD), len(blocks))
        self.assertEqual(
            reusable.count(
                REPOSITORY_GUARD + "\n      - uses: actions/checkout@"
            ),
            len(blocks),
        )
        checkout_inputs = checkout_input_maps(reusable)
        self.assertEqual(checkout_inputs.count(BASE_CHECKOUT_INPUTS), 3)
        self.assertEqual(checkout_inputs.count(SHALLOW_CHECKOUT_INPUTS), 1)
        self.assertNotIn("repository: ${{ github.repository }}", reusable)

        checkout_near_misses = {
            "token input": reusable.replace(
                f"          {PERSIST_CREDENTIALS_BINDING}\n",
                "          token: ${{ github.token }}\n"
                f"          {PERSIST_CREDENTIALS_BINDING}\n",
                1,
            ),
            "bracket secret token": reusable.replace(
                f"          {PERSIST_CREDENTIALS_BINDING}\n",
                "          token: ${{ secrets['WRITE_PAT'] }}\n"
                f"          {PERSIST_CREDENTIALS_BINDING}\n",
                1,
            ),
            "dynamic secret token": reusable.replace(
                f"          {PERSIST_CREDENTIALS_BINDING}\n",
                "          token: ${{ secrets[inputs.secret_name] }}\n"
                f"          {PERSIST_CREDENTIALS_BINDING}\n",
                1,
            ),
            "unknown input": reusable.replace(
                f"          {PERSIST_CREDENTIALS_BINDING}\n",
                "          sparse-checkout: skills\n"
                f"          {PERSIST_CREDENTIALS_BINDING}\n",
                1,
            ),
            "wrong repository": reusable.replace(
                REPOSITORY_BINDING, "repository: Joey-Tools/another-repository", 1
            ),
            "missing ref": reusable.replace(f"          {REF_BINDING}\n", "", 1),
        }
        for label, near_miss in checkout_near_misses.items():
            with self.subTest(label=label):
                self.assertNotEqual(near_miss, reusable)
                self.assertIn(
                    "checkout inputs", required_ci_contract_violations(near_miss)
                )


if __name__ == "__main__":
    unittest.main()
